import os
import getpass
from typing import List, Annotated, Any, Optional
from typing_extensions import TypedDict, Literal
from functools import partial
from langchain_openai import ChatOpenAI, AzureChatOpenAI
from langchain_deepseek import ChatDeepSeek
from langchain_xai import ChatXAI
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_core.messages import HumanMessage, SystemMessage, AIMessage
from langchain_core.tools import tool, BaseTool, StructuredTool
from langchain_core.runnables.config import RunnableConfig
from langgraph.prebuilt import ToolNode, tools_condition
from langgraph.graph.message import add_messages
from langgraph.graph import StateGraph, START, END
from langgraph.graph.graph import CompiledGraph
from langgraph.types import Command
from langgraph.checkpoint.memory import MemorySaver
from langfuse.callback import CallbackHandler
from .tools_def import ToolsDef
from .agent_def import AgentDef
from rich import print
from utils import VMContext
from utils import get_random_helpers, get_helpers_by_indices, parse_helper_indices_syntax, get_insns_defs, get_reg_types_defs, get_func_proto_for_helper
from .prompt_caching_strategy import (
    PromptCachingManager,
    CacheableContent,
    CachingStrategyFactory
)
import time
import threading
from langgraph.errors import GraphRecursionError
import random
from langchain_anthropic import ChatAnthropic
# Network error exceptions from various LLM providers
from anthropic import APIConnectionError as AnthropicConnectionError
from anthropic import APITimeoutError as AnthropicTimeoutError
from openai import APIConnectionError as OpenAIConnectionError
from openai import APITimeoutError as OpenAITimeoutError
import httpx  # Common HTTP client used by most LLM SDKs
import requests  # Fallback for some providers
import csv
from pathlib import Path

class State(TypedDict):
	messages: Annotated[list, add_messages]
	compile_state: str
	verifier_state: str

class LLMBPFSEED:
	# Class-level lock for thread-safe CSV writing (shared across all instances)
	_csv_write_lock = threading.Lock()

	llm_model: Any
	graph: CompiledGraph
	vm_thread: threading.Thread
	compile_round: int
	compile_total: int
	compile_fix_suggestions_history: List[str]
	verifier_round: int
	verifier_total: int
	verifier_fix_suggestions_history: List[str]
	seednum: int
	seedcnt: int
	start_time: float
	vm_context: VMContext
	config: RunnableConfig
	enable_fix_compile: bool
	enable_fix_verifier: bool
	logdebug: bool = False
	_insn_context: str
	_semantic_rules: str
	_selected_helpers: List[str]
	_all_helpers: List[str]
	helper_strategy: str
	helper_indices: List[int]
	helper_groups: List[List[int]]  # Parsed helper group list
	current_helper_group_index: int  # Current helper group index
	base_seednum: int  # Original seednum (before multiplying by group count)

	# Conversation history management
	_cached_system_prompt: Optional[SystemMessage] = None  # Cacheable system prompt
	_cached_helper_context: str = ""  # Cached helper context
	current_seed_conversation: List[Any] = []  # Current seed's full conversation history
	max_history_rounds: int = 3  # Number of recent rounds to keep

	# Seed save tracking (prevents duplicate saves)
	_current_seed_saved: bool = False  # Flag to track if current seed has been saved

	# Token usage statistics
	total_input_tokens: int = 0
	total_output_tokens: int = 0
	total_cache_creation_tokens: int = 0
	total_cache_read_tokens: int = 0

	# Timing statistics
	total_llm_time: float = 0
	total_compile_time: float = 0
	total_verifier_time: float = 0

	# Network retry configuration
	max_retry_attempts: int = 3
	base_backoff_seconds: int = 5
	current_retry_count: int = 0

	def __init__(self,
				 context: VMContext,
				 args_url: str,
				 args_provider: str,
				 args_key: str = "",
				 args_seednum: int = 1,
				 langfuse: bool = False,
				 fixcompile: bool = False,
				 fixverifier: bool = False,
				 logdebug: bool = False,
				 enablemutate: bool = False,
				 helper_strategy: str = "random",
				 helper_indices: str = "",
				 stats_csv_file: str = "bpf_seed_statistics.csv",
				 enable_cache: bool = False,
				 enable_semantic: bool = True,
				 run_id: str = "",
				 max_verifier_fix_rounds: int = 5) -> None:
		if not "OPENAI_API_KEY" in os.environ.keys():
			if args_key != "":
				os.environ["OPENAI_API_KEY"] = args_key
			else:
				api_key = getpass.getpass(prompt="Please enter your api key: ")
				os.environ["OPENAI_API_KEY"] = api_key

		self.vm_context = context
		self._init_model(args_url, args_provider)

		# Initialize Prompt Caching Manager
		self.caching_manager = PromptCachingManager(self.llm_model)
		if logdebug:
			cache_info = self.caching_manager.get_model_info()
			print(f"[Caching] Model: {cache_info['model_type']}")
			print(f"[Caching] Strategy: {cache_info['strategy_type']}")
			print(f"[Caching] Max cache points: {cache_info['max_cache_points']}")
			print(f"[Caching] Cache discount: {cache_info['cache_discount_rate'] * 100}%")

		self.config = RunnableConfig(configurable={"thread_id": "1"}, recursion_limit=20)
		if langfuse:
			self._init_langfuse()
		self.enable_fix_compile = fixcompile
		self.enable_fix_verifier = fixverifier
		self.max_verifier_fix_rounds = max_verifier_fix_rounds
		self.logdebug = logdebug
		self.base_seednum = int(args_seednum)
		self.seedcnt = 0
		self.enable_mutate = enablemutate
		self.enable_cache = enable_cache
		self.enable_semantic = enable_semantic
		self._selected_helpers = []
		self._all_helpers = []

		# Parse and store helper strategy
		self.helper_strategy = helper_strategy
		self.helper_indices = []
		self.helper_groups = []
		self.current_helper_group_index = 0

		if helper_strategy == "specified" and helper_indices:
			try:
				# Use enhanced syntax parser
				self.helper_groups = parse_helper_indices_syntax(helper_indices)

				# Calculate actual seednum (base_seednum * number of groups)
				num_groups = len(self.helper_groups)
				self.seednum = self.base_seednum * num_groups if num_groups > 0 else self.base_seednum

				if self.logdebug:
					print(f"Helper strategy: specified")
					print(f"Parsed helper groups: {self.helper_groups}")
					print(f"Number of groups: {num_groups}")
					print(f"Base seednum: {self.base_seednum}, Total seednum: {self.seednum}")
			except ValueError as e:
				print(f"Error parsing helper indices '{helper_indices}': {e}")
				print("Falling back to random helper strategy")
				self.helper_strategy = "random"
				self.seednum = self.base_seednum
		else:
			self.seednum = self.base_seednum
			if self.logdebug:
				print(f"Helper strategy: {self.helper_strategy}")

		# Initialize context and semantic rules
		self._init_context_and_rules()


		# Initialize CSV statistics file path
		# CSV file path is now configurable via constructor parameter
		self.statistics_csv_file = stats_csv_file

		# Store run_id for tracking this execution run
		self.run_id = run_id

		# Determine experiment component based on configuration
		feedback_enabled = fixcompile or fixverifier
		if enable_semantic and feedback_enabled:
			self.experiment_component = "Base + Semantic + Feedback"
		elif enable_semantic:
			self.experiment_component = "Base + Semantic"
		elif feedback_enabled:
			self.experiment_component = "Base + Feedback"
		else:
			self.experiment_component = "Base"

		if logdebug:
			print(f"Run ID: {self.run_id}")
			print(f"Experiment Component: {self.experiment_component}")

		# Update seedcorpus to include experiment subdirectory
		experiment_subdir = self._get_experiment_subdirectory()
		self.vm_context.seedcorpus = os.path.join(self.vm_context.seedcorpus, experiment_subdir)
		# Create subdirectory if it doesn't exist
		os.makedirs(self.vm_context.seedcorpus, exist_ok=True)
		if logdebug:
			print(f"Seed corpus directory: {self.vm_context.seedcorpus}")

		self._build_graph()
		if self.logdebug:
			print(f"LLMBPFSEED Init: args_url: {args_url}, args_provider: {args_provider}, args_key: {args_key}, langfuse: {langfuse}")
			print(self.graph.get_graph().draw_ascii())

	def _init_model(self, args_url, args_provider) -> Any:
		match args_provider:
			case "openai":
				self.llm_model = ChatOpenAI(
					temperature=1,
					# top_p=1.0,
					model="gpt-4o",
					verbose=True,
					max_tokens=None,
					timeout=None,
					max_retries=2,
					streaming=True,
				)
			case "deepseek":
				self.llm_model = ChatDeepSeek(
					model="deepseek-chat",
					# model="deepseek-reasoner",
					temperature=0.5,
					max_tokens=None,
				)
			case "xai":
				self.llm_model = ChatXAI(
					model="grok-3-beta",
					# model="grok-3-fast-beta",
					temperature=0.5,
					max_tokens=None,
					timeout=None,
					max_retries=2,
				)
			case "gemini":
				self.llm_model = ChatGoogleGenerativeAI(
					model="gemini-2.5-pro",
					temperature=0.5,
					max_tokens=None,
					timeout=None,
					max_retries=1,
				)
			case "claude":
				claude_kwargs = {
					"model": "claude-sonnet-4-5-20250929",
					"temperature": 0.5,
					"max_tokens": 64000,
					"max_retries": 1,
				}
				base_url = os.environ.get("ANTHROPIC_BASE_URL", "")
				if base_url:
					if base_url.endswith("/v1/messages"):
						base_url = base_url[:-len("/v1/messages")]
					claude_kwargs["base_url"] = base_url
				self.llm_model = ChatAnthropic(**claude_kwargs)

		self._llm_generate_initial_seed = AgentDef.def_generate_initial_seed(self.llm_model, self.vm_context)
		self._llm_analysis_compile_log = AgentDef.def_analysis_compile_log(self.llm_model, self.vm_context)
		self._llm_analysis_verifier_log = AgentDef.def_analysis_verifier_log(self.llm_model, self.vm_context)
		self._llm_mutate_seed = AgentDef.def_mutate_seed(self.llm_model, self.vm_context)

	def _build_graph(self):
		graph = StateGraph(State)
		graph.add_node("generate_seed", self.generate_seed)
		graph.add_node("compile_insn", self.compile_insn)
		graph.add_node("run_verifier", self.run_verifier)

		if self.enable_mutate:
				graph.add_node("mutate_seed", self.mutate_seed)
				graph.add_edge("generate_seed", "mutate_seed")
				graph.add_edge("mutate_seed", "compile_insn")
		else:
				graph.add_edge("generate_seed", "compile_insn")

		if self.enable_fix_compile:
			graph.add_node("fix_compile", self.fix_compile_issue)
			graph.add_edge("fix_compile", "compile_insn")
			graph.add_conditional_edges(
				"compile_insn",
				self.check_grammar,
				{"SUCC": "run_verifier", "FAIL": "fix_compile", END: END}
			)
		else:
			# When fix_compile is disabled, handle compile failures gracefully
			graph.add_node("handle_compile_fail", self.handle_compile_failure)
			graph.add_conditional_edges(
				"compile_insn",
				self.check_grammar,
				{"SUCC": "run_verifier", "FAIL": "handle_compile_fail", END: END}
			)
			graph.add_conditional_edges(
				"handle_compile_fail",
				self.check_failure_continue,
				{"CONT": "generate_seed", END: END}
			)

		if self.enable_fix_verifier:
			graph.add_node("fix_verifier", self.fix_verifier_issue)
			graph.add_node("handle_verifier_fail", self.handle_verifier_failure)  # For max rounds exceeded
			graph.add_edge("fix_verifier", "compile_insn")
			graph.add_conditional_edges(
				"run_verifier",
				self.check_semantic,
				{"CONT": "generate_seed", "FAIL": "fix_verifier", "MAX_EXCEEDED": "handle_verifier_fail", END: END}
			)
			graph.add_conditional_edges(
				"handle_verifier_fail",
				self.check_failure_continue,
				{"CONT": "generate_seed", END: END}
			)
		else:
			# When fix_verifier is disabled, handle verifier failures gracefully
			graph.add_node("handle_verifier_fail", self.handle_verifier_failure)
			graph.add_conditional_edges(
				"run_verifier",
				self.check_semantic,
				{"CONT": "generate_seed", "FAIL": "handle_verifier_fail", END: END}
			)
			graph.add_conditional_edges(
				"handle_verifier_fail",
				self.check_failure_continue,
				{"CONT": "generate_seed", END: END}
			)
		graph.set_entry_point("generate_seed")

		memory = MemorySaver()
		self.graph = graph.compile(checkpointer=memory)
		

	def _init_langfuse(self):
		langfuse_handler = CallbackHandler()
		self.config["callbacks"] = [langfuse_handler]

	def _get_model_name(self) -> str:
		"""Get the model name from the LLM model, handling different attribute names."""
		if hasattr(self.llm_model, 'model_name'):
			return self.llm_model.model_name
		elif hasattr(self.llm_model, 'model'):
			return self.llm_model.model
		else:
			return self.llm_model.__class__.__name__

	def _get_experiment_subdirectory(self) -> str:
		"""Convert experiment_component to subdirectory name.

		Maps experiment component to a filesystem-friendly subdirectory name:
		- "Base" → "base"
		- "Base + Semantic" → "base_semantic"
		- "Base + Feedback" → "base_feedback"
		- "Base + Semantic + Feedback" → "base_semantic_feedback"
		"""
		component_to_dir = {
			"Base": "base",
			"Base + Semantic": "base_semantic",
			"Base + Feedback": "base_feedback",
			"Base + Semantic + Feedback": "base_semantic_feedback",
		}
		return component_to_dir.get(self.experiment_component, "base")

	def _detect_helper_coverage(self, seed_file_path: str) -> tuple:
		"""Detect helper coverage in the generated seed.

		Compares actual helpers in the seed with target helpers to determine coverage.

		Args:
			seed_file_path: Path to the generated seed file

		Returns:
			tuple: (coverage_type, actual_helpers_list, target_helpers_list)
				- coverage_type: 'full', 'partial', 'none', or 'n_a' (for random strategy)
				- actual_helpers_list: List of helper names found in the seed
				- target_helpers_list: List of target helper names
		"""
		import re

		# For random strategy, return N/A
		if self.helper_strategy != "specified" or not self._selected_helpers:
			return ("n_a", [], [])

		# Extract target helper names from _selected_helpers
		# Format: '"BPF_FUNC_xxx": {...}' -> 'BPF_FUNC_xxx'
		target_helpers = set()
		for helper_detail in self._selected_helpers:
			match = re.match(r'"(BPF_FUNC_\w+)":', helper_detail)
			if match:
				target_helpers.add(match.group(1))

		if not target_helpers:
			return ("n_a", [], [])

		# Read the seed file and extract actual helpers
		actual_helpers = set()
		try:
			with open(seed_file_path, 'r', encoding='utf-8') as f:
				content = f.read()
				# Match BPF_EMIT_CALL(BPF_FUNC_xxx) or BPF_FUNC_xxx patterns
				helper_pattern = re.compile(r'BPF_FUNC_\w+')
				found_helpers = helper_pattern.findall(content)
				actual_helpers = set(found_helpers)
		except Exception as e:
			if self.logdebug:
				print(f"Warning: Failed to read seed file for helper detection: {e}")
			return ("none", [], list(target_helpers))

		# Determine coverage type
		target_helpers_list = list(target_helpers)
		actual_helpers_list = list(actual_helpers)

		if target_helpers <= actual_helpers:
			# All target helpers are present (may have additional helpers)
			coverage_type = "full"
		elif target_helpers & actual_helpers:
			# Some but not all target helpers are present
			coverage_type = "partial"
		else:
			# No target helpers are present
			coverage_type = "none"

		if self.logdebug:
			print(f"[Helper Coverage] Target: {target_helpers_list}")
			print(f"[Helper Coverage] Actual: {actual_helpers_list}")
			print(f"[Helper Coverage] Type: {coverage_type}")

		return (coverage_type, actual_helpers_list, target_helpers_list)

	def _get_model_pricing(self) -> dict:
		"""
		Get pricing information for the current model.

		Returns:
			dict with keys: input_price, output_price, cache_creation_price, cache_read_price (all in $/MTok)
		"""
		# Model pricing configuration (price unit: USD per Million Tokens)
		MODEL_PRICING = {
			# Claude models (Anthropic)
			'claude-sonnet-4-5-20250929': {
				'input_price': 3.0,
				'output_price': 15.0,
				'cache_creation_price': 3.75,
				'cache_read_price': 0.30,
			},
			'claude-haiku-4-5-20251001': {
				'input_price': 1.0,
				'output_price': 5.0,
				'cache_creation_price': 1.25,
				'cache_read_price': 0.10,
			},

			# GPT models (OpenAI)
			'gpt-4o': {
				'input_price': 2.5,
				'output_price': 10.0,
				'cache_creation_price': 2.5,
				'cache_read_price': 1.25,  # 50% discount
			},
			'gpt-4o-2024-11-20': {
				'input_price': 2.5,
				'output_price': 10.0,
				'cache_creation_price': 2.5,
				'cache_read_price': 1.25,
			},

			# DeepSeek models
			'deepseek-chat': {
				'input_price': 0.14,
				'output_price': 0.28,
				'cache_creation_price': 0.14,
				'cache_read_price': 0.014,  # 90% discount
			},
			'deepseek-reasoner': {
				'input_price': 0.55,
				'output_price': 2.19,
				'cache_creation_price': 0.55,
				'cache_read_price': 0.055,
			},

			# Google Gemini models
			'gemini-2.5-pro': {
				'input_price': 1.25,
				'output_price': 10.0,
			},
		}

		# Default pricing (if model not in configuration)
		DEFAULT_PRICING = {
			'input_price': 3.0,
			'output_price': 15.0,
			'cache_creation_price': 3.75,
			'cache_read_price': 0.30,
		}

		model_name = self._get_model_name()
		pricing = MODEL_PRICING.get(model_name, DEFAULT_PRICING)

		if self.logdebug and model_name not in MODEL_PRICING:
			print(f"Warning: No pricing found for model '{model_name}', using default pricing")

		return pricing

	def _init_context_and_rules(self):
		"""Initialize instruction context and semantic rules."""
		self._insn_context = '''
			## 3. Knowledge & Context

			### BPF Instructions Basic Knowledge

			**Context**: This section serves as the definitive technical reference for all BPF instruction syntax.
				The generated program must strictly adhere to the provided C macro definitions.

			**Task**: When generating any BPF instruction, use the exact structure and values defined in the `Instruction Definitions` below.
				Additionally, ensure all generated code complies with the `Semantic Rules`.

			**Instruction Definitions**:
		'''
		# Get BPF instruction set definitions
		self._insn_context += "\n```c\n"
		self._insn_context += "\n".join(get_insns_defs())
		self._insn_context += "\n```\n"

		self._semantic_rules = self._build_semantic_rules()

	def _build_semantic_rules(self) -> str:
		"""
		Build BPF verifier semantic rules.
		This section describes the verifier rules that BPF programs must follow.
		"""
		return '''
			### **Semantic Rules**

			#### **Category 1: Register Rules**

			1.  **Register State at Entry**:
			At the start of a program, only `BPF_REG_1` (context pointer) and `BPF_REG_10` (frame pointer) are initialized and readable. All other general-purpose registers (`R0`, `R2`-`R9`) are considered uninitialized.

			2.  **Initialization Before Read**:
			A register **MUST** be written to (i.e., be a destination operand) before it can be read from (i.e., be a source operand). This includes being the source for ALU operations, moves, memory stores, or helper function arguments.

			3.  **Frame Pointer (BPF_REG_10)**:
			This register is **read-only** and its value is constant throughout the program. It can only be used as a base for memory addressing and cannot be the destination of any move or ALU operation.

			4.  **Return Value & Exit Code (BPF_REG_0)**:
			This register has a special role. It holds the return value from helper function calls and is used to pass the final exit code of the program. Be mindful that its contents are overwritten by every helper call.

			5.  **Helper Argument Type Safety**:
			Arguments passed to a helper function in registers `R1`-`R5` must strictly match the types expected by the function's signature. The verifier tracks register types (e.g., `ctx`, `sock*`, `map*`, `ptr_to_stack`, `scalar_value`). Passing a register with an incorrect type will result in an error.

			#### **Category 2: Memory Rules**

			6.  **Stack Buffer Initialization**:
			When passing a pointer to a stack-allocated buffer to a helper function, the **entire memory region** defined by the pointer and its size argument **MUST** be initialized before the helper call. The verifier will not allow a helper to read from uninitialized stack slots.

			#### **Category 3: Control Flow & Program Structure Rules**

			7.  **Pseudo-Instructions (`BPF_LD_IMM64`)**:
			The `BPF_LD_IMM64` macro expands to two `bpf_insn` structs. This must be accounted for when calculating instruction counts or relative jump offsets.

			8.  **No Unreachable Code (Dead Code)**:
			Do not generate instructions that can never be executed (e.g., code immediately following an unconditional `BPF_JMP_A` or a `BPF_EXIT_INSN`). The verifier performs static analysis to ensure all instructions are reachable.

			9.  **Valid Program Exit**:
			A program must end with a `BPF_EXIT_INSN` or an unconditional jump that eventually leads to one. When exiting via `BPF_EXIT_INSN`, the value in `BPF_REG_0` determines the exit code, which for many program types should be a specific, well-defined constant (e.g., `XDP_PASS`, `TC_ACT_OK`, or a simple 0/1 for success/failure).
		'''

	def _build_generation_logic(self) -> str:
		"""
		Build helper generation logic algorithm description.
		This section describes how to generate correct BPF code blocks for each helper.
		"""
		return '''
#### **Generation Logic (Algorithm)**

For each helper in the `Target Helper Library`, follow this intelligent dependency resolution algorithm:

1.  **Analyze the Target Helper**:
    *   **Find or Infer Proto**: Determine its `bpf_func_proto` using:
        1.  **Direct Lookup (Priority 1)**: Use the Task-Specific Prototypes above
        2.  **Fallback Inference (Priority 2)**: Use patterns from Illustrative Examples in the system message
    *   **Identify Argument Requirements**: Based on the proto, identify required verifier types

2.  **Resolve Preamble Dependencies (Setup)**:
    *   **Match Return to Arg**: Find provider helpers whose `ret_type` matches argument requirements
    *   **Selection & Chaining**: Generate BPF instructions for provider helpers
    *   **Handle Return State**: Generate NULL checks for `PTR_MAYBE_NULL` return types

3.  **Generate the Target Call**:
    *   Prepare all arguments ensuring type compatibility
    *   Generate the `BPF_EMIT_CALL` for the target helper

4.  **Resolve Postamble Dependencies (Teardown)**:
    *   Find teardown helpers for resources (look for `OBJ_RELEASE` flag)
    *   Generate cleanup instructions

5.  **Randomize and Isolate**:
    *   Ensure self-contained, valid unit
    *   Apply randomization per requirements

---
'''

	def _build_static_type_definitions(self) -> str:
		"""
		Build static BPF type definitions and example patterns.
		This content is the same across all requests and should be cached.
		"""
		type_context = '''
#### **Knowledge Base: BPF Verifier Type System**

This section is the authoritative source for the verifier's type-checking logic.

**1. BPF Type Definitions:**
*This section defines the fundamental enums (`bpf_reg_type`, `bpf_arg_type`, `bpf_return_type`, `bpf_type_flag`).*
'''
		type_context += "\n```c\n"
		type_context += "\n".join(get_reg_types_defs())
		type_context += "\n```\n"

		# Illustrative Examples
		type_context += '''
**2. BPF Helper Prototypes (`bpf_func_proto`)**

**B. Illustrative Examples for Fallback Inference:**
*If a required helper function is NOT listed in the "Task-Specific Prototypes", infer its proto from these patterns.*

```c
// Pattern 1: Basic Map Operation (Key -> Value Pointer)
static const struct bpf_func_proto bpf_map_lookup_elem_proto = {{
	.ret_type	= RET_PTR_TO_MAP_VALUE_OR_NULL,
	.arg1_type	= ARG_CONST_MAP_PTR,
	.arg2_type	= ARG_PTR_TO_MAP_KEY,
}};

// Pattern 2: Context-based Socket Lookup (CTX -> Typed Pointer)
static const struct bpf_func_proto bpf_sk_lookup_tcp_proto = {{
	.ret_type	= RET_PTR_TO_SOCKET_OR_NULL,
	.arg1_type	= ARG_PTR_TO_CTX,
	.arg2_type	= ARG_PTR_TO_MEM | MEM_RDONLY,
	.arg3_type	= ARG_CONST_SIZE,
}};

// Pattern 3: Resource Release (Typed Pointer -> Void)
static const struct bpf_func_proto bpf_sk_release_proto = {{
	.ret_type	= RET_VOID,
	.arg1_type	= ARG_PTR_TO_BTF_ID_SOCK_COMMON | OBJ_RELEASE,
}};

// Pattern 4: Writing to an Uninitialized Buffer (Output Buffer)
static const struct bpf_func_proto bpf_probe_read_kernel_proto = {{
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_UNINIT_MEM,
	.arg2_type	= ARG_CONST_SIZE_OR_ZERO,
	.arg3_type	= ARG_ANYTHING,
}};

// Pattern 5: Ring Buffer Interaction (Reserve/Submit cycle)
static const struct bpf_func_proto bpf_ringbuf_reserve_proto = {{
	.ret_type	= RET_PTR_TO_RINGBUF_MEM_OR_NULL,
	.arg1_type	= ARG_CONST_MAP_PTR,
	.arg2_type	= ARG_CONST_ALLOC_SIZE_OR_ZERO,
}};
static const struct bpf_func_proto bpf_ringbuf_submit_proto = {{
	.ret_type	= RET_VOID,
	.arg1_type	= ARG_PTR_TO_RINGBUF_MEM | OBJ_RELEASE,
}};

// Pattern 6: BTF-ID Typed Pointers (Kernel Data Structures)
static const struct bpf_func_proto bpf_get_current_task_btf_proto = {{
	.ret_type	= RET_PTR_TO_BTF_ID_TRUSTED,
	.ret_btf_id	= &btf_tracing_ids[BTF_TRACING_TYPE_TASK],
}};
static const struct bpf_func_proto bpf_task_storage_delete_proto = {{
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_CONST_MAP_PTR,
	.arg2_type	= ARG_PTR_TO_BTF_ID_OR_NULL,
	.arg2_btf_id	= &btf_tracing_ids[BTF_TRACING_TYPE_TASK],
}};

// Pattern 7: Function Pointers as Arguments (Callbacks)
static const struct bpf_func_proto bpf_for_each_map_elem_proto = {{
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_CONST_MAP_PTR,
	.arg2_type	= ARG_PTR_TO_FUNC,
	.arg3_type	= ARG_PTR_TO_STACK_OR_NULL,
}};

// Pattern 8: Dynamic Pointer (DynPtr) Interaction
static const struct bpf_func_proto bpf_dynptr_from_mem_proto = {{
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_UNINIT_MEM,
	.arg2_type	= ARG_CONST_SIZE_OR_ZERO,
	.arg3_type	= ARG_ANYTHING,
	.arg4_type	= ARG_PTR_TO_DYNPTR | DYNPTR_TYPE_LOCAL | MEM_UNINIT | MEM_WRITE,
}};
static const struct bpf_func_proto bpf_dynptr_read_proto = {{
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_UNINIT_MEM,
	.arg2_type	= ARG_CONST_SIZE_OR_ZERO,
	.arg3_type	= ARG_PTR_TO_DYNPTR | MEM_RDONLY,
}};

// Pattern 9: Pointer to Fixed-Size, Aligned Memory
static const struct bpf_func_proto bpf_strtoul_proto = {{
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_MEM | MEM_RDONLY,
	.arg2_type	= ARG_CONST_SIZE,
	.arg3_type	= ARG_ANYTHING,
	.arg4_type	= ARG_PTR_TO_FIXED_SIZE_MEM | MEM_UNINIT | MEM_WRITE | MEM_ALIGNED,
	.arg4_size	= sizeof(u64),
}};

// Pattern 10: Per-CPU Data Access
static const struct bpf_func_proto bpf_this_cpu_ptr_proto = {{
	.ret_type	= RET_PTR_TO_MEM_OR_BTF_ID | MEM_RDONLY,
	.arg1_type	= ARG_PTR_TO_PERCPU_BTF_ID,
}};

// Pattern 11: Stateful Object Lifecycle (Timers)
static const struct bpf_func_proto bpf_timer_init_proto = {{
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_TIMER,
	.arg2_type	= ARG_CONST_MAP_PTR,
	.arg3_type	= ARG_ANYTHING,
}};
static const struct bpf_func_proto bpf_timer_start_proto = {{
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_TIMER,
	.arg2_type	= ARG_ANYTHING,
	.arg3_type	= ARG_ANYTHING,
}};
```
'''

		return type_context

	def _build_all_helpers_json(self) -> str:
		"""
		Build JSON of all helper definitions.
		This is the largest static content block (~50,000 tokens) and must be cached.
		"""
		if len(self._all_helpers) == 0:
			_, all_helpers = get_random_helpers()
			self._all_helpers = all_helpers

		helpers_json = "\n**All Helper Definitions (Complete Reference):**\n"
		helpers_json += "\n```json\n"
		helpers_json += "\n".join(self._all_helpers)
		helpers_json += "\n```\n"

		return helpers_json

	def _build_output_format(self) -> str:
		"""
		Build output format specification.
		This content is the same across all requests and should be cached.
		"""
		output_format = '''
## Output Format and Style

The output eBPF bytecode program must be defined in C language.

**CRITICAL - Helper Function Calls**:
- **ALWAYS** use `BPF_EMIT_CALL(BPF_FUNC_xxx)` for calling helper functions
- **NEVER** use numeric function IDs like `BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, 12)`

**Complete Program Example:**
```c
struct bpf_insn prog[] = {{
	BPF_MOV64_REG(BPF_REG_6, BPF_REG_1),
	BPF_EMIT_CALL(BPF_FUNC_skb_change_type),  // ✅ Use symbolic name
	BPF_EXIT_INSN(),
}};
```
'''
		return output_format

	def _build_cached_system_prompt(self) -> SystemMessage:
		"""
		Build cacheable system prompt message (using strategy pattern).
		This content is fixed during seed generation and can be cached by LLM to reduce cost.

		Uses PromptCachingManager to manage caching strategies for different models:
		- Claude (Anthropic): cache_control with ephemeral type (90% cost reduction)
		- GPT-4/GPT-4o (OpenAI): Prompt Caching (50% cost reduction)
		- Gemini (Google): Context Caching (up to 1 hour)
		- DeepSeek/XAI: Not supported, but reusing message objects still has performance benefits

		When enable_semantic=False, only includes output_format (for ablation study).
		"""
		content_blocks = []

		# Semantic enhancement content (only included when enable_semantic=True)
		if self.enable_semantic:
			content_blocks.extend([
				CacheableContent(
					name="instruction_context",
					content=self._insn_context,
					cacheable=self.enable_cache,
					priority=1
				),
				CacheableContent(
					name="semantic_rules",
					content=self._semantic_rules,
					cacheable=self.enable_cache,
					priority=2
				),
				CacheableContent(
					name="static_type_definitions",
					content=self._build_static_type_definitions(),
					cacheable=self.enable_cache,
					priority=3
				),
				CacheableContent(
					name="all_helpers_json",
					content=self._build_all_helpers_json(),
					cacheable=self.enable_cache,
					priority=4  # Largest block, most important, placed last for caching
				),
			])

		# Base content (always included)
		content_blocks.append(
			CacheableContent(
				name="output_format",
				content=self._build_output_format(),
				cacheable=self.enable_cache,
				priority=5 if self.enable_semantic else 1
			)
		)

		# Use strategy manager to build message (automatically applies correct caching strategy)
		return self.caching_manager.build_cached_system_message(content_blocks)

	def _extract_token_usage(self, llm_response: Any) -> dict:
		"""
		Extract token usage information from LLM response.

		Supports different response formats:
		- LangChain AIMessage with response_metadata
		- Dict with messages list
		- Direct AIMessage

		Returns:
			dict with keys: input_tokens, output_tokens, cache_creation_input_tokens, cache_read_input_tokens
		"""
		usage = {
			'input_tokens': 0,
			'output_tokens': 0,
			'cache_creation_input_tokens': 0,
			'cache_read_input_tokens': 0
		}

		try:
			def read_usage_field(metadata: Any, key: str, default: int = 0) -> int:
				if isinstance(metadata, dict):
					return metadata.get(key, default)
				return getattr(metadata, key, default)

			# Case 1: Response is a dict with 'messages' key
			if isinstance(llm_response, dict) and 'messages' in llm_response:
				if llm_response['messages']:
					last_message = llm_response['messages'][-1]
					if hasattr(last_message, 'response_metadata'):
						metadata = last_message.response_metadata
						if 'usage' in metadata:
							for key in usage:
								usage[key] = read_usage_field(metadata['usage'], key, usage[key])

			# Case 2: Response is an AIMessage directly
			elif hasattr(llm_response, 'response_metadata'):
				metadata = llm_response.response_metadata
				if 'usage' in metadata:
					for key in usage:
						usage[key] = read_usage_field(metadata['usage'], key, usage[key])

			# Case 3: Response has usage_metadata attribute (newer LangChain)
			elif hasattr(llm_response, 'usage_metadata'):
				metadata = llm_response.usage_metadata
				usage['input_tokens'] = read_usage_field(metadata, 'input_tokens', 0)
				usage['output_tokens'] = read_usage_field(metadata, 'output_tokens', 0)
				# Cache tokens might be in different field names
				usage['cache_creation_input_tokens'] = read_usage_field(metadata, 'cache_creation_input_tokens', 0)
				usage['cache_read_input_tokens'] = read_usage_field(metadata, 'cache_read_input_tokens', 0)

		except Exception as e:
			if self.logdebug:
				print(f"Warning: Failed to extract token usage: {e}")

		return usage

	def _accumulate_token_usage(self, llm_response: Any, operation: str = ""):
		"""
		Extract and accumulate token usage.

		Args:
			llm_response: LLM response object
			operation: Operation description (for logging)
		"""
		usage = self._extract_token_usage(llm_response)

		self.total_input_tokens += usage['input_tokens']
		self.total_output_tokens += usage['output_tokens']
		self.total_cache_creation_tokens += usage['cache_creation_input_tokens']
		self.total_cache_read_tokens += usage['cache_read_input_tokens']

		if self.logdebug and any(usage.values()):
			print(f"\n[Token Usage - {operation}]")
			print(f"  Input: {usage['input_tokens']:,}")
			print(f"  Output: {usage['output_tokens']:,}")
			if usage['cache_creation_input_tokens'] > 0:
				print(f"  Cache Creation: {usage['cache_creation_input_tokens']:,}")
			if usage['cache_read_input_tokens'] > 0:
				print(f"  Cache Read: {usage['cache_read_input_tokens']:,}")

	def _reset_token_counters(self):
		"""Reset token counters and timing statistics (called when generating new seed)"""
		self.total_input_tokens = 0
		self.total_output_tokens = 0
		self.total_cache_creation_tokens = 0
		self.total_cache_read_tokens = 0

		# Reset timing statistics
		self.total_llm_time = 0
		self.total_compile_time = 0
		self.total_verifier_time = 0

		# Reset retry counter for new seed generation round
		self.current_retry_count = 0

	def _invoke_with_retry(self, llm_chain, inputs: dict, operation_name: str = "LLM"):
		"""
		Invoke LLM chain with retry logic for network errors.

		Args:
			llm_chain: The LLM chain to invoke
			inputs: Input dictionary for the chain
			operation_name: Name of the operation for logging

		Returns:
			The result of the LLM invocation

		Raises:
			APIConnectionError: If all retry attempts are exhausted
		"""
		# Tuple of all network-related exceptions from various LLM providers
		network_exceptions = (
			# Anthropic (Claude)
			AnthropicConnectionError, AnthropicTimeoutError,
			# OpenAI (GPT, also used by DeepSeek and some others)
			OpenAIConnectionError, OpenAITimeoutError,
			# httpx (common HTTP client used by most LLM SDKs)
			httpx.ConnectError, httpx.TimeoutException, httpx.ConnectTimeout, httpx.ReadTimeout,
			# requests (fallback for some providers like Google)
			requests.exceptions.ConnectionError, requests.exceptions.Timeout,
		)

		while self.current_retry_count < self.max_retry_attempts:
			try:
				return llm_chain.invoke(inputs)
			except network_exceptions as e:
				self.current_retry_count += 1
				backoff_time = self.current_retry_count * self.base_backoff_seconds

				if self.current_retry_count < self.max_retry_attempts:
					print(f"\n[Network Error] {operation_name} failed: {type(e).__name__}")
					print(f"[Retry] Attempt {self.current_retry_count}/{self.max_retry_attempts}")
					print(f"[Retry] Waiting {backoff_time} seconds before next attempt...")
					time.sleep(backoff_time)
				else:
					print(f"\n[Network Error] {operation_name} failed after {self.max_retry_attempts} attempts")
					print(f"[Exit] This seed generation will be abandoned, thread exiting gracefully...")
					raise

		# This should not be reached, but just in case
		raise APIConnectionError("Max retry attempts exceeded")

	def _print_token_statistics(self) -> float:
		"""
		Print token usage statistics for the current seed.

		Returns:
			total_cost: Total cost in USD
		"""
		total_tokens = (
			self.total_input_tokens +
			self.total_output_tokens +
			self.total_cache_creation_tokens +
			self.total_cache_read_tokens
		)
		total_elapsed = max(time.time() - self.start_time, 0.0)

		def token_percent(token_count: int) -> float:
			return (token_count / total_tokens * 100) if total_tokens > 0 else 0.0

		def time_percent(duration: float) -> float:
			return (duration / total_elapsed * 100) if total_elapsed > 0 else 0.0

		# Get current model pricing
		pricing = self._get_model_pricing()
		model_name = self._get_model_name()

		# Calculate actual cost
		input_cost = self.total_input_tokens * pricing['input_price'] / 1_000_000
		output_cost = self.total_output_tokens * pricing['output_price'] / 1_000_000
		cache_creation_cost = self.total_cache_creation_tokens * pricing['cache_creation_price'] / 1_000_000
		cache_read_cost = self.total_cache_read_tokens * pricing['cache_read_price'] / 1_000_000
		total_cost = input_cost + output_cost + cache_creation_cost + cache_read_cost

		# Calculate theoretical cost (no-cache assumption: all input-related tokens at input_price)
		total_input_related_tokens = (
			self.total_input_tokens +
			self.total_cache_creation_tokens +
			self.total_cache_read_tokens
		)
		theoretical_input_cost = total_input_related_tokens * pricing['input_price'] / 1_000_000
		theoretical_total_cost = theoretical_input_cost + output_cost
		cost_saved = theoretical_total_cost - total_cost
		cost_saved_percent = (cost_saved / theoretical_total_cost * 100) if theoretical_total_cost > 0 else 0

		print("\n" + "="*70)
		print(f"Token Usage Statistics - Seed #{self.seedcnt} ({model_name})")
		print("="*70)
		print(f"Input tokens:           {self.total_input_tokens:>10,}  ({token_percent(self.total_input_tokens):>5.1f}%)  ${input_cost:.4f}")
		print(f"Output tokens:          {self.total_output_tokens:>10,}  ({token_percent(self.total_output_tokens):>5.1f}%)  ${output_cost:.4f}")

		if self.total_cache_creation_tokens > 0:
			print(f"Cache creation tokens:  {self.total_cache_creation_tokens:>10,}  ({token_percent(self.total_cache_creation_tokens):>5.1f}%)  ${cache_creation_cost:.4f}")

		if self.total_cache_read_tokens > 0:
			print(f"Cache read tokens:      {self.total_cache_read_tokens:>10,}  ({token_percent(self.total_cache_read_tokens):>5.1f}%)  ${cache_read_cost:.4f}")

		print("-"*70)
		print(f"Total:                  {total_tokens:>10,}  ({100.0 if total_tokens > 0 else 0.0:>5.1f}%)  ${total_cost:.4f}")
		print(f"Theoretical (no cache):                         ${theoretical_total_cost:.4f}")
		print(f"Saved:                                          ${cost_saved:.4f} ({cost_saved_percent:.1f}%)")
		print("-"*70)
		print(f"Compile fix rounds: {self.compile_total}")
		print(f"Verifier fix rounds: {self.verifier_total}")

		# Timing statistics
		other_time = total_elapsed - (self.total_llm_time + self.total_compile_time + self.total_verifier_time)

		print("-"*70)
		print(f"Total time:             {total_elapsed:>10.2f}s  ({100.0 if total_elapsed > 0 else 0.0:>5.1f}%)")
		print(f"  ├─ LLM inference:     {self.total_llm_time:>10.2f}s  ({time_percent(self.total_llm_time):>5.1f}%)")
		print(f"  ├─ Compile:           {self.total_compile_time:>10.2f}s  ({time_percent(self.total_compile_time):>5.1f}%)")
		print(f"  ├─ Verifier:          {self.total_verifier_time:>10.2f}s  ({time_percent(self.total_verifier_time):>5.1f}%)")
		print(f"  └─ Other:             {other_time:>10.2f}s  ({time_percent(other_time):>5.1f}%)")
		print("="*70 + "\n")

		return total_cost

	def _record_seed_statistics(self, success: bool = True, seed_category: str = "success",
							helper_coverage: str = "n_a", target_helpers: list = None,
							actual_helpers: list = None):
		"""
		Record seed generation statistics to CSV file.

		Args:
			success: Whether the seed was generated successfully
			seed_category: One of 'success', 'usable', 'failed'
			helper_coverage: One of 'full', 'partial', 'none', 'n_a'
			target_helpers: List of target helper names
			actual_helpers: List of actual helper names found in seed
		"""
		if target_helpers is None:
			target_helpers = []
		if actual_helpers is None:
			actual_helpers = []
		try:
			# Get model pricing
			pricing = self._get_model_pricing()
			model_name = self._get_model_name()

			# Calculate actual cost
			input_cost = self.total_input_tokens * pricing['input_price'] / 1_000_000
			output_cost = self.total_output_tokens * pricing['output_price'] / 1_000_000
			cache_creation_cost = self.total_cache_creation_tokens * pricing['cache_creation_price'] / 1_000_000
			cache_read_cost = self.total_cache_read_tokens * pricing['cache_read_price'] / 1_000_000
			total_cost = input_cost + output_cost + cache_creation_cost + cache_read_cost

			# Calculate theoretical cost (no-cache assumption: all input-related tokens at input_price)
			total_input_related_tokens = (
				self.total_input_tokens +
				self.total_cache_creation_tokens +
				self.total_cache_read_tokens
			)
			theoretical_input_cost = total_input_related_tokens * pricing['input_price'] / 1_000_000
			theoretical_total_cost = theoretical_input_cost + output_cost
			cost_saved = theoretical_total_cost - total_cost
			cost_saved_percent = (cost_saved / theoretical_total_cost * 100) if theoretical_total_cost > 0 else 0

			# Calculate total time
			total_time = time.time() - self.start_time

			# Calculate other time
			other_time = total_time - (self.total_llm_time + self.total_compile_time + self.total_verifier_time)

			# Calculate theoretical input tokens (for summary statistics)
			theoretical_input_tokens = total_input_related_tokens

			# Prepare data to write
			row_data = {
				'run_id': self.run_id,
				'experiment_component': self.experiment_component,
				'seed_filename': self.vm_context.corpus_filename if hasattr(self.vm_context, 'corpus_filename') else 'unknown',
				'model_name': model_name,
				'success': 'success' if success else 'failed',
				'seed_category': seed_category,
				'helper_coverage': helper_coverage,
				'target_helpers': ','.join(target_helpers) if target_helpers else '',
				'actual_helpers': ','.join(actual_helpers) if actual_helpers else '',
				'compile_fixes': self.compile_total,
				'verifier_fixes': self.verifier_total,
				'input_tokens': self.total_input_tokens,
				'output_tokens': self.total_output_tokens,
				'cache_creation_tokens': self.total_cache_creation_tokens,
				'cache_read_tokens': self.total_cache_read_tokens,
				'theoretical_input_tokens': theoretical_input_tokens,
				'total_time_seconds': f"{total_time:.2f}",
				'llm_time_seconds': f"{self.total_llm_time:.2f}",
				'compile_time_seconds': f"{self.total_compile_time:.2f}",
				'verifier_time_seconds': f"{self.total_verifier_time:.2f}",
				'other_time_seconds': f"{other_time:.2f}",
				'total_cost_usd': f"{total_cost:.4f}",
				'theoretical_cost_usd': f"{theoretical_total_cost:.4f}",
				'cost_saved_usd': f"{cost_saved:.4f}",
				'cost_saved_percent': f"{cost_saved_percent:.1f}",
			}

			# Thread-safe CSV writing with class-level lock
			# This prevents race conditions when multiple threads write to the same file
			with LLMBPFSEED._csv_write_lock:
				# Check if file exists INSIDE the lock to prevent header duplication
				file_exists = Path(self.statistics_csv_file).exists()

				# Append to CSV file
				with open(self.statistics_csv_file, 'a', newline='', encoding='utf-8') as csvfile:
					fieldnames = [
						'run_id',
						'experiment_component',
						'seed_filename',
						'model_name',
						'success',
						'seed_category',
						'helper_coverage',
						'target_helpers',
						'actual_helpers',
						'compile_fixes',
						'verifier_fixes',
						'input_tokens',
						'output_tokens',
						'cache_creation_tokens',
						'cache_read_tokens',
						'theoretical_input_tokens',
						'total_time_seconds',
						'llm_time_seconds',
						'compile_time_seconds',
						'verifier_time_seconds',
						'other_time_seconds',
						'total_cost_usd',
						'theoretical_cost_usd',
						'cost_saved_usd',
						'cost_saved_percent',
					]
					writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

					# Write header if file doesn't exist
					if not file_exists:
						writer.writeheader()

					# Write data row
					writer.writerow(row_data)

					# Explicit flush to ensure data is written before releasing lock
					csvfile.flush()

			if self.logdebug:
				print(f"Statistics recorded to {self.statistics_csv_file}")

		except Exception as e:
			print(f"Warning: Failed to record statistics to CSV: {e}")

	def _compress_history(self, conversation: List[Any], keep_recent: int = None) -> List[Any]:
		"""
		Intelligently compress conversation history (Strategy A).
		Keep the most recent N rounds of conversation, compress earlier conversations into a summary.

		Args:
			conversation: Full conversation history (excluding system messages)
			keep_recent: Number of recent rounds to keep, defaults to self.max_history_rounds

		Returns:
			Compressed message list
		"""
		if keep_recent is None:
			keep_recent = self.max_history_rounds

		# If message count is small, return directly
		if len(conversation) <= keep_recent * 2:  # Each round includes user message + AI reply
			return conversation

		# Separate early messages and recent messages
		# Each conversation round includes: user message + AI reply, so it's keep_recent * 2
		recent_messages = conversation[-(keep_recent * 2):]
		early_messages = conversation[:-(keep_recent * 2)]

		# Count early fix rounds
		early_rounds = len(early_messages) // 2

		# Generate summary message
		summary_parts = []
		if early_rounds > 0:
			summary_parts.append(f"📝 Early attempts summary: {early_rounds} fix rounds completed.")

			# Briefly extract key information from early failures
			compile_errors = []
			verifier_errors = []
			for msg in early_messages:
				if hasattr(msg, 'content'):
					content = msg.content
					if "Compile bpf insn failed" in content or "compiler error" in content.lower():
						compile_errors.append("compile_error")
					if "verifier" in content.lower() or "BPF_" in content:
						verifier_errors.append("verifier_error")

			if compile_errors:
				summary_parts.append(f"- Encountered {len(compile_errors)} compile errors")
			if verifier_errors:
				summary_parts.append(f"- Encountered {len(verifier_errors)} verifier errors")

			summary_parts.append("Detailed information of above issues has been omitted. Please focus on recent fix rounds.")

		summary_text = "\n".join(summary_parts)

		if self.logdebug:
			print(f"[History Compression] Original messages: {len(conversation)}, Compressed: {len(recent_messages) + 1}")
			print(f"[History Compression] Summary: {summary_text}")

		# Build compressed history
		compressed = []
		if summary_text:
			compressed.append(HumanMessage(content=summary_text))
		compressed.extend(recent_messages)

		return compressed

	def _build_helper_context(self, selected_helpers: List[str], all_helpers: List[str]) -> str:
		"""
		Build helper context string for the given helpers.

		NOTE: Static content (BPF Type Definitions, All Helpers JSON, Illustrative Examples)
		has been moved to the cached system message for token optimization.
		This method now only contains dynamic, task-specific content.

		When enable_semantic=False, only includes the Target Helper Library list.
		"""
		if not selected_helpers:
			return ""

		helper_context = ""

		# Semantic enhancement content: Task-Specific Helper Prototypes (only included when enable_semantic=True)
		if self.enable_semantic:
			helper_context += '''
### BPF Helpers Requirement

**Overarching Goal**: For each helper function listed in the `Target Helper Library`, generate a logically complete and verifier-compliant BPF code block. This block MUST include not only the target helper call itself, but also any necessary "setup" (preamble) and "teardown" (postamble) helper calls required to make it valid.

---

#### **Task-Specific Helper Prototypes**

**Target Function Prototypes (High Priority):**
*This section contains the precise `bpf_func_proto` definitions for your target helpers. Use these directly when available.*

```c
'''
			# Add task-specific prototypes for selected helpers only
			for helper_detail in selected_helpers:
				helper_name = helper_detail.split('"')[1]
				helper_func_proto = get_func_proto_for_helper(helper_name)
				helper_context += f"{helper_func_proto}\n"

			helper_context += '''```

**Reference**: For BPF type definitions and illustrative examples, see the Knowledge Base in the system message above.

---

'''
			# Add generation logic algorithm description
			helper_context += self._build_generation_logic()

		# Base content: Target Helper Library (always included)
		helper_context += '''
#### **Helper Libraries**
'''
		helper_context += "\n**Target Helper Library:**\n"
		helper_context += "\n```\n"
		helper_context += "\n".join(selected_helpers)
		helper_context += "\n```\n"

		# NOTE: "All Helper Definitions" is now in the cached system message
		# to save ~50,000 tokens in the user message

		# Semantic enhancement content: BPF Program Example (only included when enable_semantic=True)
		if self.enable_semantic:
			helper_context += "\n**BPF Program Example:**\n"
			helper_context += "\n```c\n"
			# Add program examples
			for helper_detail in selected_helpers:
				helper_name = helper_detail.split('"')[1]
				sample_content = self.vm_context.get_sample_for_helper(helper_name)
				helper_context += f"{sample_content}\n"
			helper_context += "```\n"

		return helper_context

	def generate_seed(self, state: State):
		self.compile_round = 0
		self.compile_total = 0
		self.compile_fix_suggestions_history = []
		self.verifier_round = 0
		self.verifier_total = 0
		self.verifier_fix_suggestions_history = []
		print(f"[DEBUG] generate_seed called: seedcnt={self.seedcnt} -> {self.seedcnt + 1}, seednum={self.seednum}, helper_group_idx={self.current_helper_group_index}")
		self.seedcnt += 1
		self.vm_context.init_vars()
		self.start_time = time.time()

		# Initialize conversation history for current seed
		self.current_seed_conversation = []

		# Reset seed save tracking flag
		self._current_seed_saved = False

		# Reset token counters
		self._reset_token_counters()

		# Reset cached helper context unless using "specified" strategy with exactly 1 group
		# - random strategy: helpers change every seed
		# - specified with N groups (N>1): helpers cycle through groups
		# - specified with 1 group: same helpers every seed (can cache)
		should_cache_helpers = (
			self.helper_strategy == "specified"
			and self.helper_groups
			and len(self.helper_groups) == 1
		)
		if not should_cache_helpers:
			self._cached_helper_context = ""

		if self.logdebug:
			print("\n-----------------------------------------------------\n")
			print("Call generate_seed!")
			print(f"Generate the {self.seedcnt} bpf prog using {self._get_model_name()}")

		generate_message = state['messages']

		# Get original message content
		base_content = generate_message[0].content if generate_message else ""

		filler_insn_num = random.randrange(1, 10)
		total_insn_num = random.randrange(filler_insn_num, 12)

		base_content = f'''
			# Smart Assistant prompt: Generate Linux eBPF bytecode program

			## 1. Functional Description (The Goal)

			The program's structure is adaptive based on the number of helpers provided in the `Helper Function Library`.

			**- If the `Helper Function Library` is EMPTY:**
			- The program will be a simple, valid sequence of instructions.
			- It must meet the `Instruction Count` and `Filler Instructions` requirements.
			- It will end by setting a constant value in R0 and calling `BPF_EXIT_INSN()`.

			**- If the `Helper Function Library` is NOT EMPTY:**
			- The program's core goal is to sequentially call ALL helper functions listed.
			- It will execute a self-contained block for each helper, in the order they are provided.
			- After the final helper block, it will exit the program.

			## 2. Randomization Requirements (The "How-to")

			-   **Instruction Variety**: The generated program must use a mix of instruction types (`BPF_ALU`, `BPF_MOV`, `BPF_STX`, `BPF_LDX`, `BPF_JMP`, `BPF_CALL`, `BPF_EXIT`).
			-   **Filler Instructions**: Insert {filler_insn_num} "filler" instructions that do not corrupt the main logic. This applies to the "empty" case and within each helper block in the "non-empty" case.
			-   **Control Flow**: If helpers are called, use a conditional jump after at least one helper call. If no helpers are called, you may optionally include a simple conditional jump that doesn't create a loop.
			-   **Instruction Count**: The total number of instructions should not smaller then {total_insn_num}.
        	'''

		full_content = base_content

		# Select helpers and definitions - based on strategy
		if self.helper_strategy == "specified" and self.helper_groups:
			# Use specified index strategy (enhanced version, supports groups)
			all_helpers = []
			# First get all helper definitions (only need to fetch once)
			if len(self._all_helpers) == 0:
				_, all_helpers = get_random_helpers()
				self._all_helpers = all_helpers
			else:
				all_helpers = self._all_helpers

			# Determine which group to use currently (cyclic usage)
			group_index = self.current_helper_group_index % len(self.helper_groups)
			current_group_indices = self.helper_groups[group_index]

			# Get specified helpers based on current group indices
			selected_helpers = get_helpers_by_indices(current_group_indices, debug=self.logdebug)
			self._selected_helpers = selected_helpers

			print(f"[Specified Strategy] Seed #{self.seedcnt}/{self.seednum}")
			print(f"[Specified Strategy] Using group {group_index + 1}/{len(self.helper_groups)}: {current_group_indices}")
			print(f"[Specified Strategy] Selected helpers: {selected_helpers}, count: {len(selected_helpers)}")

			# Update group index for next generation
			self.current_helper_group_index += 1
		else:
			# Use random strategy (default)
			selected_helpers, all_helpers = get_random_helpers()
			self._selected_helpers = selected_helpers  # Store for use in fix_verifier_issue
			if len(self._all_helpers) == 0:
				self._all_helpers = all_helpers
			print(f"[Random Strategy] Seed #{self.seedcnt}/{self.seednum}")
			print(f"[Random Strategy] Selected helpers: {selected_helpers}, count: {len(selected_helpers)}")

		# Build helper context (only build and cache on first call)
		if not self._cached_helper_context:
			self._cached_helper_context = self._build_helper_context(self._selected_helpers, self._all_helpers)

		if self._cached_helper_context:
			full_content += self._cached_helper_context

		# Build cached system prompt (only build on first call)
		if self._cached_system_prompt is None:
			self._cached_system_prompt = self._build_cached_system_prompt()

		# Build user message
		user_message = HumanMessage(content=full_content)

		# Add message to conversation history
		self.current_seed_conversation.append(user_message)

		# Build complete message list (system prompt + user message)
		messages_to_send = [self._cached_system_prompt, user_message]

		if self.logdebug:
			print(f"[Conversation History] Current conversation messages: {len(self.current_seed_conversation)}")
			print(f"[Conversation History] Messages to send: {len(messages_to_send)}")

		# Invoke LLM with retry
		llm_start = time.time()
		message = self._invoke_with_retry(
			self._llm_generate_initial_seed,
			{"messages": messages_to_send},
			"Generate Initial Seed"
		)
		llm_elapsed = time.time() - llm_start
		self.total_llm_time += llm_elapsed

		message_content = message['messages'][-1].content

		# Accumulate token usage
		self._accumulate_token_usage(message, "Generate Initial Seed")

		# Add AI response to conversation history
		ai_response = message['messages'][-1]  # Get complete AI message object
		self.current_seed_conversation.append(ai_response)

		if self.logdebug:
			print(f"Generate initial bpf prog:\n{message_content}")

		# Create timestamp file and ensure tmpfile is set
		created_file = self.vm_context.create_timestamp_file(message_content, self._get_model_name(), self.logdebug)
		if created_file is None:
			print("Error: Failed to create timestamp file")
		elif self.logdebug:
			print(f"Created file: {created_file}, tmpfile: {self.vm_context.tmpfile}")

		return {'messages': [message_content]}

	def mutate_seed(self, state: State):
		if self.logdebug:
			print("\n-----------------------------------------------------\n")
			print("Call mutate_seed!")
			print(f"Mutate the {self.seedcnt} bpf prog using {self._get_model_name()}")

		current_bpfprog = self.vm_context.extract_bpf_insn(self.vm_context.tmpfile) # Assuming tmpfile contains source to be compiled
		bpfprog_sample_contents = self.vm_context.get_random_sample_contents(self.vm_context.samplescorpus)

		prompt_lines = [
			"""
			## User Requirements:
			Please mutate the target BPF program by referencing the listed BPF program samples.

			## Mutation Rules:
			1. Selection of Mutation Fragments: Randomly select a random number of BPF instruction segments from the BPF program samples. 
				These will be referred to as "mutation instruction segments."
			2. Embedding Mutation Segments: Randomly choose one of the following methods to embed the mutation instruction segments into the target BPF program:
			2.1 Replacement: A mutation instruction segment can replace arbitrary instructions within the target BPF program. 
				However, the number of replaced instructions must not exceed twice the number of instructions contained within the mutation instruction segment.
			2.2 Insertion: A mutation instruction segment can be inserted at a random position within the target BPF program.
			3. Compilation Requirement: The mutated BPF program must adhere to the compiler's syntax rules and compile successfully.
			4. Verification Requirement: The mutated BPF program must satisfy the semantic requirements of the BPF verifier as much as possible.
			"""
		]

		prompt_lines.append("\n## Target BPF Insn Program That Should Be Mutated\n")
		prompt_lines.append(
			"Below is the BPF program that needs to be mutated. Please ensure that the mutated program can be compiled successfully and passes the BPF verifier."
		)
		prompt_lines.append(f"```c\n{current_bpfprog}\n```\n")
		prompt_lines.append("\n## Sample BPF Insn Programs For Mutation Reference:\n")
		prompt_lines.append(
			"Below are BPF program samples. You can refer to these samples for mutation. The specific mutation rules have been listed above."
		)
		for i, bpfprog_sample in enumerate(bpfprog_sample_contents):
			prompt_lines.append(f"\n### BPF Program Sample {i}:\n" + f"```c\n{bpfprog_sample}\n```\n")
		
		final_user_prompt_content = "\n".join(prompt_lines)
		messages_for_llm = [HumanMessage(content=final_user_prompt_content)]

		llm_start = time.time()
		message = self._invoke_with_retry(
			self._llm_mutate_seed,
			{"messages": messages_for_llm},
			"Mutate Seed"
		)
		llm_elapsed = time.time() - llm_start
		self.total_llm_time += llm_elapsed

		message_content = message['messages'][-1].content

		# Accumulate token usage
		self._accumulate_token_usage(message, "Mutate Seed")

		if self.logdebug:
			print(f"Mutate initial bpf prog:\n{message_content}")
		mutate_file_path = f"{self.vm_context.tmpfile}_m"
		self.vm_context.write_to_file(mutate_file_path, message_content)

		return {'messages': [message_content]}
	
	def check_grammar(self, state: State):
		if state['compile_state'] == "SUCC":
			return "SUCC"
		elif state['compile_state'] == "FAIL":
			return "FAIL"
		elif state['compile_state'] == END:
			return END
		
	def compile_insn(self, state: State):
		print("\n-----------------------------------------------------\n")
		print("Call compile_insn!")

		if self.compile_total + self.verifier_total > 100:
			print("The round count is too large, please check the code!")
			return END

		compile_start = time.time()
		succ, compile_log = self.vm_context.compile_bpf_insn(self.vm_context.tmpfile)
		compile_elapsed = time.time() - compile_start
		self.total_compile_time += compile_elapsed

		if not succ:
			print(f"Compile bpf insn failed {compile_log}")
			return {"compile_state": "FAIL"}
		
		print(f"Compile bpf insn succ: {compile_log}")
		return {"compile_state": "SUCC"}

	def fix_compile_issue(self, state: State):
		"""
		Attempts to fix BPF compilation errors by querying an LLM,
		maintaining a history of previous suggestions to guide future attempts.
		Uses conversation history to maintain context (Strategy A + B).
		"""
		print("\n-----------------------------------------------------\n")
		print(f"Call fix_compile_issue! Round: {self.compile_round}")
		self.verifier_round = 0
		self.verifier_fix_suggestions_history = []

		current_bpf_source_text = self.vm_context.extract_bpf_insn(self.vm_context.tmpfile)
		current_compiler_errors = self.vm_context.compile_log

		# Build task prompt (not cached, task-specific)
		task_prompt = """
		## Task: Fix BPF Compilation Errors

		An error occurred when compiling an eBPF program using GCC (Ubuntu 13.3.0-6ubuntu2~24.04) 13.3.0.

		### Your Objectives:
		1. Analyze the provided eBPF C-like source code and the compiler errors
		2. Identify the root cause of each compilation error
		3. Provide a corrected version of the complete eBPF source code

		### Important Notes:
		- The fixed program's **format and intended function** must remain consistent with the original
		- **Preserve all helper function calls** that were specified in the original program
		- Provide **only the complete, corrected eBPF C-like source code** as your primary output
		- Enclose the corrected code in a ```c ... ``` code block
		- You may add brief explanatory comments if helpful

		### Constraints:
		- Do NOT change the program's core logic or purpose
		- Do NOT remove helper function calls unless they are causing the compilation error
		- Ensure the corrected code compiles successfully with GCC

		### CRITICAL - Helper Function Call Format:
		- **ALWAYS** use `BPF_EMIT_CALL(BPF_FUNC_xxx)` for helper calls (e.g., `BPF_EMIT_CALL(BPF_FUNC_tail_call)`)
		- **NEVER** use numeric IDs like `BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, 12)` or `BPF_EMIT_CALL(12)`
		- Use symbolic constant names from the Helper Function Library (e.g., `BPF_FUNC_tail_call`, not `12`)
		"""

		# Build current error details (dynamic content, not cached)
		compiler_error_details = (
			f"\n## Current Problem Details (Attempt {self.compile_round})\n"
			f"\n### eBPF Source Code Under Review:\n"
			f"```c\n{current_bpf_source_text}\n```\n"
			f"\n### Compiler Errors Reported:\n"
			f"```\n{current_compiler_errors}\n```\n"
		)

		# Complete user message
		full_user_message = task_prompt + compiler_error_details

		# Compress history conversation (only keep recent rounds)
		compressed_history = self._compress_history(self.current_seed_conversation)

		# Build new user message
		user_message = HumanMessage(content=full_user_message)

		# Add new message to complete history
		self.current_seed_conversation.append(user_message)

		# Build messages to send to LLM (system prompt + compressed history + new message)
		messages_to_send = [self._cached_system_prompt] + compressed_history + [user_message]

		if self.logdebug:
			print(f"[Conversation History] Compile fix round: {self.compile_round}")
			print(f"[Conversation History] Complete history messages: {len(self.current_seed_conversation)}")
			print(f"[Conversation History] Compressed messages: {len(compressed_history)}")
			print(f"[Conversation History] Total messages to send: {len(messages_to_send)}")

		# Invoke LLM with retry
		llm_start = time.time()
		llm_response_payload = self._invoke_with_retry(
			self._llm_analysis_compile_log,
			{"messages": messages_to_send},
			"Fix Compile Issue"
		)
		llm_elapsed = time.time() - llm_start
		self.total_llm_time += llm_elapsed

		# Accumulate token usage
		self._accumulate_token_usage(llm_response_payload, "Fix Compile Issue")

		# Extract LLM response
		latest_ai_compile_suggestion = ""
		ai_response = None
		if isinstance(llm_response_payload, dict) and "messages" in llm_response_payload:
			if llm_response_payload["messages"] and hasattr(llm_response_payload["messages"][-1], 'content'):
				ai_response = llm_response_payload["messages"][-1]
				latest_ai_compile_suggestion = ai_response.content
			else:
				print("Error: LLM response 'messages' list is empty or last message has no content (compiler).")
				latest_ai_compile_suggestion = "// Error: Malformed LLM response message (compiler)."
		elif hasattr(llm_response_payload, 'content'):
			ai_response = llm_response_payload
			latest_ai_compile_suggestion = llm_response_payload.content
		else:
			print("Error: Unexpected LLM response structure (compiler). Expected a dict with a 'messages' key or a BaseMessage object.")
			latest_ai_compile_suggestion = "// Error: Could not parse LLM response (compiler)."

		# Add AI response to complete history
		if ai_response:
			self.current_seed_conversation.append(ai_response)

		print(f"\n--- LLM Compiler Suggestion (Round {self.compile_round}) ---")
		print(latest_ai_compile_suggestion)

		self.compile_fix_suggestions_history.append(latest_ai_compile_suggestion)

		current_round_compile_log_entry = (
			f"### Suggestions To Fix Compiler Errors, Round {self.compile_round}:\n"
			f"```c\n{latest_ai_compile_suggestion}\n```\n\n"
			f"{full_user_message}"  # Append the full task prompt and error details
		)
		
		compile_log_file_path = f"{self.vm_context.tsfile}_c{self.compile_round}" # Log file for this attempt
		self.vm_context.write_to_file(compile_log_file_path, current_round_compile_log_entry)

		self.vm_context.tmpfile = compile_log_file_path # This is the file to be compiled next
		self.compile_round += 1
		self.compile_total += 1
		return
	
	def check_semantic(self, state: State):
		if state['verifier_state'] == "FAIL":
			# Check if max verifier fix rounds exceeded
			if self.enable_fix_verifier and self.verifier_round >= self.max_verifier_fix_rounds:
				print(f"[Max Rounds Exceeded] Verifier fix rounds ({self.verifier_round}) >= max ({self.max_verifier_fix_rounds})")
				return "MAX_EXCEEDED"
			return "FAIL"
		elif state['verifier_state'] == "CONT":
			return "CONT"
		elif state['verifier_state'] == END:
			return END

	def check_failure_continue(self, state: State):
		"""Check if we should continue generating seeds after a failure."""
		# Check both possible state keys
		if state.get('compile_state') == "CONT" or state.get('verifier_state') == "CONT":
			return "CONT"
		return END

	def handle_compile_failure(self, state: State):
		"""
		Handle compile failure when fix_compile is disabled.
		Saves the failed seed and decides whether to continue generating more seeds.
		"""
		print("\n-----------------------------------------------------\n")
		print("Compilation failed (fix_compile disabled), saving as failed seed...")
		self.save_seed_to_corpus(isfail=True)

		# Check if enough seeds have been generated
		if self.seedcnt >= self.seednum:
			print(f"Generate total {self.seednum} seeds (including failed), finish!")
			# Must set both states to END to ensure graph terminates
			# Otherwise check_failure_continue might see stale "CONT" from other state
			return {"compile_state": END, "verifier_state": END}

		# Continue generating next seed
		print(f"Continuing to generate next seed ({self.seedcnt}/{self.seednum})...")
		return {"compile_state": "CONT"}

	def handle_verifier_failure(self, state: State):
		"""
		Handle verifier failure when fix_verifier is disabled.
		Saves the failed seed and decides whether to continue generating more seeds.
		"""
		print("\n-----------------------------------------------------\n")
		print("Verifier check failed (fix_verifier disabled), saving as failed seed...")
		self.save_seed_to_corpus(isfail=True)

		# Check if enough seeds have been generated
		print(f"[DEBUG] handle_verifier_failure termination check: seedcnt={self.seedcnt} >= seednum={self.seednum}? {self.seedcnt >= self.seednum}")
		if self.seedcnt >= self.seednum:
			print(f"Generate total {self.seednum} seeds (including failed), finish!")
			# Must set both states to END to ensure graph terminates
			# Otherwise check_failure_continue might see stale "CONT" from other state
			return {"compile_state": END, "verifier_state": END}

		# Continue generating next seed
		print(f"[DEBUG] handle_verifier_failure returning CONT, will generate more seeds")
		print(f"Continuing to generate next seed ({self.seedcnt}/{self.seednum})...")
		return {"verifier_state": "CONT"}

	def save_seed_to_corpus(self, isfail: bool = False):
		# Guard against duplicate saves for the same seed
		if self._current_seed_saved:
			print(f"[Warning] Seed #{self.seedcnt} already saved, skipping duplicate save")
			return

		# Guard against tsfile being None (e.g., network error before file creation)
		if self.vm_context.tsfile is None:
			print("[Warning] Cannot save seed: tsfile is None (likely due to network error before file creation)")
			# Still print statistics and record to CSV even without a seed file
			self._print_token_statistics()
			self._record_seed_statistics(success=False, seed_category="failed",
										 helper_coverage="none", target_helpers=[], actual_helpers=[])
			self._current_seed_saved = True  # Mark as saved (even without file)
			return

		# Detect helper coverage before saving (need to read from tmpfile)
		coverage_type, actual_helpers, target_helpers = self._detect_helper_coverage(self.vm_context.tmpfile)

		# Determine seed_category based on isfail and helper coverage
		if isfail:
			seed_category = "failed"
		elif coverage_type == "full" or coverage_type == "n_a":
			# Full coverage or random strategy (n_a) -> success
			seed_category = "success"
		else:
			# Partial or none coverage -> usable
			seed_category = "usable"

		# Save to appropriate directory
		self.vm_context.save_valid_seed_to_corpus(isfail=isfail, seed_category=seed_category)

		bpf_insn_cnt = self.vm_context.get_bpf_instructions_count(self.vm_context.corpus_filename)
		print(f"self.vm_context.corpus_filename = {self.vm_context.corpus_filename}, bpf_insn_cnt = {bpf_insn_cnt}")
		print(f"[Seed Category] {seed_category} (helper_coverage: {coverage_type})")

		# Generate appropriate tag based on seed category
		if seed_category == "failed":
			identifytag = f"\n// This is a FAILED bpf prog generated by {self._get_model_name()} "
		elif seed_category == "usable":
			identifytag = f"\n// This is a USABLE bpf prog (missing target helpers) generated by {self._get_model_name()} "
		else:
			identifytag = f"\n// This is a valid bpf prog generated by {self._get_model_name()} "
		identifytag += f"with {self.compile_total} grammar corrections and "
		identifytag += f"{self.verifier_total} semantic corrections, taking {time.time()-self.start_time:.4f} seconds."
		identifytag += f"\n// The total number of bpf instructions is {bpf_insn_cnt}."
		if target_helpers:
			identifytag += f"\n// Target helpers: {','.join(target_helpers)}"
			identifytag += f"\n// Actual helpers: {','.join(actual_helpers)}"
			identifytag += f"\n// Helper coverage: {coverage_type}"
		identifytag += "\n"

		self.vm_context.write_to_file(self.vm_context.corpus_filename, identifytag, False)

		# Mark the seed as saved before statistics/CSV bookkeeping so later
		# non-critical failures do not cause the same seed to be reclassified.
		self._current_seed_saved = True

		# Print token statistics for this seed
		self._print_token_statistics()

		# Record statistics when saving seed
		self._record_seed_statistics(
			success=(seed_category == "success"),
			seed_category=seed_category,
			helper_coverage=coverage_type,
			target_helpers=target_helpers,
			actual_helpers=actual_helpers
		)

	def run_verifier(self, state: State):
		print("\n-----------------------------------------------------\n")
		print("Call run_verifier!")

		if not self.vm_context.vm_is_running:
			print("The vm is not running, please start it first!")
			return {"verifier_state": END}

		while self.vm_context.run_vm is None:
			timewait = 3
			print(f"The vm is running, waiting {timewait} s ...")
			time.sleep(timewait)

		print("The vm is running, start to run verifier!")
		verifier_start = time.time()
		succ, verifier_log = self.vm_context.exec_bpf_insn(self.vm_context.tmpfile)
		verifier_elapsed = time.time() - verifier_start
		self.total_verifier_time += verifier_elapsed
		if not succ:
			print(f"Run verifier failed: {verifier_log}")
			return {"verifier_state": "FAIL"}

		print(f"Run verifier succ: {verifier_log}")
		self.save_seed_to_corpus()

		# Check if enough seeds have been generated
		print(f"[DEBUG] run_verifier termination check: seedcnt={self.seedcnt} >= seednum={self.seednum}? {self.seedcnt >= self.seednum}")
		if self.seedcnt >= self.seednum:
			print(f"Generate total {self.seednum} seeds, finish!")
			return {"verifier_state": END}

		# Continue generating next seed
		print(f"[DEBUG] run_verifier returning CONT, will generate more seeds")
		return {"verifier_state": "CONT"}

	def fix_verifier_issue(self, state: State):
		"""
		Attempts to fix BPF verifier issues by querying an LLM,
		maintaining a history of previous suggestions to guide future attempts.
		Uses conversation history to maintain context (Strategy A + B).
		"""
		print("\n-----------------------------------------------------\n")
		print(f"Call fix_verifier_issue! Attempt: {self.verifier_round}")

		# --- 1. Construct details of the current BPF verifier error ---
		current_bpf_program_text = self.vm_context.extract_bpf_insn(self.vm_context.tmpfile)
		current_verifier_errors = self.vm_context.verifier_log

		# Build task prompt (not cached, task-specific)
		task_prompt = '''
		# Task: Correct Linux eBPF Bytecode Program

		## Overall Goal
		Your primary goal is to act as an **expert BPF debugger**. You will analyze the provided BPF program and its corresponding verifier log, identify the root causes of all reported errors, and produce a corrected, verifier-compliant version of the program.

		## Required Output Structure
		Your response **MUST** be structured into the following three sections, in this exact order:

		### 1. Root Cause Analysis
		- For each error reported by the verifier, provide a concise analysis.
		- Clearly state which **Semantic Rule** was violated or explain the logic error.
		- Pinpoint the specific instruction(s) that caused the failure.

		### 2. Discovered BPF Verifier Rules
		- If the verifier error reveals a rule not explicitly listed in the Semantic Rules, you must state the newly discovered rule here
		- If no new rules are discovered, simply state "No new verifier rules were discovered."

		### 3. Corrected eBPF Program
		- Provide the complete, corrected eBPF program code.
		- The code must be enclosed in a single ```c ... ``` block.
		- Add comments to the code to explain the key changes you made.

		## Correction Workflow
		You must follow these steps to arrive at the solution:
		1. **Analyze Log**: Carefully read the entire BPF verifier log to identify all reported errors.
		2. **Map to Rules**: For each error, map it to a specific rule in the provided Semantic Rules. If no existing rule applies, formulate a new one.
		3. **Formulate Plan**: Create a mental plan to correct the errors. This may involve changing arguments, reordering instructions, or adding new helper calls to satisfy verifier requirements.
		4. **Implement Fix**: Write the corrected eBPF program, strictly adhering to all constraints.
		5. **Format Output**: Present your findings and the corrected code according to the Required Output Structure.

		## Constraints
		1. **Do Not Delete Helpers**: You must not remove any of the original helper function calls that were specified in the Helper Function Library.
		2. **Can Add Helpers**: You are permitted to add new helper function calls (e.g., `bpf_get_current_task_btf`) if they are essential to fix a type or logic error.
		3. **Adhere to Rules**: The corrected program must strictly adhere to all Semantic Rules.
		4. **Preserve Intent**: The corrected program's core function and logic should remain as close as possible to the original intent.

		## CRITICAL - Helper Function Call Format
		- **ALWAYS** use `BPF_EMIT_CALL(BPF_FUNC_xxx)` for helper function calls (e.g., `BPF_EMIT_CALL(BPF_FUNC_tail_call)`)
		- **NEVER** use numeric function IDs like `BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, 12)` or `BPF_EMIT_CALL(12)`
		- Use symbolic constant names from the Helper Function Library (e.g., `BPF_FUNC_tail_call`, not `12`)
		- This applies to BOTH the original target helpers AND any new helpers you add for fixing errors
		'''

		# Build current error details (dynamic content, not cached)
		verifier_error_details = f'''
		## Current Problem Details (Attempt {self.verifier_round})

		### eBPF Bytecode Program Under Review:
		```c
		{current_bpf_program_text}
		```

		### BPF Verifier Errors Reported:
		```c
		{current_verifier_errors}
		```
		'''

		# Complete user message
		full_user_message = task_prompt + verifier_error_details

		# Compress history conversation (only keep recent rounds)
		compressed_history = self._compress_history(self.current_seed_conversation)

		# Build new user message
		user_message = HumanMessage(content=full_user_message)

		# Add new message to complete history
		self.current_seed_conversation.append(user_message)

		# Build messages to send to LLM
		# Note: helper_context was cached during generate_seed and included in system prompt or initial message
		messages_to_send = [self._cached_system_prompt] + compressed_history + [user_message]

		if self.logdebug:
			print(f"[Conversation History] Verifier fix round: {self.verifier_round}")
			print(f"[Conversation History] Complete history messages: {len(self.current_seed_conversation)}")
			print(f"[Conversation History] Compressed messages: {len(compressed_history)}")
			print(f"[Conversation History] Total messages to send: {len(messages_to_send)}")

		# Invoke LLM with retry
		llm_start = time.time()
		llm_response_payload = self._invoke_with_retry(
			self._llm_analysis_verifier_log,
			{"messages": messages_to_send},
			"Fix Verifier Issue"
		)
		llm_elapsed = time.time() - llm_start
		self.total_llm_time += llm_elapsed

		# Accumulate token usage
		self._accumulate_token_usage(llm_response_payload, "Fix Verifier Issue")

		# Extract LLM response
		latest_ai_message_content = ""
		ai_response = None
		if isinstance(llm_response_payload, dict) and "messages" in llm_response_payload:
			if llm_response_payload["messages"] and hasattr(llm_response_payload["messages"][-1], 'content'):
				ai_response = llm_response_payload["messages"][-1]
				latest_ai_message_content = ai_response.content
			else:
				print("Error: LLM response 'messages' list is empty or last message has no content.")
				latest_ai_message_content = "# Error: Malformed LLM response message."
		elif hasattr(llm_response_payload, 'content'):
			ai_response = llm_response_payload
			latest_ai_message_content = llm_response_payload.content
		else:
			print("Error: Unexpected LLM response structure. Expected a dict with a 'messages' key or a BaseMessage object.")
			latest_ai_message_content = "# Error: Could not parse LLM response."

		# Add AI response to complete history
		if ai_response:
			self.current_seed_conversation.append(ai_response)

		print(f"\n--- LLM Verifier Suggestion (Attempt {self.verifier_round}) ---")
		print(latest_ai_message_content)

		# Keep old history mechanism (for logging)
		formatted_suggestion = f"\n### Your Suggestions To Fix Verifier Logs (Attempt {self.verifier_round}):\n\n{latest_ai_message_content}\n\n"
		self.verifier_fix_suggestions_history.append(full_user_message + formatted_suggestion)

		# Save log file
		current_round_log_entry = (
			f"{formatted_suggestion}\n"
			f"{full_user_message}"
		)

		verifier_file_path = f"{self.vm_context.tsfile}_c{self.compile_round}_v{self.verifier_round}"
		self.vm_context.write_to_file(verifier_file_path, current_round_log_entry)
		self.vm_context.tmpfile = verifier_file_path

		# --- 9. Update counters ---
		self.verifier_round += 1
		self.verifier_total += 1
		return

	def do_generate_seed(self, user_content: str, init_VM: bool = False):
		if init_VM:
			self.vm_context.vm_is_running = True
			self.vm_context.start_vm()

		messages = [HumanMessage(content = user_content)]
		# result = self.graph.invoke({"messages": messages}, config=self.config)
		# print(result["messages"][-1].content)

		# Create fresh config for each seed with recursion_limit=20
		fresh_config = RunnableConfig(
			configurable={"thread_id": f"seed_{self.seedcnt}_{int(time.time())}"},
			recursion_limit=20
		)

		# Copy callbacks if they exist
		if hasattr(self, 'config') and 'callbacks' in self.config:
			fresh_config['callbacks'] = self.config['callbacks']

		print(f"Attempting to run graph with fresh recursion_limit: {fresh_config.get('recursion_limit')} for seed {self.seedcnt}")

		try:
			events = self.graph.stream(
				{"messages": messages},
				stream_mode="values",
				config=fresh_config,
			)
			for event in events:
				# Only print AI responses, filter out HumanMessage (prompts) to avoid noise
				last_msg = event["messages"][-1]
				if isinstance(last_msg, AIMessage):
					last_msg.pretty_print()

			# Token statistics are printed in save_seed_to_corpus() for each seed

		except GraphRecursionError as e:
			print(f"Error: GraphRecursionError occurred: {e}")
			print(f"The recursion limit of {fresh_config.get('recursion_limit')} was reached for seed {self.seedcnt}.")
			print("Consider if the graph has a non-terminating loop or if the limit needs to be increased further.")

			self.save_seed_to_corpus(True)
			# Token statistics are printed in save_seed_to_corpus()

			# Check if more seeds need to be generated
			if self.seedcnt < self.seednum:
				print(f"Continuing seed generation: {self.seedcnt}/{self.seednum} seeds completed")
				# Continue with the next seed generation by calling recursively
				return self.do_generate_seed(user_content, init_VM=False)
			else:
				print(f"All {self.seednum} seeds have been attempted. Exiting.")
				return {"error": "GraphRecursionError", "message": str(e)}

		except (
			# Anthropic (Claude)
			AnthropicConnectionError, AnthropicTimeoutError,
			# OpenAI (GPT, also used by DeepSeek and some others)
			OpenAIConnectionError, OpenAITimeoutError,
			# httpx (common HTTP client used by most LLM SDKs)
			httpx.ConnectError, httpx.TimeoutException, httpx.ConnectTimeout, httpx.ReadTimeout,
			# requests (fallback for some providers like Google)
			requests.exceptions.ConnectionError, requests.exceptions.Timeout,
		) as e:
			# Network error after all retries exhausted - thread exits gracefully
			print(f"\n[Fatal Network Error] {type(e).__name__}: {e}")
			print(f"[Thread Exit] Seed {self.seedcnt} generation failed after {self.max_retry_attempts} retries.")
			print(f"[Thread Exit] This thread will exit gracefully without affecting other threads.")
			self.save_seed_to_corpus(True)
			# Do NOT continue with more seeds - let this thread exit gracefully
			return {"error": "NetworkError", "message": str(e), "retries_exhausted": True}

		except KeyError as e:
			print(f"Error: KeyError occurred: {e}")
			self.save_seed_to_corpus(True)
			self.vm_context.write_to_file("logException", str(e), False)

			# Check if more seeds need to be generated
			if self.seedcnt < self.seednum:
				print(f"Continuing seed generation after KeyError: {self.seedcnt}/{self.seednum} seeds completed")
				return self.do_generate_seed(user_content, init_VM=False)
			else:
				print(f"All {self.seednum} seeds have been attempted. Exiting.")
				return {"error": "KeyError", "message": str(e)}

		except Exception as e:
			print(f"An unexpected error occurred: {type(e).__name__} - {e}")
			self.save_seed_to_corpus(True)
			self.vm_context.write_to_file("logException", str(e), False)
			# Token statistics are printed in save_seed_to_corpus()

			# Check if more seeds need to be generated
			print(f"[DEBUG] Exception handler termination check: seedcnt={self.seedcnt} < seednum={self.seednum}? {self.seedcnt < self.seednum}")
			if self.seedcnt < self.seednum:
				print(f"[DEBUG] Exception handler recursing to generate more seeds")
				print(f"Continuing seed generation after error: {self.seedcnt}/{self.seednum} seeds completed")
				# Continue with the next seed generation by calling recursively
				return self.do_generate_seed(user_content, init_VM=False)
			else:
				print(f"All {self.seednum} seeds have been attempted. Exiting.")
				return {"error": f"Unexpected error: {type(e).__name__}", "message": str(e)}

		return
