"""
Prompt Caching Strategy Module
"""

from typing import List, Dict, Any, Optional
from dataclasses import dataclass
from abc import ABC, abstractmethod
from langchain_core.messages import SystemMessage
from langchain_anthropic import ChatAnthropic
from langchain_openai import ChatOpenAI
from langchain_google_genai import ChatGoogleGenerativeAI


@dataclass
class CacheableContent:
    """
    Cacheable content block definition.

    Attributes:
        name: Content block name (for debugging and logging)
        content: Actual text content
        cacheable: Whether to be cached (True = cache, False = regular content)
        priority: Cache priority (lower number = higher priority, for model cache point limits)
    """
    name: str
    content: str
    cacheable: bool = True
    priority: int = 0  # 0 = highest priority


class BaseCachingStrategy(ABC):
    """
    Base class for prompt caching strategies.
    """

    @abstractmethod
    def format_system_message(self, content_blocks: List[CacheableContent]) -> SystemMessage:
        """
        Format content blocks into a SystemMessage suitable for the specific model.

        Args:
            content_blocks: List of content blocks to format

        Returns:
            Formatted SystemMessage
        """
        pass

    @abstractmethod
    def get_max_cache_points(self) -> Optional[int]:
        """
        Get the maximum number of cache points supported by the model.

        Returns:
            Maximum number of cache points, None means unlimited
        """
        pass

    @abstractmethod
    def get_cache_discount_rate(self) -> float:
        """
        Get the discount rate for cache reads.

        Returns:
            Discount rate (0.0-1.0), e.g., 0.9 means 90% discount
        """
        pass

    def _filter_cacheable_blocks(self, content_blocks: List[CacheableContent]) -> List[CacheableContent]:
        """
        Filter content blocks based on priority and max cache points.

        Args:
            content_blocks: Original content block list

        Returns:
            Filtered content block list
        """
        max_points = self.get_max_cache_points()
        if max_points is None:
            return content_blocks

        # Sort by priority (lower value = higher priority)
        sorted_blocks = sorted(content_blocks, key=lambda x: x.priority)

        # Keep only the first max_points cacheable blocks
        cache_count = 0
        result = []
        for block in sorted_blocks:
            if block.cacheable:
                if cache_count < max_points:
                    result.append(block)
                    cache_count += 1
                else:
                    # Exceeded limit, mark as non-cacheable
                    result.append(CacheableContent(
                        name=block.name,
                        content=block.content,
                        cacheable=False,
                        priority=block.priority
                    ))
            else:
                result.append(block)

        return result


class ClaudeCachingStrategy(BaseCachingStrategy):
    """
    Anthropic Claude Prompt Caching strategy.

    Claude features:
    - Supports content structured as list
    - Each content block can have cache_control: {"type": "ephemeral"}
    - Supports multiple cache points (tested to support at least 4)
    - Cache read: 90% discount
    - Cache write: 25% discount
    """

    def format_system_message(self, content_blocks: List[CacheableContent]) -> SystemMessage:
        """
        Format to structure required by Claude API.

        Claude requirements:
        content = [
            {"type": "text", "text": "...", "cache_control": {"type": "ephemeral"}},
            ...
        ]
        """
        # Filter and sort content blocks
        filtered_blocks = self._filter_cacheable_blocks(content_blocks)

        # Build content list
        formatted_content = []
        for block in filtered_blocks:
            content_dict = {
                "type": "text",
                "text": block.content
            }

            # Only add cache_control for cacheable blocks
            if block.cacheable:
                content_dict["cache_control"] = {"type": "ephemeral"}

            formatted_content.append(content_dict)

        return SystemMessage(content=formatted_content)

    def get_max_cache_points(self) -> Optional[int]:
        """Claude supports multiple cache points, tested at least 4, conservatively set to 4 here"""
        return 4

    def get_cache_discount_rate(self) -> float:
        """Cache read: 90% discount"""
        return 0.9


class OpenAICachingStrategy(BaseCachingStrategy):
    """
    OpenAI GPT-4/GPT-4o Prompt Caching strategy.

    OpenAI features:
    - Automatically caches content exceeding 1024 tokens
    - No special markers needed (automatic detection)
    - Cache read: 50% discount
    - Recommendation: merge cacheable content into single large block to trigger automatic caching
    """

    def format_system_message(self, content_blocks: List[CacheableContent]) -> SystemMessage:
        """
        OpenAI's caching is automatic, just need to merge content into string.
        To maximize caching effect, place all cacheable content at front.
        """
        # Separate cacheable and non-cacheable blocks
        cacheable = [b for b in content_blocks if b.cacheable]
        non_cacheable = [b for b in content_blocks if not b.cacheable]

        # Sort cacheable blocks by priority
        cacheable.sort(key=lambda x: x.priority)

        # Merge all content (cacheable first)
        all_content = "\n\n".join([b.content for b in cacheable + non_cacheable])

        return SystemMessage(content=all_content)

    def get_max_cache_points(self) -> Optional[int]:
        """OpenAI automatic caching, no need to limit cache points"""
        return None

    def get_cache_discount_rate(self) -> float:
        """Cache read: 50% discount"""
        return 0.5


class GeminiCachingStrategy(BaseCachingStrategy):
    """
    Google Gemini Context Caching strategy.

    Gemini features:
    - Supports Context Caching (create cache via API)
    - LangChain integration may not fully support
    - Current implementation: similar to OpenAI, merge into single string
    - Future extensible: add Gemini-specific cache API calls
    """

    def format_system_message(self, content_blocks: List[CacheableContent]) -> SystemMessage:
        """
        Current implementation: merge into single string (similar to OpenAI)
        Future extensible: add Gemini-specific cached_content parameter
        """
        # Separate cacheable and non-cacheable blocks
        cacheable = [b for b in content_blocks if b.cacheable]
        non_cacheable = [b for b in content_blocks if not b.cacheable]

        # Sort cacheable blocks by priority
        cacheable.sort(key=lambda x: x.priority)

        # Merge all content
        all_content = "\n\n".join([b.content for b in cacheable + non_cacheable])

        # TODO: Can add Gemini-specific cache parameters in future
        # return SystemMessage(
        #     content=all_content,
        #     additional_kwargs={"cached_content": cache_name}
        # )

        return SystemMessage(content=all_content)

    def get_max_cache_points(self) -> Optional[int]:
        """Gemini supports caching, but current implementation does not limit"""
        return None

    def get_cache_discount_rate(self) -> float:
        """Gemini Context Caching discount rate (estimated)"""
        return 0.75  # Estimated value, adjust based on actual API pricing


class DefaultCachingStrategy(BaseCachingStrategy):
    """
    Default caching strategy (for models that do not support Prompt Caching).

    Features:
    - Simply merge all content into string
    - Reuse message objects for performance benefits
    - No cost optimization
    """

    def format_system_message(self, content_blocks: List[CacheableContent]) -> SystemMessage:
        """Merge all content blocks into single string"""
        all_content = "\n\n".join([b.content for b in content_blocks])
        return SystemMessage(content=all_content)

    def get_max_cache_points(self) -> Optional[int]:
        """Caching not supported"""
        return 0

    def get_cache_discount_rate(self) -> float:
        """No discount"""
        return 0.0


class CachingStrategyFactory:
    """
    Cache strategy factory class.
    Automatically select appropriate cache strategy based on LLM model type.
    """

    # Mapping from model type to strategy class
    _strategy_map: Dict[type, type] = {
        ChatAnthropic: ClaudeCachingStrategy,
        ChatOpenAI: OpenAICachingStrategy,
        ChatGoogleGenerativeAI: GeminiCachingStrategy,
    }

    @classmethod
    def create_strategy(cls, llm_model: Any) -> BaseCachingStrategy:
        """
        Create corresponding cache strategy based on LLM model.

        Args:
            llm_model: LLM model instance

        Returns:
            Corresponding cache strategy instance
        """
        model_type = type(llm_model)

        # Find matching strategy
        strategy_class = cls._strategy_map.get(model_type, DefaultCachingStrategy)

        return strategy_class()

    @classmethod
    def register_strategy(cls, model_type: type, strategy_class: type):
        """
        Register new model type and strategy mapping.
        Used to extend support for new LLM models.

        Args:
            model_type: LLM model type
            strategy_class: Corresponding strategy class

        Example:
            # Add new model support
            CachingStrategyFactory.register_strategy(
                ChatNewModel,
                NewModelCachingStrategy
            )
        """
        cls._strategy_map[model_type] = strategy_class


class PromptCachingManager:
    """
    Prompt Caching manager.
    Provides unified interface to build cacheable system prompts.
    """

    def __init__(self, llm_model: Any):
        """
        Initialize manager.

        Args:
            llm_model: LLM model instance
        """
        self.llm_model = llm_model
        self.strategy = CachingStrategyFactory.create_strategy(llm_model)

    def build_cached_system_message(self, content_blocks: List[CacheableContent]) -> SystemMessage:
        """
        Build cacheable system message.

        Args:
            content_blocks: List of content blocks

        Returns:
            Formatted SystemMessage
        """
        return self.strategy.format_system_message(content_blocks)

    def get_model_info(self) -> Dict[str, Any]:
        """
        Get current model's cache information.

        Returns:
            Dictionary containing model cache information
        """
        return {
            "model_type": type(self.llm_model).__name__,
            "strategy_type": type(self.strategy).__name__,
            "max_cache_points": self.strategy.get_max_cache_points(),
            "cache_discount_rate": self.strategy.get_cache_discount_rate(),
            "supports_caching": self.strategy.get_cache_discount_rate() > 0
        }


# ========================================
# Usage examples
# ========================================

if __name__ == "__main__":
    # Example 1: Claude model
    from langchain_anthropic import ChatAnthropic

    claude_model = ChatAnthropic(model="claude-sonnet-4-5-20250929")
    manager = PromptCachingManager(claude_model)

    # Define content blocks
    content_blocks = [
        CacheableContent(
            name="instructions",
            content="BPF Instructions and Semantic Rules...",
            cacheable=True,
            priority=0  # Highest priority
        ),
        CacheableContent(
            name="type_definitions",
            content="BPF Type Definitions...",
            cacheable=True,
            priority=1
        ),
        CacheableContent(
            name="all_helpers_json",
            content="All Helper Definitions JSON...",
            cacheable=True,
            priority=2
        ),
        CacheableContent(
            name="output_format",
            content="Output Format Instructions...",
            cacheable=True,
            priority=3
        )
    ]

    # Build cache message
    system_message = manager.build_cached_system_message(content_blocks)

    # View model information
    info = manager.get_model_info()
    print(f"Model: {info['model_type']}")
    print(f"Strategy: {info['strategy_type']}")
    print(f"Max cache points: {info['max_cache_points']}")
    print(f"Cache discount: {info['cache_discount_rate'] * 100}%")

    # Example 2: OpenAI model
    from langchain_openai import ChatOpenAI

    openai_model = ChatOpenAI(model="gpt-4o")
    manager2 = PromptCachingManager(openai_model)

    system_message2 = manager2.build_cached_system_message(content_blocks)
    print(f"\nOpenAI Strategy: {type(manager2.strategy).__name__}")
