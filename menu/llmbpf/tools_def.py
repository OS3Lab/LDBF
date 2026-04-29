from typing import Annotated
from utils import VMContext
from langchain_core.tools import tool, BaseTool

class ToolsDef:
	@staticmethod
	def def_write_tempfile(context: VMContext) -> BaseTool:
		@tool
		def write_tempfile(
				content: Annotated[str, "The file content you want to write."]
			) -> str:
			"""
			This tool allows you to write content to a temp file.

			The parameter `content` represents the content you want to write.
			"""
			if context is None:
				return "The vm context is not initialized.\nPlease notify the user."

			ret = ""
			try:
				ret = context.write_tempfile(content)
			except RuntimeError as err:
				ret = f"Something went wrong while write to tempfile: {err}\nPlease notify the user."
			return ret

		return write_tempfile
	
	@staticmethod
	def def_exec_bpf_insn(context: VMContext) -> BaseTool:
		@tool
		def exec_bpf_insn(
				insn: Annotated[str, "The bpf insn you want to execute."]
			) -> str:
			"""
			This tool allows you to execute a target bpf insn program in a QEMU VM.
			Later you can interact with it using `connectvm`.

			The parameter `insn` represents the bpf insn.
			"""
			if context is None:
				return "The vm context is not initialized.\nPlease notify the user."

			ret = ""
			try:
				ret = context.exec_bpf_insn(insn)
			except RuntimeError as err:
				ret = f"Something went wrong while starting program: {err}\nPlease notify the user."
			return ret

		return exec_bpf_insn
