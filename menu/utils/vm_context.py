import subprocess
import re
import os
from datetime import datetime
from collections import defaultdict

'''
import pwnlib.xxx, instead of `from pwn import *` to adapt Console.log()
'''
from pwnlib.timeout import Timeout
from pwnlib.replacements import sleep
from pwnlib.tubes.ssh import ssh
from pwnlib.tubes.process import process
from pwnlib.context import context
from rich.console import Console
from .fix_template import fill_poc, DependencyFixer
import tempfile
import threading
import random

timefmt = "%Y-%m-%d %H:%M:%S"
console = Console(log_time_format="%Y-%m-%d %H:%M:%S")
# context.log_level = 'debug'

STARTVM_SUCCESS = 0
STARTVM_FAILED = 1
STARTVM_AGAIN = 2
RUN_QEMU_LIMIT = 3
RUN_QEMU_CNT = 0

def get_filename(filepath):
	"""Get filename using os.path.basename()"""
	return os.path.basename(filepath)

def get_absolute_path(filepath):
	"""Get absolute path using os.path.abspath()"""
	return os.path.abspath(filepath)

def get_current_directory():
	"""Get absolute path of current directory"""
	return os.path.dirname(os.path.abspath(__file__))

def save_result(flag, workdir, log_info:str=None):
	if flag :
		with open('./panic_list.txt', 'a') as file:
			file.write("[" + datetime.now().strftime(timefmt) + "] " + workdir + ": " + log_info + '\n' )
	else :
		with open('./no_panic_list.txt', 'a') as file:
			file.write("[" + datetime.now().strftime(timefmt) + "] " + workdir + ": " + log_info + '\n')

def compile_regex(pattern):
	pattern = pattern.replace("{{ADDR}}", "0x[0-9a-f]+")
	pattern = pattern.replace("{{PC}}", "\\[\\<?(?:0x)?[0-9a-f]+\\>?\\]")
	pattern = pattern.replace("{{FUNC}}", "([a-zA-Z0-9_]+)(?:\\.|\\+)")
	pattern = pattern.replace("{{SRC}}", "([a-zA-Z0-9-_/.]+\\.[a-z]+:[0-9]+)")
	return re.compile(pattern)

class VMContext:
	"""
	Api wrapper for better comprehension for VM context
	"""
	_shared_run_vm: process = None
	_vm_management_lock = threading.Lock()

	# store the last bpf insn program filepath
	tmpfile: str

	def __init__(self, workdir, pocexecfile, poctemplate, pocinsnfile, seedcorpus, samplescorpus, vmlock: threading.Lock = None):
		if not os.path.exists(workdir):
			console.log(f"workdir {workdir} not exists")
			exit(1)
		if not os.path.exists(poctemplate):
			console.log(f"poctemplate {poctemplate} not exists")
			exit(1)
		self.workdir = get_absolute_path(workdir)
		self.pocexecfile = get_absolute_path(pocexecfile)
		self.poctemplate = get_absolute_path(poctemplate)
		self.pocinsnfile = get_absolute_path(pocinsnfile)
		self.seedcorpus = get_absolute_path(seedcorpus)
		self.samplescorpus = get_absolute_path(samplescorpus)
		
		if not os.path.exists(self.seedcorpus):
			os.mkdir(self.seedcorpus)
			console.log(f"create seedcorpus {self.seedcorpus}")
		self.helpertable = HelperTable(self.samplescorpus)
		
		# Point to the shared VM instance and update status
		self.run_vm = VMContext._shared_run_vm
		self.vm_is_running = self.run_vm is not None

		self.vmlock = vmlock
		self.tsfile = None
		self.init_vars()

	def check_bug(self, workdir):
		patterns = [
			compile_regex(r'BUG: KASAN: ([a-z\\-]+) in {{FUNC}}(?:.*\\n)+?.*(Read|Write) (?:of size|at addr) (?:[0-9a-f]+)'),
			compile_regex(r'BUG: KASAN: ([a-z\\-]+) in {{FUNC}}(?:.*\\n)+?.*(Read|Write) (?:of size|at addr) (?:[0-9a-f]+)'),
			compile_regex(r'BUG: KASAN: (?:double-free or invalid-free|double-free|invalid-free) in {{FUNC}}'),
			compile_regex(r'BUG: KASAN: ([a-z\\-]+) on address(?:.*\\n)+?.*(Read|Write) of size ([0-9]+)'),
			compile_regex(r'BUG: KASAN: (.*)'),
			compile_regex(r'BUG: KASAN:	'),
			compile_regex(r'BUG: KMSAN: (.*)'),
			compile_regex(r'BUG: KFENCE: (.*)'),
			compile_regex(r'BUG: (?:unable to handle kernel NULL pointer dereference|kernel NULL pointer dereference|Kernel NULL pointer dereference)'),
			compile_regex(r'KASAN: (.*)'),
			re.compile(r'BUG: KASAN: (.*)'),
			re.compile(r': Permission denied'),
			re.compile(r'^([a-zA-Z0-9_\-/.]+):[0-9]+:([0-9]+:)?.*(error|invalid|fatal|wrong)'),
			re.compile(r'FAILED unresolved symbol'),
			re.compile(r'No rule to make target'),
			re.compile(r': not found'),
			re.compile(r': final link failed: '),
			re.compile(r'collect2: error: '),
			re.compile(r'(ERROR|FAILED): Build did NOT complete'),
			# WARNING: CPU: 0 PID: 6148 at net/sched/sch_qfq.c:1003 qfq_dequeue+0x3bc/0x790
			re.compile(r'WARNING: CPU: [0-9]+ PID: [0-9]+ at ([a-zA-Z0-9_\-/.]+):[0-9]+ ([a-zA-Z0-9_]+)\+0x[0-9a-f]+/0x[0-9a-f]+'),
			# kernel BUG at net/core/skbuff.c:2812!
			re.compile(r'kernel BUG at ([a-zA-Z0-9_\-/.]+):[0-9]+'),
			re.compile(r'WARNING: possible circular locking dependency detected'),
			re.compile(r"UBSAN: array-index-out-of-bounds in"),
			re.compile(r"UBSAN: Undefined behaviour in"),
			re.compile(r"UBSAN:"),
			re.compile(r"BUG: .*stack guard page was hit at"),
			re.compile(r"WARNING: .*lib/debugobjects\\.c.* (?:debug_print|debug_check)"),
			#WARNING: possible circular locking dependency detected
			re.compile(r"WARNING: possible circular locking dependency detected"),
			re.compile(r"FAULT_INJECTION: forcing a failure"),
			re.compile(r"WARNING: held lock freed!"),
			re.compile(r': error: '),
			re.compile(r'Error: '),
			re.compile(r'ERROR: '),
			re.compile(r': fatal error: '),
			re.compile(r': undefined reference to'),
			re.compile(r': multiple definition of'),
		]

		filename=f'{workdir}/vm.log'

		try:
			with open(filename, 'r') as file:
				content = file.read()
				for pattern in patterns:
					res = pattern.search(content)
					if res:
						console.log(f"[*] {res} matches {pattern}")
						save_result(True, workdir, str(res.group()))
						console.log("TrueTrueTrueTrueTrueTrueTrueTrueTrue")
						return True

			save_result(False, workdir, "Regex check failed")
			console.log("FalseFalseFalseFalseFalseFalseFalse")
			return False

		except FileNotFoundError:
			console.log(f"file {filename} not found.")
			return False

	def handle_panic(self, command: str):
		console.log("Handling VM panic/hang...")
		
		# 1. Check for bug signature in vm.log
		is_bug = self.check_bug(self.workdir)
		
		if is_bug:
			console.log("[bold green]Confirmed crash from vm.log. Saving artifacts...[/bold green]")
			artifacts_dir = os.path.join(self.workdir, "crashes")
			base_artifact_name = f"crash_{datetime.now().strftime('%y%m%d-%H%M%S-%f')}"
		else:
			console.log("[bold yellow]Timeout occurred without a crash signature. Saving hang artifacts...[/bold yellow]")
			artifacts_dir = os.path.join(self.workdir, "hangs")
			base_artifact_name = f"hang_{datetime.now().strftime('%y%m%d-%H%M%S-%f')}"

		# Create artifacts directory if it doesn't exist
		if not os.path.exists(artifacts_dir):
			os.makedirs(artifacts_dir)
			
		# Save the eBPF source that caused the issue
		prog_path = os.path.join(artifacts_dir, f"{base_artifact_name}.c")
		if os.path.exists(self.pocinsnfile):
			os.rename(self.pocinsnfile, prog_path)
			console.log(f"Saved program to: {prog_path}")

		# Save the corresponding vm.log
		log_path = os.path.join(artifacts_dir, f"{base_artifact_name}.log")
		vm_log_path = os.path.join(self.workdir, "vm.log")
		if os.path.exists(vm_log_path):
			os.rename(vm_log_path, log_path)
			console.log(f"Saved log to: {log_path}")
		
		# Save the command that was executed
		cmd_path = os.path.join(artifacts_dir, f"{base_artifact_name}.cmd")
		with open(cmd_path, 'w') as f:
			f.write(command)
		console.log(f"Saved command to: {cmd_path}")

		# 2. Stop and restart the shared VM
		console.log("Stopping and restarting shared VM...")
		self.stop_vm()
		self.start_vm()

	def init_vars(self):
		self.tmpfile = None
		self.compile_log = None
		self.verifier_log = None
		self.corpus_filename = None
	
	def start_vm(self) -> process:
		with VMContext._vm_management_lock:
			# If VM is already running, just return the shared instance
			if VMContext._shared_run_vm is not None:
				self.run_vm = VMContext._shared_run_vm
				self.vm_is_running = True
				return self.run_vm

			global RUN_QEMU_CNT, STARTVM_AGAIN, STARTVM_FAILED
			RUN_QEMU_CNT = 0
			status, p = self.run_qemu()
			while status == STARTVM_AGAIN:
				status, p = self.run_qemu()
			
			if status == STARTVM_FAILED:
				self.vm_is_running = False
				VMContext._shared_run_vm = None
				console.log("Failed to start shared VM")
				exit(1)

			if p:
				VMContext._shared_run_vm = p
				self.run_vm = p
				self.vm_is_running = True
				console.log(f"Shared VM started successfully {self.run_vm}")
				return p
			else:
				console.log("pwntools failed to start VM process")
				exit(1)
	
	def cleanup_tmpfiles(self):
		if self.pocexecfile and os.path.exists(self.pocexecfile):
			console.log(f"Remove pocexecfile {self.pocexecfile}")
			os.remove(self.pocexecfile)
		if self.pocinsnfile and os.path.exists(self.pocinsnfile):
			console.log(f"Remove corpus file {self.pocinsnfile}")
			os.remove(self.pocinsnfile)
		# if self.tsfile and os.path.exists(self.tsfile):
		# 	console.log(f"Remove tsfile {self.tsfile}")
		# 	os.remove(self.tsfile)

	def cleanup_stats(self):
		# This method should only clean up thread-local (instance) state,
		# not the shared VM state.
		self.init_vars()

	def stop_vm(self):
		with VMContext._vm_management_lock:
			if VMContext._shared_run_vm is None:
				return  # Already stopped

			if os.path.exists(f'{self.workdir}/vm.pid'):
				try:
					with open(f'{self.workdir}/vm.pid', 'r') as file:
						pid = int(file.read().strip())
					os.system(f"kill -9 {pid}")
				except (IOError, ValueError) as e:
					console.log(f"Could not read or kill vm.pid: {e}")

			VMContext._shared_run_vm = None
			self.run_vm = None
			self.vm_is_running = False
			console.log("Shared VM stopped.")

	def connectvm(self, cmd:str, timeout=3, no_output_threshold=0.3):
		"""
		Execute command in VM with optimized intelligent waiting.

		Args:
			cmd: Command to execute
			timeout: Maximum wait time (seconds)
			no_output_threshold: Return early if no output for this duration (seconds)

		Returns:
			(success, output) tuple
		"""
		import time

		# Read .port file
		total_start = time.time()  # Track total time including SSH setup
		console.log(f"Try connect to VM")
		with open(f'{self.workdir}/.port', 'r') as file:
			port = int(file.read().strip())
		console.log(f"SSH Port:{port}")

		try:
			conn = process(["./connectvm"], cwd=self.workdir, shell=True, timeout=timeout)
			ssh_time = time.time() - total_start
			console.log(f"Connectvm execute: [bold magenta]{cmd}[/bold magenta]")

			# Optimized: Clear SSH banner quickly - stop as soon as no more data
			# instead of waiting for fixed timeout
			banner_start = time.time()
			banner_size = 0
			try:
				while True:
					chunk = conn.recv(timeout=0.05)  # Increase to 50ms for long banners
					if chunk:
						banner_size += len(chunk)
					else:
						break
			except Timeout:
				pass  # No more initial output, continue

			banner_time = time.time() - banner_start

			conn.sendline(cmd.encode('utf-8'))

			# Initialize buffer before any operation
			buffer = b""

			# After sending command, the shell may output login messages again
			# Clear this "post-command banner" before collecting actual output
			post_banner_start = time.time()
			post_banner_size = 0
			try:
				while True:
					chunk = conn.recv(timeout=0.05)
					if chunk:
						# Check if this looks like actual POC output (starts with "create map")
						if b'create map' in chunk:
							# This is the actual output! Put it back in buffer and stop clearing
							buffer = chunk
							break
						post_banner_size += len(chunk)
					else:
						break
			except Timeout:
				pass

			post_banner_time = time.time() - post_banner_start
			if post_banner_size > 0:
				console.log(f"[dim]Cleared {post_banner_size} bytes of post-command banner in {post_banner_time:.3f}s[/dim]")

			# Optimized intelligent waiting: accumulate output until no new data
			# Note: buffer may already contain first chunk if we detected "create map" above
			start_time = time.time()
			last_data_time = time.time()
			poll_interval = 0.02  # 20ms polling interval

			while time.time() - start_time < timeout:
				try:
					chunk = conn.recv(timeout=poll_interval)
					if chunk:
						buffer += chunk
						last_data_time = time.time()
				except Timeout:
					pass  # No data in this poll, continue

				# Check if we should exit early (moved outside except block)
				# This runs on every iteration, not just when recv times out
				if buffer and (time.time() - last_data_time) > no_output_threshold:
					conn.close()
					cmd_time = time.time() - start_time
					total_time = time.time() - total_start
					console.log(f"[dim]⚡ Fast return: cmd={cmd_time:.3f}s | ssh={ssh_time:.3f}s banner={banner_time:.3f}s total={total_time:.3f}s[/dim]")
					return True, buffer

			# Timeout reached - collect any remaining data
			try:
				remaining = conn.recv(timeout=0.05)
				if remaining:
					buffer += remaining
			except:
				pass

			conn.close()
			cmd_time = time.time() - start_time
			total_time = time.time() - total_start
			console.log(f"[dim]⏱️  Timeout: cmd={cmd_time:.3f}s | ssh={ssh_time:.3f}s banner={banner_time:.3f}s total={total_time:.3f}s[/dim]")
			return True, buffer

		except Exception as e:
			console.log(f"Connect to VM failed: {e}")
			return False, None

	def run_qemu(self):
		global STARTVM_SUCCESS, STARTVM_FAILED, STARTVM_AGAIN, RUN_QEMU_LIMIT, RUN_QEMU_CNT
		
		console.log("[bold green]Starting QEMU[/bold green]")
		p = process(["/bin/bash", "startvm"],cwd=self.workdir)
		try:
			res = p.recv(4096, timeout=10)
			while res:
				if b"Invalid host forwarding rule" in res or b"Could not set up host forwarding rule" in res and RUN_QEMU_CNT < RUN_QEMU_LIMIT:
					console.log("Checking port")
					os.system(f"rm {self.workdir}/.port")
					RUN_QEMU_CNT += 1
					return STARTVM_AGAIN, None
				if b"syzkaller login:" in res:
					# console.log("Checking syzkaller")
					console.log("QEMU started successfully")
					break
				res = p.recv(4096, timeout=10)
			console.log("Wait for syzkaller login")
		except EOFError as e:
			console.log(f"QEMU startup failure: {res}; {e}")
			return STARTVM_FAILED, None
		else:
			console.log("QEMU started successfully")
			return STARTVM_SUCCESS, p
		
	def extract_bpf_insn(self, src_path):
		"""
		Extract 'struct bpf_insn prog[] = {**}' definition from file src

		Args:
			src_path (str): Source file (contains bpf_insn definition).
		"""
		try:
			# Extract bpf_insn definition from source file src
			with open(src_path, 'r') as src_file:
				src_content = src_file.read()
				match = re.search(r'struct bpf_insn prog\[\] = \{([^{}]*(?:\{(?:[^{}]*)\}[^{}]*)*)\};', src_content, re.DOTALL)
				if match:
					bpf_insn_definition = f"struct bpf_insn prog[] = {{{match.group(1)}}};\n"
					return bpf_insn_definition
				else:
					# print(f"Warning: 'struct bpf_insn prog[]' definition not found in file '{src_path}'.")
					return None
		except FileNotFoundError:
			print(f"Error: File '{src_path}' does not exist.")
			return None
		except Exception as e:
			print(f"Error occurred: {e}")
			return None

	def get_bpf_instructions_count(self, filepath: str) -> int:
		"""
		Extract the number of BPF instructions from text content containing BPF program definition.

		Count by analyzing the content of `struct bpf_insn prog[]` array.
		During counting, ignore "// The total number of bpf instructions is ..." comment lines added by this script.

		Args:
			filepath: File path containing BPF program definition.

		Returns:
			Number of BPF instructions. Returns 0 if instructions not found or cannot be parsed.
		"""

		try:
			with open(filepath, 'r', encoding='utf-8') as f:
				lines = f.readlines()
		except Exception as e:
			print(f"Error: Failed to read file {filepath}: {e}")
			return

		comment_prefix_to_manage = "// The total number of bpf instructions is"
			
		# Remove any existing count comment lines added by this script
		cleaned_lines = [line for line in lines if not line.strip().startswith(comment_prefix_to_manage)]
		
		# Use cleaned content for counting
		file_content = "".join(cleaned_lines)

		instruction_count = 0
		in_prog_array = False
		lines = file_content.splitlines()

		for line in lines:
			stripped_line = line.strip()

			# Skip comment lines we added/manage to avoid interference when recounting
			if stripped_line.startswith("// The total number of bpf instructions is"):
				continue
			# Also skip C-style block comment lines we prioritize parsing (if regex above didn't catch)
			if stripped_line.startswith("/* The total number of BPF instructions is:"):
				continue

			if stripped_line.startswith("struct bpf_insn prog[] = {"):
				in_prog_array = True
				continue

			if not in_prog_array:
				continue

			if stripped_line == "};":
				in_prog_array = False
				break # Reached end of array

			line_for_analysis = stripped_line
			
			# Remove C++ style comments at end of line (// ...)
			if "//" in line_for_analysis:
				line_for_analysis = line_for_analysis.split("//", 1)[0].strip()
			
			# Remove C style block comments at end of line or entire line (/* ... */)
			# This logic mainly targets simple end-of-line comments or pure comment lines.
			if "/*" in line_for_analysis:
				parts = line_for_analysis.split("/*", 1)
				main_code_part = parts[0].strip()
				
				# Check if it's a valid block comment that ends on the same line
				is_comment_line = False
				if len(parts) > 1 and "*/" in parts[1]:
					if main_code_part: # Code followed by comment
						line_for_analysis = main_code_part
					else: # Entire line is /* ... */ comment
						line_for_analysis = "" 
						is_comment_line = True
				
				if is_comment_line or not line_for_analysis: # If pure comment line or empty after processing
					if not main_code_part and not line_for_analysis.endswith("*/"):
						# May be start of multi-line comment, and line has no actual code
						pass # Keep line_for_analysis unchanged, subsequent instruction check will fail
					else:
						continue

			if not line_for_analysis: # If line is empty after removing comments, skip
				continue
			
			# Determine if it's an instruction line
			# if line_for_analysis.startswith("BPF_LD_IMM64"):
			# 	instruction_count += 2
			if line_for_analysis.startswith("BPF_"): # Other BPF_ macros
				instruction_count += 1
			elif line_for_analysis.startswith("{") and \
				".code" in line_for_analysis and \
				(line_for_analysis.endswith("},") or \
				(line_for_analysis.endswith("}") and "BPF_EXIT" in line_for_analysis)):
				# Struct-form instruction, e.g., { .code = ..., .imm = ... },
				# Or BPF_EXIT style { .code = (BPF_JMP | BPF_EXIT), ... }
				instruction_count += 1
				
		return instruction_count

	def extract_and_merge_bpf_insn(self, src_path: str, template_path: str, dst_path: str):
		"""
		Extract 'struct bpf_insn prog[] = {**}' definition from file src，
		Read template file content and merge extracted definition into template content,
		then write to file dst.

		Args:
			src_path (str): Source file (contains bpf_insn definition).
			template_path (str): Template file.
			dst_path (str): Destination file.
		"""
		try:
			# Extract bpf_insn definition from source file src
			bpf_insn_definition = self.extract_bpf_insn(src_path)
			if not bpf_insn_definition:
				print(f"Warning: 'struct bpf_insn prog[]' definition not found in file '{src_path}'.")
				return

			# Read template file content
			with open(template_path, 'r') as template_file:
				template_content = template_file.read()
			########################################
			# Read template and write content into template
			# Split template content
			fixer = DependencyFixer(bpf_insn_definition, template_content)
			template_filled = fixer.random_fix()

			# Write to destination file dst
			with open(dst_path, 'w') as dst_file:
				# dst_file.write(before_marker)
				# dst_file.write(start_marker + "\n")
				# dst_file.write(bpf_insn_definition)
				# dst_file.write(end_marker + "\n")
				# dst_file.write(after_marker)
				dst_file.write(template_filled)

			print(f"Successfully merged 'struct bpf_insn prog[]' definition from '{src_path}' to '{dst_path}'.")
			###########################################

		except FileNotFoundError:
			print(f"Error: File '{src_path}' or '{template_path}' does not exist.")
		except Exception as e:
			print(f"Error occurred: {e}")

	def run_command(self, cmd:str, debugmsg:str, debug=True, timeout=3):
		"""
		Run the provided command.
		"""
		console.log(f"Execute command: {cmd}")
		try:
			res = subprocess.run(args=cmd, cwd=self.workdir, check=True, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=timeout)
			if debug:
				console.log(f"{debugmsg} output: {res.stdout.decode()}")
			return True, res.stdout.decode()
		except subprocess.CalledProcessError as e:
			console.log(f"{debugmsg} failed: {e.output.decode()}")
			return False, e.output.decode()

	def compile_bpf_insn(self, insnfile: str, fix:bool=True):
		console.log(f"compile bpf insn file: {insnfile}")
		if not insnfile or not os.path.exists(insnfile):
			console.log(f"insnfile {insnfile} not exists")
			return False
		else:
			# copy insnfile content to self.pocinsnfile
			if fix:
				self.extract_and_merge_bpf_insn(insnfile, self.poctemplate, self.pocinsnfile)
				console.log(f"Copy insnfile {insnfile} to {self.pocinsnfile}")
		
		# remove old poc
		self.run_command(f"rm {self.pocexecfile}", "Remove old poc")

		# compile the new poc
		compilecmd = f"gcc -static -o {self.pocexecfile} -I . {self.pocinsnfile}"
		succ, log = self.run_command(compilecmd, "Compilation")
		if os.path.exists(self.pocexecfile):
			console.log(f"Compilation success, {self.pocexecfile} exists")
			return True, log
		else:
			console.log(f"Compilation failed, {self.pocexecfile} not exists")
			self.compile_log = log
			return False, log
		
	def run_poc_once(self):
		console.log("[bold green]Starting SSH[/bold green]")

		scpcmd = f"./scptovm {self.pocexecfile}"
		succ, log = self.run_command(scpcmd, "Upload")
		if not succ:
			console.log("Upload POC failed")
			return succ, log

		exec_poc = f"chmod +x {get_filename(self.pocexecfile)} ; ./{get_filename(self.pocexecfile)}"
		console.log(f"Run POC: {exec_poc}")
		try:
			# Optimized: fast return when program completes
			# BPF verifier output can be slow/chunked, use shorter threshold
			# max timeout=3s for safety, early return after 0.1s of no output
			return self.connectvm(exec_poc, timeout=3, no_output_threshold=0.1)
		except Timeout:
			console.log("[bold red]VM interaction timed out. Assuming VM panic.[/bold red]")
			self.handle_panic(exec_poc)
			return False, b"VM Panic Detected"
	
	def exec_bpf_insn(self, insnfile: str):
		console.log(f"exec bpf insn file: {insnfile}")
		self.vmlock.acquire()
		try:
			# Get all dependent prog types and map types, and iterate through tests
			insns = self.extract_bpf_insn(insnfile)
			with open(self.poctemplate, 'r') as f:
				template = f.read()
			fixer = DependencyFixer(insns, template)
			dependency = fixer.dependency
			prog_types = dependency["suitable_prog_types"]
			map_types = dependency["maps"]

			# Add debug information and defensive checks
			console.log(f"[bold cyan]Found {len(prog_types)} prog types and {len(map_types)} maps[/bold cyan]")
			for i, m in enumerate(map_types):
				if len(m) == 0:
					console.log(f"[bold red]ERROR: map_types[{i}] is empty![/bold red]")
					return False, b"Empty map configuration found"

			for prog_type in prog_types:
				select_maps = []
				for i, m in enumerate(map_types):
					if len(m) == 0:
						console.log(f"[bold red]ERROR: Cannot select from empty map list at index {i}[/bold red]")
						return False, b"Empty map configuration"
					select_maps.append(random.choice(m))
				fixed_insns = fixer.fix_once(prog_type, select_maps)
				with open(self.pocinsnfile, 'w') as f:
					f.write(fixed_insns)
				compile_result, log = self.compile_bpf_insn(insnfile, False)
				if compile_result:
					succ, log = self.run_poc_once()
					# Check if log is None before using it
					if log is None:
						console.log("[bold red]VM connection failed, log is None[/bold red]")
						return False, b"VM connection failed"
					if b"Could not load program\n" in log:
						console.log("\n## Run BPF prog failed")
						if log:
							console.log(f"BPF verifier result is: {log}")
						self.verifier_log = log.split(b"Could not load program\n")[0].decode()
					else:
						return succ, log
			return False, log
		finally:
			self.vmlock.release()
	
	def __enter__(self):
		return self

	def __exit__(self, exc_type, exc_value, traceback):
		self.cleanup_stats()

	def write_tempfile(self, content: str):
		# Create a temporary file with mode 'w+' (read/write)
		try:
			fd, temp_file_path = tempfile.mkstemp(dir=self.workdir, text=True)
			print(f"Temporary file created at: {temp_file_path}")

			with os.fdopen(fd, 'w') as tmp_file:
				tmp_file.write(content)

			with open(temp_file_path, 'r') as tmp_file:
				read_content = tmp_file.read()
				print(f"Temporary file content:\n{read_content}")
			self.tmpfile = temp_file_path

		except Exception as e:
			print(f"Failed to create temporary file: {e}")
			temp_file_path = None

	def create_timestamp_file(self, content: str, prefix: str = None, logdebug: bool = True):
		"""
		Create a file named with current timestamp in specified directory, timestamp format is YYYYMMDD-HHMMSS.
		Args:
			directory (str, optional): Target directory for file creation. Defaults to current directory.

		Returns:
			str or None: Created file path, returns None if creation fails.
		"""
		try:
			# Get current timestamp
			now = datetime.now()

			# Convert timestamp to string in specified format
			time_format = "%y%m%d-%H%M%S-%f"
			timestamp_str = now.strftime(time_format)

			# Build complete file path
			if prefix:
				filename = f"{prefix}_prog_{timestamp_str}"
			else:
				filename = f"prog_{timestamp_str}" # Can change file extension as needed
			filepath = os.path.join(self.workdir + '/initial_seeds', filename)

			# Create and write empty file (can write content as needed)
			with open(filepath, 'w') as f:
				# Can optionally write some initial content here
				f.write(f"{content}\n")
				pass
			
			self.tmpfile = get_absolute_path(filepath)
			self.tsfile = self.tmpfile
			if logdebug:
				print(f"File created successfully: {filepath}")
			return filepath

		except Exception as e:
			print(f"Failed to create file: {e}")
			return None
	
	def write_to_file(self, filename: str, content: str, remove_old: bool = True):
		"""
		Write content to specified file
		"""
		try:
			# Check if file exists, delete if it does
			if remove_old and os.path.exists(filename):
				console.log(f"File {filename} exists, deleting...")
				os.remove(filename)
			with open(filename, 'a+') as file:
				file.write(content)
			console.log(f"Successfully wrote content to file: {filename}")
			return True
		except Exception as e:
			console.log(f"Failed to write file: {e}")
			return False

	def extract_and_save_bpf_insn(self, filename: str):
		"""
		Save temporary file content to seed directory
		"""
		bpf_insn_definition = self.extract_bpf_insn(self.tmpfile)
		if not bpf_insn_definition:
			print(f"Warning: 'struct bpf_insn prog[]' definition not found in file '{self.tmpfile}'.")
			return False

		return self.write_to_file(filename, bpf_insn_definition)

	def save_valid_seed_to_corpus(self, isfail: bool = False, seed_category: str = None):
		"""
		Save generated valid bpf insn content to seed directory

		Args:
			isfail: Deprecated, kept for backward compatibility. Use seed_category instead.
			seed_category: One of 'success', 'usable', 'failed'. If None, determined by isfail.
				- 'success': Passed verification and contains all target helpers (or random strategy)
				- 'usable': Passed verification but missing some/all target helpers
				- 'failed': Did not pass compilation or verification
		"""
		# Determine seed_category from isfail if not explicitly provided
		if seed_category is None:
			seed_category = "failed" if isfail else "success"

		# Create seed directory
		if not os.path.exists(self.seedcorpus):
			os.mkdir(self.seedcorpus)
			console.log(f"create seedcorpus {self.seedcorpus}")

		# Write temporary file content to seed directory
		# Use os.path.basename() to get filename
		filename = os.path.basename(self.tsfile)

		# Build target file path based on seed_category
		if seed_category in ("success", "usable", "failed"):
			category_dir = os.path.join(self.seedcorpus, seed_category)
			if not os.path.exists(category_dir):
				os.makedirs(category_dir, exist_ok=True)
				console.log(f"create {seed_category} seed corpus {category_dir}")
			self.corpus_filename = os.path.join(category_dir, f"{filename}")
		else:
			# Fallback for unknown category
			self.corpus_filename = os.path.join(self.seedcorpus, f"{filename}")

		# Write content to target file
		self.extract_and_save_bpf_insn(self.corpus_filename)

		# Record to helpertable (only for success and usable seeds)
		if seed_category in ("success", "usable"):
			self.helpertable.update(self.corpus_filename)

		self.tmpfile = None

	def get_random_sample_contents(self, directory_path) -> list[str]:
		"""
		Randomly select three files from target directory and return list of their contents.

		Parameters:
			directory_path (str): Path to target directory.

		Returns:
			list: List containing contents of three randomly selected files.
			If directory has fewer than three files, return all file contents.
			If directory does not exist or is empty, return empty list.
			If error occurs while reading file, corresponding file content will be error message.
		"""
		# Create seed directory
		if not os.path.exists(directory_path):
			console.log(f"BPF IR samples directory: {directory_path} not exists")
		
		if not os.path.isdir(directory_path):
			console.log(f"Error: {directory_path} is not a directory")

		try:
			# Get list of all files in directory
			files = [f for f in os.listdir(directory_path) if os.path.isfile(os.path.join(directory_path, f))]
		except OSError as e:
			console.log(f"Error: Cannot access directory '{directory_path}': {e}")

		if not files:
			console.log(f"Error: Directory is empty or contains no files.")

		# Randomly select three files
		num_files_to_select = min(3, len(files))
		selected_files = random.sample(files, num_files_to_select)

		file_contents = []
		i = 0
		for file_name in selected_files:
			file_path = os.path.join(directory_path, file_name)
			try:
				with open(file_path, 'r', encoding='utf-8') as f: # Assume file is UTF-8 encoded
					file_contents.append(f.read())
			except UnicodeDecodeError:
				try:
					# If UTF-8 fails, try other common encodings
					with open(file_path, 'r', encoding='latin-1') as f:
						file_contents.append(f.read())
				except Exception as e:
					console.log(f"Error: Unable to read file '{file_name}': {e}")
			except Exception as e:
				console.log(f"Error: Unable to read file '{file_name}': {e}")

		return file_contents

	def get_sample_for_helper(self, helper_name: str):
		# Randomly select a file containing the helper based on helper function
		file = self.helpertable.select_file(helper_name)
		if file is None:
			return ""
		with open(file, 'r') as f: 
			content = f.read()
		return content

class HelperTable:
	'''
	Build a table recording bpf insn files containing specific helper functions
	Information:
	helper function -> [file1, file2, ...]

	'''
	def __init__(self, seedcorpus):
		self.table = defaultdict(list)
		self.seedcorpus = seedcorpus
		self.filelist = []
		self.initTable()

	def initTable(self):
		# Build mapping from helper function to files based on seedcorpus directory files
		if not os.path.exists(self.seedcorpus):
			console.log(f"seedcorpus {self.seedcorpus} not exists")
			return
		files = [f for f in os.listdir(self.seedcorpus) if os.path.isfile(os.path.join(self.seedcorpus, f))]
		for file in files:
			file_path = os.path.join(self.seedcorpus, file)
			self.update(file_path)
			
			# with open(file_path, 'r') as f: # Assume file is UTF-8 encoded
			# 	content = f.read()
			# 	helpers = re.findall(r'(BPF_FUNC_\w+)', content)
			# 	for helper in helpers:
			# 		if file_path not in self.table[helper]:
			# 			self.table[helper].append(file_path)

	def update(self, file_path):
		# Add new file and update table
		self.filelist.append(file_path)
		with open(file_path, 'r') as f: # Assume file is UTF-8 encoded
			content = f.read()
			helpers = re.findall(r'(BPF_FUNC_\w+)', content)
			for helper in helpers:
				if file_path not in self.table[helper]:
					self.table[helper].append(file_path)
	
	def select_file(self, helper_name):
		# Randomly select a file containing the helper based on helper function
		if helper_name == "":
			# Randomly select a file
			if not self.filelist:
				console.log("filelist is empty")
				return None
			selected_file = random.choice(self.filelist)
			return selected_file
		if helper_name not in self.table:
			console.log(f"helper {helper_name} not in table")
			return None
		files = self.table[helper_name]
		if not files:
			console.log(f"helper {helper_name} has no files")
			return None
		selected_file = random.choice(files)
		return selected_file
	
	def print_table(self):
		for helper, files in self.table.items():
			console.log(f"Helper: {helper}")
			for file in files:
				console.log(f"  - {file}")


	