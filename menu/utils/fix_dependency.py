import os
import json
from collections import defaultdict
import re
import random
from typing import List, Dict

# Handle eBPF dependency issues
ldbf_dir = os.environ.get("LDBF_DIR")
func_map_path = os.path.join(ldbf_dir, "dependency/func_map.json")
func_prog_path = os.path.join(ldbf_dir, "dependency/func_prog.json")
all_ebpf_path = os.path.join(ldbf_dir, "dependency/all_ebpf.json")
helper_def_path = os.path.join(ldbf_dir, "dependency/helper_def.json")
insn_def_path = os.path.join(ldbf_dir, "dependency/filter.h")
bpf_types_path = os.path.join(ldbf_dir, "dependency/bpf_types.h")
helper_protos_path = os.path.join(ldbf_dir, "dependency/bpf_helper_protos.c") 

# Maximum number of helpers that each BPF program can accommodate
helper_threshold = 1

# Define a module-level cache dictionary to store read file contents
# The key is the file path, and the value is a list of all the file lines
bpf_context_cache: Dict[str, List[str]] = {}

BPF_F_NO_PREALLOC      = (1 << 0)
BPF_F_NO_COMMON_LRU    = (1 << 1)
BPF_F_NUMA_NODE        = (1 << 2)
BPF_F_RDONLY           = (1 << 3)
BPF_F_WRONLY           = (1 << 4)
BPF_F_STACK_BUILD_ID   = (1 << 5)
BPF_F_ZERO_SEED        = (1 << 6)
BPF_F_RDONLY_PROG      = (1 << 7)
BPF_F_WRONLY_PROG      = (1 << 8)
BPF_F_CLONE            = (1 << 9)
BPF_F_MMAPABLE         = (1 << 10)
BPF_F_PRESERVE_ELEMS   = (1 << 11)
BPF_F_INNER_MAP        = (1 << 12)
BPF_F_LINK             = (1 << 13)
BPF_F_PATH_FD          = (1 << 14)
BPF_F_VTYPE_BTF_OBJ_FD = (1 << 15)
BPF_F_TOKEN_FD         = (1 << 16)
BPF_F_SEGV_ON_FAULT    = (1 << 17)
BPF_F_NO_USER_CONV     = (1 << 18)

# BPF map type definitions
# todo: update
# Specific map types require BTF ID
BPF_MAP_TYPES = {
	"BPF_MAP_TYPE_UNSPEC": {"type": 0, "key_size": [], "value_size": [], "max_entries": []},
	"BPF_MAP_TYPE_HASH": {"type": 1, "key_size": [4], "value_size": [], "max_entries": []},
	"BPF_MAP_TYPE_ARRAY": {"type": 2, "key_size": [4], "value_size": [], "max_entries": []},
	"BPF_MAP_TYPE_PROG_ARRAY": {"type": 3, "key_size": [4], "value_size": [4], "max_entries": []},
	"BPF_MAP_TYPE_PERF_EVENT_ARRAY": {"type": 4, "key_size": [4], "value_size": [4], "max_entries": []},
	"BPF_MAP_TYPE_PERCPU_HASH": {"type": 5, "key_size": [], "value_size": [], "max_entries": []},
	"BPF_MAP_TYPE_PERCPU_ARRAY": {"type": 6, "key_size": [4], "value_size": [], "max_entries": []},
	"BPF_MAP_TYPE_STACK_TRACE": {"type": 7, "key_size": [4], "value_size": [8], "max_entries": []},
	"BPF_MAP_TYPE_CGROUP_ARRAY": {"type": 8, "key_size": [4], "value_size": [4], "max_entries": []},
	"BPF_MAP_TYPE_LRU_HASH": {"type": 9, "key_size": [], "value_size": [], "max_entries": []},
	"BPF_MAP_TYPE_LRU_PERCPU_HASH": {"type": 10, "key_size": [4], "value_size": [4], "max_entries": []},
	"BPF_MAP_TYPE_LPM_TRIE": {"type": 11, "key_size": [8], "value_size": [8], "max_entries": [], "map_flags": BPF_F_NO_PREALLOC},
	"BPF_MAP_TYPE_ARRAY_OF_MAPS": {"type": 12, "key_size": [4], "value_size": [4], "max_entries": []},
	"BPF_MAP_TYPE_HASH_OF_MAPS": {"type": 13, "key_size": [], "value_size": [], "max_entries": []},
	"BPF_MAP_TYPE_DEVMAP": {"type": 14, "key_size": [4], "value_size": [4, 8], "max_entries": []},
	"BPF_MAP_TYPE_SOCKMAP": {"type": 15, "key_size": [4], "value_size": [4], "max_entries": []},
	"BPF_MAP_TYPE_CPUMAP": {"type": 16, "key_size": [4], "value_size": [4, 8], "max_entries": []},
	"BPF_MAP_TYPE_XSKMAP": {"type": 17, "key_size": [4], "value_size": [4], "max_entries": []},
	"BPF_MAP_TYPE_SOCKHASH": {"type": 18, "key_size": [8], "value_size": [4], "max_entries": []},
	"BPF_MAP_TYPE_CGROUP_STORAGE": {"type": 19, "key_size": [8], "value_size": [], "max_entries": [0]},
	"BPF_MAP_TYPE_REUSEPORT_SOCKARRAY": {"type": 20, "key_size": [4], "value_size": [4, 8], "max_entries": []},
	"BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE": {"type": 21, "key_size": [8], "value_size": [], "max_entries": [0]},
	"BPF_MAP_TYPE_QUEUE": {"type": 22, "key_size": [0], "value_size": [], "max_entries": []},
	"BPF_MAP_TYPE_STACK": {"type": 23, "key_size": [0], "value_size": [], "max_entries": []},
	"BPF_MAP_TYPE_SK_STORAGE": {"type": 24, "key_size": [4], "value_size": [4], "max_entries": [0], "need_btf": 1, "map_flags": BPF_F_NO_PREALLOC},
	"BPF_MAP_TYPE_DEVMAP_HASH": {"type": 25, "key_size": [4], "value_size": [4, 8], "max_entries": []},
	"BPF_MAP_TYPE_STRUCT_OPS": {"type": 26, "key_size": [4], "value_size": [], "max_entries": [1]},
	"BPF_MAP_TYPE_RINGBUF": {"type": 27, "key_size": [0], "value_size": [0], "max_entries": [4096, 8192, 16384, 32768]},
	"BPF_MAP_TYPE_INODE_STORAGE": {"type": 28, "key_size": [4], "value_size": [4], "max_entries": [0], "need_btf": 1, "map_flags": BPF_F_NO_PREALLOC},
	"BPF_MAP_TYPE_TASK_STORAGE": {"type": 29, "key_size": [4], "value_size": [4], "max_entries": [0], "need_btf": 1, "map_flags": BPF_F_NO_PREALLOC},
	"BPF_MAP_TYPE_BLOOM_FILTER": {"type": 30, "key_size": [0], "value_size": [], "max_entries": [1]},
	"BPF_MAP_TYPE_USER_RINGBUF": {"type": 31, "key_size": [0], "value_size": [0], "max_entries": [4096, 8192, 16384, 32768]},
	"BPF_MAP_TYPE_CGRP_STORAGE": {"type": 32, "key_size": [4], "value_size": [4], "max_entries": [0], "need_btf": 1, "map_flags": BPF_F_NO_PREALLOC},
	"BPF_MAP_TYPE_ARENA": {"type": 33, "key_size": [0], "value_size": [0], "max_entries": [1]},
}


with open(func_map_path, 'r') as f:
	func_map = json.load(f)
with open(func_prog_path, 'r') as f:
	func_prog = json.load(f)
with open(all_ebpf_path, 'r') as f:
	all_ebpf = json.load(f)
helpers = all_ebpf['helper']
map_type = all_ebpf['map']
progs = all_ebpf['prog']
func_with_map = all_ebpf['helper_map']
default_select = ["BPF_MAP_TYPE_HASH", "BPF_MAP_TYPE_ARRAY"]
# Identify helpers that operate on maps in the program, and ld_map instructions
# Read C file content, match map types and names, and call order
# Replace BPF_LD_MAP_FD instructions in IR with map_create return values
import re

def generate_map_attr(map_type, map_name):
	info = BPF_MAP_TYPES[map_type]
	if info["key_size"] !=[]:
		map_key=random.choice(info["key_size"])
	else:
		map_key=random.randint(1, 20)*4
	if info["value_size"] !=[]:
		map_value=random.choice(info["value_size"])
	else:
		map_value=random.randint(1, 20)*4
	if info["max_entries"] !=[]:
		map_max_entries=random.choice(info["max_entries"])
	else:
		map_max_entries= random.randint(1, 20)*4
	need_btf = info.get("need_btf", 0)
	map_flags = info.get("map_flags", 0)

	return (map_type, map_name, map_key, map_value, map_max_entries, map_flags, need_btf)

def select_map_for_helper(helpers:list):
	# Take the intersection of map types for each helper
	print("target helper:",helpers)
	possible_maps = []
	for helper in helpers:
		if helper in func_map:
			if possible_maps == []:
				possible_maps = func_map[helper]
			else:
				possible_maps = list(set(possible_maps) & set(func_map[helper]))
	if possible_maps == []:
		possible_maps = default_select

	# Print selected map type(s)
	if len(possible_maps) == 1:
		print(f"Selected map type: {possible_maps[0]}")
	else:
		print(f"Selected map types: {', '.join(possible_maps)}")

	return possible_maps



def extract_maps_ir(ir_code):
    # Extract all BPF_LD_MAP_FD and BPF_EMIT_CALL instructions in order from start to end
    helper_func = re.compile(r'(BPF_FUNC_\w+)')
    target_insns = []
    map_pairs = []
    map_refs = []
    insns = ir_code.split('\n')

    # First collect all target instructions (keeping original logic)
    for insn in insns:
        # Filter comment lines: skip lines starting with //, /*, *
        stripped = insn.strip()
        if stripped.startswith('//') or stripped.startswith('/*') or stripped.startswith('*'):
            continue

        if 'BPF_LD_MAP_FD' in insn:
            target_insns.append(insn.strip())
        if "BPF_FUNC_" in insn:
            helper = helper_func.search(insn)
            if helper and helper.group(1) in func_with_map:
                target_insns.append(insn.strip())
    
    # Pair LD_MAP with corresponding HELPER instructions
    length = len(target_insns)
    total = 0
    
    i = 0
    while i < length:
        if 'BPF_LD_MAP_FD' in target_insns[i]:
            # Find all HELPERs after current MAP instruction until next MAP or end
            helpers = []
            j = i + 1
            while j < length and 'BPF_LD_MAP_FD' not in target_insns[j]:
                if 'BPF_FUNC_' in target_insns[j]:
                    # Extract helper function name (keeping original extraction logic)
                    helper = helper_func.search(target_insns[j]).group(1)
                    helpers.append(helper.upper())
                j += 1
            
            map_name = f"map_{total}"
            
            if helpers:
                # Has corresponding helpers, pass all helpers for selection
                choose_maps = select_map_for_helper(helpers)
                map_attrs = []
                for choose_map in choose_maps:
                    map_attr = generate_map_attr(choose_map, map_name)
                    map_attrs.append(map_attr)
                map_pairs.append(map_attrs)
            else:
                # No corresponding helper, use default_select
                choose_map = random.choice(default_select)
                map_attr = generate_map_attr(choose_map, map_name)
                map_pairs.append([map_attr])
            
            map_refs.append(map_name)
            total += 1
            i = j  # Jump to next MAP instruction position
        else:
            i += 1
    
    return map_pairs, map_refs

def extract_maps(c_code):
	# c_code = """
	# struct {
	#     __uint(type, BPF_MAP_TYPE_HASH);
	#     __uint(max_entries, 1024);
	# } hash_map SEC(".maps");

	# struct {
	#     __uint(type, BPF_MAP_TYPE_ARRAY);
	#     __uint(max_entries, 256);
	# } array_map SEC(".maps");
	# int z = bpf_map_delete_elem(&array_map, &key);
	# """
	# print(c_code)
	map_types = []
	map_names = []
	pattern = r'__uint\(\s*type\s*,\s*(BPF_MAP_TYPE_\w+)\s*\)[^}]*}\s*(\w+)\s*SEC'

	matches = re.findall(pattern, c_code, re.DOTALL)
	for match in matches:
		map_type, map_name = match
		map_types.append(map_type)
		map_names.append(map_name)
	# print(matches)

	# Extract all map_type and map_name
	# map_types = re.findall(r"__uint*type,\s*(BPF_MAP_TYPE_\w+);$", c_code)
	# map_names = re.findall(r"}\s*(\w+)\s*SEC$\".maps\"$", c_code)
	suspect = re.findall(r"&(\w+)", c_code)
	# print(suspect)
	map_refs = []
	for s in suspect:
		if s in map_names:
			map_refs.append(s)

	# Pair into list (zip combination)
	map_pairs = []

	for i in range(len(map_types)):
		map_type = map_types[i]
		map_name = map_names[i]
		info = BPF_MAP_TYPES[map_type]
		if info["key_size"] !=[]:
			map_key=random.choice(info["key_size"])
		else:
			map_key=random.randint(1, 20)*4
		if info["value_size"] !=[]:
			map_value=random.choice(info["value_size"])
		else:
			map_value=random.randint(1, 20)*4
		if info["max_entries"] !=[]:
			map_max_entries=random.choice(info["max_entries"])
		else:
			map_max_entries= random.randint(1, 20)*4
		map_pairs.append((map_type, map_name, map_key, map_value, map_max_entries))


	print(map_pairs)
	print(map_refs)
	return map_pairs, map_refs

def create_all_maps():
	map_pairs = []
	map_types = list(BPF_MAP_TYPES.keys())
	for i in range(len(map_types)):
		map_type = map_types[i]
		map_name = "map_" + str(i)
		info = BPF_MAP_TYPES[map_type]
		if info["key_size"] !=[]:
			map_key=random.choice(info["key_size"])
		else:
			map_key=random.randint(1, 20)*4
		if info["value_size"] !=[]:
			map_value=random.choice(info["value_size"])
		else:
			map_value=random.randint(1, 20)*4
		if info["max_entries"] !=[]:
			map_max_entries=random.choice(info["max_entries"])
		else:
			map_max_entries=random.randint(1, 20)*4
		map_pairs.append((map_type, map_name, map_key, map_value, map_max_entries))
	return map_pairs

# Create function that calls map_create and fill its parameters
# Identify suitable prog type for the program and fill its parameters

def find_prog_type(helper_list):
	suitable_prog_types = []
	for prog_type in progs:
		flag=True
		for helper in helper_list:
			if prog_type not in func_prog[helper]:
				flag=False
				break
		if flag:
			suitable_prog_types.append(prog_type)
	return list(set(suitable_prog_types))



def fix_all(prog_insns):
	insns = prog_insns.split('\n')
	# Identify helpers that operate on maps in the program, and ld_map instructions
	helper_list = []
	ld_map_insn = []
	helper_with_map_list = []
	for helper in helpers:
		if helper in prog_insns:
			helper_list.append(helper)
			if helper in func_with_map:
				helper_with_map_list.append(helper)

	#map_pairs, map_refs = extract_maps(c_code)
	map_pairs, map_refs = extract_maps_ir(prog_insns)
	i=0
	for x in range(len(insns)):
		if 'BPF_LD_MAP_FD' in insns[x]:
			insns[x]=insns[x].replace('0x0', map_refs[i])
			i+=1
	
	# Identify suitable prog type for the program and fill its parameters
	suitable_prog_types = find_prog_type(helper_list)
	# print(f"Suitable program types: {suitable_prog_types}")
	
	# Output result
	result = {
		"prog": '\n'.join(insns),
		"maps": map_pairs,
		"suitable_prog_types": suitable_prog_types
	}
	
	return result

def analyze_dependency(prog_insns):
	insns = prog_insns.split('\n')
	# Identify helpers that operate on maps in the program, and ld_map instructions
	helper_list = []
	ld_map_insn = []
	helper_with_map_list = []
	for helper in helpers:
		if helper in prog_insns:
			helper_list.append(helper)
			if helper in func_with_map:
				helper_with_map_list.append(helper)

	#map_pairs, map_refs = extract_maps(c_code)
	map_pairs, map_refs = extract_maps_ir(prog_insns)
	print(f"[DEBUG] extract_maps_ir found {len(map_refs)} maps: {map_refs}")
	i=0
	map_fd_count = 0
	for x in range(len(insns)):
		# Skip comment lines to match extract_maps_ir logic
		stripped = insns[x].strip()
		if stripped.startswith('//') or stripped.startswith('/*') or stripped.startswith('*'):
			if 'BPF_LD_MAP_FD' in insns[x]:
				print(f"[DEBUG] Skipping BPF_LD_MAP_FD in comment at line {x}: {insns[x][:60]}")
			continue

		if 'BPF_LD_MAP_FD' in insns[x]:
			map_fd_count += 1
			# Add bounds check to prevent IndexError
			if i >= len(map_refs):
				print(f"[ERROR] More BPF_LD_MAP_FD instructions ({i+1}) than map_refs ({len(map_refs)})")
				print(f"[ERROR] This is likely a bug. Stopping map replacement.")
				break
			print(f"[DEBUG] Replacing BPF_LD_MAP_FD at line {x}: map_refs[{i}] = {map_refs[i]}")
			insns[x]=insns[x].split(',')[0]+f', {map_refs[i]}),'
			i+=1
	print(f"[DEBUG] Total BPF_LD_MAP_FD found in non-comment lines: {map_fd_count}")
	
	# Identify suitable prog type for the program and fill its parameters
	suitable_prog_types = find_prog_type(helper_list)
	# print(f"Suitable program types: {suitable_prog_types}")
	
	# Output result
	result = {
		"maps": map_pairs,
		"suitable_prog_types": suitable_prog_types
	}
	
	return result, '\n'.join(insns)
	
def get_random_lines_from_file(file_path: str, count_threshold: int):
	"""
	Randomly select 0 to count_threshold lines from specified file and return.
	
	This function caches file content to improve performance on repeated calls to the same file.

	Args:
		file_path (str): Path to the target file.

	Returns:
		List[str]: A list containing randomly selected lines (0 to count_threshold lines),
				   Returns empty list if file does not exist or read error occurs.
	"""
	global bpf_context_cache

	all_lines: List[str] = []

	# Step 1: Check if content is already in cache
	if file_path in bpf_context_cache:
		all_lines = bpf_context_cache[file_path]
	else:
		# If not in cache, read from file
		try:
			with open(file_path, 'r', encoding='utf-8') as f:
				# Read all lines and strip newline from each, then store in cache
				all_lines = [line.strip() for line in f.readlines()]
				bpf_context_cache[file_path] = all_lines
		except FileNotFoundError:
			print(f"Error: File '{file_path}' not found.")
			return []  # File does not exist, return empty list
		except Exception as e:
			print(f"Error occurred while reading file '{file_path}': {e}")
			return []  # Other read errors, return empty list

	# If file is empty, return empty list directly
	if not all_lines:
		return []

	# Step 2: Randomly decide number of lines to select (between 0 and selection_count)
	# To prevent requesting more lines than file has, take minimum between selection_count and total lines
	max_selection_count = min(len(all_lines), count_threshold)
	num_to_select = random.randint(1, max_selection_count)

	# Step 3: Use random.sample() to randomly select specified number of unique lines
	# random.sample() is the ideal choice for random sampling from a sequence
	selected_lines = random.sample(all_lines, k=num_to_select)

	return selected_lines, all_lines

def clear_helper_cache():
	"""Clear helper_def.json cache, force reload"""
	global bpf_context_cache
	if helper_def_path in bpf_context_cache:
		del bpf_context_cache[helper_def_path]

def get_random_helpers():
	return get_random_lines_from_file(helper_def_path, helper_threshold)

def _parse_range_or_int(item_str: str) -> List[int]:
	"""
	Parse a single item that can be either an integer or a range.

	Args:
		item_str (str): String like "5" or "1-211"

	Returns:
		List[int]: List of integers (single element for int, multiple for range)

	Examples:
		>>> _parse_range_or_int("5")
		[5]
		>>> _parse_range_or_int("1-5")
		[1, 2, 3, 4, 5]
	"""
	item_str = item_str.strip()
	if not item_str:
		return []

	# Check if it's a range (contains '-' but not at the start for negative numbers)
	if '-' in item_str and not item_str.startswith('-'):
		parts = item_str.split('-')
		if len(parts) == 2:
			try:
				start = int(parts[0].strip())
				end = int(parts[1].strip())
				if start > end:
					raise ValueError(f"Invalid range: start ({start}) > end ({end})")
				return list(range(start, end + 1))
			except ValueError as e:
				if "invalid literal" in str(e):
					raise ValueError(f"Invalid range format: '{item_str}'")
				raise

	# It's a single integer
	try:
		return [int(item_str)]
	except ValueError:
		raise ValueError(f"Invalid integer: '{item_str}'")


def parse_helper_indices_syntax(indices_str: str) -> List[List[int]]:
	"""
	Parse enhanced helper index syntax, supporting groups, individual indices, and ranges.

	Syntax rules:
	- [1,2,3]: Brackets indicate a group of helpers to be used together in one program
	- [1-5]: Range inside brackets, all helpers combined in one group
	- 4: Single number generates an independent program
	- 1-5: Range outside brackets, each helper generates independent program
	- [1,2,3],4,5-7: Comma separates different groups or individual helpers

	Args:
		indices_str (str): Helper index string, e.g., "[1,2,3],4,5-7" or "1-211"

	Returns:
		List[List[int]]: Nested list, each inner list represents a group of helper indices

	Examples:
		>>> parse_helper_indices_syntax("[1,2,3]")
		[[1, 2, 3]]

		>>> parse_helper_indices_syntax("4,5,6")
		[[4], [5], [6]]

		>>> parse_helper_indices_syntax("[1,2,3],4,5,6")
		[[1, 2, 3], [4], [5], [6]]

		>>> parse_helper_indices_syntax("1-5")
		[[1], [2], [3], [4], [5]]

		>>> parse_helper_indices_syntax("[1-5]")
		[[1, 2, 3, 4, 5]]

		>>> parse_helper_indices_syntax("[1-3],5,10-12")
		[[1, 2, 3], [5], [10], [11], [12]]
	"""
	if not indices_str or not indices_str.strip():
		return []

	result = []
	current_pos = 0
	indices_str = indices_str.strip()

	while current_pos < len(indices_str):
		# Skip whitespace
		while current_pos < len(indices_str) and indices_str[current_pos].isspace():
			current_pos += 1

		if current_pos >= len(indices_str):
			break

		# Check if it's a group (brackets)
		if indices_str[current_pos] == '[':
			# Find matching right bracket
			end_pos = indices_str.find(']', current_pos)
			if end_pos == -1:
				raise ValueError(f"Unmatched '[' at position {current_pos}")

			# Extract content inside brackets
			group_str = indices_str[current_pos + 1:end_pos]
			# Parse as integer list (support ranges inside brackets)
			group_indices = []
			for item in group_str.split(','):
				item = item.strip()
				if item:
					# Support range syntax inside brackets (e.g., [1-5])
					parsed = _parse_range_or_int(item)
					group_indices.extend(parsed)

			if group_indices:
				result.append(group_indices)

			current_pos = end_pos + 1

			# Skip trailing comma
			while current_pos < len(indices_str) and indices_str[current_pos] in [',', ' ']:
				current_pos += 1
		else:
			# Single number or range outside brackets
			# Find next comma or bracket
			next_comma = indices_str.find(',', current_pos)
			next_bracket = indices_str.find('[', current_pos)

			# Determine end position
			if next_comma == -1 and next_bracket == -1:
				end_pos = len(indices_str)
			elif next_comma == -1:
				end_pos = next_bracket
			elif next_bracket == -1:
				end_pos = next_comma
			else:
				end_pos = min(next_comma, next_bracket)

			item_str = indices_str[current_pos:end_pos].strip()
			if item_str:
				# Parse range or single integer
				parsed = _parse_range_or_int(item_str)
				# For items outside brackets, each number becomes its own group
				for num in parsed:
					result.append([num])

			current_pos = end_pos

			# Skip comma
			if current_pos < len(indices_str) and indices_str[current_pos] == ',':
				current_pos += 1

	return result

def get_helpers_by_indices(indices: List[int], debug: bool = False) -> List[str]:
	"""
	Get helper function definition by specified index (starting from 0).

	Args:
		indices (List[int]): List of helper function indices, e.g. [0, 5, 10] means get 1st, 6th, 11th helper

	Returns:
		List[str]: List containing helper function definitions for specified indices, skip if index out of range

	Examples:
		>>> get_helpers_by_indices([0, 2, 5])
		['BPF_FUNC_map_lookup_elem', 'BPF_FUNC_probe_read', 'BPF_FUNC_ktime_get_ns']

		>>> get_helpers_by_indices([100])  # If index out of range
		[]
	"""
	global bpf_context_cache

	all_lines: List[str] = []

	# Step 1: Read all helper definitions from cache or file
	cache_valid = False
	if helper_def_path in bpf_context_cache:
		cached_lines = bpf_context_cache[helper_def_path]
		# Validate cache: Check if first line is JSON structure character (indicates old version cache)
		if cached_lines and cached_lines[0] not in ['{', '}']:
			# Cache valid (already filtered { and })
			all_lines = cached_lines
			cache_valid = True
			if debug:
				print(f"[DEBUG] Using cached helper_def (total: {len(all_lines)} helpers)")
		else:
			# Cache invalid (contains { or }, old version), need to reload
			if debug:
				print(f"[DEBUG] Cache invalid (old format detected), reloading...")
			del bpf_context_cache[helper_def_path]

	if not cache_valid:
		try:
			with open(helper_def_path, 'r', encoding='utf-8') as f:
				raw_lines = [line.strip() for line in f.readlines()]
				# Filter out JSON structure characters (lines containing only { or })
				all_lines = [line for line in raw_lines if line not in ['{', '}']]
				bpf_context_cache[helper_def_path] = all_lines

				if debug:
					print(f"[DEBUG] Loaded helper_def from file: {helper_def_path}")
					print(f"[DEBUG] Raw lines: {len(raw_lines)}, After filtering {{/}}: {len(all_lines)}")
					if len(all_lines) > 51:
						import re
						match = re.match(r'"(BPF_FUNC_\w+)":', all_lines[51])
						helper_51 = match.group(1) if match else "PARSE_ERROR"
						print(f"[DEBUG] Helper at index 51: {helper_51}")
		except FileNotFoundError:
			print(f"Error: File '{helper_def_path}' not found.")
			return []
		except Exception as e:
			print(f"Error occurred while reading file '{helper_def_path}': {e}")
			return []

	# If file is empty, return empty list directly
	if not all_lines:
		return []

	# Step 2: Extract corresponding helper functions by specified indices
	selected_helpers = []
	for idx in indices:
		# Check if index is within valid range
		if 0 <= idx < len(all_lines):
			selected_helpers.append(all_lines[idx])
		else:
			print(f"Warning: Index {idx} out of range (valid range: 0-{len(all_lines)-1}), skipped.")

	return selected_helpers

def fetch_sample():
	# Select samples from sample library that contain target helper
	return

def get_insns_defs() -> List[str]:
	lines = []
	with open(insn_def_path, 'r', encoding='utf-8') as f:
		lines = [line.strip() for line in f.readlines()]
	return lines

def get_reg_types_defs() -> List[str]:
	lines = []
	with open(bpf_types_path, 'r', encoding='utf-8') as f:
		lines = [line.strip() for line in f.readlines()]
	return lines

def get_func_proto_for_helper(helper_name: str) -> str:
	"""
	Extract corresponding bpf_func_proto struct definition from bpf_helper_protos.c file by helper name

	Args:
		helper_name (str): Helper function name, e.g. "BPF_FUNC_map_lookup_elem"

	Returns:
		str: Corresponding complete bpf_func_proto struct definition, return empty string if not found
	"""
	# Convert helper name to corresponding proto name
	# BPF_FUNC_map_lookup_elem -> bpf_map_lookup_elem_proto
	if not helper_name.startswith("BPF_FUNC_"):
		return ""

	# Remove BPF_FUNC_ prefix, convert to lowercase, then add bpf_ prefix and _proto suffix
	func_name = helper_name[9:]  # Remove "BPF_FUNC_" prefix
	proto_name = f"bpf_{func_name.lower()}_proto"

	try:
		# Use cache mechanism to read helper_protos file
		if helper_protos_path in bpf_context_cache:
			lines = bpf_context_cache[helper_protos_path]
		else:
			with open(helper_protos_path, 'r', encoding='utf-8') as f:
				lines = [line.rstrip() for line in f.readlines()]
				bpf_context_cache[helper_protos_path] = lines

		# Find corresponding struct definition
		proto_definition = []
		found_start = False
		brace_count = 0

		for line in lines:
			# Find start of struct definition
			if not found_start and f"struct bpf_func_proto {proto_name} = {{" in line:
				found_start = True
				proto_definition.append(line)
				brace_count = 1
				continue
			elif not found_start and f"const struct bpf_func_proto {proto_name} = {{" in line:
				found_start = True
				proto_definition.append(line)
				brace_count = 1
				continue

			if found_start:
				proto_definition.append(line)

				# Count braces to determine end of struct definition
				brace_count += line.count('{')
				brace_count -= line.count('}')

				# Struct definition ends when braces are balanced
				if brace_count == 0:
					break

		if proto_definition:
			return '\n'.join(proto_definition)
		else:
			return f"/* Helper prototype not found for {helper_name} */"

	except FileNotFoundError:
		return f"/* Error: {helper_protos_path} not found */"
	except Exception as e:
		return f"/* Error reading helper prototypes: {e} */"