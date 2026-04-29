import struct
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import Section
from static import disassemble_bpf, BPF_FUNC
from collections import defaultdict
import re

# Constant definitions (partially from documentation)
BPF_ALU64 = 0x07
BPF_JMP = 0x05
BPF_LD = 0x00
BPF_ALU = 0x04
BPF_K = 0x00
BPF_X = 0x08

BPF_OP_ALU = {
    0x00: 'BPF_ADD',
    0x10: 'BPF_SUB',
    0x20: 'BPF_MUL',
    0x30: 'BPF_DIV',
    0x40: 'BPF_OR',
    0x50: 'BPF_AND',
    0x60: 'BPF_LSH',
    0x70: 'BPF_RSH',
    0x80: 'BPF_NEG',
    0x90: 'BPF_MOD',
    0xa0: 'BPF_XOR',
    0xb0: 'BPF_MOV',
    0xc0: 'BPF_ARSH',
    0xd0: 'BPF_END',
}

BPF_OP_JMP = {
    0x00: 'BPF_JA',
    0x10: 'BPF_JEQ',
    0x20: 'BPF_JGT',
    0x30: 'BPF_JGE',
    0x40: 'BPF_JSET',
    0x50: 'BPF_JNE',
    0x60: 'BPF_JSGT',
    0x70: 'BPF_JSGE',
    0x80: 'BPF_CALL',
    0x90: 'BPF_EXIT',
    0xa0: 'BPF_JLT',
    0xb0: 'BPF_JLE',
    0xc0: 'BPF_JSLT',
    0xd0: 'BPF_JSLE',
}

def disassemble(bytecode):
    instructions = []
    i = 0
    num =0
    while i < len(bytecode):
        if i + 8 > len(bytecode):
            break
        chunk = bytecode[i:i+8]

        # Parse instruction
        code, regs, off, imm = struct.unpack('<BBHI', chunk)
        src = (regs >> 4) & 0x0F
        dst = regs & 0x0F

        # Handle multi-byte instructions (e.g., LD_IMM64)
        if code == 0x18:  # First part of BPF_LD_IMM64
            if i + 16 > len(bytecode):
                instructions.append(f"// Incomplete LD_IMM64 at offset {i}")
                i += 8
                continue
            next_chunk = bytecode[i+8:i+16]
            next_code, _, _, next_imm = struct.unpack('<BBHI', next_chunk)
            if next_code == 0x00:
                imm64 = (next_imm << 32) | imm
                x=disassemble_bpf(code, dst, src, off, imm64)
                print(x)
                instructions.append(disassemble_bpf(code, dst, src, off, imm64))
                i += 8  # Skip second instruction
                i += 8
                continue

        # Handle common instructions
        # Common instructions classified by opcode,
        
        instructions.append(disassemble_bpf(code, dst, src, off, imm))
        
        i += 8
        num += 1
    #print(f"Disassembled {num} instructions")
    return instructions

def calculate_all(instructions):
    """
    Calculate statistics of instruction counts and types, and helper function counts and types.
    """
    instruction_count = defaultdict(int)
    helper_count = defaultdict(int)
    for func in BPF_FUNC:
        helper_count[func] = 0
    for instruction in instructions:
        # Count instructions
        if not instruction:
            continue
        instruction_type = instruction.split("(")[0]
        instruction_count[instruction_type] += 1

        function_match = re.search(r'BPF_FUNC_(\w+)', instruction)

        if function_match:
            function_name = 'BPF_FUNC_'+function_match.group(1)
            helper_count[function_name] += 1


    return instruction_count, helper_count


def disassemble_section(input_file, output_file, section_name):
    # section_name="cgroup/dev"
    with open(input_file, 'rb') as f:
        # bytecode = f.read()
        elf = ELFFile(f)
        section = elf.get_section_by_name(section_name)
        
        if not isinstance(section, Section):
            print(f"Section '{section_name}' not found")
            return False, f"Section '{section_name}' not found"
            
        bytecode = section.data()
        #print("section:", bytecode)

    ir_code = disassemble(bytecode)
    print(ir_code)
    instruction_count, helper_count = calculate_all(ir_code)
    if None not in ir_code and len(ir_code) > 0:
        with open(output_file, 'w') as f:
            # f.write("[\n")
            f.write(",\n".join(ir_code))
            # f.write("\n]\n")
    else:
        print("Disassembly failed or incomplete bytecode")
        return False, "Disassembly failed or incomplete bytecode"
    return instruction_count, helper_count

def disassemble_string(input_file:str, output_file:str):
    with open(input_file, 'r') as f:
        bytecode_string = f.read().strip()
    
    print("bytecode_string is", bytecode_string)
    bytecode = bytes([int(s.strip(), 0) for s in bytecode_string.split(',')])
    print(f"bytecode is {bytecode}, length is {len(bytecode)}")
    ir_code = disassemble(bytecode)
    print("IRcode is", ir_code)
    instruction_count, helper_count = calculate_all(ir_code)
    if None not in ir_code and len(ir_code) > 0:
        with open(output_file, 'w') as f:
            # f.write("[\n")
            f.write(",\n".join(ir_code))
            # f.write("\n]\n")
    else:
        print("Disassembly failed or incomplete bytecode")
        return False, "Disassembly failed or incomplete bytecode"
    return instruction_count, helper_count

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 3:
        print("Usage: python disassembler.py <input.bin> [output.ir] <secname>")
        sys.exit(1)
    input_file = sys.argv[1]
    output_file = sys.argv[2]

    if len(sys.argv) > 3:
        secname = sys.argv[3]
        insn, funcs = disassemble_section(input_file, output_file, secname)
    else:
        insn, funcs = disassemble_string(input_file, output_file)

    print("Instruction Count:", insn)
    print("Helper Count:", funcs)