from bpf_proto import *
import sys
import os
import re
import json


PROG=[]


def decode_bytecode(bytecode: bytes):
    if len(bytecode) % 8 != 0:
        raise ValueError(f"Bytecode length must be multiple of 8, got {len(bytecode)}")

    bpf_insns = []
    for i in range(0, len(bytecode), 8):
        chunk = bytecode[i:i+8]
        code, regs, off, imm = struct.unpack('<BBHI', chunk)
        dst = regs & 0xf
        src = (regs >> 4) & 0xf
        bpf_insns.append(
            "{{0x{:x}, 0x{:x}, 0x{:x}, 0x{:x}, 0x{:x}}}".format(
                code, dst, src, off & 0xffff, imm & 0xffffffff
            )
        )

    json_result = {
        "bpf_insn": ", ".join(bpf_insns)
    }

    return json.dumps(json_result, indent=4)

def execute_embedded_program(prog:str):
    # Preprocess IR program, strip comments and other C code, extract IR code
    pattern = r'(BPF_[A-Z0-9_]+\([^)]*\)[,\n]?)'
    instructions = re.findall(pattern, prog)
    prog_string = "[\n" + ",\n".join(insn.rstrip(',') for insn in instructions) + "\n]"
    print("Number of instructions:", len(instructions))
    print(prog_string)

    # Use exec to execute code in string and convert to JSON format result
    env={}
    env.update(globals())
    exec(f"PROG = {prog_string}", env)
    PROG=env['PROG']
    result = decode_bytecode(assemble(PROG))
    
    print(result)

    return result





if __name__ == "__main__":
    # Get command line arguments
    # Input file path
    # Output file path, defaults to output.json
    if len(sys.argv) < 2:
        print("Usage: python translate.py <input_file> [output_file]")
        sys.exit(1)

    filepath = sys.argv[1] 
    output_path = sys.argv[2] if len(sys.argv) > 2 else "output.json"

    
    if os.path.exists(filepath):
        with open(filepath, 'r') as f:
            content=f.read()
    else:
        print(f"File {filepath} does not exist.")
        
    result=execute_embedded_program(content)
    with open(output_path, "w") as f:
        f.write(result)


