import os
import subprocess
import re
from .fix_dependency import fix_all, analyze_dependency
import random


class DependencyFixer:
    '''fix the dependency of the given program instructions'''
    def __init__(self, prog_insns, template):
        self.prog_insns = prog_insns
        self.template = template

        '''
        dependency = {
            "maps": [[maps...],...],
            "suitable_prog_types": [],
        '''
        self.dependency = {}
        self.analyze()
    

    def analyze(self):
        '''Analyze the program instructions to determine dependencies'''
        self.dependency, self.prog_insns = analyze_dependency(self.prog_insns)
        if self.dependency["suitable_prog_types"]==[]:
            raise Exception("No suitable program types found for the given instructions.")
    
    def random_fix(self):
        '''Randomly fix the dependencies'''
        prog_type = random.choice(self.dependency["suitable_prog_types"])
        map_types = []
        for i, maps in enumerate(self.dependency["maps"]):
            if len(maps) == 0:
                raise Exception(f"Empty map configuration at index {i}. Cannot select map type.")
            map_types.append(random.choice(maps))
        return self.fix_once(prog_type, map_types)
    

        

    def fix_once(self, prog_type: str, map_types: list):
        '''
            Fix the dependencies once
            select prog type
            select map types
        '''
        # Input: template PoC and prog sequence
        # Output: filled PoC content
        # The input prog sequence includes struct definitions

        poc_template = self.template
        """
    /** The definition of bpf insn array Start ... **/

    /** The definition of bpf insn array End ... **/
        """

        #prog = extract_prog(filename)
        try:
            
            prog=self.prog_insns
            map_create = create_maps(map_types)
            #map_create = create_maps(create_all_maps())
        except Exception as e:
            print(f"Error in fix_all: {e}")
            return (False, str(e))   
        #prog_type="BPF_PROG_TYPE_LSM"
        print(f"Selected program type: {prog_type}")    
        poc = poc_template.replace("/** The definition of bpf insn array Start ... **/", prog)
        poc = poc.replace("/*replace_with_map_create*/", map_create)
        poc = poc.replace("/*replace_with_prog_flags*/", fix_flags(prog_type))
        poc = poc.replace("/*replace_with_expected_attach_type*/", fix_expected_attach_type(prog_type))
        poc = poc.replace("/*replace_with_btf_id*/", fix_btf_id(prog_type))
        poc = poc.replace("replace_with_prog_type", prog_type)

        return poc


def fetch_btf_id():
    # Use bpftool command to get BTF ID
    vmlinux_path = os.environ.get("LDBF_VMLINUX_PATH","")
    command = f"bpftool btf dump file {vmlinux_path} | grep 'bpf_lsm_file_mprotect'"
    try:
        result = subprocess.run(command, shell=True, check=True, capture_output=True, text=True)
        btf_id = result.stdout.strip().split('[')[1].split(']')[0]
        return btf_id
    except subprocess.CalledProcessError as e:
        print(f"Error fetching BTF ID: {e}")
        return ""

btf_id = fetch_btf_id()

def fix_flags(type):
    if type == "BPF_PROG_TYPE_SYSCALL":
        return "attr.prog_flags = BPF_F_SLEEPABLE;"
    elif type=="BPF_PROG_TYPE_XDP":
        return "attr.prog_flags = BPF_F_XDP_HAS_FRAGS;"

    else :
        return ""

def fix_expected_attach_type(type):
    if type == "BPF_PROG_TYPE_CGROUP_SOCK_ADDR":
        return "attr.expected_attach_type = BPF_CGROUP_INET4_CONNECT;"
    elif type == "BPF_PROG_TYPE_CGROUP_SOCKOPT":
        return "attr.expected_attach_type = BPF_CGROUP_GETSOCKOPT;"
    elif type == "BPF_PROG_TYPE_SK_LOOKUP":
        return "attr.expected_attach_type = BPF_SK_LOOKUP;"
    elif type == "BPF_PROG_TYPE_LIRC_MODE2":
        return "attr.expected_attach_type = BPF_LIRC_MODE2;"
    elif type == "BPF_PROG_TYPE_TRACING":
        return "attr.expected_attach_type = BPF_TRACE_FENTRY;"
    elif type == "BPF_PROG_TYPE_LSM":
        return "attr.expected_attach_type = BPF_LSM_MAC;"
    elif type == "BPF_PROG_TYPE_NETFILTER":
        return "attr.expected_attach_type = BPF_NETFILTER;"
    elif type == "BPF_PROG_TYPE_CGROUP_SKB":
        return "attr.expected_attach_type = BPF_CGROUP_INET_INGRESS;"
    elif type == "BPF_PROG_TYPE_CGROUP_SOCK":
        return "attr.expected_attach_type = BPF_CGROUP_INET_SOCK_CREATE;"
    else:
        return ""

def fix_btf_id(type):
    global btf_id
    if (type == "BPF_PROG_TYPE_LSM" or type == "BPF_PROG_TYPE_TRACING" or type == "BPF_PROG_TYPE_EXT") and btf_id!="":
        return f"attr.attach_btf_id = {btf_id};"
    else:
        return ""

def run_command(command):
    message=""
    flag=True
    try:
        result = subprocess.run(command, timeout=25, check=True, capture_output=True, text=True, shell=True)
        message+=result.stdout
        message+=result.stderr
    except subprocess.TimeoutExpired as e:
        flag=False
        message+=f'Command timeout: {e}'
        message+=str(e.stdout)
        message+=str(e.stderr)
    except subprocess.CalledProcessError as e:
        flag=False
        message+=f'Command execution failed: {e}'
        message+=e.stdout
        message+=e.stderr
    except Exception as e:
        flag=False
        message+=f'Error occurred: {e}'
    return (flag, message)




def extract_prog(filename):
    with open(filename, 'r') as file:
        content = file.read()
    # program example:
    """
    Match including the struct definition
  struct bpf_insn prog[] = {
  BPF_MOV64_REG(BPF_REG_6, BPF_REG_1),   // R6 = R1 (save sk_buff pointer)
  BPF_MOV64_IMM(BPF_REG_2, 0),          // R2 = 0 (initialize counter)
  ...
  };
    
    """

    prog = """
struct bpf_insn prog[] = {

{content}
};

"""
    prog=prog.replace("{content}",content)
    #prog=prog.replace("{prog}", re.search(r'struct bpf_insn prog\[\] = \{(.*?)\};', content, re.DOTALL).group(1).strip())
    return prog


def create_maps(map_pairs):
    map_defines= ""
    map_define = """
    int {name}=bpf_map_create({type}, {key_size}, {value_size}, {max_entries}, {map_flags}, {need_btf});\n
    printf("create map {name}: %d\\n", {name});
    """
    for pair in map_pairs:
        type, name, key_size, value_size, max_entries, map_flags, need_btf = pair
        map_defines += map_define.format(name=name, type=type, key_size=key_size,
                                         value_size=value_size, max_entries=max_entries,
                                         map_flags=map_flags, need_btf=need_btf)
    return map_defines


def fill_poc(template_content, prog_insns):
    # Input: template PoC and prog sequence
    # Output: filled PoC content
    # The input prog sequence includes struct definitions

    poc_template = template_content
    """
/** The definition of bpf insn array Start ... **/

/** The definition of bpf insn array End ... **/
    """

    #prog = extract_prog(filename)
    try:
        result=fix_all(prog_insns)
        prog=result["prog"]
        map_create = create_maps(result["maps"])
        #map_create = create_maps(create_all_maps())
        prog_type = random.choice(result["suitable_prog_types"])
    except Exception as e:
        print(f"Error in fix_all: {e}")
        return (False, str(e))   
    #prog_type="BPF_PROG_TYPE_LSM"
    print(f"Selected program type: {prog_type}")    
    poc = poc_template.replace("/** The definition of bpf insn array Start ... **/", prog)
    poc = poc.replace("/*replace_with_map_create*/", map_create)
    poc = poc.replace("/*replace_with_prog_flags*/", fix_flags(prog_type))
    poc = poc.replace("/*replace_with_expected_attach_type*/", fix_expected_attach_type(prog_type))
    poc = poc.replace("/*replace_with_btf_id*/", fix_btf_id(prog_type))
    poc = poc.replace("replace_with_prog_type", prog_type)

    return poc

