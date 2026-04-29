import argparse
from llmbpf import LLMBPFSEED
from utils import VMContext
import langchain.globals
import threading
import queue
from langchain_core.messages import HumanMessage
import random
import json
import sys

user_content = '''
Help me generate a Linux ebpf bytecode program. Requirements are as follows:
1. Generate at least 10 ebpf instructions, and combine multiple types of BPF instructions, including but not limited to:
BPF_ALU, BPF_MOV, BPF_LD, BPF_ATOMIC, BPF_ST, BPF_JMP, BPF_RAW_INSN, BPF_EXIT_INSN, etc.
2. Randomly select ebpf instructions, and the sequence order and content of each generation are significantly different.
'''

def generate_user_content():
        insnnum = random.randrange(5, 46)
        insnnum = 10
        # print(f"Generate ebpf instructions number is {insnnum}")
        user_content = f'''
        Help me generate a Linux ebpf bytecode program. Requirements are as follows:
        1. Generate at least {insnnum} ebpf instructions, and combine multiple types of BPF instructions, including but not limited to:
        BPF_ALU, BPF_MOV, BPF_LD, BPF_ATOMIC, BPF_ST, BPF_JMP, BPF_RAW_INSN, BPF_EXIT_INSN, etc.
        2. Randomly select ebpf instructions, and the sequence order and content of each generation are significantly different.
        '''
        return user_content

def worker_thread(args: argparse.Namespace, threadid: int, user_content: str, prog_queue: queue.Queue):
        """A simple thread that simulates works."""
        # print(f"Thread {threadid} executed to generate ebpf program.")
        with VMContext(workdir=args.workdir, 
                       pocexecfile=args.pocexecfile, 
                       poctemplate=args.poctemplate, 
                       pocinsnfile=args.pocinsnfile, 
                       seedcorpus=args.seedcorpus,) as vm_context:
                llm_bpf_seed = LLMBPFSEED(vm_context,
                                        args_url=args.url,
                                        args_provider=args.model,
                                        args_key=args.key,
                                        args_seednum=args.seednum,
                                        langfuse=args.langfuse,
                                        fixcompile=args.fixcompile,
                                        fixverifier=args.fixverifier,
                                        logdebug=args.logdebug,)
                
                messages = [HumanMessage(content = user_content)]
                llm_bpf_seed.generate_seed({"messages": messages})

                bpf_prog_file = llm_bpf_seed.vm_context.tmpfile
                extract_bpf_prog = f'{llm_bpf_seed.vm_context.extract_bpf_insn(llm_bpf_seed.vm_context.tmpfile)}\n'
                # print("Extract bpf prog is:\n", extract_bpf_prog)
                prog_queue.put([bpf_prog_file, extract_bpf_prog])

def main():
        parser = argparse.ArgumentParser()
        parser.add_argument('-w', '--workdir', help="work directory of target VM", required=True)
        parser.add_argument('-e', '--pocexecfile', help="filepath of the executable poc program to run bpf insn", default="./vm/poc")
        parser.add_argument('-t', '--poctemplate', help="filepath of the template poc", default="./template/poc.c")
        parser.add_argument('-b', '--pocinsnfile', help="filepath of the poc with bpf insn program", default="./vm/poc.c")
        parser.add_argument('-o', '--seedcorpus', help="the output directory to store valid seed corpus", default="./generate-seeds")
        parser.add_argument('-u', '--url', help="base url of api", default="https://api.openai.com/v1")
        parser.add_argument('-m', '--model', help="llm model provider", choices=['openai', 'deepseek', 'xai'], required=True)
        parser.add_argument('-k', '--key', help="api key, could also provided from environment variables", default="")
        parser.add_argument('-n', '--seednum', help="how many bpf prog you want to generate", default=1)
        parser.add_argument('-p', '--thread', help="how many thread you want to create", type=int, default=1)
        parser.add_argument('-v', '--verbose', help="enable the verbose of langchain", action=argparse.BooleanOptionalAction)
        parser.add_argument('--langfuse', help="use langfuse for tracing", action=argparse.BooleanOptionalAction, default=True)
        parser.add_argument('--fixcompile', help="use compile result for feedback", action=argparse.BooleanOptionalAction, default=False)
        parser.add_argument('--fixverifier', help="use verifier result for feedback", action=argparse.BooleanOptionalAction, default=False)
        parser.add_argument('--logdebug', help="print debug issues", action=argparse.BooleanOptionalAction, default=False)
        args = parser.parse_args()

        if args.verbose:
                langchain.globals.set_debug(True)
                langchain.globals.set_verbose(True)

        thread_list = []
        prog_queue = queue.Queue()

        num_to_generate = args.thread

        for idx in range(num_to_generate):
                user_content = generate_user_content()
                thri = threading.Thread(target=worker_thread, args=(args, idx, user_content, prog_queue,))
                thri.start()
                # print(f"Thread {idx} started.")
                thread_list.append(thri)

        # print("Main Thread: All threads started. Waiting for them to finish...")

        bpfgrogs_dict = {}
        for _ in range(num_to_generate):
                try:
                    # Get result from queue, expected to be a list with two elements [filepath, code]
                    prog_item = prog_queue.get(timeout=300) # Add timeout to prevent deadlock
                    if isinstance(prog_item, list) and len(prog_item) == 2:
                        file_path = prog_item[0]
                        program_code = prog_item[1]
                        # Add to dictionary with file path as key and code as value
                        bpfgrogs_dict[file_path] = program_code
                    else:
                         print(f"Warning: Received unexpected item from queue: {prog_item}", file=sys.stderr)
                except queue.Empty:
                    print("Warning: Queue is empty, maybe a thread failed?", file=sys.stderr)
                    break # Exit loop if queue is empty

        # Wait for all threads to actually finish
        for idx, thr in enumerate(thread_list):
                thr.join()
                # print(f"Thread {idx} finished.")

        # print("Generate BPF program dict:\n", bpfgrogs_dict)

        # Output JSON using the modified dictionary
        print(json.dumps(bpfgrogs_dict, indent=4), file=sys.stderr) # Use indent=4 for pretty printing (optional)
        # print("Main Thread: All tasks completed.")

if __name__ == '__main__':
        main()