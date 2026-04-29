import argparse
from llmbpf import LLMBPFSEED
from utils import VMContext
import langchain.globals
import threading
from queue import Queue
import time
from datetime import datetime
from pwnlib.tubes.process import process
import csv
from pathlib import Path
from rich import print


def _safe_int(value, default=0):
        """Safely parse integer from CSV value, handling schema mismatch."""
        if value is None or value == '':
                return default
        try:
                return int(value)
        except (ValueError, TypeError):
                return default


def _safe_float(value, default=0.0):
        """Safely parse float from CSV value, handling schema mismatch."""
        if value is None or value == '':
                return default
        try:
                return float(value)
        except (ValueError, TypeError):
                return default


def print_run_summary(csv_file: str, run_id: str):
        """
        Print summary statistics for a specific run_id from the CSV file.

        Args:
                csv_file: Path to the CSV statistics file
                run_id: The run_id to filter records
        """
        csv_path = Path(csv_file)
        if not csv_path.exists():
                print(f"Warning: Statistics file {csv_file} not found. No summary available.")
                return

        # Read and filter CSV records
        records = []
        try:
                with open(csv_file, 'r', newline='', encoding='utf-8') as f:
                        reader = csv.DictReader(f)
                        for row in reader:
                                if row.get('run_id') == run_id:
                                        records.append(row)
        except Exception as e:
                print(f"Error reading CSV file: {e}")
                return

        if not records:
                print(f"No records found for run_id: {run_id}")
                return

        # Calculate statistics
        total_seeds = len(records)

        # Seed category statistics (based on seed_category field)
        success_count = sum(1 for r in records if r.get('seed_category') == 'success')
        usable_count = sum(1 for r in records if r.get('seed_category') == 'usable')
        failed_count = sum(1 for r in records if r.get('seed_category') == 'failed')

        # Fallback: if seed_category not available, use success field
        if success_count + usable_count + failed_count == 0:
                success_count = sum(1 for r in records if r.get('success') == 'success')
                failed_count = total_seeds - success_count

        # Helper coverage statistics
        coverage_full = sum(1 for r in records if r.get('helper_coverage') == 'full')
        coverage_partial = sum(1 for r in records if r.get('helper_coverage') == 'partial')
        coverage_none = sum(1 for r in records if r.get('helper_coverage') == 'none')
        coverage_na = sum(1 for r in records if r.get('helper_coverage') == 'n_a')

        # Average compile and verifier fixes
        compile_fixes = [_safe_int(r.get('compile_fixes', 0)) for r in records]
        verifier_fixes = [_safe_int(r.get('verifier_fixes', 0)) for r in records]
        avg_compile_fixes = sum(compile_fixes) / total_seeds if total_seeds > 0 else 0
        avg_verifier_fixes = sum(verifier_fixes) / total_seeds if total_seeds > 0 else 0

        # Token statistics (theoretical input tokens = input + cache_creation + cache_read)
        theoretical_input_tokens = []
        output_tokens = []
        for r in records:
                # Use pre-calculated theoretical_input_tokens if available
                if 'theoretical_input_tokens' in r and r['theoretical_input_tokens']:
                        theo_input = _safe_int(r['theoretical_input_tokens'])
                else:
                        # Fallback: calculate from individual fields
                        input_t = _safe_int(r.get('input_tokens', 0))
                        cache_creation = _safe_int(r.get('cache_creation_tokens', 0))
                        cache_read = _safe_int(r.get('cache_read_tokens', 0))
                        theo_input = input_t + cache_creation + cache_read
                theoretical_input_tokens.append(theo_input)
                output_tokens.append(_safe_int(r.get('output_tokens', 0)))

        avg_input_tokens = sum(theoretical_input_tokens) / total_seeds if total_seeds > 0 else 0
        avg_output_tokens = sum(output_tokens) / total_seeds if total_seeds > 0 else 0

        # Time statistics
        total_times = [_safe_float(r.get('total_time_seconds', 0)) for r in records]
        avg_time = sum(total_times) / total_seeds if total_seeds > 0 else 0
        total_time = sum(total_times)

        # Detailed time breakdown statistics
        llm_times = [_safe_float(r.get('llm_time_seconds', 0)) for r in records]
        compile_times = [_safe_float(r.get('compile_time_seconds', 0)) for r in records]
        verifier_times = [_safe_float(r.get('verifier_time_seconds', 0)) for r in records]

        avg_llm_time = sum(llm_times) / total_seeds if total_seeds > 0 else 0
        avg_compile_time = sum(compile_times) / total_seeds if total_seeds > 0 else 0
        avg_verifier_time = sum(verifier_times) / total_seeds if total_seeds > 0 else 0

        total_llm_time = sum(llm_times)
        total_compile_time = sum(compile_times)
        total_verifier_time = sum(verifier_times)

        # Cost statistics (theoretical cost)
        theoretical_costs = [_safe_float(r.get('theoretical_cost_usd', 0)) for r in records]
        avg_cost = sum(theoretical_costs) / total_seeds if total_seeds > 0 else 0
        total_cost = sum(theoretical_costs)

        # Get experiment component and model name from first record
        experiment_component = records[0].get('experiment_component', 'Unknown')
        model_name = records[0].get('model_name', 'Unknown')

        # Print formatted summary
        print("\n" + "=" * 80)
        print("                           Task Summary Statistics")
        print("=" * 80)
        print(f"Run ID: {run_id}")
        print(f"Task Component: {experiment_component}")
        print(f"Model: {model_name}")
        print()

        # Seeds Statistics Table
        print("Seeds Statistics:")
        print("┌" + "─" * 10 + "┬" + "─" * 10 + "┬" + "─" * 10 + "┬" + "─" * 10 + "┬" + "─" * 12 + "┬" + "─" * 12 + "┐")
        print("│{:^10}│{:^10}│{:^10}│{:^10}│{:^12}│{:^12}│".format(
                "Total", "Success", "Usable", "Failed", "Avg Compile", "Avg Verifier"))
        print("│{:^10}│{:^10}│{:^10}│{:^10}│{:^12}│{:^12}│".format(
                "Seeds", "Count", "Count", "Count", "Fixes", "Fixes"))
        print("├" + "─" * 10 + "┼" + "─" * 10 + "┼" + "─" * 10 + "┼" + "─" * 10 + "┼" + "─" * 12 + "┼" + "─" * 12 + "┤")
        print("│{:^10}│{:^10}│{:^10}│{:^10}│{:^12.2f}│{:^12.2f}│".format(
                total_seeds, success_count, usable_count, failed_count, avg_compile_fixes, avg_verifier_fixes))
        print("└" + "─" * 10 + "┴" + "─" * 10 + "┴" + "─" * 10 + "┴" + "─" * 10 + "┴" + "─" * 12 + "┴" + "─" * 12 + "┘")
        print()

        # Token & Cost Statistics Table
        print("Token & Cost Statistics:")
        print("┌" + "─" * 14 + "┬" + "─" * 14 + "┬" + "─" * 14 + "┬" + "─" * 14 + "┐")
        print("│{:^14}│{:^14}│{:^14}│{:^14}│".format(
                "Avg Input", "Avg Output", "Avg Cost", "Total Cost"))
        print("│{:^14}│{:^14}│{:^14}│{:^14}│".format(
                "Tokens", "Tokens", "(USD)", "(USD)"))
        print("├" + "─" * 14 + "┼" + "─" * 14 + "┼" + "─" * 14 + "┼" + "─" * 14 + "┤")
        print("│{:^14,.0f}│{:^14,.0f}│{:^14}│{:^14}│".format(
                avg_input_tokens, avg_output_tokens,
                f"${avg_cost:.4f}", f"${total_cost:.4f}"))
        print("└" + "─" * 14 + "┴" + "─" * 14 + "┴" + "─" * 14 + "┴" + "─" * 14 + "┘")
        print()

        # Helper Coverage Table (only show if there's any coverage data)
        if coverage_full + coverage_partial + coverage_none + coverage_na > 0:
                print("Helper Coverage Statistics:")
                print("┌" + "─" * 10 + "┬" + "─" * 12 + "┬" + "─" * 10 + "┬" + "─" * 10 + "┐")
                print("│{:^10}│{:^12}│{:^10}│{:^10}│".format(
                        "Full", "Partial", "None", "N/A"))
                print("│{:^10}│{:^12}│{:^10}│{:^10}│".format(
                        "Coverage", "Coverage", "Coverage", "(Random)"))
                print("├" + "─" * 10 + "┼" + "─" * 12 + "┼" + "─" * 10 + "┼" + "─" * 10 + "┤")
                print("│{:^10}│{:^12}│{:^10}│{:^10}│".format(
                        coverage_full, coverage_partial, coverage_none, coverage_na))
                print("└" + "─" * 10 + "┴" + "─" * 12 + "┴" + "─" * 10 + "┴" + "─" * 10 + "┘")
                print()

        # Time Statistics Table
        print("Time Statistics:")
        print("┌" + "─" * 16 + "┬" + "─" * 16 + "┬" + "─" * 16 + "┬" + "─" * 16 + "┐")
        print("│{:^16}│{:^16}│{:^16}│{:^16}│".format("Category", "Avg (s)", "Total (s)", "Percent"))
        print("├" + "─" * 16 + "┼" + "─" * 16 + "┼" + "─" * 16 + "┼" + "─" * 16 + "┤")
        print("│{:^16}│{:^16.2f}│{:^16.2f}│{:^16}│".format(
                "Overall", avg_time, total_time, "100.0%"))
        print("│{:^16}│{:^16.2f}│{:^16.2f}│{:^16}│".format(
                "LLM", avg_llm_time, total_llm_time,
                f"{total_llm_time/total_time*100:.1f}%" if total_time > 0 else "0.0%"))
        print("│{:^16}│{:^16.2f}│{:^16.2f}│{:^16}│".format(
                "Compile", avg_compile_time, total_compile_time,
                f"{total_compile_time/total_time*100:.1f}%" if total_time > 0 else "0.0%"))
        print("│{:^16}│{:^16.2f}│{:^16.2f}│{:^16}│".format(
                "Verifier", avg_verifier_time, total_verifier_time,
                f"{total_verifier_time/total_time*100:.1f}%" if total_time > 0 else "0.0%"))
        print("└" + "─" * 16 + "┴" + "─" * 16 + "┴" + "─" * 16 + "┴" + "─" * 16 + "┘")
        print("=" * 80 + "\n")

def worker_thread(args: argparse.Namespace, threadid: int, vmlock: threading.Lock, run_id: str):
        """A worker thread that generates BPF seeds."""
        print(f"Thread {threadid} executed")
        with VMContext(workdir=args.workdir,
                       pocexecfile=args.pocexecfile + "_t" + str(threadid),
                       poctemplate=args.poctemplate,
                       pocinsnfile=args.pocinsnfile + "_t" + str(threadid) + ".c",
                       seedcorpus=args.seedcorpus,
                       samplescorpus=args.samplescorpus,
                       vmlock=vmlock) as vm_context:
                llm_bpf_seed = LLMBPFSEED(vm_context,
                                        args_url=args.url,
                                        args_provider=args.model,
                                        args_key=args.key,
                                        args_seednum=args.seednum,
                                        langfuse=args.langfuse,
                                        fixcompile=args.fixcompile,
                                        fixverifier=args.fixverifier,
                                        logdebug=args.logdebug,
                                        enablemutate=args.mutate,
                                        helper_strategy=args.helper_strategy,
                                        helper_indices=args.helper_indices,
                                        stats_csv_file=args.stats_csv,
                                        enable_cache=args.enable_cache,
                                        enable_semantic=args.enable_semantic,
                                        run_id=run_id,
                                        max_verifier_fix_rounds=args.max_verifier_rounds)
                # The VM state is now managed by the VMContext class itself.
                # Note: user_content is no longer used as generate_seed() builds its own prompt
                llm_bpf_seed.do_generate_seed("")

def main():
        parser = argparse.ArgumentParser()
        parser.add_argument('-w', '--workdir', help="work directory of target VM", required=True)
        parser.add_argument('-e', '--pocexecfile', help="filepath of the executable poc program to run bpf insn", default="./vm/poc")
        parser.add_argument('-t', '--poctemplate', help="filepath of the template poc", default="./template/poc.c")
        parser.add_argument('-b', '--pocinsnfile', help="filepath of the poc with bpf insn program", default="./vm/poc.c")
        parser.add_argument('-o', '--seedcorpus', help="the output directory to store valid seed corpus", default="./generate-seeds")
        parser.add_argument('-s', '--samplescorpus', help="the directory that store the BPF IR samples", default="./samples/IR")
        parser.add_argument('-u', '--url', help="base url of api", default="https://api.openai.com/v1")
        parser.add_argument('-m', '--model', help="llm model provider", choices=['openai', 'deepseek', 'xai', 'gemini', 'claude'], required=True)
        parser.add_argument('-k', '--key', help="api key, could also provided from environment variables", default="")
        parser.add_argument('-n', '--seednum', help="how many bpf prog you want to generate", default=1)
        parser.add_argument('-p', '--thread', help="how many thread you want to create", type=int, default=1)
        parser.add_argument('-v', '--verbose', help="enable the verbose of langchain", action=argparse.BooleanOptionalAction)
        parser.add_argument('-lf', '--langfuse', help="use langfuse for tracing", action=argparse.BooleanOptionalAction, default=True)
        parser.add_argument('-fc', '--fixcompile', help="use compile result for feedback", action=argparse.BooleanOptionalAction, default=False)
        parser.add_argument('-fv', '--fixverifier', help="use verifier result for feedback", action=argparse.BooleanOptionalAction, default=False)
        parser.add_argument('-mvr', '--max-verifier-rounds', type=int, default=5,
                            help="maximum number of verifier fix rounds per seed (default: 5, only effective when -fv is enabled)")
        parser.add_argument('-ld', '--logdebug', help="print debug issues", action=argparse.BooleanOptionalAction, default=False)
        parser.add_argument('-M', '--mutate', help="mutate the generated bpf program", action=argparse.BooleanOptionalAction, default=False)
        parser.add_argument('-hs', '--helper-strategy',
                            choices=['random', 'specified'], default='random',
                            help="strategy for selecting helper functions: 'random' to randomly select helpers, 'specified' to use --helper-indices")
        parser.add_argument('-hi', '--helper-indices',
                            type=str, default="",
                            help="comma-separated list of helper indices when using 'specified' strategy (e.g., '0,5,10')")
        parser.add_argument('-sc', '--stats-csv',
                            type=str, default="bpf_seed_statistics.csv",
                            help="path to CSV file for recording seed generation statistics (default: bpf_seed_statistics.csv)")
        parser.add_argument('-ec', '--enable-cache', help="enable prompt caching to reduce cost (recommended for batch generation)",
                            action=argparse.BooleanOptionalAction, default=False)
        parser.add_argument('-es', '--enable-semantic', help="enable semantic enhancement (BPF definitions, rules, examples, RAG docs). Disable for ablation study.",
                            action=argparse.BooleanOptionalAction, default=True)
        args = parser.parse_args()

        if args.verbose:
                langchain.globals.set_debug(True)
                langchain.globals.set_verbose(True)

        vmlock = threading.Lock()
        llm_bpf_seed_main = None

        # Generate run_id for this execution
        run_id = f"{args.model}_{datetime.now().strftime('%Y%m%d-%H%M%S')}"
        print(f"Run ID: {run_id}")

        # --- VM Initialization in Main Thread ---
        print("Main Thread: Initializing VM...")
        with VMContext(workdir=args.workdir,
                       pocexecfile=args.pocexecfile + "_t_init",
                       poctemplate=args.poctemplate,
                       pocinsnfile=args.pocinsnfile + "_t_init.c",
                       seedcorpus=args.seedcorpus,
                       samplescorpus=args.samplescorpus,
                       vmlock=vmlock) as vm_context:
                # Create a dummy seed generator instance just to manage the VM
                llm_bpf_seed_main = LLMBPFSEED(vm_context,
                                        args_url=args.url,
                                        args_provider=args.model,
                                        args_key=args.key,
                                        args_seednum=1, # Only for vm start
                                        langfuse=args.langfuse,
                                        fixcompile=args.fixcompile,
                                        fixverifier=args.fixverifier,
                                        logdebug=args.logdebug,
                                        enablemutate=args.mutate,
                                        helper_strategy=args.helper_strategy,
                                        helper_indices=args.helper_indices,
                                        stats_csv_file=args.stats_csv,
                                        enable_cache=args.enable_cache,
                                        enable_semantic=args.enable_semantic,
                                        run_id=run_id,
                                        max_verifier_fix_rounds=args.max_verifier_rounds)
                
                # Start the VM without generating a seed
                llm_bpf_seed_main.vm_context.start_vm()
                
                # Wait until the VM is running
                while llm_bpf_seed_main.vm_context.run_vm is None:
                        timewait = 3
                        print(f"Waiting for VM to start, checking in {timewait}s ...")
                        time.sleep(timewait)
                        if not llm_bpf_seed_main.vm_context.is_vm_running():
                                print("Main Thread: Failed to start VM.")
                                llm_bpf_seed_main.vm_context.stop_vm()
                                exit(1)

                print("Main Thread: VM initialized successfully.")

        # --- Worker Threads ---
        num_threads = int(args.thread)
        print(f"Main Thread: Starting {num_threads} worker threads...")
        thread_list = []
        for idx in range(num_threads):
                thri = threading.Thread(target=worker_thread, args=(args, idx, vmlock, run_id))
                thri.start()
                print(f"Thread {idx} started.")
                thread_list.append(thri)
                # Add a delay between thread starts to reduce burst load
                time.sleep(10)

        print("Main Thread: All threads started. Waiting for them to finish...")
        for idx, t in enumerate(thread_list):
                t.join()
                print(f"Thread {idx} finished.")

        # Print summary statistics before stopping VM
        print_run_summary(args.stats_csv, run_id)

        print("Main Thread: stop VM ...")
        if llm_bpf_seed_main:
                llm_bpf_seed_main.vm_context.stop_vm()

        print("Main Thread: All tasks completed.")