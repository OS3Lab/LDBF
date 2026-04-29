# LDBF: Deep Exploration of eBPF Runtime via LLM-Driven Program Generation and Adaptive Context Orchestration


## Seed Generation

### Setup

- Setup LLM API KEY env in bash/zsh profile

```sh
export DEEPSEEK_API_KEY="xxx"
export OPENAI_API_KEY="xxx"
```

- Specify the root path to the LDBF

```
export LDBF_DIR=/yourpath
```

- Option: setup LANGFUSE configs in bash/zsh profile

```sh
export LANGFUSE_PUBLIC_KEY="xxx"
export LANGFUSE_SECRET_KEY="xxx"
export LANGFUSE_HOST="xxx"
```

### Build

Build python environment

```sh
pdm install
```

Build QEMU VM environment

 - Compile Linux kernel `bzImage` 
 - Build Debian bullseye `image`


### Run

Example:

Run the generation engine (deepseek) with both Semantic Enhancement and Feedback Loop enabled.

```sh
pdm run python menu -w <workdir> -m <llm> -t <poctemplate> -o <output seeds directory> -p <thread> -n <seed number> -hs {random,specified} -hi <helper indices> --enable-semantic --enable-cache -fc -fv --logdebug -sc <path to CSV file>

pdm run python menu -w vm -m deepseek -t ./template/template.c -o deepseek/deepseek-seeds/ -p 1 -n 1 -hs specified -hi 40 --enable-semantic --enable-cache -fc -fv --logdebug -sc deepseek/deepseek-seeds/base_semantic_feedback/base_semantic_feedback.csv
```

## Context Orchestration & Fuzzing

The context orchestration module is based on syzkaller, commit d971f7e21bf575c68223c77d5bcb784ac4912aa1.
Apply the `ldbf.patch` first, then follow the usage guide below.

### Usage

- Specify the path to the LDBF

```
export LDBF_DIR=/your_LDBF_path
```

- Specify the path of the generated eBPF program seeds

```
export LDBF_SEED_DIR=/your_path_of_eBPF_seeds
```

- Whether to enable debug information about LBPF syscall

```
export LDBF_DEBUG_BPF_INSN=1
```

- Whether to reuse the generated BPF instruction program

```
export LDBF_REUSE_BPF_INSN=1
```

- Whether to save the kernel dmesg info from QEMU VM

```
export LDBF_KERNEL_LOG_DIR=/your_path_to_save_kernel_vm_logs
```

- Set the path of vmlinux to get btf id

```
export LDBF_VMLINUX_PATH=/your_path_to_vmlinux
```

- For details on enabling syscalls, please refer to `sample.config`.