# SymFit

SymFit is a symbolic execution framework for analyzing binaries, supporting multiple backends such as SymCC and SymSan. This document provides instructions for building and running SymFit using Docker.

## Prerequisites
- Docker installed and running on your system
- Sufficient permissions to perform Docker pull and run operations (either root/sudo, or your user added to the `docker` group)

## How to Build the Docker Image

**Option A: Build from Dockerfile**

Navigate to the root directory containing the `Dockerfile`, then build the image:

```bash
docker build -t symfit .
```

**Option B: Load from pre-built image**

```bash
docker image load -i /path/to/symfit.tar.gz
```

## Launch the Container

```bash
docker run --rm -it symfit
```

## Usage
SymFit is operated through the `fgtest` wrapper program, located at `symsan_build/driver/fgtest` once build is complete. The wrapper accepts environment variables to configure execution behavior, followed by the path to the emulator and any QEMU options.

The general invocation looks like this:

```bash
SYMCC_INPUT_FILE=<input> SYMCC_OUTPUT_DIR=<output> symsan_build/driver/fgtest [qemu path] [qemu options]
```

You can use system or user-mode emulation. They can be found at:

`qemu-system`: `symfit_symsan_build/x86_64-softmmu/symqemu-system-x86_64`

`qemu-user`: `symfit-symsan/x86_64-linux-user/symqemu-x86_64`

## Example 1: Instrumenting Local ELF Binary

```bash
SYMCC_INPUT_FILE=stdin SYMCC_OUTPUT_DIR=/tmp symsan_build/driver/fgtest symfit-symsan/x86_64-linux-user/symqemu-x86_64 /path/to/your/binary
```

TODO: explain commands

## Example 2: CVE-2022-0995

This example shows how you can instrument an Android kernel using qemu system emulator. 

1. Download Android kernel, VM image, and configuration file: https://drive.google.com/file/d/1aSUPs7hyualvY094q0m8AZRIPReV5Y5h/view?usp=sharing

2. Unzip into the current folder.

   **Note:** Steps 1 and 2 are not necessary if you loaded the Docker image from `symfit.tar.gz`, as these files are already included.

3. Launch the container. 

Once you are in the container bash, run:

```bash
SYMCC_INPUT_FILE=stdin SYMCC_OUTPUT_DIR=/tmp/solver SYMSAN_PC_CONFIG=/workdir/symfit/expected.json SYMSAN_CONSTRAINT_DIR=/workdir/constraints \
        symsan_build/driver/fgtest \
        symfit_symsan_build/x86_64-softmmu/symqemu-system-x86_64 \
        -m 2048 \
        -gdb tcp::2368 \
        -monitor unix:/tmp/qemu-monitor.sock,server,nowait \
        -smp 1 \
        -display none -serial stdio -no-reboot \
        -device virtio-rng-pci \
        -cpu max \
        -kernel /workdir/symfit/bzImage_android5_10_wq \
        -device virtio-scsi-pci,id=scsi \
        -device scsi-hd,bus=scsi.0,drive=d0 \
        -drive file=/workdir/symfit/disk.qcow2,if=none,id=d0 \
        -append "nokaslr earlyprintk=serial root=/dev/sda1 console=ttyS0" \
        -net user,host=10.0.2.10,hostfwd=tcp:127.0.0.1:555-:22 \
        -net nic,model=e1000 \
        -accel tcg,thread=multi \
        -nographic \
        -loadvm after-login
```

4. Run the PoC

```bash
./cve_poc_wmmap\r
```

SymFit will collect constraints and save them to `SYMSAN_CONSTRAINT_DIR`.

### Configurations

**SYMSAN_PC_CONFIG**
- **Purpose**: Specifies a JSON configuration file that defines which program counter (PC) addresses to track during symbolic execution
- **Value**: `/workdir/symfit/expected.json`
- **Usage**: This configuration file tells SymSan which code locations (instruction addresses) should be monitored and symbolically executed. It's essential for targeting specific vulnerable code paths
- **Example**: The JSON file contains PC addresses that correspond to the CVE vulnerability being analyzed

### QEMU Parameters

**-kernel**
- **Purpose**: Specifies the Linux kernel image to boot in QEMU
- **Value**: `/workdir/symfit/bzImage_android5_10_wq`

**-drive**
- **Purpose**: Defines a disk drive for the virtual machine. This drive contains a snapshot after login to save boot time.
- **Value**: `file=/workdir/symfit/disk.qcow2,if=none,id=d0`

## Outputs

The script generates the following outputs in `/workdir/constraints`:
- *[constraints]*.txt*: Extracted constraints for the program counters specified in `SYMSAN_PC_CONFIG`


### Userland Binaries and Hybrid Fuzzing
When analyzing userland binaries within QEMU, an AFL++ coverage map can be passed to the solver using the `SYMCC_AFL_COVERAGE_MAP` option. This allows constraints to be imported from AFL++ for use in hybrid fuzzing environments.

### Marking Variables as Symbolic
In system mode, variables in compiled programs can be marked symbolic by loading them into memory from the address `0x10000000`. This is done by mapping that address and reading or writing through it. The following example marks a variable as symbolic and prints its value at runtime:

```c
#include <stdio.h>
#include <sys/mman.h>

int main(void) {
    void *ptr = mmap((void *)0x10000000, 1024,
                     PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED,
                     -1, 0);
    if (ptr == MAP_FAILED) {
        fprintf(stderr, "Couldn't mmap!\n");
        return 1;
    }

    unsigned int *iptr = (unsigned int *)ptr;
    *iptr = 1; // Concrete value - can be reassigned normally
    printf("The value of the symbolic variable at the time of execution is %d\n", *iptr);

    munmap((void *)0x10000000, 1024);
    return 0;
}
```

> **Note:** The target address (`0x10000000`) will need to differ on other emulated CPU architectures, as it could conflict with memory-mapped I/O or other components. No other modifications are needed — the solver will automatically track propagation of symbolic values throughout system memory, generating constraints and producing test cases for the uninstrumented binary.

### Intercepting Syscall Arguments
Rather than instrumenting individual arguments, the emulator can be signaled to create labels for all syscall arguments automatically. Compile `syscall_instrument.c` for your preferred guest operating system, then use it to bracket your target program:

```sh
./syscall_instrument enable && ./target_executable && ./syscall_instrument disable
```

It is recommended to halt instrumentation immediately after the target program terminates in order to reduce noise.

## Automated Concolic Execution with LLM Agent

SymFit comes with a dedicated LLM agent to help with automated concolic execution. To see how it works on CVE-2022-0995:

1. Inside the Docker container, start the agent:
   ```bash
   python server.py
   ```

2. Enter the following prompt:
   ```
   Please read /workdir/symfit/claude_code_task.md and run the task
   ```

The agent will automatically perform the concolic execution workflow for the specified CVE.

## MCP Server for LLM Agents
SymFit includes an MCP (Model Context Protocol) server that enables LLM agents to perform automated concolic execution on binaries. It provides a standardized interface for running symbolic execution campaigns, managing test case corpora, analyzing coverage and results, and automating binary analysis workflows.

See the [SymFit MCP repository](https://github.com/bitsecurerlab/symfit) for more details.

