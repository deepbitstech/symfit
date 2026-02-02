# SymFit

SymFit is a symbolic execution framework for analyzing binaries, supporting multiple backends such as SymCC and SymSan. This document provides instructions for building and running SymFit using Docker.

## Prerequisites
- Docker installed and running on your system
- Sufficient permissions to perform Docker pull and run operations (either root/sudo, or your user added to the `docker` group)

## How to Build the Docker Image

Navigate to the root directory containing the `Dockerfile`, then build the image:

```bash
docker build -t symfit_env .
```

## Launch the Container

Mount the root directory into /workdir/mnt:

```bash
docker run --rm -it -v .:/workdir/mnt symfit_env
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

Once you are in the container bash, run:

```bash
SYMCC_INPUT_FILE=stdin SYMCC_OUTPUT_DIR=/tmp/solver SYMSAN_PC_CONFIG=/workdir/mnt/expected.json SYMSAN_CONSTRAINT_DIR=/workdir/constraints \
        symsan_build/driver/fgtest \
        symfit_symsan_build/x86_64-softmmu/symqemu-system-x86_64 \
        -m 2048 \
        -gdb tcp::2368 \
        -monitor unix:/tmp/qemu-monitor.sock,server,nowait \
        -smp 1 \
        -display none -serial stdio -no-reboot \
        -device virtio-rng-pci \
        -cpu max \
        -kernel /workdir/mnt/bzImage_android5_10_wq \
        -device virtio-scsi-pci,id=scsi \
        -device scsi-hd,bus=scsi.0,drive=d0 \
        -drive file=/workdir/mnt/disk.qcow2,if=none,id=d0 \
        -append "nokaslr earlyprintk=serial root=/dev/sda1 console=ttyS0" \
        -net user,host=10.0.2.10,hostfwd=tcp:127.0.0.1:555-:22 \
        -net nic,model=e1000 \
        -accel tcg,thread=multi \
        -nographic \
        -loadvm after-login
```

This will load the snapshot and qemu to get constraints.

### Configurations

**SYMSAN_PC_CONFIG**
- **Purpose**: Specifies a JSON configuration file that defines which program counter (PC) addresses to track during symbolic execution
- **Value**: `/workdir/mnt/expected.json`
- **Usage**: This configuration file tells SymSan which code locations (instruction addresses) should be monitored and symbolically executed. It's essential for targeting specific vulnerable code paths
- **Example**: The JSON file contains PC addresses that correspond to the CVE vulnerability being analyzed

### QEMU Parameters

**-kernel**
- **Purpose**: Specifies the Linux kernel image to boot in QEMU
- **Value**: `/workdir/mnt/bzImage_android5_10_wq`

**-drive**
- **Purpose**: Defines a disk drive for the virtual machine. This drive contains a snapshot after login to save boot time.
- **Value**: `file=/workdir/mnt/disk.qcow2,if=none,id=d0`

## Outputs

The script generates the following outputs in `/workdir/constraints`:
- *[constraints]*.txt*: Extracted constraints for the program counters specified in `SYMSAN_PC_CONFIG`
