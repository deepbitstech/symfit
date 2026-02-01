# SymFit

SymFit is a symbolic execution framework for analyzing binaries, supporting multiple backends such as SymCC and SymSan. This document provides instructions for building and running SymFit using Docker.


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

## Run SymFit

Once you are in the container bash, run:

```bash
./mnt/run_cve_automated.sh
```

This will load the snapshot and qemu to get constraints.

## Spawn Parameters Explained

The `run_cve_automated.sh` script launches QEMU with symbolic execution using several key parameters:

### Environment Variables

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
