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