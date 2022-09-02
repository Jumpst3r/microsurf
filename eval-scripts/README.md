# microsurf-eval-infra

Evaluation scripts for the microsurf tool

## Files

`config.json`: Contains information on how to build the different frameworks for different architectures

`builder.py`: Script used to build and analyze a selected framework

`k8s-config`: Kubernetes config stuff

`create-cluster.sh`: Deploy a large scale cluster on Exoscale and run the evaluation workflow

`workflow/`: Kubernetes workflow engine (argo) templates

`framework-builder/`: driver source code for the different frameworks

## Examples:

```
python3 builder.py x86-64-core-i7--glibc--stable-2018.11-1 openssl fed8dbea27b7e01ee934951b25c6ffd40ad1d5c3 -O3 gcc
```

```
python3 builder.py powerpc-440fp--musl--stable-2021.11-1 compare local -O3 clang
```
