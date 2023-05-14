## MMS Fuzzer
A mutational fuzzer built on boofuzz for the IEC61850 MMS protocol.

## Installation
Running setup.sh should get you up and running. The script installs all dependencies, including cloning and building [libiec61850](https://github.com/mz-automation/libiec61850.git).

## Running

To start fuzzing, simply run the fuzzer.py from the command line. To print available arguments run it with the --help flag.

## Packet replaying
A simple packet replaying tool is included. To print available arguments run it with the --help flag.