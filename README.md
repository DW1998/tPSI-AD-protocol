# Implementation of the tPSI-AD protocol

This repository contains a working implementation of the tPSI-AD protocol presented by Apple

## Instruction on how to run the implementation:

    1. Install the requirements in "requirements.txt".
    2. Change "root_dir" in util.py to the directory, in which you want all files to be saved.
    3. Run "main.py" once to generate all needed directories.
    4. Put the dummy malicious images you want to use in the directory "Malicous-Images" in the root directory.
    5. To change the threshold value t, change "self.t" in "server.py". As a default, this is set to 3.

## Credits

* [AppleNeuralHash2ONNX](https://github.com/AsuharietYgvar/AppleNeuralHash2ONNX)