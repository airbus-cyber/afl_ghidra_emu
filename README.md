# afl_ghidra_emu
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

afl_ghidra_emu allows to fuzz exotic architecture using AFL++ and Ghidra emulation with code coverage functionality.

For more information, read this [article](https://airbus-cyber-security.com/fuzzing-exotic-arch-with-afl-using-ghidra-emulator/).

<p align="center">
<img src="https://airbus-cyber-security.com/wp-content/uploads/2021/04/Blog-graphic_Fuzzing-.png">
</p>

## How it works?

First, AFL++ listens on TCP socket (Ex: 22222/tcp) to get notified about sample’s code execution path.

Then AFL++ runs a trampoline script (afl_bridge_external.py) which is in charge of forwarding samples and maintaining 
the AFL++ configuration to Ghidra emulation via a TCP socket (Ex: 127.0.0.1:6674/tcp)  

Finally, a python script in Ghidra (fuzz_xtensa_check_serial.py) is responsible of emulating code execution. It listens 
on a TCP socket (127.0.0.1:6674/tcp) and waits for input data coming from trampoline script.
As soon as the script receives input data, the emulation will be started. During the execution, the executed path addresses are 
sent to AFL++ using its socket (127.0.0.1:22222).

The emulation engine reports the final execution status (Ex: got crash or not) to the trampoline script (afl_bridge_external.py). 
If state crash is reported, the trampoline script exits with segfault signal that AFL++ caches.


## Installation
Clone AFLplusplus-socket-mode directory.
```bash
git clone https://github.com/airbus-cyber/AFLplusplus-socket-mode
```

Compile AFLplusplus (read AFLplusplus-socket-mode/README.md for more options)
```bash
cd AFLplusplus-socket-mode
make
```

Get AFL Ghidra emulator scripts and library
```bash
cd AFLplusplus-socket-mode/utils/socket_mode
sh get_afl_ghidra_emulator.sh
```

Copy afl_ghidra_emu files to your ghidra script directory
```bash
cp –r afl_ghidra_emu/* $USER_HOME/ghidra_scripts/
```

## Example: Fuzzing Xtensa binary code keygenme_xtensa.elf
./examples/xtensa/bin/keygenme_xtensa.elf is a *keygenMe* compiled for Xtensa (ex: esp32) architecture.
Xtensa is not officially supported in Ghidra yet. So, you need first to install it by following these [instruction](https://github.com/Ebiroll/ghidra-xtensa)


#### Load in Ghidra
- Create a new project in Ghidra;
- Import file ./bin/keygenme_xtensa.elf (arch: Xtensa:LE:32);
- Open it in CodeBrowser and execute auto-analyze;
- Open Script Manager in "Window" submenu;
- Run script fuzz_xtensa_check_serial.py;



#### Start Fuzz
Make AFL workspace directories
```bash
mkdir input output
```

Add first sample
```bash
echo -n "BBBBBBBB" > input/sample1.bin
```

Start AFL++ with trampoline script.
```bash
afl-fuzz -p explore -D -Y 22222 -i input -o output -t 90000 /usr/bin/python2 afl_bridge_external.py -H 127.0.0.1 -P 6674 -a 127.0.0.1 -p 22222 -i @@
```

#### Stop Ghidra emulation
```bash
./afl_bridge_external.py -H 127.0.0.1 -P 6674 -s
```

## Example: Fuzzing PPC binary code keygenme_ppc.elf
./examples/ppc/bin/keygenme_ppc.elf is also a *keygenMe* compiled for PowerPC architecture.

Follow the same steps above with PowerPC:BE:32:default architecture in Ghidra and run the script fuzz_ppc_check_serial.py.
  


