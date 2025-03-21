# afl_ghidra_emu
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

afl_ghidra_emu allows to fuzz exotic architecture using AFL++ and Ghidra emulation with code coverage functionality.

For more information, read this [article](https://airbus-cyber-security.com/fuzzing-exotic-arch-with-afl-using-ghidra-emulator/).

<p align="center">
<img src="https://airbus-cyber-security.com/wp-content/uploads/2021/04/202104_Blog_Graphic_Fuzzing.png">
</p>


## How it works?

AFL++ runs a trampoline program (afl_bridge_external) which is in charge of forwarding samples to Ghidra emulation 
via a TCP socket (Ex: 127.0.0.1:6674/tcp). 

A python script in Ghidra (fuzz_xtensa_check_serial.py) is responsible for emulating code execution. It listens 
on a TCP socket (127.0.0.1:6674/tcp) and waits for input data coming from trampoline script.
As soon as the script receives input data, the emulation will be started. During the execution, the executed path addresses, 
and the execution status are sent to afl_bridge_external using established TCP socket. 

afl_bridge_external reports the execution status and execution path to AFL++ using pipes and shared memory. 


## Installation
Install [AFL++](https://github.com/AFLplusplus/AFLplusplus)  

Clone afl_ghidra_emu directory
```bash
git clone https://github.com/airbus-cyber/afl_ghidra_emu.git
```

Compile afl_bridge_external
```
cd afl_ghidra_emu/afl_bridge_external
make
```

Copy afl_ghidra_emu files to your ghidra script directory
```bash
cd ../..
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

Start AFL++ with trampoline program.
```bash
afl-fuzz -D -i input -o output afl_bridge_external 127.0.0.1 6674 20
```

#### Stop Ghidra emulation
Stop AFL++ using CTRL+C. If Ghidra emulation still running, we can send "STOP" command:
```bash
echo -e "\xff" | nc 127.0.0.1 6674
```
Do no use Ghidra Cancel button, because it does not properly close the socket.

## Example: Fuzzing PPC binary code keygenme_ppc.elf
./examples/ppc/bin/keygenme_ppc.elf is also a *keygenMe* compiled for PowerPC architecture.

Follow the same steps above with PowerPC:BE:32:default architecture in Ghidra and run the script fuzz_ppc_check_serial.py.
  


