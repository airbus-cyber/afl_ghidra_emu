

"""
Copyright 2021 by Airbus CyberSecurity - Flavian Dola

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""


import struct
import time

from ghidra.app.emulator import EmulatorHelper
from ghidra.program.model.address import GenericAddress
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.program.model.block import BasicBlockModel

from libAFL import libAFL


# TCP listen PORT
PORT = 6674

DEBUG = False

REG_FILTER = [
        "r1", "r2", "r3", "r4",
        "r9", "r31"
]

D_REG = {
    "r1": "r1",
    "r2": "r2",
    "r3": "r3",
    "r4": "r4",
    "r9": "r9",
    "r31": "r31",
}




def write_memory(addr, data, sz = None):
    if type(addr) == GenericAddress:
        addr = libAFL.addr2int(addr)
    data_str = data
    if sz:
        if data < 0:
            raise ValueError("data must be positive")
        data_str = ""
        while data != 0:
            b = data & 0xff
            data_str += struct.pack("B", b)
            data = data >> 8
    i = 0
    while i < len(data_str):
        c = struct.unpack("B", data_str[i])[0]
        ghidra_addr = toAddr(addr+i)
        emuHelper.writeMemoryValue(ghidra_addr, 1, c)
        i += 1
    return



def apply_hooks(emuHelper, addr, debug=False):
    """
    Apply hook if needed
    """
    # n_addr = get_next_execution_addr(addr)

    bRes = None
    addr_int = libAFL.addr2int(addr)
    if addr_int in D_HOOKS.keys():
        if debug:
            print(" * * * apply_hook: %s - %s" % (str(addr), D_HOOKS[addr_int]["name"]))
        bRes = D_HOOKS[addr_int]["callback"](emuHelper, addr)

    return bRes



def hook_good_serial(emuHelper, addr):
    ret = emuHelper.readRegister("r3")
    if ret == 2:
        # force crash
        # => pc = 0
        emuHelper.writeRegister(emuHelper.getPCRegister(), 0x0)
        return True
    return False


D_HOOKS = {
    0x1000071c:{
        "name": "good_serial",
        "callback": hook_good_serial,
        },
}


if __name__ == '__main__':

    emuHelper = EmulatorHelper(currentProgram)

    monitor = ConsoleTaskMonitor()
    bbm = BasicBlockModel(currentProgram)

    ctx = {}
    ctx = libAFL.init_ctx(ctx, monitor, bbm)

    res, ctx = libAFL.run_bridge_server_api(ctx, port=PORT)
    if not res:
        print("Error on listen on %d tcp port", PORT)
        exit(1)

    start_addr = 0x1000063c
    stop_addr = toAddr(0x1000071c)

    # Add new memory section to store emulate values
    addr_section_emu = 0x20000000
    sz_emu = 0x100000

    pInput = addr_section_emu

    count = 0
    bFirstRun = True

    isRunning = True
    while isRunning:

        # reset previous block reached
        ctx = libAFL.init_ctx(ctx, monitor, bbm)

        res, ctx = libAFL.rcv_input(ctx, debug=DEBUG)
        if not res:
            if DEBUG:
                print("Error get config")
            res, ctx = libAFL.notify_err(ctx)
            continue

        if DEBUG:
            print("CONFIG: %s" % str(ctx))

        if libAFL.isStopOrder(ctx):
            isRunning = False
            break

        # Do some stats
        if count % 1000 == 0:
            count = 0
            if not bFirstRun:
                stat = 1000.0 / (time.time() - ref_time)
                print("Exec %d/s" % int(stat))
            bFirstRun = False
            ref_time = time.time()
        count += 1

        write_memory(pInput, libAFL.get_data_input(ctx))
        szInput = len(libAFL.get_data_input(ctx))

        # set register
        emuHelper.writeRegister("r3", pInput)
        emuHelper.writeRegister("r4", szInput)
        emuHelper.writeRegister(emuHelper.getPCRegister(), start_addr)


        # Emulation
        bCrash = False
        while True:
            if monitor.isCancelled():
                break

            executionAddress = emuHelper.getExecutionAddress()


            if apply_hooks(emuHelper, executionAddress):
                continue


            if (executionAddress in [stop_addr]):
                if DEBUG:
                    print("Emulation complete.")
                break


           # Print current instruction and the registers we care about

            if DEBUG:
                print("\n%s: %s" % (str(executionAddress).upper(), getInstructionAt(executionAddress)))

            res, ctx = libAFL.notify_code_coverage(ctx, executionAddress, debug=DEBUG)
            if not res:
                print("Error on notify_code_coverage")
                isRunning = False
                break

            if DEBUG:
                for reg in REG_FILTER:
                    reg_value = emuHelper.readRegister(reg)
                    print("\t{} ({}) =\t{:08X}".format(reg, D_REG[reg], reg_value))

            # single step emulation
            success = emuHelper.step(monitor)
            if success == False:
                bCrash = True
                lastError = emuHelper.getLastError()
                print("Emulation Error: '{}'".format(lastError))
                break

        # End of Emulation
        if bCrash:
            res, ctx = libAFL.notify_crash(ctx)
        else:
            res, ctx = libAFL.notify_end_exec(ctx)

        if not res:
            # Error on notify
            break

    # End of prog

    ctx = libAFL.free_ctx(ctx)


