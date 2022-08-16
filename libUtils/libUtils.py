#!/usr/bin/python2



import struct
from ghidra.program.model.address import GenericAddress
from ghidra.program.flatapi import FlatProgramAPI




def addr2int(addr):
    return addr.offset


def write_memory(emuHelper, addr, data, sz = None):
    api = None
    if type(addr) == GenericAddress:
        addr = addr2int(addr)
    data_str = data
    if sz:
        if data < 0:
            raise ValueError("data must be positive")
        data_str = ""
        while data != 0:
            b = data & 0xff
            data_str += struct.pack("B", b)
            data = data >> 8

    api = FlatProgramAPI(emuHelper.getProgram())
    i = 0
    while i < len(data_str):
        c = struct.unpack("B", data_str[i])[0]
        ghidra_addr = api.toAddr(addr+i)
        emuHelper.writeMemoryValue(ghidra_addr, 1, c)
        i += 1
    del api
    return



def get_string(emuHelper, addr):
    my_str = ""
    api = None
    if type(addr) != GenericAddress:
        api = FlatProgramAPI(emuHelper.getProgram())
        addr = api.toAddr(addr)


    while True:
        b = emuHelper.readMemoryByte(addr)
        if b == 0:
            break
        my_str += struct.pack("B", b)
        addr = addr.add(1)

    del api
    return my_str



def apply_hooks(emuHelper, d_hooks, addr, debug=False):
    """
    Apply hook if needed
    """
    # n_addr = get_next_execution_addr(addr)

    bRes = None
    addr_int = addr2int(addr)
    if addr_int in d_hooks.keys():
        if debug:
            print(" * * * apply_hook: %s - %s" % (str(addr), d_hooks[addr_int]["name"]))
        bRes = d_hooks[addr_int]["callback"](emuHelper, addr)

    return bRes


def get_next_execution_addr(addr):
    if type(addr) in [int, long]:
        addr = toAddr(addr)
    return getInstructionAfter(addr).address