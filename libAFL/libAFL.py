#!/usr/bin/python2

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
import socket
import copy

CONFIG = "\x02"
STOP = "\xff"


def addr2int(addr):
    return addr.offset


def run_bridge_server_api(ctx, host="127.0.0.1", port=6666):
    res = False
    s_bridge = None
    try:
        s_bridge = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s_bridge.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s_bridge.bind((host, port))
        s_bridge.listen(1)
        ctx.update({"sock_bridge": s_bridge})
        res = True
    except Exception as e:
        print("run_bridge_server_api failed: %s" % str(e))
        if s_bridge is not None:
            s_bridge.close()

    return res, ctx



def parse_config(ctx, data, debug=False):
    res = False
    host = ""
    port = 0
    input_data = ""

    if len(data) < 3:
        # too short
        if debug:
            print("parse_config: Data too short: %d\n" % len(data))
        return res, ctx

    offset = 0
    if data[0] == CONFIG:
        offset += 1
        size_host = struct.unpack("B", data[offset])[0]
        offset += 1
        host = data[offset:offset+size_host]
        offset += size_host
        if len(data[offset:]) < 3:
            if debug:
                print("parse_config: port invalid length: %d\n" % len(data[offset:]))
            return res, ctx
        port = struct.unpack("<H", data[offset:offset+2])[0]
        offset += 2
        if len(data[offset:]) < 2:
            if debug:
                print("parse_config: data invalid length: %d\n" % len(data[offset:]))
            return res, ctx
        size_input_data = struct.unpack("<H", data[offset:offset+2])[0]
        offset += 2
        input_data = data[offset:]
        if len(input_data) != size_input_data:
            if debug:
                print("parse_config: input_data_length not match: 0x%X - 0x%X\n" % (len(input_data), size_input_data))
            return res, ctx

        ctx.update(
            {
                "AFL_HOST": host,
                "AFL_PORT": port,
                "DATA_INPUT": input_data,
            }
        )
        res = True

    elif data[0] == STOP:
        offset += 1
        if len(data) != 5:
            if debug:
                print("parse_config: Stop invalid length: %d\n" % len(data))
            return res, ctx
        if data[offset:] != "STOP":
            if debug:
                print("parse_config: Stop invalid frame: %s\n" % data.encode("hex"))
            return res, ctx

        ctx.update({"STOP": True})
        res = True

    return res, ctx



def get_data_input(ctx):
    return ctx["DATA_INPUT"]



def isStopOrder(ctx):
    if ctx.has_key("STOP"):
        if ctx["STOP"]:
            return True
    return False




def rcv_config_and_input(ctx, debug):
    res = False
    d_config = {
        "AFL_HOST": "127.0.0.1",
        "AFL_PORT": 55555,
        "DATA_INPUT": "",
        "CONFIG_RAW": ""
    }


    if not ctx.has_key("sock_bridge"):
        return res, ctx

    conn, addr = ctx["sock_bridge"].accept()
    if debug:
        print('rcv_config_and_input: Connected by', addr)

    ctx.update({"conn_bridge": conn})


    # GET AFL config frame
    config_raw = ctx["conn_bridge"].recv(0xffff)
    if not config_raw:
        if debug:
            print("rcv_config_and_input: error on get config frame\n")
        return res, ctx


    ctx.update({"CONFIG_RAW": config_raw})
    res, ctx = parse_config(ctx, config_raw, debug)
    if not res:
        if debug:
            print("rcv_config_and_input: error on parse config frame: %s\n" % config_raw.encode("hex"))
        return res, ctx


    res = True

    return res, ctx



def notify_crash(ctx):
    try:
        ctx["conn_bridge"].sendall("CRASH")
    except Exception as e:
        print("notify_crash: error: %s\n" % str(e))

    ctx["conn_bridge"].shutdown(socket.SHUT_RDWR)
    ctx["conn_bridge"].close()
    del ctx["conn_bridge"]

    return ctx



def notify_end_exec(ctx):
    try:
        ctx["conn_bridge"].sendall("END")
    except Exception as e:
        print("notify_end_exec: error: %s\n" % str(e))

    ctx["conn_bridge"].shutdown(socket.SHUT_RDWR)
    ctx["conn_bridge"].close()
    del ctx["conn_bridge"]
    return ctx



def init_ctx(ctx, monitor, bbm):
    ctx.update({
        "monitor": monitor,
        "bbm": bbm,
        "last_block_addr": 0
    })
    return ctx



def free_ctx(ctx):
    if ctx.has_key("sock_afl"):
        try:
            ctx["sock_afl"].shutdown(socket.SHUT_RDWR)
        except:
            pass
        ctx["sock_afl"].close()
        del ctx["sock_afl"]

    if ctx.has_key("conn_bridge"):
        try:
            ctx["conn_bridge"].shutdown(socket.SHUT_RDWR)
        except:
            pass
        ctx["conn_bridge"].close()
        del ctx["conn_bridge"]

    if ctx.has_key("sock_bridge"):
        try:
            ctx["sock_bridge"].shutdown(socket.SHUT_RDWR)
        except:
            pass
        ctx["sock_bridge"].close()
        del ctx["sock_bridge"]

    return ctx


def connect_to_afl(ctx):
    res = False
    ctx.update({"sock_afl": socket.socket(socket.AF_INET, socket.SOCK_STREAM)})
    try:
        ctx["sock_afl"].connect((ctx["AFL_HOST"], ctx["AFL_PORT"]))
        res = True
    except Exception as e:
        print("connect_to_afl: Error on connect to AFL (%s:%d): %s\n" % (ctx["AFL_HOST"], ctx["AFL_PORT"], str(e)))
        if ctx.has_key("sock_afl"):
            del ctx["sock_afl"]

    return res, ctx


def notify_code_coverage(ctx, executionAddress, debug=False):
    res = False
    b = ctx["bbm"].getFirstCodeBlockContaining(executionAddress, ctx["monitor"])
    if b is None:
        print("notify_code_coverage: Warning cannot get block for addr 0x%08X" % addr2int(executionAddress))
        return True, ctx

    b_addr = addr2int(b.minAddress)


    if b_addr == ctx["last_block_addr"]:
        res = True
        return res, ctx
    else:
        # New block
        if debug:
            print("notify_code_coverage: New block: 0x%08X\n" % b_addr)

        if not ctx.has_key("sock_afl"):
            r, ctx = connect_to_afl(ctx)
            if not r:
                print("notify_code_coverage: Error on connect to AFL")
                return res, ctx

        try:
            ctx["sock_afl"].sendall(struct.pack("<I", b_addr))
            ctx["last_block_addr"] = b_addr
            res = True
        except Exception as e:
            print("notify_code_coverage: Failed to send address: %s" % str(e))

    return res, ctx


