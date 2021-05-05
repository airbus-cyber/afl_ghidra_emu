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
import socket


CONFIG  = "\x02"

TRACE   = "\x03"
STOP    = "\xff"
CRASH   = "\xfe"
END     = "\xfd"
ERR     = "\xfc"





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



def parse_cmd(ctx, data, debug=False):
    res = False


    if len(data) < 1:
        # too short
        if debug:
            print("parse_cmd: Data too short: %d\n" % len(data))
        return res, ctx

    offset = 0
    if data[0] == CONFIG:
        offset += 1
        if len(data[offset:]) < 6:
            if debug:
                print("parse_cmd: data invalid length: %d\n" % len(data[offset:]))
            return res, ctx

        id_sample = struct.unpack("<I", data[offset:offset+4])[0]
        offset += 4

        size_input_data = struct.unpack("<H", data[offset:offset+2])[0]
        offset += 2
        input_data = data[offset:]
        if len(input_data) != size_input_data:
            if debug:
                print("parse_cmd: input_data_length not match: 0x%X - 0x%X\n" % (len(input_data), size_input_data))
            return res, ctx

        ctx.update(
            {
                "id_sample" : id_sample,
                "DATA_INPUT": input_data,
            }
        )
        res = True

    elif data[0] == STOP:
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




def rcv_large(sock, sz):
    chunk_size = 0x40
    data = ""
    while len(data) < sz:
        sz2rcv = chunk_size
        sz_left = sz - len(data)
        if sz_left < chunk_size:
            sz2rcv = sz_left
        data += sock.recv(sz2rcv)
    return data



def rcv_cmd(ctx, debug):
    res = False
    frame_raw = ""
    if not ctx.has_key("sock_bridge"):
        return res, ctx, frame_raw


    if not ctx.has_key("conn_bridge"):
        conn, addr = ctx["sock_bridge"].accept()
        if debug:
            print('rcv_cmd: Connected by', addr)

        ctx.update({"conn_bridge": conn})

    c = ctx["conn_bridge"].recv(1)
    if c is None:
        print("rcv_cmd: rcv type failed")
        return res, ctx, frame_raw

    if c not in [CONFIG, STOP]:
        print("rcv_cmd: invalid type frame:"+c.encode("hex"))
        return res, ctx, frame_raw

    frame_raw += c
    if c == STOP:
        res = True
        return res, ctx, frame_raw

    # get CONFIG frame
    id_sample = ctx["conn_bridge"].recv(4)
    if len(id_sample) != 4:
        print("rcv_cmd: rcv id_sample failed")
        return res, ctx, frame_raw
    frame_raw += id_sample

    sz_sample = ctx["conn_bridge"].recv(2)
    if len(sz_sample) != 2:
        print("rcv_cmd: rcv sz_sample failed")
        return res, ctx, frame_raw
    frame_raw += sz_sample

    frame_raw += rcv_large(ctx["conn_bridge"], struct.unpack("<H", sz_sample)[0])

    res = True
    return res, ctx, frame_raw



def rcv_input(ctx, debug):
    res = False

    # GET input frame
    res, ctx, config_raw = rcv_cmd(ctx, debug)
    if not res:
        #if debug:
        print("rcv_input: error on get config frame\n")
        return res, ctx


    ctx.update({"CONFIG_RAW": config_raw})
    res, ctx = parse_cmd(ctx, config_raw, debug)
    if not res:
        #if debug:
        print("rcv_input: error on parse config frame: %s\n" % config_raw.encode("hex"))
        return res, ctx


    res = True

    return res, ctx



def notify_crash(ctx):
    res = False
    try:
        ctx["conn_bridge"].sendall(CRASH+struct.pack("<I", ctx["id_sample"]))
        res = True
    except Exception as e:
        print("notify_crash: error: %s\n" % str(e))
        if ctx.has_key("conn_bridge"):
            ctx["conn_bridge"].close()
            del ctx["conn_bridge"]

    return res, ctx



def notify_end_exec(ctx):
    res = False
    try:
        ctx["conn_bridge"].sendall(END+struct.pack("<I", ctx["id_sample"]))
        res = True
    except Exception as e:
        print("notify_end_exec: error: %s\n" % str(e))
        if ctx.has_key("conn_bridge"):
            ctx["conn_bridge"].close()
            del ctx["conn_bridge"]

    return res, ctx


def notify_err(ctx):
    res = False
    try:
        ctx["conn_bridge"].sendall(ERR)
        res = True
    except Exception as e:
        print("notify_err: error: %s\n" % str(e))
        if ctx.has_key("conn_bridge"):
            ctx["conn_bridge"].close()
            del ctx["conn_bridge"]

    return res, ctx




def init_ctx(ctx, monitor, bbm):
    ctx.update({
        "monitor": monitor,
        "bbm": bbm,
        "last_block_addr": 0
    })
    return ctx



def free_ctx(ctx):

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

        if not ctx.has_key("conn_bridge"):
            print("notify_code_coverage: Error socket")
            return res, ctx

        try:
            ctx["conn_bridge"].sendall(TRACE + struct.pack("<I", ctx["id_sample"]) + struct.pack("<I", b_addr))
            ctx["last_block_addr"] = b_addr
            res = True
        except Exception as e:
            print("notify_code_coverage: Failed to send address: %s" % str(e))
            ctx["conn_bridge"].close()
            del ctx["conn_bridge"]

    return res, ctx

