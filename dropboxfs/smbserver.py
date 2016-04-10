#!/usr/bin/env python3

# This file is part of dropboxfs.

# dropboxfs is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# dropboxfs is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with dropboxfs.  If not, see <http://www.gnu.org/licenses/>.

import asyncio
import contextlib
import fcntl
import functools
import itertools
import os
import logging
import queue
import random
import socketserver
import struct
import sys
import time
import threading

from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from io import StringIO

try:
    from socket import socketpair
except ImportError:
    from asyncio.windows_utils import socketpair

# hack smb struct defs from PySMB
import smb.smb_structs as smb_structs

log = logging.getLogger(__name__)

SMB_COM_QUERY_INFORMATION_DISK = 0x80
SMB_COM_CHECK_DIRECTORY = 0x10
SMB_COM_TREE_DISCONNECT = 0x71

class SMBMessage(smb_structs.SMBMessage):
    # NB: default _decodePayload() assumes responses from servers
    # since we are the server, we assume requests
    def _decodePayload(self):
        if self.isReply: return super()._decodePayload();

        if self.command == smb_structs.SMB_COM_READ_ANDX:
            self.payload = ComReadAndxRequest()
        elif self.command == smb_structs.SMB_COM_WRITE_ANDX:
            self.payload = smb_structs.ComWriteAndxRequest()
        elif self.command == smb_structs.SMB_COM_TRANSACTION:
            self.payload = smb_structs.ComTransactionRequest()
        elif self.command == smb_structs.SMB_COM_TRANSACTION2:
            self.payload = ComTransaction2Request()
        elif self.command == smb_structs.SMB_COM_OPEN_ANDX:
            self.payload = smb_structs.ComOpenAndxRequest()
        elif self.command == smb_structs.SMB_COM_NT_CREATE_ANDX:
            self.payload = ComNTCreateAndxRequest()
        elif self.command == smb_structs.SMB_COM_TREE_CONNECT_ANDX:
            self.payload = ComTreeConnectAndxRequest()
        elif self.command == smb_structs.SMB_COM_ECHO:
            self.payload = ComEchoRequest()
        elif self.command == smb_structs.SMB_COM_SESSION_SETUP_ANDX:
            self.payload = ComSessionSetupAndxRequest()
        elif self.command == smb_structs.SMB_COM_NEGOTIATE:
            self.payload = ComNegotiateRequest()
        elif self.command == SMB_COM_QUERY_INFORMATION_DISK:
            self.payload = ComQueryInformationDiskRequest()
        elif self.command == smb_structs.SMB_COM_CLOSE:
            self.payload = ComCloseRequest()
        elif self.command == smb_structs.SMB_COM_NT_TRANSACT:
            self.payload = ComNTTransactRequest()
        elif self.command == SMB_COM_CHECK_DIRECTORY:
            self.payload = ComCheckDirectoryRequest()
        elif self.command == SMB_COM_TREE_DISCONNECT:
            self.payload = ComTreeDisconnectRequest()


        if self.payload:
            self.payload.decode(self)

def init_reply(payload, message, command):
    smb_structs.Payload.initMessage(payload, message)
    message.command = command
    message.flags = message.flags | smb_structs.SMB_FLAGS_REPLY
    message.flags2 = message.flags2 & ~smb_structs.SMB_FLAGS2_EXTENDED_SECURITY
    message.tid = getattr(payload, 'tid', 0)
    message.uid = getattr(payload, 'uid', 0)
    message.mid = getattr(payload, 'mid', 0)

def prepare(payload, message):
    assert message.payload is payload
    message.pid = getattr(payload, 'pid', 0)

def parse_zero_terminated_utf16(buf, offset):
    s = offset
    while True:
        next_offset = buf.index(b'\0\0', s)
        if (next_offset - offset) % 2: s = next_offset + 1
        else: break
    return (buf[offset:next_offset].decode("utf-16-le"), next_offset + 2)

class ComNegotiateRequest(smb_structs.ComNegotiateRequest):
    def __str__(self):
        lines = []

        lines.append("SMB_COM_NEGOTIATE (request)")
        lines.append("Dialect Supported:")
        for d in self.dialects:
            lines.append("  %s" % (d,))

        return os.linesep.join(lines)

    def decode(self, message):
        self.dialects = message.data.split(b'\0')
        a = self.dialects.pop()
        if a: raise smb_structs.ProtocolError("Non-trailing null byte!")
        self.dialects = [d.lstrip(b"\x02").decode("ascii") for d in self.dialects]

class ComNegotiateResponse(smb_structs.ComNegotiateResponse):
    def __init__(self, **kw):
        for (k, v) in kw.items():
            setattr(self, k, v)

    def initMessage(self, message):
        init_reply(self, message, smb_structs.SMB_COM_NEGOTIATE)

    def prepare(self, message):
        prepare(self, message)

        PAYLOAD_STRUCT_FORMAT = '<HBHHIIIIQhB'

        message.parameters_data = struct.pack(PAYLOAD_STRUCT_FORMAT,
                                              self.dialect_index, self.security_mode, self.max_mpx_count,
                                              self.max_number_vcs, self.max_buffer_size, self.max_raw_size,
                                              self.session_key, self.capabilities, self.system_time,
                                              self.server_time_zone, self.challenge_length)
        message.data = "\0".encode("utf-16-le")

class ComSessionSetupAndxRequest(smb_structs.ComSessionSetupAndxRequest__NoSecurityExtension):
    def __init__(self):
        pass

    def decode(self, message):
        andx_header = message.parameters_data[:self.DEFAULT_ANDX_PARAM_SIZE]
        (andx_command, andx_reserved, andx_offset) = andx_header_o = struct.unpack(">BBH", andx_header)

        # TODO: better andx parsing
        if not (andx_command == 0xff and not andx_offset):
            raise Exception("We don't support non-terminal ANDX parameter blocks yet...")

        params = message.parameters_data[self.DEFAULT_ANDX_PARAM_SIZE:]
        (max_buffer_size, max_mpx_count, vc_number,
         session_key, oem_password_len, unicode_password_len, reserved, capabilities) = params_o =struct.unpack(self.PAYLOAD_STRUCT_FORMAT, params)

        # TODO: check session_key from SMB_COM_NEGOTIATE

        is_unicode = message.flags2 & smb_structs.SMB_FLAGS2_UNICODE
        if not is_unicode: raise Exception("Only support unicode!")

        if is_unicode:
            if oem_password_len:
                # NB: Mac OS X sends oem_password_len == 1 even when SMB_FLAGS2_UNICODE is
                #     set, even though this is against spec
                log.warning("OEM Password len must be 0 when SMB_FLAGS2_UNICODE is set: %r, %r" %
                            (oem_password_len, message.data[:oem_password_len]))
            # Linux CIFS_VFS client sends NTLMv2 even when we ask it not to
            password = None
            #password = message.data[oem_password_len:oem_password_len + unicode_password_len].decode("utf-16-le")
        else:
            if unicode_password_len:
                log.warning("Unicode Password len must be 0 when SMB_FLAGS2_UNICODE is clear")
            # TODO: 'ascii' is probably not the right encoding here
            password = message.data[:oem_password_len].rstrip(b'\0').decode("ascii")


        # read padding
        raw_offset = (SMBMessage.HEADER_STRUCT_SIZE + len(message.parameters_data) + 2 +
                      oem_password_len + unicode_password_len)
        if raw_offset % 2 and is_unicode:
            if message.raw_data[raw_offset] != 0:
                raise Exception("Was expecting null byte!: %r" % (message.raw_data[raw_offset],))
            raw_offset += 1

        term = b"\0\0" if is_unicode else b"\0"
        encoding = "utf-16-le" if is_unicode else "ascii"

        elts = {}
        for n in ["username", "domain", "nativeos", "nativelanman"]:
            (elts[n], raw_offset) = parse_zero_terminated_utf16(message.raw_data,
                                                                 raw_offset)

        self.max_buffer_size = max_buffer_size
        self.max_mpx_count = max_mpx_count
        self.vc_number = vc_number
        self.session_key = session_key
        self.capabilities = capabilities

        self.password = password
        self.username = elts['username']
        self.domain = elts['domain']
        self.native_os = elts['nativeos']
        self.native_lan_man = elts['nativelanman']

class ComSessionSetupAndxResponse(smb_structs.ComSessionSetupAndxResponse):
    def __init__(self, **kw):
        for (k, v) in kw.items():
            setattr(self, k, v)

    def initMessage(self, message):
        init_reply(self, message, smb_structs.SMB_COM_SESSION_SETUP_ANDX)

    def prepare(self, message):
        prepare(self, message)

        # this gets reset in SMBMessage.encode()
        message.pid = self.pid

        message.parameters_data = (self.DEFAULT_ANDX_PARAM_HEADER +
                                   struct.pack('<H',self.action))

        prefix = b''
        if (SMBMessage.HEADER_STRUCT_SIZE + len(message.parameters_data) + 2):
            prefix = b'\0'

        message.data = prefix + b''.join([x.encode("utf-16-le") + b'\0\0'  for x in ["Unix", "DropboxFS", self.domain]])

class ComTreeConnectAndxRequest(smb_structs.ComTreeConnectAndxRequest):
    def __init__(self): pass

    def decode(self, message):
        is_unicode = message.flags2 & smb_structs.SMB_FLAGS2_UNICODE
        if not is_unicode: raise Exception("Only support unicode!")

        andx_header = message.parameters_data[:self.DEFAULT_ANDX_PARAM_SIZE]
        (andx_command, andx_reserved, andx_offset) = andx_header_o = struct.unpack(">BBH", andx_header)

        # TODO: better andx parsing
        if not (andx_command == 0xff and not andx_offset):
            raise Exception("We don't support non-terminal ANDX parameter blocks yet...")

        (self.flags, password_len) = struct.unpack(self.PAYLOAD_STRUCT_FORMAT,
                                                   message.parameters_data[self.DEFAULT_ANDX_PARAM_SIZE:self.PAYLOAD_STRUCT_SIZE + self.DEFAULT_ANDX_PARAM_SIZE])

        # Linux CIFS_VFS client sends NTLMv2 even when we ask it not to
        self.password = None
        #self.password = message.data[:password_len].rstrip(b'\0').decode("utf-8")

        raw_offset = (SMBMessage.HEADER_STRUCT_SIZE + len(message.parameters_data) +
                      2 + password_len)
        if raw_offset % 2:
            if message.raw_data[raw_offset] != 0:
                raise Exception("Was expecting null byte padding!")
            raw_offset += 1

        (self.path, raw_offset) = parse_zero_terminated_utf16(message.raw_data, raw_offset)

        service_off = message.raw_data.index(b'\0', raw_offset)
        self.service = message.raw_data[raw_offset:service_off].decode("ascii")

class ComTreeConnectAndxResponse(smb_structs.ComTreeConnectAndxResponse):
    def __init__(self, **kw):
        for (k, v) in kw.items():
            setattr(self, k, v)

    def initMessage(self, message):
        init_reply(self, message, smb_structs.SMB_COM_TREE_CONNECT_ANDX)

    def prepare(self, message):
        prepare(self, message)

        message.parameters_data = struct.pack(self.PAYLOAD_STRUCT_FORMAT,
                                              0xff, 0, 0,
                                              self.optional_support)

        # NB A: means disk share
        message.data = b'A:\0'

class ComTreeDisconnectRequest(smb_structs.Payload):
    def decode(self, message):
        pass

class ComTreeDisconnectResponse(smb_structs.Payload):
    def __init__(self, **kw):
        for (k, v) in kw.items():
            setattr(self, k, v)

    def initMessage(self, message):
        init_reply(self, message, SMB_COM_TREE_DISCONNECT)

    def prepare(self, message):
        prepare(self, message)
        message.parameters_data = b''
        message.data = b''

class ComEchoRequest(smb_structs.ComEchoRequest):
    def decode(self, message):
        fmt = '<H'
        fmt_size = struct.calcsize(fmt)
        (self.echo_count,) = struct.unpack(fmt, message.parameters_data[:fmt_size])
        self.echo_data = message.data

class ComEchoResponse(smb_structs.ComEchoResponse):
    def __init__(self, **kw):
        for (k, v) in kw.items():
            setattr(self, k, v)

    def initMessage(self, message):
        init_reply(self, message, smb_structs.SMB_COM_ECHO)

    def prepare(self, message):
        prepare(self, message)

        message.parameters_data = struct.pack("<H", self.sequence_number)
        message.data = self.data

class ComTransaction2Request(smb_structs.ComTransaction2Request):
    def __init__(self): pass

    def decode(self, message):
        (self.total_params_count, self.total_data_count,
         self.max_params_count, self.max_data_count,
         self.max_setup_count, _, self.flags, self.timeout,
         _, params_bytes_len, params_bytes_offset, data_bytes_len,
         data_bytes_offset, setup_words_len) = \
            struct.unpack(self.PAYLOAD_STRUCT_FORMAT,
                          message.parameters_data[:self.PAYLOAD_STRUCT_SIZE])

        self.setup_bytes = message.parameters_data[self.PAYLOAD_STRUCT_SIZE:self.PAYLOAD_STRUCT_SIZE + setup_words_len * 2]

        self.params_bytes = message.raw_data[params_bytes_offset:params_bytes_offset + params_bytes_len]
        self.data_bytes = message.raw_data[data_bytes_offset:data_bytes_offset + data_bytes_len]

class ComTransaction2Response(smb_structs.ComTransaction2Response):
    def __init__(self, **kw):
        for (k, v) in kw.items():
            setattr(self, k, v)

    def initMessage(self, message):
        init_reply(self, message, smb_structs.SMB_COM_TRANSACTION2)

    def prepare(self, message):
        prepare(self, message)

        assert not (len(self.setup_bytes) % 2)

        data_offset = (message.HEADER_STRUCT_SIZE +
                       struct.calcsize("<HHHHHHHHHBB") +
                       len(self.setup_bytes) + 2)
        params_bytes_offset = data_offset
        if params_bytes_offset % 4:
            params_bytes_offset += 4 - params_bytes_offset % 4

        data_bytes_offset = params_bytes_offset + len(self.params_bytes)
        if data_bytes_offset % 4:
            data_bytes_offset += 4 - data_bytes_offset % 4

        message.parameters_data = struct.pack("<HHHHHHHHHBB",
                                              len(self.params_bytes),
                                              len(self.data_bytes),
                                              0,
                                              len(self.params_bytes),
                                              params_bytes_offset,
                                              0,
                                              len(self.data_bytes),
                                              data_bytes_offset,
                                              0, len(self.setup_bytes) // 2, 0)
        message.parameters_data += self.setup_bytes

        message.data = ((params_bytes_offset - data_offset) * b'\0' +
                        self.params_bytes +
                        (data_bytes_offset - (params_bytes_offset + len(self.params_bytes))) * b'\0' +
                        self.data_bytes)

class ComQueryInformationDiskRequest(smb_structs.Payload):
    def decode(self, message):
        pass

class ComQueryInformationDiskResponse(smb_structs.Payload):
    def __init__(self, **kw):
        for (k, v) in kw.items():
            setattr(self, k, v)

    def initMessage(self, message):
        init_reply(self, message, SMB_COM_QUERY_INFORMATION_DISK)

    def prepare(self, message):
        prepare(self, message)

        message.parameters_data = struct.pack("<HHHHH",
                                              self.total_units,
                                              self.blocks_per_unit,
                                              self.block_size,
                                              self.free_units,
                                              0)

class ComNTCreateAndxRequest(smb_structs.ComNTCreateAndxRequest):
    def __init__(self): pass

    def decode(self, message):
        is_unicode = message.flags2 & smb_structs.SMB_FLAGS2_UNICODE
        if not is_unicode: raise Exception("Only support unicode!")

        (andx_command, andx_reserved, andx_offset,
         reserved, filename_len, self.flags,
         self.root_fid, self.access_mask,
         self.allocation_size, self.ext_attr,
         self.share_access, self.create_disp,
         self.create_options, self.impersonation,
         self.security_flags) = struct.unpack("<BBH" + self.PAYLOAD_STRUCT_FORMAT[1:],
                                              message.parameters_data)

        # TODO: better andx parsing
        if not (andx_command == 0xff and not andx_offset):
            raise Exception("We don't support non-terminal ANDX parameter blocks yet...")

        raw_offset = message.HEADER_STRUCT_SIZE + len(message.parameters_data) + 2
        if raw_offset % 2:
            raw_offset += 1

        self.filename = message.raw_data[raw_offset:raw_offset + filename_len].decode("utf-16-le").rstrip("\0")

class ComNTCreateAndxResponse(smb_structs.ComNTCreateAndxResponse):
    def __init__(self, **kw):
        for (k, v) in kw.items():
            setattr(self, k, v)

    def initMessage(self, message):
        init_reply(self, message, smb_structs.SMB_COM_NT_CREATE_ANDX)

    def prepare(self, message):
        prepare(self, message)

        message.parameters_data = struct.pack("<BBHBHLQQQQLQQHHB",
                                              0xff, 0, 0,
                                              self.op_lock_level,
                                              self.fid,
                                              self.create_disp,
                                              self.create_time,
                                              self.last_access_time,
                                              self.last_write_time,
                                              self.last_change_time,
                                              self.ext_attr,
                                              self.allocation_size,
                                              self.end_of_file,
                                              self.resource_type,
                                              self.nm_pipe_status,
                                              self.directory)
        message.data = b''

class ComReadAndxRequest(smb_structs.ComReadAndxRequest):
    def __init__(self): pass

    def decode(self, message):
        fmt = "<BBHHLHHLH"
        fmt_size = struct.calcsize(fmt)
        (andx_command, _, andx_offset,
         self.fid, self.offset,
         self.max_return_bytes_count,
         self.min_return_bytes_count,
         self.timeout,
         self.remaining) = struct.unpack("<BBHHLHHLH", message.parameters_data[:fmt_size])

        if len(message.parameters_data) > fmt_size:
            (offset_high,) = struct.unpack("<L", message.parameters_data[fmt_size:])
            self.offset = (offset_high << 32) | self.offset

        # TODO: better andx parsing
        if not (andx_command == 0xff and not andx_offset):
            raise Exception("We don't support non-terminal ANDX parameter blocks yet...")

class ComReadAndxResponse(smb_structs.ComReadAndxResponse):
    def __init__(self, **kw):
        for (k, v) in kw.items():
            setattr(self, k, v)

    def initMessage(self, message):
        init_reply(self, message, smb_structs.SMB_COM_READ_ANDX)

    def prepare(self, message):
        prepare(self, message)

        fmt = "<BBHHHHHHHHHHH"
        parameters_size = struct.calcsize(fmt)

        offset = message.HEADER_STRUCT_SIZE + parameters_size + 2
        pad = False
        if offset % 2:
            pad = True
            offset += 1

        reserved = 0
        message.parameters_data = struct.pack(fmt,
                                              0xff, 0, reserved,
                                              reserved, reserved,
                                              reserved,
                                              len(self.data), offset,
                                              reserved, reserved, reserved,
                                              reserved, reserved)

        message.data = (b'\0' if pad else b'') + self.data

class ComCloseRequest(smb_structs.ComCloseRequest):
    def __init__(self): pass

    def decode(self, message):
        (self.fid,
         self.last_modified_time) = struct.unpack("<HL", message.parameters_data)

class ComCloseResponse(smb_structs.Payload):
    def __init__(self, **kw):
        for (k, v) in kw.items():
            setattr(self, k, v)

    def initMessage(self, message):
        init_reply(self, message, smb_structs.SMB_COM_CLOSE)

    def prepare(self, message):
        prepare(self, message)
        message.parameters_data = b''
        message.data = b''

class ComNTTransactRequest(smb_structs.ComNTTransactRequest):
    def __init__(self): pass

    def decode(self, message):
        fmt = "<BHLLLLLLLLBH"
        fmt_size = struct.calcsize(fmt)

        (self.max_setup_count,
         _,
         self.total_params_count,
         self.total_data_count,
         self.max_params_count,
         self.max_data_count,
         params_count,
         params_offset,
         data_count,
         data_offset,
         setup_count,
         self.function,
         ) = struct.unpack(fmt, message.parameters_data[:fmt_size])

        self.setup_bytes = message.parameters_data[fmt_size:fmt_size + setup_count * 2]

        if (data_count < self.total_data_count or
            params_count < self.total_params_count):
            raise Exception("We don't support extended SMB_COM_NT_TRANSACT yet")

        self.params_bytes = message.raw_data[params_offset:params_offset + params_count]
        self.data_bytes = message.raw_data[data_offset:data_offset + data_count]

class ComNTTransactResponse(smb_structs.ComNTTransactResponse):
    def __init__(self, **kw):
        for (k, v) in kw.items():
            setattr(self, k, v)

    def initMessage(self, message):
        init_reply(self, message, smb_structs.SMB_COM_NT_TRANSACT)

    def prepare(self, message):
        prepare(self, message)

        if len(self.setup_bytes) % 2:
            raise Exception("invalid setup bytes!")

        fmt = "<BBBLLLLLLLLB"
        fmt_size = struct.calcsize(fmt)

        offset = message.HEADER_STRUCT_SIZE + fmt_size + len(self.setup_bytes) + 2

        pad1 = b''
        if offset % 4:
            pad1 = b' ' * (4 - offset % 4)
            offset += 4 - offset % 4
        params_offset = offset

        offset += len(self.params_bytes)

        pad2 = b''
        if offset % 4:
            pad2 = b' ' * (4 - offset % 4)
            offset += 4 - offset % 4
        data_offset = offset

        message.parameters_data = b''.join([struct.pack(fmt,
                                                        0, 0, 0,
                                                        self.total_params_count,
                                                        self.total_data_count,
                                                        len(self.params_bytes),
                                                        params_offset,
                                                        0,
                                                        len(self.data_bytes),
                                                        data_offset,
                                                        0,
                                                        len(self.setup_bytes) // 2),
                                            self.setup_bytes])

        message.data = b''.join([pad1, self.params_bytes, pad2, self.data_bytes])

class ComCheckDirectoryRequest(smb_structs.Payload):
    def decode(self, message):
        self.filename = message.data[1:].decode('utf-16-le').rstrip('\0')

class ComCheckDirectoryResponse(smb_structs.Payload):
    def __init__(self, **kw):
        for (k, v) in kw.items():
            setattr(self, k, v)

    def initMessage(self, message):
        init_reply(self, message, SMB_COM_CHECK_DIRECTORY)

    def prepare(self, message):
        prepare(self, message)
        message.parameters_data = b''
        message.data = b''

def response_args_from_req(req, **kw):
    return dict(pid=req.pid, tid=req.tid,
                uid=req.uid, mid=req.mid, **kw)

STATUS_NOT_FOUND = 0xc0000225
STATUS_SMB_BAD_COMMAND = 0x160002
STATUS_NOT_SUPPORTED = 0xc00000bb
STATUS_NO_SUCH_FILE = 0xc000000f
STATUS_TOO_MANY_OPENED_FILES = 0xc000011f
STATUS_FILE_IS_A_DIRECTORY = 0xc00000ba
STATUS_SHARING_VIOLATION = 0xc0000043
STATUS_INVALID_HANDLE = 0xc0000008
STATUS_ACCESS_DENIED = 0xc0000022
STATUS_INSUFF_SERVER_RESOURCES = 0xc00000cf
STATUS_OBJECT_PATH_NOT_FOUND = 0xc000003a
STATUS_SMB_BAD_TID = 0x50002
STATUS_SMB_BAD_UID = 0x5b0002
STATUS_NOTIFY_ENUM_DIR = 0x10c
STATUS_OS2_INVALID_LEVEL = 0x7c0001
STATUS_NOT_A_DIRECTORY = 0xC0000000 | 0x0103

TREE_CONNECT_ANDX_DISCONNECT_TID = 0x1
SMB_TRANS2_FIND_FIRST2 = 0x1
SMB_TRANS2_FIND_NEXT2 = 0x2
SMB_TRANS2_QUERY_FS_INFORMATION = 0x3
SMB_TRANS2_QUERY_PATH_INFORMATION = 0x5
SMB_INFO_STANDARD = 0x1
SMB_INFO_QUERY_EAS_FROM_LIST = 0x3
SMB_FIND_FILE_DIRECTORY_INFO = 0x101
SMB_FIND_FILE_BOTH_DIRECTORY_INFO = 0x104
SMB_FIND_RETURN_RESUME_KEYS = 0x4
SMB_FIND_CLOSE_AT_EOS = 0x2
SMB_FIND_CLOSE_AFTER_REQUEST = 0x1
ATTR_DIRECTORY = 0x10
ATTR_NORMAL = 0x80
SMB_QUERY_FS_SIZE_INFO = 0x103
SMB_QUERY_FS_DEVICE_INFO = 0x104
SMB_QUERY_FS_ATTRIBUTE_INFO = 0x105
SMB_QUERY_FILE_ALL_INFO = 0x107
NT_TRANSACT_NOTIFY_CHANGE = 0x4

NT_CREATE_REQUEST_OPLOCK = 0x2
NT_CREATE_REQUEST_OPBATCH = 0x4
NT_CREATE_OPEN_TARGET_DIR = 0x8

FILE_WRITE_DATA = 0x2
FILE_APPEND_DATA = 0x4
FILE_WRITE_EA = 0x10
FILE_WRITE_ATTRIBUTES = 0x100
DELETE = 0x10000
WRITE_DAC = 0x40000
WRITE_OWNER = 0x80000
ACCESS_SYSTEM_SECURITY = 0x1000000
GENERIC_ALL = 0x1000000
GENERIC_WRITE = 0x40000000

FILE_OPEN = 0x1

FILE_DELETE_ON_CLOSE = 0x1000
FILE_OPEN_BY_FILE_ID = 0x2000

FILE_NON_DIRECTORY_FILE = 0x40

FILE_SHARE_READ = 0x1

FILE_ACTION_ADDED = 0x1
FILE_ACTION_REMOVED = 0x2
FILE_ACTION_MODIFIED = 0x3
FILE_ACTION_RENAMED_OLD_NAME = 0x4
FILE_ACTION_RENAMED_NEW_NAME = 0x5

def encode_smb_datetime(dt):
    log.debug("date is %r", dt)
    date = 0
    date |= (dt.year - 1980) << 9
    date |= (dt.month & 0xf) << 5
    date |= dt.day & 0x1f
    assert date < 2 ** 16
    time = 0
    time |= dt.hour << 11
    time |= dt.minute << 5
    time |= int(dt.second / 2)
    assert time < 2 ** 16
    return (date, time)

class NullPayload(smb_structs.Payload):
    def __init__(self, **kw):
        for (k, v) in kw.items():
            setattr(self, k, v)

    def initMessage(self, message):
        init_reply(self, message, self.command)

    def prepare(self, message):
        prepare(self, message)

def error_response(req, status):
    assert status, "Status must be an error!"
    m = SMBMessage(NullPayload(**response_args_from_req(req, command=req.command)))
    m.status.internal_value = status
    m.status.is_ntstatus = True
    return m

def decode_smb_message(message):
    i = SMBMessage()
    i.decode(message)
    return i

def recv_all(sock, len_):
    toret = []
    recvd = 0
    while recvd != len_:
        b = sock.recv(len_ - recvd)
        if not b:
            raise Exception("EOF while expecting data!")
        recvd += len(b)
        toret.append(b)
    return b''.join(toret)

def datetime_to_win32(dt):
    # Assumes dt is a naive datetime in UTC time
    assert dt.tzinfo is None
    return (int(dt.replace(tzinfo=timezone.utc).timestamp()) + 11644473600) * 10000000

def get_size(md):
    return getattr(md, 'size', 0)

def generate_info_standard(idx, offset, flags, name, md, _):
    include_resume_key = flags & SMB_FIND_RETURN_RESUME_KEYS

    # SMB_INFO_STANDARD
    fmt = "<"
    args = []
    if include_resume_key:
        fmt += "I"
        args.append(idx)
    fmt += "HHHHHHIIHB"
    name += '\0'
    file_name_encoded = name.encode("utf-16-le")

    (creation_date, creation_time) = encode_smb_datetime(md.birthtime)
    (last_access_date, last_access_time) = encode_smb_datetime(md.atime)
    (last_write_date, last_write_time) = encode_smb_datetime(md.mtime)

    file_data_size = get_size(md)
    allocation_size = 4096
    attributes = (ATTR_DIRECTORY
                  if md.type == "directory" else
                  ATTR_NORMAL)

    args.extend([creation_date, creation_time,
                 last_access_date, last_access_time,
                 last_write_date, last_write_time,
                 file_data_size, allocation_size,
                 attributes, len(file_name_encoded)])

    bufs = []
    bufs.append(struct.pack(fmt, *args))
    offset += len(bufs[-1])
    if offset % 2:
        data.append(b' ')
        offset += 1
    bufs.append(file_name_encoded)
    offset += len(bufs[-1])

    return bufs

def generate_find_file_directory_info(idx, offset, flags, name, md, is_last):
    fmt = "<IIQQQQQQII"

    encoded_file_name = (name + "\0").encode("utf-16-le")
    fmt_size = struct.calcsize(fmt)
    SHORT_NAME_SIZE = 24

    next_entry_offset = (0
                         if is_last else
                         fmt_size + len(encoded_file_name))

    file_data_size = get_size(md)

    allocation_size = 4096
    ext_file_attributes = (ATTR_DIRECTORY
                           if md.type == "directory" else
                           ATTR_NORMAL)

    buf = struct.pack(fmt, next_entry_offset,
                      # FileIndex is set to zero because there is not guarantee
                      # on directory sort order
                      0,
                      datetime_to_win32(md.birthtime),
                      datetime_to_win32(md.atime),
                      datetime_to_win32(md.mtime),
                      datetime_to_win32(md.ctime),
                      file_data_size,
                      allocation_size,
                      ext_file_attributes,
                      len(encoded_file_name))

    return [buf, encoded_file_name]

def generate_find_file_both_directory_info(idx, offset, flags, name, md, is_last):
    fmt = "<IIQQQQQQIIIBB"

    encoded_file_name = (name + "\0").encode("utf-16-le")
    fmt_size = struct.calcsize(fmt)
    SHORT_NAME_SIZE = 24

    next_entry_offset = (0
                         if is_last else
                         fmt_size + SHORT_NAME_SIZE + len(encoded_file_name))

    file_data_size = get_size(md)

    allocation_size = 4096
    ext_file_attributes = (ATTR_DIRECTORY
                           if md.type == "directory" else
                           ATTR_NORMAL)
    ea_size = 0

    buf = struct.pack(fmt, next_entry_offset, 0,
                      datetime_to_win32(md.birthtime),
                      datetime_to_win32(md.atime),
                      datetime_to_win32(md.mtime),
                      datetime_to_win32(md.ctime),
                      file_data_size,
                      allocation_size,
                      ext_file_attributes,
                      len(encoded_file_name),
                      ea_size,
                      0, 0)

    bufs = []
    bufs.append(buf)
    bufs.append(b'\0' * 24)
    bufs.append(encoded_file_name)

    return bufs

INFO_GENERATORS = {
    SMB_INFO_STANDARD: generate_info_standard,
    SMB_FIND_FILE_DIRECTORY_INFO: generate_find_file_directory_info,
    SMB_FIND_FILE_BOTH_DIRECTORY_INFO: generate_find_file_both_directory_info,
}

def generate_fs_size_info():
    return struct.pack("<QQII",
                       2 ** 64 - 1, # total allocation units
                       0, # total free allocation units
                       16384, # sectors per allocation unit
                       512, # bytes per sector
                       )

FILE_DEVICE_DISK = 0x7

def generate_fs_device_info():
    # TODO: there are a whole bunch of options we can use for the
    #       "characteristics" field
    return struct.pack("<II",
                         FILE_DEVICE_DISK,
                         0)

FILE_CASE_SENSITIVE_SEARCH = 0x1
FILE_CASE_PRESERVED_NAMES = 0x2
FILE_UNICODE_ON_DISK = 0x4

def generate_fs_attribute_info():
    file_system_attributes = FILE_UNICODE_ON_DISK | FILE_CASE_PRESERVED_NAMES
    max_file_name_length_in_bytes = 255 * 2
    file_system_name = "what"
    file_system_name_encoded = file_system_name.encode("utf-16-le")
    header = struct.pack("<LlL",
                         file_system_attributes,
                         max_file_name_length_in_bytes,
                         len(file_system_name_encoded))
    return header + file_system_name_encoded

FS_INFO_GENERATORS = {
    SMB_QUERY_FS_SIZE_INFO: generate_fs_size_info,
    SMB_QUERY_FS_DEVICE_INFO: generate_fs_device_info,
    SMB_QUERY_FS_ATTRIBUTE_INFO: generate_fs_attribute_info,
}

def generate_query_file_all_info(path, md):
    creation_time = datetime_to_win32(md.birthtime)
    last_access_time = datetime_to_win32(md.atime)
    last_write_time = datetime_to_win32(md.mtime)
    last_change_time = datetime_to_win32(md.ctime)
    ext_file_attributes = (ATTR_DIRECTORY
                           if md.type == "directory" else
                           ATTR_NORMAL)
    allocation_size = 4096
    file_data_size = get_size(md)

    reserved = 0

    number_of_links = 1
    delete_pending = 0
    directory = int(md.type == "directory")

    ea_size = 0

    encoded_file_name = (path + "\0").encode("utf-16-le")

    buf = struct.pack("<QQQQLLQQLBBHLL",
                      creation_time, last_access_time,
                      last_write_time, last_change_time,
                      ext_file_attributes,
                      reserved, allocation_size,
                      file_data_size,
                      number_of_links,
                      delete_pending,
                      directory,
                      reserved,
                      ea_size,
                      len(encoded_file_name))
    buf += encoded_file_name

    return (0, buf)

QUERY_FILE_INFO_GENERATORS = {
    SMB_QUERY_FILE_ALL_INFO: generate_query_file_all_info,
}

class ProtocolError(Exception):
    def __init__(self, error, message=None):
        self.error = error
        self.message = message
        self.args = (error, message)

    def __repr__(self):
        return 'ProtocolError(0x%x, %r)' % (self.error, self.message)

@asyncio.coroutine
def cant_fail(on_fail, future):
    try:
        ret = yield from future
    except Exception:
        log.exception("Process-stopping exception!")
        on_fail()

INVALID_UIDS = (0x0, 0xfffe)
INVALID_TIDS = (0x0, 0xffff)
INVALID_SIDS = (0xffff,)
INVALID_FIDS = (0xffff,)

class SMBClientHandler(object):
    def __init__(self):
        self._open_uids = set()
        self._open_tids = {}
        self._open_find_trans = {}
        self._open_files = {}

    @asyncio.coroutine
    def verify_tid(self, req):
        try:
            toret = self._open_tids[req.tid]
            if toret['closing']: raise KeyError()
            toret['ref'] += 1
            return toret['fs']
        except KeyError:
            raise ProtocolError(STATUS_SMB_BAD_TID)

    @asyncio.coroutine
    def deref_tid(self, tid):
        toret = self._open_tids[tid]
        toret['ref'] -= 1
        if (toret['closing'] is not None and
            not toret['ref']):
            toret['closing'].set_result(None)

    @asyncio.coroutine
    def verify_uid(self, req):
        if req.uid not in self._open_uids:
            raise ProtocolError(STATUS_SMB_BAD_UID)

    def _create_id(self, set_, invalid, error=STATUS_INSUFF_SERVER_RESOURCES):
        assert len(set_) <= 2 ** 16 - len(invalid)
        if len(set_) == 2 ** 16 - len(invalid):
            raise ProtocolError(error)

        uid = random.randint(0, 2 ** 16)
        while uid in set_ or uid in invalid:
            uid = random.randint(0, 2 ** 16)

        return uid

    @asyncio.coroutine
    def create_session(self):
        uid = self._create_id(self._open_uids, INVALID_UIDS)
        self._open_uids.add(uid)
        return uid

    @asyncio.coroutine
    def destroy_session(self, uid):
        del self._open_uids[uid]

    @asyncio.coroutine
    def create_tree(self, fs):
        tid = self._create_id(self._open_tids, INVALID_TIDS)
        self._open_tids[tid] = dict(closing=None,
                                    ref=0,
                                    fs=fs)
        return tid

    @asyncio.coroutine
    def destroy_tree(self, tid):
        ret = self._open_tids[tid]

        if ret['closing']: raise KeyError()

        # mark tid as closing
        all_closed = asyncio.Future(loop=self._loop)
        ret['closing'] = all_closed

        # close all resources associated with tid (in parallel)
        waiting = []

        @asyncio.coroutine
        def destroy_close_file(fid):
            fidmd = yield from self.destroy_file(fid)
            yield from fidmd['handle'].close()

        for fid, value in self._open_files.items():
            if value['tid'] != tid: continue
            waiting.append(asyncio.async(destroy_close_file(fid), loop=self._loop))

        @asyncio.coroutine
        def destroy_close_search(sid):
            searchmd = yield from self.destroy_search(sid)
            yield from searchmd['handle'].close()

        for sid, value in self._open_find_trans.items():
            if value['tid'] != tid: continue
            waiting.append(asyncio.async(destroy_close_search(sid), loop=self._loop))

        if ret['ref']:
            # wait for all tids to be dereffed
            waiting.append(all_closed)

        if waiting:
            yield from asyncio.wait(waiting, loop=self._loop)

        assert not ret['ref']

        popped = self._open_tids.pop(tid)
        assert popped is ret
        return ret['fs']

    @asyncio.coroutine
    def hard_destroy_all_trees(self, server, backend):
        @asyncio.coroutine
        def destroy_tid(tid):
            fs = yield from self.destroy_tree(tid)
            yield from backend.tree_disconnect_hard(server, fs)

        waiting = []
        for tid in self._open_tids:
            waiting.append(asyncio.async(destroy_tid(tid), loop=self._loop))

        if waiting:
            yield from asyncio.wait(waiting, loop=self._loop)

    @asyncio.coroutine
    def create_search(self, **kw):
        sid = self._create_id(self._open_find_trans, INVALID_SIDS)
        kw['lock'] = asyncio.Lock(loop=self._loop)
        kw['closing'] = False
        self._open_find_trans[sid] = dict(**kw)
        return sid

    @asyncio.coroutine
    def ref_search(self, sid):
        toret = self._open_find_trans[sid]
        if toret['closing']: raise KeyError()
        yield from toret['lock'].acquire()
        return toret

    @asyncio.coroutine
    def deref_search(self, sid):
        toret = self._open_find_trans[sid]
        toret['lock'].release()

    @asyncio.coroutine
    def destroy_search(self, sid):
        # flag file as closing
        ret = self._open_find_trans[sid]
        if ret['closing']: raise KeyError()

        ret['closing'] = True

        yield from ret['lock'].acquire()
        try:
            popped = self._open_find_trans.pop(sid)
            assert popped is ret
            return ret
        finally:
            ret['lock'].release()

    @asyncio.coroutine
    def verify_share(self, file_path, is_sharing):
        for (fid, open_md) in self._open_files.items():
            if open_md['path'].lower() == file_path.lower():
                if not (open_md['share'] and is_sharing):
                    raise ProtocolError(STATUS_SHARING_VIOLATION)

    @asyncio.coroutine
    def ref_file(self, fid):
        # KeyError is okay for now
        toret = self._open_files[fid]
        if toret['closing'] is not None: raise KeyError()
        toret['ref'] += 1
        return toret

    @asyncio.coroutine
    def deref_file(self, fid):
        toret = self._open_files[fid]
        toret['ref'] -= 1
        if (toret['closing'] is not None and
            not toret['ref']):
            toret['closing'].set_result(None)

    @asyncio.coroutine
    def create_file(self, path, is_sharing, handle, tid):
        fid = self._create_id(self._open_files, INVALID_FIDS)
        self._open_files[fid] = dict(path=path,
                                     ref=0,
                                     share=is_sharing,
                                     handle=handle,
                                     closing=None,
                                     is_closing=asyncio.Future(loop=self._loop),
                                     watches=[],
                                     tid=tid)
        return fid

    @asyncio.coroutine
    def destroy_file(self, fid):
        # flag file as closing
        ret = self._open_files[fid]
        if ret['closing'] is not None: raise KeyError()
        all_closed = asyncio.Future(loop=self._loop)
        ret['closing'] = all_closed
        if not ret['ref']:
            all_closed.set_result(None)

        # flag to all blockers that this file is closing
        ret['is_closing'].set_result(None)

        # wait for all files to be dereffed
        yield from all_closed
        assert not ret['ref']
        popped = self._open_files.pop(fid)
        assert popped is ret
        return ret

    @asyncio.coroutine
    def watch_file(self, fid, fs, *n, **kw):
        ret = self._open_files[fid]
        if ret['closing'] is not None: raise KeyError()

        changes_future = asyncio.Future(loop=self._loop)
        stop_new_watch = fs.create_watch(changes_future.set_result, ret['handle'],
                                         *n, **kw)

        ret['ref'] += 1

        (done, pending) = yield from asyncio.wait([changes_future,
                                                   ret['is_closing']],
                                                  return_when=asyncio.FIRST_COMPLETED,
                                                  loop=self._loop)

        assert (fid in self._open_files and
                self._open_files[fid] is ret)

        changes = []
        if changes_future in done:
            changes = changes_future.result()

        ret['ref'] -= 1
        if (ret['closing'] is not None and
            not ret['ref']):
            ret['closing'].set_result(None)

        stop_new_watch()

        return changes

    @classmethod
    @asyncio.coroutine
    def read_message(cls, reader):
        data = yield from reader.read(4)
        # Signal EOF
        if not data: return None
        (length,) = struct.unpack(">I", data)
        return decode_smb_message((yield from reader.read(length)))

    @classmethod
    @asyncio.coroutine
    def send_message(cls, writer, msg):
        if not msg.raw_data:
            msg.raw_data = msg.encode()
        writer.writelines([struct.pack(">I", len(msg.raw_data)),
                           msg.raw_data])

    @asyncio.coroutine
    def run(self, server, backend, loop, reader, writer):
        self._loop = loop

        # first negotiate SMB protocol
        negotiate_req = yield from self.read_message(reader)
        if negotiate_req is None:
            raise Exception("Received client EOF!")

        if negotiate_req.command != smb_structs.SMB_COM_NEGOTIATE:
            raise Exception("Got unexpected request: %s" % (negotiate_req,))

        server_capabilities = (smb_structs.CAP_UNICODE |
                               smb_structs.CAP_LARGE_FILES |
                               smb_structs.CAP_STATUS32 |
                               smb_structs.CAP_NT_SMBS |
                               smb_structs.CAP_NT_FIND)

        # win32 time
        now = datetime.utcnow()
        win32_time = datetime_to_win32(now)
        args = dict(
            # TODO: catch this and throw a friendlier error
            dialect_index=negotiate_req.payload.dialects.index('NT LM 0.12'),
            security_mode=0, # we support NO SECURITY FEATURES
            max_mpx_count=2 ** 16 - 1, # unlimited clients baby
            max_number_vcs=2 ** 16 - 1, # not sure what this means
            max_buffer_size=2 ** 16 - 1, # this doesn't matter
            max_raw_size=2 ** 16 - 1, # this doesn't matter
            session_key=0, # can be anything, we don't use it
            capabilities=server_capabilities,
            system_time=win32_time,
            server_time_zone=0,
            challenge_length=0,
        )
        # Mac OS X client want the same tid/pid/uid back
        args = response_args_from_req(negotiate_req, **args)

        negotiate_resp = smb_structs.SMBMessage(ComNegotiateResponse(**args))
        # TODO: set flags? status?

        yield from self.send_message(writer, negotiate_resp)

        # okay now kick off SMB connection machinery

        @asyncio.coroutine
        def read_client(reader, dead_future, writer_queue):
            read_future = asyncio.async(self.read_message(reader),
                                        loop=loop)
            while True:
                (done, pending) = yield from asyncio.wait([dead_future, read_future],
                                                          return_when=asyncio.FIRST_COMPLETED,
                                                          loop=loop)
                if dead_future in done: break

                if read_future in done:
                    try:
                        msg = read_future.result()
                    except Exception:
                        # not sure what happened but we received invalid data
                        log.exception("Exception during reading socket")
                        break
                    if not msg:
                        log.debug("EOF from client, closing connection")
                        break

                    # kick off concurrent request handler
                    @asyncio.coroutine
                    def real_handle_request(msg):
                        try:
                            ret = yield from handle_request(server, server_capabilities,
                                                            self, backend, msg)
                        except ProtocolError as e:
                            if e.error not in (STATUS_NO_SUCH_FILE,):
                                log.debug("Protocol Error!!! %r %r",
                                          hex(msg.command), e)
                            ret = error_response(msg, e.error)
                        ret.raw_data = ret.encode()
                        yield from writer_queue.put(ret)

                    reqfut = asyncio.async(real_handle_request(msg), loop=loop)
                    def on_fail():
                        dead_future.set_result(None)
                    asyncio.async(cant_fail(on_fail, reqfut), loop=loop)
                    read_future = asyncio.async(self.read_message(reader),
                                                loop=loop)

            # release resources associated with connection
            yield from self.hard_destroy_all_trees(server, backend)

            # we have died, signal to writer coroutine to die as well
            yield from writer_queue.put(None)

        @asyncio.coroutine
        def write_client(writer, queue):
            # TODO: set dead_future on exception
            while True:
                msg = yield from queue.get()
                if msg is None: break
                yield from self.send_message(writer, msg)
            writer.close()

        # NB: dead future is our out-of-band way to signal to the read client
        #     to stop
        dead_future = asyncio.Future(loop=loop)
        writer_queue = asyncio.Queue(loop=loop)

        # start up reader/writer coroutines
        read_client_future = asyncio.async(read_client(reader, dead_future,
                                                       writer_queue),
                                           loop=loop)
        try:
            yield from write_client(writer, writer_queue)
        finally:
            # make sure read client is dead
            (done, pending) = yield from asyncio.wait([read_client_future],
                                                      loop=loop)
            assert len(done) == 1

@asyncio.coroutine
def handle_request(server, server_capabilities, cs, backend, req):
    @asyncio.coroutine
    def smb_path_to_fs_path(path):
        comps = path[1:].split("\\")
        if comps == ['']:
            comps = []
        return (yield from fs.create_path(*comps))

    def normalize_stat(stat):
        class MyEntry(object): pass
        mystat = MyEntry()

        mystat.birthtime = getattr(stat, "birthtime", datetime.utcfromtimestamp(0))
        mystat.mtime = getattr(stat, "mtime", mystat.birthtime)
        mystat.ctime = getattr(stat, "ctime", mystat.mtime)
        mystat.atime = getattr(stat, "atime", mystat.ctime)

        mystat.type = getattr(stat, "type")
        mystat.size = getattr(stat, "size")

        return mystat

    @asyncio.coroutine
    def normalize_dir_entry(entry):
        try:
            normalize_dir_entry.has_attr_cache
        except AttributeError:
            normalize_dir_entry.has_attr_cache = defaultdict(dict)

        need_to_stat = False
        for prop in ["birthtime", "mtime", "ctime", "atime",
                     "type", "size"]:
            if not hasattr(entry, prop):
                # NB: memoize fs.stat_has_attr since it's an expensive call
                try:
                    has_attr = normalize_dir_entry.has_attr_cache[fs][prop]
                except KeyError:
                    has_attr = normalize_dir_entry.has_attr_cache[fs][prop] = (yield from fs.stat_has_attr(prop))
                if has_attr:
                    need_to_stat = True
                    break

        to_normalize = entry
        if need_to_stat:
            to_normalize = yield from fs.stat(path / entry.name)

        return normalize_stat(to_normalize)

    if req.command == smb_structs.SMB_COM_SESSION_SETUP_ANDX:
        if req.payload.capabilities & ~server_capabilities:
            log.warning("Client's capabilities aren't a subset of Server's: 0x%x vs 0x%x",
                        req.payload.capabilities, server_capabilities)

        uid = yield from cs.create_session()

        args = response_args_from_req(req,
                                      action=1,
                                      domain=req.payload.domain)
        args['uid'] = uid
        return SMBMessage(ComSessionSetupAndxResponse(**args))
    elif req.command == smb_structs.SMB_COM_TREE_CONNECT_ANDX:
        yield from cs.verify_uid(req)

        if req.payload.flags & TREE_CONNECT_ANDX_DISCONNECT_TID:
            try:
                fs = yield from cs.destroy_tree(req.tid)
            except KeyError:
                # NB: this is allowed to fail silently
                pass
            else:
                yield from backend.tree_disconnect(server, fs)

        if req.payload.service not in ("?????", "A:"):
            log.debug("Client attempted to connect to %r service",
                      req.payload.service)
            raise ProtocolError(STATUS_OBJECT_PATH_NOT_FOUND)

        try:
            fs = yield from backend.tree_connect(server, req.payload.path)
        except KeyError:
            log.debug("Error tree connect: %r", req.payload.path)
            raise ProtocolError(STATUS_OBJECT_PATH_NOT_FOUND)

        tid = yield from cs.create_tree(fs)

        args = response_args_from_req(req,
                                      optional_support=smb_structs.SMB_TREE_CONNECTX_SUPPORT_SEARCH,
                                      service="A:",
                                      native_file_system="FAT")
        args['tid'] = tid
        return SMBMessage(ComTreeConnectAndxResponse(**args))
    elif req.command == SMB_COM_TREE_DISCONNECT:
        yield from cs.verify_uid(req)

        try:
            fs = yield from cs.destroy_tree(req.tid)
        except KeyError:
            raise ProtocolError(STATUS_SMB_BAD_TID)

        yield from backend.tree_disconnect(server, fs)

        args = response_args_from_req(req)

        return SMBMessage(ComTreeDisconnectResponse(**args))
    elif req.command == SMB_COM_CHECK_DIRECTORY:
        yield from cs.verify_uid(req)
        fs = yield from cs.verify_tid(req)
        try:
            fspath = yield from smb_path_to_fs_path(req.payload.filename)

            try:
                stat = yield from fs.stat(fspath)
            except FileNotFoundError:
                raise ProtocolError(STATUS_NO_SUCH_FILE)
            except NotADirectoryError:
                raise ProtocolError(STATUS_OBJECT_PATH_NOT_FOUND)
            except PermissionError:
                raise ProtocolError(STATUS_ACCESS_DENIED)

            if stat.type != 'directory':
                raise ProtocolError(STATUS_NOT_A_DIRECTORY)

            args = response_args_from_req(req)
            return SMBMessage(ComCheckDirectoryResponse(**args))
        finally:
            yield from cs.deref_tid(req.tid)
    elif req.command == smb_structs.SMB_COM_ECHO:
        log.debug("echo...")
        if req.payload.echo_count > 1:
            raise Exception("Echo count is too high: %r" %
                            (req.payload.echo_count,))

        args = response_args_from_req(req,
                                      sequence_number=0,
                                      data=req.payload.echo_data)
        return SMBMessage(ComEchoResponse(**args))
    elif req.command == smb_structs.SMB_COM_TRANSACTION2:
        yield from cs.verify_uid(req)
        fs = yield from cs.verify_tid(req)
        try:
            if len(req.payload.setup_bytes) % 2:
                raise Exception("bad setup bytes length!")
            setup = struct.unpack("<%dH" % (len(req.payload.setup_bytes) / 2,),
                                  req.payload.setup_bytes)

            if req.payload.timeout:
                raise Exception("Transaction2 Delayed request not supported!")

            if (req.payload.total_params_count != len(req.payload.params_bytes) or
                req.payload.total_data_count != len(req.payload.data_bytes)):
                raise Exception("Multiple TRANSACTION2 packets not supported!")

            if req.payload.flags:
                # NBL we don't current support DISCONNECT_TID nor NO_RESPONSE
                raise Exception("Transaction 2 flags not supported!")

            @asyncio.coroutine
            def generate_find_data(max_data, search_count, handle,
                                   info_generator, idx,
                                   entry, next_entry,
                                   buffered_entries, buffered_entries_idx):
                @asyncio.coroutine
                def get_next_entry():
                    nonlocal buffered_entries_idx, buffered_entries
                    try:
                        toret = buffered_entries[buffered_entries_idx]
                    except IndexError:
                        buffered_entries = []
                        buffered_entries_idx = 0

                        if handle is not None:
                            # NB: 512 is roughly a single FIND_{FIRST,NEXT}2 request
                            for ent in (yield from handle.readmany(512)):
                                buffered_entries.append((ent.name, (yield from normalize_dir_entry(ent))))

                        if not buffered_entries:
                            return None

                        toret = buffered_entries[buffered_entries_idx]
                    buffered_entries_idx += 1
                    return toret

                num_entries_to_ret = 0
                offset = 0
                data = []

                # XXX: what's the right index to use here?
                for i in range(idx, idx + search_count):
                    if entry is None:
                        break

                    (name, md) = entry

                    is_last = next_entry is None

                    bufs = info_generator(i, offset, flags, name, md, is_last)
                    new_data_len = sum(map(len, bufs))
                    if new_data_len + offset > max_data:
                        break

                    data.extend(bufs)
                    offset += new_data_len
                    num_entries_to_ret += 1

                    entry = next_entry
                    next_entry = yield from get_next_entry()

                return (data, num_entries_to_ret,
                        entry, next_entry,
                        buffered_entries, buffered_entries_idx)

            # go through another layer of parsing
            if setup[0] == SMB_TRANS2_FIND_FIRST2:
                fmt = "<HHHHI"
                fmt_size = struct.calcsize(fmt)
                (search_attributes, search_count,
                 flags, information_level,
                 search_storage_type) = struct.unpack("<HHHHI", req.payload.params_bytes[:fmt_size])
                filename = req.payload.params_bytes[fmt_size:].decode("utf-16-le")[:-1]

                try:
                    info_generator = INFO_GENERATORS[information_level]
                except KeyError:
                    raise ProtocolError(STATUS_OS2_INVALID_LEVEL,
                                        "Find First Information level not supported: %r" %
                                        (information_level,))

                if filename == "\\":
                    is_directory_search = False
                else:
                    comps = filename[1:].split("\\")
                    for c in comps[:-1]:
                        if '*' in c or '?' in c:
                            raise Exception("unsupported search path: %r" % (filename,))

                    if '*' in comps[-1] and comps[-1] not in ["*", "*.*", ""]:
                        raise Exception("unsupported search path: %r" % (filename,))

                    is_directory_search = comps[-1] in ["*", "*.*", ""]
                    if is_directory_search:
                        comps = comps[:-1]

                path = yield from fs.create_path(*comps)
                try:
                    if is_directory_search:
                        handle = yield from fs.open_directory(path)

                        class Dir(object):
                            def __init__(self):
                                self.type = "directory"
                                self.size = 0

                        entry = (".", normalize_stat(Dir()))
                        next_entry = ("..", normalize_stat(Dir()))
                        buffered_entries = []
                        buffered_entries_idx = 0
                    else:
                        handle = None
                        stat = yield from fs.stat(path)
                        entry = (path.name, normalize_stat(stat))
                        next_entry = None
                        buffered_entries = []
                        buffered_entries_idx = 0
                except FileNotFoundError:
                    raise ProtocolError(STATUS_NO_SUCH_FILE)

                (data, num_entries_to_ret, entry, next_entry,
                 buffered_entries, buffered_entries_idx) = \
                    yield from generate_find_data(req.payload.max_data_count,
                                                  search_count,
                                                  handle,
                                                  info_generator, 0,
                                                  entry, next_entry,
                                                  buffered_entries, buffered_entries_idx)

                is_search_over = next_entry is None

                if (is_search_over and flags & SMB_FIND_CLOSE_AT_EOS or
                    flags & SMB_FIND_CLOSE_AFTER_REQUEST):
                    if handle is not None:
                        yield from handle.close()
                        handle = None
                    sid = 0
                    is_search_over = True
                else:
                    sid = yield from cs.create_search(handle=handle,
                                                      entry=entry,
                                                      next_entry=next_entry,
                                                      buffered_entries=buffered_entries,
                                                      buffered_entries_idx=buffered_entries_idx,
                                                      idx=num_entries_to_ret,
                                                      tid=req.tid)

                data_bytes = b''.join(data)
                last_name_offset = (0
                                    if is_search_over else
                                    len(data_bytes) - len(data[-1]))

                assert information_level != SMB_INFO_QUERY_EAS_FROM_LIST
                ea_error_offset = 0

                setup_bytes = b''
                params_bytes = struct.pack("<HHHHH",
                                           sid, num_entries_to_ret,
                                           int(is_search_over),
                                           ea_error_offset,
                                           0 if is_search_over else
                                           last_name_offset)
            elif setup[0] == SMB_TRANS2_FIND_NEXT2:
                fmt = "<HHHIH"
                fmt_size = struct.calcsize(fmt)
                (sid, search_count, information_level,
                 resume_key, flags) = stuff = struct.unpack(fmt, req.payload.params_bytes[:fmt_size])
                filename = req.payload.params_bytes[fmt_size:].decode("utf-16-le")[:-1]

                try:
                    info_generator = INFO_GENERATORS[information_level]
                except KeyError:
                    raise ProtocolError(STATUS_OS2_INVALID_LEVEL,
                                        "Find First Information level not supported: %r" %
                                        (information_level,))


                search_md = yield from cs.ref_search(sid)

                (data, num_entries_to_ret,
                 entry, next_entry,
                 search_md['buffered_entries'], search_md['buffered_entries_idx']) = \
                    yield from generate_find_data(req.payload.max_data_count,
                                                  search_count,
                                                  search_md['handle'],
                                                  info_generator,
                                                  search_md['idx'],
                                                  search_md['entry'],
                                                  search_md['next_entry'],
                                                  search_md['buffered_entries'],
                                                  search_md['buffered_entries_idx'])

                search_md['idx'] += num_entries_to_ret
                search_md['entry'] = entry
                search_md['next_entry'] = next_entry

                is_search_over = next_entry is None

                if (is_search_over and flags & SMB_FIND_CLOSE_AFTER_REQUEST or
                    flags & SMB_FIND_CLOSE_AFTER_REQUEST):
                    if search_md['handle'] is not None:
                        yield from search_md['handle'].close()
                        search_md['handle'] = None
                    yield from cs.deref_search(sid)
                    yield from cs.destroy_search(sid)
                    is_search_over = True
                else:
                    yield from cs.deref_search(sid)

                data_bytes = b''.join(data)
                last_name_offset = (0
                                    if is_search_over else
                                    len(data_bytes) - len(data[-1]))

                assert information_level != SMB_INFO_QUERY_EAS_FROM_LIST
                ea_error_offset = 0

                setup_bytes = b''
                params_bytes = struct.pack("<HHHH",
                                           num_entries_to_ret,
                                           int(is_search_over),
                                           ea_error_offset,
                                           last_name_offset)
            elif setup[0] == SMB_TRANS2_QUERY_FS_INFORMATION:
                if req.payload.flags:
                    raise Exception("Transaction 2 flags not supported!")

                fmt = "<H"
                fmt_size = struct.calcsize(fmt)
                (information_level,) = struct.unpack(fmt, req.payload.params_bytes[:fmt_size])

                try:
                    fs_info_generator = FS_INFO_GENERATORS[information_level]
                except KeyError:
                    raise ProtocolError(STATUS_OS2_INVALID_LEVEL,
                                        "QUERY FS Information level not supported: %r" %
                                        (information_level,))

                data_bytes = fs_info_generator()

                setup_bytes = b''
                params_bytes = b''
            elif setup[0] == SMB_TRANS2_QUERY_PATH_INFORMATION:
                if req.payload.flags:
                    raise Exception("Transaction 2 flags not supported!")

                (information_level,) = struct.unpack("<H",
                                                     req.payload.params_bytes[:2])

                try:
                    query_path_info_generator = QUERY_FILE_INFO_GENERATORS[information_level]
                except KeyError:
                    raise ProtocolError(STATUS_OS2_INVALID_LEVEL,
                                        "QUERY PATH Information level not supported: %r" %
                                        (information_level,))

                path = req.payload.params_bytes[6:].decode("utf-16-le").rstrip("\0")
                fspath = yield from smb_path_to_fs_path(path)

                try:
                    md = yield from fs.stat(fspath)
                except OSError as e:
                    raise ProtocolError(STATUS_NO_SUCH_FILE)

                setup_bytes = b''
                name = fspath.name if fspath.name else '\\'
                (ea_error_offset, data_bytes) = query_path_info_generator(name, normalize_stat(md))
                params_bytes = struct.pack("<H", ea_error_offset)
            else:
                log.warning("TRANS2 Sub command not supported: %02x, %s" % (setup[0], req))
                raise ProtocolError(STATUS_NOT_SUPPORTED)

            assert len(setup_bytes) <= req.payload.max_setup_count, "TRANSACTION2 setup bytes count is too large %r vs required %r" % (len(setup_bytes), req.payload.max_setup_count)
            assert len(params_bytes) <= req.payload.max_params_count, "TRANSACTION2 params bytes count is too large %r vs required %r" % (len(params_bytes), req.payload.max_params_count)
            assert len(params_bytes) <= req.payload.max_data_count, "TRANSACTION2 data bytes count is too large %r vs required %r" % (len(params_bytes), req.payload.max_data_count)

            args = response_args_from_req(req,
                                          setup_bytes=setup_bytes,
                                          params_bytes=params_bytes,
                                          data_bytes=data_bytes)
            return SMBMessage(ComTransaction2Response(**args))
        finally:
            yield from cs.deref_tid(req.tid)
    elif req.command == SMB_COM_QUERY_INFORMATION_DISK:
        yield from cs.verify_uid(req)
        fs = yield from cs.verify_tid(req)
        try:
            args = response_args_from_req(req,
                                          total_units=2 ** 16 - 1,
                                          blocks_per_unit=16384,
                                          block_size=512,
                                          free_units=0
            )
            return SMBMessage(ComQueryInformationDiskResponse(**args))
        finally:
            yield from cs.deref_tid(req.tid)
    elif req.command == smb_structs.SMB_COM_NT_CREATE_ANDX:
        request = req.payload

        yield from cs.verify_uid(req)
        fs = yield from cs.verify_tid(req)
        try:
            if (request.flags &
                (
                 NT_CREATE_OPEN_TARGET_DIR)):
                raise Exception("SMB_COM_NT_CREATE_ANDX doesn't support flags! 0x%x" % (request.flags,))

            if (request.access_mask &
                (FILE_WRITE_DATA | FILE_APPEND_DATA |
                 FILE_WRITE_EA | FILE_WRITE_ATTRIBUTES |
                 DELETE | WRITE_DAC | WRITE_OWNER |
                 ACCESS_SYSTEM_SECURITY |
                 GENERIC_ALL | GENERIC_WRITE)):
                # Don't allow write access
                # TODO: allow write access when we have an actual backend
                raise ProtocolError(STATUS_ACCESS_DENIED)

            if request.create_disp != FILE_OPEN:
                raise ProtocolError(STATUS_ACCESS_DENIED)

            if request.create_options & FILE_DELETE_ON_CLOSE:
                raise ProtocolError(STATUS_ACCESS_DENIED)

            if request.create_options & FILE_OPEN_BY_FILE_ID:
                raise ProtocolError(STATUS_NOT_SUPPORTED)

            if request.root_fid:
                try:
                    root_md = yield from cs.ref_file(request.root_fid)
                except KeyError:
                    raise ProtocolError(STATUS_INVALID_HANDLE)
                root_path = root_md['path']
                yield from cs.deref_file(request.root_fid)
            else:
                root_path = ""

            file_path = root_path + request.filename

            is_sharing = request.share_access & FILE_SHARE_READ

            # verify share access
            # find other files
            yield from cs.verify_share(file_path, is_sharing)

            is_directory = False
            path = yield from smb_path_to_fs_path(file_path)
            try:
                handle = yield from fs.open(path)
                # TODO: dbfs currently doesn't return FileNotFoundError
                #       on open, so we have to fstat in this try-except-block
                md = yield from fs.fstat(handle)
            except FileNotFoundError:
                raise ProtocolError(STATUS_NO_SUCH_FILE)

            is_directory = md.type == "directory"

            if (is_directory and
                request.create_options & FILE_NON_DIRECTORY_FILE):
                handle.close()
                raise ProtocolError(STATUS_FILE_IS_A_DIRECTORY)

            fid = yield from cs.create_file(file_path,
                                            is_sharing, handle,
                                            req.tid)

            now = datetime.now()
            directory = int(is_directory)
            ext_attr = (ATTR_DIRECTORY
                        if directory else
                        ATTR_NORMAL)

            file_data_size = get_size(md)

            FILE_TYPE_DISK = 0

            md2 = normalize_stat(md)

            log.debug("Opening file_path: %r, %r", file_path, fid)

            args = response_args_from_req(req,
                                          op_lock_level=0,
                                          fid=fid,
                                          create_disp=request.create_disp,
                                          create_time=datetime_to_win32(md2.birthtime),
                                          last_access_time=datetime_to_win32(md2.atime),
                                          last_write_time=datetime_to_win32(md2.mtime),
                                          last_change_time=datetime_to_win32(md2.ctime),
                                          ext_attr=ext_attr,
                                          allocation_size=4096,
                                          end_of_file=file_data_size,
                                          resource_type=FILE_TYPE_DISK,
                                          nm_pipe_status=0,
                                          directory=directory)
            return SMBMessage(ComNTCreateAndxResponse(**args))
        finally:
            yield from cs.deref_tid(req.tid)
    elif req.command == smb_structs.SMB_COM_READ_ANDX:
        request = req.payload
        yield from cs.verify_uid(req)
        fs = yield from cs.verify_tid(req)
        try:
            log.debug("About to read file... %r", request.fid)

            try:
                fid_md = yield from cs.ref_file(request.fid)
            except KeyError:
                raise ProtocolError(STATUS_INVALID_HANDLE)

            log.debug("About to do pread... %r, offset: %r, amt: %r",
                      fid_md['path'], request.offset, request.max_return_bytes_count)

            buf = yield from fid_md['handle'].pread(request.offset, request.max_return_bytes_count)

            log.debug("PREAD DONE... %r buf len: %r", fid_md['path'], len(buf))

            yield from cs.deref_file(request.fid)

            args = response_args_from_req(req, data=buf)
            return SMBMessage(ComReadAndxResponse(**args))
        finally:
            yield from cs.deref_tid(req.tid)
    elif req.command == smb_structs.SMB_COM_CLOSE:
        request = req.payload
        yield from cs.verify_uid(req)
        fs = yield from cs.verify_tid(req)
        try:
            log.debug("CLOSE FILE... %r", request.fid)

            try:
                fidmd = yield from cs.destroy_file(request.fid)
                assert 'handle' in fidmd
            except KeyError:
                raise ProtocolError(STATUS_INVALID_HANDLE)

            # Close asynchronously
            def on_fail():
                log.warning("Closing %r failed!", fidmd['handle'])
            asyncio.async(cant_fail(on_fail, fidmd['handle'].close()),
                          loop=cs._loop)

            log.debug("CLose done! %r", request.fid)

            args = response_args_from_req(req)
            return SMBMessage(ComCloseResponse(**args))
        finally:
            yield from cs.deref_tid(req.tid)
    elif req.command == smb_structs.SMB_COM_NT_TRANSACT:
        yield from cs.verify_uid(req)
        fs = yield from cs.verify_tid(req)
        try:
            nt_transact = req.payload

            assert not (len(nt_transact.setup_bytes) % 2),\
                "bad setup bytes length!"

            if nt_transact.function == NT_TRANSACT_NOTIFY_CHANGE:
                fmt = "<LH?"
                fmt_size = struct.calcsize(fmt)
                (completion_filter, fid, watch_tree) = struct.unpack(fmt,
                                                                     nt_transact.setup_bytes[:fmt_size])

                log.debug("COMPLETION_FILTER: %x", completion_filter)
                log.debug("FID: %r", fid)
                log.debug("WATCH_TREE: %r", watch_tree)

                try:
                    changes = yield from cs.watch_file(fid, fs, completion_filter, watch_tree)
                except KeyError:
                    raise ProtocolError(STATUS_INVALID_HANDLE)

                log.debug("CHANGES: %r %r", fid, changes)

                if changes == 'reset':
                    raise ProtocolError(STATUS_NOTIFY_ENUM_DIR)

                buf = []
                curoffset = 0
                for (idx, change) in enumerate(changes):
                    if curoffset % 4:
                        buf.append(b'\0' * (4 - curoffset % 4))
                        curoffset += len(buf[-1])
                    action = {"added": FILE_ACTION_ADDED,
                              "removed": FILE_ACTION_REMOVED,
                              "modified": FILE_ACTION_MODIFIED,
                              "renamed_from": FILE_ACTION_RENAMED_OLD_NAME,
                              "renamed_to": FILE_ACTION_RENAMED_NEW_NAME,}[change.action]

                    filename_encoded = change.path.name.encode("utf-16-le")
                    potential_next_entry_offset = 4 + 4 + 4 + len(filename_encoded)
                    if potential_next_entry_offset % 4:
                        potential_next_entry_offset += 4 - potential_next_entry_offset % 4
                    next_entry_offset = (potential_next_entry_offset
                                         if idx != len(changes) - 1 else
                                         0)
                    buf.append(struct.pack("<III", next_entry_offset, action,
                                           len(filename_encoded)))
                    curoffset += len(buf[-1])
                    buf.append(filename_encoded)
                    curoffset += len(buf[-1])

                param_bytes = b''.join(buf)

                args = response_args_from_req(req,
                                              total_params_count=len(param_bytes),
                                              total_data_count=0,
                                              params_bytes=param_bytes,
                                              data_bytes=b'',
                                              setup_bytes=b'',
                                              )
                return SMBMessage(ComNTTransactResponse(**args))
        finally:
            yield from cs.deref_tid(req.tid)

    log.debug("%s", req)
    raise ProtocolError(STATUS_NOT_SUPPORTED)

def set_fd_non_blocking(fd, val):
    fl = fcntl.fcntl(fd, fcntl.F_GETFL)
    if val:
        fl = fl | os.O_NONBLOCK
    else:
        fl = fl & ~os.O_NONBLOCK
    fcntl.fcntl(fd, fcntl.F_SETFL, fl)

class AsyncWorkerPool(object):
    def __init__(self, loop, size=1):
        self.loop = loop
        self.executor = ThreadPoolExecutor(None if size < 0 else size)

    @asyncio.coroutine
    def run_async(self, f, *n, **kw):
        f = functools.partial(f, *n, **kw)
        fut = self.loop.run_in_executor(self.executor, f)
        return (yield from fut)

    def close(self):
        self.executor.shutdown(wait=False)

class AsyncWrapped(object):
    def __init__(self, obj, worker_pool):
        self._obj = obj
        self._worker_pool = worker_pool

    @asyncio.coroutine
    def _run_method(self, name, *n, **kw):
        return (yield from self._worker_pool.run_async(getattr(self._obj, name),
                                                       *n, **kw))

    def __getattr__(self, name):
        @asyncio.coroutine
        def fn(*n, **kw):
            return (yield from self._run_method(name, *n, **kw))
        return fn

class AsyncFS(AsyncWrapped):
    @asyncio.coroutine
    def fstat(self, handle):
        # NB: we have to unwrap the async handle
        return (yield from self._worker_pool.run_async(self._obj.fstat,
                                                       handle._obj))

    def create_watch(self, cb, dir_handle, *n, **kw):
        is_stopped = [False]

        def on_main(changes):
            if is_stopped[0]: return
            return cb(changes)

        def wrapped_cb(changes):
            self._worker_pool.loop.call_soon_threadsafe(functools.partial(on_main, changes))

        stop = self._obj.create_watch(wrapped_cb, dir_handle._obj, *n, **kw)

        def wrapped_stop():
            is_stopped[0] = True
            return stop()

        return wrapped_stop

    def __getattr__(self, name):
        @asyncio.coroutine
        def fn(*n, **kw):
            ret = yield from self._worker_pool.run_async(getattr(self._obj, name),
                                                         *n, **kw)
            if name in ("open_directory", "open"):
                ret = AsyncWrapped(ret, self._worker_pool)
            return ret
        return fn

class AsyncBackend(AsyncWrapped):
    @asyncio.coroutine
    def tree_connect(self, *n, **kw):
        fs = yield from (self._run_method('tree_connect', *n, **kw))
        return AsyncFS(fs, self._worker_pool)

    @asyncio.coroutine
    def tree_disconnect(self, server, fs):
        # unwraps the real fs out of fs
        return (yield from(self._run_method('tree_disconnect', server, fs._obj)))

# SMBServer abstracts away the fact that it is implemented using
# asyncio. It expects to be used in normal python code.
class SMBServer(object):
    def __init__(self, backend, address=None,sock=None):
        if address is None:
            address = (None, None)

        self._loop = asyncio.new_event_loop()

        self._worker_pool = AsyncWorkerPool(self._loop, 8)

        async_backend = AsyncBackend(backend, self._worker_pool)

        @asyncio.coroutine
        def handle_client(reader, writer):
            yield from SMBClientHandler().run(self, async_backend, self._loop,
                                              reader, writer)
            log.debug("client done!")

        start_server_coro = asyncio.start_server(handle_client,
                                                 host=address[0], port=address[1],
                                                 sock=sock,
                                                 loop=self._loop)
        self._server = self._loop.run_until_complete(start_server_coro)

        self._server_done = asyncio.Future(loop=self._loop)

        # NB: due to a quirk in asyncio, we need to call wait_closed()
        #     before any connections are made so that it waits for all
        #     open client connections to close before returning after close()
        #     is called
        @asyncio.coroutine
        def _on_close():
            yield from self._server.wait_closed()
            self._worker_pool.close()
            self._server_done.set_result(None)

        asyncio.async(_on_close(), loop=self._loop)

    def close(self):
        @asyncio.coroutine
        def _on_main_thread():
            self._server.close()
        asyncio.run_coroutine_threadsafe(_on_main_thread(), self._loop)

    def run(self):
        self._loop.run_until_complete(self._server_done)

def main(argv):
    logging.basicConfig(level=logging.DEBUG)

    # This runtime import is okay because it happens in main()
    from dropboxfs.memoryfs import FileSystem as MemoryFileSystem

    fs = MemoryFileSystem([("foo", {"type": "directory",
                                    "children" : [
                                        ("baz", {"type": "file", "data": b"YOOOO"}),
                                        ("quux", {"type": "directory"}),
                                    ]
    }),
                           ("bar", {"type": "file", "data": b"f"})])

    with contextlib.closing(SMBServer(('0.0.0.0', 8888), fs)) as server:
        server.run()

if __name__ == "__main__":
    sys.exit(main(sys.argv))
