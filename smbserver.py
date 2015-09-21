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

import os
import logging
import random
import socketserver
import struct
import sys
import time

from datetime import datetime
from io import StringIO

# hack smb struct defs from PySMB
import smb.smb_structs as smb_structs

log = logging.getLogger(__name__)

SMB_COM_QUERY_INFORMATION_DISK = 0x80

class SMBMessage(smb_structs.SMBMessage):
    # NB: default _decodePayload() assumes responses from servers
    # since we are the server, we assume requests
    def _decodePayload(self):
        if self.isReply: return super()._decodePayload();

        if self.command == smb_structs.SMB_COM_READ_ANDX:
            self.payload = smb_structs.ComReadAndxRequest()
        elif self.command == smb_structs.SMB_COM_WRITE_ANDX:
            self.payload = smb_structs.ComWriteAndxRequest()
        elif self.command == smb_structs.SMB_COM_TRANSACTION:
            self.payload = smb_structs.ComTransactionRequest()
        elif self.command == smb_structs.SMB_COM_TRANSACTION2:
            self.payload = ComTransaction2Request()
        elif self.command == smb_structs.SMB_COM_OPEN_ANDX:
            self.payload = smb_structs.ComOpenAndxRequest()
        elif self.command == smb_structs.SMB_COM_NT_CREATE_ANDX:
            self.payload = smb_structs.ComNTCreateAndxRequest()
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
        if next_offset % 2: s = next_offset + 1
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

        message.parameters_data = struct.pack(self.PAYLOAD_STRUCT_FORMAT,
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
         session_key, length1, length2, reserved, capabilities) = params_o =struct.unpack(self.PAYLOAD_STRUCT_FORMAT, params)


        is_unicode = message.flags2 & smb_structs.SMB_FLAGS2_UNICODE
        if not is_unicode: raise Exception("Only support unicode!")

        case_insensitive_password = message.data[:length1].rstrip(b'\0').decode("ascii")
        case_sensitive_password = message.data[length1:length1 + length2].rstrip(b'\0').decode("ascii")

        # read padding
        raw_offset = (SMBMessage.HEADER_STRUCT_SIZE + len(message.parameters_data) + 2 +
                      length1 + length2)
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

        self.password = (case_insensitive_password or case_sensitive_password)
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

        (flags, password_len) = struct.unpack(self.PAYLOAD_STRUCT_FORMAT,
                                              message.parameters_data[self.DEFAULT_ANDX_PARAM_SIZE:self.PAYLOAD_STRUCT_SIZE + self.DEFAULT_ANDX_PARAM_SIZE])

        self.password = message.data[:password_len].rstrip(b'\0').decode("utf-8")

        raw_offset = (SMBMessage.HEADER_STRUCT_SIZE + len(message.parameters_data) +
                      2 + password_len)
        if raw_offset % 2:
            if message.data[raw_offset] != 0:
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

def response_args_from_req(req, **kw):
    return dict(pid=req.pid, tid=req.tid,
                uid=req.uid, mid=req.mid, **kw)

STATUS_NOT_FOUND = 0xc0000225
STATUS_SMB_BAD_COMMAND = 0x160002

SMB_TRANS2_FIND_FIRST2 = 0x1
SMB_TRANS2_QUERY_FS_INFORMATION = 0x3
SMB_TRANS2_QUERY_PATH_INFORMATION = 0x5
SMB_INFO_STANDARD = 0x1
SMB_FIND_FILE_BOTH_DIRECTORY_INFO = 0x104
SMB_FIND_RETURN_RESUME_KEYS = 0x4
SMB_FIND_CLOSE_AT_EOS = 0x2
ATTR_DIRECTORY = 0x10
SMB_QUERY_FS_SIZE_INFO = 0x103
SMB_QUERY_FS_ATTRIBUTE_INFO = 0x105
SMB_QUERY_FILE_ALL_INFO = 0x107

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
    return (int(dt.timestamp()) + 11644473600) * 10000000

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

    (creation_date, creation_time) = encode_smb_datetime(datetime.now())
    (last_access_date, last_access_time) = encode_smb_datetime(datetime.now())
    (last_write_date, last_write_time) = encode_smb_datetime(datetime.now())

    if md["type"] == "directory":
        file_data_size = 0
    else:
        assert md["type"] == "file"
        file_data_size = md["size"]

    allocation_size = 4096
    attributes = (0 |
                  (ATTR_DIRECTORY if md["type"] == "directory" else 0))

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

def generate_find_file_both_directory_info(idx, offset, flags, name, md, is_last):
    fmt = "<IIQQQQQQIIIBB"

    encoded_file_name = (name + "\0").encode("utf-16-le")
    fmt_size = struct.calcsize(fmt)
    SHORT_NAME_SIZE = 24

    next_entry_offset = (0
                         if is_last else
                         fmt_size + SHORT_NAME_SIZE + len(encoded_file_name))

    now = datetime.now()

    if md["type"] == "directory":
        file_data_size = 0
    else:
        assert md["type"] == "file"
        file_data_size = md["size"]

    allocation_size = 4096
    ext_file_attributes = (ATTR_DIRECTORY if md["type"] == "directory" else 0)
    ea_size = 0

    buf = struct.pack(fmt, next_entry_offset, 0,
                      datetime_to_win32(now),
                      datetime_to_win32(now),
                      datetime_to_win32(now),
                      datetime_to_win32(now),
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
    SMB_FIND_FILE_BOTH_DIRECTORY_INFO: generate_find_file_both_directory_info,
}

def generate_fs_size_info():
    return struct.pack("<QQII",
                       2 ** 64 - 1, # total allocation units
                       0, # total free allocation units
                       16384, # sectors per allocation unit
                       512, # bytes per sector
                       )

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
    SMB_QUERY_FS_ATTRIBUTE_INFO: generate_fs_attribute_info,
}

def generate_query_file_all_info(path, md):
    dt = datetime.now()
    creation_time = datetime_to_win32(dt)
    last_access_time = datetime_to_win32(dt)
    last_write_time = datetime_to_win32(dt)
    last_change_time = datetime_to_win32(dt)
    ext_file_attributes = (ATTR_DIRECTORY if md["type"] == "directory" else 0)
    allocation_size = 4096

    if md["type"] == "directory":
        file_data_size = 0
    else:
        assert md["type"] == "file"
        file_data_size = md["size"]

    reserved = 0

    number_of_links = 1
    delete_pending = 0
    directory = int(md["type"] == "directory")

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

class SMBClientHandler(socketserver.BaseRequestHandler):
    def read_message(self):
        data = self.request.recv(4)
        (length,) = struct.unpack(">I", data)
        return decode_smb_message(recv_all(self.request, length))

    def send_message(self, msg):
        msg.raw_data = msg.encode()
        self.request.sendall(struct.pack(">I", len(msg.raw_data)) + msg.raw_data)

    def handle(self):
        negotiate_req = self.read_message()
        if negotiate_req.command != smb_structs.SMB_COM_NEGOTIATE:
            raise Exception("Got unexpected request: %s" % (negotiate_req,))

        server_capabilities = (smb_structs.CAP_UNICODE |
                               smb_structs.CAP_LARGE_FILES |
                               smb_structs.CAP_STATUS32 |
                               smb_structs.CAP_NT_SMBS |
                               smb_structs.CAP_NT_FIND)

        # win32 time
        now = datetime.now()
        win32_time = datetime_to_win32(now)
        utc_offset = int(-(now -
                           datetime.utcfromtimestamp(now.timestamp())).total_seconds() / 60)
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
            server_time_zone=utc_offset,
            challenge_length=0,
        )
        # Mac OS X client want the same tid/pid/uid back
        args = response_args_from_req(negotiate_req, **args)

        negotiate_resp = smb_structs.SMBMessage(ComNegotiateResponse(**args))
        # TODO: set flags? status?

        self.send_message(negotiate_resp)

        session_setup_andx_req = self.read_message()
        if session_setup_andx_req.command != smb_structs.SMB_COM_SESSION_SETUP_ANDX:
            raise Exception("Got unexpected request: %s" % (session_setup_andx_req,))

        if session_setup_andx_req.payload.capabilities & ~server_capabilities:
            raise Exception("Client sent capabilities outside of the server posted caps")

        args = response_args_from_req(session_setup_andx_req,
                                      action=1,
                                      domain=session_setup_andx_req.payload.domain)
        session_setup_andx_resp = SMBMessage(ComSessionSetupAndxResponse(**args))
        self.send_message(session_setup_andx_resp)

        tree_connect_andx_req = self.read_message()
        if tree_connect_andx_req.command != smb_structs.SMB_COM_TREE_CONNECT_ANDX:
            raise Exception("Got unexpected request: %s" % (session_setup_andx_req,))

        if tree_connect_andx_req.payload.service not in ("?????", "A:"):
            raise Exception("We don't provide the requested service: %s" %
                            (tree_connect_andx_req.payload.service,))

        args = response_args_from_req(tree_connect_andx_req,
                                      optional_support=smb_structs.SMB_TREE_CONNECTX_SUPPORT_SEARCH,
                                      service="A:",
                                      native_file_system="FAT")
        self.send_message(SMBMessage(ComTreeConnectAndxResponse(**args)))

        entries = [("foo", {"type": "directory"}),
                   ("bar", {"type": "file", "size": 1})]
        open_find_trans = {}
        while True:
            req = self.read_message()

            if req.command == smb_structs.SMB_COM_ECHO:
                log.debug("echo...")
                if req.payload.echo_count > 1:
                    raise Exception("Echo count is too high: %r" %
                                    (req.payload.echo_count,))

                args = response_args_from_req(req,
                                              sequence_number=0,
                                              data=req.payload.echo_data)
                self.send_message(SMBMessage(ComEchoResponse(**args)))
            elif req.command == smb_structs.SMB_COM_TRANSACTION2:
                if len(req.payload.setup_bytes) % 2:
                    raise Exception("bad setup bytes length!")
                setup = struct.unpack("<%dH" % (len(req.payload.setup_bytes) / 2,),
                                      req.payload.setup_bytes)

                if req.payload.timeout:
                    raise Exception("Transaction2 Delayed request not supported!")

                # go through another layer of parsing
                if setup[0] == SMB_TRANS2_FIND_FIRST2:
                    if req.payload.flags:
                        raise Exception("Transaction 2 flags not supported!")

                    fmt = "<HHHHI"
                    fmt_size = struct.calcsize(fmt)
                    (search_attributes, search_count,
                     flags, information_level,
                     search_storage_type) = struct.unpack("<HHHHI", req.payload.params_bytes[:fmt_size])
                    filename = req.payload.params_bytes[fmt_size:].decode("utf-16-le")[:-1]

                    try:
                        info_generator = INFO_GENERATORS[information_level]
                    except KeyError:
                        raise Exception("Find First Information level not supported: %r" % (information_level,))

                    # todo: actually implement this
                    #       for now just send "foo" and "bar"
                    entries_offset = 0
                    num_entries_to_ret = min(len(entries) - entries_offset, search_count)

                    entries_to_ret = entries[entries_offset:entries_offset + num_entries_to_ret]


                    sid = random.randint(0, 2 ** 16)
                    while sid in open_find_trans or sid == 0xffff:
                        sid = random.randint(0, 2 ** 16)

                    is_search_over = entries_offset + num_entries_to_ret == len(entries)

                    assert len(open_find_trans) <= 2 ** 16
                    if not (is_search_over and flags & SMB_FIND_CLOSE_AT_EOS):
                        if len(open_find_trans) == 2 ** 16:
                            raise Exception("Too many find first transactions open!")

                    offset = 0
                    data = []
                    for (i, (name, md)) in enumerate(entries[entries_offset:entries_offset + num_entries_to_ret], entries_offset):
                        bufs = info_generator(i, offset, flags, name, md,
                                              i == len(entries) - 1)
                        data.extend(bufs)
                        offset += sum(map(len, bufs))

                    data_bytes = b''.join(data)
                    last_name_offset = len(data_bytes) - len(data[-1])

                    params_bytes = struct.pack("<HHHHH",
                                               sid, num_entries_to_ret,
                                               int(is_search_over),
                                               0x0,
                                               0 if is_search_over else
                                               last_name_offset)

                    args = response_args_from_req(req,
                                                  setup_bytes=struct.pack("<H", SMB_TRANS2_FIND_FIRST2),
                                                  params_bytes=params_bytes,
                                                  data_bytes=data_bytes)
                    self.send_message(SMBMessage(ComTransaction2Response(**args)))
                    open_find_trans[sid] = {}

                    if is_search_over and flags & SMB_FIND_CLOSE_AT_EOS:
                        del open_find_trans[sid]
                elif setup[0] == SMB_TRANS2_QUERY_FS_INFORMATION:
                    if req.payload.flags:
                        raise Exception("Transaction 2 flags not supported!")

                    fmt = "<H"
                    fmt_size = struct.calcsize(fmt)
                    (information_level,) = struct.unpack(fmt, req.payload.params_bytes[:fmt_size])

                    try:
                        fs_info_generator = FS_INFO_GENERATORS[information_level]
                    except KeyError:
                        raise Exception("QUERY FS Information level not supported: %r" % (information_level,))

                    data_bytes = fs_info_generator()

                    args = response_args_from_req(req,
                                                  setup_bytes=struct.pack("<H", SMB_TRANS2_QUERY_FS_INFORMATION),
                                                  params_bytes=b'',
                                                  data_bytes=data_bytes)
                    self.send_message(SMBMessage(ComTransaction2Response(**args)))
                elif setup[0] == SMB_TRANS2_QUERY_PATH_INFORMATION:
                    if req.payload.flags:
                        raise Exception("Transaction 2 flags not supported!")

                    (information_level,) = struct.unpack("<H",
                                                         req.payload.params_bytes[:2])

                    try:
                        query_path_info_generator = QUERY_FILE_INFO_GENERATORS[information_level]
                    except KeyError:
                        raise Exception("QUERY PATH Information level not supported: %r" % (information_level,))

                    path = req.payload.params_bytes[6:].decode("utf-16-le").rstrip("\0")

                    if path[:1] != '\\':
                        raise Exception("bad path: %r" % (path,))

                    components = path[:2].split("\\")
                    if components == ['']:
                        components = []

                    parent = {"type": "directory",
                              "children": entries}
                    real_comps = []
                    for comp in components:
                        for (name, md) in parent["children"]:
                            if name.lower() == comp.lower():
                                real_comps.append(name)
                                parent = md
                                break
                    path = '\\' + '\\'.join(real_comps)
                    md = parent

                    setup_bytes = struct.pack("<H", SMB_TRANS2_QUERY_PATH_INFORMATION)
                    (ea_error_offset, data_bytes) = query_path_info_generator(path, md)
                    params_bytes = struct.pack("<H", ea_error_offset)

                    args = response_args_from_req(req,
                                                  setup_bytes=setup_bytes,
                                                  params_bytes=params_bytes,
                                                  data_bytes=data_bytes)
                    self.send_message(SMBMessage(ComTransaction2Response(**args)))
                else:
                    log.debug("%s", req)
                    self.send_message(error_response(req, STATUS_SMB_BAD_COMMAND))
            elif req.command == SMB_COM_QUERY_INFORMATION_DISK:
                args = response_args_from_req(req,
                                              total_units=2 ** 16 - 1,
                                              blocks_per_unit=16384,
                                              block_size=512,
                                              free_units=0
                )
                self.send_message(SMBMessage(ComQueryInformationDiskResponse(**args)))
            else:
                log.debug("%s", req)
                self.send_message(error_response(req, STATUS_SMB_BAD_COMMAND))

def main(argv):
    logging.basicConfig(level=logging.DEBUG)

    # run basic server
    server = socketserver.ThreadingTCPServer(('localhost', 8888),
                                             SMBClientHandler, False)
    server.allow_reuse_address = True
    server.server_bind()
    server.server_activate()
    server.serve_forever()
    return 0

if __name__ == "__main__":
    sys.exit(main(sys.argv))
