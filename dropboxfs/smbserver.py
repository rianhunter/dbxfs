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
import random
import struct
import sys

from collections import defaultdict, namedtuple
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

from dropboxfs.util_dumpster import quick_container

log = logging.getLogger(__name__)

SMB_COM_CLOSE = 0x04
SMB_COM_DELETE = 0x06
SMB_COM_RENAME = 0x07
SMB_COM_TRANSACTION = 0x25
SMB_COM_ECHO = 0x2B
SMB_COM_OPEN_ANDX = 0x2D
SMB_COM_READ_ANDX = 0x2E
SMB_COM_WRITE_ANDX = 0x2F
SMB_COM_TRANSACTION2 = 0x32
SMB_COM_NEGOTIATE = 0x72
SMB_COM_SESSION_SETUP_ANDX = 0x73
SMB_COM_TREE_CONNECT_ANDX = 0x75
SMB_COM_NT_TRANSACT = 0xA0
SMB_COM_NT_CREATE_ANDX = 0xA2
SMB_COM_QUERY_INFORMATION_DISK = 0x80
SMB_COM_CHECK_DIRECTORY = 0x10
SMB_COM_TREE_DISCONNECT = 0x71
SMB_COM_FLUSH = 0x05
SMB_COM_CREATE_DIRECTORY = 0x0
SMB_COM_DELETE_DIRECTORY = 0x1

SMB_FLAGS_REPLY = 0x80
SMB_FLAGS2_NT_STATUS = 0x4000
SMB_FLAGS2_UNICODE = 0x8000
SMB_FLAGS2_EXTENDED_SECURITY = 0x0800

CAP_RAW_MODE = 0x01
CAP_MPX_MODE = 0x02
CAP_UNICODE = 0x04
CAP_LARGE_FILES = 0x08
CAP_NT_SMBS = 0x10
CAP_RPC_REMOTE_APIS = 0x20
CAP_STATUS32 = 0x40
CAP_LEVEL_II_OPLOCKS = 0x80
CAP_LOCK_AND_READ = 0x0100
CAP_NT_FIND = 0x0200
CAP_DFS = 0x1000
CAP_INFOLEVEL_PASSTHRU = 0x2000
CAP_LARGE_READX = 0x4000
CAP_LARGE_WRITEX = 0x8000
CAP_LWIO = 0x010000
CAP_UNIX = 0x800000
CAP_COMPRESSED = 0x02000000
CAP_DYNAMIC_REAUTH = 0x20000000
CAP_PERSISTENT_HANDLES = 0x40000000
CAP_EXTENDED_SECURITY = 0x80000000

SMB_TREE_CONNECTX_SUPPORT_SEARCH = 0x0001

SMB_FILE_ATTRIBUTE_DIRECTORY = 0x10

SMB_MAX_DATA_PAYLOAD = 2 ** 16 - 1
DATA_BYTE_COUNT_LENGTH = 2

def parse_zero_terminated_utf16(buf, offset):
    s = offset
    while True:
        next_offset = buf.index(b'\0\0', s)
        if (next_offset - offset) % 2: s = next_offset + 1
        else: break
    return (buf[offset:next_offset].decode("utf-16-le"), next_offset + 2)

def generate_simple_params_decoder(fmt, type_):
    def decode_params(_, __, buf):
        try:
            return type_(*struct.unpack(fmt, buf))
        except Exception as e:
            raise Exception("Error while unpacking %s:%s" %
                            (type_.__name__, fmt)) from e
    return decode_params

SMBHeader = namedtuple('SMBHeader',
                       ['protocol', 'command',
                        'status', 'flags', 'flags2', 'pid',
                        'security_features', 'tid', 'uid', 'mid'])

SMBMessage = namedtuple('SMBMessage',
                        ['header', 'parameters', 'data'])

SMB_HEADER_STRUCT_FORMAT = "<4sBIBHHQxxHHHH"
SMB_HEADER_STRUCT_SIZE = struct.calcsize(SMB_HEADER_STRUCT_FORMAT)

def decode_smb_header(buf):
    kw = {}
    (kw['protocol'], kw['command'], kw['status'],
     kw['flags'], kw['flags2'], pid_high, kw['security_features'], kw['tid'],
     pid_low, kw['uid'], kw['mid']) = struct.unpack(SMB_HEADER_STRUCT_FORMAT, buf)

    if kw['protocol'] != b'\xFFSMB':
        raise Exception('Invalid 4-byte protocol field: %r' % (kw['protocol'],))

    kw['pid'] = (pid_high << 16) | pid_low

    return SMBHeader(**kw)

def decode_null_params(_, __, buf):
    if buf:
        raise Exception("Exception 0-length parameters")
    return None

def decode_null_data(_, __, ___, buf):
    if buf:
        raise Exception("Exception 0-length parameters")
    return None

def decode_byte_data(_, __, ___, buf):
    return buf

SMBNegotiateRequestData = namedtuple('SMBNegotiateRequestData', ['dialects'])
def decode_negotiate_request_data(_, __, ___, buf):
    dialects = buf.split(b'\0')
    a = dialects.pop()
    if a: raise Exception("Non-trailing null byte!")
    dialects = [d.lstrip(b"\x02").decode("ascii") for d in dialects]
    return SMBNegotiateRequestData(dialects=dialects)

decode_session_setup_andx_request_params = generate_simple_params_decoder(
    '<BBHHHHIHHII',
    namedtuple('SMBSessionSetupAndxRequestParameters',
               ['andx_command', 'andx_reserved', 'andx_offset',
                'max_buffer_size', 'max_mpx_count',
                'vc_number', 'session_key',
                'oem_password_len', 'unicode_password_len',
                'reserved', 'capabilities']))

SMBSessionSetupAndxRequestData = namedtuple(
    'SMBSessionSetupAndxRequestData',
    ['password', 'account_name', 'primary_domain',
     'native_os', 'native_lan_man'])
def decode_session_setup_andx_request_data(smb_header, smb_parameters,
                                           buf_offset, buf):
    if not (smb_header.flags2 & SMB_FLAGS2_UNICODE):
        raise Exception("Only supports unicode!")

    if smb_parameters.oem_password_len:
        # NB: Mac OS X sends oem_password_len == 1 even when SMB_FLAGS2_UNICODE is
        #     set, even though this is against spec
        log.warning("OEM Password len must be 0 when SMB_FLAGS2_UNICODE is set: %r, %r" %
                    (smb_parameters.oem_password_len,
                     buf[:smb_parameters.oem_password_len]))

    # Linux CIFS_VFS client sends NTLMv2 even when we ask it not to
    password = None
    #password = message.data[oem_password_len:oem_password_len + unicode_password_len].decode("utf-16-le")

    # read padding
    raw_offset = (buf_offset + smb_parameters.oem_password_len +
                  smb_parameters.unicode_password_len)
    if raw_offset % 2:
        if buf[raw_offset - buf_offset] != 0:
            raise Exception("Was expecting null byte!: %r" %
                            (buf[raw_offset - buf_offset],))
        raw_offset += 1

    kw = {'password' : password}

    rel_offset = raw_offset - buf_offset
    for n in ["account_name", "primary_domain", "native_os", "native_lan_man"]:
        (kw[n], rel_offset) = parse_zero_terminated_utf16(buf, rel_offset)

    return SMBSessionSetupAndxRequestData(**kw)

decode_tree_connect_andx_request_params = generate_simple_params_decoder(
    "<BBHHH",
    namedtuple('SMBTreeConnectAndxRequestParameters',
               ['andx_command', 'andx_reserved', 'andx_offset',
                'flags', 'password_len']))

SMBTreeConnectAndxRequestData = namedtuple('SMBTreeConnectAndxRequestData',
                                           ['password', 'path', 'service'])
def decode_tree_connect_andx_request_data(smb_header, smb_parameters, buf_offset, buf):
    if not (smb_header.flags2 & SMB_FLAGS2_UNICODE):
        raise Exception("Only supports unicode!")

    # Linux CIFS_VFS client sends NTLMv2 even when we ask it not to
    password = None
    #password = message.data[oem_password_len:oem_password_len + unicode_password_len].decode("utf-16-le")

    # read padding
    raw_offset = (buf_offset + smb_parameters.password_len)
    if raw_offset % 2:
        if buf[raw_offset - buf_offset] != 0:
            raise Exception("Was expecting null byte!: %r" %
                            (buf[raw_offset - buf_offset],))
        raw_offset += 1

    kw = {'password' : password}

    rel_offset = raw_offset - buf_offset
    (kw['path'], rel_offset) = parse_zero_terminated_utf16(buf, rel_offset)

    kw['service'] = buf[rel_offset:-1].decode("ascii")

    return SMBTreeConnectAndxRequestData(**kw)

decode_echo_request_params = generate_simple_params_decoder(
    '<H', namedtuple('SMBEchoRequestParameters', ['echo_count']))

SMBTransaction2RequestParameters = namedtuple(
    'SMBTransaction2RequestParameters',
    ['total_parameter_count', 'total_data_count',
     'max_parameter_count', 'max_data_count',
     'max_setup_count', 'flags', 'timeout',
     'parameter_count', 'parameter_offset',
     'data_count', 'data_offset', 'setup'])
def decode_transaction_2_request_params(_, __, buf):
    fmt = 'HHHHBBHIHHHHHH'
    fmt_size = struct.calcsize(fmt)

    kw = {}
    (kw['total_parameter_count'], kw['total_data_count'],
     kw['max_parameter_count'], kw['max_data_count'],
     kw['max_setup_count'], _, kw['flags'], kw['timeout'],
     _, kw['parameter_count'], kw['parameter_offset'], kw['data_count'],
     kw['data_offset'], setup_words_len) = struct.unpack(fmt, buf[:fmt_size])


    kw['setup'] = struct.unpack("<%dH" % (setup_words_len,),
                                buf[fmt_size : fmt_size + setup_words_len * 2])

    return SMBTransaction2RequestParameters(**kw)


SMBTransaction2RequestData = \
    namedtuple('SMBTransaction2RequestData',
               ['parameters', 'data'])
def decode_transaction_2_request_data(smb_header, smb_parameters, buf_offset, buf):
    params = buf[smb_parameters.parameter_offset - buf_offset :
                 smb_parameters.parameter_offset - buf_offset + smb_parameters.parameter_count]

    data = buf[smb_parameters.data_offset - buf_offset :
               smb_parameters.data_offset - buf_offset + smb_parameters.data_count]

    return SMBTransaction2RequestData(params, data)

decode_nt_create_andx_request_params = generate_simple_params_decoder(
    "<BBHBHIIIQIIIIIB",
    namedtuple('SMBNTCreateAndxRequestParameters',
               ['andx_command', 'andx_reserved', 'andx_offset',
                'reserved1', 'name_length', 'flags',
                'root_directory_fid', 'desired_access',
                'allocation_size', 'ext_file_attributes',
                'share_access', 'create_disposition',
                'create_options', 'impersonation_level',
                'security_flags']))

SMBNTCreateAndxRequestData = \
    namedtuple('SMBNTCreateAndxRequestData', ['filename'])
def decode_nt_create_andx_request_data(smb_header, smb_parameters, buf_offset, buf):
    if not (smb_header.flags2 & SMB_FLAGS2_UNICODE):
        raise Exception("Only support unicode!")

    raw_offset = buf_offset
    if raw_offset % 2:
        raw_offset += 1

    filename = buf[raw_offset - buf_offset :
                   raw_offset - buf_offset + smb_parameters.name_length].decode("utf-16-le").rstrip("\0")
    return SMBNTCreateAndxRequestData(filename)

SMBReadAndxRequestParameters = \
    namedtuple('SMBReadAndxRequestParameters',
               ['andx_command', 'andx_reserved', 'andx_offset',
                'fid', 'offset',
                'max_count_of_bytes_to_return',
                'min_count_of_bytes_to_return',
                'timeout', 'remaining'])
def decode_read_andx_request_params(_, __, buf):
    kw = {}

    fmt = "<BBHHLHHLH"
    fmt_size = struct.calcsize(fmt)
    (kw['andx_command'], kw['andx_reserved'], kw['andx_offset'],
     kw['fid'], kw['offset'],
     kw['max_count_of_bytes_to_return'],
     kw['min_count_of_bytes_to_return'],
     kw['timeout'], kw['remaining']) = struct.unpack(fmt, buf[:fmt_size])

    if len(buf) > fmt_size:
        (offset_high,) = struct.unpack("<I", buf[fmt_size:])
        kw['offset'] = (offset_high << 32) | kw['offset']

    return SMBReadAndxRequestParameters(**kw)

decode_close_request_params = generate_simple_params_decoder(
    "<HL",
    namedtuple('SMBComCloseRequestParameters',
               ['fid', 'last_modified_time']))
SMBNTTransactRequestParameters = \
    namedtuple('SMBNTTransactRequestParameters',
               ['max_setup_count',
                'total_parameter_count', 'total_data_count',
                'max_parameter_count', 'max_data_count',
                'parameter_count', 'parameter_offset',
                'data_count', 'data_offset',
                'function',
                'setup'])
def decode_nt_transact_request_params(smb_header, _, buf):
    fmt = "<BHLLLLLLLLBH"
    fmt_size = struct.calcsize(fmt)

    kw = {}
    (kw['max_setup_count'], _,
     kw['total_parameter_count'], kw['total_data_count'],
     kw['max_parameter_count'], kw['max_data_count'],
     kw['parameter_count'], kw['parameter_offset'],
     kw['data_count'], kw['data_offset'],
     setup_count,
     kw['function']) = struct.unpack(fmt, buf[:fmt_size])

    kw['setup'] = buf[fmt_size : fmt_size + setup_count * 2]

    return SMBNTTransactRequestParameters(**kw)

SMBNTTransactRequestData = namedtuple(
    'SMBNTTransactRequestData', ['parameters', 'data'])
def decode_nt_transact_request_data(smb_header, smb_parameters, buf_offset, buf):
    params = buf[smb_parameters.parameter_offset - buf_offset :
                 smb_parameters.parameter_offset - buf_offset + smb_parameters.parameter_count]

    data = buf[smb_parameters.data_offset - buf_offset :
               smb_parameters.data_offset - buf_offset + smb_parameters.data_count]

    return SMBNTTransactRequestData(params, data)

SMBCheckDirectoryRequestData = namedtuple('SMBCheckDirectoryRequestData', ['filename'])
def decode_check_directory_request_data(smb_header, __, ___, buf):
    if not (smb_header.flags2 & SMB_FLAGS2_UNICODE):
        raise Exception("Only support unicode!")

    filename = buf.decode('utf-16-le').rstrip('\0')
    return SMBCheckDirectoryRequestData(filename=filename)

SMBWriteAndxRequestParameters = namedtuple(
    'SMBWriteAndxRequestParameters',
    ['andx_command', 'andx_reserved', 'andx_offset',
     'fid', 'offset', 'timeout', 'write_mode', 'remaining',
     'data_length', 'data_offset'])
def decode_write_andx_request_params(_, __, buf):
    kw = {}

    fmt = "<BBHHLLHHHHH"
    fmt_size = struct.calcsize(fmt)
    (kw['andx_command'], kw['andx_reserved'], kw['andx_offset'],
     kw['fid'], kw['offset'],
     kw['timeout'], kw['write_mode'],
     kw['remaining'], _reserved, kw['data_length'],
     kw['data_offset']) = struct.unpack(fmt, buf[:fmt_size])

    if len(buf) > fmt_size:
        (offset_high,) = struct.unpack("<L", buf[fmt_size:])
        kw['offset'] = (offset_high << 32) | kw['offset']

    return SMBWriteAndxRequestParameters(**kw)

def decode_write_andx_request_data(_, params, __, buf):
    # NB: skip pad byte
    if (len(buf) - 1) < params.data_length:
        raise Exception("Not enough data!")
    elif (len(buf) - 1) > params.data_length:
        log.warn("Got more data than was expecting")
    return buf[1:1 + params.data_length]

decode_flush_request_params = generate_simple_params_decoder(
    "<H",
    namedtuple('SMBComFlushParameters',
               ['fid']))

decode_delete_request_params = generate_simple_params_decoder(
    "<H",
    namedtuple('SMBDeleteRequestParameters',
               ['search_attributes']))

SMBDeleteRequestData = namedtuple('SMBDeleteRequestData',
                                  ['buffer_format', 'filename'])
def decode_delete_request_data(smb_header, params, __, buf):
    if not (smb_header.flags2 & SMB_FLAGS2_UNICODE):
        raise Exception("Only support unicode!")

    (buffer_format,) = struct.unpack("<B", buf[:1])
    filename = buf[1:].decode('utf-16-le').rstrip('\0')
    return SMBDeleteRequestData(buffer_format, filename)

# It's the same structure
decode_create_directory_request_data = decode_delete_request_data
decode_delete_directory_request_data = decode_delete_request_data

# same structure
decode_rename_request_params = decode_delete_request_params

SMBRenameRequestData = namedtuple('SMBRenameRequestData',
                                  ['buffer_format_1', 'old_filename',
                                   'buffer_format_2', 'new_filename'])
def decode_rename_request_data(smb_header, params, __, buf):
    if not (smb_header.flags2 & SMB_FLAGS2_UNICODE):
        raise Exception("Only support unicode!")

    (buffer_format_1,) = struct.unpack("<B", buf[:1])
    (old_filename, new_offset) = parse_zero_terminated_utf16(buf, 1)
    (buffer_format_2,) = struct.unpack("<B", buf[new_offset:new_offset + 1])
    (new_filname, _) = parse_zero_terminated_utf16(buf, new_offset + 2)

    return SMBRenameRequestData(buffer_format_1, old_filename,
                                buffer_format_2, new_filname)

REQUEST = False
REPLY = True
_decoder_dispatch = {
    (SMB_COM_NEGOTIATE, REQUEST): (decode_null_params,
                                   decode_negotiate_request_data),
    (SMB_COM_SESSION_SETUP_ANDX, REQUEST): (decode_session_setup_andx_request_params,
                                            decode_session_setup_andx_request_data),
    (SMB_COM_TREE_CONNECT_ANDX, REQUEST): (decode_tree_connect_andx_request_params,
                                           decode_tree_connect_andx_request_data),
    (SMB_COM_TREE_DISCONNECT, REQUEST): (decode_null_params,
                                         decode_null_data),
    (SMB_COM_ECHO, REQUEST): (decode_echo_request_params,
                              decode_byte_data),
    (SMB_COM_TRANSACTION2, REQUEST): (decode_transaction_2_request_params,
                                      decode_transaction_2_request_data),
    (SMB_COM_QUERY_INFORMATION_DISK, REQUEST): (decode_null_params,
                                                decode_null_data),
    (SMB_COM_NT_CREATE_ANDX, REQUEST): (decode_nt_create_andx_request_params,
                                        decode_nt_create_andx_request_data),
    (SMB_COM_READ_ANDX, REQUEST): (decode_read_andx_request_params,
                                   decode_null_data),
    (SMB_COM_CLOSE, REQUEST): (decode_close_request_params,
                               decode_null_data),
    (SMB_COM_NT_TRANSACT, REQUEST): (decode_nt_transact_request_params,
                                     decode_nt_transact_request_data),
    (SMB_COM_CHECK_DIRECTORY, REQUEST): (decode_null_params,
                                         decode_check_directory_request_data),
    (SMB_COM_WRITE_ANDX, REQUEST): (decode_write_andx_request_params,
                                    decode_write_andx_request_data),
    (SMB_COM_FLUSH, REQUEST): (decode_flush_request_params,
                               decode_null_data),
    (SMB_COM_DELETE, REQUEST): (decode_delete_request_params,
                                decode_delete_request_data),
    (SMB_COM_CREATE_DIRECTORY, REQUEST): (decode_null_params,
                                          decode_create_directory_request_data),
    (SMB_COM_DELETE_DIRECTORY, REQUEST): (decode_null_params,
                                          decode_delete_directory_request_data),
    (SMB_COM_RENAME, REQUEST): (decode_rename_request_params,
                                decode_rename_request_data),
}

def get_decoder(header):
    try:
        return _decoder_dispatch[(header.command, bool(header.flags & SMB_FLAGS_REPLY))]
    except KeyError:
        raise ProtocolError(STATUS_NOT_SUPPORTED)

def decode_smb_payload(smb_header, buf):
    (params_decoder, data_decoder) = get_decoder(smb_header)

    cur_offset = 0

    params_size = buf[cur_offset] * 2
    cur_offset += 1

    smb_parameters = params_decoder(smb_header, SMB_HEADER_STRUCT_SIZE + cur_offset,
                                    buf[cur_offset : cur_offset + params_size])
    cur_offset += params_size

    (data_size,) = struct.unpack("<H", buf[cur_offset : cur_offset + 2])
    cur_offset += 2

    smb_data = data_decoder(smb_header, smb_parameters, SMB_HEADER_STRUCT_SIZE + cur_offset,
                            buf[cur_offset : cur_offset + data_size])
    cur_offset += data_size

    if cur_offset != len(buf):
        raise Exception("Bad SMB packet length!")

    return (smb_parameters, smb_data)

def decode_smb_message(buf):
    smb_header = decode_smb_header(buf[:SMB_HEADER_STRUCT_SIZE])
    (smb_parameters, smb_data) = decode_smb_payload(smb_header, buf[SMB_HEADER_STRUCT_SIZE:])

    return SMBMessage(header=smb_header,
                      parameters=smb_parameters,
                      data=smb_data)

def encode_null_params(header, buf_offset, parameters):
    return b''

def encode_null_data(header, parameters, buf_offset, data):
    return b''

def encode_byte_data(header, parameters, buf_offset, data):
    return data

def generate_simple_parameter_encoder(fmt, attrs):
    def encoder(_, buf_offset, parameters):
        return struct.pack(fmt, *[getattr(parameters, a) if a is not None else 0
                                  for a in attrs])
    return encoder

encode_negotiate_reply_parameters = generate_simple_parameter_encoder(
    '<HBHHIIIIQhB',
    ['dialect_index', 'security_mode', 'max_mpx_count',
     'max_number_vcs', 'max_buffer_size', 'max_raw_size',
     'session_key', 'capabilities', 'system_time',
     'server_time_zone', 'challenge_length'])

def encode_negotiate_reply_data(header, parameters, buf_offset, data):
    if not (header.flags2 & SMB_FLAGS2_UNICODE):
        raise NotImplementedError("non-unicode not implemented!")

    assert parameters.challenge_length == len(data.challenge)
    return b''.join([data.challenge,
                     (data.domain_name + "\0").encode('utf-16-le')])

encode_session_setup_andx_reply_params = generate_simple_parameter_encoder(
    '<BBHH',
    ['andx_command', 'andx_reserved', 'andx_offset', 'action'])

def encode_session_setup_andx_reply_data(header, parameters, buf_offset, data):
    if not (header.flags2 & SMB_FLAGS2_UNICODE):
        raise NotImplementedError("non-unicode not implemented!")

    prefix = b''
    if buf_offset % 2:
        prefix += b'\0'

    return b''.join(itertools.chain([prefix],
                                    (x.encode('utf-16-le')
                                     for x in [data.native_os, "\0",
                                               data.native_lan_man, "\0",
                                               data.primary_domain, "\0"])))

encode_tree_connect_reply_params = generate_simple_parameter_encoder(
    '<BBHH',
    ['andx_command', 'andx_reserved', 'andx_offset', 'optional_support'])


def encode_tree_connect_reply_data(header, parameters, buf_offset, data):
    if not (header.flags2 & SMB_FLAGS2_UNICODE):
        raise NotImplementedError("non-unicode not implemented!")

    return b''.join([data.service.encode("ascii"),
                     data.native_file_system.encode("utf-16-le"),
                     b'\0\0'])

encode_echo_reply_params = generate_simple_parameter_encoder(
    "<H",
    ["sequence_number"])

def encode_transaction_2_reply_params(header, buf_offset, parameters):
    fmt = "<HHHHHHHHHBB"

    data_offset = (buf_offset +
                   struct.calcsize(fmt) +
                   len(parameters.setup) * 2 +
                   DATA_BYTE_COUNT_LENGTH)

    trans2_params_offset = data_offset
    if trans2_params_offset % 4:
        trans2_params_offset += 4 - trans2_params_offset % 4

    trans2_data_offset = trans2_params_offset + parameters.parameter_count
    if trans2_data_offset % 4:
        trans2_data_offset += 4 - trans2_data_offset % 4

    return b''.join([struct.pack(fmt,
                                 parameters.total_parameter_count,
                                 parameters.total_data_count,
                                 0,
                                 parameters.parameter_count,
                                 trans2_params_offset,
                                 parameters.parameter_displacement,
                                 parameters.data_count,
                                 trans2_data_offset,
                                 parameters.data_displacement,
                                 len(parameters.setup), 0),
                     struct.pack('<%dH' % (len(parameters.setup),),
                                 *parameters.setup)])

def encode_transaction_2_reply_data(header, parameters, buf_offset, data):
    trans2_params_offset = buf_offset
    if trans2_params_offset % 4:
        trans2_params_offset += 4 - trans2_params_offset % 4

    trans2_data_offset = trans2_params_offset + len(data.parameters)
    if trans2_data_offset % 4:
        trans2_data_offset += 4 - trans2_data_offset % 4

    return b''.join([(trans2_params_offset - buf_offset) * b'\0',
                     data.parameters,
                     (trans2_data_offset - (trans2_params_offset + len(data.parameters))) * b'\0',
                     data.data])

encode_query_information_disk_reply_params = generate_simple_parameter_encoder(
    "<HHHHH",
    ["total_units", "blocks_per_unit", "block_size", "free_units"])

encode_nt_create_andx_reply_params = generate_simple_parameter_encoder(
    "<BBHBHLQQQQLQQHHB",
    ["andx_command", "andx_reserved", "andx_offset",
     'op_lock_level', 'fid', 'create_disposition', 'create_time',
     'last_access_time', 'last_write_time', 'last_change_time',
     'ext_file_attributes', 'allocation_size', 'end_of_file',
     'resource_type', 'nm_pipe_status', 'directory'])

def encode_read_andx_reply_params(header, buf_offset, parameters):
    fmt = "<BBHHHHHHHHHHH"

    offset = buf_offset + struct.calcsize(fmt) + DATA_BYTE_COUNT_LENGTH
    if offset % 2:
        offset += 1

    p = parameters
    return struct.pack(fmt,
                       p.andx_command, p.andx_reserved, p.andx_offset,
                       p.available, 0, 0, p.data_length, offset,
                       0, 0, 0, 0, 0)

def encode_read_andx_reply_data(header, parameters, buf_offset, data):
    assert parameters.data_length == len(data)

    pad = b''
    if buf_offset % 2:
        pad += b'\0'

    return b''.join([pad, data])

def encode_nt_transact_reply_params(header, buf_offset, parameters):
    fmt = "<BBBLLLLLLLLB"

    data_offset = (buf_offset +
                   struct.calcsize(fmt) +
                   len(parameters.setup) * 2 +
                   DATA_BYTE_COUNT_LENGTH)

    nt_transact_params_offset = data_offset
    if nt_transact_params_offset % 4:
        nt_transact_params_offset += 4 - nt_transact_params_offset % 4

    nt_transact_data_offset = nt_transact_params_offset + parameters.parameter_count
    if nt_transact_data_offset % 4:
        nt_transact_data_offset += 4 - nt_transact_data_offset % 4

    assert not (len(parameters.setup) % 2)

    return b''.join([struct.pack(fmt,
                                 0, 0, 0,
                                 parameters.total_parameter_count,
                                 parameters.total_data_count,
                                 parameters.parameter_count,
                                 nt_transact_params_offset,
                                 parameters.parameter_displacement,
                                 parameters.data_count,
                                 nt_transact_data_offset,
                                 parameters.data_displacement,
                                 len(parameters.setup) // 2),
                     parameters.setup])

def encode_nt_transact_reply_data(header, parameters, data_offset, data):
    nt_transact_params_offset = data_offset
    if nt_transact_params_offset % 4:
        nt_transact_params_offset += 4 - nt_transact_params_offset % 4

    nt_transact_data_offset = nt_transact_params_offset + len(data.parameters)
    if nt_transact_data_offset % 4:
        nt_transact_data_offset += 4 - nt_transact_data_offset % 4

    return b''.join([(nt_transact_params_offset - data_offset) * b'\0',
                     data.parameters,
                     (nt_transact_data_offset - (nt_transact_params_offset +
                                                 len(data.parameters))) * b'\0',
                     data.data])

encode_write_andx_reply_params = generate_simple_parameter_encoder(
    "<BBHHHL",
    ["andx_command", "andx_reserved", "andx_offset",
     "count", "available", None])

_encoder_dispatch = {
    (SMB_COM_NEGOTIATE, REPLY): (encode_negotiate_reply_parameters,
                                 encode_negotiate_reply_data),
    (SMB_COM_SESSION_SETUP_ANDX, REPLY): (encode_session_setup_andx_reply_params,
                                          encode_session_setup_andx_reply_data),
    (SMB_COM_TREE_CONNECT_ANDX, REPLY): (encode_tree_connect_reply_params,
                                         encode_tree_connect_reply_data),
    (SMB_COM_TREE_DISCONNECT, REPLY): (encode_null_params,
                                       encode_null_data),
    (SMB_COM_ECHO, REPLY): (encode_echo_reply_params,
                            encode_byte_data),
    (SMB_COM_TRANSACTION2, REPLY): (encode_transaction_2_reply_params,
                                    encode_transaction_2_reply_data),
    (SMB_COM_QUERY_INFORMATION_DISK, REPLY): (encode_query_information_disk_reply_params,
                                              encode_null_data),
    (SMB_COM_NT_CREATE_ANDX, REPLY): (encode_nt_create_andx_reply_params,
                                      encode_null_data),
    (SMB_COM_READ_ANDX, REPLY): (encode_read_andx_reply_params,
                                 encode_read_andx_reply_data),
    (SMB_COM_CLOSE, REPLY): (encode_null_params,
                             encode_null_data),
    (SMB_COM_NT_TRANSACT, REPLY): (encode_nt_transact_reply_params,
                                   encode_nt_transact_reply_data),
    (SMB_COM_CHECK_DIRECTORY, REPLY): (encode_null_params,
                                       encode_null_data),
    (SMB_COM_WRITE_ANDX, REPLY): (encode_write_andx_reply_params,
                                  encode_null_data),
    (SMB_COM_FLUSH, REPLY): (encode_null_params,
                             encode_null_data),
    (SMB_COM_DELETE, REPLY): (encode_null_params,
                              encode_null_data),
    (SMB_COM_CREATE_DIRECTORY, REPLY): (encode_null_params,
                                        encode_null_data),
    (SMB_COM_DELETE_DIRECTORY, REPLY): (encode_null_params,
                                        encode_null_data),
    (SMB_COM_RENAME, REPLY): (encode_null_params,
                              encode_null_data),
}

def get_encoder(header):
    return _encoder_dispatch[(header.command, bool(header.flags & SMB_FLAGS_REPLY))]

def encode_smb_header(header):
    return struct.pack(SMB_HEADER_STRUCT_FORMAT,
                       b'\xFFSMB', header.command, header.status, header.flags,
                       header.flags2, (header.pid >> 16) & 0xFFFF,
                       header.security_features, header.tid,
                       header.pid & 0xFFFF, header.uid, header.mid)

def encode_smb_message(msg):
    cur_offset = 0

    header = encode_smb_header(msg.header)
    cur_offset += len(header)

    if not msg.header.status:
        (params_encoder, data_encoder) = get_encoder(msg.header)

        # account for word-length prefix
        cur_offset += 1

        params = params_encoder(msg.header, cur_offset, msg.parameters)
        assert not (len(params) % 2)
        cur_offset += len(params)

        # account for byte-length prefix
        cur_offset += DATA_BYTE_COUNT_LENGTH
        assert DATA_BYTE_COUNT_LENGTH == 2

        data = data_encoder(msg.header, msg.parameters, cur_offset, msg.data)
        cur_offset += len(data)
    else:
        # This is an "error response" message
        cur_offset += 1
        params = b''
        cur_offset += DATA_BYTE_COUNT_LENGTH
        data = b''

    toret = b''.join([header,
                      struct.pack("<B", len(params) // 2), params,
                      struct.pack("<H", len(data)), data])

    assert len(toret) == cur_offset

    return toret

SMBTransaction2FindFirstRequestParameters = namedtuple(
    'SMBTransaction2FindFirstRequestParameters',
    ['search_attributes', 'search_count',
     'flags', 'information_level',
     'search_storage_type', 'filename'])
def decode_transaction_2_find_first_request_params(smb_header, _, buf):
    if not (smb_header.flags2 & SMB_FLAGS2_UNICODE):
        raise Exception("Only supports unicode!")

    kw = {}

    fmt = "<HHHHI"
    fmt_size = struct.calcsize(fmt)
    (kw['search_attributes'], kw['search_count'],
     kw['flags'], kw['information_level'],
     kw['search_storage_type']) = struct.unpack(fmt, buf[:fmt_size])

    kw['filename'] = buf[fmt_size:].decode("utf-16-le")[:-1]
    return SMBTransaction2FindFirstRequestParameters(**kw)

def decode_transaction_2_find_first_request_data(_, __, trans2_params, buf):
    if trans2_params.information_level == SMB_INFO_QUERY_EAS_FROM_LIST:
        raise Exception("Not supported")

    if buf:
        raise Exception("buf should be empty")

    return None

SMBTransaction2FindNextRequestParameters = namedtuple(
    'SMBTransaction2FindNextRequestParameters',
    ['sid', 'search_count', 'information_level', 'resume_key',
     'flags', 'filename'])
def decode_transaction_2_find_next_request_params(smb_header, _, buf):
    if not (smb_header.flags2 & SMB_FLAGS2_UNICODE):
        raise Exception("Only supports unicode!")

    kw = {}

    fmt = "<HHHIH"
    fmt_size = struct.calcsize(fmt)
    (kw['sid'], kw['search_count'],
     kw['information_level'], kw['resume_key'],
     kw['flags']) = struct.unpack(fmt, buf[:fmt_size])

    kw['filename'] = buf[fmt_size:].decode("utf-16-le")[:-1]
    return SMBTransaction2FindNextRequestParameters(**kw)

decode_transaction_2_find_next_request_data = \
    decode_transaction_2_find_first_request_data

def decode_transaction_2_null_request_data(_, __, ___, buf):
    if buf:
        raise Exception("buf should be empty")
    return None

SMBTransaction2QueryFSInformationRequestParameters = \
    namedtuple('SMBTransaction2QueryFSInformationRequestParameters',
               ['information_level'])
def decode_transaction_2_query_fs_information_request_params(_, __, buf):
    return SMBTransaction2QueryFSInformationRequestParameters(*struct.unpack("<H", buf))

SMBTransaction2QueryPathInformationRequestParams = \
    namedtuple('SMBTransaction2QueryPathInformationRequestParams',
               ['information_level', 'filename'])
def decode_transaction_2_query_path_information_request_params(smb_header, _, buf):
    if not (smb_header.flags2 & SMB_FLAGS2_UNICODE):
        raise Exception("Only supports unicode!")

    kw = {}

    fmt = "<HI"
    fmt_size = struct.calcsize(fmt)

    (kw['information_level'], _reserved) = struct.unpack(fmt, buf[:fmt_size])

    kw['filename'] = buf[fmt_size:].decode("utf-16-le")[:-1]

    return SMBTransaction2QueryPathInformationRequestParams(**kw)

decode_transaction_2_query_path_information_request_data = \
    decode_transaction_2_find_first_request_data

SMBTransaction2QueryFileInformationRequestParams = \
    namedtuple('SMBTransaction2QueryFileInformationRequestParams',
               ['fid', 'information_level'])
def decode_transaction_2_query_file_information_request_params(smb_header, _, buf):
    fmt = "<HH"
    return SMBTransaction2QueryFileInformationRequestParams(*struct.unpack(fmt, buf))

decode_transaction_2_query_file_information_request_data = \
    decode_transaction_2_find_first_request_data

def parse_set_file_data(trans2_params, buf):
    if trans2_params.information_level == SMB_SET_FILE_END_OF_FILE_INFO:
        fmt = "<Q"
        (end_of_file,) = struct.unpack(fmt, buf)
        return quick_container(end_of_file=end_of_file)
    else:
        raise ProtocolError(STATUS_OS2_INVALID_LEVEL,
                            "Information level not supported: %r" %
                            (trans2_params.information_level,))

SMBTransaction2SetFileInformationRequestParameters = \
    namedtuple('SMBTransaction2SetFileInformationRequestParameters',
               ['fid', 'information_level', 'reserved'])
def decode_transaction_2_set_file_information_request_params(smb_header, _, buf):
    fmt = "<HHH"
    return SMBTransaction2SetFileInformationRequestParameters(*struct.unpack(fmt, buf))

def decode_transaction_2_set_file_information_request_data(smb_header, smb_params,
                                                           trans2_params, buf):
    return parse_set_file_data(trans2_params, buf)

SMB_TRANS2_FIND_FIRST2 = 0x1
SMB_TRANS2_FIND_NEXT2 = 0x2
SMB_TRANS2_QUERY_FS_INFORMATION = 0x3
SMB_TRANS2_QUERY_PATH_INFORMATION = 0x5
SMB_TRANS2_QUERY_FILE_INFORMATION = 0x7
SMB_TRANS2_SET_FILE_INFORMATION = 0x8

_TRANS_2_DECODERS = {
    SMB_TRANS2_FIND_FIRST2: (decode_transaction_2_find_first_request_params,
                             decode_transaction_2_find_first_request_data),
    SMB_TRANS2_FIND_NEXT2: (decode_transaction_2_find_next_request_params,
                            decode_transaction_2_find_next_request_data),
    SMB_TRANS2_QUERY_FS_INFORMATION: (decode_transaction_2_query_fs_information_request_params,
                                      decode_transaction_2_null_request_data),
    SMB_TRANS2_QUERY_PATH_INFORMATION: (decode_transaction_2_query_path_information_request_params,
                                        decode_transaction_2_query_path_information_request_data),
    SMB_TRANS2_QUERY_FILE_INFORMATION: (decode_transaction_2_query_file_information_request_params,
                                        decode_transaction_2_query_file_information_request_data),
    SMB_TRANS2_SET_FILE_INFORMATION: (decode_transaction_2_set_file_information_request_params,
                                      decode_transaction_2_set_file_information_request_data),
}
def get_transaction2_request_decoder(smb_parameters):
    try:
        return _TRANS_2_DECODERS[smb_parameters.setup[0]]
    except KeyError:
        raise ProtocolError(STATUS_NOT_SUPPORTED,
                            "Trans 2 request not supported: %r" % (smb_parameters.setup,))

def decode_transaction_2_request_message(msg):
    assert (msg.parameters.total_parameter_count == msg.parameters.parameter_count and
            msg.parameters.total_data_count == msg.parameters.data_count), \
            "only supports single smb-message transaction 2 requests"

    (params_decoder, data_decoder) = get_transaction2_request_decoder(msg.parameters)

    params = params_decoder(msg.header, msg.parameters, msg.data.parameters)
    data = data_decoder(msg.header, msg.parameters, params, msg.data.data)

    return (msg.parameters.setup[0], params, data)

SMBNTTransactNotifyChangeRequestSetup = namedtuple(
    'SMBNTTransactNotifyChangeRequestSetup',
    ['completion_filter', 'fid', 'watch_tree'])
def decode_nt_transact_notify_change_request_setup(_, parameters):
    return SMBNTTransactNotifyChangeRequestSetup(
        *struct.unpack("<LH?", parameters.setup[:7]))

def decode_nt_transact_null_request_params(_, __, ___, buf):
    if buf:
        raise Exception("there should be no buf!")
    return None

def decode_nt_transact_null_request_data(_, __, ___, ____, buf):
    if buf:
        raise Exception("there should be no buf!")
    return None

def get_nt_transact_request_decoder(smb_parameters):
    return {
        NT_TRANSACT_NOTIFY_CHANGE: (decode_nt_transact_notify_change_request_setup,
                                    decode_nt_transact_null_request_params,
                                    decode_nt_transact_null_request_data),
    }[smb_parameters.function]


def decode_nt_transact_request_message(msg):
    assert (msg.parameters.total_parameter_count == msg.parameters.parameter_count and
            msg.parameters.total_data_count == msg.parameters.data_count), \
            "only supports single smb-message nt transact requests"

    (setup_decoder, params_decoder, data_decoder) = \
        get_nt_transact_request_decoder(msg.parameters)

    setup = setup_decoder(msg.header, msg.parameters)
    params = params_decoder(msg.header, msg.parameters, setup, msg.data.parameters)
    data = data_decoder(msg.header, msg.parameters, setup, params, msg.data.data)

    return (msg.parameters.function, setup, params, data)

def reply_header_from_request_header(header, **kw):
    for x in SMBHeader._fields:
        if x not in kw:
            if x == 'flags':
                kw[x] = header.flags | SMB_FLAGS_REPLY
            elif x == "flags2":
                kw[x] = header.flags2 & ~SMB_FLAGS2_EXTENDED_SECURITY
            elif x == 'status':
                kw[x] = STATUS_SUCCESS
            else:
                kw[x] = getattr(header, x)
    return SMBHeader(**kw)

def reply_header_from_request(msg, **kw):
    return reply_header_from_request_header(msg.header, **kw)

STATUS_SUCCESS = 0x0
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
STATUS_UNSUCCESSFUL = 0xc0000001
STATUS_OBJECT_NAME_COLLISION = 0xc0000035
STATUS_OBJECT_PATH_SYNTAX_BAD = 0xc000003B
STATUS_OBJECT_PATH_INVALID = 0xc0000039

TREE_CONNECT_ANDX_DISCONNECT_TID = 0x1
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
SMB_QUERY_FILE_BASIC_INFO = 0x101
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
GENERIC_EXECUTE = 0x20000000
GENERIC_WRITE = 0x40000000
GENERIC_READ = 0x80000000
FILE_READ_DATA = 0x1
MAXIMUM_ALLOWED = 0x02000000

FILE_SUPERSEDE = 0x0
FILE_OPEN = 0x1
FILE_CREATE = 0x2
FILE_OPEN_IF = 0x3
FILE_OVERWRITE = 0x4
FILE_OVERWRITE_IF = 0x5

FILE_DELETE_ON_CLOSE = 0x1000
FILE_OPEN_BY_FILE_ID = 0x2000

FILE_DIRECTORY_FILE = 0x1
FILE_NON_DIRECTORY_FILE = 0x40

FILE_SHARE_READ = 0x1
FILE_SHARE_WRITE = 0x2
FILE_SHARE_DELETE = 0x4

FILE_ACTION_ADDED = 0x1
FILE_ACTION_REMOVED = 0x2
FILE_ACTION_MODIFIED = 0x3
FILE_ACTION_RENAMED_OLD_NAME = 0x4
FILE_ACTION_RENAMED_NEW_NAME = 0x5

DEFAULT_ANDX_PARAMETERS = dict(andx_command=0xff,
                               andx_reserved=0,
                               andx_offset=0)

SMB_SET_FILE_END_OF_FILE_INFO = 0x104

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

def error_response(header, status=STATUS_UNSUCCESSFUL):
    assert status, "Status must be an error!"
    return SMBMessage(
        reply_header_from_request_header(
            header,
            status=status,
            flags2=header.flags2 | SMB_FLAGS2_NT_STATUS),
        None, None)

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
        bufs.append(b' ')
        offset += 1
    bufs.append(file_name_encoded)
    offset += len(bufs[-1])

    return bufs

def generate_find_file_directory_info(idx, offset, flags, name, md, is_last):
    fmt = "<IIQQQQQQII"

    encoded_file_name = (name + "\0").encode("utf-16-le")
    fmt_size = struct.calcsize(fmt)

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

def generate_query_file_basic_info(path, md):
    creation_time = datetime_to_win32(md.birthtime)
    last_access_time = datetime_to_win32(md.atime)
    last_write_time = datetime_to_win32(md.mtime)
    last_change_time = datetime_to_win32(md.ctime)
    ext_file_attributes = (ATTR_DIRECTORY
                           if md.type == "directory" else
                           ATTR_NORMAL)
    buf = struct.pack("<QQQQLL",
                      creation_time, last_access_time,
                      last_write_time, last_change_time,
                      ext_file_attributes,
                      0)

    return (0, buf)

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
    SMB_QUERY_FILE_BASIC_INFO: generate_query_file_basic_info,
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
        return (yield from future)
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
            toret = self._open_tids[req.header.tid]
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
        if req.header.uid not in self._open_uids:
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
            try:
                fidmd = yield from self.destroy_file(fid)
            except KeyError:
                return
            yield from fidmd['handle'].close()

        for fid, value in self._open_files.items():
            if value['tid'] != tid: continue
            waiting.append(asyncio.async(destroy_close_file(fid), loop=self._loop))

        @asyncio.coroutine
        def destroy_close_search(sid):
            try:
                searchmd = yield from self.destroy_search(sid)
            except KeyError:
                return
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
            try:
                fs = yield from self.destroy_tree(tid)
            except KeyError:
                return
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
    def create_file(self, path, handle, tid):
        fid = self._create_id(self._open_files, INVALID_FIDS)
        self._open_files[fid] = dict(path=path,
                                     ref=0,
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
        return (yield from reader.read(length))

    @classmethod
    @asyncio.coroutine
    def send_message(cls, writer, raw_data):
        writer.writelines([struct.pack(">I", len(raw_data)),
                           raw_data])

    @asyncio.coroutine
    def run(self, server, backend, loop, master_kill, reader, writer):
        self._loop = loop

        # first negotiate SMB protocol
        negotiate_req_raw = yield from self.read_message(reader)
        if negotiate_req_raw is None:
            raise Exception("Received client EOF!")

        negotiate_req = decode_smb_message(negotiate_req_raw)

        if negotiate_req.header.command != SMB_COM_NEGOTIATE:
            raise Exception("Got unexpected request: %s" % (negotiate_req,))

        server_capabilities = (CAP_UNICODE |
                               CAP_LARGE_FILES |
                               CAP_STATUS32 |
                               CAP_NT_SMBS |
                               CAP_NT_FIND)

        # win32 time
        now = datetime.utcnow()
        win32_time = datetime_to_win32(now)
        negotiate_reply_params = quick_container(
            # TODO: catch this and throw a friendlier error
            dialect_index=negotiate_req.data.dialects.index('NT LM 0.12'),
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

        negotiate_resp = SMBMessage(reply_header_from_request(negotiate_req),
                                    negotiate_reply_params,
                                    quick_container(challenge=b'', domain_name=''))

        yield from self.send_message(writer, encode_smb_message(negotiate_resp))

        # okay now kick off SMB connection machinery

        @asyncio.coroutine
        def read_client(reader, writer_queue):
            try:
                read_future = asyncio.async(self.read_message(reader),
                                            loop=loop)
                in_flight_requests = set()
                while True:
                    (done, pending) = yield from asyncio.wait(itertools.chain([read_future, master_kill],
                                                                              in_flight_requests),
                                                              return_when=asyncio.FIRST_COMPLETED,
                                                              loop=loop)
                    for fut in done:
                        try:
                            in_flight_requests.remove(fut)
                        except KeyError:
                            pass

                    if master_kill in done:
                        break

                    if read_future in done:
                        raw_msg = read_future.result()

                        if not raw_msg:
                            log.debug("EOF from client, closing connection")
                            break

                        header = decode_smb_header(raw_msg[:SMB_HEADER_STRUCT_SIZE])

                        # kick off concurrent request handler
                        @asyncio.coroutine
                        def real_handle_request(header, payload):
                            try:
                                (parameters, data) = decode_smb_payload(header, payload)
                                msg = SMBMessage(header, parameters, data)
                                ret = yield from handle_request(server, server_capabilities,
                                                                self, backend, msg)
                                ret = encode_smb_message(ret)
                            except ProtocolError as e:
                                if e.error not in (STATUS_NO_SUCH_FILE,):
                                    log.debug("Protocol Error!!! Command:0x%x %r",
                                              header.command, e)
                                ret = encode_smb_message(error_response(header, e.error))
                            except Exception:
                                log.exception("Unexpected exception!")
                                ret = encode_smb_message(error_response(header))

                            yield from writer_queue.put(ret)

                        reqfut = asyncio.async(
                            real_handle_request(header,
                                                raw_msg[SMB_HEADER_STRUCT_SIZE:]),
                            loop=loop)
                        in_flight_requests.add(reqfut)
                        read_future = asyncio.async(self.read_message(reader),
                                                    loop=loop)
            finally:
                # release resources associated with connection
                yield from self.hard_destroy_all_trees(server, backend)

                # wait for all in flight requests to be done
                if in_flight_requests:
                    yield from asyncio.wait(in_flight_requests, loop=loop)

                # we have died, signal to writer coroutine to die as well
                yield from writer_queue.put(None)

        @asyncio.coroutine
        def write_client(writer, queue):
            while True:
                msg = yield from queue.get()
                if msg is None: break
                yield from self.send_message(writer, msg)

        writer_queue = asyncio.Queue(loop=loop)

        # start up reader/writer coroutines
        read_client_future = asyncio.async(read_client(reader, writer_queue),
                                           loop=loop)
        try:
            yield from write_client(writer, writer_queue)
        finally:
            # make sure read client is dead
            (done, pending) = yield from asyncio.wait([read_client_future],
                                                      loop=loop)
            assert len(done) == 1
            # propagate client reader exception (if any)
            done.pop().result()

@asyncio.coroutine
def handle_request(server, server_capabilities, cs, backend, req):
    @asyncio.coroutine
    def smb_path_to_fs_path(path):
        comps = path[1:].split("\\")
        if comps and not comps[-1]:
            comps.pop()
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

    def verify_andx(req):
        if req.parameters.andx_command != 0xff:
            raise Exception("Do not support andx chains!")

    if req.header.command == SMB_COM_SESSION_SETUP_ANDX:
        verify_andx(req)

        if req.parameters.capabilities & ~server_capabilities:
            log.warning("Client's capabilities aren't a subset of Server's: 0x%x vs 0x%x",
                        req.parameters.capabilities, server_capabilities)

        uid = yield from cs.create_session()

        header = reply_header_from_request(req, uid=uid)
        parameters = quick_container(action=1,
                                     **DEFAULT_ANDX_PARAMETERS)
        data = quick_container(native_os='Unix', native_lan_man='DropboxFS',
                               primary_domain=req.data.primary_domain)
        return SMBMessage(header, parameters, data)
    elif req.header.command == SMB_COM_TREE_CONNECT_ANDX:
        verify_andx(req)

        yield from cs.verify_uid(req)

        if req.parameters.flags & TREE_CONNECT_ANDX_DISCONNECT_TID:
            try:
                fs = yield from cs.destroy_tree(req.tid)
            except KeyError:
                # NB: this is allowed to fail silently
                pass
            else:
                yield from backend.tree_disconnect(server, fs)

        if req.data.service not in ("?????", "A:"):
            log.debug("Client attempted to connect to %r service",
                      req.data.service)
            raise ProtocolError(STATUS_OBJECT_PATH_NOT_FOUND)

        try:
            fs = yield from backend.tree_connect(server, req.data.path)
        except KeyError:
            log.debug("Error tree connect: %r", req.data.path)
            raise ProtocolError(STATUS_OBJECT_PATH_NOT_FOUND)

        tid = yield from cs.create_tree(fs)

        header = reply_header_from_request(req, tid=tid)
        parameters = quick_container(optional_support=SMB_TREE_CONNECTX_SUPPORT_SEARCH,
                                     **DEFAULT_ANDX_PARAMETERS)
        data = quick_container(service="A:",
                               native_file_system="FAT")
        return SMBMessage(header, parameters, data)
    elif req.header.command == SMB_COM_TREE_DISCONNECT:
        yield from cs.verify_uid(req)

        try:
            fs = yield from cs.destroy_tree(req.header.tid)
        except KeyError:
            raise ProtocolError(STATUS_SMB_BAD_TID)

        yield from backend.tree_disconnect(server, fs)

        return SMBMessage(reply_header_from_request(req), None, None)
    elif req.header.command == SMB_COM_CHECK_DIRECTORY:
        yield from cs.verify_uid(req)
        fs = yield from cs.verify_tid(req)
        try:
            fspath = yield from smb_path_to_fs_path(req.data.filename)

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

            return SMBMessage(reply_header_from_request(req), None, None)
        finally:
            yield from cs.deref_tid(req.tid)
    elif req.header.command == SMB_COM_ECHO:
        log.debug("echo...")
        if req.parameters.echo_count > 1:
            raise Exception("Echo count is too high: %r" %
                            (req.parameters.echo_count,))

        return SMBMessage(reply_header_from_request(req),
                          quick_container(sequence_number=0),
                          req.data)
    elif req.header.command == SMB_COM_TRANSACTION2:
        yield from cs.verify_uid(req)
        fs = yield from cs.verify_tid(req)
        try:
            if req.parameters.timeout:
                raise Exception("Transaction2 Delayed request not supported!")

            if (req.parameters.total_parameter_count != req.parameters.parameter_count or
                req.parameters.total_data_count != req.parameters.data_count):
                raise Exception("Multiple TRANSACTION2 packets not supported!")

            if req.parameters.flags:
                # NBL we don't current support DISCONNECT_TID nor NO_RESPONSE
                raise Exception("Transaction 2 flags not supported!")

            (trans2_type, trans2_params, trans2_data) = decode_transaction_2_request_message(req)

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

            MAX_ALIGNMENT_PADDING = 6

            # go through another layer of parsing
            if trans2_type == SMB_TRANS2_FIND_FIRST2:
                (search_attributes, search_count,
                 flags, information_level,
                 ) = (trans2_params.search_attributes,
                       trans2_params.search_count,
                       trans2_params.flags,
                       trans2_params.information_level,
                       )
                filename = trans2_params.filename

                if not (search_attributes & SMB_FILE_ATTRIBUTE_DIRECTORY):
                    raise NotImplementedError("Search attributes not implemented: 0x%x" % (search_attributes,))

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

                        entry = None
                        next_entry = None

                        for idx, ent in enumerate((yield from handle.readmany(2))):
                            if idx == 0:
                                entry = (ent.name, (yield from normalize_dir_entry(ent)))
                            else:
                                assert idx == 1
                                next_entry = (ent.name, (yield from normalize_dir_entry(ent)))

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
                except NotADirectoryError:
                    raise ProtocolError(STATUS_OBJECT_PATH_SYNTAX_BAD)

                PARAMS_FMT = "<HHHHH"
                PARAMS_SIZE = struct.calcsize(PARAMS_FMT)

                max_data_count = min(req.parameters.max_data_count,
                                     SMB_MAX_DATA_PAYLOAD - MAX_ALIGNMENT_PADDING -
                                     PARAMS_SIZE)

                (data, num_entries_to_ret, entry, next_entry,
                 buffered_entries, buffered_entries_idx) = \
                    yield from generate_find_data(max_data_count,
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
                                                      tid=req.header.tid)

                data_bytes = b''.join(data)
                last_name_offset = (0
                                    if is_search_over else
                                    len(data_bytes) - len(data[-1]))

                assert information_level != SMB_INFO_QUERY_EAS_FROM_LIST
                ea_error_offset = 0

                setup = []
                params_bytes = struct.pack(PARAMS_FMT,
                                           sid, num_entries_to_ret,
                                           int(is_search_over),
                                           ea_error_offset,
                                           0 if is_search_over else
                                           last_name_offset)
            elif trans2_type == SMB_TRANS2_FIND_NEXT2:
                (sid, search_count, information_level,
                 resume_key, flags) = (trans2_params.sid, trans2_params.search_count,
                                       trans2_params.information_level,
                                       trans2_params.resume_key, trans2_params.flags)
                if resume_key:
                    raise NotImplementedError("resume key is not yet handled")

                filename = trans2_params.filename

                try:
                    info_generator = INFO_GENERATORS[information_level]
                except KeyError:
                    raise ProtocolError(STATUS_OS2_INVALID_LEVEL,
                                        "Find First Information level not supported: %r" %
                                        (information_level,))


                search_md = yield from cs.ref_search(sid)
                try:
                    PARAMS_FMT = "<HHHH"
                    PARAMS_SIZE = struct.calcsize(PARAMS_FMT)

                    max_data_count = min(req.parameters.max_data_count,
                                         SMB_MAX_DATA_PAYLOAD - MAX_ALIGNMENT_PADDING
                                         - PARAMS_SIZE)

                    (data, num_entries_to_ret,
                     entry, next_entry,
                     search_md['buffered_entries'], search_md['buffered_entries_idx']) = \
                        yield from generate_find_data(max_data_count,
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
                finally:
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

                setup = []
                params_bytes = struct.pack(PARAMS_FMT,
                                           num_entries_to_ret,
                                           int(is_search_over),
                                           ea_error_offset,
                                           last_name_offset)
            elif trans2_type == SMB_TRANS2_QUERY_FS_INFORMATION:
                (information_level,) = (trans2_params.information_level,)

                try:
                    fs_info_generator = FS_INFO_GENERATORS[information_level]
                except KeyError:
                    raise ProtocolError(STATUS_OS2_INVALID_LEVEL,
                                        "QUERY FS Information level not supported: %r" %
                                        (information_level,))

                data_bytes = fs_info_generator()

                setup = []
                params_bytes = b''
            elif trans2_type == SMB_TRANS2_QUERY_PATH_INFORMATION:
                (information_level,) = (trans2_params.information_level,)

                try:
                    query_path_info_generator = QUERY_FILE_INFO_GENERATORS[information_level]
                except KeyError:
                    raise ProtocolError(STATUS_OS2_INVALID_LEVEL,
                                        "QUERY PATH Information level not supported: %r" %
                                        (information_level,))

                path = trans2_params.filename
                fspath = yield from smb_path_to_fs_path(path)

                try:
                    md = yield from fs.stat(fspath)
                except FileNotFoundError:
                    raise ProtocolError(STATUS_NO_SUCH_FILE)
                except NotADirectoryError:
                    raise ProtocolError(STATUS_OBJECT_PATH_SYNTAX_BAD)

                setup = []
                name = fspath.name if fspath.name else '\\'
                (ea_error_offset, data_bytes) = query_path_info_generator(name, normalize_stat(md))
                params_bytes = struct.pack("<H", ea_error_offset)
            elif trans2_type == SMB_TRANS2_QUERY_FILE_INFORMATION:
                try:
                    query_file_info_generator = QUERY_FILE_INFO_GENERATORS[trans2_params.information_level]
                except KeyError:
                    raise ProtocolError(STATUS_OS2_INVALID_LEVEL,
                                        "QUERY FILE Information level not supported: %r" %
                                        (trans2_params.information_level,))

                try:
                    fid_md = yield from cs.ref_file(trans2_params.fid)
                except KeyError:
                    raise ProtocolError(STATUS_INVALID_HANDLE)

                try:
                    file_path = fid_md['path']
                    md = yield from fs.fstat(fid_md['handle'])
                finally:
                    yield from cs.deref_file(trans2_params.fid)

                setup = []
                fspath = yield from smb_path_to_fs_path(file_path)
                name = fspath.name if fspath.name else '\\'
                (ea_error_offset, data_bytes) = query_file_info_generator(name, normalize_stat(md))
                params_bytes = struct.pack("<H", ea_error_offset)
            elif trans2_type == SMB_TRANS2_SET_FILE_INFORMATION:
                if trans2_params.information_level != SMB_SET_FILE_END_OF_FILE_INFO:
                    raise ProtocolError(STATUS_OS2_INVALID_LEVEL,
                                        "SET FILE INFORMATION Information level not supported: %r" %
                                        (trans2_params.information_level,))

                try:
                    fid_md = yield from cs.ref_file(trans2_params.fid)
                except KeyError:
                    raise ProtocolError(STATUS_INVALID_HANDLE)
                try:
                    yield from fid_md['handle'].seek(trans2_data.end_of_file)
                    yield from fid_md['handle'].truncate()
                finally:
                    yield from cs.deref_file(trans2_params.fid)

                setup = []
                data_bytes = b''
                params_bytes = b''
            else:
                log.warning("TRANS2 Sub command not supported: %02x, %s" % (trans2_type, req))
                raise ProtocolError(STATUS_NOT_SUPPORTED)

            assert len(setup) * 2 <= req.parameters.max_setup_count, "TRANSACTION2 setup bytes count is too large %r vs required %r" % (len(setup) * 2, req.parameters.max_setup_count)
            assert len(params_bytes) <= req.parameters.max_parameter_count, "TRANSACTION2 params bytes count is too large %r vs required %r" % (len(params_bytes), req.parameters.max_parameter_count)
            assert len(data_bytes) <= req.parameters.max_data_count, "TRANSACTION2 data bytes count is too large %r vs required %r" % (len(data_bytes), req.parameters.max_data_count)

            parameters = quick_container(
                total_parameter_count=len(params_bytes),
                total_data_count=len(data_bytes),
                parameter_count=len(params_bytes),
                parameter_displacement=0,
                data_count=len(data_bytes),
                data_displacement=0,
                setup=setup,
            )
            data = quick_container(parameters=params_bytes,
                                   data=data_bytes)
            return SMBMessage(reply_header_from_request(req),
                              parameters,
                              data)
        finally:
            yield from cs.deref_tid(req.header.tid)
    elif req.header.command == SMB_COM_QUERY_INFORMATION_DISK:
        yield from cs.verify_uid(req)
        fs = yield from cs.verify_tid(req)
        try:
            parameters = quick_container(total_units=2 ** 16 - 1,
                                         blocks_per_unit=16384,
                                         block_size=512,
                                         free_units=0
            )
            return SMBMessage(reply_header_from_request(req),
                              parameters, None)
        finally:
            yield from cs.deref_tid(req.header.tid)
    elif req.header.command == SMB_COM_NT_CREATE_ANDX:
        verify_andx(req)

        header = req.parameters

        yield from cs.verify_uid(req)
        fs = yield from cs.verify_tid(req)
        try:
            if (header.flags &
                (
                 NT_CREATE_OPEN_TARGET_DIR)):
                raise Exception("SMB_COM_NT_CREATE_ANDX doesn't support flags! 0x%x" % (header.flags,))

            # NB: We only support full sharing for now
            # TODO: will this be a problem on windows? we can't support
            #       blocking FILE_SHARE_DELETE on most FSes
            if ((header.share_access &
                 (FILE_SHARE_DELETE | FILE_SHARE_WRITE | FILE_SHARE_READ)) !=
                (FILE_SHARE_DELETE | FILE_SHARE_WRITE | FILE_SHARE_READ)):
                raise ProtocolError(STATUS_SHARING_VIOLATION)

            mode = 0

            wants_read = (header.desired_access &
                          (GENERIC_READ | FILE_READ_DATA | MAXIMUM_ALLOWED | GENERIC_EXECUTE |
                           GENERIC_ALL))
            wants_write = (header.desired_access &
                           (GENERIC_WRITE | FILE_WRITE_DATA | MAXIMUM_ALLOWED | GENERIC_ALL))

            if wants_read and wants_write:
                mode = mode | os.O_RDWR
            elif wants_read:
                mode = mode | os.O_RDONLY
            elif wants_write:
                mode = mode | os.O_WRONLY
            else:
                log.warn("Isn't requesting any READ/WRITE privileges: 0x%x", header.desired_access)

            # we don't support supersede for now
            if header.create_disposition == FILE_SUPERSEDE:
                raise ProtocolError(STATUS_ACCESS_DENIED)
            elif header.create_disposition == FILE_CREATE:
                mode = mode | os.O_CREAT | os.O_EXCL
            elif header.create_disposition == FILE_OPEN_IF:
                mode = mode | os.O_CREAT
            elif header.create_disposition == FILE_OVERWRITE:
                mode = mode | os.O_TRUNC
            elif header.create_disposition == FILE_OVERWRITE_IF:
                mode = mode | os.O_CREAT | os.O_TRUNC

            if header.create_options & FILE_DELETE_ON_CLOSE:
                raise ProtocolError(STATUS_ACCESS_DENIED)

            if header.create_options & FILE_OPEN_BY_FILE_ID:
                raise ProtocolError(STATUS_NOT_SUPPORTED)

            if header.root_directory_fid:
                try:
                    root_md = yield from cs.ref_file(header.root_directory_fid)
                except KeyError:
                    raise ProtocolError(STATUS_INVALID_HANDLE)
                try:
                    root_path = root_md['path']
                finally:
                    yield from cs.deref_file(header.root_directory_fid)
            else:
                root_path = ""

            file_path = root_path + req.data.filename

            is_directory = False
            path = yield from smb_path_to_fs_path(file_path)
            try:
                handle = yield from fs.open(path, mode, header.create_options & FILE_DIRECTORY_FILE)
                md = yield from fs.fstat(handle)
            except FileExistsError:
                raise ProtocolError(STATUS_OBJECT_NAME_COLLISION)
            except FileNotFoundError:
                raise ProtocolError(STATUS_NO_SUCH_FILE)
            except NotADirectoryError:
                raise ProtocolError(STATUS_OBJECT_PATH_SYNTAX_BAD)

            is_directory = md.type == "directory"

            if (is_directory and
                header.create_options & FILE_NON_DIRECTORY_FILE):
                yield from handle.close()
                raise ProtocolError(STATUS_FILE_IS_A_DIRECTORY)

            fid = yield from cs.create_file(file_path,
                                            handle,
                                            req.header.tid)

            directory = int(is_directory)
            ext_attr = (ATTR_DIRECTORY
                        if directory else
                        ATTR_NORMAL)

            file_data_size = get_size(md)

            FILE_TYPE_DISK = 0

            md2 = normalize_stat(md)

            log.debug("Opening file_path: %r, %r", file_path, fid)

            parameters = quick_container(op_lock_level=0,
                                         fid=fid,
                                         create_disposition=header.create_disposition,
                                         create_time=datetime_to_win32(md2.birthtime),
                                         last_access_time=datetime_to_win32(md2.atime),
                                         last_write_time=datetime_to_win32(md2.mtime),
                                         last_change_time=datetime_to_win32(md2.ctime),
                                         ext_file_attributes=ext_attr,
                                         allocation_size=4096,
                                         end_of_file=file_data_size,
                                         resource_type=FILE_TYPE_DISK,
                                         nm_pipe_status=0,
                                         directory=directory,
                                         **DEFAULT_ANDX_PARAMETERS)
            return SMBMessage(reply_header_from_request(req),
                              parameters, None)
        finally:
            yield from cs.deref_tid(req.header.tid)
    elif req.header.command == SMB_COM_READ_ANDX:
        verify_andx(req)

        request = req.parameters
        yield from cs.verify_uid(req)
        fs = yield from cs.verify_tid(req)
        try:
            log.debug("About to read file... %r", request.fid)

            try:
                fid_md = yield from cs.ref_file(request.fid)
            except KeyError:
                raise ProtocolError(STATUS_INVALID_HANDLE)
            try:
                log.debug("About to do pread... %r, offset: %r, amt: %r",
                          fid_md['path'], request.offset,
                          request.max_count_of_bytes_to_return)

                buf = yield from fid_md['handle'].pread(request.offset, request.max_count_of_bytes_to_return)

                log.debug("PREAD DONE... %r buf len: %r", fid_md['path'], len(buf))
            finally:
                yield from cs.deref_file(request.fid)

            parameters = quick_container(available=0,
                                      data_length=len(buf),
                                      **DEFAULT_ANDX_PARAMETERS)

            return SMBMessage(reply_header_from_request(req),
                              parameters, buf)
        finally:
            yield from cs.deref_tid(req.header.tid)
    elif req.header.command == SMB_COM_CLOSE:
        request = req.parameters
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

            return SMBMessage(reply_header_from_request(req), None, None)
        finally:
            yield from cs.deref_tid(req.header.tid)
    elif req.header.command == SMB_COM_NT_TRANSACT:
        yield from cs.verify_uid(req)
        fs = yield from cs.verify_tid(req)
        try:
            (function, nt_transact_setup,
             nt_transact_parameters, nt_transact_data) = \
                decode_nt_transact_request_message(req)

            if function == NT_TRANSACT_NOTIFY_CHANGE:
                (completion_filter, fid, watch_tree) = (
                    nt_transact_setup.completion_filter,
                    nt_transact_setup.fid,
                    nt_transact_setup.watch_tree,
                    )

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
                data_bytes = b''

                parameters = quick_container(total_parameter_count=len(param_bytes),
                                             total_data_count=len(data_bytes),
                                             parameter_count=len(param_bytes),
                                             parameter_displacement=0,
                                             data_count=len(data_bytes),
                                             data_displacement=0,
                                             setup=b'')

                data = quick_container(parameters=param_bytes,
                                       data=data_bytes)

                return SMBMessage(reply_header_from_request(req),
                                  parameters, data)
        finally:
            yield from cs.deref_tid(req.header.tid)
    elif req.header.command == SMB_COM_WRITE_ANDX:
        verify_andx(req)
        yield from cs.verify_uid(req)
        fs = yield from cs.verify_tid(req)
        try:
            try:
                fid_md = yield from cs.ref_file(req.parameters.fid)
            except KeyError:
                raise ProtocolError(STATUS_INVALID_HANDLE)
            try:
                log.debug("PWRITE START... %r, offset: %r, amt: %r",
                          fid_md['path'], req.parameters.offset,
                          req.parameters.data_length)

                if req.parameters.timeout:
                    log.warning("Got timeout value for SMB_COM_WRITE: %r, ignoring...",
                                req.parameters.timeout)

                amt = yield from fid_md['handle'].pwrite(req.data, req.parameters.offset)

                WRITE_THROUGH_MODE = 0x1
                if req.parameters.write_mode & WRITE_THROUGH_MODE:
                    yield from fs.fsync(fid_md['handle'])

                log.debug("PWRITE DONE... %r buf len: %r", fid_md['path'], amt)
            finally:
                yield from cs.deref_file(req.parameters.fid)

            parameters = quick_container(count=amt,
                                         available=0xffff,
                                         **DEFAULT_ANDX_PARAMETERS)

            return SMBMessage(reply_header_from_request(req),
                              parameters, None)
        finally:
            yield from cs.deref_tid(req.header.tid)
    elif req.header.command == SMB_COM_FLUSH:
        yield from cs.verify_uid(req)
        fs = yield from cs.verify_tid(req)
        try:
            try:
                fid_md = yield from cs.ref_file(req.parameters.fid)
            except KeyError:
                raise ProtocolError(STATUS_INVALID_HANDLE)
            try:
                yield from fs.fsync(fid_md['handle'])
            finally:
                yield from cs.deref_file(req.parameters.fid)


            return SMBMessage(reply_header_from_request(req),
                              None, None)
        finally:
            yield from cs.deref_tid(req.header.tid)
    elif req.header.command == SMB_COM_DELETE:
        yield from cs.verify_uid(req)
        fs = yield from cs.verify_tid(req)
        try:
            if req.data.buffer_format != 0x4:
                raise Exception("Buffer format not accepted!")
            path = yield from smb_path_to_fs_path(req.data.filename)

            try:
                yield from fs.unlink(path)
            except FileNotFoundError:
                raise ProtocolError(STATUS_NO_SUCH_FILE)
            except NotADirectoryError:
                raise ProtocolError(STATUS_OBJECT_PATH_SYNTAX_BAD)

            return SMBMessage(reply_header_from_request(req),
                              None, None)
        finally:
            yield from cs.deref_tid(req.header.tid)
    elif req.header.command == SMB_COM_CREATE_DIRECTORY:
        yield from cs.verify_uid(req)
        fs = yield from cs.verify_tid(req)
        try:
            if req.data.buffer_format != 0x4:
                raise Exception("Buffer format not accepted!")
            path = yield from smb_path_to_fs_path(req.data.filename)

            try:
                yield from fs.mkdir(path)
            except FileNotFoundError:
                raise ProtocolError(STATUS_OBJECT_PATH_NOT_FOUND)
            except FileExistsError:
                raise ProtocolError(STATUS_OBJECT_NAME_COLLISION)
            except NotADirectoryError:
                raise ProtocolError(STATUS_OBJECT_PATH_SYNTAX_BAD)

            return SMBMessage(reply_header_from_request(req),
                              None, None)
        finally:
            yield from cs.deref_tid(req.header.tid)
    elif req.header.command == SMB_COM_DELETE_DIRECTORY:
        yield from cs.verify_uid(req)
        fs = yield from cs.verify_tid(req)
        try:
            if req.data.buffer_format != 0x4:
                raise Exception("Buffer format not accepted!")
            path = yield from smb_path_to_fs_path(req.data.filename)

            try:
                yield from fs.rmdir(path)
            except FileNotFoundError:
                raise ProtocolError(STATUS_NO_SUCH_FILE)
            except FileExistsError:
                raise ProtocolError(STATUS_DIRECTORY_NOT_EMPTY)
            except NotADirectoryError:
                raise ProtocolError(STATUS_OBJECT_PATH_INVALID)
            except OSError as e:
                if e.errno == errno.ENOTEMPTY:
                    raise ProtocolError(STATUS_DIRECTORY_NOT_EMPTY)
                else:
                    raise

            return SMBMessage(reply_header_from_request(req),
                              None, None)
        finally:
            yield from cs.deref_tid(req.header.tid)
    elif req.header.command == SMB_COM_RENAME:
        yield from cs.verify_uid(req)
        fs = yield from cs.verify_tid(req)
        try:
            if (req.data.buffer_format_1 != 0x4 or
                req.data.buffer_format_2 != 0x4):
                raise Exception("Buffer format not accepted!")
            old_path = yield from smb_path_to_fs_path(req.data.old_filename)
            new_path = yield from smb_path_to_fs_path(req.data.new_filename)

            try:
                yield from fs.rename_noreplace(old_path, new_path)
            except FileNotFoundError:
                raise ProtocolError(STATUS_NO_SUCH_FILE)
            except FileExistsError:
                raise ProtocolError(STATUS_OBJECT_NAME_COLLISION)
            except NotADirectoryError:
                raise ProtocolError(STATUS_OBJECT_PATH_SYNTAX_BAD)

            return SMBMessage(reply_header_from_request(req),
                              None, None)
        finally:
            yield from cs.deref_tid(req.header.tid)

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

    @asyncio.coroutine
    def fsync(self, handle):
        # NB: we have to unwrap the async handle
        return (yield from self._worker_pool.run_async(self._obj.fsync,
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
        self._master_kill = asyncio.Future(loop=self._loop)

        @asyncio.coroutine
        def handle_client(reader, writer):
            try:
                yield from SMBClientHandler().run(self, async_backend, self._loop,
                                                  self._master_kill,
                                                  reader, writer)
            except Exception:
                log.exception("Client handler failed!")
            else:
                log.debug("client done!")
            finally:
                writer.close()

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
            self._master_kill.set_result(None)
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
