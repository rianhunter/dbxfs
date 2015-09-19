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
import socketserver
import struct
import sys
import time

from datetime import datetime
from io import StringIO

# hack smb struct defs from PySMB
import smb.smb_structs as smb_structs

log = logging.getLogger(__name__)

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
            self.payload = smb_structs.ComTransaction2Request()
        elif self.command == smb_structs.SMB_COM_OPEN_ANDX:
            self.payload = smb_structs.ComOpenAndxRequest()
        elif self.command == smb_structs.SMB_COM_NT_CREATE_ANDX:
            self.payload = smb_structs.ComNTCreateAndxRequest()
        elif self.command == smb_structs.SMB_COM_TREE_CONNECT_ANDX:
            self.payload = smb_structs.ComTreeConnectAndxRequest()
        elif self.command == smb_structs.SMB_COM_ECHO:
            self.payload = smb_structs.ComEchoRequest()
        elif self.command == smb_structs.SMB_COM_SESSION_SETUP_ANDX:
            self.payload = smb_structs.ComSessionSetupAndxRequest()
        elif self.command == smb_structs.SMB_COM_NEGOTIATE:
            self.payload = ComNegotiateRequest()

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
        message.data = b''


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

        # win32 time
        ts = time.time()
        win32_time = (int(ts) + 11644473600) * 10000000
        utc_offset = int(-(datetime.fromtimestamp(ts) -
                           datetime.utcfromtimestamp(ts)).total_seconds())
        args = dict(
            # TODO: catch this and throw a friendlier error
            dialect_index=negotiate_req.payload.dialects.index('NT LM 0.12'),
            security_mode=0, # we support NO SECURITY FEATURES
            max_mpx_count=2 ** 16 - 1, # unlimited clients baby
            max_number_vcs=2 ** 16 - 1, # not sure what this means
            max_buffer_size=2 ** 16 - 1, # this doesn't matter
            max_raw_size=2 ** 16 - 1, # this doesn't matter
            session_key=0, # can be anything, we don't use it
            capabilities=0, # n/s yet
            system_time=win32_time,
            server_time_zone=utc_offset,
            challenge_length=0,
        )

        negotiate_resp = smb_structs.SMBMessage(ComNegotiateResponse(**args))
        # TODO: set flags? status?

        self.send_message(negotiate_resp)

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
