#!/usr/bin/env python3

import argparse
import binascii
import socket
import struct
import threading
import os
import sys

import aiohttp
from aiohttp import web

# Configuration
PORT_BLOBS = 9021
PORT_DEBUG = 9022

# Context
current_file = None

# Sockets
def server_blobs():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.bind(('', PORT_BLOBS))
    except socket.error as msg:
        print('blobs-server: Bind failed: %s\n' % msg)
        sys.exit()
    s.listen(5)
    while True:
        c, addr = s.accept()
        print('blobs-server: Client connected: %s:%s' % addr)
        while True:
            # File path
            path_size = c.recv(8, socket.MSG_WAITALL)
            if not path_size: break
            path_size = struct.unpack('Q', path_size)[0]
            if not path_size: break
            path = c.recv(path_size, socket.MSG_WAITALL)
            path = os.path.join('dump', path.decode('utf-8'))
            # File data
            data_size = c.recv(8, socket.MSG_WAITALL)
            if not data_size: break
            data_size = struct.unpack('Q', data_size)[0]
            if not data_size: break
            data = c.recv(data_size, socket.MSG_WAITALL)
            # Save file
            path_dir = os.path.dirname(path)
            if path_dir and not os.path.exists(path_dir):
                os.makedirs(path_dir, exist_ok=True)
            with open(path, 'wb') as f:
                f.write(data)
        print('blobs-server: Client disconnected: %s:%s' % addr)
        c.close()
    s.close()

def server_debug():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.bind(('', PORT_DEBUG))
    except socket.error as msg:
        print('debug-server: Bind failed: %s\n' % msg)
        sys.exit()
    s.listen(5)
    while True:
        c, addr = s.accept()
        print('debug-server: Client connected: %s:%s' % addr)
        while True:
            # TODO: There's surely a better way, but whatever
            byte = c.recv(1)
            if not byte:
                break
            sys.stdout.buffer.write(byte)
            sys.stdout.flush()
        print('debug-server: Client disconnected: %s:%s' % addr)
        c.close()
    s.close()

# Website
async def handle_index(request):
    return web.FileResponse('./index.html')

async def handle_websocket(request):
    ws = web.WebSocketResponse()
    await ws.prepare(request)
    async for msg in ws:
        if msg.type == aiohttp.WSMsgType.TEXT:
            current_file = os.path.normpath(
                os.path.join('dump', msg.data))
        elif msg.type == aiohttp.WSMsgType.BINARY and current_file:
            os.makedirs(os.path.dirname(current_file), exist_ok=True)
            with open(current_file, 'wb') as f:
                f.write(msg.data)
        elif msg.type == aiohttp.WSMsgType.ERROR:
            print('WS connection closed with exception %s' % ws.exception())
    print('WS connection closed')
    return ws

def main():
    # Handle arguments
    parser = argparse.ArgumentParser(
        description='Create server for Orbital dumper.')
    parser.add_argument('-p', '--port', type=int, default=80, required=False,
        help='Port for HTTP/WS server')
    args = parser.parse_args()

    # Create sockets
    t_blobs = threading.Thread(target=server_blobs)
    t_debug = threading.Thread(target=server_debug)
    t_blobs.start()
    t_debug.start()
    
    # Create webserver
    app = web.Application()
    app.router.add_get('/', handle_index)
    app.router.add_get('/ws', handle_websocket)
    app.router.add_static('/', path='.')
    web.run_app(app, port=args.port)

if __name__ == '__main__':
    main()
