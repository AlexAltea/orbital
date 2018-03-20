#!/usr/bin/env python3

import argparse
import os

import aiohttp
from aiohttp import web

# Context
current_file = None

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

    # Create server
    app = web.Application()
    app.router.add_get('/', handle_index)
    app.router.add_get('/ws', handle_websocket)
    app.router.add_static('/', path='.')
    web.run_app(app, port=args.port)

if __name__ == '__main__':
    main()
