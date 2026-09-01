#!/usr/bin/env python3
"""
TCP Hole Punch Relay Server v3.0 - ICE-Lite Edition
Entry Point
"""
import asyncio
import argparse
import logging
from .relay import TCPRelayServerICE

# Default values
# Gemessen: bei einem Band von 251 Ports und 16 gleichzeitig gehaltenen
# lokalen Ports auf der Gegenseite genuegen 32 gedeckte Ports fuer 12/12
# erfolgreiche Versuche — genauso zuverlaessig wie 368 gedeckte Ports, aber
# mit 48 statt 376 Sockets und einem schnelleren Punch (228 statt 271 ms).
# 64 statt 32 als Vorgabe laesst Luft fuer Baender bis etwa doppelter Breite,
# bei denen 32 nicht mehr reichen wuerden.
DEFAULT_MAX_SCAN_PORTS = 64

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


async def main():
    parser = argparse.ArgumentParser(description='TCP Relay Server v3.0 (ICE-Lite)')
    parser.add_argument('--host', default='0.0.0.0', help='Host to bind to')
    parser.add_argument('--port', type=int, default=9999, help='Main port')
    parser.add_argument('--probe-port', type=int, default=9998, help='Probe port for NAT analysis')
    parser.add_argument('--probe-port2', type=int, default=9997,
                        help='Zweiter Probe-Port: nur mit ihm laesst sich das '
                             'Mapping-Verhalten nach RFC 4787 bestimmen')
    parser.add_argument(
        '--max-scan-ports',
        type=int,
        default=DEFAULT_MAX_SCAN_PORTS,
        help=f'Max candidate ports to send to clients (default: {DEFAULT_MAX_SCAN_PORTS})',
    )
    args = parser.parse_args()

    if args.max_scan_ports < 1:
        parser.error('--max-scan-ports must be >= 1')
    
    server = TCPRelayServerICE(
        args.host,
        args.port,
        args.probe_port,
        max_scan_ports=args.max_scan_ports,
        probe_port2=args.probe_port2,
    )
    await server.start()


if __name__ == '__main__':
    asyncio.run(main())