"""
TCP Hole Punch Relay Server - Utility Functions
"""
import asyncio
import json
import logging
from typing import Dict, List, Set

logger = logging.getLogger(__name__)

MIN_PORT = 1024
MAX_PORT = 65535


async def send_message(writer: asyncio.StreamWriter, msg: dict):
    """Send JSON message to client"""
    data = json.dumps(msg) + '\n'
    writer.write(data.encode())
    await writer.drain()


async def send_error(writer: asyncio.StreamWriter, message: str):
    """Send error message to client"""
    await send_message(writer, {'type': 'error', 'message': message})


def get_peer_addresses_with_prediction(peer, other, max_scan_ports: int) -> List[Dict]:
    """
    Get addresses including scan range from NAT analysis
    
    Args:
        peer: The peer whose addresses to build
        other: The other peer in the session
        max_scan_ports: Maximum number of scan ports to include
    
    Returns:
        List of address dictionaries with ip, port, type, and priority
    """
    from ..nat_analyzer import build_candidate_ports
    
    addresses = []
    seen: Set[tuple] = set()

    def add_address(ip: str, port: int, addr_type: str, priority: int):
        key = (ip, port)
        if key in seen:
            return
        seen.add(key)
        addresses.append({
            'ip': ip,
            'port': port,
            'type': addr_type,
            'priority': priority
        })
    
    # 1. Primary public address (IMMER!)
    add_address(peer.public_addr[0], peer.public_addr[1], 'public', 1)

    # 2. Für COMPLEX NAT (needs_scan): Port-Range aus NAT-Analyse
    if peer.nat_analysis and peer.nat_analysis.needs_scan:
        scan_ports = build_candidate_ports(peer.nat_analysis, max_scan_ports)
        for i, port in enumerate(scan_ports):
            # Nur Ports hinzufügen, die NICHT bereits der PRIMARY Port sind
            if port != peer.public_addr[1]:
                add_address(peer.public_addr[0], port, 'predicted_range', 10 + i)
    
    # Sort by priority
    addresses.sort(key=lambda x: x.get('priority', 999))
    
    return addresses