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


def get_peer_addresses_with_prediction(peer, max_scan_ports: int, base_port: int = None,
                                       lan_addr: tuple = None) -> List[Dict]:
    """
    Get addresses including scan range from NAT analysis
    
    Args:
        peer: The peer whose addresses to build
        max_scan_ports: Maximum number of scan ports to include
        base_port: Optional per-connection NAT port to use as primary (instead of public_addr[1])
        lan_addr: Optional (ip, port) im gemeinsamen LAN. Wird als Kandidat mit
            hoechster Prioritaet vorangestellt, wenn beide Peers hinter derselben
            oeffentlichen Adresse sitzen. Das ist keine Optimierung, sondern eine
            Korrektur: viele Consumer-Router koennen kein Hairpinning, zwei Peers
            hinter derselben NAT erreichen sich ueber die oeffentliche Adresse
            also gar nicht — ueber das LAN dagegen sofort.
    
    Returns:
        List of address dictionaries with ip, port, type, and priority
    """
    from ..nat_analyzer import build_candidate_ports, noetige_abdeckung
    
    addresses = []
    seen: Set[tuple] = set()
    
    # Verwende base_port falls angegeben, sonst public_addr[1] (für erste Connection)
    primary_port = base_port if base_port is not None else peer.public_addr[1]

    def add_address(ip: str, port: int, addr_type: str, priority: int):
        key = (ip, port)
        if key in seen:
            return
        seen.add(key)
        addresses.append({
            'ip': ip,
            'port': port,
            'addr_type': addr_type,
            'priority': priority
        })
    
    # 0. LAN-Adresse zuerst: kein NAT im Spiel, verbindet praktisch sofort.
    if lan_addr and lan_addr[0] and lan_addr[1]:
        add_address(lan_addr[0], lan_addr[1], 'local', 0)

    # 1. Primary public address mit dem RICHTIGEN Port für diese Connection!
    add_address(peer.public_addr[0], primary_port, 'public', 1)

    # 2. Für COMPLEX NAT (needs_scan): Port-Range aus NAT-Analyse.
    # Wie viele Kandidaten noetig sind, ergibt sich aus dem gemessenen Band
    # dieses Peers und der Zahl der Ports, die er beim Punchen haelt —
    # `max_scan_ports` ist nur noch die Obergrenze.
    if peer.nat_analysis and peer.nat_analysis.needs_scan:
        noetig = noetige_abdeckung(
            peer.nat_analysis, getattr(peer, "punch_ports", 1), max_scan_ports
        )
        scan_ports = build_candidate_ports(peer.nat_analysis, noetig)
        for i, port in enumerate(scan_ports):
            # Nur Ports hinzufügen, die NICHT bereits der PRIMARY Port sind
            if port != primary_port:
                add_address(peer.public_addr[0], port, 'predicted_range', 10 + i)
    
    # Sort by priority
    addresses.sort(key=lambda x: x.get('priority', 999))
    
    return addresses
