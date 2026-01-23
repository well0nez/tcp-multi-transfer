"""
TCP Hole Punch Relay Server - Session Coordinator
"""
import asyncio
import logging
import time
from typing import Optional

from .utils import send_message, get_peer_addresses_with_prediction

logger = logging.getLogger(__name__)


async def coordinate_multi_connections(
    session_id: str,
    session_manager,
    tcp_connections: int,
    max_scan_ports: int
):
    """
    Koordiniert mehrere Hole-Punch-Zyklen für Multi-Connection Support.
    
    Für jede Connection:
    1. Sende peer_info mit connection_num und Port/Range
    2. Warte auf BEIDE READYs
    3. Sende synchronized GO
    4. Warte 2+ Sekunden vor nächster Connection
    """
    lock = session_manager.get_session_lock(session_id)
    
    async with lock:
        session = session_manager.sessions.get(session_id)
        if not session:
            logger.error(f"Session {session_id} not found")
            return
        
        sender = session.get('sender')
        receiver = session.get('receiver')
        
        if not sender or not receiver:
            logger.error(f"Session {session_id}: Missing sender or receiver")
            return
    
    logger.info(f"Session {session_id}: Starting multi-connection coordination ({tcp_connections} connections)")
    
    for conn_num in range(tcp_connections):
        logger.info(f"Session {session_id}: Coordinating connection {conn_num+1}/{tcp_connections}")
        
        # 1. Sende peer_info für diese Connection
        await send_peer_info_for_connection(
            session_id,
            sender,
            receiver,
            conn_num,
            max_scan_ports,
            session_manager
        )
        
        # 2. Warte auf BEIDE READYs
        max_wait = 30.0  # 30 Sekunden Timeout
        start_wait = time.time()
        
        while True:
            async with lock:
                sender_ready = sender.ready_for_connection.get(conn_num, False)
                receiver_ready = receiver.ready_for_connection.get(conn_num, False)
                
                if sender_ready and receiver_ready:
                    logger.info(f"Session {session_id}: Both peers ready for connection {conn_num}")
                    break
                
                if time.time() - start_wait > max_wait:
                    logger.error(f"Session {session_id}: Timeout waiting for READYs (conn {conn_num})")
                    return
            
            await asyncio.sleep(0.1)
        
        # 3. Sende synchronized GO
        start_at = time.time() + 1.5  # 1.5s Vorlauf
        go_msg = {
            'type': 'go',
            'start_at': start_at,
            'connection_num': conn_num,
            'message': f'Connection {conn_num+1}/{tcp_connections}'
        }
        
        await send_message(sender.writer, go_msg)
        await send_message(receiver.writer, go_msg)
        
        logger.info(f"Session {session_id}: GO sent for connection {conn_num+1} at {start_at:.3f}")
        
        # 4. Reset ready flags
        async with lock:
            sender.ready_for_connection[conn_num] = False
            receiver.ready_for_connection[conn_num] = False
        
        # 5. Warte mindestens 2 Sekunden vor nächster Connection
        if conn_num < tcp_connections - 1:  # Nicht nach letzter Connection
            await asyncio.sleep(2.5)  # 2s Pause + 0.5s Buffer


async def send_peer_info_for_connection(
    session_id: str,
    sender,
    receiver,
    conn_num: int,
    max_scan_ports: int,
    session_manager
):
    """Sende peer_info für eine spezifische Connection mit Punch-Strategie"""
    from .utils import get_peer_addresses_with_prediction
    
    # Port-Auswahl für diese Connection
    sender_port = sender.bound_ports[conn_num] if conn_num < len(sender.bound_ports) else sender.local_port
    receiver_port = receiver.bound_ports[conn_num] if conn_num < len(receiver.bound_ports) else receiver.local_port
    
    # Bestimme Punch-Strategie basierend auf NAT-Typen
    sender_strategy = determine_punch_strategy(sender, receiver)
    receiver_strategy = determine_punch_strategy(receiver, sender)
    
    # Baue peer_addresses (bleibt gleich, aber mit FESTER Range)
    sender_addrs = get_peer_addresses_with_prediction(sender, receiver, max_scan_ports)
    receiver_addrs = get_peer_addresses_with_prediction(receiver, sender, max_scan_ports)
    
    # Sende an Sender
    msg_to_sender = {
        'type': 'peer_info',
        'connection_num': conn_num,
        'peer_public_addr': list(receiver.public_addr),
        'peer_local_port': receiver_port,
        'peer_addresses': receiver_addrs,
        'your_role': 'sender',
        'same_network': False,
        'peer_nat_analysis': receiver.nat_analysis.to_dict() if receiver.nat_analysis else None,
        'punch_strategy': sender_strategy,
    }
    await send_message(sender.writer, msg_to_sender)
    
    # Sende an Receiver
    msg_to_receiver = {
        'type': 'peer_info',
        'connection_num': conn_num,
        'peer_public_addr': list(sender.public_addr),
        'peer_local_port': sender_port,
        'peer_addresses': sender_addrs,
        'your_role': 'receiver',
        'same_network': False,
        'peer_nat_analysis': sender.nat_analysis.to_dict() if sender.nat_analysis else None,
        'punch_strategy': receiver_strategy,
    }
    await send_message(receiver.writer, msg_to_receiver)
    
    logger.info(f"Session {session_id}: peer_info sent for connection {conn_num} "
                f"(sender={sender_strategy}, receiver={receiver_strategy})")


def determine_punch_strategy(my_peer, other_peer) -> str:
    """
    Bestimme Punch-Strategie basierend auf NAT-Typen.
    
    Strategien:
    - "listen": Warte auf eingehende Verbindung (NAT-friendly)
    - "connect": Direkter Connect (NAT-friendly zu NAT-friendly)
    - "scan": Scanne Port-Range (Complex NAT)
    """
    my_nat = my_peer.nat_analysis
    other_nat = other_peer.nat_analysis
    
    my_friendly = my_nat and my_nat.pattern_type == "port_preserved"
    other_friendly = other_nat and other_nat.pattern_type == "port_preserved"
    
    if my_friendly and other_friendly:
        # Beide NAT-friendly: Einer listet, einer connected
        return "connect" if my_peer.role == "sender" else "listen"
    elif my_friendly and not other_friendly:
        # Ich friendly, Peer complex: Ich liste, Peer scannt
        return "listen"
    elif not my_friendly and other_friendly:
        # Ich complex, Peer friendly: Ich scanne, Peer listet
        return "scan"
    else:
        # Beide complex: Beide scannen
        return "scan"
