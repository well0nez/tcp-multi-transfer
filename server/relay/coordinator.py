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
    
    # FIX: Finde die richtigen NAT-Ports aus probe_ports!
    sender_nat_port = get_nat_port_for_local_port(sender, sender_port)
    receiver_nat_port = get_nat_port_for_local_port(receiver, receiver_port)
    
    logger.info(f"Session {session_id}: Connection {conn_num} - "
                f"Sender local={sender_port} nat={sender_nat_port}, "
                f"Receiver local={receiver_port} nat={receiver_nat_port}")
    
    # Bestimme Punch-Strategie basierend auf NAT-Typen
    sender_strategy = determine_punch_strategy(sender, receiver)
    receiver_strategy = determine_punch_strategy(receiver, sender)
    
    # FIX: Baue peer_addresses mit den RICHTIGEN per-Connection NAT-Ports!
    # Statt get_peer_addresses_with_prediction() (verwendet ersten Port),
    # verwenden wir direkt die berechneten NAT-Ports für diese Connection.
    sender_addrs = [{
        "ip": sender.public_addr[0],
        "port": sender_nat_port,  # ← Richtiger Port für DIESE Connection!
        "addr_type": "public"
    }]
    
    receiver_addrs = [{
        "ip": receiver.public_addr[0],
        "port": receiver_nat_port,  # ← Richtiger Port für DIESE Connection!
        "addr_type": "public"
    }]
    
    logger.debug(f"Connection {conn_num}: sender_addrs={sender_addrs}, receiver_addrs={receiver_addrs}")
    
    # Sende an Sender
    # peer_nat_analysis = NAT-Analyse des PEERS (Port-Range zum Scannen)
    # Der Sender scannt die Port-Range des Receivers
    msg_to_sender = {
        'type': 'peer_info',
        'connection_num': conn_num,
        'peer_public_addr': [receiver.public_addr[0], receiver_nat_port],  # FIX: Richtiger NAT-Port!
        'peer_local_port': receiver_port,
        'peer_addresses': receiver_addrs,
        'your_role': 'sender',
        'same_network': False,
        'peer_nat_analysis': receiver.nat_analysis.to_dict() if receiver.nat_analysis else None,
        'punch_strategy': sender_strategy,
        'tcp_connections': sender.tcp_connections,  # Sender weiß schon, wie viele er will
    }
    await send_message(sender.writer, msg_to_sender)
    
    # Sende an Receiver
    # peer_nat_analysis = NAT-Analyse des PEERS (Port-Range zum Scannen)
    # Der Receiver scannt die Port-Range des Senders
    # WICHTIG: Sende die tcp_connections des SENDERS, damit Receiver weiß, wie viele Connections nötig sind!
    msg_to_receiver = {
        'type': 'peer_info',
        'connection_num': conn_num,
        'peer_public_addr': [sender.public_addr[0], sender_nat_port],  # FIX: Richtiger NAT-Port!
        'peer_local_port': sender_port,
        'peer_addresses': sender_addrs,
        'your_role': 'receiver',
        'same_network': False,
        'peer_nat_analysis': sender.nat_analysis.to_dict() if sender.nat_analysis else None,
        'punch_strategy': receiver_strategy,
        'tcp_connections': sender.tcp_connections,  # ← CRITICAL: Receiver muss wissen, wie viele Connections der Sender will!
    }
    await send_message(receiver.writer, msg_to_receiver)
    
    logger.info(f"Session {session_id}: peer_info sent for connection {conn_num} "
                f"(sender={sender_strategy}, receiver={receiver_strategy})")


def get_nat_port_for_local_port(peer, local_port: int) -> int:
    """
    Finde NAT-Port für einen gegebenen lokalen Port aus probe_ports.
    Fallback: Intelligente Vorhersage basierend auf NAT-Typ.
    """
    # 1. Versuche exakte Übereinstimmung in probe_ports
    for lport, nport in peer.probe_ports:
        if lport == local_port:
            logger.debug(f"Found NAT port {nport} for local port {local_port}")
            return nport
    
    # 2. Port-Preserved NAT: NAT-Port = Local-Port (kein Probing nötig!)
    if peer.nat_analysis and peer.nat_analysis.pattern_type == "port_preserved":
        logger.debug(f"Port-Preserved NAT: predicting NAT port {local_port} for local port {local_port}")
        return local_port
    
    # 3. Versuche Delta-Berechnung (falls wir mindestens ein Mapping haben)
    if peer.probe_ports:
        # Berechne Delta aus erstem bekannten Mapping
        first_local, first_nat = peer.probe_ports[0]
        delta = first_nat - first_local
        predicted_nat = local_port + delta
        
        logger.info(f"Predicted NAT port {predicted_nat} for local port {local_port} (delta={delta})")
        return predicted_nat
    
    # 4. Letzter Fallback: Verwende public_addr Port (nur für erste Connection)
    logger.warning(f"No probe_port found for local {local_port}, using public_addr port {peer.public_addr[1]} (first connection fallback)")
    return peer.public_addr[1]


def determine_punch_strategy(my_peer, other_peer) -> str:
    """
    Bestimme Punch-Strategie basierend auf NAT-Typen.
    
    Strategien:
    - "listen": Warte auf eingehende Verbindung (NAT-friendly zu NAT-friendly)
    - "connect": Direkter Connect (NAT-friendly zu NAT-friendly)
    - "scan": Scanne Port-Range + Listener parallel (Complex NAT oder gemischt)
    
    Wichtig: Im SCAN Mode läuft IMMER ein Listener parallel zum Scanner!
    """
    my_nat = my_peer.nat_analysis
    other_nat = other_peer.nat_analysis
    
    my_friendly = my_nat and my_nat.pattern_type == "port_preserved"
    other_friendly = other_nat and other_nat.pattern_type == "port_preserved"
    
    if my_friendly and other_friendly:
        # Beide NAT-friendly: Einer listet, einer connected
        return "connect" if my_peer.role == "sender" else "listen"
    else:
        # ALLE ANDEREN FÄLLE: SCAN (mit Listener parallel!)
        # - Mixed (friendly + complex): Beide müssen scannen UND lauschen
        # - Beide complex: Beide müssen scannen UND lauschen
        # SCAN = Simultaneous Open (Scanner + Listener parallel)
        return "scan"
