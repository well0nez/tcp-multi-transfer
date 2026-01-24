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
    """Coordinates multiple hole-punch cycles for multi-connection support."""
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
        
        max_port_wait = 60.0
        port_wait_start = time.time()
        while True:
            sender_has_port = conn_num < len(sender.bound_ports)
            receiver_has_port = conn_num < len(receiver.bound_ports)
            
            if sender_has_port and receiver_has_port:
                logger.debug(f"Session {session_id}: Both peers have port for connection {conn_num}")
                break
            
            if time.time() - port_wait_start > max_port_wait:
                logger.error(f"Session {session_id}: Timeout waiting for ports (conn {conn_num}) - "
                           f"sender={len(sender.bound_ports)} ports, receiver={len(receiver.bound_ports)} ports")
                return
            
            await asyncio.sleep(0.05)
        
        await send_peer_info_for_connection(
            session_id,
            sender,
            receiver,
            conn_num,
            max_scan_ports,
            session_manager
        )
        
        max_wait = 60.0
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
        
        start_at = time.time() + 1.5
        go_msg = {
            'type': 'go',
            'start_at': start_at,
            'connection_num': conn_num,
            'message': f'Connection {conn_num+1}/{tcp_connections}'
        }
        
        await send_message(sender.writer, go_msg)
        await send_message(receiver.writer, go_msg)
        
        logger.info(f"Session {session_id}: GO sent for connection {conn_num+1} at {start_at:.3f}")
        
        async with lock:
            sender.ready_for_connection[conn_num] = False
            receiver.ready_for_connection[conn_num] = False
        
        if conn_num < tcp_connections - 1:
            await asyncio.sleep(0.1)


async def send_peer_info_for_connection(
    session_id: str,
    sender,
    receiver,
    conn_num: int,
    max_scan_ports: int,
    session_manager
):
    """Send peer_info for specific connection with punch strategy."""
    from .utils import get_peer_addresses_with_prediction
    
    sender_port = sender.bound_ports[conn_num] if conn_num < len(sender.bound_ports) else sender.local_port
    receiver_port = receiver.bound_ports[conn_num] if conn_num < len(receiver.bound_ports) else receiver.local_port
    
    sender_nat_port = get_nat_port_for_local_port(sender, sender_port)
    receiver_nat_port = get_nat_port_for_local_port(receiver, receiver_port)
    
    logger.info(f"Session {session_id}: Connection {conn_num} - "
                f"Sender local={sender_port} nat={sender_nat_port}, "
                f"Receiver local={receiver_port} nat={receiver_nat_port}")
    
    sender_strategy = determine_punch_strategy(sender, receiver)
    receiver_strategy = determine_punch_strategy(receiver, sender)
    
    sender_addrs = get_peer_addresses_with_prediction(
        sender, receiver, max_scan_ports,
        base_port=sender_nat_port
    )
    
    receiver_addrs = get_peer_addresses_with_prediction(
        receiver, sender, max_scan_ports,
        base_port=receiver_nat_port
    )
    
    logger.debug(f"Connection {conn_num}: sender_addrs={len(sender_addrs)} addresses (primary={sender_nat_port}), "
                 f"receiver_addrs={len(receiver_addrs)} addresses (primary={receiver_nat_port})")
    
    msg_to_sender = {
        'type': 'peer_info',
        'connection_num': conn_num,
        'peer_public_addr': [receiver.public_addr[0], receiver_nat_port],
        'peer_local_port': receiver_port,
        'peer_addresses': receiver_addrs,
        'your_role': 'sender',
        'same_network': False,
        'peer_nat_analysis': receiver.nat_analysis.to_dict() if receiver.nat_analysis else None,
        'punch_strategy': sender_strategy,
        'tcp_connections': sender.tcp_connections,
    }
    await send_message(sender.writer, msg_to_sender)
    
    msg_to_receiver = {
        'type': 'peer_info',
        'connection_num': conn_num,
        'peer_public_addr': [sender.public_addr[0], sender_nat_port],
        'peer_local_port': sender_port,
        'peer_addresses': sender_addrs,
        'your_role': 'receiver',
        'same_network': False,
        'peer_nat_analysis': sender.nat_analysis.to_dict() if sender.nat_analysis else None,
        'punch_strategy': receiver_strategy,
        'tcp_connections': sender.tcp_connections,
    }
    await send_message(receiver.writer, msg_to_receiver)
    
    logger.info(f"Session {session_id}: peer_info sent for connection {conn_num} "
                f"(sender={sender_strategy}, receiver={receiver_strategy})")


def get_nat_port_for_local_port(peer, local_port: int) -> int:
    """Find NAT port for local port with intelligent prediction fallback."""
    for lport, nport in peer.probe_ports:
        if lport == local_port:
            logger.debug(f"Found NAT port {nport} for local port {local_port}")
            return nport
    
    if peer.nat_analysis and peer.nat_analysis.pattern_type == "port_preserved":
        logger.debug(f"Port-Preserved NAT: predicting NAT port {local_port} for local port {local_port}")
        return local_port
    
    if peer.probe_ports:
        first_local, first_nat = peer.probe_ports[0]
        delta = first_nat - first_local
        predicted_nat = local_port + delta
        
        logger.info(f"Predicted NAT port {predicted_nat} for local port {local_port} (delta={delta})")
        return predicted_nat
    
    logger.warning(f"No probe_port found for local {local_port}, using public_addr port {peer.public_addr[1]} (first connection fallback)")
    return peer.public_addr[1]


def determine_punch_strategy(my_peer, other_peer) -> str:
    """
    Determine punch strategy for TCP hole punching.
    
    Always returns "scan" (Simultaneous Open: Listener + Connect parallel).
    All NAT types require Simultaneous Open to create holes in both NATs.
    
    Port-Preserved NAT: peer_addresses contains 1 address (predictable).
    Complex NAT (CGNAT): peer_addresses contains 100-500 addresses (port range).
    """
    return "scan"