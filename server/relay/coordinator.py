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
    coordination_started = False
    
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
        
        session['coordination_active'] = True
        coordination_started = True
    try:
        logger.info(f"Session {session_id}: Starting multi-connection coordination ({tcp_connections} connections)")
        
        for conn_num in range(tcp_connections):
            logger.info(f"Session {session_id}: Coordinating connection {conn_num+1}/{tcp_connections}")
            
            max_port_wait = 60.0
            port_wait_start = time.time()
            skip_connection = False
            while True:
                # If both peers already reported a result, skip coordination.
                async with lock:
                    session = session_manager.sessions.get(session_id)
                    session_results = (session or {}).get('conn_results') or {}
                    sender_result = session_results.get('sender', {}).get(conn_num) or sender.conn_results.get(conn_num)
                    receiver_result = session_results.get('receiver', {}).get(conn_num) or receiver.conn_results.get(conn_num)
                if sender_result and receiver_result:
                    logger.info(
                        f"Session {session_id}: Connection {conn_num} already resolved "
                        f"(sender={sender_result}, receiver={receiver_result})"
                    )
                    skip_connection = True
                    break
                
                sender_has_port = conn_num < len(sender.bound_ports)
                receiver_has_port = conn_num < len(receiver.bound_ports)
                
                if sender_has_port and receiver_has_port:
                    logger.debug(f"Session {session_id}: Both peers have port for connection {conn_num}")
                    break
                
                if time.time() - port_wait_start > max_port_wait:
                    logger.warning(
                        f"Session {session_id}: Still waiting for ports (conn {conn_num}) - "
                        f"sender={len(sender.bound_ports)} ports, receiver={len(receiver.bound_ports)} ports"
                    )
                    port_wait_start = time.time()
                
                await asyncio.sleep(0.05)

            if skip_connection:
                continue

            # Clear any stale results before coordinating this connection
            async with lock:
                sender.conn_results.pop(conn_num, None)
                receiver.conn_results.pop(conn_num, None)
                sender.conn_reasons.pop(conn_num, None)
                receiver.conn_reasons.pop(conn_num, None)
                session = session_manager.sessions.get(session_id)
                if session:
                    session_results = session.get('conn_results')
                    if session_results:
                        session_results.get('sender', {}).pop(conn_num, None)
                        session_results.get('receiver', {}).pop(conn_num, None)
                    session_reasons = session.get('conn_reasons')
                    if session_reasons:
                        session_reasons.get('sender', {}).pop(conn_num, None)
                        session_reasons.get('receiver', {}).pop(conn_num, None)
            
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

            # Wait for both peers to report the connection result before proceeding
            result = await wait_for_connection_result(
                session_id,
                session_manager,
                conn_num,
                timeout=300.0,
            )
            if not result:
                logger.error(f"Session {session_id}: Timeout waiting for connection {conn_num} result")
                return
            
            sender_result, receiver_result = result
            logger.info(
                f"Session {session_id}: Connection {conn_num} results "
                f"(sender={sender_result}, receiver={receiver_result})"
            )
            
            if conn_num < tcp_connections - 1:
                await asyncio.sleep(0.1)
    finally:
        if coordination_started:
            async with lock:
                session = session_manager.sessions.get(session_id)
                if session:
                    session['coordination_active'] = False
                    if not session.get('sender') and not session.get('receiver'):
                        session_manager.sessions.pop(session_id, None)
                        session_manager.pending_probes.pop(session_id, None)
                        session_manager.peer_info_sent.pop(session_id, None)


async def coordinate_retry_connection(
    session_id: str,
    session_manager,
    conn_num: int,
    max_scan_ports: int,
    ready_timeout: float = 60.0,
    go_delay: float = 1.5,
):
    """Coordinate a retry for a single connection after both peers added new ports."""
    lock = session_manager.get_session_lock(session_id)
    
    async with lock:
        session = session_manager.sessions.get(session_id)
        if not session:
            logger.error(f"Session {session_id} not found for retry connection {conn_num}")
            return
        
        sender = session.get('sender')
        receiver = session.get('receiver')
        
        if not sender or not receiver:
            logger.error(f"Session {session_id}: Missing sender or receiver for retry connection {conn_num}")
            return
    
    await send_peer_info_for_connection(
        session_id,
        sender,
        receiver,
        conn_num,
        max_scan_ports,
        session_manager
    )
    
    start_wait = time.time()
    
    while True:
        async with lock:
            sender_ready = sender.ready_for_connection.get(conn_num, False)
            receiver_ready = receiver.ready_for_connection.get(conn_num, False)
            
            if sender_ready and receiver_ready:
                logger.info(f"Session {session_id}: Both peers ready for retry connection {conn_num}")
                break
            
            if time.time() - start_wait > ready_timeout:
                logger.error(f"Session {session_id}: Timeout waiting for READYs (retry conn {conn_num})")
                return
        
        await asyncio.sleep(0.1)
    
    start_at = time.time() + go_delay
    go_msg = {
        'type': 'go',
        'start_at': start_at,
        'connection_num': conn_num,
        'message': f'Retry connection {conn_num+1}'
    }
    
    await send_message(sender.writer, go_msg)
    await send_message(receiver.writer, go_msg)
    
    logger.info(f"Session {session_id}: GO sent for retry connection {conn_num+1} at {start_at:.3f}")
    
    async with lock:
        sender.ready_for_connection[conn_num] = False
        receiver.ready_for_connection[conn_num] = False


async def wait_for_connection_result(
    session_id: str,
    session_manager,
    conn_num: int,
    timeout: float = 300.0,
):
    """Wait for both peers to report established/abandoned for a connection."""
    lock = session_manager.get_session_lock(session_id)
    start = time.time()
    warned = False
    
    while True:
        async with lock:
            session = session_manager.sessions.get(session_id)
            if not session:
                logger.error(f"Session {session_id} not found while waiting for conn {conn_num} result")
                return None
            
            sender = session.get('sender')
            receiver = session.get('receiver')
            session_results = session.setdefault('conn_results', {'sender': {}, 'receiver': {}})
            session_reasons = session.setdefault('conn_reasons', {'sender': {}, 'receiver': {}})

            sender_result = session_results.get('sender', {}).get(conn_num)
            receiver_result = session_results.get('receiver', {}).get(conn_num)

            if sender and not sender_result:
                live = sender.conn_results.get(conn_num)
                if live:
                    session_results['sender'][conn_num] = live
                    sender_result = live
                    reason = sender.conn_reasons.get(conn_num)
                    if reason:
                        session_reasons['sender'][conn_num] = reason

            if receiver and not receiver_result:
                live = receiver.conn_results.get(conn_num)
                if live:
                    session_results['receiver'][conn_num] = live
                    receiver_result = live
                    reason = receiver.conn_reasons.get(conn_num)
                    if reason:
                        session_reasons['receiver'][conn_num] = reason
            
            if sender_result and receiver_result:
                return sender_result, receiver_result
            
            missing = []
            if not sender and not sender_result:
                session_results['sender'][conn_num] = "abandoned"
                session_reasons['sender'][conn_num] = "peer_missing"
                sender_result = "abandoned"
                missing.append("sender")
            
            if not receiver and not receiver_result:
                session_results['receiver'][conn_num] = "abandoned"
                session_reasons['receiver'][conn_num] = "peer_missing"
                receiver_result = "abandoned"
                missing.append("receiver")
            
            if missing and sender_result and receiver_result:
                logger.warning(
                    f"Session {session_id}: Peer(s) {', '.join(missing)} missing; "
                    f"marking conn {conn_num} as abandoned"
                )
                return sender_result, receiver_result
        
        elapsed = time.time() - start
        if elapsed > timeout:
            return None
        
        if elapsed > 30.0 and not warned:
            logger.warning(f"Session {session_id}: Still waiting for conn {conn_num} results after {elapsed:.1f}s")
            warned = True
        
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
    
    analysis = peer.nat_analysis
    if analysis:
        if analysis.pattern_type == "port_preserved":
            logger.debug(f"Port-Preserved NAT: predicting NAT port {local_port} for local port {local_port}")
            return local_port
        
        # External mode: NAT port is independent of local port.
        if getattr(peer, "prediction_mode", "delta") == "external" and analysis.predicted_port:
            predicted = max(1024, min(65535, int(round(analysis.predicted_port))))
            logger.info(f"External NAT mode: using predicted NAT port {predicted} for local port {local_port}")
            return predicted
        
        # Delta-based prediction: NAT port follows local port with a stable offset.
        if analysis.delta_min != 0 or analysis.delta_max != 0 or analysis.delta_median != 0:
            predicted_nat = local_port + analysis.delta_median + (analysis.predicted_shift or 0)
            predicted = max(1024, min(65535, int(round(predicted_nat))))
            logger.info(
                f"Predicted NAT port {predicted} for local port {local_port} "
                f"(delta_median={analysis.delta_median}, shift={analysis.predicted_shift})"
            )
            return predicted
        
        if analysis.predicted_port:
            predicted = max(1024, min(65535, int(round(analysis.predicted_port))))
            logger.info(f"Fallback to predicted NAT port {predicted} for local port {local_port}")
            return predicted
    
    logger.warning(
        f"No NAT prediction available for local {local_port}, using public_addr port {peer.public_addr[1]} "
        f"(control-connection fallback)"
    )
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
