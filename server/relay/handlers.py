"""
TCP Hole Punch Relay Server - Message Handlers
"""
import asyncio
import json
import logging
import time
from datetime import datetime
from typing import List

from ..models import Peer, NATAnalysis
from ..nat_analyzer import analyze_nat
from .utils import send_message

logger = logging.getLogger(__name__)

MIN_PORT = 1024
MAX_PORT = 65535


async def wait_for_peer_messages(peer: Peer, session_manager, max_scan_ports: int):
    """Wait for messages from peer"""
    while True:
        try:
            data = await asyncio.wait_for(peer.reader.readline(), timeout=300.0)
            if not data:
                break
            
            msg = json.loads(data.decode())
            msg_type = msg.get('type')
            
            if msg_type == 'ready':
                conn_num = msg.get('connection_num', 0)
                peer.ready_for_connection[conn_num] = True
                logger.info(f"Peer {peer.role} is READY for connection {conn_num}")
            
            elif msg_type == 'keepalive':
                await send_message(peer.writer, {'type': 'keepalive_ack'})
            
            elif msg_type == 'add_ports':
                logger.info(f"Peer {peer.role} sent add_ports")
                await handle_add_ports(msg, peer, session_manager)
            
            elif msg_type == 'probes_complete':
                logger.info(f"Peer {peer.role} sent probes_complete")
                await handle_probes_complete(peer, session_manager, max_scan_ports)
            
            elif msg_type == 'retry_request':
                logger.info(f"Peer {peer.role} sent retry_request")
                await handle_retry_request(msg, peer, session_manager, max_scan_ports)
            
        except asyncio.TimeoutError:
            try:
                await send_message(peer.writer, {'type': 'ping'})
            except:
                break
        except Exception as e:
            logger.debug(f"Error reading from {peer.role}: {e}")
            break


async def handle_add_ports(msg: dict, peer: Peer, session_manager):
    """Handle add_ports message from client."""
    ports = msg.get('ports', [])
    if not ports:
        logger.warning(f"Received add_ports with no ports from {peer.role}")
        return
    
    session_id = peer.session_id
    
    logger.info(f"Peer {peer.role} added {len(ports)} new ports: {ports}")
    
    retry_mapped = False
    
    if session_id in session_manager.pending_probes:
        probes = session_manager.pending_probes[session_id]
        peer_probes = [(ip, nat, local, ts) for ip, nat, local, ts in probes
                       if ip == peer.public_addr[0] and local in ports]
        
        if peer_probes:
            logger.info(f"Found {len(peer_probes)} probes for new ports from {peer.role}")
            
            for _, nat_port, local_port, _ in peer_probes:
                if (local_port, nat_port) not in peer.probe_ports:
                    peer.probe_ports.append((local_port, nat_port))
                    logger.debug(f"  Added mapping: local {local_port} -> NAT {nat_port}")
            
            session_manager.pending_probes[session_id] = [
                (ip, nat, local, ts) for ip, nat, local, ts in probes
                if not (ip == peer.public_addr[0] and local in ports)
            ]
        else:
            logger.warning(f"No probes received yet for new ports from {peer.role}")
    else:
        logger.warning(f"No probe list found for session {session_id}")
    
    await send_message(peer.writer, {
        'type': 'ports_added_ack',
        'ports': ports
    })
    logger.info(f"Sent ports_added_ack to {peer.role} for {len(ports)} ports")
    
    lock = session_manager.get_session_lock(session_id)
    async with lock:
        session = session_manager.sessions.get(session_id)
        if session:
            other_peer = session.get('sender' if peer.role == 'receiver' else 'receiver')
            if other_peer:
                await send_message(other_peer.writer, {
                    'type': 'peer_added_ports',
                    'ports': ports
                })
                logger.info(f"Notified {other_peer.role} about {len(ports)} new ports from {peer.role}")
            
            if 'retry_add_ports_pending' in session and session.get('retry_add_ports_pending'):
                for conn_num, pending in list(session['retry_add_ports_pending'].items()):
                    if not pending.get(peer.role):
                        # Map the new retry port to the original connection index
                        new_port = ports[0]
                        if conn_num < len(peer.bound_ports):
                            old_port = peer.bound_ports[conn_num]
                            peer.bound_ports[conn_num] = new_port
                            logger.info(
                                f"Session {session_id}: Retry port mapped for {peer.role} conn {conn_num} "
                                f"({old_port} -> {new_port})"
                            )
                        else:
                            peer.bound_ports.append(new_port)
                            logger.warning(
                                f"Session {session_id}: Retry port mapped for {peer.role} conn {conn_num} "
                                f"(appended {new_port})"
                            )
                        retry_mapped = True
                        pending[peer.role] = True
                        logger.info(f"Session {session_id}: Peer {peer.role} sent add_ports for retry connection {conn_num}")
                        
                        sender = session.get('sender')
                        receiver = session.get('receiver')
                        
                        if sender and receiver and pending.get('sender') and pending.get('receiver'):
                            logger.info(f"Session {session_id}: BOTH peers sent add_ports for retry connection {conn_num} - coordinating retry")
                            
                            from .coordinator import coordinate_retry_connection
                            
                            max_scan_ports = pending.get('max_scan_ports', 100)
                            
                            asyncio.create_task(
                                coordinate_retry_connection(
                                    session_id,
                                    session_manager,
                                    conn_num,
                                    max_scan_ports,
                                )
                            )
                            
                            del session['retry_add_ports_pending'][conn_num]
                            logger.info(f"Session {session_id}: Retry coordination task started for connection {conn_num}")
                        
                        break

    if not retry_mapped:
        peer.bound_ports.extend(ports)


async def handle_probes_complete(peer: Peer, session_manager, max_scan_ports: int):
    """Handle probes_complete message from client."""
    session_id = peer.session_id

    if not peer.needs_probing:
        peer.probes_done = True
        logger.info(f"Peer {peer.role} probes_done=True (no probing required)")
    else:
        if session_id in session_manager.pending_probes:
            probes = session_manager.pending_probes[session_id]
            peer_probes = [(ip, nat, local, ts) for ip, nat, local, ts in probes
                           if ip == peer.public_addr[0]]
            
            if peer_probes:
                logger.info(f"Analyzing {len(peer_probes)} probes from {peer.role}")
                peer.nat_analysis = analyze_nat(
                    peer_probes,
                    peer.local_port,
                    peer.prediction_mode,
                    peer.prediction_range_extra_pct,
                )
                session_manager.pending_probes[session_id] = [
                    (ip, nat, local, ts) for ip, nat, local, ts in probes
                    if ip != peer.public_addr[0]
                ]
            else:
                logger.warning(f"No probes received from {peer.role}")
        else:
            logger.warning(f"No probe list found for session {session_id}")

        if not peer.nat_analysis:
            peer.nat_analysis = NATAnalysis(
                probed_ports=[peer.public_addr[1]],
                local_ports=[peer.local_port],
                min_port=peer.public_addr[1],
                max_port=peer.public_addr[1],
                port_range=0,
                predicted_port=peer.public_addr[1],
                error_range=0,
                pattern_type="insufficient_data",
                needs_scan=False,
                scan_start=peer.public_addr[1],
                scan_end=peer.public_addr[1],
            )
        
        peer.probes_done = True
        logger.info(f"Peer {peer.role} probes_done=True")
    
    lock = session_manager.get_session_lock(session_id)
    async with lock:
        session = session_manager.sessions.get(session_id)
        if session:
            sender = session.get('sender')
            receiver = session.get('receiver')
            
            if sender and receiver and sender.probes_done and receiver.probes_done:
                tcp_connections = sender.tcp_connections or receiver.tcp_connections or 1
                
                logger.info(f"Session {session_id}: Both peers ready, starting multi-connection coordination ({tcp_connections} connections)")
                
                from .coordinator import coordinate_multi_connections
                
                asyncio.create_task(
                    coordinate_multi_connections(
                        session_id,
                        session_manager,
                        tcp_connections,
                        max_scan_ports
                    )
                )


async def handle_retry_request(msg: dict, peer: Peer, session_manager, max_scan_ports: int):
    """Handle retry_request from client."""
    conn_num = msg.get('connection_num')
    if conn_num is None:
        logger.warning(f"Received retry_request with no connection_num from {peer.role}")
        return
    
    session_id = peer.session_id
    
    logger.info(f"Peer {peer.role} requests retry for connection {conn_num}")
    
    if not hasattr(peer, 'retry_requested'):
        peer.retry_requested = {}
    peer.retry_requested[conn_num] = True
    
    lock = session_manager.get_session_lock(session_id)
    async with lock:
        session = session_manager.sessions.get(session_id)
        if not session:
            logger.error(f"Session {session_id} not found for retry_request")
            return
        
        sender = session.get('sender')
        receiver = session.get('receiver')
        
        if not sender or not receiver:
            logger.error(f"Session {session_id}: Missing sender or receiver for retry_request")
            return
        
        if not hasattr(sender, 'retry_requested'):
            sender.retry_requested = {}
        if not hasattr(receiver, 'retry_requested'):
            receiver.retry_requested = {}
        
        if sender.retry_requested.get(conn_num) and receiver.retry_requested.get(conn_num):
            logger.info(f"Session {session_id}: Both peers want retry for connection {conn_num} - granting!")
            
            # Cancel timeout task if it exists
            timeout_key = f'retry_timeout_task_{conn_num}'
            if timeout_key in session:
                session[timeout_key].cancel()
                del session[timeout_key]
            
            await send_message(sender.writer, {
                'type': 'retry_granted',
                'connection_num': conn_num
            })
            await send_message(receiver.writer, {
                'type': 'retry_granted',
                'connection_num': conn_num
            })
            
            sender.retry_requested[conn_num] = False
            receiver.retry_requested[conn_num] = False
            
            sender.ready_for_connection[conn_num] = False
            receiver.ready_for_connection[conn_num] = False
            
            if 'retry_add_ports_pending' not in session:
                session['retry_add_ports_pending'] = {}
            session['retry_add_ports_pending'][conn_num] = {
                'sender': False,
                'receiver': False,
                'max_scan_ports': max_scan_ports,
            }
            
            logger.info(f"Session {session_id}: Retry granted for connection {conn_num}, waiting for add_ports from BOTH peers")
        else:
            # Start timeout task if not already started
            timeout_key = f'retry_timeout_task_{conn_num}'
            if timeout_key not in session:
                logger.info(f"Session {session_id}: Starting retry coordination timeout (45s) for connection {conn_num}")
                session[timeout_key] = asyncio.create_task(
                    retry_coordination_timeout(session_id, conn_num, 45.0, session_manager)
                )
            else:
                logger.info(f"Session {session_id}: Waiting for other peer to request retry for connection {conn_num}")


async def retry_coordination_timeout(session_id: str, conn_num: int, timeout_sec: float, session_manager):
    """Handle retry coordination timeout - send retry_rejected if peer missing."""
    await asyncio.sleep(timeout_sec)
    
    lock = session_manager.get_session_lock(session_id)
    async with lock:
        session = session_manager.sessions.get(session_id)
        if not session:
            logger.debug(f"Session {session_id} no longer exists (timeout cleanup)")
            return
        
        sender = session.get('sender')
        receiver = session.get('receiver')
        
        if not sender or not receiver:
            return
        
        sender_waiting = getattr(sender, 'retry_requested', {}).get(conn_num, False)
        receiver_waiting = getattr(receiver, 'retry_requested', {}).get(conn_num, False)
        
        # If both are now waiting, they already got granted (race condition)
        if sender_waiting and receiver_waiting:
            logger.debug(f"Session {session_id}: Both peers waiting at timeout - already handled")
            return
        
        # If only one is waiting, send retry_rejected
        if sender_waiting and not receiver_waiting:
            logger.warning(f"Session {session_id}: Retry coordination timeout - receiver missing for conn {conn_num}")
            await send_message(sender.writer, {
                'type': 'retry_rejected',
                'connection_num': conn_num,
                'reason': 'peer_missing'
            })
            sender.retry_requested[conn_num] = False
        elif receiver_waiting and not sender_waiting:
            logger.warning(f"Session {session_id}: Retry coordination timeout - sender missing for conn {conn_num}")
            await send_message(receiver.writer, {
                'type': 'retry_rejected',
                'connection_num': conn_num,
                'reason': 'peer_missing'
            })
            receiver.retry_requested[conn_num] = False
        
        # Clean up timeout task
        timeout_key = f'retry_timeout_task_{conn_num}'
        if timeout_key in session:
            del session[timeout_key]
