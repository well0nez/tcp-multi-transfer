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
                # NEU: Connection-spezifisches READY
                conn_num = msg.get('connection_num', 0)
                peer.ready_for_connection[conn_num] = True
                logger.info(f"Peer {peer.role} is READY for connection {conn_num}")
                
                # NICHT mehr try_send_go aufrufen!
                # Multi-Connection Loop handled das
            
            elif msg_type == 'keepalive':
                await send_message(peer.writer, {'type': 'keepalive_ack'})
            
            elif msg_type == 'probes_complete':
                logger.info(f"Peer {peer.role} sent probes_complete")
                await handle_probes_complete(peer, session_manager, max_scan_ports)
            
        except asyncio.TimeoutError:
            try:
                await send_message(peer.writer, {'type': 'ping'})
            except:
                break
        except Exception as e:
            logger.debug(f"Error reading from {peer.role}: {e}")
            break


async def handle_probes_complete(peer: Peer, session_manager, max_scan_ports: int):
    """Handle probes_complete message from client"""
    session_id = peer.session_id

    if not peer.needs_probing:
        peer.probes_done = True
        logger.info(f"Peer {peer.role} probes_done=True (no probing required)")
        return
    
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
            # Clear used probes
            session_manager.pending_probes[session_id] = [
                (ip, nat, local, ts) for ip, nat, local, ts in probes
                if ip != peer.public_addr[0]
            ]
        else:
            logger.warning(f"No probes received from {peer.role}")
    else:
        logger.warning(f"No probe list found for session {session_id}")

    if not peer.nat_analysis:
        # Create basic analysis from registration
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
    
    # NEU: Starte Multi-Connection Koordination wenn beide ready
    lock = session_manager.get_session_lock(session_id)
    async with lock:
        session = session_manager.sessions.get(session_id)
        if session:
            sender = session.get('sender')
            receiver = session.get('receiver')
            
            if sender and receiver and sender.probes_done and receiver.probes_done:
                # Beide haben Probing abgeschlossen
                # Ermittle tcp_connections (vom Sender oder Receiver)
                tcp_connections = sender.tcp_connections or receiver.tcp_connections or 1
                
                logger.info(f"Session {session_id}: Both peers ready, starting multi-connection coordination ({tcp_connections} connections)")
                
                # Importiere coordinate_multi_connections
                from .coordinator import coordinate_multi_connections
                
                # Starte Multi-Connection Loop asynchron
                asyncio.create_task(
                    coordinate_multi_connections(
                        session_id,
                        session_manager,
                        tcp_connections,
                        max_scan_ports
                    )
                )
