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
            
            elif msg_type == 'add_ports':
                logger.info(f"Peer {peer.role} sent add_ports")
                await handle_add_ports(msg, peer, session_manager)
            
            elif msg_type == 'probes_complete':
                logger.info(f"Peer {peer.role} sent probes_complete")
                await handle_probes_complete(peer, session_manager, max_scan_ports)
            
            elif msg_type == 'retry_request':
                logger.info(f"Peer {peer.role} sent retry_request")
                await handle_retry_request(msg, peer, session_manager)
            
        except asyncio.TimeoutError:
            try:
                await send_message(peer.writer, {'type': 'ping'})
            except:
                break
        except Exception as e:
            logger.debug(f"Error reading from {peer.role}: {e}")
            break


async def handle_add_ports(msg: dict, peer: Peer, session_manager):
    """Handle add_ports message from client (new ports bound for multi-connection)"""
    ports = msg.get('ports', [])
    if not ports:
        logger.warning(f"Received add_ports with no ports from {peer.role}")
        return
    
    session_id = peer.session_id
    
    logger.info(f"Peer {peer.role} added {len(ports)} new ports: {ports}")
    
    # Speichere die neuen Ports
    peer.bound_ports.extend(ports)
    
    # Warte kurz auf eingehende Probes für die neuen Ports
    await asyncio.sleep(0.5)  # Gib Client Zeit, Probes zu senden
    
    # Matche Probes mit den neuen Ports
    if session_id in session_manager.pending_probes:
        probes = session_manager.pending_probes[session_id]
        peer_probes = [(ip, nat, local, ts) for ip, nat, local, ts in probes
                       if ip == peer.public_addr[0] and local in ports]
        
        if peer_probes:
            logger.info(f"Found {len(peer_probes)} probes for new ports from {peer.role}")
            
            # Füge neue Mappings zu probe_ports hinzu
            for _, nat_port, local_port, _ in peer_probes:
                if (local_port, nat_port) not in peer.probe_ports:
                    peer.probe_ports.append((local_port, nat_port))
                    logger.debug(f"  Added mapping: local {local_port} -> NAT {nat_port}")
            
            # Entferne verarbeitete Probes
            session_manager.pending_probes[session_id] = [
                (ip, nat, local, ts) for ip, nat, local, ts in probes
                if not (ip == peer.public_addr[0] and local in ports)
            ]
        else:
            logger.warning(f"No probes received yet for new ports from {peer.role}")
    else:
        logger.warning(f"No probe list found for session {session_id}")
    
    # Sende ACK mit den Ports zurück
    await send_message(peer.writer, {
        'type': 'ports_added_ack',
        'ports': ports
    })
    logger.info(f"Sent ports_added_ack to {peer.role} for {len(ports)} ports")
    
    # Notifiziere den anderen Peer über die neuen Ports
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
            
            # NEU: Prüfe ob das ein Retry-Port ist (für Retry-Koordination)
            if hasattr(session, 'retry_add_ports_pending') and session.get('retry_add_ports_pending'):
                # Finde die Connection für die wir auf add_ports warten
                for conn_num, pending in session['retry_add_ports_pending'].items():
                    if not pending[peer.role]:
                        # Dieser Peer hat jetzt add_ports gesendet!
                        pending[peer.role] = True
                        logger.info(f"Session {session_id}: Peer {peer.role} sent add_ports for retry connection {conn_num}")
                        
                        # Prüfe ob BEIDE Peers ihre add_ports gesendet haben
                        sender = session.get('sender')
                        receiver = session.get('receiver')
                        
                        if sender and receiver and pending['sender'] and pending['receiver']:
                            logger.info(f"Session {session_id}: BOTH peers sent add_ports for retry connection {conn_num} - sending updated peer_info!")
                            
                            # Sende NEUE peer_info mit aktualisierten Ports!
                            from .coordinator import send_peer_info_for_connection
                            
                            max_scan_ports = pending['max_scan_ports']
                            
                            await send_peer_info_for_connection(
                                session_id,
                                sender,
                                receiver,
                                conn_num,
                                max_scan_ports,
                                session_manager
                            )
                            
                            # Entferne pending Flag
                            del session['retry_add_ports_pending'][conn_num]
                            logger.info(f"Session {session_id}: Updated peer_info sent for retry connection {conn_num}, waiting for new READYs")
                        
                        break  # Nur den ersten pending Retry verarbeiten


async def handle_probes_complete(peer: Peer, session_manager, max_scan_ports: int):
    """Handle probes_complete message from client"""
    session_id = peer.session_id

    # SCHRITT 1: Setze probes_done (entweder direkt oder nach Analyse)
    if not peer.needs_probing:
        peer.probes_done = True
        logger.info(f"Peer {peer.role} probes_done=True (no probing required)")
    else:
        # Probe-Analyse nur wenn needed
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
    
    # SCHRITT 2: Prüfe IMMER, ob beide Peers bereit sind (unabhängig vom Probe-Status)
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


async def handle_retry_request(msg: dict, peer: Peer, session_manager):
    """Handle retry_request from client (wants to retry a failed connection with new ports)"""
    conn_num = msg.get('connection_num')
    if conn_num is None:
        logger.warning(f"Received retry_request with no connection_num from {peer.role}")
        return
    
    session_id = peer.session_id
    
    logger.info(f"Peer {peer.role} requests retry for connection {conn_num}")
    
    # Markiere, dass dieser Peer einen Retry will
    if not hasattr(peer, 'retry_requested'):
        peer.retry_requested = {}
    peer.retry_requested[conn_num] = True
    
    # Prüfe ob BEIDE Peers retry wollen
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
        
        # Initialisiere retry_requested falls nicht vorhanden
        if not hasattr(sender, 'retry_requested'):
            sender.retry_requested = {}
        if not hasattr(receiver, 'retry_requested'):
            receiver.retry_requested = {}
        
        # Prüfe ob BEIDE wollen
        if sender.retry_requested.get(conn_num) and receiver.retry_requested.get(conn_num):
            logger.info(f"Session {session_id}: Both peers want retry for connection {conn_num} - granting!")
            
            # Sende retry_granted an BEIDE
            await send_message(sender.writer, {
                'type': 'retry_granted',
                'connection_num': conn_num
            })
            await send_message(receiver.writer, {
                'type': 'retry_granted',
                'connection_num': conn_num
            })
            
            # Reset retry flags für diese Connection
            sender.retry_requested[conn_num] = False
            receiver.retry_requested[conn_num] = False
            
            # Reset READY flags für diese Connection (müssen neu gesendet werden)
            sender.ready_for_connection[conn_num] = False
            receiver.ready_for_connection[conn_num] = False
            
            # Setze Flag: Wir warten auf add_ports von BEIDEN Peers für diese Connection
            if not hasattr(session, 'retry_add_ports_pending'):
                session['retry_add_ports_pending'] = {}
            session['retry_add_ports_pending'][conn_num] = {
                'sender': False,
                'receiver': False,
                'max_scan_ports': sender.scan_budget or receiver.scan_budget or 100
            }
            
            logger.info(f"Session {session_id}: Retry granted for connection {conn_num}, waiting for add_ports from BOTH peers")
        else:
            logger.info(f"Session {session_id}: Waiting for other peer to request retry for connection {conn_num}")
