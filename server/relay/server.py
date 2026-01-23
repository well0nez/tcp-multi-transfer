"""
TCP Hole Punch Relay Server - Main Server Class
"""
import asyncio
import json
import logging
import time
from typing import Dict, List, Optional

from ..models import Peer, NATAnalysis
from ..session_manager import SessionManager
from .utils import send_message, send_error
from .handlers import wait_for_peer_messages
from .coordinator import try_start_session

logger = logging.getLogger(__name__)

MIN_PORT = 1024
MAX_PORT = 65535


class TCPRelayServerICE:
    """TCP Hole Punch Relay Server with NAT Probing"""
    
    def __init__(
        self,
        host: str = '0.0.0.0',
        port: int = 9999,
        probe_port: int = 9998,
        max_scan_ports: int = 512,
    ):
        self.host = host
        self.port = port
        self.probe_port = probe_port
        self.max_scan_ports = max(1, max_scan_ports)
        self.session_manager = SessionManager()
    
    async def start(self):
        """Start both main server and probe server"""
        # Main server
        main_server = await asyncio.start_server(
            self.handle_client,
            self.host,
            self.port
        )
        
        # Probe server (for NAT analysis)
        probe_server = await asyncio.start_server(
            self.handle_probe,
            self.host,
            self.probe_port
        )
        
        logger.info(f"TCP Relay Server v3.0 (ICE-Lite) listening on {self.host}:{self.port}")
        logger.info(f"NAT Probe Server listening on {self.host}:{self.probe_port}")
        logger.info("Features: NAT Probing, Pattern Detection, Port Prediction")
        
        await asyncio.gather(
            main_server.serve_forever(),
            probe_server.serve_forever()
        )
    
    async def handle_probe(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """Handle a probe connection (for NAT analysis)"""
        addr = writer.get_extra_info('peername')
        
        try:
            # Quick read of probe info
            data = await asyncio.wait_for(reader.readline(), timeout=5.0)
            if not data:
                return
            
            msg = json.loads(data.decode())
            if msg.get('type') != 'probe':
                return
            
            session_id = msg.get('session_id')
            local_port = msg.get('local_port', 0)
            probe_num = msg.get('probe_num', 0)
            
            if not session_id:
                return
            
            # Record this probe
            ip, nat_port = addr
            ts = time.time()
            logger.debug(f"Probe #{probe_num} from {session_id}: local={local_port} nat={nat_port}")
            
            if session_id not in self.session_manager.pending_probes:
                self.session_manager.pending_probes[session_id] = []
            self.session_manager.pending_probes[session_id].append((ip, nat_port, local_port, ts))
            
            # Send ACK with observed port
            await send_message(writer, {
                'type': 'probe_ack',
                'probe_num': probe_num,
                'your_nat_port': nat_port
            })
            
        except Exception as e:
            logger.debug(f"Probe error: {e}")
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except:
                pass
    
    async def handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """Handle a new client connection"""
        addr = writer.get_extra_info('peername')
        logger.info(f"New connection from {addr}")
        
        peer = None
        session_id = None
        
        try:
            data = await asyncio.wait_for(reader.readline(), timeout=300.0)
            if not data:
                return
            
            msg = json.loads(data.decode())
            
            if msg.get('type') != 'register':
                await send_error(writer, "Expected 'register' message")
                return
            
            session_id = msg['session_id']
            role = msg['role']
            local_port = msg.get('local_port', 0)
            private_ip = msg.get('private_ip')
            skip_probing = msg.get('skip_probing', False)
            prediction_mode = (msg.get('prediction_mode') or 'delta').lower()
            if prediction_mode not in ('delta', 'external'):
                logger.warning(f"Unknown prediction_mode '{prediction_mode}', defaulting to 'delta'")
                prediction_mode = 'delta'
            range_raw = msg.get('prediction_range_extra_pct', 0.0)
            try:
                prediction_range_extra_pct = float(range_raw)
            except (TypeError, ValueError):
                logger.warning(f"Invalid prediction_range_extra_pct '{range_raw}', defaulting to 0.0")
                prediction_range_extra_pct = 0.0
            
            if role not in ('sender', 'receiver'):
                await send_error(writer, f"Invalid role: {role}")
                return
            
            peer = Peer(
                reader=reader,
                writer=writer,
                public_addr=addr,
                local_port=local_port,
                role=role,
                session_id=session_id,
                private_ip=private_ip,
                prediction_mode=prediction_mode,
                prediction_range_extra_pct=prediction_range_extra_pct,
            )
            
            lock = self.session_manager.get_session_lock(session_id)
            
            async with lock:
                if session_id not in self.session_manager.sessions:
                    self.session_manager.sessions[session_id] = {}
                
                session = self.session_manager.sessions[session_id]
                
                if role in session:
                    await send_error(writer, f"Role '{role}' already taken")
                    return
                
                session[role] = peer
                logger.info(f"Registered {role} for session {session_id}: {addr}, local_port={local_port}")
            
            # Calculate initial delta
            initial_delta = addr[1] - local_port if local_port else 0
            port_preserved = (initial_delta == 0)
            
            # Determine if probing is needed
            peer.needs_probing = not skip_probing and not port_preserved
            peer.probes_done = not peer.needs_probing
            
            # Create basic NAT analysis for port-preserved case
            if port_preserved:
                predicted_port = max(MIN_PORT, min(MAX_PORT, local_port or addr[1]))
                peer.nat_analysis = NATAnalysis(
                    probed_ports=[addr[1]],
                    local_ports=[local_port],
                    min_port=addr[1],
                    max_port=addr[1],
                    port_range=0,
                    predicted_port=predicted_port,
                    error_range=0,
                    pattern_type="port_preserved",
                    needs_scan=False,
                    scan_start=predicted_port,
                    scan_end=predicted_port,
                )
            
            # Collect multiple timestamps for robust time synchronization
            # Using 5 samples with 50ms intervals for median-based offset calculation
            server_times = []
            for _ in range(5):
                server_times.append(time.time())
                await asyncio.sleep(0.05)  # 50ms between samples
            
            # Send registration ACK with multiple timestamps
            await send_message(writer, {
                'type': 'registered',
                'your_public_addr': list(addr),
                'your_role': role,
                'session_id': session_id,
                'server_time': server_times[0],  # Keep first for backward compat
                'server_times': server_times,     # NEW: Multiple timestamps for median
                'initial_delta': initial_delta,
                'port_preserved': port_preserved,
                'needs_probing': peer.needs_probing,
                'probe_port': self.probe_port if peer.needs_probing else None
            })
            
            logger.info(f"Peer {role}: port_preserved={port_preserved}, needs_probing={peer.needs_probing}")
            
            # Try to start session
            await try_start_session(session_id, self.session_manager, self.max_scan_ports)
            
            # Wait for messages
            await wait_for_peer_messages(peer, self.session_manager, self.max_scan_ports)
        
        except asyncio.TimeoutError:
            logger.warning(f"Client {addr} timed out")
        except Exception as e:
            logger.error(f"Error handling client {addr}: {e}", exc_info=True)
        finally:
            if session_id and peer:
                await self.session_manager.cleanup_peer(session_id, peer)
            try:
                writer.close()
                await writer.wait_closed()
            except:
                pass