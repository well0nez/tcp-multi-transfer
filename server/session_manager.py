"""
Session and Peer Management
"""
import asyncio
import logging
from typing import Dict, List
from .models import Peer

logger = logging.getLogger(__name__)

MIN_PORT = 1024
MAX_PORT = 65535


class SessionManager:
    """Manages sessions and peer connections"""
    
    def __init__(self):
        self.sessions: Dict[str, Dict[str, Peer]] = {}
        self.session_locks: Dict[str, asyncio.Lock] = {}
        self.pending_probes: Dict[str, List[tuple]] = {}
        self.peer_info_sent: Dict[str, bool] = {}
    
    def get_session_lock(self, session_id: str) -> asyncio.Lock:
        """Get or create lock for session"""
        if session_id not in self.session_locks:
            self.session_locks[session_id] = asyncio.Lock()
        return self.session_locks[session_id]
    
    def parse_local_ports(self, local_ports_raw, fallback_port: int) -> List[int]:
        """Parse and validate local ports list"""
        ports: List[int] = []
        if isinstance(local_ports_raw, list):
            for port in local_ports_raw:
                try:
                    port_int = int(port)
                except (TypeError, ValueError):
                    continue
                if MIN_PORT <= port_int <= MAX_PORT:
                    ports.append(port_int)

        seen = set()
        ordered: List[int] = []
        for port in ports:
            if port in seen:
                continue
            seen.add(port)
            ordered.append(port)

        if fallback_port and fallback_port not in ordered:
            ordered.insert(0, fallback_port)
        if not ordered and fallback_port:
            ordered = [fallback_port]

        return ordered
    
    async def cleanup_peer(self, session_id: str, peer: Peer):
        """Clean up peer from session"""
        lock = self.get_session_lock(session_id)
        other_peer = None
        async with lock:
            session = self.sessions.get(session_id)
            if not session:
                return

            if peer.role in session and session[peer.role] is peer:
                del session[peer.role]

            other_role = 'sender' if peer.role == 'receiver' else 'receiver'
            other_peer = session.get(other_role)
            if other_peer:
                del session[other_role]

            # Always clear the session if any peer disconnects.
            self.sessions.pop(session_id, None)
            self.pending_probes.pop(session_id, None)
            self.peer_info_sent.pop(session_id, None)

        if other_peer:
            logger.warning(
                f"Session {session_id}: {peer.role} disconnected - closing {other_peer.role} and clearing session"
            )
            try:
                if not other_peer.writer.is_closing():
                    other_peer.writer.close()
                await other_peer.writer.wait_closed()
            except Exception:
                pass
