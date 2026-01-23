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
        async with lock:
            session = self.sessions.get(session_id)
            if session and peer.role in session:
                if session[peer.role] is peer:
                    del session[peer.role]
                if not session:
                    del self.sessions[session_id]
                    if session_id in self.pending_probes:
                        del self.pending_probes[session_id]
                    if session_id in self.peer_info_sent:
                        del self.peer_info_sent[session_id]