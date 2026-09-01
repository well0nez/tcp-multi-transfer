"""
Session and Peer Management
"""
import asyncio
import logging
from typing import Dict, List
from .models import Peer, SessionState

logger = logging.getLogger(__name__)

MIN_PORT = 1024
MAX_PORT = 65535


class SessionManager:
    """Manages sessions and peer connections"""
    
    def __init__(self):
        self.sessions: Dict[str, SessionState] = {}
        self.session_locks: Dict[str, asyncio.Lock] = {}
        self.pending_probes: Dict[str, List[tuple]] = {}
        # (session_id, oeffentliche IP) -> Ergebnis des Filtertests
        self.filter_ergebnis: Dict[tuple, str] = {}
    
    def get_session_lock(self, session_id: str) -> asyncio.Lock:
        """Get or create lock for session"""
        if session_id not in self.session_locks:
            self.session_locks[session_id] = asyncio.Lock()
        return self.session_locks[session_id]
    
    async def cleanup_peer(self, session_id: str, peer: Peer):
        """Clean up peer from session"""
        lock = self.get_session_lock(session_id)
        other_peer = None
        async with lock:
            session = self.sessions.get(session_id)
            if not session:
                return

            if session.peer(peer.role) is peer:
                session.setze(peer.role, None)

            other_peer = session.gegenseite(peer.role)
            if other_peer:
                session.setze('sender' if peer.role == 'receiver' else 'receiver', None)

            # Always clear the session if any peer disconnects.
            self.sessions.pop(session_id, None)
            self.pending_probes.pop(session_id, None)
            # Auch das Schloss selbst: sonst sammelt ein langlaufender Relay
            # einen Eintrag je jemals gesehener Sitzungskennung an.
            self.session_locks.pop(session_id, None)

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
