"""
Tests for server/session_manager.py - Session lifecycle and coordination.
"""

import pytest
import asyncio
from server.session_manager import SessionManager
from server.models import Peer


class TestSessionManager:
    """Tests for SessionManager class."""

    def test_creation(self):
        """SessionManager should initialize with empty state."""
        sm = SessionManager()

        assert sm.sessions == {}
        assert sm.pending_probes == {}
        assert sm.peer_info_sent == {}

    def test_get_session_lock_creates_lock(self):
        """get_session_lock should create a lock for new sessions."""
        sm = SessionManager()

        lock1 = sm.get_session_lock("session-1")
        lock2 = sm.get_session_lock("session-2")

        assert lock1 is not None
        assert lock2 is not None
        assert lock1 is not lock2

    def test_get_session_lock_returns_same_lock(self):
        """get_session_lock should return the same lock for the same session."""
        sm = SessionManager()

        lock1 = sm.get_session_lock("session-1")
        lock2 = sm.get_session_lock("session-1")

        assert lock1 is lock2

    @pytest.mark.asyncio
    async def test_session_lock_prevents_concurrent_access(self):
        """Session lock should prevent concurrent modifications."""
        sm = SessionManager()
        lock = sm.get_session_lock("test-session")

        access_order = []

        async def task1():
            async with lock:
                access_order.append("task1_start")
                await asyncio.sleep(0.1)
                access_order.append("task1_end")

        async def task2():
            await asyncio.sleep(0.02)  # Ensure task1 gets lock first
            async with lock:
                access_order.append("task2_start")
                access_order.append("task2_end")

        await asyncio.gather(task1(), task2())

        # task1 should complete before task2 starts
        assert access_order == ["task1_start", "task1_end", "task2_start", "task2_end"]

    @pytest.mark.asyncio
    async def test_cleanup_peer_removes_sender(
        self, mock_stream_reader, mock_stream_writer
    ):
        """cleanup_peer should remove sender from session."""
        sm = SessionManager()
        session_id = "test-session"

        peer = Peer(
            reader=mock_stream_reader,
            writer=mock_stream_writer,
            public_addr=("1.2.3.4", 5678),
            local_port=12345,
            role="sender",
            session_id=session_id,
        )

        sm.sessions[session_id] = {"sender": peer}

        await sm.cleanup_peer(session_id, peer)

        assert "sender" not in sm.sessions.get(session_id, {})

    @pytest.mark.asyncio
    async def test_cleanup_peer_removes_receiver(
        self, mock_stream_reader, mock_stream_writer
    ):
        """cleanup_peer should remove receiver from session."""
        sm = SessionManager()
        session_id = "test-session"

        peer = Peer(
            reader=mock_stream_reader,
            writer=mock_stream_writer,
            public_addr=("1.2.3.4", 5678),
            local_port=12345,
            role="receiver",
            session_id=session_id,
        )

        sm.sessions[session_id] = {"receiver": peer}

        await sm.cleanup_peer(session_id, peer)

        assert "receiver" not in sm.sessions.get(session_id, {})

    @pytest.mark.asyncio
    async def test_cleanup_peer_removes_empty_session(
        self, mock_stream_reader, mock_stream_writer
    ):
        """cleanup_peer should remove session if empty and not coordinating."""
        sm = SessionManager()
        session_id = "test-session"

        peer = Peer(
            reader=mock_stream_reader,
            writer=mock_stream_writer,
            public_addr=("1.2.3.4", 5678),
            local_port=12345,
            role="sender",
            session_id=session_id,
        )

        sm.sessions[session_id] = {"sender": peer, "coordination_active": False}

        await sm.cleanup_peer(session_id, peer)

        # Session should be removed entirely
        assert session_id not in sm.sessions

    @pytest.mark.asyncio
    async def test_cleanup_peer_always_clears_session(
        self, mock_stream_reader, mock_stream_writer
    ):
        """cleanup_peer should always clear session when peer disconnects.

        Note: The current implementation always clears the session when any peer
        disconnects, regardless of coordination_active state. This is intentional
        to prevent orphaned sessions and potential deadlocks.
        """
        sm = SessionManager()
        session_id = "test-session"

        peer = Peer(
            reader=mock_stream_reader,
            writer=mock_stream_writer,
            public_addr=("1.2.3.4", 5678),
            local_port=12345,
            role="sender",
            session_id=session_id,
        )

        sm.sessions[session_id] = {"sender": peer, "coordination_active": True}

        await sm.cleanup_peer(session_id, peer)

        # Session is always cleared when a peer disconnects
        assert session_id not in sm.sessions
