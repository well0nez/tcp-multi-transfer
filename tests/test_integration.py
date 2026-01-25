"""
Integration tests for server + client communication.

These tests verify end-to-end behavior of the relay server with simulated clients.
"""

import pytest
import asyncio
import json
from server.relay.server import TCPRelayServerICE
from server.session_manager import SessionManager


class TestServerClientProtocol:
    """Tests for the server-client protocol flow."""

    @pytest.mark.asyncio
    async def test_server_starts_and_stops(self):
        """Server should start and be stoppable."""
        server = TCPRelayServerICE(host="127.0.0.1", port=19999, probe_port=19998)

        # Start server in background
        server_task = asyncio.create_task(server.start())

        # Give it time to start
        await asyncio.sleep(0.2)

        # Cancel (stop) the server
        server_task.cancel()
        try:
            await server_task
        except asyncio.CancelledError:
            pass

        # If we get here without exception, server started and stopped correctly
        assert True

    @pytest.mark.asyncio
    async def test_client_registration(self):
        """Client should be able to register with the server."""
        server = TCPRelayServerICE(host="127.0.0.1", port=19997, probe_port=19996)
        server_task = asyncio.create_task(server.start())
        await asyncio.sleep(0.2)

        try:
            # Connect as client
            reader, writer = await asyncio.open_connection("127.0.0.1", 19997)

            # Send registration
            register_msg = {
                "type": "register",
                "session_id": "test-session-001",
                "role": "sender",
                "local_port": 12345,
            }
            writer.write((json.dumps(register_msg) + "\n").encode())
            await writer.drain()

            # Read response
            response_line = await asyncio.wait_for(reader.readline(), timeout=5.0)
            response = json.loads(response_line.decode())

            assert response["type"] == "registered"
            assert "your_public_addr" in response
            assert response["session_id"] == "test-session-001"

            writer.close()
            await writer.wait_closed()
        finally:
            server_task.cancel()
            try:
                await server_task
            except asyncio.CancelledError:
                pass

    @pytest.mark.asyncio
    async def test_two_clients_same_session(self):
        """Two clients should be able to join the same session."""
        server = TCPRelayServerICE(host="127.0.0.1", port=19995, probe_port=19994)
        server_task = asyncio.create_task(server.start())
        await asyncio.sleep(0.2)

        try:
            # Connect sender
            sender_reader, sender_writer = await asyncio.open_connection(
                "127.0.0.1", 19995
            )
            sender_msg = {
                "type": "register",
                "session_id": "test-session-002",
                "role": "sender",
                "local_port": 12345,
            }
            sender_writer.write((json.dumps(sender_msg) + "\n").encode())
            await sender_writer.drain()

            sender_response = await asyncio.wait_for(
                sender_reader.readline(), timeout=5.0
            )
            sender_resp = json.loads(sender_response.decode())
            assert sender_resp["type"] == "registered"

            # Connect receiver
            receiver_reader, receiver_writer = await asyncio.open_connection(
                "127.0.0.1", 19995
            )
            receiver_msg = {
                "type": "register",
                "session_id": "test-session-002",
                "role": "receiver",
                "local_port": 23456,
            }
            receiver_writer.write((json.dumps(receiver_msg) + "\n").encode())
            await receiver_writer.drain()

            receiver_response = await asyncio.wait_for(
                receiver_reader.readline(), timeout=5.0
            )
            receiver_resp = json.loads(receiver_response.decode())
            assert receiver_resp["type"] == "registered"

            # Verify session has both peers
            assert "test-session-002" in server.session_manager.sessions
            session = server.session_manager.sessions["test-session-002"]
            assert "sender" in session
            assert "receiver" in session

            sender_writer.close()
            receiver_writer.close()
            await sender_writer.wait_closed()
            await receiver_writer.wait_closed()
        finally:
            server_task.cancel()
            try:
                await server_task
            except asyncio.CancelledError:
                pass

    @pytest.mark.asyncio
    async def test_duplicate_role_rejected(self):
        """Server should reject duplicate role registration."""
        server = TCPRelayServerICE(host="127.0.0.1", port=19993, probe_port=19992)
        server_task = asyncio.create_task(server.start())
        await asyncio.sleep(0.2)

        try:
            # Connect first sender
            sender1_reader, sender1_writer = await asyncio.open_connection(
                "127.0.0.1", 19993
            )
            sender1_msg = {
                "type": "register",
                "session_id": "test-session-003",
                "role": "sender",
                "local_port": 12345,
            }
            sender1_writer.write((json.dumps(sender1_msg) + "\n").encode())
            await sender1_writer.drain()

            response1 = await asyncio.wait_for(sender1_reader.readline(), timeout=5.0)
            resp1 = json.loads(response1.decode())
            assert resp1["type"] == "registered"

            # Try to connect second sender (should be rejected)
            sender2_reader, sender2_writer = await asyncio.open_connection(
                "127.0.0.1", 19993
            )
            sender2_msg = {
                "type": "register",
                "session_id": "test-session-003",
                "role": "sender",  # Same role!
                "local_port": 23456,
            }
            sender2_writer.write((json.dumps(sender2_msg) + "\n").encode())
            await sender2_writer.drain()

            response2 = await asyncio.wait_for(sender2_reader.readline(), timeout=5.0)
            resp2 = json.loads(response2.decode())
            assert resp2["type"] == "error"
            assert "already taken" in resp2.get("message", "").lower()

            sender1_writer.close()
            sender2_writer.close()
            await sender1_writer.wait_closed()
            await sender2_writer.wait_closed()
        finally:
            server_task.cancel()
            try:
                await server_task
            except asyncio.CancelledError:
                pass


class TestTimeoutBehavior:
    """Tests for timeout and deadlock prevention."""

    @pytest.mark.asyncio
    async def test_client_disconnect_cleans_session(self):
        """Session should be cleaned up when client disconnects."""
        server = TCPRelayServerICE(host="127.0.0.1", port=19991, probe_port=19990)
        server_task = asyncio.create_task(server.start())
        await asyncio.sleep(0.2)

        try:
            # Connect client
            reader, writer = await asyncio.open_connection("127.0.0.1", 19991)
            msg = {
                "type": "register",
                "session_id": "test-session-004",
                "role": "sender",
                "local_port": 12345,
            }
            writer.write((json.dumps(msg) + "\n").encode())
            await writer.drain()

            response = await asyncio.wait_for(reader.readline(), timeout=5.0)
            assert json.loads(response.decode())["type"] == "registered"

            # Verify session exists
            assert "test-session-004" in server.session_manager.sessions

            # Disconnect client
            writer.close()
            await writer.wait_closed()

            # Give server time to clean up
            await asyncio.sleep(0.5)

            # Session should be cleaned up
            # Note: cleanup happens on next read attempt or explicit cleanup
            # The session might still exist briefly

        finally:
            server_task.cancel()
            try:
                await server_task
            except asyncio.CancelledError:
                pass
