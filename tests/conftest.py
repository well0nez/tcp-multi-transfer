"""
Pytest configuration and shared fixtures for tcp-multi-transfer tests.
"""

import asyncio
import pytest
import sys
from pathlib import Path

# Add server module to path
sys.path.insert(0, str(Path(__file__).parent.parent))


@pytest.fixture(scope="session")
def event_loop():
    """Create an event loop for the entire test session."""
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


@pytest.fixture
def mock_stream_reader():
    """Create a mock StreamReader for testing."""

    class MockStreamReader:
        def __init__(self):
            self._buffer = asyncio.Queue()
            self._closed = False

        async def readline(self):
            if self._closed:
                return b""
            try:
                return await asyncio.wait_for(self._buffer.get(), timeout=1.0)
            except asyncio.TimeoutError:
                return b""

        def feed_data(self, data: bytes):
            """Add data to be read."""
            self._buffer.put_nowait(data)

        def close(self):
            self._closed = True

    return MockStreamReader()


@pytest.fixture
def mock_stream_writer():
    """Create a mock StreamWriter for testing."""

    class MockStreamWriter:
        def __init__(self):
            self._buffer = []
            self._closed = False
            self._drained = False

        def write(self, data: bytes):
            if not self._closed:
                self._buffer.append(data)

        async def drain(self):
            self._drained = True

        def close(self):
            self._closed = True

        async def wait_closed(self):
            pass

        def get_extra_info(self, name):
            if name == "peername":
                return ("127.0.0.1", 12345)
            return None

        def get_written_data(self) -> bytes:
            return b"".join(self._buffer)

        def get_written_messages(self) -> list:
            """Parse written JSON messages."""
            import json

            data = self.get_written_data().decode()
            messages = []
            for line in data.strip().split("\n"):
                if line:
                    try:
                        messages.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass
            return messages

    return MockStreamWriter()


@pytest.fixture
def sample_peer(mock_stream_reader, mock_stream_writer):
    """Create a sample Peer for testing."""
    from server.models import Peer

    return Peer(
        reader=mock_stream_reader,
        writer=mock_stream_writer,
        public_addr=("192.168.1.100", 54321),
        local_port=12345,
        role="sender",
        session_id="test-session-123",
    )


@pytest.fixture
def sample_nat_analysis():
    """Create a sample NATAnalysis for testing."""
    from server.models import NATAnalysis

    return NATAnalysis(
        probed_ports=[54321, 54322, 54323],
        local_ports=[12345, 12346, 12347],
        min_port=54321,
        max_port=54323,
        port_range=2,
        delta_min=41976,
        delta_max=41976,
        delta_median=41976.0,
        predicted_port=54324,
        error_range=5,
        pattern_type="constant_delta",
        needs_scan=False,
    )
