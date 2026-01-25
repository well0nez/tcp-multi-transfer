"""
Tests for server/models.py - Data model validation and serialization.
"""

import pytest
from server.models import Peer, NATAnalysis


class TestNATAnalysis:
    """Tests for NATAnalysis dataclass."""

    def test_default_values(self):
        """NATAnalysis should have sensible defaults."""
        analysis = NATAnalysis()

        assert analysis.probed_ports == []
        assert analysis.local_ports == []
        assert analysis.min_port == 0
        assert analysis.max_port == 0
        assert analysis.port_range == 0
        assert analysis.pattern_type == "unknown"
        assert analysis.needs_scan == False

    def test_to_dict_contains_all_fields(self):
        """to_dict() should include all relevant fields."""
        analysis = NATAnalysis(
            probed_ports=[54321],
            local_ports=[12345],
            min_port=54321,
            max_port=54321,
            port_range=0,
            pattern_type="port_preserved",
        )

        d = analysis.to_dict()

        assert "probed_ports" in d
        assert "local_ports" in d
        assert "min_port" in d
        assert "max_port" in d
        assert "port_range" in d
        assert "pattern_type" in d
        assert "needs_scan" in d
        assert "predicted_port" in d
        assert "error_range" in d

    def test_to_dict_values_match(self):
        """to_dict() values should match instance attributes."""
        analysis = NATAnalysis(
            probed_ports=[54321, 54322],
            predicted_port=54325,
            pattern_type="constant_delta",
        )

        d = analysis.to_dict()

        assert d["probed_ports"] == [54321, 54322]
        assert d["predicted_port"] == 54325
        assert d["pattern_type"] == "constant_delta"


class TestPeer:
    """Tests for Peer dataclass."""

    def test_peer_creation(self, mock_stream_reader, mock_stream_writer):
        """Peer should be creatable with required fields."""
        peer = Peer(
            reader=mock_stream_reader,
            writer=mock_stream_writer,
            public_addr=("1.2.3.4", 5678),
            local_port=12345,
            role="sender",
            session_id="test-123",
        )

        assert peer.public_addr == ("1.2.3.4", 5678)
        assert peer.local_port == 12345
        assert peer.role == "sender"
        assert peer.session_id == "test-123"

    def test_peer_default_values(self, mock_stream_reader, mock_stream_writer):
        """Peer should have sensible defaults for optional fields."""
        peer = Peer(
            reader=mock_stream_reader,
            writer=mock_stream_writer,
            public_addr=("1.2.3.4", 5678),
            local_port=12345,
            role="receiver",
            session_id="test-456",
        )

        assert peer.ready == False
        assert peer.private_ip is None
        assert peer.nat_analysis is None
        assert peer.probe_ports == []
        assert peer.probes_done == False
        assert peer.needs_probing == False
        assert peer.tcp_connections is None
        assert peer.bound_ports == []
        assert peer.ready_for_connection == {}
        assert peer.conn_results == {}
        assert peer.measured_rtt == 0.0

    def test_peer_ready_for_connection_tracking(self, sample_peer):
        """Peer should track ready state per connection."""
        sample_peer.ready_for_connection[0] = True
        sample_peer.ready_for_connection[1] = False
        sample_peer.ready_for_connection[2] = True

        assert sample_peer.ready_for_connection[0] == True
        assert sample_peer.ready_for_connection[1] == False
        assert sample_peer.ready_for_connection[2] == True

    def test_peer_conn_results_tracking(self, sample_peer):
        """Peer should track connection results."""
        sample_peer.conn_results[0] = "established"
        sample_peer.conn_results[1] = "abandoned"

        assert sample_peer.conn_results[0] == "established"
        assert sample_peer.conn_results[1] == "abandoned"

    def test_peer_measured_rtt(self, sample_peer):
        """Peer should store measured RTT for adaptive GO delay."""
        sample_peer.measured_rtt = 0.05  # 50ms

        assert sample_peer.measured_rtt == 0.05
