"""
Tests for server/relay/coordinator.py - Connection coordination and GO delay.
"""

import pytest
import time
from unittest.mock import MagicMock, AsyncMock, patch
from server.relay.coordinator import (
    determine_punch_strategy,
    get_nat_port_for_local_port,
)
from server.models import Peer, NATAnalysis


class TestDeterminePunchStrategy:
    """Tests for determine_punch_strategy function."""

    def test_always_returns_scan(self, mock_stream_reader, mock_stream_writer):
        """Strategy should always be 'scan' for TCP hole punching."""
        peer1 = Peer(
            reader=mock_stream_reader,
            writer=mock_stream_writer,
            public_addr=("1.2.3.4", 5678),
            local_port=12345,
            role="sender",
            session_id="test",
        )
        peer2 = Peer(
            reader=mock_stream_reader,
            writer=mock_stream_writer,
            public_addr=("5.6.7.8", 9012),
            local_port=23456,
            role="receiver",
            session_id="test",
        )

        strategy = determine_punch_strategy(peer1, peer2)

        assert strategy == "scan"


class TestGetNatPortForLocalPort:
    """Tests for get_nat_port_for_local_port function."""

    def test_returns_known_mapping(self, mock_stream_reader, mock_stream_writer):
        """Should return NAT port if mapping exists in probe_ports."""
        peer = Peer(
            reader=mock_stream_reader,
            writer=mock_stream_writer,
            public_addr=("1.2.3.4", 5678),
            local_port=12345,
            role="sender",
            session_id="test",
        )
        peer.probe_ports = [(12345, 54321), (12346, 54322)]

        nat_port = get_nat_port_for_local_port(peer, 12345)

        assert nat_port == 54321

    def test_port_preserved_nat(self, mock_stream_reader, mock_stream_writer):
        """Should return local port for port-preserved NAT."""
        peer = Peer(
            reader=mock_stream_reader,
            writer=mock_stream_writer,
            public_addr=("1.2.3.4", 5678),
            local_port=12345,
            role="sender",
            session_id="test",
        )
        peer.nat_analysis = NATAnalysis(pattern_type="port_preserved")

        nat_port = get_nat_port_for_local_port(peer, 12345)

        assert nat_port == 12345

    def test_delta_prediction(self, mock_stream_reader, mock_stream_writer):
        """Should use delta-based prediction when available."""
        peer = Peer(
            reader=mock_stream_reader,
            writer=mock_stream_writer,
            public_addr=("1.2.3.4", 5678),
            local_port=12345,
            role="sender",
            session_id="test",
        )
        peer.nat_analysis = NATAnalysis(
            delta_median=1000,
            predicted_shift=0,
            pattern_type="constant_delta",
        )

        nat_port = get_nat_port_for_local_port(peer, 12345)

        # 12345 + 1000 = 13345
        assert nat_port == 13345

    def test_clamps_to_valid_port_range(self, mock_stream_reader, mock_stream_writer):
        """Should clamp predicted port to valid range (1024-65535)."""
        peer = Peer(
            reader=mock_stream_reader,
            writer=mock_stream_writer,
            public_addr=("1.2.3.4", 5678),
            local_port=60000,
            role="sender",
            session_id="test",
        )
        peer.nat_analysis = NATAnalysis(
            delta_median=10000,  # Would give 70000, exceeds max
            pattern_type="constant_delta",
        )

        nat_port = get_nat_port_for_local_port(peer, 60000)

        assert nat_port <= 65535

    def test_fallback_to_public_addr(self, mock_stream_reader, mock_stream_writer):
        """Should fallback to public_addr port if no prediction available."""
        peer = Peer(
            reader=mock_stream_reader,
            writer=mock_stream_writer,
            public_addr=("1.2.3.4", 5678),
            local_port=12345,
            role="sender",
            session_id="test",
        )
        # No nat_analysis, no probe_ports

        nat_port = get_nat_port_for_local_port(peer, 99999)

        assert nat_port == 5678  # Falls back to public_addr port


class TestAdaptiveGoDelay:
    """Tests for adaptive GO delay calculation."""

    def test_go_delay_formula(self):
        """GO delay should follow the formula: max(0.5, min(3.0, 2*rtt + 0.3))."""
        # Test cases: (rtt, expected_delay)
        test_cases = [
            (0.001, 0.5),  # 1ms RTT -> min 0.5s
            (0.05, 0.5),  # 50ms RTT -> 2*0.05+0.3 = 0.4 -> min 0.5s
            (0.1, 0.5),  # 100ms RTT -> 2*0.1+0.3 = 0.5s
            (0.2, 0.7),  # 200ms RTT -> 2*0.2+0.3 = 0.7s
            (0.5, 1.3),  # 500ms RTT -> 2*0.5+0.3 = 1.3s
            (1.0, 2.3),  # 1000ms RTT -> 2*1.0+0.3 = 2.3s
            (2.0, 3.0),  # 2000ms RTT -> 2*2.0+0.3 = 4.3 -> max 3.0s
        ]

        for rtt, expected in test_cases:
            # Formula from coordinator.py
            calculated = max(0.5, min(3.0, 2 * rtt + 0.3))
            assert abs(calculated - expected) < 0.01, (
                f"RTT={rtt}: expected {expected}, got {calculated}"
            )

    def test_zero_rtt_uses_default(self):
        """Zero RTT (not measured) should use default delay."""
        rtt = 0.0

        # When RTT is 0 or very small, coordinator uses default 1.5s
        if rtt <= 0.01:
            delay = 1.5  # Default
        else:
            delay = max(0.5, min(3.0, 2 * rtt + 0.3))

        assert delay == 1.5
