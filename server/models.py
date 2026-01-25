"""
Data models for TCP Relay Server
"""

from dataclasses import dataclass, field
from typing import Any, Optional, List, Tuple, Dict
import asyncio


@dataclass
class NATAnalysis:
    """Analysis of NAT port allocation behavior - Focus on PORT RANGE not delta!"""

    probed_ports: List[int] = field(default_factory=list)  # NAT ports seen
    local_ports: List[int] = field(default_factory=list)  # Local ports used

    # KEY METRICS - Range is what matters!
    min_port: int = 0  # Minimum NAT port seen
    max_port: int = 0  # Maximum NAT port seen
    port_range: int = 0  # max - min (THIS IS KEY!)

    # Delta metrics (nat_port - local_port)
    delta_min: int = 0
    delta_max: int = 0
    delta_median: float = 0.0
    delta_stdev: float = 0.0
    predicted_port: int = 0
    error_range: int = 0
    port_rate: float = 0.0
    prediction_delay: float = 0.0
    predicted_shift: int = 0

    # Classification
    pattern_type: str = "unknown"  # port_preserved, small_range, large_range, random
    needs_scan: bool = False  # Do we need port range scanning?
    scan_start: int = 0  # Start port for scanning
    scan_end: int = 0  # End port for scanning

    def to_dict(self) -> Dict[str, Any]:
        return {
            "probed_ports": self.probed_ports,
            "local_ports": self.local_ports,
            "min_port": self.min_port,
            "max_port": self.max_port,
            "port_range": self.port_range,
            "delta_min": self.delta_min,
            "delta_max": self.delta_max,
            "delta_median": self.delta_median,
            "delta_stdev": self.delta_stdev,
            "predicted_port": self.predicted_port,
            "error_range": self.error_range,
            "port_rate": self.port_rate,
            "prediction_delay": self.prediction_delay,
            "predicted_shift": self.predicted_shift,
            "pattern_type": self.pattern_type,
            "needs_scan": self.needs_scan,
            "scan_start": self.scan_start,
            "scan_end": self.scan_end,
        }


@dataclass
class Peer:
    """Represents a connected peer"""

    reader: asyncio.StreamReader
    writer: asyncio.StreamWriter
    public_addr: Tuple[str, int]  # (ip, port) as seen by server
    local_port: int  # Port the client will use for hole punch
    role: str  # 'sender' or 'receiver'
    session_id: str
    ready: bool = False
    private_ip: Optional[str] = None
    nat_analysis: Optional[NATAnalysis] = None
    probe_ports: List[Tuple[int, int]] = field(
        default_factory=list
    )  # [(local, nat), ...]
    probes_done: bool = False  # True when probing phase complete
    needs_probing: bool = False  # True if NAT port changed (not preserved)
    prediction_mode: str = "delta"  # delta or external
    prediction_range_extra_pct: float = 0.0  # percent to expand scan range

    # Multi-TCP connection support
    tcp_connections: Optional[int] = None  # Number of TCP connections requested
    bound_ports: List[int] = field(default_factory=list)  # All bound ports from client

    # Multi-Connection coordination state
    ready_for_connection: Dict[int, bool] = field(default_factory=dict)
    conn_results: Dict[int, str] = field(
        default_factory=dict
    )  # conn_num -> "established" | "abandoned"
    conn_reasons: Dict[int, str] = field(
        default_factory=dict
    )  # conn_num -> reason (optional)  # conn_num → ready (bool)

    # PERF: RTT measurement for adaptive GO delay
    measured_rtt: float = 0.0

    # Retry coordination
    retry_requested: Dict[int, bool] = field(
        default_factory=dict
    )  # conn_num -> requested
