"""
Data models for TCP Relay Server
"""
from dataclasses import dataclass, field
from typing import Optional, List, Tuple, Dict
import asyncio


@dataclass
class NATAnalysis:
    """Analysis of NAT port allocation behavior - Focus on PORT RANGE not delta!"""
    probed_ports: List[int] = field(default_factory=list)  # NAT ports seen
    local_ports: List[int] = field(default_factory=list)   # Local ports used
    
    # KEY METRICS - Range is what matters!
    min_port: int = 0          # Minimum NAT port seen
    max_port: int = 0          # Maximum NAT port seen
    port_range: int = 0        # max - min (THIS IS KEY!)

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
    prediction_source: str = "unbekannt"  # extrapoliert | median_beobachtet
    pattern_type: str = "unknown"  # port_preserved, small_range, large_range, random
    needs_scan: bool = False       # Do we need port range scanning?
    scan_start: int = 0            # Start port for scanning
    scan_end: int = 0              # End port for scanning

    # Getrennte Eigenschaften nach RFC 4787 — Vergabe, Mapping, Filterung sind
    # drei verschiedene Dinge und wurden frueher in `pattern_type` vermengt.
    allocation: str = "unbestimmt"          # portbewahrend|versatzstabil|fortlaufend|zufaellig_im_band
    mapping_behaviour: str = "unbestimmt"   # endpunktunabhaengig|portabhaengig
    filtering_behaviour: str = "unbestimmt" # adressabhaengig|adress_und_portabhaengig
    band_low: int = 0              # geschaetzte Bandgrenzen bei zufaelliger Vergabe
    band_high: int = 0
    block_size: int = 0            # erkannter CGNAT-Portblock, 0 = keiner
    trend_r2: float = 0.0          # Bestimmtheitsmass des Zeittrends
    hit_probability: float = 0.0   # erwartete Trefferquote einer frischen Ziehung
    
    def to_dict(self) -> dict:
        return {
            'probed_ports': self.probed_ports,
            'local_ports': self.local_ports,
            'min_port': self.min_port,
            'max_port': self.max_port,
            'port_range': self.port_range,
            'delta_min': self.delta_min,
            'delta_max': self.delta_max,
            'delta_median': self.delta_median,
            'delta_stdev': self.delta_stdev,
            'predicted_port': self.predicted_port,
            'error_range': self.error_range,
            'port_rate': self.port_rate,
            'prediction_delay': self.prediction_delay,
            'predicted_shift': self.predicted_shift,
            'prediction_source': self.prediction_source,
            'pattern_type': self.pattern_type,
            'needs_scan': self.needs_scan,
            'scan_start': self.scan_start,
            'scan_end': self.scan_end,
            'allocation': self.allocation,
            'mapping_behaviour': self.mapping_behaviour,
            'filtering_behaviour': self.filtering_behaviour,
            'band_low': self.band_low,
            'band_high': self.band_high,
            'block_size': self.block_size,
            'trend_r2': self.trend_r2,
            'hit_probability': self.hit_probability,
        }


@dataclass
class SessionState:
    """Der Zustand einer Sitzung — deklariert statt zusammengesteckt.

    Vorher war das ein `dict` mit Schluesseln, die ueber drei Dateien verstreut
    gesetzt und gelesen wurden (`'retry_add_ports_pending'`,
    `f'retry_timeout_task_{n}'`, `'conn_results'` …). Ein Tippfehler fiel dabei
    erst zur Laufzeit auf, und es gab keine Stelle, an der man nachlesen
    konnte, woraus der Zustand ueberhaupt besteht.
    """
    sender: Optional["Peer"] = None
    receiver: Optional["Peer"] = None
    # Ergebnis je Rolle und Verbindungsnummer: "established" | "abandoned"
    conn_results: Dict[str, Dict[int, str]] = field(
        default_factory=lambda: {"sender": {}, "receiver": {}})
    conn_reasons: Dict[str, Dict[int, str]] = field(
        default_factory=lambda: {"sender": {}, "receiver": {}})
    # Verbindungsnummer -> welche Seite ihre neuen Ports schon gemeldet hat
    retry_pending: Dict[int, dict] = field(default_factory=dict)
    # Verbindungsnummer -> laufende Zeitueberwachung der Wiederholung
    retry_tasks: Dict[int, asyncio.Task] = field(default_factory=dict)
    # Laufende Koordinationsaufgaben. Sie brauchen eine Referenz: eine Aufgabe,
    # die nur der Ereignisschleife bekannt ist, kann eingesammelt werden, und
    # ihre Ausnahmen gingen still verloren.
    koordination: Optional[asyncio.Task] = None
    retry_koordination: Dict[int, asyncio.Task] = field(default_factory=dict)

    def peer(self, rolle: str) -> Optional["Peer"]:
        return self.sender if rolle == "sender" else self.receiver

    def setze(self, rolle: str, peer: Optional["Peer"]) -> None:
        if rolle == "sender":
            self.sender = peer
        else:
            self.receiver = peer

    def gegenseite(self, rolle: str) -> Optional["Peer"]:
        return self.receiver if rolle == "sender" else self.sender

    def beide(self):
        return self.sender, self.receiver


@dataclass
class Peer:
    """Represents a connected peer"""
    reader: asyncio.StreamReader
    writer: asyncio.StreamWriter
    public_addr: tuple  # (ip, port) as seen by server
    local_port: int     # Port the client will use for hole punch
    role: str           # 'sender' or 'receiver'
    session_id: str
    private_ip: Optional[str] = None
    nat_analysis: Optional[NATAnalysis] = None
    probe_ports: List[Tuple[int, int]] = field(default_factory=list)  # [(local, nat), ...]
    probes_done: bool = False  # True when probing phase complete
    needs_probing: bool = False  # True if NAT port changed (not preserved)
    prediction_mode: str = "delta"  # delta or external
    prediction_range_extra_pct: float = 0.0  # percent to expand scan range
    
    # Wie viele lokale Ports die Gegenstelle beim Punchen gleichzeitig haelt.
    # Daraus rechnet der Relay, wie viele Ports dieses Peers die andere Seite
    # abdecken muss.
    punch_ports: int = 1

    # Multi-TCP connection support
    tcp_connections: Optional[int] = None  # Number of TCP connections requested
    bound_ports: List[int] = field(default_factory=list)  # All bound ports from client
    
    # Multi-Connection coordination state
    ready_for_connection: dict = field(default_factory=dict)
    conn_results: Dict[int, str] = field(default_factory=dict)  # conn_num -> "established" | "abandoned"
    conn_reasons: Dict[int, str] = field(default_factory=dict)  # conn_num -> Grund (optional)
    # Verbindungsnummer -> will diese Seite eine Wiederholung?
    # Frueher per `hasattr` nachtraeglich angeklebt.
    retry_requested: Dict[int, bool] = field(default_factory=dict)
