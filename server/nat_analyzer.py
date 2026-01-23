"""
NAT Pattern Detection and Port Prediction
"""
import statistics
import logging
from typing import List, Tuple, Dict
from .models import NATAnalysis

logger = logging.getLogger(__name__)

MIN_PORT = 1024
MAX_PORT = 65535
PREDICTION_DELAY_SEC = 2.0
RATE_DAMPING = 0.5
MAX_RATE_SHIFT = 32


def analyze_nat(
    probes: List[Tuple[str, int, int, float]],
    target_local_port: int,
    prediction_mode: str,
    prediction_range_extra_pct: float,
) -> NATAnalysis:
    """Analyze NAT behavior and predict the peer-facing port range."""
    analysis = NATAnalysis()
    use_external = prediction_mode == "external"

    if len(probes) < 2:
        analysis.pattern_type = "insufficient_data"
        return analysis

    if not use_external and target_local_port <= 0:
        analysis.pattern_type = "insufficient_data"
        return analysis

    # Extract ports
    for ip, nat_port, local_port, _ts in probes:
        analysis.probed_ports.append(nat_port)
        analysis.local_ports.append(local_port)

    # Key metrics
    analysis.min_port = min(analysis.probed_ports)
    analysis.max_port = max(analysis.probed_ports)
    analysis.port_range = analysis.max_port - analysis.min_port

    # Port preservation
    preserved = all(
        nat == local
        for nat, local in zip(analysis.probed_ports, analysis.local_ports)
    )

    if preserved and target_local_port > 0:
        analysis.pattern_type = "port_preserved"
        analysis.needs_scan = False
        analysis.predicted_port = max(MIN_PORT, min(MAX_PORT, target_local_port))
        analysis.scan_start = analysis.predicted_port
        analysis.scan_end = analysis.predicted_port
        logger.info("NAT Analysis: port preserved (no scan needed)")
        return analysis

    if use_external:
        mean_port = statistics.mean(analysis.probed_ports)
        predicted = int(round(mean_port))
        analysis.predicted_port = max(MIN_PORT, min(MAX_PORT, predicted))

        max_dev = max(abs(p - mean_port) for p in analysis.probed_ports)
        stdev = statistics.pstdev(analysis.probed_ports) if len(analysis.probed_ports) > 1 else 0.0
        jitter = max(2, int(round(stdev * 2)))
        analysis.error_range = int(round(max_dev + jitter))
    else:
        # Delta-based prediction (nat_port - local_port)
        deltas = [
            nat - local
            for nat, local in zip(analysis.probed_ports, analysis.local_ports)
            if local > 0
        ]
        if not deltas:
            analysis.pattern_type = "insufficient_data"
            return analysis

        analysis.delta_min = min(deltas)
        analysis.delta_max = max(deltas)
        analysis.delta_median = statistics.median(deltas)
        analysis.delta_stdev = statistics.pstdev(deltas) if len(deltas) > 1 else 0.0

        predicted = int(round(target_local_port + analysis.delta_median))
        analysis.predicted_port = max(MIN_PORT, min(MAX_PORT, predicted))

        max_dev = max(abs(d - analysis.delta_median) for d in deltas)
        jitter = max(2, int(round(analysis.delta_stdev * 2)))
        analysis.error_range = int(round(max_dev + jitter))

    analysis.prediction_delay = PREDICTION_DELAY_SEC
    analysis.port_rate = 0.0
    analysis.predicted_shift = 0

    sorted_probes = sorted(probes, key=lambda p: p[3])
    if len(sorted_probes) >= 2:
        times = [p[3] for p in sorted_probes]
        ports = [p[1] for p in sorted_probes]
        time_span = times[-1] - times[0]
        if time_span > 0:
            diffs = [ports[i] - ports[i - 1] for i in range(1, len(ports))]
            pos_diffs = [d for d in diffs if d > 0]
            pos_ratio = len(pos_diffs) / len(diffs) if diffs else 0.0
            if pos_ratio >= 0.6:
                port_span = sum(pos_diffs)
                if port_span > 0:
                    analysis.port_rate = port_span / time_span

    if analysis.port_rate > 0.0:
        raw_shift = int(round(analysis.port_rate * analysis.prediction_delay * RATE_DAMPING))
        analysis.predicted_shift = max(0, min(MAX_RATE_SHIFT, raw_shift))
        if analysis.predicted_shift > 0:
            analysis.predicted_port = max(
                MIN_PORT,
                min(MAX_PORT, analysis.predicted_port + analysis.predicted_shift),
            )

    analysis.scan_start = max(MIN_PORT, analysis.predicted_port - analysis.error_range)
    analysis.scan_end = min(MAX_PORT, analysis.predicted_port + analysis.error_range)
    analysis.needs_scan = analysis.error_range > 0

    def apply_range_extra() -> None:
        if prediction_range_extra_pct <= 0.0:
            return
        if analysis.scan_start <= 0 or analysis.scan_end <= 0:
            return
        if analysis.scan_end < analysis.scan_start:
            return
        span = analysis.scan_end - analysis.scan_start
        if span <= 0:
            return
        extra_total = int(round(span * (prediction_range_extra_pct / 100.0)))
        if extra_total <= 0:
            return
        pad_low = extra_total // 2
        pad_high = extra_total - pad_low
        analysis.scan_start = max(MIN_PORT, analysis.scan_start - pad_low)
        analysis.scan_end = min(MAX_PORT, analysis.scan_end + pad_high)
        analysis.needs_scan = True
        logger.info(
            "NAT Analysis: expanded scan range by %.2f%%",
            prediction_range_extra_pct,
        )

    if use_external:
        if analysis.port_range == 0:
            analysis.pattern_type = "constant"
            analysis.needs_scan = False
            analysis.error_range = 0
            analysis.scan_start = analysis.predicted_port
            analysis.scan_end = analysis.predicted_port
        elif analysis.error_range <= 5:
            analysis.pattern_type = "small_range"
        elif analysis.error_range <= 30:
            analysis.pattern_type = "medium_range"
        elif analysis.error_range <= 100:
            analysis.pattern_type = "large_range"
        else:
            analysis.pattern_type = "random_like"
            analysis.scan_start = max(MIN_PORT, analysis.min_port)
            analysis.scan_end = min(MAX_PORT, analysis.max_port)
            analysis.needs_scan = True
        apply_range_extra()

        logger.info(
            "NAT Analysis (external): predicted=%s range=%s-%s",
            analysis.predicted_port,
            analysis.scan_start,
            analysis.scan_end,
        )

        return analysis

    delta_spread = analysis.delta_max - analysis.delta_min
    if delta_spread == 0:
        analysis.pattern_type = "constant_delta"
        analysis.needs_scan = False
        analysis.error_range = 0
        analysis.scan_start = analysis.predicted_port
        analysis.scan_end = analysis.predicted_port
    elif analysis.error_range <= 5:
        analysis.pattern_type = "small_delta_range"
    elif analysis.error_range <= 30:
        analysis.pattern_type = "medium_delta_range"
    elif analysis.error_range <= 100:
        analysis.pattern_type = "large_delta_range"
    else:
        analysis.pattern_type = "random_like"
        analysis.scan_start = max(MIN_PORT, analysis.min_port)
        analysis.scan_end = min(MAX_PORT, analysis.max_port)
        analysis.needs_scan = True
    apply_range_extra()

    logger.info(
        "NAT Analysis: delta_range=%s predicted=%s range=%s-%s",
        delta_spread,
        analysis.predicted_port,
        analysis.scan_start,
        analysis.scan_end,
    )

    return analysis


def build_candidate_ports(analysis: NATAnalysis, max_scan_ports: int) -> List[int]:
    """Build list of candidate ports to try based on NAT analysis."""
    if not analysis or not analysis.needs_scan:
        return []
    if analysis.scan_start <= 0 or analysis.scan_end <= 0:
        return []
    if analysis.scan_end < analysis.scan_start:
        return []

    if analysis.pattern_type == "random_like":
        ports = []
        seen = set()

        def add_port(port: int):
            if port < analysis.scan_start or port > analysis.scan_end:
                return
            if port in seen:
                return
            seen.add(port)
            ports.append(port)

        if analysis.predicted_port:
            add_port(analysis.predicted_port)

        base = analysis.min_port
        for delta in (1, 2, 3, 4, 5):
            add_port(base + delta)

        remaining = max_scan_ports - len(ports)
        if remaining > 0:
            span = analysis.scan_end - analysis.scan_start
            step = max(1, span // remaining) if span > 0 else 1
            p = analysis.scan_start
            while p <= analysis.scan_end and len(ports) < max_scan_ports:
                add_port(p)
                p += step

        return ports

    total = analysis.scan_end - analysis.scan_start + 1
    if total <= max_scan_ports:
        return list(range(analysis.scan_start, analysis.scan_end + 1))

    predicted = analysis.predicted_port or ((analysis.scan_start + analysis.scan_end) // 2)
    half = max_scan_ports // 2
    window_start = max(analysis.scan_start, predicted - half)
    window_end = window_start + max_scan_ports - 1
    if window_end > analysis.scan_end:
        window_end = analysis.scan_end
        window_start = max(analysis.scan_start, window_end - max_scan_ports + 1)
    return list(range(window_start, window_end + 1))
