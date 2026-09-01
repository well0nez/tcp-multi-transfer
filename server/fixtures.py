"""
Aufzeichnung von NAT-Analysen als Golden Fixtures.

Zweck: Der Port des Analysators nach Rust muss *beweisbar* dasselbe Ergebnis
liefern wie diese Implementierung. Dafuer werden hier echte Probe-Saetze samt
Eingabeparametern und dem daraus berechneten Resultat weggeschrieben. Der
Rust-Test spielt sie ein und vergleicht feldweise.

Aktivierung ueber die Umgebungsvariable TMT_FIXTURE_DIR. Ohne sie passiert
nichts — im Normalbetrieb ist das Modul wirkungslos.
"""
import json
import logging
import os
import threading

logger = logging.getLogger(__name__)

_lock = threading.Lock()
_counter = 0


def enabled() -> bool:
    return bool(os.environ.get("TMT_FIXTURE_DIR"))


def record(probes, target_local_port, prediction_mode, prediction_range_extra_pct, analysis) -> None:
    """Schreibt einen Probe-Satz und sein Analyseergebnis als JSON-Datei."""
    directory = os.environ.get("TMT_FIXTURE_DIR")
    if not directory:
        return

    global _counter
    try:
        os.makedirs(directory, exist_ok=True)
        with _lock:
            _counter += 1
            index = _counter

        payload = {
            "input": {
                # (ip, nat_port, local_port, ts) -> ip bewusst weggelassen, es
                # geht nicht in die Analyse ein und ist personenbeziehbar.
                # Die Probes tragen seit der Mapping-Erkennung ein fuenftes
                # Feld (Zielport). Beide Laengen werden vertragen, sonst reisst
                # die Aufzeichnung ab — und zwar still, weil unten alles
                # abgefangen wird.
                "probes": [
                    {
                        "nat_port": eintrag[1],
                        "local_port": eintrag[2],
                        "ts": eintrag[3],
                        **({"ziel_port": eintrag[4]} if len(eintrag) > 4 else {}),
                    }
                    for eintrag in probes
                ],
                "target_local_port": target_local_port,
                "prediction_mode": prediction_mode,
                "prediction_range_extra_pct": prediction_range_extra_pct,
            },
            "expected": analysis.to_dict(),
        }

        path = os.path.join(directory, f"nat-{index:04d}.json")
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2, sort_keys=True)
        logger.info("Fixture written: %s (%d probes)", path, len(payload["input"]["probes"]))
    except Exception as exc:  # Aufzeichnung darf den Betrieb nie stoeren
        logger.warning("Could not write fixture: %s", exc)
