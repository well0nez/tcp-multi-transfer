"""NAT-Verhalten erkennen und den Portbereich der Gegenstelle schaetzen.

Die Analyse trennt drei Eigenschaften, die frueher in einer einzigen
Musterklasse vermengt waren:

* **Vergabe** (`allocation`) — wie die NAT den externen Port waehlt:
  portbewahrend, mit stabilem Versatz, fortlaufend (zeitgesteuert) oder
  zufaellig aus einem Band. Nur diese Eigenschaft rechtfertigt eine
  Punktvorhersage.
* **Mapping** (`mapping_behaviour`, RFC 4787) — haengt das Mapping vom Ziel ab?
  Messbar nur, wenn gegen mehrere Zielports geprobt wurde; sonst
  `unbestimmt`. Fuer die Vorhersage ist das entscheidend: ein zielabhaengiges
  Mapping laesst sich vom Relay auf den Peer *nicht* uebertragen, dann bleibt
  nur die Bandschaetzung.
* **Filterung** (`filtering_behaviour`, RFC 4787) — laesst die NAT ein SYN von
  einem Absenderport durch, an den nie gesendet wurde? Das entscheidet, ob die
  Gegenstelle ueberhaupt scannen muss.

Fuer jede Vergabeart gibt es einen eigenen Schaetzer statt eines
Allzweck-Delta-Modells.

## Bandschaetzung bei zufaelliger Vergabe

Beobachtet man `n` gleichverteilte Ziehungen aus einem Band der Breite `W`, so
ist die erwartete Spannweite nur `W·(n−1)/(n+1)`. Der Bereich `[min, max]`
unterschaetzt das Band also systematisch, und eine frische Ziehung faellt nur
mit Wahrscheinlichkeit `(n−1)/(n+1)` hinein — bei `n = 10` sind das **81,8 %**,
unabhaengig von der Bandbreite und unabhaengig davon, wie breit gescannt wird.

Nachgerechnet an 558 echten Proben derselben Carrier-NAT (56 Sitzungen):
beobachtete Spannweite im Mittel 198,3 bei einem tatsaechlichen Band von 251 —
erwartet waeren 205,4. Die Gleichverteilung haelt der Pruefung stand
(Chi-Quadrat 6,5 bei 9 Freiheitsgraden).

Deshalb wird das Band um `BAND_AUFSCHLAG · (max − min)` je Seite erweitert. Der
Wert 0,25 stammt aus einer Simulation der Trefferquote:

    Aufschlag   Trefferquote (n=10)   abgedecktes Band von 251
      0,00            81,8 %                205
      0,11            92,9 %                233
      0,25            97,5 %                245
      0,40            99,1 %                249

0,25 kauft 15,7 Prozentpunkte fuer 20 % mehr Kandidaten; darueber wird es teuer.
"""
import logging
import math
import statistics
from typing import List, Tuple

from .models import NATAnalysis

logger = logging.getLogger(__name__)

MIN_PORT = 1024
MAX_PORT = 65535

# Ab dieser Streubreite gilt die Portvergabe als unvorhersagbar ("random_like").
# Derselbe Schwellwert entscheidet, ob der Extrapolation noch zu trauen ist —
# beides muss zusammen bleiben, sonst widersprechen sich Klassifikation und
# Vorhersage.
RANDOM_LIKE_ERROR_RANGE = 100

# Aufschlag auf die beobachtete Spannweite, je Seite. Herleitung im Modulkopf.
BAND_AUFSCHLAG = 0.25

# Angestrebte Trefferquote eines einzelnen Punch-Versuchs. Darueber wird die
# noetige Abdeckung ausgerechnet (siehe `noetige_abdeckung`). 0,95 je Versuch
# heisst bei bis zu fuenf Wiederholungen praktisch sichere Sitzungen; hoeher
# anzusetzen kostet Kandidaten, ohne dass es sich noch bemerkbar macht.
ZIEL_TREFFERQUOTE = 0.95

# Zeitgesteuerte Vergabe: Vorlauf zwischen Probe und Punch. Wird aus den
# Zeitstempeln ueberschrieben, sobald sie vorliegen.
PREDICTION_DELAY_SEC = 2.0
RATE_DAMPING = 0.5
MAX_RATE_SHIFT = 32

# Ein Trend gilt erst als Trend, wenn er nicht mehr durch Zufall erklaerbar ist.
# Vorzeichentest auf den Differenzen, einseitig, 5 %.
TREND_ALPHA = 0.05
# ... und wenn die Gerade auch tatsaechlich etwas erklaert.
TREND_MIN_R2 = 0.5


def _binom_p_mindestens(k: int, n: int) -> float:
    """P(X >= k) fuer X ~ Binomial(n, 1/2). Fuer den Vorzeichentest."""
    if n <= 0:
        return 1.0
    return sum(math.comb(n, i) for i in range(k, n + 1)) / (2 ** n)


def _trend(zeiten: List[float], ports: List[int]) -> Tuple[bool, float, float]:
    """Steigt der Port mit der Zeit — und zwar nachweisbar?

    Rueckgabe: (signifikant, Rate in Ports je Sekunde, Bestimmtheitsmass).

    Zwei Huerden, weil jede fuer sich zu leicht zu nehmen ist:
    ein Vorzeichentest auf den aufeinanderfolgenden Differenzen (schliesst
    Zufall aus) und ein Bestimmtheitsmass (schliesst aus, dass ein schwacher
    Trend im Rauschen als Vergabemodell durchgeht).

    Der Vorgaenger nutzte `Anteil positiver Differenzen >= 0,6`. Bei neun
    Differenzen aus reinem Rauschen ist das mit 25 % Wahrscheinlichkeit erfuellt
    — an 56 echten Messreihen derselben driftfreien NAT hat die Regel denn auch
    in 10 Faellen angeschlagen und die Vorhersage um bis zu 32 Ports verschoben.
    Ein Rauschgenerator, kein Modell.
    """
    n = len(zeiten)
    if n < 4:
        return False, 0.0, 0.0
    spanne = zeiten[-1] - zeiten[0]
    if spanne <= 0:
        return False, 0.0, 0.0

    diffs = [ports[i] - ports[i - 1] for i in range(1, n)]
    positiv = sum(1 for d in diffs if d > 0)
    if _binom_p_mindestens(positiv, len(diffs)) > TREND_ALPHA:
        return False, 0.0, 0.0

    # Ausgleichsgerade Port ueber Zeit.
    mx = statistics.mean(zeiten)
    my = statistics.mean(ports)
    sxx = sum((x - mx) ** 2 for x in zeiten)
    if sxx <= 0:
        return False, 0.0, 0.0
    sxy = sum((x - mx) * (y - my) for x, y in zip(zeiten, ports))
    syy = sum((y - my) ** 2 for y in ports)
    steigung = sxy / sxx
    r2 = (sxy * sxy) / (sxx * syy) if syy > 0 else 0.0
    if r2 < TREND_MIN_R2 or steigung <= 0:
        return False, 0.0, r2
    return True, steigung, r2


# Die Paritaetsheuristik ist entfallen.
#
# Sie sollte den Scanaufwand halbieren, wenn eine NAT die Paritaet des lokalen
# Ports bewahrt. Zwei Gruende dagegen, beide beim Nachrechnen aufgefallen:
#
# 1. Der Nachweis trug nicht. Geprueft wurde `nat % 2 == lokal % 2` ueber die
#    Proben — sind alle geprobten lokalen Ports zufaellig gerade (der Client
#    bindet fortlaufende Ports!), ist das von "die NAT vergibt immer gerade"
#    nicht zu unterscheiden. Die Bedingung fiel also auf einen Zufall herein.
# 2. Der Schaden war gross. Die Kandidaten wurden an der Paritaet von
#    `predicted_port` ausgerichtet — und der stammt aus einem *Median*, der
#    ueber eine gerade Anzahl von Werten mittelt und dabei die Paritaet
#    wechseln kann. Nachgerechnet an 500 synthetischen Sitzungen: in **245**
#    lagen daraufhin *alle* Kandidaten auf der unmoeglichen Paritaet, der
#    Punch konnte gar nicht gelingen.
#
# Richtig gebaut braeuchte es die Paritaet des lokalen Ports *dieser
# Verbindung* (nicht des geprobten) und beide Paritaeten unter den Proben als
# Nachweis. Keine der vermessenen NATs bewahrt die Paritaet (558 Proben,
# Verteilung 50:50) — der Aufwand lohnt erst, wenn eine auftaucht, die es tut.


def _blockgroesse(nat_ports: List[int]) -> int:
    """Liegen alle Ports in einem ausgerichteten Zweierpotenz-Block?

    CGNAT-Implementierungen vergeben Teilnehmern haeufig einen festen Block
    (typisch 256 bis 2048 Ports). Ist er erkennbar, ist er die *richtige*
    Bandgrenze — besser als jede aus wenigen Proben geschaetzte.
    Rueckgabe 0, wenn kein Block passt.
    """
    n = len(nat_ports)
    if n < 8:
        return 0
    lo, hi = min(nat_ports), max(nat_ports)
    spanne = hi - lo
    for groesse in (256, 512, 1024, 2048, 4096):
        if spanne >= groesse:
            continue
        if lo // groesse != hi // groesse:
            continue
        # Ausrichtung allein genuegt nicht. Liegen die Beobachtungen zufaellig
        # in einem Band der Breite `spanne`, so faellt dieses Band mit
        # Wahrscheinlichkeit (groesse − spanne)/groesse ganz in *irgendeinen*
        # ausgerichteten Block dieser Groesse. Bei Spannweite 200 und einem
        # 256er-Block sind das 22 % — und genau in dieser Groessenordnung hat
        # ein schwaecheres Kriterium an den 56 echten Messreihen falsch
        # angeschlagen (9 Treffer, obwohl das wahre Band die Blockgrenzen
        # nachweislich ueberschreitet). Verlangt wird deshalb, dass die
        # Zufallserklaerung unter 5 % faellt.
        if (groesse - spanne) / groesse > 0.05:
            continue
        return groesse
    return 0


def _band_schaetzen(nat_ports: List[int]) -> Tuple[int, int, float]:
    """Band einer gleichverteilten Vergabe aus n Ziehungen.

    Rueckgabe: (untere Grenze, obere Grenze, erwartete Trefferquote ohne
    Aufschlag). Herleitung im Modulkopf.
    """
    n = len(nat_ports)
    lo, hi = min(nat_ports), max(nat_ports)
    spanne = hi - lo
    aufschlag = int(round(BAND_AUFSCHLAG * spanne))
    roh_quote = (n - 1) / (n + 1) if n >= 2 else 0.0
    return max(MIN_PORT, lo - aufschlag), min(MAX_PORT, hi + aufschlag), roh_quote


def _ensure_range_contains_prediction(analysis: NATAnalysis) -> None:
    """Invariante: der Scanbereich enthaelt immer den vorhergesagten Port.

    Ohne sie kann `build_candidate_ports` den wichtigsten Kandidaten ueberhaupt
    stillschweigend verwerfen — die Bereichspruefung in `add_port` wirft ihn
    kommentarlos weg. Ausserdem zentriert die Fensterung bei knapper
    Kandidatenobergrenze um den vorhergesagten Port; liegt der ausserhalb,
    rutscht das Fenster an den Rand und trifft nichts.
    """
    if analysis.scan_start <= 0 or analysis.scan_end <= 0:
        return
    if analysis.predicted_port < analysis.scan_start:
        analysis.scan_start = max(MIN_PORT, analysis.predicted_port)
    if analysis.predicted_port > analysis.scan_end:
        analysis.scan_end = min(MAX_PORT, analysis.predicted_port)


def klassifiziere_mapping(probes: List[Tuple]) -> str:
    """Wie stabil ist das Mapping? (RFC 4787)

    Drei Faelle, in dieser Reihenfolge zu pruefen:

    * **pro_verbindung** — schon zwei Verbindungen mit *identischem* Fuenftupel
      bekommen verschiedene externe Ports. Dann gibt es gar kein
      wiederverwendbares Mapping, und die Frage nach Endpunktabhaengigkeit
      stellt sich nicht mehr. Praktische Folge: der am Relay gemessene Port sagt
      ueber den Port zur Gegenstelle nichts, es bleibt nur die Bandschaetzung —
      und jeder zusaetzliche lokale Port ist eine eigene Ziehung.
    * **endpunktunabhaengig** — derselbe lokale Port bekommt gegen *verschiedene*
      Ziele denselben externen Port. Dann gilt die Messung am Relay auch fuer die
      Gegenstelle: ein einziger Kandidat genuegt, kein Scan.
    * **portabhaengig** — je Ziel ein eigener, aber in sich stabiler Port.

    `unbestimmt`, solange nur gegen ein Ziel geprobt wurde oder die Daten nicht
    reichen. Eine Aussage ohne zweites Ziel waere nicht gedeckt.
    """
    nach_paar = {}
    for eintrag in probes:
        if len(eintrag) < 5:
            return "unbestimmt"
        _ip, nat_port, local_port, _ts, ziel_port = eintrag[:5]
        nach_paar.setdefault((local_port, ziel_port), []).append(nat_port)

    # Vergibt die NAT beim selben Fuenftupel jedes Mal neu?
    wiederholt = [werte for werte in nach_paar.values() if len(werte) >= 2]
    if wiederholt and any(len(set(werte)) > 1 for werte in wiederholt):
        return "pro_verbindung"

    ziele = {ziel for _lokal, ziel in nach_paar}
    if len(ziele) < 2:
        return "unbestimmt"

    # Nur lokale Ports vergleichen, die gegen beide Ziele gemessen wurden.
    aussagen = set()
    for lokal in {l for l, _z in nach_paar}:
        werte = [set(nach_paar[(lokal, z)]) for z in ziele if (lokal, z) in nach_paar]
        if len(werte) < 2:
            continue
        aussagen.add("endpunktunabhaengig" if set.intersection(*werte) else "portabhaengig")

    if not aussagen:
        return "unbestimmt"
    if len(aussagen) == 1:
        return aussagen.pop()
    return "unbestimmt"


def _bereich_erweitern(analysis: NATAnalysis, prozent: float) -> None:
    """Manueller Aufschlag ueber `--prediction-range-extra-pct`."""
    if prozent <= 0.0:
        return
    if analysis.scan_start <= 0 or analysis.scan_end <= 0:
        return
    if analysis.scan_end < analysis.scan_start:
        return
    span = analysis.scan_end - analysis.scan_start
    if span <= 0:
        return
    extra_total = int(round(span * (prozent / 100.0)))
    if extra_total <= 0:
        return
    pad_low = extra_total // 2
    analysis.scan_start = max(MIN_PORT, analysis.scan_start - pad_low)
    analysis.scan_end = min(MAX_PORT, analysis.scan_end + (extra_total - pad_low))
    analysis.needs_scan = True
    logger.info("NAT Analysis: expanded scan range by %.2f%%", prozent)


def _als_band(analysis: NATAnalysis) -> None:
    """Zufaellige Vergabe: das Band ist die Aussage, nicht der Punkt.

    Die Punktvorhersage aus dem Delta hat hier keine Grundlage — sie wird
    durch den Median der beobachteten Ports ersetzt, der aus genau der
    Verteilung stammt, die getroffen werden soll. Der Bereich kommt aus der
    Ordnungsstatistik, nicht aus dem Fehlerband des Deltas.
    """
    analysis.allocation = "zufaellig_im_band"
    lo, hi, roh = _band_schaetzen(analysis.probed_ports)
    if analysis.block_size:
        # Ein erkannter Portblock darf den Bereich nur **beschneiden**, nie
        # erweitern: ausserhalb des Blocks kann die NAT nichts vergeben, und
        # ein Block ist stets breiter als die aus zehn Proben geschaetzte
        # Bandbreite.
        block = analysis.block_size
        basis = analysis.min_port // block * block
        lo = max(lo, basis)
        hi = min(hi, basis + block - 1)
        logger.info("NAT Analysis: port block %s (%s-%s) narrows the range to %s-%s",
                    block, basis, basis + block - 1, lo, hi)
    analysis.scan_start = lo
    analysis.scan_end = hi
    analysis.band_low = lo
    analysis.band_high = hi
    analysis.needs_scan = True
    analysis.hit_probability = roh

    median_port = int(round(statistics.median(analysis.probed_ports)))
    if not (analysis.scan_start <= analysis.predicted_port <= analysis.scan_end):
        logger.info(
            "NAT Analysis: prediction %s lies outside the estimated band "
            "%s-%s and is replaced by the median %s",
            analysis.predicted_port, analysis.scan_start, analysis.scan_end, median_port,
        )
        analysis.predicted_port = max(MIN_PORT, min(MAX_PORT, median_port))
        analysis.prediction_source = "median_beobachtet"
    else:
        analysis.prediction_source = "extrapoliert"


def _einordnen(analysis: NATAnalysis, streuung: int, namen: Tuple[str, str, str, str, str]) -> None:
    """Die Leiter von "gar keine Streuung" bis "unvorhersagbar".

    Sie stand zweimal wortgleich da — einmal fuer den Delta-, einmal fuer den
    externen Zweig; nur die Musternamen unterschieden sich.
    """
    konstant, klein, mittel, gross, zufall = namen
    if streuung == 0:
        analysis.pattern_type = konstant
        analysis.allocation = "versatzstabil"
        analysis.needs_scan = False
        analysis.error_range = 0
        analysis.scan_start = analysis.predicted_port
        analysis.scan_end = analysis.predicted_port
        analysis.hit_probability = 1.0
    elif analysis.error_range <= 5:
        analysis.pattern_type = klein
        analysis.allocation = "versatzstabil"
    elif analysis.error_range <= 30:
        analysis.pattern_type = mittel
        analysis.allocation = "versatzstabil"
    elif analysis.error_range <= RANDOM_LIKE_ERROR_RANGE:
        analysis.pattern_type = gross
        analysis.allocation = "versatzstabil"
    else:
        analysis.pattern_type = zufall
        _als_band(analysis)


def analyze_nat(
    probes: List[Tuple],
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
    for eintrag in probes:
        nat_port, local_port = eintrag[1], eintrag[2]
        analysis.probed_ports.append(nat_port)
        analysis.local_ports.append(local_port)

    analysis.mapping_behaviour = klassifiziere_mapping(probes)
    # Standardweg. Nur die Bandschaetzung darf ihn auf den Median umbiegen.
    analysis.prediction_source = "extrapoliert"

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
        analysis.allocation = "portbewahrend"
        analysis.needs_scan = False
        analysis.predicted_port = max(MIN_PORT, min(MAX_PORT, target_local_port))
        analysis.scan_start = analysis.predicted_port
        analysis.scan_end = analysis.predicted_port
        analysis.hit_probability = 1.0
        logger.info("NAT Analysis: port preserved (no scan needed)")
        return analysis

    analysis.block_size = _blockgroesse(analysis.probed_ports)

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

    # Zeitgesteuerte Vergabe: nur wenn ein Trend nachweisbar ist.
    sorted_probes = sorted(probes, key=lambda p: p[3])
    zeiten = [p[3] for p in sorted_probes]
    ports = [p[1] for p in sorted_probes]
    analysis.prediction_delay = PREDICTION_DELAY_SEC
    analysis.port_rate = 0.0
    analysis.predicted_shift = 0

    trend, rate, r2 = _trend(zeiten, ports)
    analysis.trend_r2 = r2
    if trend:
        analysis.port_rate = rate
        raw_shift = int(round(rate * analysis.prediction_delay * RATE_DAMPING))
        analysis.predicted_shift = max(0, min(MAX_RATE_SHIFT, raw_shift))
        if analysis.predicted_shift > 0:
            analysis.predicted_port = max(
                MIN_PORT,
                min(MAX_PORT, analysis.predicted_port + analysis.predicted_shift),
            )
        logger.info(
            "NAT Analysis: progressive allocation detected (%.1f ports/s, R2=%.2f), "
            "prediction shifted by %s",
            rate, r2, analysis.predicted_shift,
        )

    analysis.scan_start = max(MIN_PORT, analysis.predicted_port - analysis.error_range)
    analysis.scan_end = min(MAX_PORT, analysis.predicted_port + analysis.error_range)
    analysis.needs_scan = analysis.error_range > 0

    if use_external:
        _einordnen(analysis, analysis.port_range,
                   ("constant", "small_range", "medium_range", "large_range", "random_like"))
        _bereich_erweitern(analysis, prediction_range_extra_pct)
        _ensure_range_contains_prediction(analysis)
        logger.info(
            "NAT Analysis (external): predicted=%s range=%s-%s",
            analysis.predicted_port, analysis.scan_start, analysis.scan_end,
        )
        return analysis

    delta_spread = analysis.delta_max - analysis.delta_min
    _einordnen(analysis, delta_spread,
               ("constant_delta", "small_delta_range", "medium_delta_range",
                "large_delta_range", "random_like"))

    if analysis.allocation == "versatzstabil" and analysis.port_rate > 0.0:
        analysis.allocation = "fortlaufend"

    _bereich_erweitern(analysis, prediction_range_extra_pct)
    _ensure_range_contains_prediction(analysis)

    logger.info(
        "NAT Analysis: allocation=%s mapping=%s delta_range=%s predicted=%s range=%s-%s source=%s",
        analysis.allocation, analysis.mapping_behaviour, delta_spread,
        analysis.predicted_port, analysis.scan_start, analysis.scan_end,
        analysis.prediction_source,
    )

    return analysis


def noetige_abdeckung(
    analysis: NATAnalysis,
    punch_ports: int,
    obergrenze: int,
    ziel_quote: float = ZIEL_TREFFERQUOTE,
) -> int:
    """Wie viele Ports dieses Peers muss die Gegenstelle oeffnen?

    Aus dem Modell `P = 1 − (1 − k/N)^m` nach k aufgeloest:

        k = N · (1 − (1 − P)^(1/m))

    `m` ist die Zahl der lokalen Ports, die dieser Peer beim Punchen
    gleichzeitig haelt — jeder davon ist eine Ziehung aus seinem Portband.
    `N` ist die Breite dieses Bandes; aus `n` Ziehungen ist die erwartungstreue
    Schaetzung `Spannweite · (n+1)/(n−1)`, weil die beobachtete Spannweite das
    Band systematisch unterschaetzt (Herleitung im Modulkopf).

    Damit richtet sich der Aufwand nach dem, was gemessen wurde, statt nach
    einer festen Zahl. Beispiel aus der Praxis: Band 251 Ports, 16 lokale Ports,
    Ziel 95 % → 43 Kandidaten statt der frueheren 512. Bei einer NAT mit
    doppelt so breitem Band kaemen automatisch doppelt so viele heraus.

    Ohne Scanbedarf (portbewahrend, stabiler Versatz) ist die Antwort 1: dort
    ist der Port bekannt.
    """
    if not analysis or not analysis.needs_scan:
        return 1
    n = len(analysis.probed_ports)
    spanne = analysis.max_port - analysis.min_port
    if n < 2:
        return obergrenze
    if spanne <= 0:
        # Alle Proben zeigten denselben externen Port. Dann gibt es nichts zu
        # streuen — ein Kandidat ist die ganze Aussage. Frueher kam hier die
        # Obergrenze samt einer frei erfundenen Trefferquote heraus.
        analysis.hit_probability = 1.0
        return 1
    band = spanne * (n + 1) / (n - 1)
    m = max(1, int(punch_ports))
    p = min(0.999, max(0.5, ziel_quote))
    anteil = 1.0 - (1.0 - p) ** (1.0 / m)
    k = max(1, min(obergrenze, int(math.ceil(band * anteil))))

    # Was dabei tatsaechlich herauskommt — die Obergrenze kann den Wunsch
    # gekappt haben.
    analysis.hit_probability = 1.0 - (1.0 - min(1.0, k / band)) ** m
    logger.info(
        "NAT Analysis: band ~%.0f ports, peer holds %d port(s) -> %d candidates "
        "(ceiling %d), expected hit rate %.0f%% per attempt",
        band, m, k, obergrenze, analysis.hit_probability * 100,
    )
    return k


def build_candidate_ports(analysis: NATAnalysis, max_scan_ports: int) -> List[int]:
    """Build list of candidate ports to try based on NAT analysis."""
    if not analysis or not analysis.needs_scan:
        return []
    if analysis.scan_start <= 0 or analysis.scan_end <= 0:
        return []
    if analysis.scan_end < analysis.scan_start:
        return []

    if analysis.pattern_type == "random_like":
        # Bei zufaelliger Vergabe ist jeder Port im Band gleich wahrscheinlich.
        # Es gibt also keinen Grund, die Naehe der Vorhersage zu bevorzugen —
        # gleichmaessige Streuung ueber das Band maximiert die Trefferquote.
        ports = []
        seen = set()

        def add_port(port: int):
            if port < analysis.scan_start or port > analysis.scan_end:
                return
            if port in seen:
                return
            seen.add(port)
            ports.append(port)

        gesamt = analysis.scan_end - analysis.scan_start + 1
        if gesamt <= max_scan_ports:
            for p in range(analysis.scan_start, analysis.scan_end + 1):
                add_port(p)
            return ports

        # Mehr Band als Budget: gleichmaessig ausduennen — aber **ohne** den
        # Aufschlag.
        #
        # Reicht das Budget fuer eine dichte Abdeckung, zahlt sich der
        # Aufschlag aus: er faengt die Raender ab, die `[min, max]` aus zehn
        # Proben systematisch verfehlt (81,8 % gegen 96,2 % Trefferquote).
        # Reicht es *nicht*, kehrt sich das um. Bei gleichmaessiger Streuung
        # ueber einen Bereich der Breite R treffen von k Kandidaten nur
        # k · W/R in das tatsaechlich benutzte Band der Breite W — der Rest
        # ist verschenkt. Innerhalb von `[min, max]` liegt dagegen jeder
        # Kandidat garantiert im Band.
        #
        # Gemessen: 32 Kandidaten ueber das erweiterte Band von ~375 gestreut
        # ergaben 71 % Erfolg je Versuch statt der aus 32 wirksamen Kandidaten
        # erwarteten 88,5 % — es waren effektiv nur rund 21.
        eng_start = max(analysis.scan_start, analysis.min_port)
        eng_ende = min(analysis.scan_end, analysis.max_port)
        if eng_ende <= eng_start:
            eng_start, eng_ende = analysis.scan_start, analysis.scan_end

        # Proportional verteilen statt in festen Schritten: eine ganzzahlige
        # Schrittweite laesst am oberen Rand eine Luecke und trifft, wenn sie
        # gerade ist, nur jeden zweiten Port — beides verschenkt Abdeckung.
        add_port(analysis.predicted_port)
        rest = max_scan_ports - len(ports)
        spanne = eng_ende - eng_start
        if rest > 0 and spanne >= 0:
            for i in range(rest):
                versatz = 0 if rest == 1 else round(i * spanne / (rest - 1))
                add_port(eng_start + versatz)
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
