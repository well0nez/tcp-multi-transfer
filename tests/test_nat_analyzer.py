"""Tests fuer den NAT-Analysator.

Die Fixtures sind echte Probe-Saetze, aufgezeichnet mit TMT_FIXTURE_DIR gegen
zwei reale NATs (Carrier-CGNAT und portbewahrende Buero-NAT). Sie sind zugleich
die Vorlage fuer den geplanten Port des Servers nach Rust: die Rust-Fassung gilt
erst als fertig, wenn sie dieselben Eingaben auf dieselben Werte abbildet.

Die synthetischen Faelle decken die Typen ab, die in den Fixtures *nicht*
vorkommen — aufgezeichnet wurde nur eine einzige NAT-Art (zufaellige Vergabe im
Band). Ohne sie waeren alle anderen Zweige des Analysators ungetestet.
"""
import glob
import json
import os
import random
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from server.nat_analyzer import (analyze_nat, build_candidate_ports,
                                 noetige_abdeckung, _band_schaetzen)

FIXTURE_DIR = os.environ.get(
    "TMT_TEST_FIXTURES",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures"),
)


def _load():
    for path in sorted(glob.glob(os.path.join(FIXTURE_DIR, "*.json"))):
        with open(path, encoding="utf-8") as fh:
            yield os.path.basename(path), json.load(fh)


def _replay(data):
    i = data["input"]
    probes = [("x", p["nat_port"], p["local_port"], p["ts"]) for p in i["probes"]]
    return analyze_nat(
        probes, i["target_local_port"], i["prediction_mode"], i["prediction_range_extra_pct"]
    )


class TestVorhersageInvarianten(unittest.TestCase):
    """Eigenschaften, die fuer *jede* Eingabe gelten muessen."""

    def test_fixtures_vorhanden(self):
        self.assertTrue(list(_load()), f"keine Fixtures unter {FIXTURE_DIR}")

    def test_vorhersage_liegt_im_scanbereich(self):
        """Sonst verwirft build_candidate_ports den wichtigsten Kandidaten still.

        Ausserdem zentriert die Fensterung bei knapper Obergrenze um die
        Vorhersage — liegt sie ausserhalb, rutscht das Fenster an den Rand.
        """
        for name, data in _load():
            with self.subTest(name):
                a = _replay(data)
                if not a.needs_scan:
                    continue
                self.assertLessEqual(a.scan_start, a.predicted_port, name)
                self.assertLessEqual(a.predicted_port, a.scan_end, name)

    def test_vorhersage_liegt_im_beobachteten_band(self):
        """Kern der Korrektur: die Vorhersage darf den eigenen Messwerten nicht
        widersprechen. Ueber welchen Weg sie zustande kam, sagt prediction_source
        — beide Wege muessen im Band landen."""
        for name, data in _load():
            with self.subTest(name):
                a = _replay(data)
                if a.pattern_type in ("port_preserved", "insufficient_data"):
                    continue
                self.assertIn(a.prediction_source, ("extrapoliert", "median_beobachtet"), name)
                self.assertLessEqual(a.min_port, a.predicted_port, name)
                self.assertLessEqual(a.predicted_port, a.max_port, name)

    def test_kandidaten_liegen_im_scanbereich(self):
        for name, data in _load():
            with self.subTest(name):
                a = _replay(data)
                for cap in (16, 64, 512):
                    for port in build_candidate_ports(a, cap):
                        self.assertGreaterEqual(port, a.scan_start, name)
                        self.assertLessEqual(port, a.scan_end, name)

    def test_obergrenze_wird_eingehalten(self):
        for name, data in _load():
            with self.subTest(name):
                a = _replay(data)
                for cap in (16, 64, 512):
                    self.assertLessEqual(len(build_candidate_ports(a, cap)), cap, name)

    def test_vorhersage_ist_der_erste_kandidat(self):
        """Bei knappem Budget muss der wahrscheinlichste Port zuerst kommen."""
        for name, data in _load():
            with self.subTest(name):
                a = _replay(data)
                ports = build_candidate_ports(a, 64)
                if a.needs_scan and ports:
                    self.assertIn(a.predicted_port, ports, name)

    def test_geschaetztes_band_enthaelt_die_beobachtungen(self):
        """Der Aufschlag darf das Band nur erweitern, nie beschneiden."""
        for name, data in _load():
            with self.subTest(name):
                a = _replay(data)
                if a.pattern_type != "random_like":
                    continue
                self.assertLessEqual(a.scan_start, a.min_port, name)
                self.assertGreaterEqual(a.scan_end, a.max_port, name)


class TestBandschaetzung(unittest.TestCase):
    """Die Ordnungsstatistik, an echten Daten geprueft."""

    def test_kreuzvalidierung_an_echten_proben(self):
        """Weglassen einer Probe, Band aus dem Rest, Treffer pruefen.

        Das ist die einzige Pruefung, die ohne Modellannahme auskommt: die
        weggelassene Probe *ist* eine frische Ziehung derselben NAT. Ohne
        Aufschlag liegt die Trefferquote bei den theoretischen (n-2)/n — mit
        Aufschlag muss sie deutlich darueber liegen.
        """
        treffer_roh = gesamt = treffer_erweitert = 0
        for _name, data in _load():
            nat = [p["nat_port"] for p in data["input"]["probes"]]
            if len(nat) < 4:
                continue
            for i in range(len(nat)):
                rest = nat[:i] + nat[i + 1:]
                lo, hi, _ = _band_schaetzen(rest)
                gesamt += 1
                if min(rest) <= nat[i] <= max(rest):
                    treffer_roh += 1
                if lo <= nat[i] <= hi:
                    treffer_erweitert += 1

        quote_roh = treffer_roh / gesamt
        quote_erw = treffer_erweitert / gesamt
        self.assertGreater(
            quote_erw, quote_roh + 0.08,
            f"Aufschlag bringt zu wenig: roh {quote_roh:.3f}, erweitert {quote_erw:.3f}",
        )
        self.assertGreater(
            quote_erw, 0.90,
            f"Trefferquote mit Aufschlag zu niedrig: {quote_erw:.3f}",
        )

    def test_knappes_budget_bleibt_im_beobachteten_band(self):
        """Reicht das Budget nicht fuer eine dichte Abdeckung, ist jeder
        Kandidat ausserhalb des beobachteten Bandes verschenkt — dort ist nicht
        einmal belegt, dass die NAT ueberhaupt vergibt."""
        rng = random.Random(19)
        probes = [("x", 5000 + rng.randrange(0, 250), 40000, 1000.0 + rng.random())
                  for _ in range(10)]
        a = analyze_nat(probes, 40000, "delta", 0.0)
        self.assertEqual(a.pattern_type, "random_like")
        self.assertGreater(a.scan_end - a.scan_start, a.max_port - a.min_port,
                           "Aufschlag nicht wirksam")

        eng = build_candidate_ports(a, 32)
        self.assertLessEqual(len(eng), 32)
        aussen = [p for p in eng if not (a.min_port <= p <= a.max_port)]
        self.assertEqual(aussen, [], f"Kandidaten ausserhalb des Bandes: {aussen}")

        # Reicht das Budget dagegen fuer alles, wird der Aufschlag genutzt.
        weit = build_candidate_ports(a, 512)
        self.assertLessEqual(min(weit), a.min_port)
        self.assertGreaterEqual(max(weit), a.max_port)

    def test_band_waechst_symmetrisch(self):
        lo, hi, quote = _band_schaetzen([5100, 5200])
        self.assertEqual((lo, hi), (5100 - 25, 5200 + 25))
        self.assertAlmostEqual(quote, 1 / 3)


class TestAbdeckung(unittest.TestCase):
    """Wie viele Kandidaten die Gegenstelle oeffnen muss."""

    def _band(self, breite=250, n=10, saat=31):
        rng = random.Random(saat)
        probes = [("x", 5000 + rng.randrange(0, breite), 40000, 1000.0 + rng.random())
                  for _ in range(n)]
        return analyze_nat(probes, 40000, "delta", 0.0)

    def test_mehr_ports_weniger_kandidaten(self):
        """Das Produkt zaehlt: wer mehr lokale Ports haelt, braucht weniger
        Abdeckung."""
        a = self._band()
        k1 = noetige_abdeckung(a, 1, 512)
        k8 = noetige_abdeckung(a, 8, 512)
        k16 = noetige_abdeckung(a, 16, 512)
        self.assertGreater(k1, k8)
        self.assertGreater(k8, k16)
        # Bei einem Band von ~250 und 16 Ports liegt der Bedarf bei rund 43.
        self.assertTrue(30 <= k16 <= 60, k16)

    def test_breiteres_band_mehr_kandidaten(self):
        eng = noetige_abdeckung(self._band(breite=250), 16, 512)
        weit = noetige_abdeckung(self._band(breite=1000), 16, 512)
        self.assertGreater(weit, eng * 2)

    def test_obergrenze_wird_geachtet(self):
        a = self._band(breite=4000)
        self.assertLessEqual(noetige_abdeckung(a, 1, 64), 64)

    def test_ohne_scanbedarf_ein_kandidat(self):
        probes = [("x", 50000 + i, 50000 + i, 1000.0 + i) for i in range(6)]
        a = analyze_nat(probes, 50003, "delta", 0.0)
        self.assertEqual(noetige_abdeckung(a, 16, 512), 1)


class TestSynthetischeNatTypen(unittest.TestCase):
    """Die gaengigen NAT-Verhalten, unabhaengig von aufgezeichneten Daten."""

    def test_portbewahrend(self):
        probes = [("x", 50000 + i, 50000 + i, 1000.0 + i) for i in range(6)]
        a = analyze_nat(probes, 50003, "delta", 0.0)
        self.assertEqual(a.pattern_type, "port_preserved")
        self.assertEqual(a.allocation, "portbewahrend")
        self.assertFalse(a.needs_scan)
        self.assertEqual(a.predicted_port, 50003)

    def test_konstanter_versatz(self):
        """Alle Proben mit demselben Zeitstempel, damit das Ratenmodell keinen
        Vorhalt aufschlaegt und der reine Versatz geprueft wird."""
        probes = [("x", 60000 + i, 50000 + i, 1000.0) for i in range(6)]
        a = analyze_nat(probes, 50010, "delta", 0.0)
        self.assertEqual(a.pattern_type, "constant_delta")
        self.assertEqual(a.allocation, "versatzstabil")
        self.assertEqual(a.predicted_port, 60010)
        self.assertEqual(a.prediction_source, "extrapoliert",
                         "stabiler Versatz darf nicht durch den Median ersetzt werden")

    def test_sequenzieller_allokator_bleibt_im_band(self):
        probes = [("x", 40000 + i * 7, 50000 + i, 1000.0 + i * 0.5) for i in range(10)]
        a = analyze_nat(probes, 50005, "delta", 0.0)
        self.assertTrue(a.needs_scan)
        self.assertLessEqual(a.scan_start, a.predicted_port)
        self.assertLessEqual(a.predicted_port, a.scan_end)

    def test_negative_extrapolation_wird_nicht_geklemmt_uebernommen(self):
        """Der Fall, der real auftrat: Probe-Ports weit ueber den NAT-Ports,
        Summe negativ, frueher auf MIN_PORT geklemmt und als Fenstermitte benutzt."""
        probes = [("x", 5100 + i * 20, 48000 + i, 1000.0 + i * 0.3) for i in range(10)]
        a = analyze_nat(probes, 41000, "delta", 0.0)
        self.assertNotEqual(a.predicted_port, 1024, "Klemmwert als Vorhersage uebernommen")
        self.assertEqual(a.prediction_source, "median_beobachtet")
        self.assertLessEqual(a.min_port, a.predicted_port)
        self.assertLessEqual(a.predicted_port, a.max_port)

    def test_zu_wenig_daten(self):
        a = analyze_nat([("x", 5000, 4000, 1.0)], 4000, "delta", 0.0)
        self.assertEqual(a.pattern_type, "insufficient_data")

    def test_kandidaten_streuen_ueber_das_band(self):
        """Bei zufaelliger Vergabe ist jeder Port gleich wahrscheinlich — die
        Kandidaten muessen das Band abdecken statt sich zu ballen.

        (Die fruehere Paritaetsheuristik ist entfallen; sie richtete die Liste
        an der Paritaet von `predicted_port` aus, der aus einem Median stammt
        und die Paritaet wechseln kann. An 500 synthetischen Sitzungen lagen
        daraufhin in 245 Faellen *alle* Kandidaten auf der unmoeglichen
        Paritaet.)
        """
        rng = random.Random(7)
        probes = [("x", 5000 + rng.randrange(0, 250), 40000 + i, 1000.0 + rng.random())
                  for i in range(12)]
        a = analyze_nat(probes, 40000, "delta", 0.0)
        self.assertEqual(a.pattern_type, "random_like")

        k = build_candidate_ports(a, 32)
        self.assertTrue(k)
        gerade = sum(1 for p in k if p % 2 == 0)
        self.assertTrue(0 < gerade < len(k),
                        f"Kandidaten einseitig: {gerade} von {len(k)} gerade")
        # ueber das beobachtete Band verteilt, nicht geballt
        self.assertLess(min(k), a.min_port + (a.max_port - a.min_port) // 3)
        self.assertGreater(max(k), a.max_port - (a.max_port - a.min_port) // 3)

    def test_cgnat_portblock_begrenzt_den_bereich(self):
        """Ein belegter Block schneidet den Aufschlag ab — mehr nicht.

        Ausserhalb des Blocks kann die NAT nichts vergeben, dort zu scannen ist
        verschenktes Budget. Umgekehrt darf der Block den Bereich nie
        *erweitern*: er ist immer breiter als das aus zehn Proben geschaetzte
        Band.
        """
        rng = random.Random(3)
        basis = 20 * 512          # 10240
        # Der Block muss ausgefuellt sein, sonst ist er nicht belegt.
        werte = [3, 508] + [rng.randrange(0, 512) for _ in range(10)]
        probes = [("x", basis + v, 40000 + i, 1000.0 + rng.random())
                  for i, v in enumerate(werte)]
        a = analyze_nat(probes, 40000, "delta", 0.0)
        self.assertEqual(a.pattern_type, "random_like")
        self.assertEqual(a.block_size, 512)
        self.assertEqual(a.scan_start, basis)
        self.assertEqual(a.scan_end, basis + 511)

    def test_portblock_wird_nicht_aus_ausrichtungszufall_gefolgert(self):
        """Zehn Proben in einem 120 Ports schmalen Band liegen haeufig zufaellig
        in einem ausgerichteten 256er-Block. Das ist kein Beleg."""
        rng = random.Random(23)
        basis = 20 * 256 + 60
        probes = [("x", basis + rng.randrange(0, 120), 40000 + i, 1000.0 + rng.random())
                  for i in range(10)]
        a = analyze_nat(probes, 40000, "delta", 0.0)
        self.assertEqual(a.block_size, 0)

    def test_ratenmodell_schweigt_bei_rauschen(self):
        """Der wichtigste Test dieser Datei.

        Ohne Trend darf kein Vorhalt entstehen. Die alte Regel (Anteil positiver
        Differenzen >= 0,6) hat bei reinem Rauschen in einem Viertel der Faelle
        angeschlagen.
        """
        ausloeser = 0
        for saat in range(200):
            rng = random.Random(saat)
            probes = [("x", 5000 + rng.randrange(0, 250), 40000, 1000.0 + i * 0.5)
                      for i in range(10)]
            a = analyze_nat(probes, 40000, "delta", 0.0)
            if a.predicted_shift:
                ausloeser += 1
        self.assertLessEqual(ausloeser, 6,
                             f"Ratenmodell springt bei Rauschen an ({ausloeser}/200)")

    def test_ratenmodell_erkennt_echten_trend(self):
        """Ein fortlaufender Allokator: 20 Ports je Sekunde, wenig Rauschen."""
        rng = random.Random(5)
        probes = [("x", 30000 + int(i * 10) + rng.randrange(-1, 2), 40000, 1000.0 + i * 0.5)
                  for i in range(10)]
        a = analyze_nat(probes, 40000, "delta", 0.0)
        self.assertGreater(a.port_rate, 0.0, "echter Trend nicht erkannt")
        self.assertGreater(a.trend_r2, 0.9)
        self.assertGreater(a.predicted_shift, 0)

    def test_ratenmodell_bei_echten_fixtures_stumm(self):
        """Die 558 aufgezeichneten Proben zeigen keine Zeitdrift (Korrelation
        Port~Zeit im Median +0,07). Ein Vorhalt waere dort reine Erfindung."""
        mit_vorhalt = [n for n, d in _load() if _replay(d).predicted_shift]
        self.assertEqual(mit_vorhalt, [], f"Vorhalt auf driftfreien Daten: {mit_vorhalt}")


class TestMappingVerhalten(unittest.TestCase):
    """Mapping und Vergabe sind zwei verschiedene Eigenschaften (RFC 4787)."""

    def test_ohne_zweites_ziel_unbestimmt(self):
        probes = [("x", 5000 + i, 40000, 1000.0 + i) for i in range(6)]
        a = analyze_nat(probes, 40000, "delta", 0.0)
        self.assertEqual(a.mapping_behaviour, "unbestimmt",
                         "Aussage ohne zweites Ziel ist nicht gedeckt")

    def test_endpunktunabhaengiges_mapping(self):
        """Gleicher lokaler Port, zwei Ziele, gleicher externer Port."""
        probes = [("x", 5555, 40000, 1000.0, 9998), ("x", 5555, 40000, 1001.0, 9997)]
        a = analyze_nat(probes, 40000, "delta", 0.0)
        self.assertEqual(a.mapping_behaviour, "endpunktunabhaengig")

    def test_portabhaengiges_mapping(self):
        probes = [("x", 5555, 40000, 1000.0, 9998), ("x", 6666, 40000, 1001.0, 9997)]
        a = analyze_nat(probes, 40000, "delta", 0.0)
        self.assertEqual(a.mapping_behaviour, "portabhaengig")

    def test_vergabe_pro_verbindung_schlaegt_alles(self):
        """Zwei Verbindungen mit gleichem Fuenftupel, zwei verschiedene Ports:
        dann gibt es kein Mapping, das man wiederverwenden koennte — und eine
        zufaellige Portkollision zwischen den Zielen darf nicht als
        Endpunktunabhaengigkeit durchgehen."""
        probes = [
            ("x", 5100, 40000, 1000.0, 9998), ("x", 5230, 40000, 1000.5, 9998),
            ("x", 5230, 40000, 1001.0, 9997), ("x", 5301, 40000, 1001.5, 9997),
        ]
        a = analyze_nat(probes, 40000, "delta", 0.0)
        self.assertEqual(a.mapping_behaviour, "pro_verbindung")


if __name__ == "__main__":
    unittest.main(verbosity=2)
