"""Tests fuer die Sitzungskoordination im Relay.

Bis hierher gab es dafuer keinen einzigen Test — geprueft war nur der
Analysator. Die Koordination ist aber der Teil, in dem die Fehler stecken, die
eine Sitzung haengen lassen: Doppelregistrierung, Abstimmung ueber `ready` und
`go`, Ergebnismeldung, Wiederholung, Abraeumen beim Verbindungsabbruch.

Gefahren wird gegen einen echten Server auf 127.0.0.1 mit unechten Peers, die
das JSON-Zeilenprotokoll direkt sprechen. Kein Punching, kein NAT — geprueft
wird ausschliesslich das Zusammenspiel der Nachrichten.
"""
import asyncio
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from server.relay import TCPRelayServerICE


class UnechterPeer:
    """Ein Peer, der nur das Protokoll spricht."""

    def __init__(self, reader, writer):
        self.reader = reader
        self.writer = writer

    @classmethod
    async def verbinde(cls, port):
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        return cls(reader, writer)

    async def sende(self, **msg):
        self.writer.write((json.dumps(msg) + "\n").encode())
        await self.writer.drain()

    async def empfange(self, typ=None, timeout=5.0):
        """Liest, bis eine Nachricht des gewuenschten Typs kommt."""
        while True:
            zeile = await asyncio.wait_for(self.reader.readline(), timeout)
            if not zeile:
                raise AssertionError("Verbindung vom Server geschlossen")
            msg = json.loads(zeile.decode())
            if typ is None or msg.get("type") == typ:
                return msg

    async def registriere(self, session_id, rolle, local_port, **extra):
        # `extra_ports` gehoert dazu: der Koordinator vermittelt Verbindung n
        # erst, wenn beide Seiten einen Port dafuer gemeldet haben. Der echte
        # Client schickt sie immer mit.
        extra.setdefault("extra_ports", [local_port])
        await self.sende(type="register", session_id=session_id, role=rolle,
                         local_port=local_port, **extra)
        return await self.empfange()

    async def schliesse(self):
        try:
            self.writer.close()
            await self.writer.wait_closed()
        except Exception:
            pass


class RelayFall(unittest.IsolatedAsyncioTestCase):
    """Gemeinsames Auf- und Abbauen eines Servers je Test."""

    PORT = 19771

    async def asyncSetUp(self):
        self.server = TCPRelayServerICE(
            host="127.0.0.1", port=self.PORT,
            probe_port=self.PORT - 1, probe_port2=self.PORT - 2,
            max_scan_ports=64,
        )
        self.aufgabe = asyncio.create_task(self.server.start())
        # Kurz warten, bis die Lauscher stehen.
        for _ in range(50):
            try:
                probe = await asyncio.open_connection("127.0.0.1", self.PORT)
                probe[1].close()
                break
            except OSError:
                await asyncio.sleep(0.02)
        self.peers = []

    async def asyncTearDown(self):
        for p in self.peers:
            await p.schliesse()
        self.aufgabe.cancel()
        try:
            await self.aufgabe
        except (asyncio.CancelledError, Exception):
            pass

    async def peer(self):
        p = await UnechterPeer.verbinde(self.PORT)
        self.peers.append(p)
        return p


class TestRegistrierung(RelayFall):

    async def test_beide_rollen_werden_angenommen(self):
        a = await self.peer()
        antwort = await a.registriere("s1", "receiver", 40000)
        self.assertEqual(antwort["type"], "registered")
        self.assertIn("your_public_addr", antwort)

        b = await self.peer()
        antwort = await b.registriere("s1", "sender", 40001)
        self.assertEqual(antwort["type"], "registered")

    async def test_doppelte_rolle_wird_abgelehnt(self):
        a = await self.peer()
        await a.registriere("s2", "receiver", 40000)
        b = await self.peer()
        antwort = await b.registriere("s2", "receiver", 40002)
        self.assertEqual(antwort["type"], "error")
        self.assertIn("already taken", antwort["message"])

    async def test_abgelehnter_doppelstart_laesst_die_sitzung_stehen(self):
        """Der Kern eines behobenen Fehlers: frueher raeumte der abgewiesene
        Peer beim Abmelden die *fremde* Sitzung ab — der rechtmaessige Peer
        blieb verbunden, aber verwaist, und die Koordination startete nie."""
        a = await self.peer()
        await a.registriere("s3", "receiver", 40000)

        stoerer = await self.peer()
        antwort = await stoerer.registriere("s3", "receiver", 40009)
        self.assertEqual(antwort["type"], "error")
        await stoerer.schliesse()
        await asyncio.sleep(0.2)   # Abmeldung durchlaufen lassen

        # Die Sitzung muss weiterhin stehen und die Koordination anlaufen.
        b = await self.peer()
        await b.registriere("s3", "sender", 40001)
        await a.sende(type="probes_complete")
        await b.sende(type="probes_complete")

        info_a = await a.empfange("peer_info", timeout=8.0)
        info_b = await b.empfange("peer_info", timeout=8.0)
        self.assertEqual(info_a["connection_num"], 0)
        self.assertEqual(info_b["connection_num"], 0)

    async def test_ungueltige_rolle(self):
        a = await self.peer()
        antwort = await a.registriere("s4", "beobachter", 40000)
        self.assertEqual(antwort["type"], "error")


class TestKoordination(RelayFall):

    async def _paar(self, session_id, verbindungen=1):
        empf = await self.peer()
        await empf.registriere(session_id, "receiver", 40000)
        send = await self.peer()
        await send.registriere(session_id, "sender", 40001,
                               tcp_connections=verbindungen)
        await empf.sende(type="probes_complete")
        await send.sende(type="probes_complete")
        return send, empf

    async def test_peer_info_und_go_fuer_eine_verbindung(self):
        send, empf = await self._paar("k1")

        info_s = await send.empfange("peer_info", timeout=8.0)
        info_e = await empf.empfange("peer_info", timeout=8.0)
        # Jede Seite bekommt die Adresse der *anderen*.
        self.assertEqual(info_s["your_role"], "sender")
        self.assertEqual(info_e["your_role"], "receiver")
        self.assertIn("peer_addresses", info_s)
        # Die eigene Analyse gehoert dazu — nur mit ihr kann der Client
        # entscheiden, ob zusaetzliche lokale Ports Ziehungen sind.
        self.assertIn("your_nat_analysis", info_s)

        await send.sende(type="ready", connection_num=0)
        await empf.sende(type="ready", connection_num=0)

        go_s = await send.empfange("go", timeout=8.0)
        go_e = await empf.empfange("go", timeout=8.0)
        # Beide Seiten bekommen denselben Startzeitpunkt.
        self.assertEqual(go_s["start_at"], go_e["start_at"])
        self.assertEqual(go_s["connection_num"], 0)

    async def test_go_erst_wenn_beide_bereit_sind(self):
        send, empf = await self._paar("k2")
        await send.empfange("peer_info", timeout=8.0)
        await empf.empfange("peer_info", timeout=8.0)

        await send.sende(type="ready", connection_num=0)
        with self.assertRaises(asyncio.TimeoutError):
            await send.empfange("go", timeout=1.0)

        await empf.sende(type="ready", connection_num=0)
        go = await send.empfange("go", timeout=8.0)
        self.assertEqual(go["connection_num"], 0)

    async def test_zweite_verbindung_erst_nach_dem_ergebnis_der_ersten(self):
        """Sequenzielle Abstimmung: Verbindung n+1 wird erst vermittelt, wenn
        beide Seiten fuer n ein Ergebnis gemeldet haben."""
        send, empf = await self._paar("k3", verbindungen=2)
        await send.sende(type="add_ports", session_id="k3", ports=[40002])
        await empf.sende(type="add_ports", session_id="k3", ports=[40003])

        await send.empfange("peer_info", timeout=8.0)
        await empf.empfange("peer_info", timeout=8.0)
        await send.sende(type="ready", connection_num=0)
        await empf.sende(type="ready", connection_num=0)
        await send.empfange("go", timeout=8.0)
        await empf.empfange("go", timeout=8.0)

        # Nur eine Seite meldet — es darf nichts weitergehen.
        await send.sende(type="conn_established", connection_num=0)
        with self.assertRaises(asyncio.TimeoutError):
            await send.empfange("peer_info", timeout=1.5)

        await empf.sende(type="conn_established", connection_num=0)
        info = await send.empfange("peer_info", timeout=8.0)
        self.assertEqual(info["connection_num"], 1)

    async def test_abgebrochene_verbindung_blockiert_die_naechste_nicht(self):
        send, empf = await self._paar("k4", verbindungen=2)
        await send.sende(type="add_ports", session_id="k4", ports=[40004])
        await empf.sende(type="add_ports", session_id="k4", ports=[40005])

        await send.empfange("peer_info", timeout=8.0)
        await empf.empfange("peer_info", timeout=8.0)
        await send.sende(type="ready", connection_num=0)
        await empf.sende(type="ready", connection_num=0)
        await send.empfange("go", timeout=8.0)
        await empf.empfange("go", timeout=8.0)

        await send.sende(type="conn_abandoned", connection_num=0, reason="test")
        await empf.sende(type="conn_abandoned", connection_num=0, reason="test")
        info = await send.empfange("peer_info", timeout=8.0)
        self.assertEqual(info["connection_num"], 1)

    async def test_wiederholung_erst_wenn_beide_sie_wollen(self):
        send, empf = await self._paar("k5")
        await send.empfange("peer_info", timeout=8.0)
        await empf.empfange("peer_info", timeout=8.0)
        await send.sende(type="ready", connection_num=0)
        await empf.sende(type="ready", connection_num=0)
        await send.empfange("go", timeout=8.0)
        await empf.empfange("go", timeout=8.0)

        await send.sende(type="retry_request", connection_num=0)
        with self.assertRaises(asyncio.TimeoutError):
            await send.empfange("retry_granted", timeout=1.0)

        await empf.sende(type="retry_request", connection_num=0)
        gewaehrt_s = await send.empfange("retry_granted", timeout=8.0)
        gewaehrt_e = await empf.empfange("retry_granted", timeout=8.0)
        self.assertEqual(gewaehrt_s["connection_num"], 0)
        self.assertEqual(gewaehrt_e["connection_num"], 0)

    async def test_abmelden_beendet_die_gegenseite(self):
        """Geht ein Peer, soll der andere nicht endlos warten."""
        send, empf = await self._paar("k6")
        await send.empfange("peer_info", timeout=8.0)
        await empf.empfange("peer_info", timeout=8.0)

        await send.schliesse()
        with self.assertRaises(AssertionError):
            # Der Server schliesst die Gegenseite; `empfange` meldet das.
            for _ in range(20):
                await empf.empfange(timeout=2.0)

    async def test_keepalive(self):
        a = await self.peer()
        await a.registriere("k7", "receiver", 40000)
        await a.sende(type="keepalive")
        antwort = await a.empfange("keepalive_ack", timeout=5.0)
        self.assertEqual(antwort["type"], "keepalive_ack")


if __name__ == "__main__":
    unittest.main(verbosity=2)
