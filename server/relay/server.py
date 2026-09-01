"""
TCP Hole Punch Relay Server - Main Server Class
"""
import asyncio
import json
import logging
import time
from typing import Dict, List, Optional

from ..models import Peer, NATAnalysis, SessionState
from ..session_manager import SessionManager
from .utils import send_message, send_error
from .handlers import wait_for_peer_messages

logger = logging.getLogger(__name__)

MIN_PORT = 1024
MAX_PORT = 65535


async def pruefe_filter(ip: str, nat_port: int) -> str:
    """Laesst die NAT ein SYN von einem Absenderport durch, an den nie gesendet wurde?

    Der Client haelt gerade eine Probe-Verbindung von (ip, nat_port) zu uns
    offen — das Mapping lebt also nachweislich. Wir verbinden nun von einem
    Ephemeralport dieses Servers zurueck auf genau dieses (ip, nat_port). An
    diesen Absenderport hat der Client nie gesendet:

      * **abgelehnt** (RST) — die NAT hat das SYN weitergereicht, der Kernel des
        Clients hat mangels passendem Socket geantwortet. Die Filterung haengt
        also nur an der Adresse. Praktische Folge: die Gegenstelle muss unsere
        Ports gar nicht abscannen, ein beliebiges SYN kommt durch, sobald sie
        einmal an unsere Adresse gesendet hat.
      * **Zeitablauf** — die NAT hat verworfen. Filterung adress- *und*
        portabhaengig; nur der abgestimmte Punch hilft.

    Ein einzelnes SYN an dieselbe Adresse, von der die Probe gerade kam.
    """
    try:
        _reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, nat_port), timeout=2.0
        )
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        # Verbindung kam sogar zustande: durchgelassen.
        return "adressabhaengig"
    except ConnectionRefusedError:
        return "adressabhaengig"
    except asyncio.TimeoutError:
        return "adress_und_portabhaengig"
    except OSError as exc:
        logger.debug(f"Filter test against {ip}:{nat_port} inconclusive: {exc}")
        return "unbestimmt"


class TCPRelayServerICE:
    """TCP Hole Punch Relay Server with NAT Probing"""
    
    def __init__(
        self,
        host: str = '0.0.0.0',
        port: int = 9999,
        probe_port: int = 9998,
        max_scan_ports: int = 64,
        probe_port2: int = None,
    ):
        self.host = host
        self.port = port
        self.probe_port = probe_port
        # Zweiter Probe-Port auf derselben Adresse. Ohne ihn laesst sich nicht
        # entscheiden, ob das Mapping vom Ziel abhaengt (RFC 4787) — und genau
        # davon haengt ab, ob der am Relay gemessene Port fuer die Gegenstelle
        # ueberhaupt gilt.
        self.probe_port2 = probe_port2 if probe_port2 else probe_port - 1
        self.max_scan_ports = max(1, max_scan_ports)
        self.session_manager = SessionManager()
    
    async def start(self):
        """Start both main server and probe server"""
        # Main server
        main_server = await asyncio.start_server(
            self.handle_client,
            self.host,
            self.port
        )
        
        # Probe server (for NAT analysis)
        probe_server = await asyncio.start_server(
            self.handle_probe,
            self.host,
            self.probe_port
        )
        probe_server2 = await asyncio.start_server(
            self.handle_probe,
            self.host,
            self.probe_port2
        )
        
        logger.info(f"TCP Relay Server v3.0 (ICE-Lite) listening on {self.host}:{self.port}")
        logger.info(f"NAT Probe Server listening on {self.host}:{self.probe_port} "
                    f"und {self.host}:{self.probe_port2}")
        logger.info("Features: NAT Probing, Pattern Detection, Port Prediction")
        
        await asyncio.gather(
            main_server.serve_forever(),
            probe_server.serve_forever(),
            probe_server2.serve_forever()
        )
    
    async def handle_probe(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """Handle a probe connection (for NAT analysis)"""
        addr = writer.get_extra_info('peername')
        
        try:
            # Quick read of probe info
            data = await asyncio.wait_for(reader.readline(), timeout=5.0)
            if not data:
                return
            
            msg = json.loads(data.decode())
            if msg.get('type') != 'probe':
                return
            
            session_id = msg.get('session_id')
            local_port = msg.get('local_port', 0)
            probe_num = msg.get('probe_num', 0)
            halten = bool(msg.get('hold'))
            
            if not session_id:
                return
            
            # Record this probe. Der Zielport gehoert dazu: nur mit ihm laesst
            # sich spaeter sagen, ob das Mapping vom Ziel abhing.
            ip, nat_port = addr
            ts = time.time()
            ziel_port = writer.get_extra_info('sockname')[1]
            logger.debug(f"Probe #{probe_num} from {session_id}: local={local_port} "
                         f"nat={nat_port} ziel={ziel_port}")
            
            if session_id not in self.session_manager.pending_probes:
                self.session_manager.pending_probes[session_id] = []
            self.session_manager.pending_probes[session_id].append(
                (ip, nat_port, local_port, ts, ziel_port))
            
            # Filtertest, solange diese Verbindung offen ist: nur dann ist das
            # Mapping nachweislich lebendig. Nach dem Schliessen der Probe
            # kann die NAT es laengst freigegeben haben, und ein Zeitablauf
            # waere dann kein Beleg fuer Filterung, sondern fuer Vergesslichkeit.
            if halten:
                ergebnis = await pruefe_filter(ip, nat_port)
                self.session_manager.filter_ergebnis[(session_id, ip)] = ergebnis
                logger.info(f"Filter test {ip}:{nat_port} -> {ergebnis}")

            # Send ACK with observed port
            await send_message(writer, {
                'type': 'probe_ack',
                'probe_num': probe_num,
                'your_nat_port': nat_port
            })
            
        except Exception as e:
            logger.debug(f"Probe error: {e}")
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except:
                pass
    
    async def handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """Handle a new client connection"""
        addr = writer.get_extra_info('peername')
        logger.info(f"New connection from {addr}")
        
        peer = None
        session_id = None
        # Erst wenn der Peer wirklich in der Sitzung steht, darf er sie beim
        # Verlassen auch abraeumen.
        registriert = False
        
        try:
            data = await asyncio.wait_for(reader.readline(), timeout=300.0)
            if not data:
                return
            
            msg = json.loads(data.decode())
            
            if msg.get('type') != 'register':
                await send_error(writer, "Expected 'register' message")
                return
            
            session_id = msg['session_id']
            role = msg['role']
            local_port = msg.get('local_port', 0)
            private_ip = msg.get('private_ip')
            prediction_mode = (msg.get('prediction_mode') or 'delta').lower()
            if prediction_mode not in ('delta', 'external'):
                logger.warning(f"Unknown prediction_mode '{prediction_mode}', defaulting to 'delta'")
                prediction_mode = 'delta'
            range_raw = msg.get('prediction_range_extra_pct', 0.0)
            try:
                prediction_range_extra_pct = float(range_raw)
            except (TypeError, ValueError):
                logger.warning(f"Invalid prediction_range_extra_pct '{range_raw}', defaulting to 0.0")
                prediction_range_extra_pct = 0.0
            
            # Extract tcp_connections from register message
            tcp_connections = msg.get('tcp_connections', 1)
            
            extra_ports = msg.get('extra_ports', [])
            try:
                punch_ports = max(1, int(msg.get('punch_ports') or 1))
            except (TypeError, ValueError):
                punch_ports = 1
            
            if role not in ('sender', 'receiver'):
                await send_error(writer, f"Invalid role: {role}")
                return
            
            peer = Peer(
                reader=reader,
                writer=writer,
                public_addr=addr,
                local_port=local_port,
                role=role,
                session_id=session_id,
                private_ip=private_ip,
                prediction_mode=prediction_mode,
                prediction_range_extra_pct=prediction_range_extra_pct,
                tcp_connections=tcp_connections,
                punch_ports=punch_ports,
            )
            
            if extra_ports:
                peer.bound_ports = extra_ports.copy()
                logger.info(f"Peer {role} registered with {len(extra_ports)} bound ports: {extra_ports}")
            
            lock = self.session_manager.get_session_lock(session_id)
            
            async with lock:
                if session_id not in self.session_manager.sessions:
                    self.session_manager.sessions[session_id] = SessionState()
                
                session = self.session_manager.sessions[session_id]
                
                if session.peer(role) is not None:
                    await send_error(writer, f"Role '{role}' already taken")
                    return
                
                session.setze(role, peer)
                registriert = True
                logger.info(f"Registered {role} for session {session_id}: {addr}, local_port={local_port}")
            
            # Calculate initial delta
            initial_delta = addr[1] - local_port if local_port else 0
            port_preserved = (initial_delta == 0)
            
            # Determine if probing is needed
            peer.needs_probing = not port_preserved
            peer.probes_done = not peer.needs_probing
            
            # Create basic NAT analysis for port-preserved case
            if port_preserved:
                predicted_port = max(MIN_PORT, min(MAX_PORT, local_port or addr[1]))
                peer.nat_analysis = NATAnalysis(
                    probed_ports=[addr[1]],
                    local_ports=[local_port],
                    min_port=addr[1],
                    max_port=addr[1],
                    port_range=0,
                    predicted_port=predicted_port,
                    error_range=0,
                    pattern_type="port_preserved",
                    allocation="portbewahrend",
                    hit_probability=1.0,
                    needs_scan=False,
                    scan_start=predicted_port,
                    scan_end=predicted_port,
                )
            
            # Ein Zeitstempel, moeglichst spaet gelesen.
            #
            # Frueher standen hier fuenf Stempel im Abstand von 50 ms — in
            # *einer* Nachricht. Ein Median darueber ist deterministisch der
            # dritte Wert; unabhaengiges Rauschen, gegen das ein Median helfen
            # wuerde, gibt es dabei gar nicht. Gekostet hat es 250 ms je
            # Anmeldung. Der Client korrigiert stattdessen um die halbe
            # Umlaufzeit, die er selbst misst — und braucht ohnehin nur grobe
            # Genauigkeit, weil die Punch-Fenster beider Seiten Sekunden lang
            # ueberlappen.
            
            # Send registration ACK with multiple timestamps
            await send_message(writer, {
                'type': 'registered',
                'your_public_addr': list(addr),
                'your_role': role,
                'session_id': session_id,
                'server_time': time.time(),
                'initial_delta': initial_delta,
                'port_preserved': port_preserved,
                'needs_probing': peer.needs_probing,
                # Der Probe-Port wird immer mitgeteilt. Auch eine
                # portbewahrende NAT muss ihr *Filter*verhalten offenlegen —
                # davon haengt ab, ob die Gegenstelle unsere Ports ueberhaupt
                # abscannen muss. Ohne Probing genuegt dafuer eine einzige
                # gehaltene Verbindung.
                'probe_port': self.probe_port,
                'probe_port2': self.probe_port2 if peer.needs_probing else None,
                'filter_test': True
            })
            
            logger.info(f"Peer {role}: port_preserved={port_preserved}, needs_probing={peer.needs_probing}")
            
            # Wait for messages (coordination happens in handle_probes_complete)
            await wait_for_peer_messages(peer, self.session_manager, self.max_scan_ports)
        
        except asyncio.TimeoutError:
            logger.warning(f"Client {addr} timed out")
        except Exception as e:
            logger.error(f"Error handling client {addr}: {e}", exc_info=True)
        finally:
            # Eine abgelehnte Doppelregistrierung darf die laufende Sitzung
            # nicht anfassen: `cleanup_peer` loescht sonst den *unschuldigen*
            # Gegenpeer und wirft die ganze Sitzung weg, waehrend der
            # rechtmaessige Peer verbunden bleibt und verwaist.
            if session_id and peer and registriert:
                await self.session_manager.cleanup_peer(session_id, peer)
            try:
                writer.close()
                await writer.wait_closed()
            except:
                pass