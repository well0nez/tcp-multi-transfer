//! TCP Hole Punching — Simultaneous Open
//!
//! Es gibt bewusst nur *eine* Strategie: Listener und Connect laufen parallel,
//! zeitlich synchronisiert über `start_at`. Die früheren Varianten "listen" und
//! "connect" sind entfallen — der Coordinator hat ohnehin bedingungslos "scan"
//! geliefert, und ein reiner Listener ist hinter NAT unsauber, weil er selbst
//! kein Mapping erzeugt und vom Restmapping der Probes lebt.
//!
//! ## Warum mehrere lokale Ports
//!
//! Vergibt die eigene NAT pro Verbindung einen frischen Port aus einem Band der
//! Breite `N`, dann ist jeder gleichzeitig gehaltene Connect-Socket **eine
//! Ziehung** aus diesem Band. Die Gegenstelle öffnet ihre Filter für `k` Ports.
//! Der Punch gelingt, sobald sich die Menge der gehaltenen Mappings und die
//! Menge der geöffneten Ports schneiden:
//!
//! ```text
//!   P(Treffer) = 1 − (1 − k/N)^m        m = gleichzeitig gehaltene Ports
//! ```
//!
//! Entscheidend ist *gleichzeitig*: ein geschlossener Socket nimmt sein Mapping
//! mit, ein SYN der Gegenstelle darauf bekommt ein RST. Nacheinander probierte
//! Ports summieren sich deshalb **nicht** auf — genau deshalb hat mehr Zeit in
//! den Messungen nichts gebracht, wohl aber ein breiterer Scan. Das Produkt
//! `m · k` ist der Hebel, nicht die Dauer.
//!
//! Die Sockets werden entsprechend **offen gehalten**, bis das Zeitbudget
//! abläuft. Ein Neuaufbau erfolgt nur, wenn die Gegenseite ein RST schickt —
//! dann ist das Mapping ohnehin verloren und ein neuer Versuch ist eine neue
//! Ziehung.
//!
//! Zusätzliche lokale Ports lohnen sich **nur**, wenn die eigene NAT
//! unvorhersagbar vergibt. Bei portbewahrender oder versatzstabiler Vergabe
//! kennt die Gegenstelle genau einen Port von uns; jedes Mapping auf einem
//! anderen lokalen Port läge außerhalb ihrer Kandidatenliste und wäre
//! wirkungslos. Deshalb entscheidet die eigene NAT-Analyse darüber (siehe
//! `connection/mod.rs`).

use std::time::Duration;
use std::net::SocketAddr;
use tokio::net::{TcpListener, TcpStream};
use anyhow::{Result, anyhow};
use tracing::{info, debug};

use socket2::SockAddr;
use super::helpers::*;
use crate::protocol::relay::PeerAddressInfo;
use crate::metrics::PunchReport;

/// Schalter für die A/B-Messung. Alle Neuerungen lassen sich einzeln abschalten,
/// damit alte und neue Variante mit **demselben Binary** verglichen werden können
/// und kein Unterschied im Build die Messung verfälscht.
#[derive(Debug, Clone)]
pub struct PunchOptions {
    /// LAN-Kandidaten bevorzugen, wenn beide Peers hinter derselben NAT sitzen.
    pub prefer_lan: bool,
    /// Wie viele lokale Ports je Ziel gleichzeitig gehalten werden. 1 = altes
    /// Verhalten.
    pub parallel_ports: usize,
    /// Obergrenze für `Ziele × Ports`. Schützt davor, dass eine breite
    /// Kandidatenliste mal viele Ports die Socket-Tabelle sprengt.
    pub socket_budget: usize,
    /// Wie viele Kandidaten der Gegenstelle überhaupt angefasst werden.
    /// `None` = alle. Macht die Abdeckung zu einem Schalter im selben Binary.
    pub max_candidates: Option<usize>,
    /// Wartezeit nach einem abgewiesenen Versuch, bevor neu gezogen wird.
    pub retry_pause: Duration,
    /// Obergrenze für die Wartezeit auf einen besseren Kandidaten.
    pub grace: Duration,
    /// Wartezeit aus der Laufzeit des ersten Kandidaten ableiten statt fest
    /// setzen. Siehe `warte_fenster`.
    pub grace_adaptiv: bool,
    /// Taktzeit fuer den Notbehelf, wenn das Socket-Budget nicht fuer alle
    /// Ziele reicht. `None` = Vorgabe (800 ms).
    pub rotate_after: Option<Duration>,
}

impl Default for PunchOptions {
    fn default() -> Self {
        Self {
            prefer_lan: true,
            parallel_ports: 16,
            socket_budget: 512,
            max_candidates: None,
            retry_pause: Duration::from_millis(100),
            grace: Duration::from_millis(300),
            grace_adaptiv: true,
            rotate_after: None,
        }
    }
}

impl PunchOptions {
    /// Verhalten vor den Änderungen — Referenz für den Vergleich.
    pub fn legacy() -> Self {
        Self {
            prefer_lan: false,
            parallel_ports: 1,
            socket_budget: 512,
            max_candidates: None,
            retry_pause: Duration::from_millis(100),
            grace: Duration::from_millis(300),
            grace_adaptiv: false,
            rotate_after: None,
        }
    }
}

/// Wie lange nach dem ersten Kandidaten noch gewartet wird.
///
/// Ein Kandidat braucht vom synchronisierten Start bis zur Meldung rund zwei
/// Umlaufzeiten — ein SYN hin, ein SYN-ACK zurück, dann der Pre-Handshake.
/// Gemessen über 29 erfolgreiche Punches: Median 107 ms, Spanne 82 bis 144 ms,
/// bei einer minimalen Umlaufzeit von 35 ms. Ein zweiter Kandidat entsteht aus
/// denselben Vorgängen und trifft deshalb in derselben Größenordnung ein; die
/// beobachtete Streuung zwischen erstem und letztem Kandidaten lag unter 62 ms.
///
/// Ein fester Wert muss den langsamsten denkbaren Pfad abdecken und ist auf
/// jedem schnellen verschenkt: bei 300 ms gingen **74 %** der gesamten
/// Punch-Dauer (Median 410 ms) für das Warten drauf. Die Laufzeit des ersten
/// Kandidaten misst dagegen genau die Größe, um die es geht — sie enthält
/// Umlaufzeit und Weckverzögerung des Mobilfunks bereits. Deshalb: noch einmal
/// so lange warten, wie der erste gebraucht hat, begrenzt nach oben durch
/// `--grace-ms` und nach unten durch 50 ms.
fn warte_fenster(opts: &PunchOptions, erster_ms: f64) -> Duration {
    if !opts.grace_adaptiv {
        return opts.grace;
    }
    let vorschlag = Duration::from_millis(erster_ms.max(0.0) as u64);
    // Untergrenze nie ueber die Obergrenze heben: `clamp` verlangt min <= max
    // und bricht sonst mit einer Panik ab. `--grace-ms 20` genuegte dafuer.
    let untergrenze = Duration::from_millis(50).min(opts.grace);
    vorschlag.clamp(untergrenze, opts.grace)
}

/// Peer-Info für das Punching
#[derive(Debug, Clone)]
pub struct PeerInfo {
    pub peer_addresses: Vec<PeerAddressInfo>,
    /// Beide Peers hinter derselben öffentlichen Adresse.
    pub same_network: bool,
    pub peer_nat_analysis: Option<crate::protocol::NATAnalysis>,
    /// Analyse der eigenen NAT — entscheidet über die Zahl der Port-Fächer.
    pub own_nat_analysis: Option<crate::protocol::NATAnalysis>,
}

/// Ein Kandidat, auf den gepuncht wird.
#[derive(Debug, Clone, Copy)]
struct Target {
    addr: SocketAddr,
    /// Adresse im selben lokalen Netz — erreichbar ohne NAT.
    is_lan: bool,
}

/// Ergebnis eines erfolgreichen Versuchs, inklusive der Angaben, die wir für die
/// empirische Auswertung brauchen.
struct Candidate {
    stream: TcpStream,
    local_port: u16,
    remote_port: u16,
    is_lan: bool,
    /// Aus welchem Port-Fach der Treffer kam. `None` = über den Listener.
    slot: Option<usize>,
    /// Symmetrischer Schlüssel aus dem Pre-Handshake. Beide Seiten berechnen
    /// für dieselbe Verbindung denselben Wert.
    key: (u64, u64),
}

/// Vergleicht zwei Kandidaten. LAN schlägt WAN — das sehen beide Seiten gleich,
/// weil beide dieselbe Verbindung als LAN einstufen. Danach entscheidet der im
/// Pre-Handshake ausgetauschte Schlüssel, der ebenfalls auf beiden Seiten
/// identisch ist. Die Auswahl ist damit ohne weitere Absprache auf beiden
/// Seiten dieselbe.
fn is_better(new: &Candidate, cur: &Candidate, prefer_lan: bool) -> bool {
    if prefer_lan && new.is_lan != cur.is_lan {
        return new.is_lan;
    }
    new.key < cur.key
}

fn describe(c: &Candidate) -> String {
    format!("local={} remote={} {}", c.local_port, c.remote_port, if c.is_lan { "LAN" } else { "WAN" })
}

/// Sammelt die Zieladressen und markiert LAN-Kandidaten.
fn build_targets(peer_info: &PeerInfo, max_candidates: Option<usize>) -> Vec<Target> {
    let mut out: Vec<Target> = Vec::new();
    for info in &peer_info.peer_addresses {
        let addr: SocketAddr = match format!("{}:{}", info.ip, info.port).parse() {
            Ok(a) => a,
            Err(_) => continue,
        };
        if out.iter().any(|t| t.addr == addr) {
            continue;
        }
        // Der Server markiert LAN-Kandidaten explizit; als Rückfallebene gilt eine
        // private Adresse bei gleicher öffentlicher IP ebenfalls als LAN.
        let is_lan = info.addr_type == "local"
            || (peer_info.same_network && is_private_v4(&addr));
        out.push(Target { addr, is_lan });
    }
    // LAN nach vorn — sie verbinden ohne NAT und damit praktisch sofort.
    out.sort_by_key(|t| !t.is_lan);

    // Begrenzung der Kandidatenzahl: **ausdünnen, nicht abschneiden** — und
    // dabei im beobachteten Band bleiben.
    //
    // Die Liste ist ein zusammenhängender Portbereich. Ein Abschneiden hinten
    // liesse nur den unteren Rand übrig; gleichmässiges Ausdünnen deckt
    // dieselbe Zahl von Ports über die volle Breite ab.
    //
    // Der Scanbereich enthält aber den Aufschlag aus der Ordnungsstatistik und
    // ist damit breiter als das Band, in dem die NAT nachweislich vergibt. Bei
    // dichter Abdeckung zahlt sich das aus — bei knappem Budget nicht: von `k`
    // gleichmässig über die Breite `R` gestreuten Kandidaten treffen nur
    // `k · W/R` in das Band der Breite `W`, der Rest ist verschenkt. Gemessen:
    // 32 Kandidaten über einen Bereich von ~375 statt über die beobachteten
    // ~205 ergaben 71 % Erfolg je Versuch statt der aus 32 wirksamen
    // Kandidaten erwarteten 88,5 %.
    //
    // Deshalb wird zuerst aus dem beobachteten Band gezogen und erst danach,
    // wenn Budget übrig ist, aus dem Rest.
    if let Some(max) = max_candidates {
        let max = max.max(1);
        if out.len() > max {
            let feste = out.iter().take_while(|t| t.is_lan).count() + 1;
            let feste = feste.min(max);
            let rest: Vec<Target> = out.split_off(feste);

            let (lo, hi) = peer_info
                .peer_nat_analysis
                .as_ref()
                .map(|a| (a.min_port, a.max_port))
                .unwrap_or((0, 0));
            let im_band = |t: &Target| lo > 0 && hi >= lo && {
                let p = t.addr.port();
                p >= lo && p <= hi
            };

            let (innen, aussen): (Vec<Target>, Vec<Target>) =
                rest.iter().partition(|t| im_band(t));
            let quelle = if innen.is_empty() { &rest } else { &innen };

            let nimm = |quelle: &Vec<Target>, anzahl: usize, out: &mut Vec<Target>| {
                if anzahl == 0 || quelle.is_empty() {
                    return;
                }
                let schritt = quelle.len() as f64 / anzahl as f64;
                for i in 0..anzahl {
                    let idx = (((i as f64) * schritt).round() as usize).min(quelle.len() - 1);
                    let t = quelle[idx];
                    if !out.iter().any(|x| x.addr == t.addr) {
                        out.push(t);
                    }
                }
            };

            nimm(quelle, max.saturating_sub(out.len()), &mut out);
            // Budget noch übrig? Dann deckt es das Band ohnehin dicht ab, und
            // die Ränder mitzunehmen lohnt wieder.
            if out.len() < max && !aussen.is_empty() {
                nimm(&aussen, max - out.len(), &mut out);
            }
        }
    }
    out
}

fn is_private_v4(addr: &SocketAddr) -> bool {
    match addr {
        SocketAddr::V4(v4) => v4.ip().is_private(),
        SocketAddr::V6(_) => false,
    }
}

/// Wartet bis zum synchronisierten Startzeitpunkt.
async fn wait_for_start(start_at: f64, time_offset: f64) {
    let local_start_at = start_at - time_offset;
    let remaining = (local_start_at - current_timestamp()).max(0.0);
    if remaining > 0.0 {
        info!("Waiting {:.3}s until the synchronized start", remaining);
        tokio::time::sleep(Duration::from_secs_f64(remaining)).await;
    }
}

/// Ausgang eines einzelnen Verbindungsversuchs.
enum Versuch {
    Verbunden(TcpStream),
    /// Abgewiesen (RST o.ä.) — das Mapping ist verloren, neu ziehen.
    Abgewiesen,
    /// Zeitbudget abgelaufen, während der Socket noch offen war.
    Zeitablauf,
}

/// Simultaneous Open: ein Listener auf dem gebundenen Port, parallel ein
/// Connect-Task je Ziel und lokalem Port-Fach.
///
/// Gibt zusaetzlich zum Ergebnis immer einen `PunchReport` zurueck — auch im
/// Fehlerfall, denn gerade die Fehlschlaege sind fuer den Vergleich interessant.
pub async fn punch_connection(
    socket: socket2::Socket,
    peer_info: &PeerInfo,
    opts: &PunchOptions,
    start_at: f64,
    time_offset: f64,
    timeout: Duration,
    conn_num: u32,
    mapping_stable: Option<bool>,
) -> (Result<TcpStream>, PunchReport) {
    let mut report = PunchReport { conn_num, outcome: "failed", mapping_stable, ..Default::default() };

    let targets = build_targets(peer_info, opts.max_candidates);
    report.candidates_total = targets.len();
    report.candidates_lan = targets.iter().filter(|t| t.is_lan).count();

    if targets.is_empty() {
        report.error = Some("no target addresses".to_string());
        return (Err(anyhow!("No target addresses available")), report);
    }

    let local_port = match socket.local_addr().ok().and_then(|a| a.as_socket()).map(|a| a.port()) {
        Some(p) => p,
        None => {
            report.error = Some("bound socket without IP address".to_string());
            return (Err(anyhow!("Bound socket has no IP address")), report);
        }
    };

    // Socket-Budget auf die Ziele verteilen. Fach 0 gibt es immer — das ist der
    // Versuch vom gebundenen Punch-Port, den die Gegenstelle kennt.
    let ports_per_target = opts
        .parallel_ports
        .max(1)
        .min((opts.socket_budget / targets.len().max(1)).max(1));
    report.ports_per_target = ports_per_target;
    if ports_per_target < opts.parallel_ports {
        info!(
            "Local ports capped at {} ({} targets, budget {})",
            ports_per_target, targets.len(), opts.socket_budget
        );
    }

    wait_for_start(start_at, time_offset).await;

    // Ab hier laeuft die Uhr, die wir vergleichen wollen.
    let punch_start = tokio::time::Instant::now();
    let deadline = punch_start + timeout;

    // Der uebergebene Socket ist der, dessen Port der Peer anvisiert. Er wird
    // deshalb direkt zum Listener — frueher wurde hier ein zweiter Socket auf
    // denselben Port gelegt und dieser stillschweigend fallengelassen.
    let listener = match setup_listener(socket) {
        Ok(l) => l,
        Err(e) => {
            report.error = Some(format!("listener: {}", e));
            report.elapsed_ms = punch_start.elapsed().as_secs_f64() * 1000.0;
            return (Err(e), report);
        }
    };
    info!("Listener ready on port {}", local_port);
    info!(
        "Punching {} addresses ({} of them LAN) from {} local port(s) each",
        report.candidates_total, report.candidates_lan, ports_per_target
    );
    debug!("Targets: {:?}", targets.iter().map(|t| t.addr).collect::<Vec<_>>());

    let kanal = targets.len() * ports_per_target + 2;
    let (tx, mut rx) = tokio::sync::mpsc::channel::<Candidate>(kanal.max(4));

    // Eingehende Seite des Simultaneous Open.
    let listener_tx = tx.clone();
    let listener_handle = tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((mut stream, peer_addr)) => {
                    debug!("Accepted from {}", peer_addr);
                    stream.set_nodelay(true).ok();
                    if let Ok(key) = pre_handshake(&mut stream).await {
                        let lp = stream.local_addr().ok().map(|a| a.port()).unwrap_or(0);
                        let rp = stream.peer_addr().ok().map(|a| a.port()).unwrap_or(0);
                        let is_lan = stream.peer_addr().map(|a| is_private_v4(&a)).unwrap_or(false);
                        let _ = listener_tx.send(Candidate {
                            stream, local_port: lp, remote_port: rp, is_lan, slot: None, key,
                        }).await;
                        break;
                    }
                }
                Err(e) => {
                    debug!("Accept error: {}", e);
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            }
        }
    });

    // Ausgehende Seite: ein Task je Ziel und Port-Fach.
    //
    // Reicht das Socket-Budget nicht fuer alle Ziele, bedient ein Task mehrere
    // Ziele nacheinander. Das ist erlaubt, weil die Filterfreigabe, die ein SYN
    // in der *eigenen* NAT anlegt, den Socket ueberlebt (conntrack haelt einen
    // SYN_SENT-Eintrag typisch zwei Minuten): das Loch bleibt offen, und das
    // eingehende SYN der Gegenstelle faengt der Listener auf dem gebundenen
    // Port. Die Abdeckung summiert sich also ueber die Zeit — anders als die
    // *Ziehungen* der eigenen NAT, die nur solange zaehlen, wie ihr Socket
    // lebt. Deshalb wird nur rotiert, wenn ohnehin nur ein Port-Fach laeuft.
    let total = targets.len();
    let retry_pause = opts.retry_pause;
    // Das Budget begrenzt die Zahl gleichzeitiger Sockets. Reicht es nicht fuer
    // alle Ziele, werden sie reihum bedient statt hinten abgeschnitten —
    // gemessen ist das besser als Wegwerfen, aber deutlich schlechter als
    // genug Sockets (77 % gegen 23 % je Versuch bei 256 Zielen, gepaarte
    // Laeufe). Deshalb ist Rotation ein Notbehelf und keine Vorgabe.
    let obergrenze = (opts.socket_budget.max(1) / ports_per_target.max(1)).max(1);
    let gruppen = std::cmp::min(total, obergrenze);
    let rotate_after = if gruppen < total && ports_per_target == 1 {
        Some(opts.rotate_after.unwrap_or(Duration::from_millis(800)))
    } else {
        None
    };
    report.rotating = rotate_after.is_some();
    if gruppen < total && rotate_after.is_none() {
    }

    let mut connector_handles = Vec::with_capacity(gruppen * ports_per_target);
    for gruppe in 0..gruppen {
        // Ziele im Abstand `gruppen` — so faechert jede Gruppe ueber das ganze
        // Band auf statt einen zusammenhaengenden Ausschnitt zu bearbeiten.
        let meine: Vec<Target> = targets.iter().skip(gruppe).step_by(gruppen).copied().collect();
        for slot in 0..ports_per_target {
            connector_handles.push(tokio::spawn(connector_task(ConnectorArgs {
                ziele: meine.clone(),
                gruppe,
                slot,
                local_port,
                deadline,
                retry_pause,
                rotate_after,
                tx: tx.clone(),
            })));
        }
    }

    drop(tx);

    let mut winner = match tokio::time::timeout(timeout + Duration::from_secs(1), rx.recv()).await {
        Ok(Some(c)) => { debug!("First candidate: {}", describe(&c)); c }
        Ok(None) => {
            stop_all(listener_handle, connector_handles);
            report.elapsed_ms = punch_start.elapsed().as_secs_f64() * 1000.0;
            report.error = Some("no candidate".to_string());
            return (Err(anyhow!("No candidate materialized")), report);
        }
        Err(_) => {
            stop_all(listener_handle, connector_handles);
            report.elapsed_ms = punch_start.elapsed().as_secs_f64() * 1000.0;
            report.outcome = "timeout";
            report.error = Some(format!("timed out after {:?}", timeout));
            return (Err(anyhow!("Timed out after {:.1}s (configured: {:?})",
                                punch_start.elapsed().as_secs_f64(), timeout)), report);
        }
    };
    report.candidates_seen = 1;
    report.first_candidate_ms = punch_start.elapsed().as_secs_f64() * 1000.0;

    // Ein LAN-Kandidat ist bereits das Optimum, dann lohnt das Warten nicht.
    if !(opts.prefer_lan && winner.is_lan) {
        let fenster = warte_fenster(opts, report.first_candidate_ms);
        report.grace_ms = fenster.as_millis() as u64;
        let grace_until = tokio::time::Instant::now() + fenster;
        loop {
            let now = tokio::time::Instant::now();
            if now >= grace_until { break; }
            match tokio::time::timeout(grace_until - now, rx.recv()).await {
                Ok(Some(c)) => {
                    report.candidates_seen += 1;
                    if is_better(&c, &winner, opts.prefer_lan) {
                        debug!("Better candidate: {} beats {}", describe(&c), describe(&winner));
                        winner = c;
                        report.grace_switch = true;
                    }
                }
                Ok(None) | Err(_) => break,
            }
        }
    }

    stop_all(listener_handle, connector_handles);

    report.outcome = "established";
    report.elapsed_ms = punch_start.elapsed().as_secs_f64() * 1000.0;
    report.winner_local_port = winner.local_port;
    report.winner_remote_port = winner.remote_port;
    report.winner_is_lan = winner.is_lan;
    report.winner_slot = winner.slot;

    info!("Chosen: {} after {:.3}s", describe(&winner), report.elapsed_ms / 1000.0);
    (Ok(winner.stream), report)
}

fn setup_listener(socket: socket2::Socket) -> Result<TcpListener> {
    socket.listen(128)?;
    let std_listener: std::net::TcpListener = socket.into();
    std_listener.set_nonblocking(true)?;
    Ok(TcpListener::from_std(std_listener)?)
}

fn stop_all(lh: tokio::task::JoinHandle<()>, chs: Vec<tokio::task::JoinHandle<()>>) {
    lh.abort();
    for h in chs { h.abort(); }
}

/// Wartet auf den Abschluss eines nicht-blockierenden Connect.
///
/// Unterscheidet Abweisung von Zeitablauf: nur die Abweisung rechtfertigt einen
/// neuen Socket, denn nur dort ist das NAT-Mapping verloren.
async fn warte_auf_verbindung(stream: TcpStream, timeout: Duration) -> Versuch {
    use tokio::io::Interest;
    match tokio::time::timeout(timeout, stream.ready(Interest::WRITABLE)).await {
        Ok(Ok(_)) => match stream.peer_addr() {
            Ok(_) => {
                stream.set_nodelay(true).ok();
                Versuch::Verbunden(stream)
            }
            Err(_) => Versuch::Abgewiesen,
        },
        Ok(Err(_)) => Versuch::Abgewiesen,
        Err(_) => Versuch::Zeitablauf,
    }
}

/// Was ein Connect-Task braucht. Als Struktur statt als zehn eingefangene
/// Variablen — die Closure war so nicht mehr am Stueck lesbar.
struct ConnectorArgs {
    ziele: Vec<Target>,
    gruppe: usize,
    slot: usize,
    local_port: u16,
    deadline: tokio::time::Instant,
    retry_pause: Duration,
    rotate_after: Option<Duration>,
    tx: tokio::sync::mpsc::Sender<Candidate>,
}

/// Ein ausgehender Punch-Versuch: bindet einen lokalen Port, schickt das SYN
/// und haelt den Socket offen, bis das Zeitbudget ablaeuft oder die
/// Gegenstelle abweist.
async fn connector_task(a: ConnectorArgs) {
    let ConnectorArgs {
        ziele, gruppe, slot, local_port, deadline, retry_pause, rotate_after, tx,
    } = a;
    if ziele.is_empty() {
        return;
    }

    let mut ziehungen = 0usize;
    let mut ziel_idx = 0usize;
    let mut ziel_seit = tokio::time::Instant::now();

    while tokio::time::Instant::now() < deadline {
        ziehungen += 1;
        if let Some(dauer) = rotate_after {
            if ziele.len() > 1 && ziel_seit.elapsed() >= dauer {
                ziel_idx = (ziel_idx + 1) % ziele.len();
                ziel_seit = tokio::time::Instant::now();
            }
        }
        let target = ziele[ziel_idx];

        // Fach 0 nutzt den gebundenen Punch-Port. Die uebrigen ziehen einen
        // frischen Ephemeralport — jeder davon ist eine eigene Ziehung aus dem
        // Band der eigenen NAT.
        let bind_port = if slot == 0 { local_port } else { 0 };

        let sock = match create_hole_punch_socket() {
            Ok(s) => s,
            Err(e) => {
                debug!("Target[{}/{}]: socket failed: {}", gruppe, slot, e);
                tokio::time::sleep(retry_pause).await;
                continue;
            }
        };
        if let Err(e) = bind_to_port(&sock, bind_port) {
            debug!("Target[{}/{}]: bind failed: {}", gruppe, slot, e);
            tokio::time::sleep(retry_pause).await;
            continue;
        }
        sock.set_nonblocking(true).ok();

        let sofort = match sock.connect(&SockAddr::from(target.addr)) {
            Ok(()) => true,
            Err(e) => {
                #[cfg(unix)]
                let in_progress = e.raw_os_error() == Some(libc::EINPROGRESS)
                    || e.kind() == std::io::ErrorKind::WouldBlock;
                #[cfg(not(unix))]
                let in_progress = e.kind() == std::io::ErrorKind::WouldBlock;

                if !in_progress {
                    debug!("Target[{}/{}]: connect refused: {}", gruppe, slot, e);
                    tokio::time::sleep(retry_pause).await;
                    continue;
                }
                false
            }
        };

        let std_stream: std::net::TcpStream = sock.into();
        let stream = match TcpStream::from_std(std_stream) {
            Ok(s) => s,
            Err(_) => { tokio::time::sleep(retry_pause).await; continue; }
        };

        // Der Socket bleibt bis zum Zeitbudget offen — damit bleibt auch das
        // NAT-Mapping bestehen, auf das die Gegenstelle treffen muss.
        let rest = deadline.saturating_duration_since(tokio::time::Instant::now());
        let warte = match rotate_after {
            Some(d) if ziele.len() > 1 => std::cmp::min(rest, d),
            _ => rest,
        };
        let ausgang = if sofort {
            Versuch::Verbunden(stream)
        } else {
            warte_auf_verbindung(stream, warte).await
        };

        match ausgang {
            Versuch::Verbunden(mut stream) => {
                if let Ok(key) = pre_handshake(&mut stream).await {
                    let lp = stream.local_addr().ok().map(|a| a.port()).unwrap_or(0);
                    // Der lokale Port ist die unterscheidende Groesse: alle
                    // Faecher zielen auf dieselbe Adresse, verschieden ist nur,
                    // welches NAT-Mapping die eigene NAT dahinter legt.
                    info!("Connected {} -> {} (group {}, slot {})",
                          lp, target.addr, gruppe, slot);
                    let rp = stream.peer_addr().ok().map(|a| a.port()).unwrap_or(0);
                    let _ = tx.send(Candidate {
                        stream, local_port: lp, remote_port: rp,
                        is_lan: target.is_lan, slot: Some(slot), key,
                    }).await;
                    return;
                }
                tokio::time::sleep(retry_pause).await;
            }
            Versuch::Abgewiesen => {
                tokio::time::sleep(retry_pause).await;
            }
            Versuch::Zeitablauf => {
                // Ohne Rotation ist das Budget aufgebraucht; mit Rotation geht
                // es beim naechsten Ziel weiter.
                if rotate_after.is_none() || ziele.len() <= 1 {
                    break;
                }
            }
        }
    }
    debug!("Group[{}/{}]: {} draws across {} targets, no success",
           gruppe, slot, ziehungen, ziele.len());
}
