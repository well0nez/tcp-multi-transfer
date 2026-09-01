//! Auskunft des Kernels ueber eine bestehende TCP-Verbindung (`TCP_INFO`).
//!
//! Warum das noetig ist: aus Anwendungssicht sieht ein zu kleiner Sendepuffer,
//! ein zu kleines Empfangsfenster, ein Verlustereignis und eine langsame
//! Gegenstelle alle gleich aus — der Durchsatz ist niedrig. Der Kernel fuehrt
//! aber getrennt Buch:
//!
//!   * `sndbuf_limited` — Mikrosekunden, in denen der Sendepuffer der Grund
//!     war, dass nicht mehr geschickt wurde. Das ist die direkte Antwort auf
//!     die Frage, ob die Deckelung von 64 MB auf `wmem_max` ueberhaupt bindet.
//!   * `rwnd_limited` — dasselbe fuer das Empfangsfenster der Gegenstelle.
//!   * `busy_time` — Zeit mit ausstehenden Daten. Der Rest ist Leerlauf, also
//!     Wartezeit der Anwendung (Quittungen, Platte, Pruefsummen).
//!   * `total_retrans` / `bytes_retrans` — Verlust auf der Strecke.
//!   * `min_rtt` — die Umlaufzeit ohne Warteschlangenanteil.
//!
//! Damit laesst sich "Strecke oder Code" ohne Vermutung entscheiden.

#[cfg(target_os = "linux")]
mod linux {
    use std::os::unix::io::AsRawFd;
    use tokio::net::TcpStream;

    // Reihenfolge und Typen wie in linux/tcp.h. Es wird nur so weit gelesen,
    // wie der Kernel tatsaechlich gefuellt hat — aeltere Kernel kennen die
    // hinteren Felder nicht.
    #[repr(C)]
    #[derive(Default, Clone, Copy)]
    struct TcpInfo {
        state: u8,
        ca_state: u8,
        retransmits: u8,
        probes: u8,
        backoff: u8,
        options: u8,
        wscale: u8,
        app_limited: u8,

        rto: u32,
        ato: u32,
        snd_mss: u32,
        rcv_mss: u32,

        unacked: u32,
        sacked: u32,
        lost: u32,
        retrans: u32,
        fackets: u32,

        last_data_sent: u32,
        last_ack_sent: u32,
        last_data_recv: u32,
        last_ack_recv: u32,

        pmtu: u32,
        rcv_ssthresh: u32,
        rtt: u32,
        rttvar: u32,
        snd_ssthresh: u32,
        snd_cwnd: u32,
        advmss: u32,
        reordering: u32,

        rcv_rtt: u32,
        rcv_space: u32,

        total_retrans: u32,

        pacing_rate: u64,
        max_pacing_rate: u64,
        bytes_acked: u64,
        bytes_received: u64,
        segs_out: u32,
        segs_in: u32,

        notsent_bytes: u32,
        min_rtt: u32,
        data_segs_in: u32,
        data_segs_out: u32,

        delivery_rate: u64,

        busy_time: u64,
        rwnd_limited: u64,
        sndbuf_limited: u64,

        delivered: u32,
        delivered_ce: u32,

        bytes_sent: u64,
        bytes_retrans: u64,
        dsack_dups: u32,
        reord_seen: u32,

        rcv_ooopack: u32,
        snd_wnd: u32,
    }

    /// Liest `TCP_INFO` und gibt die Felder als JSON zurueck. `None`, wenn der
    /// Abruf scheitert — eine Messung darf nie einen Transfer abbrechen.
    pub fn tcp_info(stream: &TcpStream) -> Option<serde_json::Value> {
        let fd = stream.as_raw_fd();
        let mut info = TcpInfo::default();
        let mut len = std::mem::size_of::<TcpInfo>() as libc::socklen_t;
        let rc = unsafe {
            libc::getsockopt(
                fd,
                libc::IPPROTO_TCP,
                libc::TCP_INFO,
                &mut info as *mut TcpInfo as *mut libc::c_void,
                &mut len,
            )
        };
        if rc != 0 {
            return None;
        }
        let hat = |bis: usize| (len as usize) >= bis;

        // Byteversatz der spaeten Felder, um alte Kernel nicht falsch zu lesen.
        const BIS_TOTAL_RETRANS: usize = 104;
        const BIS_SEGS: usize = 144;
        const BIS_MIN_RTT: usize = 160;
        const BIS_LIMITED: usize = 192;
        const BIS_BYTES_RETRANS: usize = 216;

        let mut v = serde_json::json!({
            "snd_mss": info.snd_mss,
            "rtt_us": info.rtt,
            "rttvar_us": info.rttvar,
            "snd_cwnd": info.snd_cwnd,
            "snd_ssthresh": info.snd_ssthresh,
            "ca_state": info.ca_state,
            "retransmits": info.retransmits,
            "lost": info.lost,
            "reordering": info.reordering,
        });
        let o = v.as_object_mut().unwrap();
        if hat(BIS_TOTAL_RETRANS) {
            o.insert("total_retrans".into(), serde_json::json!(info.total_retrans));
        }
        if hat(BIS_SEGS) {
            o.insert("bytes_acked".into(), serde_json::json!(info.bytes_acked));
            o.insert("bytes_received".into(), serde_json::json!(info.bytes_received));
            o.insert("segs_out".into(), serde_json::json!(info.segs_out));
            o.insert("segs_in".into(), serde_json::json!(info.segs_in));
        }
        if hat(BIS_MIN_RTT) {
            o.insert("min_rtt_us".into(), serde_json::json!(info.min_rtt));
            o.insert("notsent_bytes".into(), serde_json::json!(info.notsent_bytes));
        }
        if hat(BIS_LIMITED) {
            o.insert("delivery_rate_bps".into(), serde_json::json!(info.delivery_rate * 8));
            o.insert("busy_time_us".into(), serde_json::json!(info.busy_time));
            o.insert("rwnd_limited_us".into(), serde_json::json!(info.rwnd_limited));
            o.insert("sndbuf_limited_us".into(), serde_json::json!(info.sndbuf_limited));
        }
        if hat(BIS_BYTES_RETRANS) {
            o.insert("delivered".into(), serde_json::json!(info.delivered));
            o.insert("bytes_sent".into(), serde_json::json!(info.bytes_sent));
            o.insert("bytes_retrans".into(), serde_json::json!(info.bytes_retrans));
        }
        Some(v)
    }

    /// Puffergroessen, wie der Kernel sie meldet.
    ///
    /// Achtung beim Lesen: Linux legt intern das Doppelte des per
    /// `setsockopt` gesetzten Werts ab und gibt genau das hier zurueck. Der
    /// mit `net.core.wmem_max` vergleichbare Wert ist also die Haelfte —
    /// halbiert wird hier bewusst nicht, damit in den Metriken steht, was der
    /// Kernel sagt, und nicht eine Umrechnung.
    pub fn puffer(stream: &TcpStream) -> Option<serde_json::Value> {
        let fd = stream.as_raw_fd();
        let wert = |opt: libc::c_int| -> Option<i32> {
            let mut v: libc::c_int = 0;
            let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
            let rc = unsafe {
                libc::getsockopt(
                    fd,
                    libc::SOL_SOCKET,
                    opt,
                    &mut v as *mut libc::c_int as *mut libc::c_void,
                    &mut len,
                )
            };
            if rc == 0 { Some(v) } else { None }
        };
        Some(serde_json::json!({
            "sndbuf_kernel": wert(libc::SO_SNDBUF),
            "rcvbuf_kernel": wert(libc::SO_RCVBUF),
        }))
    }
}

#[cfg(target_os = "linux")]
pub use linux::{puffer, tcp_info};

#[cfg(not(target_os = "linux"))]
pub fn tcp_info(_stream: &tokio::net::TcpStream) -> Option<serde_json::Value> {
    None
}

#[cfg(not(target_os = "linux"))]
pub fn puffer(_stream: &tokio::net::TcpStream) -> Option<serde_json::Value> {
    None
}
