# REFACTORING PLAN: main.rs (795 Zeilen → ~200 Zeilen)

**Erstellt:** 2026-01-23  
**Ziel:** main.rs von 795 Zeilen auf ~200 Zeilen reduzieren für bessere LLM-Verarbeitung  
**Strategie:** Aufsplitten in 3 Module: `relay.rs`, `connection.rs`, und reduzierte `main.rs`

---

## 📊 AKTUELLE STRUKTUR (main.rs - 795 Zeilen)

### 1. Imports & Module Declarations (Zeilen 1-28)
```rust
// Imports für std, externe Crates, eigene Module
use std::net::{SocketAddr, ToSocketAddrs};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
// ... etc
mod cli;
mod protocol;
mod punch;
mod transfer;
```

### 2. Session Struct (Zeilen 30-51)
```rust
struct Session {
    peer_public_addr: Option<SocketAddr>,
    peer_addresses: Vec<protocol::relay::PeerAddressInfo>,
    peer_nat_analysis: Option<protocol::NATAnalysis>,
    same_network: bool,
    time_offset: f64,
    our_public_port: Option<u16>,
    our_delta: i32,
    port_preserved: bool,
    tcp_connections: u32,
    scan_budget: u32,
    punch_overshoot: f64,
    allow_fallback: bool,
    min_connections: u32,
    bound_sockets: Vec<Socket>,
    peer_extra_ports: Vec<u16>,
}
```

### 3. Utility Functions (Zeilen 53-136)
- `parse_host_port()` (Zeilen 53-65) - 13 Zeilen
- `resolve_host_port()` (Zeilen 67-70) - 4 Zeilen
- `resolve_socket_addr()` (Zeilen 72-75) - 4 Zeilen
- `do_nat_probing()` (Zeilen 77-103) - 27 Zeilen
- `get_free_port()` (Zeilen 105-113) - 9 Zeilen
- `create_bound_socket()` (Zeilen 115-123) - 9 Zeilen
- `compute_punch_task_count()` (Zeilen 125-129) - 5 Zeilen

**Total: ~71 Zeilen**

### 4. Relay Protocol Function (Zeilen 131-380)
- `run_relay_protocol()` - **249 Zeilen** (SEHR GROß!)
  - Verbindet zum Relay-Server
  - Sendet Register-Message
  - Empfängt Registered-Message
  - Handhabt Time Synchronization
  - NAT Probing
  - Empfängt PeerInfo (alte Protokoll-Logik)
  - Dynamic Port Binding
  - Sendet READY
  - Handhabt Ping/Keepalive

**Total: ~249 Zeilen**

### 5. Multi-Connection Loop Structures & Functions (Zeilen 382-540)
- `GoSignal` struct (Zeilen 382-385) - 4 Zeilen
- `receive_peer_info_for_connection()` (Zeilen 387-432) - 46 Zeilen
- `receive_go_for_connection()` (Zeilen 434-466) - 33 Zeilen
- `establish_multi_connections()` (Zeilen 468-605) - 138 Zeilen

**Total: ~221 Zeilen**

### 6. Run Functions (Zeilen 607-795)
- `run_sender()` (Zeilen 607-690) - 84 Zeilen
- `run_receiver()` (Zeilen 692-775) - 84 Zeilen
- `run_probe_debug()` (Zeilen 777-783) - 7 Zeilen
- `main()` (Zeilen 785-829) - 45 Zeilen

**Total: ~220 Zeilen**

---

## 🎯 ZIEL-STRUKTUR (3 neue Module)

### MODULE 1: `src/relay.rs` (~330 Zeilen)
**Verantwortlichkeit:** Relay-Server-Kommunikation, Socket-Management, NAT Probing

**Inhalt:**
1. **Session Struct** (aktuell Zeilen 30-51)
   - Alle Felder 1:1 kopieren
   - Keine Änderungen an der Struktur

2. **Utility Functions** (aktuell Zeilen 53-129)
   - `parse_host_port()`
   - `resolve_host_port()`
   - `resolve_socket_addr()`
   - `do_nat_probing()`
   - `get_free_port()`
   - `create_bound_socket()`
   - `compute_punch_task_count()`

3. **Relay Protocol Function** (aktuell Zeilen 131-380)
   - `run_relay_protocol()`
   - KEINE ÄNDERUNGEN an der Logik!

**Exports:**
```rust
pub use Session;
pub use run_relay_protocol;
pub use get_free_port;
pub use create_bound_socket;
pub use compute_punch_task_count;
```

**Imports (neu benötigt):**
```rust
use std::net::{SocketAddr, ToSocketAddrs};
use std::time::Duration;
use tokio::io::{AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use socket2::{Socket, Domain, Type, Protocol, SockAddr};
use anyhow::{Result, anyhow};
use tracing::{info, error, warn, debug};

use crate::protocol::{RegisterMessage, RelayMessage, ProbeMessage, AddPortsMessage};
use crate::cli::PredictionMode;
```

---

### MODULE 2: `src/connection.rs` (~240 Zeilen)
**Verantwortlichkeit:** Multi-Connection-Logik, Peer-Info-Empfang, GO-Signal-Handling

**Inhalt:**
1. **GoSignal Struct** (aktuell Zeilen 382-385)
   ```rust
   pub struct GoSignal {
       pub start_at: f64,
   }
   ```

2. **receive_peer_info_for_connection()** (aktuell Zeilen 387-432)
   - KEINE ÄNDERUNGEN an der Logik

3. **receive_go_for_connection()** (aktuell Zeilen 434-466)
   - KEINE ÄNDERUNGEN an der Logik

4. **establish_multi_connections()** (aktuell Zeilen 468-605)
   - KEINE ÄNDERUNGEN an der Logik
   - Import `Session` von `crate::relay`

**Exports:**
```rust
pub use GoSignal;
pub use receive_peer_info_for_connection;
pub use receive_go_for_connection;
pub use establish_multi_connections;
```

**Imports (neu benötigt):**
```rust
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use anyhow::{Result, anyhow};
use tracing::{info, error, warn, debug};

use crate::protocol::RelayMessage;
use crate::punch::{punch_connection_with_strategy, PeerInfo, current_timestamp};
use crate::relay::{Session, create_bound_socket};
```

---

### MODULE 3: `src/main.rs` (REDUZIERT auf ~240 Zeilen)
**Verantwortlichkeit:** Haupt-Run-Funktionen, Entry-Point

**Inhalt:**
1. **Imports & Module Declarations**
   ```rust
   use std::time::Duration;
   use clap::Parser;
   use anyhow::{Result, anyhow};
   use tracing::{info, error, Level};
   use tracing_subscriber::FmtSubscriber;
   
   mod cli;
   mod protocol;
   mod punch;
   mod transfer;
   mod relay;      // NEU!
   mod connection; // NEU!
   
   use cli::{Args, Mode, PredictionMode, parse_chunk_size, APP_VERSION};
   use relay::{Session, run_relay_protocol, get_free_port, create_bound_socket, compute_punch_task_count};
   use connection::establish_multi_connections;
   use transfer::{
       TcpSender,
       TcpReceiver,
       calculate_sha256,
       set_chunk_size,
       run_multi_sender,
       run_multi_receiver,
   };
   ```

2. **run_sender()** (aktuell Zeilen 607-690)
   - Bleibt UNVERÄNDERT
   - Nutzt `relay::` und `connection::` Imports

3. **run_receiver()** (aktuell Zeilen 692-775)
   - Bleibt UNVERÄNDERT
   - Nutzt `relay::` und `connection::` Imports

4. **run_probe_debug()** (aktuell Zeilen 777-783)
   - Bleibt UNVERÄNDERT

5. **main()** (aktuell Zeilen 785-829)
   - Bleibt UNVERÄNDERT

---

## 🔧 IMPLEMENTIERUNGSSCHRITTE

### SCHRITT 1: `src/relay.rs` erstellen (~10 Min)

1. **Datei erstellen:**
   ```bash
   # Neue Datei: src/relay.rs
   ```

2. **Header & Imports hinzufügen:**
   ```rust
   //! Relay Server Communication Module
   //!
   //! Handles connection to relay server, NAT probing, and session management.
   
   use std::net::{SocketAddr, ToSocketAddrs};
   use std::time::Duration;
   use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
   use tokio::net::TcpStream;
   use socket2::{Socket, Domain, Type, Protocol, SockAddr};
   use anyhow::{Result, anyhow};
   use tracing::{info, error, warn, debug};
   
   use crate::protocol::{RegisterMessage, RelayMessage, ProbeMessage, AddPortsMessage};
   use crate::cli::PredictionMode;
   ```

3. **Session Struct kopieren** (aus main.rs Zeilen 30-51):
   - Einfach 1:1 kopieren mit `pub` Modifier
   - Markierung hinzufügen: `pub struct Session {`

4. **Utility Functions kopieren** (aus main.rs Zeilen 53-129):
   - `fn parse_host_port()` → `pub fn parse_host_port()`
   - `fn resolve_host_port()` → `pub fn resolve_host_port()`
   - `fn resolve_socket_addr()` → `pub fn resolve_socket_addr()`
   - `async fn do_nat_probing()` → `pub async fn do_nat_probing()`
   - `fn get_free_port()` → `pub fn get_free_port()`
   - `fn create_bound_socket()` → `pub fn create_bound_socket()`
   - `fn compute_punch_task_count()` → `pub fn compute_punch_task_count()`

5. **run_relay_protocol() kopieren** (aus main.rs Zeilen 131-380):
   - `async fn run_relay_protocol()` → `pub async fn run_relay_protocol()`
   - Alle Zeilen 1:1 kopieren
   - WICHTIG: Keine Änderungen an der Logik!

**Erwartete Zeilen:** ~330 Zeilen

---

### SCHRITT 2: `src/connection.rs` erstellen (~8 Min)

1. **Datei erstellen:**
   ```bash
   # Neue Datei: src/connection.rs
   ```

2. **Header & Imports hinzufügen:**
   ```rust
   //! Multi-Connection Management Module
   //!
   //! Handles establishing multiple TCP connections through coordinated hole punching cycles.
   
   use std::net::SocketAddr;
   use std::time::Duration;
   use tokio::io::{AsyncWriteExt, BufReader};
   use tokio::net::TcpStream;
   use anyhow::{Result, anyhow};
   use tracing::{info, error, warn, debug};
   
   use crate::protocol::RelayMessage;
   use crate::punch::{punch_connection_with_strategy, PeerInfo, current_timestamp};
   use crate::relay::{Session, create_bound_socket};
   ```

3. **GoSignal Struct kopieren** (aus main.rs Zeilen 382-385):
   ```rust
   /// GO Signal mit Zeitstempel
   pub struct GoSignal {
       pub start_at: f64,
   }
   ```

4. **receive_peer_info_for_connection() kopieren** (aus main.rs Zeilen 387-432):
   - `async fn receive_peer_info_for_connection()` → `pub async fn receive_peer_info_for_connection()`
   - Alle Zeilen 1:1 kopieren

5. **receive_go_for_connection() kopieren** (aus main.rs Zeilen 434-466):
   - `async fn receive_go_for_connection()` → `pub async fn receive_go_for_connection()`
   - Alle Zeilen 1:1 kopieren

6. **establish_multi_connections() kopieren** (aus main.rs Zeilen 468-605):
   - `async fn establish_multi_connections()` → `pub async fn establish_multi_connections()`
   - WICHTIG: Parameter `session: &mut Session` - Session kommt jetzt von `crate::relay`
   - WICHTIG: `create_bound_socket()` wird von `crate::relay` importiert
   - Alle Zeilen 1:1 kopieren

**Erwartete Zeilen:** ~240 Zeilen

---

### SCHRITT 3: `src/main.rs` refactoren (~7 Min)

1. **LÖSCHEN:**
   - Zeilen 30-605 (Session struct, Utility Functions, Relay Protocol, Multi-Connection Functions)
   - Das sind ~575 Zeilen die gelöscht werden!

2. **Imports aktualisieren** (Zeilen 1-28):
   - Hinzufügen:
     ```rust
     mod relay;
     mod connection;
     ```
   - Importieren:
     ```rust
     use relay::{run_relay_protocol, get_free_port, create_bound_socket, compute_punch_task_count};
     use connection::establish_multi_connections;
     ```

3. **run_sender() anpassen** (aktuell Zeilen 607-690):
   - Funktion bleibt UNVERÄNDERT
   - Imports werden automatisch durch neue `use`-Statements gefunden

4. **run_receiver() anpassen** (aktuell Zeilen 692-775):
   - Funktion bleibt UNVERÄNDERT
   - Imports werden automatisch durch neue `use`-Statements gefunden

5. **run_probe_debug() anpassen** (aktuell Zeilen 777-783):
   - Muss `relay::resolve_socket_addr` nutzen, wenn es das verwendet
   - Sonst UNVERÄNDERT

6. **main() bleibt UNVERÄNDERT** (aktuell Zeilen 785-829)

**Erwartete Zeilen:** ~240 Zeilen (von 795!)

---

### SCHRITT 4: Cargo.toml Module Registration (~1 Min)

**WICHTIG:** Rust erkennt neue Module automatisch durch `mod relay;` und `mod connection;` Statements in main.rs. Keine Änderungen an Cargo.toml nötig!

---

### SCHRITT 5: Testing & Validation (~5 Min)

1. **Cargo Check:**
   ```bash
   cargo check
   ```
   - Erwartung: KEINE Fehler
   - Möglicherweise warnings wegen unused imports (können ignoriert werden)

2. **Cargo Build:**
   ```bash
   cargo build --release
   ```
   - Erwartung: Erfolgreiche Compilation

3. **Functionality Test:**
   ```bash
   # Test Sender
   tcp-transfer-ice.exe --server mozz.top:9999 --mode send --file testfile.txt --session-id test123
   
   # Test Receiver
   tcp-transfer-ice.exe --server mozz.top:9999 --mode receive --session-id test123
   ```

4. **Lines of Code Check:**
   ```bash
   powershell -ExecutionPolicy Bypass -File .\count_lines.ps1
   ```
   - Erwartung:
     - `src/main.rs`: ~240 Zeilen (war 795!)
     - `src/relay.rs`: ~330 Zeilen
     - `src/connection.rs`: ~240 Zeilen
     - **Total:** ~810 Zeilen (war 795 in einer Datei)

---

## ⚠️ WICHTIGE HINWEISE

### 1. **Session Struct Visibility**
- `Session` ist jetzt in `relay.rs` mit `pub struct Session { ... }`
- Alle Felder müssen `pub` sein, damit `connection.rs` darauf zugreifen kann:
  ```rust
  pub struct Session {
      pub peer_public_addr: Option<SocketAddr>,
      pub peer_addresses: Vec<protocol::relay::PeerAddressInfo>,
      // ... alle anderen Felder auch pub
  }
  ```

### 2. **Import Paths in connection.rs**
- `Session` kommt von `crate::relay`
- `create_bound_socket` kommt von `crate::relay`
- `PeerInfo`, `punch_connection_with_strategy`, `current_timestamp` kommen von `crate::punch`

### 3. **Import Paths in main.rs**
- Alle Relay-Funktionen kommen von `relay::`
- Alle Connection-Funktionen kommen von `connection::`
- `run_sender()` und `run_receiver()` müssen `relay::` und `connection::` Prefixes nutzen

### 4. **Keine Logik-Änderungen!**
- Alle Funktionen werden 1:1 kopiert
- Nur `pub` Modifier hinzufügen wo nötig
- Keine Änderungen an der Funktionslogik
- Keine Änderungen an Parametern oder Return-Typen

### 5. **Compilation Reihenfolge**
- Rust kompiliert Module in der Reihenfolge ihrer Dependencies
- `relay.rs` hat keine internen Dependencies (nur externe Crates)
- `connection.rs` hängt von `relay` ab
- `main.rs` hängt von beiden ab
- → Automatisch korrekt durch Rust-Compiler

---

## 📋 CHECKLISTE FÜR IMPLEMENTIERUNG

### Vor dem Start:
- [ ] Git Status prüfen - sicherstellen, dass working directory clean ist
- [ ] Backup erstellen (git branch oder commit)
- [ ] Context Window in neuer Session bei 0% starten

### Während der Implementierung:
- [ ] `src/relay.rs` erstellt
- [ ] Session Struct nach relay.rs kopiert (mit `pub`)
- [ ] Utility Functions nach relay.rs kopiert (mit `pub`)
- [ ] run_relay_protocol() nach relay.rs kopiert (mit `pub`)
- [ ] `src/connection.rs` erstellt
- [ ] GoSignal Struct nach connection.rs kopiert (mit `pub`)
- [ ] receive_peer_info_for_connection() nach connection.rs kopiert (mit `pub`)
- [ ] receive_go_for_connection() nach connection.rs kopiert (mit `pub`)
- [ ] establish_multi_connections() nach connection.rs kopiert (mit `pub`)
- [ ] `src/main.rs` refactored
- [ ] Zeilen 30-605 aus main.rs gelöscht
- [ ] Module declarations in main.rs hinzugefügt (`mod relay;`, `mod connection;`)
- [ ] Imports in main.rs aktualisiert

### Nach der Implementierung:
- [ ] `cargo check` erfolgreich
- [ ] `cargo build --release` erfolgreich
- [ ] Lines of Code Check durchgeführt
- [ ] Functionality Test erfolgreich
- [ ] Git commit mit Message: "Refactor: Split main.rs into relay and connection modules"
- [ ] Git push

---

## 🎯 ERWARTETES ERGEBNIS

### Vor Refactoring:
```
src/main.rs: 795 Zeilen
```

### Nach Refactoring:
```
src/relay.rs: ~330 Zeilen
src/connection.rs: ~240 Zeilen
src/main.rs: ~240 Zeilen
-----------------------------
Total: ~810 Zeilen (15 mehr, aber viel besser strukturiert!)
```

### Vorteile:
1. ✅ **main.rs von 795 → 240 Zeilen** (70% Reduktion!)
2. ✅ **Keine Datei über 400 Zeilen** (LLM-freundlich)
3. ✅ **Klare Modul-Verantwortlichkeiten**
4. ✅ **Bessere Code-Navigation**
5. ✅ **Einfacheres Testing einzelner Module**
6. ✅ **KEINE Funktionale Änderungen** (1:1 Copy)

---

## 🚨 TROUBLESHOOTING

### Problem: "cannot find type `Session` in this scope"
**Lösung:** In connection.rs fehlt der Import: `use crate::relay::Session;`

### Problem: "cannot find function `create_bound_socket` in this scope"
**Lösung:** In connection.rs fehlt der Import: `use crate::relay::create_bound_socket;`

### Problem: "private field `bound_sockets` of struct `Session`"
**Lösung:** Alle Felder in `Session` struct müssen `pub` sein

### Problem: Compilation dauert sehr lange
**Lösung:** Normal bei großen Refactorings - Rust prüft alle Dependencies neu

### Problem: "unused import" warnings
**Lösung:** Ignorieren oder mit `#[allow(unused_imports)]` supprimieren

---

## 📝 COMMIT MESSAGE TEMPLATE

```
Refactor: Split main.rs into relay and connection modules

- Created src/relay.rs (330 lines)
  * Session struct and relay server communication
  * Utility functions for socket management
  * NAT probing logic
  
- Created src/connection.rs (240 lines)
  * Multi-connection establishment logic
  * Peer info and GO signal handling
  
- Reduced src/main.rs from 795 to 240 lines (70% reduction)
  * Kept only run_sender, run_receiver, and main functions
  * Updated imports to use new modules

No functional changes - pure code organization improvement.
```

---

**Ende des Refactoring Plans**

Viel Erfolg bei der Implementierung in der frischen Session! 🚀