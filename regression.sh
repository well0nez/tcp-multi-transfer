#!/bin/bash
# Regressionsprobe auf Loopback. Nach jeder Umbaustufe laufen lassen.
#
# Deckt ab: Einzelstrom, Mehrstrom (2 und 4), ungleiche --chunk-Werte,
# abgelehnte Doppelregistrierung, Streckenmessung mit Zeitreihe, kleine Datei
# ueber viele Stroeme. Kein Netz ausser 127.0.0.1.
set -u

# Ortsunabhaengig, damit die CI dasselbe Skript fahren kann wie der Arbeitsplatz.
# Reihenfolge: ausdrueckliche Angabe, dann der frisch gebaute Stand im Repo,
# dann der Arbeitsplatz-Pfad (dort wird ausserhalb des Repos gebaut).
REPO="${TMT_REPO:-$(cd "$(dirname "$0")" && pwd)}"
if [ -n "${TMT_BIN:-}" ]; then
  BIN="$TMT_BIN"
elif [ -x "$REPO/target/release/tcp-multi-transfer" ]; then
  BIN="$REPO/target/release/tcp-multi-transfer"
else
  BIN=/home/user/migration/tmt-neu
fi
if [ ! -x "$BIN" ]; then
  echo "Kein Binary gefunden. Erwartet unter \$TMT_BIN oder $REPO/target/release/tcp-multi-transfer." >&2
  echo "Erst bauen: cargo build --release" >&2
  exit 2
fi
echo "Binary: $BIN"
DIR=$(mktemp -d /tmp/tmt-regression-XXXXXX)
PORT="${TMT_PORT:-19871}"
FEHLER=0

melde() { # $1 = Name, $2 = ok|fehler, $3 = Details
  if [ "$2" = "ok" ]; then printf "  \033[32m✓\033[0m %-42s %s\n" "$1" "${3:-}"
  else printf "  \033[31m✗\033[0m %-42s %s\n" "$1" "${3:-}"; FEHLER=$((FEHLER+1)); fi
}

cd "$REPO" || exit 1
echo "== Python-Tests =="
if python3 -m unittest discover -s tests > "$DIR/tests.log" 2>&1; then
  melde "unittest" ok "$(tail -3 "$DIR/tests.log" | head -1)"
else
  melde "unittest" fehler "$(tail -5 "$DIR/tests.log" | tr '\n' ' ')"
fi

echo "== Relay starten =="
setsid nohup python3 run_server.py --port $PORT --probe-port $((PORT-1)) \
  --probe-port2 $((PORT-2)) > "$DIR/relay.log" 2>&1 < /dev/null &
sleep 2
RELAY=$(ps -eo pid,args | grep -F "server.main --port $PORT" | grep -v grep | awk '{print $1}' | head -1)
[ -n "$RELAY" ] && melde "Relay laeuft" ok "PID $RELAY" || { melde "Relay laeuft" fehler; exit 1; }

lauf() { # $1 Name, $2 Sessionsuffix, $3 Sender-Flags, $4 Empfaenger-Flags, $5 Datei
  local NAME="$1" SID="reg-$2-$RANDOM" SF="$3" EF="$4" F="$5"
  rm -rf "$DIR/rx"; mkdir -p "$DIR/rx"
  ( cd "$DIR/rx" && timeout 180 $BIN -s 127.0.0.1:$PORT -i "$SID" -m receive $EF \
      > "$DIR/$2.rx.log" 2>&1 ) &
  local RX=$!
  sleep 1
  timeout 180 $BIN -s 127.0.0.1:$PORT -i "$SID" -m send -f "$F" $SF > "$DIR/$2.tx.log" 2>&1
  local SR=$?
  wait $RX; local ER=$?
  if [ $SR -eq 0 ] && [ $ER -eq 0 ] && cmp -s "$F" "$DIR/rx/$(basename "$F")"; then
    melde "$NAME" ok
  else
    melde "$NAME" fehler "sender=$SR empfaenger=$ER $(grep -ah 'Error' "$DIR/$2.tx.log" "$DIR/$2.rx.log" | head -1)"
  fi
}

head -c 4194304 /dev/urandom > "$DIR/gross.bin"
head -c 1048576 /dev/urandom > "$DIR/klein.bin"

echo "== Transfers =="
lauf "Einzelstrom"                    s1 ""                    ""                    "$DIR/gross.bin"
lauf "zwei Stroeme"                   s2 "--tcp-connections 2" "--tcp-connections 2" "$DIR/gross.bin"
lauf "vier Stroeme"                   s4 "--tcp-connections 4" "--tcp-connections 4" "$DIR/gross.bin"
lauf "ungleiches --chunk"             sc "--tcp-connections 2 --chunk 1MB" "--tcp-connections 2 --chunk 8MB" "$DIR/gross.bin"
lauf "kleine Datei, vier Stroeme"     sk "--tcp-connections 4" "--tcp-connections 4" "$DIR/klein.bin"
lauf "kleines Grace-Fenster"          sg "--grace-ms 20"       "--grace-ms 20"       "$DIR/gross.bin"

echo "== Sonderfaelle =="
# Abgelehnte Doppelregistrierung darf die Sitzung nicht abraeumen
rm -rf "$DIR/rx"; mkdir -p "$DIR/rx"
SID="reg-dup-$RANDOM"
( cd "$DIR/rx" && timeout 180 $BIN -s 127.0.0.1:$PORT -i "$SID" -m receive > "$DIR/dup.rx.log" 2>&1 ) &
RX=$!
sleep 2
$BIN -s 127.0.0.1:$PORT -i "$SID" -m receive > "$DIR/dup2.log" 2>&1
grep -q "already taken" "$DIR/dup2.log" && A=ok || A=fehler
melde "Doppelstart wird abgelehnt" $A
timeout 180 $BIN -s 127.0.0.1:$PORT -i "$SID" -m send -f "$DIR/gross.bin" > "$DIR/dup.tx.log" 2>&1
SR=$?; wait $RX
[ $SR -eq 0 ] && cmp -s "$DIR/gross.bin" "$DIR/rx/gross.bin" && melde "Sitzung ueberlebt den Doppelstart" ok \
  || melde "Sitzung ueberlebt den Doppelstart" fehler "sender=$SR"

# Streckenmessung liefert eine Zeitreihe
rm -rf "$DIR/rx"; mkdir -p "$DIR/rx"
SID="reg-bench-$RANDOM"
( cd "$DIR/rx" && timeout 180 $BIN -s 127.0.0.1:$PORT -i "$SID" -m receive --bench 512 \
    --bench-sample-ms 1 --metrics-file "$DIR/bench.jsonl" > "$DIR/bench.rx.log" 2>&1 ) &
RX=$!
sleep 1
timeout 180 $BIN -s 127.0.0.1:$PORT -i "$SID" -m send --bench 512 --bench-sample-ms 1 \
  > "$DIR/bench.tx.log" 2>&1
wait $RX
N=$(python3 -c "
import json
for l in open('$DIR/bench.jsonl'):
    d=json.loads(l)
    if d.get('record')=='bench': print(len(d['samples'])); break
" 2>/dev/null || echo 0)
[ "${N:-0}" -gt 0 ] && melde "Streckenmessung mit Zeitreihe" ok "$N Abtastwerte" \
  || melde "Streckenmessung mit Zeitreihe" fehler "leer"

# --chunk 0 wird abgewiesen
$BIN -s 127.0.0.1:$PORT -i x -m send -f "$DIR/klein.bin" --chunk 0 > "$DIR/chunk0.log" 2>&1
grep -q "at least" "$DIR/chunk0.log" && melde "--chunk 0 abgewiesen" ok || melde "--chunk 0 abgewiesen" fehler

kill "$RELAY" 2>/dev/null
sleep 1
echo
if [ $FEHLER -eq 0 ]; then echo "Alles gruen. ($DIR)"; rm -rf "$DIR"; else
  echo "$FEHLER Fehler. Logs unter $DIR"; fi
exit $FEHLER
