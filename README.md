# Status trailing-byte log amplification (MC-271325)

Unauthenticated clients can make vanilla and Fabric Minecraft servers write large stack traces to `latest.log` by sending a valid status handshake followed by a malformed status packet, taking up CPU cycles and memory, as well as writing gig+ log files.

Minecraft bug report: [MC-271325](https://bugs.mojang.com/browse/MC-271325)   
---

## What happens

1. The client opens TCP and sends a normal handshake with `next state = STATUS` (1).
2. It sends a malformed status request:
   - Primary trigger: packet id `0` (status request) plus one extra `0x00` byte → on-wire frame `02 00 00`.
   - Alternate: packet id `1` (not valid serverbound in status) → frame `01 01`.
3. The server’s decoder rejects the packet (unread bytes or unknown id).
4. `Connection.exceptionCaught` tries to send `clientbound/minecraft:disconnect` while the connection is still on the status protocol, where that packet is not registered.
5. Netty throws again:

   ```text
   io.netty.handler.codec.EncoderException: Sending unknown packet 'clientbound/minecraft:disconnect'
   ```

   That second exception is what fills the log (~50 lines per bad request in local testing).

Paper 1.21.11-69 adds a guard in `Connection.exceptionCaught` so disconnect is not sent during `HANDSHAKING` / `STATUS`, which stops the amplification in our repros. Fabric on 26.1.2 behaves like vanilla.

---

## Affected builds (local testing)

| Server | Version tested | Log amplification |
|--------|----------------|-------------------|
| Vanilla | 26.1.2 | Yes |
| Fabric | 26.1.2 + loader 0.19.2 | Yes |
| Paper | 1.21.11-69 | No (in tests) |

---

## Minimal payloads

After handshake to status state:

| Variant | Hex (frame) | Meaning |
|---------|-------------|---------|
| Trailing null | `02 00 00` | Length 2, packet id 0, extra byte |
| Unknown packet | `01 01` | Length 1, packet id 1 |

The PoC builds these with the same framing as a real client (length-prefixed varint packet id).

---

## How to run the PoC

From the repo root, against any listening server:

```powershell
python poc.py 127.0.0.1 25565 --count 10
```

Useful flags:

| Flag | Purpose |
|------|---------|
| `--protocol N` | Force handshake protocol (skip auto-detect) |
| `--no-auto-protocol` | Don’t status-ping first; use default 774 |
| `--handshake-host NAME` | Virtual host for proxies (BungeeCord / Velocity) |
| `--variant trailing_nul` | Default 3-byte trigger |
| `--variant unknown_packet` | Alternate 2-byte trigger |
| `--threads N` | Parallel connections |
| `--count N` | Number of connections |
| `-q` | Summary only |

Auto-probe (default) runs a legitimate status ping to learn the server’s protocol and version name.

---

## What to look for

Do not rely on the PoC printing `tcp_ok=True`. The TCP session can complete while the server logs the damage.

On the server, grep `latest.log` for:

- `EncoderException`
- `Sending unknown packet 'clientbound/minecraft:disconnect'`
- Stack frames under `Connection.exceptionCaught` / `LegacyQueryHandler.channelRead`

Example counts from packaged repro (`working-pocs/evidence/status-trailing-byte/repro-results.json`):

- Vanilla / Fabric: 10 attempts → ~500 new log lines, 10 `EncoderException`s, ~480 stack trace lines; server process still alive.

Stress (250 requests in ~5 s on vanilla/Fabric): on the order of 12k log lines and ~1.1 MB log growth locally.

---

## Root cause (short)

Strict decode of status request id `0` → exception path → disconnect packet encoded on wrong protocol state → second exception logged at full stack depth. Paper avoids sending disconnect in that state.

---

## Ethics

Use only on systems you own or are explicitly authorized to test. The script is for confirming [MC-271325](https://bugs.mojang.com/browse/MC-271325) and defensive patching, not for disrupting public servers.
