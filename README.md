# remko-smartweb-poc

Proof‑of‑Concept to control REMKO devices via the smartweb.remko.media cloud (MQTT over WebSockets).

**Status:** PoC. Not affiliated with REMKO. Use at your own risk.

## Quick start
```bash
# 1) Read status
REMKO_DEVICE_NAME="YOUR DEVICE NAME" REMKO_ESP_STATUS=1 REMKO_READ_SUMMARY=1 python remko_probe.py

# 2) Turn ON
REMKO_DEVICE_NAME="YOUR DEVICE NAME" REMKO_TX_HEX="AA24AC00000000000302404341667F7F003000000000000000000000000000000000006073" REMKO_NO_RESPONSE_OK=1 python remko_probe.py

# 3) Turn OFF
REMKO_DEVICE_NAME="YOUR DEVICE NAME" REMKO_TX_HEX="AA24AC00000000000302404241667F7F00300000000000000000000000000000000000CD07" REMKO_NO_RESPONSE_OK=1 python remko_probe.py

# 4) Set mode/temperature/fan and read back
REMKO_DEVICE_NAME="YOUR DEVICE NAME" REMKO_ESP_STATUS=1 REMKO_SET_POWER=on REMKO_SET_MODE=cool REMKO_SETPOINT=22.0 REMKO_SET_FAN=medium REMKO_SET_SWING=vertical REMKO_READBACK_AFTER_SET=1 python remko_probe.py
```

## What this does
- Logs into the REMKO SmartWeb portal
- Resolves device IDs (by name) from `/rest/liste`
- Connects to the cloud MQTT broker
- Sends a UART frame to the WiFi‑stick (`/ESP` topic) to toggle power

This was built as a minimal starting point for later Home Assistant integration.

## Requirements
- Python 3.10+
- `pip`

## Install
```bash
python -m pip install requests paho-mqtt python-dotenv
```

## Setup
Create a `.env` file (see `.env.example`) or export the variables:

```bash
export REMKO_EMAIL="your@email"
export REMKO_PASS="yourPassword"
```

## Usage
### Read status values (power, setpoint, room, mode, fan, swing, eco, turbo, sleep, outdoor, error)
```bash
REMKO_DEVICE_NAME="YOUR DEVICE NAME" \
REMKO_ESP_STATUS=1 \
REMKO_READ_SUMMARY=1 \
python remko_probe.py
```

### Set values (mode / setpoint / fan / swing / eco / turbo / sleep / bioclean)
```bash
REMKO_DEVICE_NAME="YOUR DEVICE NAME" \
REMKO_ESP_STATUS=1 \
REMKO_SET_POWER=on \
REMKO_SET_MODE=cool \
REMKO_SETPOINT=22.0 \
REMKO_SET_FAN=medium \
REMKO_SET_SWING=vertical \
REMKO_SET_ECO=off \
REMKO_SET_TURBO=off \
REMKO_SET_SLEEP=off \
REMKO_SET_BIOCLEAN=off \
python remko_probe.py
```
Note: The SET frame uses defaults for timer bytes, which may reset active timers.

### Turn ON (example)
```bash
REMKO_DEVICE_NAME="YOUR DEVICE NAME" \
REMKO_TX_HEX="AA24AC00000000000302404341667F7F003000000000000000000000000000000000006073" \
REMKO_NO_RESPONSE_OK=1 \
python remko_probe.py
```

### Turn OFF (example)
```bash
REMKO_DEVICE_NAME="YOUR DEVICE NAME" \
REMKO_TX_HEX="AA24AC00000000000302404241667F7F00300000000000000000000000000000000000CD07" \
REMKO_NO_RESPONSE_OK=1 \
python remko_probe.py
```

### Notes
- `REMKO_TX_HEX` is a UART frame captured from the Web UI (WebSocket → MQTT frames).
- The frame **can be device/model specific**. Capture your own frame:
  - DevTools → Network → WS → MQTT connection → power toggle
  - Copy the JSON sent to `.../ESP` and use the `Tx` field.
- Some devices do not send a response after writes; use `REMKO_NO_RESPONSE_OK=1`.

## Environment variables
- `REMKO_EMAIL`, `REMKO_PASS` — SmartWeb login
- `REMKO_DEVICE_NAME` — exact device name from the list
- `REMKO_ESP_STATUS=1` — send UART status request via `/ESP`
- `REMKO_READ_SUMMARY=1` — print decoded status values
- `REMKO_SET_POWER=on|off` — power control via SET frame
- `REMKO_SET_MODE=auto|cool|dry|heat|fan` — set mode
- `REMKO_SETPOINT=21.0` — set target temperature (Celsius)
- `REMKO_SET_FAN=auto|low|medium|high|silent` — set fan speed
- `REMKO_SET_SWING=off|vertical|horizontal|both` — set swing
- `REMKO_SET_ECO=on|off` — eco mode
- `REMKO_SET_TURBO=on|off` — turbo mode
- `REMKO_SET_SLEEP=on|off` — sleep mode
- `REMKO_SET_BIOCLEAN=on|off` — bioclean/ion
- `REMKO_READBACK_AFTER_SET=1` — request fresh status after SET and print summary
- `REMKO_TX_HEX` — UART frame to send to `/ESP`
- `REMKO_TX_CLIENT_ID` — defaults to `SMTACUARTTEST`
- `REMKO_NO_RESPONSE_OK=1` — do not error if no MQTT response arrives
- `REMKO_TIMEOUT_SEC`, `REMKO_CONNECT_TIMEOUT_SEC` — optional tuning

## Disclaimer
This is a proof‑of‑concept for interoperability. It is unofficial and may break if REMKO changes the backend.
