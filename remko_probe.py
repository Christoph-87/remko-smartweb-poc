from dotenv import load_dotenv
load_dotenv()

import os
import re
import ssl
import time
import threading
import json
import random
import requests

from urllib.parse import urljoin, urlparse, parse_qs

import paho.mqtt.client as mqtt


# ---------------------------------------------------------------------
# Konfiguration
# ---------------------------------------------------------------------

BASE = "https://smartweb.remko.media"
LOGIN_URL = f"{BASE}/rest/login_do"

WSS_HOST = "smartweb.remko.media"
WSS_PORT = 8083
WSS_PATH = "/mqtt"

VERSION = "V04P27"   # bei dir aktuell korrekt

# Kurzbeispiel (Dachgeschoss ON/OFF via /ESP-Frames):
#   REMKO_DEVICE_NAME="WIFI Stick - Schlafzimmer Dachgeschoss" \
#   REMKO_TX_HEX="AA24AC00000000000302404341667F7F003000000000000000000000000000000000006073" \
#   REMKO_NO_RESPONSE_OK=1 python remko_probe.py
#
#   REMKO_DEVICE_NAME="WIFI Stick - Schlafzimmer Dachgeschoss" \
#   REMKO_TX_HEX="AA24AC00000000000302404241667F7F00300000000000000000000000000000000000CD07" \
#   REMKO_NO_RESPONSE_OK=1 python remko_probe.py

EMAIL = os.environ.get("REMKO_EMAIL")
PASSWORD = os.environ.get("REMKO_PASS")

# Optional overrides from browser console (global.SMT_ID, global.SMT_KEY, global.MQTT_TOPIC)
SMT_ID = os.environ.get("REMKO_SMT_ID")
SMT_KEY = os.environ.get("REMKO_SMT_KEY")
MQTT_TOPIC = os.environ.get("REMKO_MQTT_TOPIC")
DEVICE_INDEX = os.environ.get("REMKO_DEVICE_INDEX")
DEVICE_HINT = os.environ.get("REMKO_DEVICE_HINT")
DEVICE_NAME = os.environ.get("REMKO_DEVICE_NAME")
DEBUG_ENDPOINTS = os.environ.get("REMKO_DUMP_ENDPOINTS") == "1"
DEBUG_REST = os.environ.get("REMKO_DEBUG_REST") == "1"
DEBUG_REST_DUMP = os.environ.get("REMKO_DEBUG_REST_DUMP") == "1"
VALUES_JSON = os.environ.get("REMKO_VALUES_JSON")
VALUES_1194 = os.environ.get("REMKO_VALUES_1194")  # 64-Byte HEX-String (ID 1194 = Power)
TX_HEX = os.environ.get("REMKO_TX_HEX")            # UART-Frame als HEX für /ESP (falls UI keinen CLIENT2HOST sendet)
TX_CLIENT_ID = os.environ.get("REMKO_TX_CLIENT_ID") or "SMTACUARTTEST"
ALLOW_NO_RESPONSE = os.environ.get("REMKO_NO_RESPONSE_OK") == "1"  # MQTT-Antwort optional
TIMEOUT_SEC = int(os.environ.get("REMKO_TIMEOUT_SEC", "15"))
CONNECT_TIMEOUT_SEC = int(os.environ.get("REMKO_CONNECT_TIMEOUT_SEC", "8"))
CLIENT_ID_OVERRIDE = os.environ.get("REMKO_CLIENT_ID")
DEBUG_NAME_SCAN = os.environ.get("REMKO_DEBUG_NAME_SCAN") == "1"

if not EMAIL or not PASSWORD:
    raise SystemExit("Bitte REMKO_EMAIL und REMKO_PASS als env vars setzen.")


# ---------------------------------------------------------------------
# Login
# ---------------------------------------------------------------------

def login(session: requests.Session) -> None:
    r = session.post(
        LOGIN_URL,
        data={"name": EMAIL, "passwort": PASSWORD},
        headers={
            "X-Requested-With": "XMLHttpRequest",
            "Origin": BASE,
            "Referer": f"{BASE}/",
        },
        timeout=15,
    )
    r.raise_for_status()

    if "PHPSESSID" not in session.cookies.get_dict():
        raise RuntimeError("Keine PHPSESSID nach Login – Login nicht akzeptiert.")

    try:
        data = r.json()
        print("Login OK. Response keys:", list(data.keys()))
    except Exception:
        print("Login OK (non-JSON response)")


# ---------------------------------------------------------------------
# SID / SK Erkennung
# ---------------------------------------------------------------------

def _extract_sid_sk_from_url(url: str):
    qs = parse_qs(urlparse(url).query)
    sid = (qs.get("SID") or [None])[0]
    sk  = (qs.get("SK")  or [None])[0]
    if sid and sk:
        return sid.upper(), sk.upper()
    return None


def _extract_sid_sk_from_text(text: str):
    m = re.search(r"SID=([0-9A-Fa-f]{16}).*?SK=([0-9A-Fa-f]{16})", text)
    if m:
        return m.group(1).upper(), m.group(2).upper()
    return None


def _extract_smt_user_from_text(text: str):
    for pat in (
        r"SMT_USER\\s*[:=]\\s*(\\d+)",
        r"\"SMT_USER\"\\s*:\\s*(\\d+)",
        r"smt_user\\s*[:=]\\s*(\\d+)",
        r"\"smt_user\"\\s*:\\s*(\\d+)",
    ):
        m = re.search(pat, text, flags=re.I)
        if m:
            try:
                return int(m.group(1))
            except Exception:
                pass
    return None


def _extract_global_var(text: str, key: str):
    patterns = [
        rf"global\\.{key}\\s*=\\s*['\\\"]([^'\\\"]+)['\\\"]",
        rf"window\\.{key}\\s*=\\s*['\\\"]([^'\\\"]+)['\\\"]",
        rf"\\b{key}\\b\\s*:\\s*['\\\"]([^'\\\"]+)['\\\"]",
        rf"\\b{key}\\b\\s*=\\s*['\\\"]([^'\\\"]+)['\\\"]",
    ]
    for pat in patterns:
        m = re.search(pat, text)
        if m:
            return m.group(1)
    return None


def _extract_from_scripts(session: requests.Session, html: str):
    scripts = re.findall(r'<script[^>]+src="([^"]+)"', html, flags=re.I)
    values = {
        "SMT_ID": None,
        "SMT_KEY": None,
        "SMT_USER": None,
        "SMT_GID": None,
        "SMT_DEV": None,
        "MQTT_TOPIC": None,
        "MQTT_USERNAME": None,
        "MQTT_PASSWORD": None,
        "MQTT_CLIENTID": None,
    }
    endpoints = set()
    for src in scripts:
        if not src:
            continue
        src_abs = urljoin(BASE, src)
        try:
            r = session.get(src_abs, timeout=15)
            r.raise_for_status()
        except Exception:
            continue
        text = r.text
        for k in values.keys():
            if not values[k]:
                values[k] = _extract_global_var(text, k)
        if DEBUG_ENDPOINTS:
            for m in re.findall(r"/rest/[^\"'\\s]+", text):
                endpoints.add(m)
            for m in re.findall(r"/mqtt[^\"'\\s]*", text):
                endpoints.add(m)
        if all(values.values()):
            break
    if DEBUG_ENDPOINTS and endpoints:
        print("Gefundene Kandidaten-Endpoints:")
        for e in sorted(endpoints):
            print(" ", e)
    return values


def _scan_json_for_keys(obj, needle_set):
    hits = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            if any(n in k.upper() for n in needle_set):
                hits.append((k, v))
            hits.extend(_scan_json_for_keys(v, needle_set))
    elif isinstance(obj, list):
        for v in obj:
            hits.extend(_scan_json_for_keys(v, needle_set))
    return hits


def _pick_device(devices):
    if not devices:
        return None
    if DEVICE_INDEX is not None:
        try:
            idx = int(DEVICE_INDEX)
            if idx < 0 or idx >= len(devices):
                raise ValueError
            return devices[idx]
        except Exception:
            raise RuntimeError(f"REMKO_DEVICE_INDEX out of range: {DEVICE_INDEX} (0..{len(devices)-1})")
    if DEVICE_HINT:
        hint = DEVICE_HINT.lower()
        for d in devices:
            if hint in (d.get("link") or "").lower():
                return d
    if DEVICE_NAME:
        hint = DEVICE_NAME.lower()
        for d in devices:
            if hint in (d.get("name") or "").lower():
                return d
    if len(devices) == 1:
        return devices[0]
    return None


def _extract_names_from_rest_list(html: str):
    name_map = {}
    if not html:
        return name_map
    for m in re.finditer(r'href="(/geraet/fernbedienung/[0-9a-f]{32})"', html, flags=re.I):
        rel = m.group(1)
        if rel in name_map:
            continue
        tail = html[m.end(): m.end() + 600]
        m2 = re.search(r"<span[^>]*>([^<]{1,200})</span>", tail, flags=re.I)
        if m2:
            name_map[rel] = m2.group(1).strip()
    return name_map


def find_devices(session: requests.Session):
    # Geräteübersicht laden
    r = session.get(f"{BASE}/", timeout=15)
    r.raise_for_status()
    html = r.text

    # Fernbedienungs-Links extrahieren
    links = re.findall(
        r'href="(/geraet/fernbedienung/[0-9a-f]{32})"',
        html,
        flags=re.I
    )
    links = list(dict.fromkeys(links))

    if not links:
        raise RuntimeError("Keine /geraet/fernbedienung/... Links gefunden.")

    # Grobe Namenszuordnung aus der Übersichtsseite
    name_map = {}
    for m in re.finditer(r'href="(/geraet/fernbedienung/[0-9a-f]{32})"[^>]*>([^<]{1,120})</a>', html, flags=re.I):
        name_map[m.group(1)] = m.group(2).strip()
    for m in re.finditer(r'href="(/geraet/fernbedienung/[0-9a-f]{32})"[^>]*data-name="([^"]{1,120})"', html, flags=re.I):
        name_map.setdefault(m.group(1), m.group(2).strip())
    for m in re.finditer(r'data-geraet-name="([^"]{1,120})".*?href="(/geraet/fernbedienung/[0-9a-f]{32})"', html, flags=re.I | re.S):
        name_map.setdefault(m.group(2), m.group(1).strip())
    # Heuristik: Name im nahen HTML-Umfeld des Links (z.B. <span>Gerätename</span>)
    for rel in links:
        if rel in name_map:
            continue
        idx = html.find(rel)
        if idx == -1:
            continue
        window = html[max(0, idx - 400): idx + 600]
        m = re.search(r"<span[^>]*>([^<]{1,120})</span>", window, flags=re.I)
        if m:
            name_map[rel] = m.group(1).strip()

    # Zusatz: Namen aus /rest/liste (enthält die Geräteübersicht mit <span>Namensanzeige</span>)
    try:
        r_list = session.get(f"{BASE}/rest/liste", timeout=15)
        r_list.raise_for_status()
        rest_names = _extract_names_from_rest_list(r_list.text)
        for rel, name in rest_names.items():
            name_map.setdefault(rel, name)
        if not links:
            links = list(rest_names.keys())
    except Exception:
        pass
    if DEBUG_NAME_SCAN:
        print("DEBUG_NAME_SCAN matches:", len(name_map))
        for rel, name in name_map.items():
            print(" ", rel, "->", name)

    devices = []
    for rel in links:
        url = urljoin(BASE, rel)
        smt_user = None

        # 1) ohne Redirects → Location Header
        r0 = session.get(url, allow_redirects=False, timeout=15)
        loc = r0.headers.get("Location")
        if loc:
            loc_abs = urljoin(BASE, loc)
            hit = _extract_sid_sk_from_url(loc_abs) or _extract_sid_sk_from_text(loc_abs)
            if hit:
                sid, sk = hit
                devices.append(
                    {
                        "link": rel,
                        "sid": sid,
                        "sk": sk,
                        "smt_user": smt_user,
                        "where": f"SID/SK aus Location-Redirect: {loc_abs}",
                    }
                )
                continue

        # 2) mit Redirects → finale URL
        r1 = session.get(url, allow_redirects=True, timeout=15)
        hit = _extract_sid_sk_from_url(r1.url)
        smt_id = _extract_global_var(r1.text, "SMT_ID")
        smt_key = _extract_global_var(r1.text, "SMT_KEY")
        smt_user = _extract_smt_user_from_text(r1.text)
        smt_gid = _extract_global_var(r1.text, "SMT_GID")
        smt_dev = _extract_global_var(r1.text, "SMT_DEV")
        mqtt_topic = _extract_global_var(r1.text, "MQTT_TOPIC")
        mqtt_user = _extract_global_var(r1.text, "MQTT_USERNAME")
        mqtt_pass = _extract_global_var(r1.text, "MQTT_PASSWORD")
        mqtt_clientid = _extract_global_var(r1.text, "MQTT_CLIENTID")
        if not (smt_id and smt_key and mqtt_topic):
            vals = _extract_from_scripts(session, r1.text)
            smt_id = smt_id or vals["SMT_ID"]
            smt_key = smt_key or vals["SMT_KEY"]
            smt_user = smt_user or vals["SMT_USER"]
            smt_gid = smt_gid or vals["SMT_GID"]
            smt_dev = smt_dev or vals["SMT_DEV"]
            mqtt_topic = mqtt_topic or vals["MQTT_TOPIC"]
            mqtt_user = mqtt_user or vals["MQTT_USERNAME"]
            mqtt_pass = mqtt_pass or vals["MQTT_PASSWORD"]
            mqtt_clientid = mqtt_clientid or vals["MQTT_CLIENTID"]
        if DEBUG_REST:
            for ep in ("/rest/geraet_finden", "/rest/li", "/rest/codeTran"):
                try:
                    rr = session.get(urljoin(BASE, ep), timeout=15)
                except Exception:
                    continue
                print(f"DEBUG_REST {ep} status={rr.status_code}")
                try:
                    data = rr.json()
                except Exception:
                    continue
                if DEBUG_REST_DUMP:
                    print(f"DEBUG_REST {ep} keys:", list(data.keys()) if isinstance(data, dict) else type(data))
                hits = _scan_json_for_keys(data, {"SMT", "MQTT", "TOPIC", "SID", "SK"})
                if hits:
                    print("DEBUG_REST hits:", hits[:20])
        if hit:
            sid, sk = hit
            smt_user = _extract_smt_user_from_text(r1.text)
            devices.append(
                {
                    "link": rel,
                    "name": name_map.get(rel),
                    "sid": sid,
                    "sk": sk,
                    "smt_user": smt_user,
                    "smt_gid": smt_gid,
                    "smt_dev": smt_dev,
                    "smt_id": smt_id,
                    "smt_key": smt_key,
                    "mqtt_topic": mqtt_topic,
                    "mqtt_user": mqtt_user,
                    "mqtt_pass": mqtt_pass,
                    "mqtt_clientid": mqtt_clientid,
                    "where": f"SID/SK aus finaler URL: {r1.url}",
                }
            )
            continue

        # 3) HTML scannen
        hit = _extract_sid_sk_from_text(r1.text)
        if hit:
            sid, sk = hit
            devices.append(
                {
                    "link": rel,
                    "name": name_map.get(rel),
                    "sid": sid,
                    "sk": sk,
                    "smt_user": smt_user,
                    "smt_gid": smt_gid,
                    "smt_dev": smt_dev,
                    "smt_id": smt_id,
                    "smt_key": smt_key,
                    "mqtt_topic": mqtt_topic,
                    "mqtt_user": mqtt_user,
                    "mqtt_pass": mqtt_pass,
                    "mqtt_clientid": mqtt_clientid,
                    "where": "SID/SK im HTML der Fernbedienung",
                }
            )
            continue

        # 4) Kein SID/SK, aber evtl. globale MQTT-Werte vorhanden
        if smt_id or smt_key or mqtt_topic or mqtt_user or mqtt_pass or mqtt_clientid:
            devices.append(
                {
                    "link": rel,
                    "name": name_map.get(rel),
                    "sid": None,
                    "sk": None,
                    "smt_user": smt_user,
                    "smt_gid": smt_gid,
                    "smt_dev": smt_dev,
                    "smt_id": smt_id,
                    "smt_key": smt_key,
                    "mqtt_topic": mqtt_topic,
                    "mqtt_user": mqtt_user,
                    "mqtt_pass": mqtt_pass,
                    "mqtt_clientid": mqtt_clientid,
                    "where": "SMT_ID/SMT_KEY/MQTT_TOPIC aus HTML",
                }
            )
            continue

    if not devices:
        raise RuntimeError(
            "Keine Geräteinformationen gefunden.\n"
            "Wenn Werte per /rest/... XHR geladen werden → Browser Network prüfen."
        )
    return devices


# ---------------------------------------------------------------------
# MQTT Healthcheck
# ---------------------------------------------------------------------

class Healthcheck:
    def __init__(self):
        self.got_message = False
        self.last_topic = None
        self.last_payload = None
        self.connected = threading.Event()
        self.connect_rc = None
        self.disconnect_rc = None


def mqtt_healthcheck(
    sid: str | None,
    sk: str | None,
    smt_user: int = 3946,
    topic_override: str | None = None,
    user_override: str | None = None,
    pass_override: str | None = None,
    client_id_override: str | None = None,
    devid_override: str | None = None,
    timeout_sec: int = 15,
    connect_timeout_sec: int = 8,
    allow_no_response: bool = False,
):
    if topic_override:
        topic_base = topic_override
    elif sid:
        topic_base = f"{VERSION}/{sid}"
    else:
        raise RuntimeError("Kein Topic verfügbar (weder MQTT_TOPIC noch SID).")

    rnd = random.randint(0, 9999)
    if client_id_override:
        client_id = client_id_override
    else:
        base = sid or (user_override or "SMT")
        client_id = f"SMT{rnd:04d}{base}"

    hc = Healthcheck()

    def _rc_value(rc):
        return rc.value if hasattr(rc, "value") else rc

    def on_connect(client, userdata, flags, reason_code, properties=None):
        rc_val = _rc_value(reason_code)
        hc.connect_rc = rc_val
        print("MQTT on_connect rc=", rc_val)
        if rc_val != 0:
            print("MQTT connect failed rc=", rc_val)
            hc.connected.set()
            return

        hc.connected.set()

        client.subscribe([
            (f"{topic_base}/HOST2CLIENT", 2),
            (f"{topic_base}/RESP", 2)
        ])

        # Optional: direkter UART-Frame an den WiFi-Stick (Topic /ESP)
        if TX_HEX:
            tx_payload = {
                "Tx": TX_HEX,
                "CLIENT_ID": TX_CLIENT_ID
            }
            client.publish(
                f"{topic_base}/ESP",
                json.dumps(tx_payload),
                qos=2,
                retain=False
            )

        poll = {
            "FORCE_RESPONSE": True,
            "query_list": [
                1161,1162,1163,1164,1165,1166,5055,5207,1014,1001,1158,
                1190,1191,1192,1194,5102,5240,5270,5255,5530,5870,
                5942,1194,1200,1195,1196,1197,1198,1210,1211,1193,
                1218,1228,1229,1199,1046,1298,1299,1300
            ],
            "CLIENT_ID": client_id,
            "LASTWRITE": 0,
            "SMT_USER": smt_user,
            "ISTOUCH": False,
            "DEVID": devid_override or ""
        }
        values = None
        if VALUES_JSON:
            try:
                values = json.loads(VALUES_JSON)
            except Exception:
                raise RuntimeError("REMKO_VALUES_JSON ist kein gueltiges JSON.")
        elif VALUES_1194:
            values = {"1194": VALUES_1194}
        if values:
            poll["values"] = values

        client.publish(
            f"{topic_base}/CLIENT2HOST",
            json.dumps(poll),
            qos=2,
            retain=False
        )

    def on_message(client, userdata, msg):
        hc.got_message = True
        hc.last_topic = msg.topic
        try:
            hc.last_payload = msg.payload.decode("utf-8", errors="replace")
        except Exception:
            hc.last_payload = repr(msg.payload)

    def on_subscribe(client, userdata, mid, reason_codes, properties=None):
        if reason_codes is None:
            print("MQTT subscribed mid=", mid)
        else:
            rc_vals = [ _rc_value(rc) for rc in reason_codes ]
            print("MQTT subscribed mid=", mid, "rc=", rc_vals)

    def on_disconnect(client, userdata, *args):
        reason_code = args[-2] if len(args) >= 2 else (args[0] if args else 0)
        rc_val = _rc_value(reason_code)
        hc.disconnect_rc = rc_val
        if rc_val != 0:
            print("MQTT disconnect rc=", rc_val)

    def on_log(client, userdata, level, buf):
        print("MQTT log:", buf)

    client = mqtt.Client(
        client_id=client_id,
        protocol=mqtt.MQTTv311,
        transport="websockets",
        callback_api_version=mqtt.CallbackAPIVersion.VERSION2,
    )
    user = user_override or sid
    pw = pass_override or sk
    if not user or not pw:
        raise RuntimeError("Kein MQTT Benutzer/Passwort verfügbar (SMT_ID/SMT_KEY oder SID/SK).")
    client.username_pw_set(user, pw)
    client.tls_set(cert_reqs=ssl.CERT_REQUIRED)
    client.ws_set_options(path=WSS_PATH)

    client.on_connect = on_connect
    client.on_message = on_message
    client.on_subscribe = on_subscribe
    client.on_disconnect = on_disconnect
    if os.environ.get("REMKO_DEBUG") == "1":
        client.on_log = on_log

    print("MQTT connect as:", client_id)
    print("Topic base:", topic_base)

    client.connect(WSS_HOST, WSS_PORT, keepalive=60)
    client.loop_start()

    if not hc.connected.wait(timeout=connect_timeout_sec):
        client.loop_stop()
        client.disconnect()
        raise RuntimeError("MQTT connect timeout – keine Verbindung aufgebaut.")

    if hc.connect_rc not in (0, None):
        client.loop_stop()
        client.disconnect()
        raise RuntimeError(f"MQTT connect failed rc={hc.connect_rc}")

    t0 = time.time()
    while time.time() - t0 < timeout_sec:
        if hc.got_message:
            break
        time.sleep(0.1)

    client.loop_stop()
    client.disconnect()

    if not hc.got_message:
        if allow_no_response:
            print("Warnung: Keine MQTT-Antwort empfangen (trotzdem gesendet).")
            return
        raise RuntimeError("MQTT Healthcheck Timeout – keine Daten empfangen.")

    print("Healthcheck OK ✅")
    print("Topic:", hc.last_topic)
    print("Sample:", (hc.last_payload or "")[:300])


# ---------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------

def main():
    s = requests.Session()
    login(s)

    devices = find_devices(s)
    print("Fernbedienungen:")
    for i, d in enumerate(devices):
        topic = d.get("mqtt_topic") or "-"
        sid = d.get("sid") or "-"
        name = d.get("name") or "-"
        print(f"  [{i}] {d.get('link')}  name={name}  sid={sid} topic={topic}")

    chosen = _pick_device(devices)
    if chosen:
        devices = [chosen]

    errors = []
    for d in devices:
        sid = d.get("sid")
        sk = d.get("sk")
        smt_user = d.get("smt_user")

        print(d.get("where"))
        if sid:
            print("SID:", sid)
        if sk:
            print("SK:", sk[:4] + "..." + sk[-4:])
        if smt_user:
            print("SMT_USER:", smt_user)

        user_override = SMT_ID or d.get("mqtt_user") or d.get("smt_id")
        pass_override = SMT_KEY or d.get("mqtt_pass") or d.get("smt_key")
        topic_override = MQTT_TOPIC or d.get("mqtt_topic")
        client_id_override = CLIENT_ID_OVERRIDE or d.get("mqtt_clientid")
        devid_override = d.get("smt_gid") or d.get("smt_dev")

        if not topic_override and not sid:
            errors.append(f"{d.get('link')}: MQTT_TOPIC fehlt und SID unbekannt.")
            print("Probe übersprungen: MQTT_TOPIC fehlt und SID unbekannt.")
            continue
        if not (user_override and pass_override) and not (sid and sk):
            errors.append(f"{d.get('link')}: SMT_ID/SMT_KEY fehlen und SID/SK unbekannt.")
            print("Probe übersprungen: SMT_ID/SMT_KEY fehlen und SID/SK unbekannt.")
            continue

        if user_override and pass_override:
            print("Using SMT_ID/SMT_KEY.")
        if topic_override:
            print("Using MQTT_TOPIC:", topic_override)

        try:
            mqtt_healthcheck(
                sid,
                sk,
                smt_user=smt_user or 3946,
                topic_override=topic_override,
                user_override=user_override,
                pass_override=pass_override,
                client_id_override=client_id_override,
                devid_override=devid_override,
                timeout_sec=TIMEOUT_SEC,
                connect_timeout_sec=CONNECT_TIMEOUT_SEC,
                allow_no_response=ALLOW_NO_RESPONSE,
            )
            return
        except RuntimeError as e:
            errors.append(f"{d.get('link')}: {e}")
            print("Probe fehlgeschlagen, versuche nächstes Gerät...")

    if errors:
        raise RuntimeError("Keine Fernbedienung antwortet:\n" + "\n".join(errors))


if __name__ == "__main__":
    main()
