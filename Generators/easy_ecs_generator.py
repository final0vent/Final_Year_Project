import json
import random
import uuid
import ipaddress
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Dict, Any, List

# -----------------------------
# Config
# -----------------------------
@dataclass
class EasyConfig:
    seed: int = 7 # Random seed
    n_events: int = 500 # How many events will be generated
    start_time_utc: datetime = datetime(2025, 11, 5, 20, 0, 0, tzinfo=timezone.utc) # Start time
    avg_interval_seconds: float = 2.0 # Avg interval seconds between two events.
    # auth-heavy so examples trigger often
    weights: Dict[str, float] = None

    def __post_init__(self):
        if self.weights is None:
            self.weights = {
                "auth": 0.06,
                "process": 0.04,
                "noise": 0.90,
            }

USERS = ["david", "alice", "bob", "carol", "eve", "frank", "grace"]
HOSTS = [f"host-{i:02d}" for i in range(1, 21)]

# -----------------------------
# Helpers
# -----------------------------
def iso_ts(dt: datetime) -> str:
    dt = dt.astimezone(timezone.utc)
    # round to 2 decimal places (centiseconds)
    cs = round(dt.microsecond / 10000)
    if cs == 100:
        dt = dt + timedelta(seconds=1)
        cs = 0
    return dt.strftime("%Y-%m-%dT%H:%M:%S") + f".{cs:02d}Z"


def rand_private_ip(rng: random.Random) -> str:
    nets = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
    net = ipaddress.IPv4Network(rng.choice(nets))
    host = rng.randint(1, net.num_addresses - 2)
    return str(net.network_address + host)

def rand_public_ip(rng: random.Random) -> str:
    while True:
        ip = ipaddress.IPv4Address(rng.getrandbits(32))
        if not (ip.is_private or ip.is_loopback or ip.is_multicast or ip.is_reserved or ip.is_unspecified):
            return str(ip)

def weighted_pick(rng: random.Random, weights: Dict[str, float]) -> str:
    x = rng.random()
    s = 0.0
    for k, w in weights.items():
        s += w
        if x <= s:
            return k
    return list(weights.keys())[-1]

# -----------------------------
# Base ECS envelope
# -----------------------------
def base_doc(cfg: EasyConfig, rng: random.Random, ts: datetime) -> Dict[str, Any]:
    return {
        "@timestamp": iso_ts(ts),
        "event": {
            "id": str(uuid.uuid4()),
            "kind": "event",
        },
        "host": {"name": rng.choice(HOSTS)},
        "user": {"name": rng.choice(USERS)},
        "source": {
            "ip": rand_public_ip(rng) if rng.random() < 0.6 else rand_private_ip(rng)
        },
        "destination": {
            "ip": rand_private_ip(rng),
            "port": None
        },
        "network": {},
        "message": "",
        "tags": []
    }
BASE_HEADER_FIELDS = [
    "@timestamp",
    "event.id",
    "event.kind",
    "host.name",
    "user.name",
    "source.ip",
    "destination.ip",
    "destination.port",
    "network",
    "message",
    "tags",
]

# -----------------------------
# Event builders
# -----------------------------
def gen_auth_event(cfg: EasyConfig, rng: random.Random, ts: datetime) -> Dict[str, Any]:
    doc = base_doc(cfg, rng, ts)

    # david appears more often for example #2
    if rng.random() < 0.25:
        doc["user"]["name"] = "david"

    outcome = "failure" if rng.random() < 0.18 else "success"

    doc["event"].update({
        "category": ["authentication"],
        "outcome": outcome,
    })

    doc["destination"]["port"] = rng.choice([22, 3389, 445])
    doc["network"] = {"transport": "tcp"}

    doc["message"] = f"user login {outcome}"
    doc["tags"] = ["suspicious"] if outcome == "failure" else ["normal"]

    return doc

def gen_process_event(cfg: EasyConfig, rng: random.Random, ts: datetime) -> Dict[str, Any]:
    doc = base_doc(cfg, rng, ts)

    doc["event"].update({
        "category": ["process"],
        "outcome": "success",
    })

    pname = "powershell.exe" if rng.random() < 0.35 else rng.choice(
        ["chrome.exe", "msedge.exe", "cmd.exe"]
    )

    doc["process"] = {"name": pname}

    doc["message"] = f"process start: {pname}"
    doc["tags"] = ["suspicious"] if pname == "powershell.exe" else ["normal"]

    return doc

def gen_noise_event(cfg: EasyConfig, rng: random.Random, ts: datetime) -> Dict[str, Any]:
    """
    Background traffic that does not match the 3 example detections.
    """
    doc = base_doc(cfg, rng, ts)

    doc["event"].update({
        "category": ["network"],
        "outcome": "success",
    })

    doc["destination"]["port"] = rng.choice([80, 443])
    doc["network"] = {"transport": "tcp"}

    doc["message"] = "web traffic"
    doc["tags"] = ["normal"]

    return doc

# -----------------------------
# Generate dataset
# -----------------------------
def generate(cfg: EasyConfig) -> List[Dict[str, Any]]:
    rng = random.Random(cfg.seed)
    ts = cfg.start_time_utc

    out: List[Dict[str, Any]] = []

    for _ in range(cfg.n_events):
        etype = weighted_pick(rng, cfg.weights)

        if etype == "auth":
            out.append(gen_auth_event(cfg, rng, ts))
        elif etype == "process":
            out.append(gen_process_event(cfg, rng, ts))
        else:
            out.append(gen_noise_event(cfg, rng, ts))

        gap = rng.random() * cfg.avg_interval_seconds * 2
        ts = ts + timedelta(seconds=gap)

    return out

def write_ndjson(events, path: str):
    with open(path, "w", encoding="utf-8") as f:
        # ---- write header line ----
        header_line = ",".join(BASE_HEADER_FIELDS)
        f.write(header_line + "\n")

        # ---- write NDJSON rows ----
        for ev in events:
            f.write(json.dumps(ev, ensure_ascii=False) + "\n")

if __name__ == "__main__":
    cfg = EasyConfig()
    events = generate(cfg)
    write_ndjson(events, "easy_events.ndjson")
    print(f"Wrote {len(events)} events to easy_events.ndjson")
