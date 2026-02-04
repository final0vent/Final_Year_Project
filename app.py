from flask import Flask, render_template, request, jsonify
from datetime import datetime, timedelta
import math
import json
import ipaddress
from typing import Any, Dict, Tuple, List
import traceback

from prompts import GENERATE_KQL_PROMPT
from kql_parser import filter_events_by_kql
from analyzer import analyze_events_with_rules

from google import genai
import config

app = Flask(__name__)

# -------- Gemini client --------

client = genai.Client(api_key=config.GEMINI_API_KEY)

def ask_gemini(prompt: str) -> str:
    resp = client.models.generate_content(
        model=config.MODEL,
        contents=prompt
    )
    return (resp.text or "").strip()

def generate_kql_from_nl(nl: str):
    sys_prompt = GENERATE_KQL_PROMPT.format(nl=nl)
    raw = ask_gemini(sys_prompt)

    def extract_json(text: str) -> str:
        start = text.find("{")
        end = text.rfind("}")
        if start != -1 and end != -1 and end > start:
            return text[start:end + 1]
        return text

    json_text = extract_json(raw)

    kql = ""
    explanation = ""
    warnings = ""

    try:
        data = json.loads(json_text)
        kql = data.get("kql", "") or ""
        explanation = data.get("explanation", "") or ""
        warnings = data.get("warnings", "") or ""
    except Exception:
        explanation = f"Parsing failed, the original response is as follows:\n{raw}"
        warnings = "Please check whether the LLM output format is valid."

    return kql, explanation, warnings


# ===================== ECS NDJSON ONLY =====================

ECS_MIN_FIELDS = ["@timestamp", "event.category"]

def _is_valid_ip(v: str) -> bool:
    try:
        ipaddress.ip_address(v)
        return True
    except Exception:
        return False

def _parse_ecs_timestamp(ts: str):
    try:
        if ts.endswith("Z"):
            return datetime.fromisoformat(ts.replace("Z", "+00:00"))
        return datetime.fromisoformat(ts)
    except Exception:
        return None

def flatten_dict(d: Dict[str, Any], parent_key: str = "", sep: str = ".") -> Dict[str, Any]:
    """Convert to style: a.b.c: value"""
    items = {}
    for k, v in (d or {}).items():
        new_key = f"{parent_key}{sep}{k}" if parent_key else k
        if isinstance(v, dict):
            items.update(flatten_dict(v, new_key, sep=sep))
        else:
            items[new_key] = v
    return items

def normalize_ecs_row(obj: Dict[str, Any], line_no: int) -> Tuple[Dict[str, Any], List[str]]:

    warnings = []

    for f in ECS_MIN_FIELDS:
        if f == "event.category":
            if "event" not in obj or "category" not in obj["event"]:
                return ({
                    "id": line_no,
                    "raw": json.dumps(obj, ensure_ascii=False),
                    "parse_error": "missing required field: event.category"
                }, warnings)
        elif f not in obj:
            return ({
                "id": line_no,
                "raw": json.dumps(obj, ensure_ascii=False),
                "parse_error": f"missing required field: {f}"
            }, warnings)

    ts_raw = obj.get("@timestamp")
    ts_dt = _parse_ecs_timestamp(ts_raw)
    if ts_dt is None:
        return ({
            "id": line_no,
            "raw": json.dumps(obj, ensure_ascii=False),
            "parse_error": "invalid @timestamp"
        }, warnings)

    src_ip = obj.get("source", {}).get("ip")
    dst_ip = obj.get("destination", {}).get("ip")
    if src_ip and not _is_valid_ip(src_ip):
        warnings.append(f"line {line_no}: invalid source.ip")
        src_ip = None
    if dst_ip and not _is_valid_ip(dst_ip):
        warnings.append(f"line {line_no}: invalid destination.ip")
        dst_ip = None

    flat = flatten_dict(obj)

    ev = {
        "id": line_no,
        "raw": json.dumps(obj, ensure_ascii=False),
        "timestamp": ts_raw,
        "timestamp_dt": ts_dt,
        "message": obj.get("message", ""),

        "event.category": obj.get("event", {}).get("category"),
        "event.action": obj.get("event", {}).get("action"),
        "source.ip": src_ip,
        "destination.ip": dst_ip,
        "severity": obj.get("event", {}).get("severity") or obj.get("log", {}).get("level"),
        "outcome": obj.get("event", {}).get("outcome"),
        "user.name": obj.get("user", {}).get("name"),
        "host.name": obj.get("host", {}).get("name"),
        "process.name": obj.get("process", {}).get("name") if isinstance(obj.get("process"), dict) else None,
        "process.pid": obj.get("process", {}).get("pid") if isinstance(obj.get("process"), dict) else None,
        "process.command_line": obj.get("process", {}).get("command_line") if isinstance(obj.get("process"), dict) else None,

        "structured": obj,
    }

    for k, v in flat.items():
        ev.setdefault(k, v)

    ev["_all_concat"] = " ".join(str(x) for x in flat.values() if x is not None)

    return ev, warnings

def parse_ndjson_file(file_storage):
    events, errors, warns = [], [], []
    for idx, raw in enumerate(file_storage.stream, start=1):
        line = raw.decode("utf-8", errors="ignore").strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except Exception as e:
            errors.append({"line": idx, "error": f"JSON parse: {e}"})
            continue

        ev, w = normalize_ecs_row(obj, idx)
        if ev.get("parse_error"):
            errors.append({"line": idx, "error": ev["parse_error"]})
            continue

        events.append(ev)
        warns.extend(w)
    return events, errors, warns


# -------- Events over time --------

def pretty_interval(seconds: float) -> str:
    if seconds < 60:
        return f"{int(seconds)} s"
    minutes = seconds / 60
    if minutes < 60:
        return f"{minutes:.1f} min"
    hours = minutes / 60
    if hours < 24:
        return f"{hours:.1f} h"
    days = hours / 24
    return f"{days:.1f} d"

def build_histogram(events):
    ts_list = [e["timestamp_dt"] for e in events if e.get("timestamp_dt") is not None]
    if not ts_list:
        return [], None, [], None, None

    ts_list.sort()
    min_ts = ts_list[0]
    max_ts = ts_list[-1]

    total_seconds = (max_ts - min_ts).total_seconds()
    if total_seconds <= 0:
        total_seconds = 1.0

    num_buckets = 25
    interval_sec = total_seconds / num_buckets

    counts = [0] * num_buckets

    for ts in ts_list:
        delta = (ts - min_ts).total_seconds()
        idx = int(delta // interval_sec)
        if idx >= num_buckets:
            idx = num_buckets - 1
        counts[idx] += 1

    max_count = max(counts) if counts else 0

    buckets = []
    for i in range(num_buckets):
        bucket_start = min_ts + timedelta(seconds=i * interval_sec)
        label = bucket_start.strftime("%m-%d\n%H:%M:%S")
        count = counts[i]
        if max_count > 0:
            height = 10 + int(90 * (count / max_count))
        else:
            height = 10
        buckets.append({
            "label": label,
            "count": count,
            "height": height,
        })

    if max_count <= 0:
        y_ticks = [0]
    else:
        step = max(1, math.ceil(max_count / 5))
        y_ticks = list(range(0, max_count + 1, step))
        if y_ticks[-1] != max_count:
            y_ticks.append(max_count)

    interval_label = pretty_interval(interval_sec)
    x_start_label = min_ts.strftime("%Y-%m-%d %H:%M:%S")
    x_end_label = max_ts.strftime("%Y-%m-%d %H:%M:%S")

    return buckets, interval_label, y_ticks, x_start_label, x_end_label


# -------- Flask routes --------

ALL_EVENTS = []
LAST_FILENAME = None

@app.route("/", methods=["GET", "POST"])
def index():
    global ALL_EVENTS, LAST_FILENAME

    events = ALL_EVENTS
    filename = LAST_FILENAME

    hist_buckets = []
    hist_interval_label = None
    hist_y_ticks = []
    hist_x_start = None
    hist_x_end = None

    parse_errors = []
    parse_warnings = []

    has_rule_warnings = False
    rule_warnings = []

    if request.method == "POST":
        uploaded = request.files.get("logfile")
        if uploaded and uploaded.filename:
            filename = uploaded.filename
            events, parse_errors, parse_warnings = parse_ndjson_file(uploaded)

            ALL_EVENTS = events
            LAST_FILENAME = filename

    kql_query = (request.values.get("kql") or "").strip()

    if events and kql_query:
        visible_events = filter_events_by_kql(events, kql_query)
    else:
        visible_events = events or []

    if visible_events:
        rule_result = analyze_events_with_rules(visible_events)
        has_rule_warnings = rule_result["has_warning"]
        rule_warnings = rule_result["warnings"]

        (hist_buckets,
         hist_interval_label,
         hist_y_ticks,
         hist_x_start,
         hist_x_end) = build_histogram(visible_events)

    return render_template(
        "index.html",
        events=visible_events,
        filename=filename,
        hist_buckets=hist_buckets,
        hist_interval_label=hist_interval_label,
        hist_y_ticks=hist_y_ticks,
        hist_x_start=hist_x_start,
        hist_x_end=hist_x_end,
        kql_query=kql_query,
        parse_errors=parse_errors[:200],
        parse_warnings=parse_warnings[:200],

        has_rule_warnings=has_rule_warnings,
        rule_warnings=rule_warnings,
    )


@app.route("/nl2kql", methods=["POST"])
def nl2kql():
    """
    JSON in: { "text": "..." }
    JSON out: { "kql": "...", "explanation": "...", "warnings": "..." }
    """
    data = request.get_json(force=True, silent=True) or {}
    nl = (data.get("text") or "").strip()
    if not nl:
        return jsonify({"error": "empty input"}), 400

    try:
        kql, explanation, warnings = generate_kql_from_nl(nl)
        kql = kql.replace('"', '')
        return jsonify({
            "kql": kql,
            "explanation": explanation,
            "warnings": warnings,
        })
    except Exception as e:
        traceback.print_exc()
        return jsonify({
            "kql": "",
            "explanation": f"error: {e}",
            "warnings": "",
        }), 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
