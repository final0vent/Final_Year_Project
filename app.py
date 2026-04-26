from flask import Flask, render_template, request, jsonify,Response
from datetime import datetime, timedelta
import json
import ipaddress
from typing import Any, Dict, Tuple, List
import traceback
import uuid

from kql_parser import filter_events_by_kql
from analyzer import analyze_events_with_rules
from nl2kql import generate_kql_from_nl
from performance_monitor import PerfMonitor
import config
import threading

app = Flask(__name__)
perf = PerfMonitor(config._PIPE, keep_last=300)
perf_lock = threading.Lock()

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

        # Keep original string + parsed dt + guaranteed ISO for frontend histogram
        "@timestamp": ts_raw,
        "timestamp_dt": ts_dt,
        "@timestamp_iso": ts_dt.isoformat().replace("+00:00", "Z"),

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
        "network": obj.get("network"),

        "structured": obj,
    }

    for k, v in flat.items():
        ev.setdefault(k, v)

    ev["_all_concat"] = " ".join(str(x) for x in flat.values() if x is not None)

    return ev, warnings


def parse_ndjson_file(file_storage):
    events, errors, warns = [], [], []
    headers = []

    raw_lines = list(file_storage.stream)

    # Find first non-empty line
    first_line = None
    first_line_no = None
    for i, raw in enumerate(raw_lines, start=1):
        line = raw.decode("utf-8", errors="ignore").strip()
        if line:
            first_line = line
            first_line_no = i
            break

    if first_line is None:
        errors.append({"line": 1, "error": "empty file"})
        return [], errors, warns, []

    # Detect whether the file starts with JSON (NDJSON) or a CSV-like header
    if first_line.lstrip().startswith("{"):
        # NDJSON: parse from the first JSON line
        start_line_no = first_line_no
        headers = []
    else:
        # Header line present: treat it as headers, parse JSON starting from next line
        headers = [h.strip() for h in first_line.split(",") if h.strip()]
        start_line_no = first_line_no + 1

    for idx, raw in enumerate(raw_lines[start_line_no - 1 :], start=start_line_no):
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

    # If no explicit headers, derive from first normalized event keys
    if not headers and events:
        # exclude noisy/internal keys if you want
        headers = [k for k in events[0].keys() if not k.startswith("_")]

    return events, errors, warns, headers

def build_histogram(events: List[Dict[str, Any]], n_buckets: int = 25):
    if not events:
        return None

    dts = [e.get("timestamp_dt") for e in events if e.get("timestamp_dt") is not None]
    if not dts:
        return None

    dts.sort()
    start = dts[0]
    end = dts[-1]
    if start == end:
        # all same timestamp -> one bucket
        buckets = [{"label": start.strftime("%Y-%m-%d %H:%M:%S"), "count": len(dts), "height": 100}]
        return {
            "hist_buckets": buckets,
            "hist_interval_label": "single",
            "hist_y_ticks": [0, len(dts)],
            "hist_x_start": start.strftime("%Y-%m-%d %H:%M"),
            "hist_x_end": end.strftime("%Y-%m-%d %H:%M"),
        }

    total_seconds = (end - start).total_seconds()
    step = total_seconds / n_buckets

    counts = [0] * n_buckets
    for dt in dts:
        idx = int((dt - start).total_seconds() / step)
        if idx >= n_buckets:
            idx = n_buckets - 1
        counts[idx] += 1

    max_count = max(counts) if counts else 1
    buckets = []
    for i, c in enumerate(counts):
        b_start = start + timedelta(seconds=i * step)
        label = b_start.strftime("%Y-%m-%d %H:%M")
        height = (c / max_count * 100.0) if max_count > 0 else 0
        buckets.append({"label": label, "count": c, "height": round(height, 2)})

    # y ticks (simple 0..max)
    hist_y_ticks = [0, max_count // 2, max_count] if max_count >= 2 else [0, max_count]

    interval_label = f"{int(step)}s" if step < 120 else f"{int(step/60)}m"

    return {
        "hist_buckets": buckets,
        "hist_interval_label": interval_label,
        "hist_y_ticks": hist_y_ticks,
        "hist_x_start": start.strftime("%Y-%m-%d %H:%M"),
        "hist_x_end": end.strftime("%Y-%m-%d %H:%M"),
    }


ALL_EVENTS = []
LAST_FILENAME = None
TABLE_HEADERS = []


@app.route("/", methods=["GET", "POST"])
def index():
    global ALL_EVENTS, LAST_FILENAME, TABLE_HEADERS

    events = ALL_EVENTS
    filename = LAST_FILENAME
    headers = TABLE_HEADERS

    parse_errors = []
    parse_warnings = []

    if request.method == "POST":
        uploaded = request.files.get("logfile")
        if uploaded and uploaded.filename:
            filename = uploaded.filename
            events, parse_errors, parse_warnings, headers = parse_ndjson_file(uploaded)

            ALL_EVENTS = events
            LAST_FILENAME = filename
            TABLE_HEADERS = headers

    kql_query = (request.values.get("kql") or "").strip()

    if events and kql_query:
        visible_events = filter_events_by_kql(events, kql_query)
    else:
        visible_events = events or []

    has_rule_warnings = False
    rule_warnings = []

    if visible_events:
        rule_result = analyze_events_with_rules(visible_events)
        has_rule_warnings = rule_result["has_warning"]
        rule_warnings = rule_result["warnings"]

    hist = build_histogram(visible_events, n_buckets=25) if visible_events else None

    return render_template(
        "index.html",
        events=visible_events,
        filename=filename,
        kql_query=kql_query,
        parse_errors=parse_errors[:200],
        parse_warnings=parse_warnings[:200],
        headers=headers,
        has_rule_warnings=has_rule_warnings,
        rule_warnings=rule_warnings,

        hist_buckets=(hist or {}).get("hist_buckets"),
        hist_interval_label=(hist or {}).get("hist_interval_label"),
        hist_y_ticks=(hist or {}).get("hist_y_ticks"),
        hist_x_start=(hist or {}).get("hist_x_start"),
        hist_x_end=(hist or {}).get("hist_x_end"),
    )


@app.route("/nl2kql", methods=["POST"])
def nl2kql():
    data = request.get_json(force=True, silent=True) or {}
    nl = (data.get("text") or "").strip()

    if not nl:
        return jsonify({"error": "empty input"}), 400

    req_id = uuid.uuid4().hex[:10]

    try:
        result = generate_kql_from_nl(nl, max_new_tokens=1024)

        with perf_lock:
            perf.record(timing=result.get("timing"))
            perf_table = perf.last_table(10)

        kql = (result.get("kql") or "").replace('"', "")

        return jsonify({
            "request_id": req_id,
            "kql": kql,
            "explanation": result.get("explanation", ""),
            "warnings": result.get("warnings", ""),
            "timing": result.get("timing", {}),
            "perf_table": perf_table,
        })

    except Exception as e:
        traceback.print_exc()
        with perf_lock:
            perf_table = perf.last_table(10)
        return jsonify({
            "request_id": req_id,
            "kql": "",
            "explanation": f"error: {e}",
            "warnings": "",
            "perf_table": perf_table,
        }), 500

@app.get("/perf")
def perf_page():
    with perf_lock:
        table = perf.last_table(30)
    html = f"""
    <html>
      <head>
        <title>Perf Monitor</title>
        <meta charset="utf-8"/>
        <style>
          body {{ font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace; padding: 16px; }}
          pre {{ background: #f6f8fa; padding: 12px; border-radius: 8px; overflow-x: auto; }}
          .hint {{ margin-bottom: 12px; color: #444; }}
        </style>
      </head>
      <body>
        <div class="hint">Showing last 30 records.</div>
        <pre>{table}</pre>
      </body>
    </html>
    """
    return Response(html, mimetype="text/html")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True, use_reloader=False)