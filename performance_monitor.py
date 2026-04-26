from __future__ import annotations
from dataclasses import dataclass, asdict
from typing import Any, Dict, Optional, List
import time
import psutil
from pynvml import *

def detect_model_device(pipe: Any) -> str:
    try:
        model = getattr(pipe, "model", None)
        if model is not None and hasattr(model, "device"):
            return str(model.device)
    except Exception:
        pass
    return "unknown GPU"


def sample_cpu_mem(pid: Optional[int] = None) -> Dict[str, Any]:
    try:
        pid = pid or os.getpid()
        p = psutil.Process(pid)
        rss = p.memory_info().rss / (1024 * 1024)
        return {"rss_mb": round(rss, 2)}
    except Exception as e:
        return {"rss_mb": None, "cpu_error": str(e)}


def sample_gpu(index: int = 0) -> Dict[str, Any]:
    if nvmlInit is None:
        return {
            "gpu_name": None,
            "gpu_util_percent": None,
            "vram_used_mb": None,
            "vram_total_mb": None,
            "gpu_note": "pynvml (nvidia-ml-py) not installed or no NVIDIA GPU",
        }

    try:
        nvmlInit()
        h = nvmlDeviceGetHandleByIndex(index)

        util = nvmlDeviceGetUtilizationRates(h)
        mem = nvmlDeviceGetMemoryInfo(h)

        raw_name = nvmlDeviceGetName(h)
        name = raw_name.decode("utf-8", errors="ignore") if isinstance(raw_name, (bytes, bytearray)) else str(raw_name)

        used = mem.used / (1024 * 1024)
        total = mem.total / (1024 * 1024)

        return {
            "gpu_name": name,
            "gpu_util_percent": int(util.gpu),
            "vram_used_mb": round(used, 2),
            "vram_total_mb": round(total, 2),
        }
    except Exception as e:
        return {
            "gpu_name": None,
            "gpu_util_percent": None,
            "vram_used_mb": None,
            "vram_total_mb": None,
            "gpu_error": str(e),
        }


class Timer:
    def __init__(self, label: str):
        self.label = label
        self.t0 = 0.0
        self.ms = None

    def __enter__(self):
        self.t0 = time.perf_counter()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.ms = (time.perf_counter() - self.t0) * 1000


@dataclass
class PerfRow:
    request_id: str
    model_device: str
    tokenize_ms: Optional[float] = None
    inference_ms: Optional[float] = None
    total_ms: Optional[float] = None
    rss_mb: Optional[float] = None
    gpu_util_percent: Optional[int] = None
    vram_used_mb: Optional[float] = None
    vram_total_mb: Optional[float] = None
    gpu_name: Optional[str] = None

class PerfMonitor:

    COLUMN_LABELS: Dict[str, str] = {
        "request_id": "request_id",
        "model_device": "model_device",
        "tokenize_ms": "tokenize_ms",
        "inference_ms": "inference_ms",
        "total_ms": "total_ms",
        "rss_mb": "resident_set_size_mb",
        "gpu_util_percent": "gpu_util_percent",
        "vram_used_mb": "vram_used_mb",
        "vram_total_mb": "vram_total_mb",
        "gpu_name": "gpu_name",
    }

    COLS: List[str] = [
        "request_id",
        "model_device",
        "tokenize_ms",
        "inference_ms",
        "total_ms",
        "rss_mb",
        "gpu_util_percent",
        "vram_used_mb",
        "vram_total_mb",
        "gpu_name",
    ]

    def __init__(self, pipe: Any, keep_last: int = 200):
        self.pipe = pipe
        self.keep_last = keep_last
        self.rows: List[PerfRow] = []
        self._counter = 0

    def record(
        self,
        timing: Optional[Dict[str, float]] = None,
        gpu_index: int = 0,
    ) -> PerfRow:
        rid = str(self._counter)
        self._counter += 1
        model_device = detect_model_device(self.pipe)
        cpu = sample_cpu_mem()
        gpu = sample_gpu(gpu_index)

        row = PerfRow(
            request_id=rid,
            model_device=model_device,
            tokenize_ms=(timing or {}).get("tokenize_ms"),
            inference_ms=(timing or {}).get("inference_ms"),
            total_ms=(timing or {}).get("total_ms"),
            rss_mb=cpu.get("rss_mb"),
            gpu_util_percent=gpu.get("gpu_util_percent"),
            vram_used_mb=gpu.get("vram_used_mb"),
            vram_total_mb=gpu.get("vram_total_mb"),
            gpu_name=gpu.get("gpu_name"),
        )

        self.rows.append(row)
        if len(self.rows) > self.keep_last:
            self.rows = self.rows[-self.keep_last:]

        return row

    def last_table(self, n: int = 10) -> str:
        data = [asdict(r) for r in self.rows[-n:]]
        if not data:
            return "(no perf records)"

        cols = self.COLS

        def fmt(v):
            if v is None:
                return ""
            if isinstance(v, float):
                return f"{v:.2f}"
            return str(v)

        header_names = [self.COLUMN_LABELS.get(c, c) for c in cols]

        widths = {}
        for c, hname in zip(cols, header_names):
            widths[c] = max(
                len(hname),
                max(len(fmt(row.get(c))) for row in data)
            )

        line = "+".join("-" * (widths[c] + 2) for c in cols)
        header = "|".join(f" {hname.ljust(widths[c])} " for c, hname in zip(cols, header_names))

        rows = []
        for row in data:
            rows.append("|".join(f" {fmt(row.get(c)).ljust(widths[c])} " for c in cols))

        return "\n".join([line, header, line] + rows + [line])

    def to_csv(self, path: str) -> None:
        import csv
        if not self.rows:
            return
        data = [asdict(r) for r in self.rows]
        cols = list(data[0].keys())
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=cols)
            w.writeheader()
            w.writerows(data)
