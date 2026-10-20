"""Feature computation — the single source of truth, shared by training and serving.

At each tick the detector builds one vector per `src_ip` active in the 60 s window:
per-IP window features (10 s and 60 s), a short 5 min history, and global features.
`FEATURE_NAMES` fixes the order; the model stores it so the service refuses a model
whose feature list differs from this code (no train/serve skew).

See `docs/feature-engineering.md`.
"""

from __future__ import annotations

import math
from collections import defaultdict

from .schema import Record

WINDOWS_S = (10, 60)
HISTORY_S = 300

# Per-IP features computed on each window size (suffix _<w>s is added below).
_PER_IP = [
    "n_requests",
    "n_fail",
    "n_success",
    "fail_ratio",
    "n_distinct_users",
    "n_unknown_user",
    "n_distinct_user_agents",
    "req_per_s",
    "inter_arrival_mean_ms",
    "inter_arrival_std_ms",
    "max_burst_1s",
]
_HISTORY = ["req_per_s_ratio_5m", "ip_age_s"]
_GLOBAL = ["g_n_requests", "g_fail_ratio", "g_n_active_ips", "g_top_ip_share"]


def _build_names() -> list[str]:
    names: list[str] = []
    for w in WINDOWS_S:
        names.extend(f"{f}_{w}s" for f in _PER_IP)
    names.extend(_HISTORY)
    names.extend(_GLOBAL)
    return names


FEATURE_NAMES = _build_names()

# Features that are proportions (no log1p). Everything else is log1p-transformed.
_RATIO = {f"fail_ratio_{w}s" for w in WINDOWS_S} | {"g_fail_ratio", "g_top_ip_share"}
_RATE_RATIO = {"req_per_s_ratio_5m"}


def _max_burst_1s(ts_sorted: list[float]) -> int:
    """Largest number of events falling inside any 1 second window."""
    if not ts_sorted:
        return 0
    best = 0
    j = 0
    for i in range(len(ts_sorted)):
        while ts_sorted[i] - ts_sorted[j] > 1.0:
            j += 1
        best = max(best, i - j + 1)
    return best


def _per_ip_window(records: list[Record], now: float, window: int) -> dict[str, dict]:
    start = now - window
    by_ip: dict[str, list[Record]] = defaultdict(list)
    for r in records:
        if start < r.ts <= now:
            by_ip[r.src_ip].append(r)

    out: dict[str, dict] = {}
    for ip, rs in by_ip.items():
        rs.sort(key=lambda r: r.ts)
        n = len(rs)
        n_fail = sum(1 for r in rs if r.result == "fail")
        users = {r.username for r in rs if r.username}
        n_unknown = sum(1 for r in rs if r.reason == "unknown_user")
        uas = {r.user_agent for r in rs if r.user_agent}
        ts = [r.ts for r in rs]
        gaps = [(ts[i] - ts[i - 1]) * 1000.0 for i in range(1, len(ts))]
        mean_gap = sum(gaps) / len(gaps) if gaps else 0.0
        if len(gaps) >= 2:
            var = sum((g - mean_gap) ** 2 for g in gaps) / len(gaps)
            std_gap = math.sqrt(var)
        else:
            std_gap = 0.0
        out[ip] = {
            "n_requests": float(n),
            "n_fail": float(n_fail),
            "n_success": float(n - n_fail),
            "fail_ratio": n_fail / max(n, 1),
            "n_distinct_users": float(len(users)),
            "n_unknown_user": float(n_unknown),
            "n_distinct_user_agents": float(len(uas)),
            "req_per_s": n / window,
            "inter_arrival_mean_ms": mean_gap,
            "inter_arrival_std_ms": std_gap,
            "max_burst_1s": float(_max_burst_1s(ts)),
        }
    return out


def _history(records: list[Record], now: float) -> dict[str, dict]:
    start = now - HISTORY_S
    by_ip: dict[str, list[float]] = defaultdict(list)
    for r in records:
        if start < r.ts <= now:
            by_ip[r.src_ip].append(r.ts)

    out: dict[str, dict] = {}
    for ip, ts in by_ip.items():
        rate_5m = len(ts) / HISTORY_S
        n60 = sum(1 for t in ts if t > now - 60)
        r60 = n60 / 60.0
        ratio = r60 / rate_5m if rate_5m > 0 else 1.0
        age = min(now - min(ts), float(HISTORY_S))
        out[ip] = {"req_per_s_ratio_5m": ratio, "ip_age_s": age}
    return out


def _global(records: list[Record], now: float, window: int = 60) -> dict[str, float]:
    start = now - window
    rows = [r for r in records if start < r.ts <= now]
    n = len(rows)
    n_fail = sum(1 for r in rows if r.result == "fail")
    per_ip: dict[str, int] = defaultdict(int)
    for r in rows:
        per_ip[r.src_ip] += 1
    top = max(per_ip.values()) if per_ip else 0
    return {
        "g_n_requests": float(n),
        "g_fail_ratio": n_fail / max(n, 1),
        "g_n_active_ips": float(len(per_ip)),
        "g_top_ip_share": top / max(n, 1),
    }


def compute_vectors(records: list[Record], now: float) -> dict[str, dict[str, float]]:
    """One feature vector per src_ip active in the 60 s window ending at `now`."""
    per_w = {w: _per_ip_window(records, now, w) for w in WINDOWS_S}
    hist = _history(records, now)
    glob = _global(records, now, 60)

    vectors: dict[str, dict[str, float]] = {}
    for ip in per_w[60]:
        v: dict[str, float] = {}
        for w in WINDOWS_S:
            feats = per_w[w].get(ip)
            for f in _PER_IP:
                v[f"{f}_{w}s"] = float(feats[f]) if feats else 0.0
        h = hist.get(ip, {"req_per_s_ratio_5m": 1.0, "ip_age_s": 0.0})
        v["req_per_s_ratio_5m"] = h["req_per_s_ratio_5m"]
        v["ip_age_s"] = h["ip_age_s"]
        for f in _GLOBAL:
            v[f] = glob[f]
        vectors[ip] = v
    return vectors


def transform_row(v: dict[str, float]) -> list[float]:
    """Encode one vector into the model input order (log1p on counts/rates)."""
    row: list[float] = []
    for name in FEATURE_NAMES:
        x = v[name]
        if name in _RATIO:
            row.append(min(max(x, 0.0), 1.0))
        elif name in _RATE_RATIO:
            row.append(math.log1p(min(max(x, 0.0), 20.0)))
        else:
            row.append(math.log1p(max(x, 0.0)))
    return row
