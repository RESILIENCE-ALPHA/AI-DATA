"""Generate synthetic `login_attempts`-shaped data with labels.

The output matches DEV's table shape, so the same JSON lines feed the detector's
file source and could seed a database. Normal traffic includes the patterns that
fool naive detectors (legit retries, a shared office IP, internet-bot noise); the
brute force is a concentrated burst from one IP. A `labels.json` records attacker
IPs and the attack window, so training and evaluation know ground truth.

Usage:
    python -m generator.generate --preset synth_bf_v1
    python -m generator.generate --preset synth_normal_v1
"""

from __future__ import annotations

import argparse
import json
import random
from datetime import UTC, datetime, timedelta
from pathlib import Path

LEGIT_UAS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Version/17.2 Safari/605.1.15",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) Mobile/15E148",
    "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Firefox/121.0",
]
ATTACK_UAS = ["Hydra/9.5", "python-requests/2.31", "curl/8.4.0", "Wfuzz/3.1.0"]
BOT_USERNAMES = ["admin", "root", "test", "administrator", "info"]

PRESETS = {
    "synth_normal_v1": {"seed": 1, "attack": None},
    "synth_bf_v1": {"seed": 2, "attack": "bruteforce"},
    "synth_hard_v1": {"seed": 4, "attack": None, "hard": True},
}


def _iso(dt: datetime) -> str:
    return dt.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _public_ip(rng: random.Random) -> str:
    # RFC 5737 documentation ranges, so no real address appears in the repo.
    block = rng.choice(["192.0.2", "198.51.100", "203.0.113"])
    return f"{block}.{rng.randint(1, 254)}"


def generate(preset: str, out_root: Path) -> Path:
    cfg = PRESETS[preset]
    rng = random.Random(cfg["seed"])
    duration_min = 60
    users = [f"user{i}@epsi.fr" for i in range(1, 201)]
    legit_ips = [_public_ip(rng) for _ in range(8)]
    office_ip = _public_ip(rng)  # shared NAT: many users, normal fail rate
    bot_ips = [_public_ip(rng) for _ in range(6)]

    start = datetime.now(UTC) - timedelta(minutes=duration_min)
    rows: list[dict] = []

    def add(ts: datetime, ip: str, email: str, ok: bool, ua: str, known: bool = True) -> None:
        rows.append(
            {
                "createdAt": _iso(ts),
                "ipAddress": ip,
                "attemptedEmail": email,
                "isAuthenticated": ok,
                "failureReason": None if ok else "INVALID_CREDENTIALS",
                "targetUserId": "u" if (ok or known) else None,
                "userAgent": ua,
            }
        )

    # Normal traffic: ~30 logins/min, 8% failures, with retry bursts.
    for minute in range(duration_min):
        n = max(0, int(rng.gauss(30, 6)))
        for _ in range(n):
            ts = start + timedelta(minutes=minute, seconds=rng.uniform(0, 60))
            email = rng.choice(users)
            ip = office_ip if rng.random() < 0.25 else rng.choice(legit_ips)
            ua = rng.choice(LEGIT_UAS)
            if rng.random() < 0.08:
                add(ts, ip, email, False, ua)
                if rng.random() < 0.25:  # a legit user retries and then succeeds
                    for k in range(rng.randint(1, 3)):
                        add(ts + timedelta(seconds=2 * (k + 1)), ip, email, False, ua)
                    add(ts + timedelta(seconds=10), ip, email, True, ua)
            else:
                add(ts, ip, email, True, ua)

    # Internet-bot noise: low-rate failed logins on common usernames from many IPs.
    noise = 200 if cfg.get("hard") else 80
    for _ in range(noise):
        ts = start + timedelta(minutes=rng.uniform(0, duration_min))
        ip = rng.choice(bot_ips)
        add(ts, ip, rng.choice(BOT_USERNAMES), False, rng.choice(ATTACK_UAS), known=False)

    labels = {"attacks": [], "protected_ips": [office_ip], "bot_ips": bot_ips}

    # Brute force: one IP, ~5 req/s for 120 s, all failures, near min 40.
    if cfg.get("attack") == "bruteforce":
        attacker_ip = _public_ip(rng)
        a_start = start + timedelta(minutes=40)
        a_end = a_start + timedelta(seconds=120)
        t = a_start
        while t < a_end:
            email = rng.choice(users[:5])  # targeted spray on the first accounts
            add(t, attacker_ip, email, False, rng.choice(ATTACK_UAS))
            t += timedelta(seconds=max(0.05, rng.expovariate(5)))
        labels["attacks"].append(
            {"type": "auth_bruteforce", "src_ips": [attacker_ip],
             "start": _iso(a_start), "end": _iso(a_end)}
        )

    rows.sort(key=lambda r: r["createdAt"])
    out_dir = out_root / preset
    out_dir.mkdir(parents=True, exist_ok=True)
    with open(out_dir / "auth.jsonl", "w") as f:
        for r in rows:
            f.write(json.dumps(r) + "\n")
    (out_dir / "labels.json").write_text(json.dumps(labels, indent=2))
    (out_dir / "params.json").write_text(json.dumps({"preset": preset, **cfg}, indent=2))
    print(f"{preset}: {len(rows)} rows -> {out_dir}/auth.jsonl")
    return out_dir


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--preset", required=True, choices=sorted(PRESETS))
    ap.add_argument("--out", default="data/raw")
    args = ap.parse_args()
    generate(args.preset, Path(args.out))


if __name__ == "__main__":
    main()
