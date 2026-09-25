# Mboa HoneyPot - prototype de collecte de menace sans données sensibles
# Objectif : enregistrer les tentatives de fraude sur des numéros factices,
# uniquement pour la surveillance et la réponse défensive.

from __future__ import annotations

import csv
import hashlib
import io
import json
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, Response

DB_PATH = Path(__file__).with_name("honeypot.db")
app = FastAPI(title="Mboa HoneyPot")


def init_db() -> None:
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS attempts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            recorded_at TEXT NOT NULL,
            bait_number TEXT NOT NULL,
            bait_hash TEXT NOT NULL,
            source_ip TEXT,
            language TEXT,
            user_agent TEXT,
            country_guess TEXT,
            message TEXT,
            source TEXT,
            risk_level TEXT
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS bait_numbers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            number TEXT UNIQUE NOT NULL,
            created_at TEXT NOT NULL
        )
        """
    )
    conn.execute("SELECT COUNT(*) FROM bait_numbers")
    if conn.execute("SELECT COUNT(*) FROM bait_numbers").fetchone()[0] == 0:
        seeds = [
            "237600000001",
            "237600000002",
            "237600000003",
            "237600000004",
            "237600000005",
        ]
        now = datetime.utcnow().isoformat()
        conn.executemany(
            "INSERT INTO bait_numbers(number, created_at) VALUES (?, ?)",
            [(n, now) for n in seeds],
        )
    conn.commit()
    conn.close()


init_db()


def normalize_number(value: str | None) -> str:
    cleaned = (value or "unknown").strip()
    if cleaned == "" or cleaned.lower() in {"null", "none", "unknown"}:
        return "unknown"
    digits = "".join(ch for ch in cleaned if ch.isdigit())
    if digits:
        return digits[:15]
    return cleaned[:32]


def hash_value(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:32]


def get_client_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    real_ip = request.headers.get("x-real-ip")
    if real_ip:
        return real_ip.strip()
    cf_ip = request.headers.get("cf-connecting-ip")
    if cf_ip:
        return cf_ip.strip()
    return request.client.host if request.client else "unknown"


def guess_country(ip: str) -> str:
    if ip == "unknown":
        return "unknown"
    if ip.startswith("10.") or ip.startswith("127.") or ip.startswith("172.16"):
        return "local"
    return "unknown"


def detect_language(text: str | None = None, request: Request | None = None) -> str:
    header_value = ""
    if request is not None:
        header_value = request.headers.get("accept-language", "") or ""

    candidate = (header_value or "").strip()
    if candidate:
        for part in candidate.split(","):
            tag = part.split(";")[0].strip().lower()
            if tag:
                if tag.startswith("fr"):
                    return "fr"
                if tag.startswith("en"):
                    return "en"
                if tag.startswith("es"):
                    return "es"
                if tag.startswith("pt"):
                    return "pt"
                if tag.startswith("ar"):
                    return "ar"
                if tag.startswith("de"):
                    return "de"
                if tag.startswith("it"):
                    return "it"

    sample = (text or "").lower()
    if not sample:
        return "unknown"

    french_markers = [
        "bonjour", "merci", "s'il", "svp", "votre", "argent", "transfert",
        "récompense", "vérification", "message", "france", "salut", "paye",
        "retrait", "versement", "momo", "client", "numero", "confirmer",
        "veuillez", "pour", "gagner", "oui", "non", "paiement", "aide",
        "urgence", "decision", "frais", "s'il vous plaît", "vérifiez",
        "confirmez", "votre code", "code otp", "votre numero", "numero de"
    ]
    english_markers = [
        "hello", "please", "confirm", "your", "otp", "transfer", "reward",
        "message", "client", "payment", "urgent", "verify", "code", "win",
        "thanks", "bank", "fraud"
    ]

    if any(marker in sample for marker in french_markers):
        return "fr"

    if any(ch in sample for ch in "éèêëàçùîïôûœ"):
        return "fr"

    if any(marker in sample for marker in english_markers):
        return "en"

    return "unknown"


def get_language(request: Request, message: str | None = None) -> str:
    return detect_language(text=message, request=request)


def fetch_all_attempts() -> list[dict[str, Any]]:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        """
        SELECT recorded_at, bait_number, source_ip, language, user_agent, country_guess, message, source, risk_level
        FROM attempts
        ORDER BY id DESC
        """
    ).fetchall()
    conn.close()
    return [dict(row) for row in rows]


def fetch_attempts(limit: int = 50) -> list[dict[str, Any]]:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        """
        SELECT recorded_at, bait_number, source_ip, language, user_agent, country_guess, message, source, risk_level
        FROM attempts
        ORDER BY id DESC
        LIMIT ?
        """,
        (limit,),
    ).fetchall()
    conn.close()
    return [dict(row) for row in rows]


def build_language_stats(rows: list[dict[str, Any]]) -> dict[str, int]:
    stats: dict[str, int] = {}
    for row in rows:
        key = row.get("language") or "unknown"
        stats[key] = stats.get(key, 0) + 1
    return dict(sorted(stats.items()))


@app.get("/")
def home() -> dict[str, Any]:
    return {
        "name": "Mboa HoneyPot",
        "status": "active",
        "description": "Piège defensif pour surveiller des tentatives de fraude sur des numéros factices",
        "dashboard": "/dashboard",
        "exports": {"csv": "/export/csv", "json": "/export/json"},
    }


@app.post("/report-scam")
async def report_scam(request: Request) -> dict[str, Any]:
    payload = await request.json()
    if not isinstance(payload, dict):
        payload = {}

    bait_number = normalize_number(payload.get("numero") or payload.get("bait_number"))
    message = str(payload.get("message") or "")[:2000]
    source = str(payload.get("source") or "web")
    source_ip = get_client_ip(request)
    language = get_language(request, message)
    user_agent = request.headers.get("user-agent", "unknown")
    country_guess = guess_country(source_ip)

    risk_level = "low"
    if any(keyword in message.lower() for keyword in ["code", "otp", "pin", "versement", "argent", "retrait", "vérification"]):
        risk_level = "medium"
    if any(keyword in message.lower() for keyword in ["paye", "transfert", "momo", "claim", "récompense"]):
        risk_level = "high"

    recorded_at = datetime.utcnow().isoformat()
    bait_hash = hash_value(bait_number)

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.execute(
        """
        INSERT INTO attempts (
            recorded_at, bait_number, bait_hash, source_ip, language, user_agent, country_guess, message, source, risk_level
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            recorded_at,
            bait_number,
            bait_hash,
            source_ip,
            language,
            user_agent,
            country_guess,
            message,
            source,
            risk_level,
        ),
    )
    conn.commit()
    attempt_id = cursor.lastrowid
    conn.close()

    return {
        "status": "recorded",
        "id": attempt_id,
        "bait_number": bait_number,
        "source_ip": source_ip,
        "language": language,
        "risk_level": risk_level,
    }


@app.get("/api/attempts")
def api_attempts() -> dict[str, Any]:
    rows = fetch_all_attempts()
    return {"total": len(rows), "attempts": rows}


@app.get("/public/bait-numbers")
def public_bait_numbers() -> dict[str, Any]:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        "SELECT number, created_at FROM bait_numbers ORDER BY id ASC"
    ).fetchall()
    conn.close()
    return {"source": "public bait list", "data": [dict(row) for row in rows]}


@app.get("/export/csv")
def export_csv() -> Response:
    rows = fetch_all_attempts()
    output = io.StringIO()
    writer = csv.DictWriter(
        output,
        fieldnames=[
            "recorded_at",
            "bait_number",
            "source_ip",
            "language",
            "user_agent",
            "country_guess",
            "message",
            "source",
            "risk_level",
        ],
    )
    writer.writeheader()
    for row in rows:
        writer.writerow({k: row.get(k, "") for k in writer.fieldnames})

    headers = {"Content-Disposition": 'attachment; filename="mboa_honeypot_export.csv"'}
    return Response(content=output.getvalue(), media_type="text/csv", headers=headers)


@app.get("/export/json")
def export_json() -> JSONResponse:
    rows = fetch_all_attempts()
    payload = {
        "exported_at": datetime.utcnow().isoformat(),
        "total": len(rows),
        "attempts": rows,
    }
    return JSONResponse(content=payload)


@app.get("/dashboard", response_class=HTMLResponse)
def dashboard() -> HTMLResponse:
    all_attempts = fetch_all_attempts()
    latest_attempts = fetch_attempts(limit=20)
    total = len(all_attempts)
    unique_ips = len({a.get("source_ip") for a in all_attempts if a.get("source_ip") and a.get("source_ip") != "unknown"})
    lang_map = build_language_stats(all_attempts)
    language_rows = "".join(
        f"<li><span>{name}</span><strong>{count}</strong></li>" for name, count in sorted(lang_map.items())
    ) or "<li><span>aucune donnée</span><strong>0</strong></li>"

    chart_data = json.dumps(lang_map, ensure_ascii=False)

    rows_html = "".join(
        f"<tr><td>{a.get('recorded_at', '—')}</td><td>{a.get('bait_number', '—')}</td><td>{a.get('source_ip', '—')}</td><td>{a.get('language', '—')}</td><td>{a.get('risk_level', '—')}</td></tr>"
        for a in latest_attempts
    ) or "<tr><td colspan='5'>Aucune tentative enregistrée.</td></tr>"

    html = f"""
    <!DOCTYPE html>
    <html lang="fr">
    <head>
        <meta charset="utf-8" />
        <title>Mboa HoneyPot Dashboard</title>
        <style>
            :root {{
                --bg: #08131a;
                --panel: #112330;
                --panel-2: #183142;
                --text: #eaf6ff;
                --muted: #9ab7c7;
                --accent: #4fc3f7;
                --warn: #ffb74d;
                --danger: #f06292;
                --ok: #66bb6a;
            }}
            * {{ box-sizing: border-box; }}
            body {{
                margin: 0; font-family: Arial, sans-serif; background: var(--bg); color: var(--text);
                line-height: 1.5;
            }}
            .wrap {{ max-width: 1200px; margin: 32px auto; padding: 0 20px 40px; }}
            h1 {{ margin-bottom: 20px; }}
            .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 16px; }}
            .card {{ background: var(--panel); border: 1px solid #244a5c; border-radius: 12px; padding: 18px; box-shadow: 0 8px 20px rgba(0,0,0,.18); }}
            .label {{ color: var(--muted); font-size: 12px; text-transform: uppercase; letter-spacing: 0.08em; }}
            .value {{ font-size: 2rem; font-weight: 700; margin-top: 8px; }}
            .top-actions {{ display: flex; gap: 12px; margin: 18px 0 24px; flex-wrap: wrap; }}
            .btn {{ display: inline-block; padding: 10px 16px; border-radius: 999px; text-decoration: none; color: var(--text); background: linear-gradient(135deg, var(--accent), #6dd3ff); font-weight: 700; }}
            .btn.secondary {{ background: linear-gradient(135deg, var(--warn), #ffc857); }}
            .chart-wrap {{ margin-top: 24px; }}
            #languageChart {{ display: flex; flex-direction: column; gap: 10px; margin-top: 12px; }}
            .bar-row {{ display: grid; grid-template-columns: 120px 1fr 40px; align-items: center; gap: 10px; }}
            .bar-label {{ color: var(--muted); }}
            .bar-track {{ width: 100%; height: 18px; background: #1d3747; border-radius: 999px; overflow: hidden; }}
            .bar-fill {{ height: 100%; background: linear-gradient(90deg, var(--accent), var(--ok)); border-radius: 999px; }}
            .table-wrap {{ overflow-x: auto; margin-top: 24px; }}
            table {{ width: 100%; border-collapse: collapse; background: var(--panel); border-radius: 12px; overflow: hidden; }}
            th, td {{ padding: 12px 14px; border-bottom: 1px solid #244a5c; text-align: left; }}
            th {{ background: var(--panel-2); color: var(--muted); }}
            ul {{ list-style: none; padding: 0; margin: 0; }}
            li {{ display: flex; justify-content: space-between; padding: 8px 0; border-bottom: 1px solid #244a5c; }}
            .footer {{ margin-top: 24px; color: var(--muted); font-size: 0.9rem; }}
        </style>
    </head>
    <body>
        <div class="wrap">
            <h1>Mboa HoneyPot Dashboard</h1>

            <div class="top-actions">
                <a class="btn" href="/export/csv">Exporter CSV</a>
                <a class="btn secondary" href="/export/json">Exporter JSON</a>
            </div>

            <div class="grid">
                <div class="card"><div class="label">Tentatives</div><div class="value">{total}</div></div>
                <div class="card"><div class="label">IPs uniques</div><div class="value">{unique_ips}</div></div>
                <div class="card"><div class="label">Langues</div><div class="value">{len(lang_map)}</div></div>
            </div>

            <div class="card chart-wrap">
                <h3>Langue observée</h3>
                <div id="languageChart"></div>
            </div>

            <div class="card" style="margin-top: 24px;">
                <h3>Répartition par langue</h3>
                <ul>{language_rows}</ul>
            </div>

            <div class="table-wrap">
                <table>
                    <thead>
                        <tr>
                            <th>Temps</th>
                            <th>Bait number</th>
                            <th>IP</th>
                            <th>Langue</th>
                            <th>Risque</th>
                        </tr>
                    </thead>
                    <tbody>{rows_html}</tbody>
                </table>
            </div>
            <div class="footer">Données de test anonymisées. Aucune donnée personnelle n'est collectée.</div>
        </div>

        <script>
            const languageData = {chart_data};
            const chart = document.getElementById('languageChart');
            if (Object.keys(languageData).length > 0) {{
                const max = Math.max(...Object.values(languageData), 1);
                Object.entries(languageData).forEach(([language, count]) => {{
                    const row = document.createElement('div');
                    row.className = 'bar-row';
                    row.innerHTML = `
                        <div class="bar-label">${{language}}</div>
                        <div class="bar-track"><div class="bar-fill" style="width: ${{(count / max) * 100}}%"></div></div>
                        <div>${{count}}</div>
                    `;
                    chart.appendChild(row);
                }});
            }} else {{
                chart.innerHTML = '<p>Aucune donnée.</p>';
            }}
        </script>
    </body>
    </html>
    """
    return HTMLResponse(content=html)


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=False)