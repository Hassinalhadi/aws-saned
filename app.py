import os
import json
import time
import secrets
import sqlite3
from datetime import datetime, timezone
from functools import wraps
from flask import Flask, request, jsonify, render_template_string, Response

app = Flask(__name__)

DB_PATH = os.environ.get("DB_PATH", "licenses.db")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "admin123")
RESELLER_PASSWORD = os.environ.get("RESELLER_PASSWORD", "saned2026")
MASTER_TOKEN = os.environ.get("MASTER_TOKEN", "AWS-PRO-MASTER-2026")


def now_ms() -> int:
    return int(time.time() * 1000)


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with get_db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS licenses (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                token TEXT UNIQUE NOT NULL,
                period_days INTEGER NOT NULL DEFAULT 30,
                device_id TEXT DEFAULT NULL,
                activated_at INTEGER DEFAULT NULL,
                expires_at INTEGER DEFAULT NULL,
                is_active INTEGER NOT NULL DEFAULT 1,
                note TEXT DEFAULT '',
                created_by TEXT DEFAULT 'admin',
                created_at INTEGER NOT NULL
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS telemetry_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp INTEGER,
                tag TEXT,
                order_id TEXT,
                device_id TEXT,
                url TEXT,
                method TEXT,
                http_code INTEGER,
                response_body TEXT,
                duration_ms INTEGER,
                error TEXT,
                raw_json TEXT,
                created_at INTEGER NOT NULL
            )
        """)
        # Ensure default master token exists for immediate testing
        cur = conn.execute("SELECT id FROM licenses WHERE token = ?", (MASTER_TOKEN,))
        if not cur.fetchone():
            conn.execute(
                """
                INSERT INTO licenses (token, period_days, is_active, note, created_by, created_at)
                VALUES (?, ?, 1, ?, 'system', ?)
                """,
                (MASTER_TOKEN, 365, "كود افتراضي للتجربة السريعة", now_ms()),
            )
        conn.commit()


init_db()


def compute_days_left(expires_at_ms: int) -> int:
    if not expires_at_ms:
        return 0
    diff_ms = expires_at_ms - now_ms()
    if diff_ms <= 0:
        return 0
    return max(1, int((diff_ms + 86399999) // 86400000))


# =====================================================================
# 1. APK LICENSE ENDPOINTS (100% Matched to VerificationManager in DEX)
# =====================================================================

@app.route("/api/activate", methods=["POST"])
def api_activate():
    data = request.get_json(silent=True) or {}
    token = str(data.get("token") or "").strip()
    device_id = str(data.get("device_id") or "").strip()

    if len(token) < 6:
        return jsonify({
            "success": False,
            "unlocked": False,
            "message": "كود التفعيل غير صالح",
            "expires_at": 0,
            "days_left": 0,
            "period_days": 0
        }), 200

    if not device_id:
        device_id = "UNKNOWN_DEVICE"

    with get_db() as conn:
        row = conn.execute("SELECT * FROM licenses WHERE UPPER(token) = UPPER(?)", (token,)).fetchone()
        if not row:
            return jsonify({
                "success": False,
                "unlocked": False,
                "message": "كود التفعيل غير موجود في السيرفر",
                "expires_at": 0,
                "days_left": 0,
                "period_days": 0
            }), 200

        if not row["is_active"]:
            return jsonify({
                "success": False,
                "unlocked": False,
                "message": "تم إيقاف هذا الكود من قبل الإدارة",
                "expires_at": 0,
                "days_left": 0,
                "period_days": int(row["period_days"])
            }), 200

        bound_device = row["device_id"]
        if bound_device and bound_device != device_id:
            return jsonify({
                "success": False,
                "unlocked": False,
                "message": "هذا الكود مستخدم بالفعل على جهاز آخر",
                "expires_at": 0,
                "days_left": 0,
                "period_days": int(row["period_days"])
            }), 200

        current_ms = now_ms()
        period_days = int(row["period_days"] or 30)
        expires_at = row["expires_at"]
        activated_at = row["activated_at"]

        # First activation sets activated_at and expires_at (in milliseconds!)
        if not expires_at:
            activated_at = current_ms
            expires_at = current_ms + (period_days * 86400 * 1000)

        if expires_at <= current_ms:
            return jsonify({
                "success": False,
                "unlocked": False,
                "message": "انتهت صلاحية هذا الاشتراك",
                "expires_at": 0,
                "days_left": 0,
                "period_days": period_days
            }), 200

        conn.execute(
            """
            UPDATE licenses
            SET device_id = ?, activated_at = ?, expires_at = ?
            WHERE id = ?
            """,
            (device_id, activated_at, expires_at, row["id"]),
        )
        conn.commit()

        days_left = compute_days_left(expires_at)
        return jsonify({
            "success": True,
            "unlocked": True,
            "message": f"تم التفعيل بنجاح! المتبقي {days_left} يوم",
            "expires_at": int(expires_at),
            "days_left": int(days_left),
            "period_days": int(period_days)
        }), 200


@app.route("/api/verify", methods=["POST"])
def api_verify():
    data = request.get_json(silent=True) or {}
    token = str(data.get("token") or "").strip()
    device_id = str(data.get("device_id") or "").strip()

    if not token:
        return jsonify({
            "success": False,
            "unlocked": False,
            "message": "لا يوجد كود تفعيل نشط",
            "expires_at": 0,
            "days_left": 0,
            "period_days": 0
        }), 200

    with get_db() as conn:
        row = conn.execute("SELECT * FROM licenses WHERE UPPER(token) = UPPER(?)", (token,)).fetchone()
        if not row or not row["is_active"]:
            return jsonify({
                "success": False,
                "unlocked": False,
                "message": "الكود غير صالح أو تم إيقافه",
                "expires_at": 0,
                "days_left": 0,
                "period_days": 0
            }), 200

        bound_device = row["device_id"]
        if bound_device and device_id and bound_device != device_id:
            return jsonify({
                "success": False,
                "unlocked": False,
                "message": "الكود مرتبط بجهاز آخر",
                "expires_at": 0,
                "days_left": 0,
                "period_days": int(row["period_days"])
            }), 200

        current_ms = now_ms()
        period_days = int(row["period_days"] or 30)
        expires_at = row["expires_at"]
        if not expires_at:
            expires_at = current_ms + (period_days * 86400 * 1000)
            conn.execute(
                "UPDATE licenses SET device_id = ?, activated_at = ?, expires_at = ? WHERE id = ?",
                (device_id or bound_device, current_ms, expires_at, row["id"]),
            )
            conn.commit()

        if expires_at <= current_ms:
            return jsonify({
                "success": False,
                "unlocked": False,
                "message": "انتهت صلاحية الاشتراك",
                "expires_at": 0,
                "days_left": 0,
                "period_days": period_days
            }), 200

        days_left = compute_days_left(expires_at)
        return jsonify({
            "success": True,
            "unlocked": True,
            "message": "Verified",
            "expires_at": int(expires_at),
            "days_left": int(days_left),
            "period_days": int(period_days)
        }), 200


# =====================================================================
# 2. TELEMETRY & LOGS ENDPOINT (Matched to SanedAutoAcceptHelper)
# =====================================================================

@app.route("/api/logs", methods=["POST"])
def api_logs():
    payload = request.get_json(silent=True)
    if payload is None:
        return jsonify({"success": True, "saved": 0}), 200

    items = payload if isinstance(payload, list) else [payload]
    saved = 0
    current_ms = now_ms()

    with get_db() as conn:
        for item in items:
            if not isinstance(item, dict):
                continue
            conn.execute(
                """
                INSERT INTO telemetry_logs (
                    timestamp, tag, order_id, device_id, url, method,
                    http_code, response_body, duration_ms, error, raw_json, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    item.get("timestamp") or current_ms,
                    str(item.get("tag") or "")[:64],
                    str(item.get("orderId") or "")[:64],
                    str(item.get("deviceId") or "")[:64],
                    str(item.get("url") or "")[:512],
                    str(item.get("method") or "GET")[:16],
                    int(item.get("httpCode") or 0),
                    str(item.get("responseBody") or "")[:2000],
                    int(item.get("durationMs") or 0),
                    str(item.get("error") or "")[:1000],
                    json.dumps(item, ensure_ascii=False)[:4000],
                    current_ms,
                ),
            )
            saved += 1
        # Keep latest 500 logs to prevent SQLite bloat on free tier
        conn.execute("""
            DELETE FROM telemetry_logs
            WHERE id NOT IN (SELECT id FROM telemetry_logs ORDER BY id DESC LIMIT 500)
        """)
        conn.commit()

    return jsonify({"success": True, "saved": saved}), 200


@app.route("/health", methods=["GET"])
@app.route("/ping", methods=["GET"])
def health():
    return jsonify({"status": "ok", "timestamp": now_ms()}), 200


# =====================================================================
# 3. RESELLER & ADMIN API + RTL WEB DASHBOARD (/reseller & /)
# =====================================================================

def check_auth():
    pwd = (
        request.headers.get("X-Admin-Key")
        or request.args.get("key")
        or (request.get_json(silent=True) or {}).get("auth_key")
        or ""
    )
    if pwd in (ADMIN_PASSWORD, RESELLER_PASSWORD):
        return True
    return False


@app.route("/api/reseller/licenses", methods=["GET"])
def list_licenses():
    if not check_auth():
        return jsonify({"success": False, "message": "غير مصرح - كلمة المرور غير صحيحة"}), 401
    with get_db() as conn:
        rows = conn.execute("SELECT * FROM licenses ORDER BY id DESC").fetchall()
        result = []
        for r in rows:
            exp = r["expires_at"]
            result.append({
                "id": r["id"],
                "token": r["token"],
                "period_days": r["period_days"],
                "device_id": r["device_id"] or "",
                "activated_at": r["activated_at"],
                "expires_at": exp,
                "days_left": compute_days_left(exp) if exp else r["period_days"],
                "is_active": bool(r["is_active"]),
                "note": r["note"] or "",
                "created_at": r["created_at"],
            })
        return jsonify({"success": True, "licenses": result}), 200


@app.route("/api/reseller/generate", methods=["POST"])
def generate_licenses():
    if not check_auth():
        return jsonify({"success": False, "message": "غير مصرح"}), 401
    data = request.get_json(silent=True) or {}
    period_days = max(1, int(data.get("period_days") or 30))
    count = min(50, max(1, int(data.get("count") or 1)))
    prefix = str(data.get("prefix") or "AWS").strip().upper()
    note = str(data.get("note") or "").strip()
    custom_token = str(data.get("custom_token") or "").strip()

    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    created = []
    with get_db() as conn:
        for i in range(count):
            if count == 1 and len(custom_token) >= 6:
                tok = custom_token
            else:
                part1 = "".join(secrets.choice(alphabet) for _ in range(4))
                part2 = "".join(secrets.choice(alphabet) for _ in range(4))
                part3 = "".join(secrets.choice(alphabet) for _ in range(4))
                tok = f"{prefix}-{part1}-{part2}-{part3}" if prefix else f"{part1}{part2}{part3}"
            conn.execute(
                """
                INSERT INTO licenses (token, period_days, is_active, note, created_by, created_at)
                VALUES (?, ?, 1, ?, 'reseller', ?)
                """,
                (tok, period_days, note, now_ms()),
            )
            created.append(tok)
        conn.commit()
    return jsonify({"success": True, "tokens": created, "period_days": period_days}), 200


@app.route("/api/reseller/action", methods=["POST"])
def license_action():
    if not check_auth():
        return jsonify({"success": False, "message": "غير مصرح"}), 401
    data = request.get_json(silent=True) or {}
    lic_id = int(data.get("id") or 0)
    action = str(data.get("action") or "")

    with get_db() as conn:
        row = conn.execute("SELECT * FROM licenses WHERE id = ?", (lic_id,)).fetchone()
        if not row:
            return jsonify({"success": False, "message": "الكود غير موجود"}), 404

        if action == "reset_device":
            conn.execute("UPDATE licenses SET device_id = NULL WHERE id = ?", (lic_id,))
        elif action == "toggle_active":
            new_state = 0 if row["is_active"] else 1
            conn.execute("UPDATE licenses SET is_active = ? WHERE id = ?", (new_state, lic_id))
        elif action == "add_days":
            extra = int(data.get("days") or 30)
            base_exp = max(row["expires_at"] or now_ms(), now_ms())
            new_exp = base_exp + (extra * 86400 * 1000)
            conn.execute(
                "UPDATE licenses SET expires_at = ?, period_days = period_days + ? WHERE id = ?",
                (new_exp, extra, lic_id),
            )
        elif action == "delete":
            conn.execute("DELETE FROM licenses WHERE id = ?", (lic_id,))
        conn.commit()

    return jsonify({"success": True}), 200


@app.route("/api/reseller/logs", methods=["GET"])
def list_logs():
    if not check_auth():
        return jsonify({"success": False, "message": "غير مصرح"}), 401
    with get_db() as conn:
        rows = conn.execute("SELECT * FROM telemetry_logs ORDER BY id DESC LIMIT 100").fetchall()
        logs = [dict(r) for r in rows]
        return jsonify({"success": True, "logs": logs}), 200


DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
<title>AWS PRO — لوحة تحكم الموزعين والتراخيص</title>
<style>
  :root {
    --bg: #0b1120;
    --card: #111827;
    --border: #1e293b;
    --primary: #10b981;
    --primary-hover: #059669;
    --danger: #ef4444;
    --warn: #f59e0b;
    --text: #f8fafc;
    --muted: #94a3b8;
  }
  * { box-sizing: border-box; font-family: system-ui, -apple-system, 'Segoe UI', Tahoma, sans-serif; }
  body { margin: 0; padding: 16px; background: var(--bg); color: var(--text); }
  .container { max-width: 960px; margin: 0 auto; }
  .card { background: var(--card); border: 1px solid var(--border); border-radius: 14px; padding: 16px; margin-bottom: 16px; }
  h1 { font-size: 1.35rem; margin: 0 0 6px 0; color: var(--primary); }
  .sub { color: var(--muted); font-size: 0.88rem; margin-bottom: 14px; }
  .row { display: flex; gap: 10px; flex-wrap: wrap; align-items: center; }
  input, select, button {
    padding: 10px 12px; border-radius: 10px; border: 1px solid var(--border);
    background: #0f172a; color: var(--text); font-size: 0.92rem;
  }
  input, select { flex: 1; min-width: 130px; }
  button {
    background: var(--primary); color: #042f2e; font-weight: 700;
    border: none; cursor: pointer; transition: 0.15s;
  }
  button:hover { background: var(--primary-hover); color: #fff; }
  .btn-sm { padding: 6px 10px; font-size: 0.8rem; border-radius: 8px; }
  .btn-warn { background: var(--warn); color: #1e1b4b; }
  .btn-danger { background: var(--danger); color: #fff; }
  .btn-outline { background: #1e293b; color: var(--text); }
  .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(130px, 1fr)); gap: 10px; margin-bottom: 16px; }
  .stat-box { background: #0f172a; border: 1px solid var(--border); padding: 12px; border-radius: 12px; text-align: center; }
  .stat-num { font-size: 1.4rem; font-weight: 800; color: var(--primary); }
  .stat-label { font-size: 0.8rem; color: var(--muted); }
  table { width: 100%; border-collapse: collapse; font-size: 0.86rem; }
  th, td { padding: 10px 8px; border-bottom: 1px solid var(--border); text-align: right; }
  th { color: var(--muted); font-weight: 600; }
  .badge { padding: 3px 8px; border-radius: 99px; font-size: 0.75rem; font-weight: 700; }
  .b-ok { background: rgba(16,185,129,0.18); color: #34d399; }
  .b-off { background: rgba(239,68,68,0.18); color: #f87171; }
  .b-new { background: rgba(59,130,246,0.18); color: #60a5fa; }
  .mono { font-family: monospace; direction: ltr; display: inline-block; font-weight: 700; color: #38bdf8; }
  .hidden { display: none; }
</style>
</head>
<body>
<div class="container">
  <div class="card" id="loginCard">
    <h1>AWS PRO — بوابة التراخيص والموزعين</h1>
    <div class="sub">أدخل كلمة مرور الإدارة أو الموزع للوصول إلى لوحة التحكم (الافتراضية: <code>saned2026</code> أو <code>admin123</code>)</div>
    <div class="row">
      <input type="password" id="authKey" placeholder="كلمة المرور..." />
      <button onclick="login()">دخول للوحة التحكم</button>
    </div>
  </div>

  <div id="mainApp" class="hidden">
    <div class="card">
      <div class="row" style="justify-content: space-between;">
        <div>
          <h1>لوحة تحكم AWS PRO</h1>
          <div class="sub">إدارة أكواد التفعيل، فك ارتباط الأجهزة، ومتابعة حالة السيرفر</div>
        </div>
        <button class="btn-outline btn-sm" onclick="logout()">تسجيل خروج</button>
      </div>
      <div class="stats">
        <div class="stat-box"><div class="stat-num" id="stTotal">0</div><div class="stat-label">إجمالي الأكواد</div></div>
        <div class="stat-box"><div class="stat-num" id="stBound">0</div><div class="stat-label">أجهزة مفعّلة</div></div>
        <div class="stat-box"><div class="stat-num" id="stUnused">0</div><div class="stat-label">أكواد جاهزة</div></div>
      </div>
    </div>

    <div class="card">
      <h1>توليد أكواد تفعيل جديدة</h1>
      <div class="row" style="margin-top:10px;">
        <select id="genDays">
          <option value="1">1 يوم (تجريبي)</option>
          <option value="7">7 أيام (أسبوعي)</option>
          <option value="30" selected>30 يوم (شهري)</option>
          <option value="90">90 يوم (3 أشهر)</option>
          <option value="365">365 يوم (سنوي)</option>
        </select>
        <input type="number" id="genCount" value="1" min="1" max="50" placeholder="العدد" style="max-width:95px;" />
        <input type="text" id="genNote" placeholder="ملاحظة / اسم العميل (اختياري)" />
        <input type="text" id="genCustom" placeholder="كود مخصص (اختياري)" />
        <button onclick="generateKeys()">+ توليد الآن</button>
      </div>
      <div id="newTokensBox" class="hidden" style="margin-top:12px; padding:10px; background:#064e3b; border-radius:10px;"></div>
    </div>

    <div class="card" style="overflow-x:auto;">
      <div class="row" style="justify-content: space-between; margin-bottom:10px;">
        <h1>قائمة التراخيص والأجهزة</h1>
        <button class="btn-outline btn-sm" onclick="loadLicenses()">تحديث القائمة</button>
      </div>
      <table>
        <thead>
          <tr>
            <th>الكود (Token)</th>
            <th>الحالة</th>
            <th>المتبقي</th>
            <th>معرّف الجهاز (Device ID)</th>
            <th>ملاحظة</th>
            <th>إجراءات</th>
          </tr>
        </thead>
        <tbody id="licBody"></tbody>
      </table>
    </div>
  </div>
</div>

<script>
let AUTH_KEY = localStorage.getItem('aws_pro_key') || '';

async function api(path, method='GET', body=null) {
  const opts = { method, headers: { 'Content-Type': 'application/json', 'X-Admin-Key': AUTH_KEY } };
  if (body) opts.body = JSON.stringify(body);
  const res = await fetch(path, opts);
  return { status: res.status, data: await res.json() };
}

async function login() {
  const val = document.getElementById('authKey').value.trim();
  if (!val) return;
  AUTH_KEY = val;
  const r = await api('/api/reseller/licenses');
  if (r.status === 200 && r.data.success) {
    localStorage.setItem('aws_pro_key', AUTH_KEY);
    document.getElementById('loginCard').classList.add('hidden');
    document.getElementById('mainApp').classList.remove('hidden');
    renderLicenses(r.data.licenses);
  } else {
    alert(r.data.message || 'كلمة المرور غير صحيحة');
  }
}

function logout() {
  localStorage.removeItem('aws_pro_key');
  location.reload();
}

async function loadLicenses() {
  const r = await api('/api/reseller/licenses');
  if (r.status === 200 && r.data.success) {
    renderLicenses(r.data.licenses);
  }
}

function renderLicenses(list) {
  document.getElementById('stTotal').textContent = list.length;
  document.getElementById('stBound').textContent = list.filter(x => x.device_id).length;
  document.getElementById('stUnused').textContent = list.filter(x => !x.device_id && x.is_active).length;

  const tbody = document.getElementById('licBody');
  tbody.innerHTML = list.map(item => {
    let badge = '<span class="badge b-new">جديد</span>';
    if (!item.is_active) badge = '<span class="badge b-off">موقوف</span>';
    else if (item.expires_at && item.days_left <= 0) badge = '<span class="badge b-off">منتهي</span>';
    else if (item.device_id) badge = '<span class="badge b-ok">مفعّل</span>';

    return `<tr>
      <td><span class="mono" onclick="copyText('${item.token}')" style="cursor:pointer;" title="اضغط للنسخ">${item.token}</span></td>
      <td>${badge}</td>
      <td>${item.days_left} يوم</td>
      <td><span class="mono" style="color:#cbd5e1;font-size:0.78rem;">${item.device_id || '— غير مرتبط —'}</span></td>
      <td>${item.note || ''}</td>
      <td>
        <div class="row" style="gap:4px;">
          <button class="btn-outline btn-sm" onclick="copyText('${item.token}')">نسخ</button>
          <button class="btn-warn btn-sm" onclick="doAction(${item.id}, 'reset_device')">فك الجهاز</button>
          <button class="btn-outline btn-sm" onclick="doAction(${item.id}, 'toggle_active')">${item.is_active ? 'إيقاف' : 'تفعيل'}</button>
          <button class="btn-danger btn-sm" onclick="doAction(${item.id}, 'delete')">حذف</button>
        </div>
      </td>
    </tr>`;
  }).join('');
}

async function generateKeys() {
  const period_days = parseInt(document.getElementById('genDays').value || '30', 10);
  const count = parseInt(document.getElementById('genCount').value || '1', 10);
  const note = document.getElementById('genNote').value.trim();
  const custom_token = document.getElementById('genCustom').value.trim();
  const r = await api('/api/reseller/generate', 'POST', { period_days, count, note, custom_token });
  if (r.status === 200 && r.data.success) {
    const box = document.getElementById('newTokensBox');
    box.classList.remove('hidden');
    box.innerHTML = '<b>تم التوليد بنجاح (اضغط للنسخ):</b><br>' + r.data.tokens.map(t => `<span class="mono" style="margin:4px 8px;cursor:pointer;" onclick="copyText('${t}')">${t}</span>`).join(' ');
    document.getElementById('genCustom').value = '';
    loadLicenses();
  }
}

async function doAction(id, action) {
  if (action === 'delete' && !confirm('هل أنت متأكد من حذف هذا الكود؟')) return;
  await api('/api/reseller/action', 'POST', { id, action });
  loadLicenses();
}

function copyText(txt) {
  navigator.clipboard.writeText(txt);
  alert('تم نسخ الكود: ' + txt);
}

if (AUTH_KEY) {
  document.getElementById('authKey').value = AUTH_KEY;
  login();
}
</script>
</body>
</html>
"""


@app.route("/", methods=["GET"])
@app.route("/reseller", methods=["GET"])
@app.route("/admin", methods=["GET"])
def reseller_dashboard():
    return Response(DASHBOARD_HTML, mimetype="text/html; charset=utf-8")


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port)