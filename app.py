import json
import os
import secrets
import tempfile
from datetime import datetime, timezone, timedelta
from functools import wraps
from pathlib import Path
from typing import Any, Dict, List, Optional

from authlib.integrations.flask_client import OAuth
from flask import Flask, jsonify, redirect, request, send_from_directory, session, url_for

BASE_DIR = Path(__file__).resolve().parent
PUBLIC_DIR = BASE_DIR / "public"
DATA_DIR = BASE_DIR / "data"
CONFIG_PATH = BASE_DIR / "config.json"

USERS_PATH = DATA_DIR / "user.json"
ROLES_PATH = DATA_DIR / "role.json"
USER_ROLES_PATH = DATA_DIR / "userrole.json"


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def safe_read_json(path: Path, fallback: Any) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return fallback


def atomic_write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    body = json.dumps(value, indent=2, ensure_ascii=False)
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False, dir=str(path.parent), suffix=".tmp") as f:
        tmp = Path(f.name)
        f.write(body)
        f.flush()
        os.fsync(f.fileno())
    tmp.replace(path)


def ensure_data_files() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    if not ROLES_PATH.exists():
        atomic_write_json(ROLES_PATH, {"roles": ["Mobius", "QA"]})
    if not USERS_PATH.exists():
        atomic_write_json(USERS_PATH, {"users": []})
    if not USER_ROLES_PATH.exists():
        atomic_write_json(USER_ROLES_PATH, {"userRoles": []})


def upsert_user_from_auth0(profile: Dict[str, Any]) -> Dict[str, Any]:
    store = safe_read_json(USERS_PATH, {"users": []})
    user_id = profile.get("sub")
    email = profile.get("email")
    if not user_id:
        return {}

    now = utc_now_iso()
    record = {
        "userId": user_id,
        "email": email,
        "auth0Id": user_id,
        "name": profile.get("name") or profile.get("nickname"),
        "nickname": profile.get("nickname"),
        "picture": profile.get("picture"),
        "updatedAt": now,
    }

    users = store.get("users") if isinstance(store, dict) else []
    if not isinstance(users, list):
        users = []

    idx = next((i for i, u in enumerate(users) if isinstance(u, dict) and u.get("userId") == user_id), -1)
    if idx == -1:
        record["createdAt"] = now
        users.append(record)
    else:
        merged = {**users[idx], **record}
        if "createdAt" not in merged:
            merged["createdAt"] = now
        users[idx] = merged

    atomic_write_json(USERS_PATH, {"users": users})
    return record


def get_user_role(user_id: str) -> Optional[str]:
    store = safe_read_json(USER_ROLES_PATH, {"userRoles": []})
    rows = store.get("userRoles") if isinstance(store, dict) else []
    if not isinstance(rows, list):
        return None
    for r in rows:
        if isinstance(r, dict) and r.get("userId") == user_id:
            role = r.get("role")
            return role if isinstance(role, str) and role else None
    return None


def set_user_role(user_id: str, role: str) -> Dict[str, Any]:
    store = safe_read_json(USER_ROLES_PATH, {"userRoles": []})
    rows = store.get("userRoles") if isinstance(store, dict) else []
    if not isinstance(rows, list):
        rows = []
    now = utc_now_iso()
    entry = {"userId": user_id, "role": role, "updatedAt": now}
    idx = next((i for i, r in enumerate(rows) if isinstance(r, dict) and r.get("userId") == user_id), -1)
    if idx == -1:
        rows.append(entry)
    else:
        rows[idx] = {**rows[idx], **entry}
    atomic_write_json(USER_ROLES_PATH, {"userRoles": rows})
    return entry


def parse_auth0_connections(raw: Optional[str]) -> List[Dict[str, str]]:
    if not raw:
        return []
    trimmed = str(raw).strip()
    if not trimmed:
        return []
    if trimmed.startswith("["):
        try:
            parsed = json.loads(trimmed)
        except Exception:
            return []
        if not isinstance(parsed, list):
            return []
        out: List[Dict[str, str]] = []
        for x in parsed:
            if not isinstance(x, dict):
                continue
            cid = x.get("id")
            label = x.get("label")
            if isinstance(cid, str) and isinstance(label, str) and cid.strip() and label.strip():
                out.append({"id": cid.strip(), "label": label.strip()})
        return out

    out2: List[Dict[str, str]] = []
    for pair in [p.strip() for p in trimmed.split(",") if p.strip()]:
        if ":" in pair:
            cid, label = pair.split(":", 1)
            cid = cid.strip()
            label = label.strip() or cid
        else:
            cid = pair.strip()
            label = cid
        if cid and label:
            out2.append({"id": cid, "label": label})
    return out2


def load_config() -> Dict[str, Any]:
    cfg = safe_read_json(CONFIG_PATH, None)
    if not isinstance(cfg, dict):
        raise RuntimeError("Missing or invalid config.json")
    return cfg


def get_cfg_str(obj: Any, key: str) -> Optional[str]:
    if not isinstance(obj, dict):
        return None
    v = obj.get(key)
    if isinstance(v, str) and v.strip():
        return v.strip()
    return None


def normalize_connections(value: Any) -> List[Dict[str, str]]:
    if isinstance(value, list):
        out: List[Dict[str, str]] = []
        for x in value:
            if not isinstance(x, dict):
                continue
            cid = x.get("id")
            label = x.get("label")
            if isinstance(cid, str) and isinstance(label, str) and cid.strip() and label.strip():
                out.append({"id": cid.strip(), "label": label.strip()})
        return out
    if isinstance(value, str):
        return parse_auth0_connections(value)
    return []

def public_configuration() -> Dict[str, Any]:
    auth0 = AUTH0_CFG if isinstance(AUTH0_CFG, dict) else {}
    return {
        "base_url": get_cfg_str(CONFIG, "base_url") or "http://localhost:3000",
        "port": CONFIG.get("port", 3000),
        "session_days": CONFIG.get("session_days", 7),
        "auth0": {
            "issuer_base_url": get_cfg_str(auth0, "issuer_base_url") or get_cfg_str(auth0, "issuerBaseURL"),
            "client_id": get_cfg_str(auth0, "client_id") or get_cfg_str(auth0, "clientID"),
            "connections": normalize_connections(auth0.get("connections")),
        },
    }

app = Flask(__name__, static_folder=None)

CONFIG = load_config()
AUTH0_CFG = CONFIG.get("auth0") if isinstance(CONFIG.get("auth0"), dict) else {}

app.secret_key = (
    get_cfg_str(CONFIG, "flask_secret_key")
    or get_cfg_str(AUTH0_CFG, "secret")
    or secrets.token_hex(32)
)

try:
    session_days_raw = CONFIG.get("session_days", 7)
    session_days = int(session_days_raw)
    if session_days < 1:
        session_days = 7
except Exception:
    session_days = 7
app.permanent_session_lifetime = timedelta(days=session_days)

ensure_data_files()

oauth = OAuth(app)
issuer = get_cfg_str(AUTH0_CFG, "issuer_base_url") or get_cfg_str(AUTH0_CFG, "issuerBaseURL")
if issuer:
    issuer = issuer.rstrip("/")

client_id = get_cfg_str(AUTH0_CFG, "client_id") or get_cfg_str(AUTH0_CFG, "clientID")
client_secret = get_cfg_str(AUTH0_CFG, "client_secret") or get_cfg_str(AUTH0_CFG, "clientSecret")

if issuer and client_id and client_secret:
    oauth.register(
        "auth0",
        client_id=client_id,
        client_secret=client_secret,
        server_metadata_url=f"{issuer}/.well-known/openid-configuration",
        client_kwargs={"scope": "openid profile email"},
    )


def is_authenticated() -> bool:
    u = session.get("user")
    return isinstance(u, dict) and bool(u.get("sub"))


def require_auth_page(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not is_authenticated():
            return redirect(url_for("root"))
        return fn(*args, **kwargs)

    return wrapper


def require_role_page(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not is_authenticated():
            return redirect(url_for("root"))
        if not session.get("userRole"):
            return redirect("/roles.html")
        return fn(*args, **kwargs)

    return wrapper


def require_auth_api(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not is_authenticated():
            return jsonify({"error": "Unauthorized"}), 401
        return fn(*args, **kwargs)

    return wrapper


@app.get("/")
def root():
    if is_authenticated():
        return redirect("/app")
    if "auth0" in oauth._registry and not session.get("silent_failed"):
        nonce = secrets.token_urlsafe(16)
        session["nonce"] = nonce
        session["return_to"] = "/app"
        session["silent_attempted"] = True
        return oauth.auth0.authorize_redirect(
            redirect_uri=url_for("callback", _external=True), nonce=nonce, prompt="none"
        )
    return send_from_directory(str(PUBLIC_DIR), "login.html")

@app.get("/configuration.json")
def configuration_json():
    return jsonify(public_configuration())


@app.get("/login")
def login():
    if "auth0" not in oauth._registry:
        return jsonify({"error": "Auth0 not configured"}), 500
    session.pop("silent_failed", None)
    session.pop("silent_attempted", None)
    return_to = request.args.get("returnTo") or "/app"
    session["return_to"] = return_to
    nonce = secrets.token_urlsafe(16)
    session["nonce"] = nonce
    return oauth.auth0.authorize_redirect(redirect_uri=url_for("callback", _external=True), nonce=nonce)


@app.get("/login/<connection>")
def login_connection(connection: str):
    if "auth0" not in oauth._registry:
        return jsonify({"error": "Auth0 not configured"}), 500
    session.pop("silent_failed", None)
    session.pop("silent_attempted", None)
    return_to = request.args.get("returnTo") or "/app"
    session["return_to"] = return_to
    nonce = secrets.token_urlsafe(16)
    session["nonce"] = nonce
    return oauth.auth0.authorize_redirect(
        redirect_uri=url_for("callback", _external=True), connection=connection, nonce=nonce
    )


@app.get("/callback")
def callback():
    if "auth0" not in oauth._registry:
        return jsonify({"error": "Auth0 not configured"}), 500

    if request.args.get("error"):
        session.pop("nonce", None)
        session.pop("return_to", None)
        session["silent_failed"] = True
        return redirect(url_for("root"))

    token = oauth.auth0.authorize_access_token()
    if isinstance(token, dict):
        session["oauth_token"] = {
            "access_token": token.get("access_token"),
            "token_type": token.get("token_type"),
            "expires_in": token.get("expires_in"),
            "expires_at": token.get("expires_at"),
            "scope": token.get("scope"),
            "refresh_token": token.get("refresh_token"),
            "id_token": token.get("id_token"),
        }
    nonce = session.pop("nonce", None)
    user_dict: Dict[str, Any] = {}
    try:
        if isinstance(nonce, str) and nonce:
            user = oauth.auth0.parse_id_token(token, nonce)
            user_dict = dict(user) if user else {}
        else:
            raise TypeError("missing nonce")
    except TypeError:
        resp = oauth.auth0.get("userinfo")
        if resp is not None and resp.status_code == 200:
            user_dict = resp.json() if isinstance(resp.json(), dict) else {}
        else:
            return redirect(url_for("root"))

    if user_dict.get("sub"):
        upsert_user_from_auth0(user_dict)
        role = get_user_role(user_dict["sub"])
    else:
        role = None

    session.permanent = True
    session["user"] = user_dict
    session["userRole"] = role
    session.pop("silent_failed", None)
    session.pop("silent_attempted", None)

    target = session.pop("return_to", "/app")
    if target == "/app" and not role:
        return redirect("/roles.html")
    return redirect(target)


@app.get("/logout")
def logout():
    return_to = request.args.get("returnTo") or "/"
    session.clear()
    if not issuer or not client_id:
        return redirect(return_to)
    base_url = get_cfg_str(CONFIG, "base_url") or request.host_url.rstrip("/")
    rt = f"{base_url}{return_to}" if return_to.startswith("/") else return_to
    return redirect(f"{issuer}/v2/logout?client_id={client_id}&returnTo={rt}")


@app.get("/roles.html")
@require_auth_page
def roles_page():
    return send_from_directory(str(PUBLIC_DIR), "roles.html")


@app.get("/app")
@require_role_page
def app_entry():
    return redirect("/XV_CDA_v4.2.html")


@app.get("/XV_CDA_v4.2.html")
@require_role_page
def xv_cda_v42():
    return send_from_directory(str(BASE_DIR), "XV_CDA_v4.2.html")


@app.get("/xv_cda_v4.2.html")
@require_role_page
def xv_cda_v42_lower():
    return redirect("/XV_CDA_v4.2.html")


@app.get("/xv_cda_v4.2html")
@require_role_page
def xv_cda_v42_no_dot():
    return redirect("/XV_CDA_v4.2.html")


@app.get("/XV_CDA_v3.3.html")
@require_role_page
def xv_cda_v33():
    return send_from_directory(str(BASE_DIR), "XV_CDA_v3.3.html")


@app.get("/api/me")
@require_auth_api
def api_me():
    user = session.get("user") if isinstance(session.get("user"), dict) else {}
    user_id = user.get("sub")
    role = session.get("userRole")
    if not role and isinstance(user_id, str) and user_id:
        role = get_user_role(user_id)
        session["userRole"] = role
    return jsonify(
        {
            "userId": user_id,
            "email": user.get("email"),
            "role": role,
            "isAuthenticated": True,
        }
    )


@app.get("/api/auth-connections")
def api_auth_connections():
    configured = normalize_connections(AUTH0_CFG.get("connections") if isinstance(AUTH0_CFG, dict) else None)
    fallback = [
        {"id": "google-oauth2", "label": "Google"},
        {"id": "windowslive", "label": "Microsoft"},
    ]
    return jsonify({"connections": configured or fallback})


@app.get("/api/roles")
@require_auth_api
def api_roles():
    ensure_data_files()
    return jsonify(safe_read_json(ROLES_PATH, {"roles": []}))


@app.get("/api/users")
@require_auth_api
def api_users():
    ensure_data_files()
    return jsonify(safe_read_json(USERS_PATH, {"users": []}))


@app.get("/api/userroles")
@require_auth_api
def api_userroles():
    ensure_data_files()
    return jsonify(safe_read_json(USER_ROLES_PATH, {"userRoles": []}))


@app.post("/api/userroles")
@require_auth_api
def api_set_userrole():
    ensure_data_files()
    payload = request.get_json(silent=True) or {}
    role = payload.get("role")
    user_id = payload.get("userId")
    email = payload.get("email")

    roles_store = safe_read_json(ROLES_PATH, {"roles": []})
    roles = roles_store.get("roles") if isinstance(roles_store, dict) else []
    if not isinstance(role, str) or role not in roles:
        return jsonify({"error": "Invalid role"}), 400

    users_store = safe_read_json(USERS_PATH, {"users": []})
    users = users_store.get("users") if isinstance(users_store, dict) else []
    if not isinstance(users, list):
        users = []

    normalized_email = email.strip().lower() if isinstance(email, str) else ""
    resolved_user_id = None
    if isinstance(user_id, str) and user_id.strip():
        resolved_user_id = user_id.strip()
    elif normalized_email:
        for u in users:
            if not isinstance(u, dict):
                continue
            u_email = (u.get("email") or "").strip().lower()
            if u_email and u_email == normalized_email:
                resolved_user_id = u.get("userId")
                break

    if not isinstance(resolved_user_id, str) or not resolved_user_id:
        return jsonify({"error": "Missing userId/email"}), 400

    entry = set_user_role(resolved_user_id, role)

    me = session.get("user") if isinstance(session.get("user"), dict) else {}
    if me.get("sub") == resolved_user_id:
        session["userRole"] = role

    return jsonify(entry)


if __name__ == "__main__":
    port = int(CONFIG.get("port") or 3000) if isinstance(CONFIG.get("port"), (int, str)) else 3000
    app.run(host="0.0.0.0", port=port, debug=False)
