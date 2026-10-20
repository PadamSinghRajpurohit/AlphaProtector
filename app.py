import streamlit as st
import pandas as pd
import altair as alt
import json
import os
import hashlib
import re
import smtplib
import socket
import urllib.error
import urllib.parse
import urllib.request

try:
    import dns.resolver as _dns_resolver
    _DNS_AVAILABLE = True
except ImportError:
    _DNS_AVAILABLE = False

# ── Page config ──────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="AlphaProtector",
    page_icon="🛡️",
    layout="wide",
)

# ── File-based user backend ───────────────────────────────────────────────────
# Accounts are stored in users.json so they survive Streamlit reruns.
# Passwords are hashed with SHA-256 before saving.
USERS_FILE = "users.json"

def _hash(password: str) -> str:
    """Return SHA-256 hex digest of password."""
    return hashlib.sha256(password.encode()).hexdigest()

def load_users() -> dict:
    """Load users from users.json. Returns {username: hashed_password}."""
    if not os.path.exists(USERS_FILE):
        # A first run starts with no accounts; users register through the app.
        return {}
    with open(USERS_FILE, "r") as f:
        return json.load(f)

def save_users(users: dict) -> None:
    """Write the users dict back to users.json."""
    with open(USERS_FILE, "w") as f:
        json.dump(users, f, indent=4)

def check_password(username: str, password: str) -> bool:
    """Return True if username exists and password matches."""
    users = load_users()
    return username in users and users[username] == _hash(password)

def register_user(username: str, password: str, email: str = "") -> bool:
    """
    Add a new user. Returns True if successful, False if username already taken.
    Saves immediately to users.json so the account persists across reruns.
    Also stores email in users_meta.json.
    """
    users = load_users()
    if username in users:
        return False            # username already taken
    users[username] = _hash(password)
    save_users(users)
    # save email metadata
    meta = load_meta()
    meta[username] = {"email": email}
    save_meta(meta)
    return True

# ── Email metadata backend ────────────────────────────────────────────────────
META_FILE = "users_meta.json"

def load_meta() -> dict:
    """Load {username: {email: ...}} from users_meta.json."""
    if not os.path.exists(META_FILE):
        return {}
    with open(META_FILE, "r") as f:
        return json.load(f)

def save_meta(meta: dict) -> None:
    """Write metadata back to users_meta.json."""
    with open(META_FILE, "w") as f:
        json.dump(meta, f, indent=4)

def get_email(username: str) -> str:
    """Return the stored email for a username, or empty string."""
    return load_meta().get(username, {}).get("email", "")

# ── Email validation ──────────────────────────────────────────────────────────
# Three levels of checking:
#   Level 1 – Format check  : does it look like name@domain.tld ?
#   Level 2 – Domain MX check: does the domain have a mail server?
#   Level 3 – SMTP check    : does the mail server accept the address?

def _is_valid_format(email: str) -> bool:
    """Basic regex check for a valid email format."""
    pattern = r"^[a-zA-Z0-9_.+\-]+@[a-zA-Z0-9\-]+\.[a-zA-Z]{2,}$"
    return bool(re.match(pattern, email))

def _get_mx_host(domain: str) -> str | None:
    """
    Look up the MX (Mail Exchange) DNS record for the domain.
    Returns the mail server hostname, or None if not found.
    Requires the dnspython library.
    """
    if not _DNS_AVAILABLE:
        return None
    try:
        records = _dns_resolver.resolve(domain, "MX")
        # Pick the record with the lowest preference (highest priority)
        best = sorted(records, key=lambda r: r.preference)[0]
        return str(best.exchange).rstrip(".")
    except Exception:
        return None

def _smtp_verify(mx_host: str, email: str, timeout: int = 5) -> bool:
    """
    Connect to the mail server and ask if it accepts mail for this address.
    Uses SMTP VRFY / RCPT TO — many servers return True even for unknown
    addresses (greylisting), so a True here means "server is reachable".
    A False or exception means the domain/server is unreachable.
    """
    try:
        with smtplib.SMTP(mx_host, 25, timeout=timeout) as smtp:
            smtp.ehlo_or_helo_if_needed()
            # RCPT TO check — sends the address to the server
            smtp.mail("")
            code, _ = smtp.rcpt(email)
            # 250 = OK, 251 = forwarded — both mean the address is accepted
            return code in (250, 251)
    except (smtplib.SMTPException, socket.error, OSError):
        # Network blocked, timeout, or server refused — can't verify
        return False

def validate_email(email: str) -> tuple[bool, str]:
    """
    Full email validation pipeline.
    Returns (is_valid: bool, message: str).

    Steps:
      1. Format check  — instant, no network
      2. MX DNS lookup — checks if the domain has a real mail server
      3. SMTP check    — connects to the mail server to verify reachability
         (Note: many servers block or grey-list this check, so if SMTP
          fails we still accept the email if MX was found)
    """
    email = email.strip().lower()

    # ── Step 1: Format ───────────────────────────────────────────────────────
    if not _is_valid_format(email):
        return False, "❌ Invalid email format (expected: name@domain.com)"

    domain = email.split("@")[1]

    # ── Step 2: MX record ────────────────────────────────────────────────────
    if not _DNS_AVAILABLE:
        # dnspython not installed — skip MX check, accept format-valid email
        return True, "✅ Email format is valid (MX check skipped — dnspython not installed)"

    mx_host = _get_mx_host(domain)
    if mx_host is None:
        return False, f"❌ Domain '{domain}' has no mail server (MX record not found). This email cannot receive mail."

    # ── Step 3: SMTP reachability ────────────────────────────────────────────
    smtp_ok = _smtp_verify(mx_host, email)
    if smtp_ok:
        return True, f"✅ Email verified — mail server at '{mx_host}' accepted the address."
    else:
        # SMTP failed but MX exists — server likely blocks external probes
        return True, f"✅ Domain '{domain}' has a real mail server ('{mx_host}'). SMTP probe was blocked by server — this is normal for Gmail, Outlook, etc."


# ── External security lookups ────────────────────────────────────────────────
def _http_json(url: str, *, headers: dict | None = None, data: bytes | None = None):
    """Make a bounded JSON API request and return (status, body, headers)."""
    request = urllib.request.Request(
        url, data=data, headers={"Accept": "application/json", **(headers or {})},
        method="POST" if data is not None else "GET",
    )
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            body = response.read(2_000_000)
            return response.status, body, response.headers
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read(200_000), exc.headers


def free_email_breach_lookup(email: str):
    """Look up an email with XposedOrNot's free, keyless community endpoint."""
    account = urllib.parse.quote(email.strip(), safe="")
    return _http_json(
        f"https://api.xposedornot.com/v1/check-email/{account}",
        headers={"user-agent": "AlphaProtector/1.0"},
    )


def pwned_password_count(password: str) -> int:
    """Check a password with HIBP's k-anonymity range API; never send the password."""
    sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    status, body, _ = _http_json(
        f"https://api.pwnedpasswords.com/range/{sha1[:5]}",
        headers={"Add-Padding": "true", "user-agent": "AlphaProtector/1.0"},
    )
    if status != 200:
        raise RuntimeError(f"Password lookup service returned HTTP {status}.")
    suffix = sha1[5:]
    for line in body.decode("utf-8", errors="replace").splitlines():
        candidate, _, count = line.partition(":")
        if candidate.upper() == suffix:
            return int(count)
    return 0


def password_strength(password: str) -> tuple[int, list[str]]:
    """Small local strength heuristic; the submitted password is not transmitted."""
    score = 0
    tips = []
    if len(password) >= 12:
        score += 1
    else:
        tips.append("Use at least 12 characters.")
    if len(password) >= 16:
        score += 1
    if any(c.islower() for c in password) and any(c.isupper() for c in password):
        score += 1
    else:
        tips.append("Mix uppercase and lowercase letters.")
    if any(c.isdigit() for c in password) and any(not c.isalnum() for c in password):
        score += 1
    else:
        tips.append("Add numbers and symbols, or use a longer passphrase.")
    if len(set(password)) >= min(8, len(password)):
        score += 1
    return score, tips


def render_security_tool(tool_name: str) -> None:
    """Render one standalone tool dashboard."""
    st.markdown(f"## {tool_name}")
    if tool_name == "Free Email Breach Check":
        st.write("Search known breach records with XposedOrNot's free, keyless community API.")
        st.caption("The service allows up to 25 checks per hour and 100 per day per IP. Your email address is sent to XposedOrNot for the lookup.")
        email = st.text_input("Email address", key="free_breach_email", value=get_email(st.session_state.username))
        if st.button("Check breaches", key="do_free_breach"):
            if not _is_valid_format(email.strip()):
                st.error("Enter an email address in a valid format.")
            else:
                try:
                    with st.spinner("Checking known breach records…"):
                        status, body, response_headers = free_email_breach_lookup(email)
                    if status == 200:
                        result = json.loads(body or b"{}")
                        groups = result.get("breaches", [])
                        names = [str(item) for group in groups for item in (group if isinstance(group, list) else [group])]
                        if names:
                            st.warning(f"Found {len(names)} breach match(es) in XposedOrNot's dataset.")
                            st.dataframe(pd.DataFrame({"Breach": names}), use_container_width=True, hide_index=True)
                        else:
                            st.success("No breach matches were found in XposedOrNot's dataset.")
                    elif status == 404:
                        st.success("No breach matches were found in XposedOrNot's dataset.")
                    elif status == 429:
                        st.warning(f"Free API rate limit reached. Retry after {response_headers.get('retry-after', 'a short wait')} seconds.")
                    else:
                        st.error(f"Breach lookup failed with HTTP {status}: {body.decode('utf-8', errors='replace')[:500]}")
                except Exception as exc:
                    st.error(f"Could not complete the breach lookup: {exc}")
        st.caption("This checks XposedOrNot's dataset, which may differ from HIBP and other services. A clean result cannot prove an address was never exposed.")
        st.link_button("Check directly on Have I Been Pwned", "https://haveibeenpwned.com/")

    elif tool_name == "Email Footprint (Behind the Email)":
        st.write("Open Behind the Email to use its public web search for profile signals associated with an email address.")
        st.caption("This is a direct link, not an API integration, so AlphaProtector does not need a paid API token. The provider may have account, usage, or paid-tier limits on its own site.")
        st.link_button("Open Behind the Email", "https://behindtheemail.com/")

    elif tool_name == "Epieos Email OSINT":
        st.write("Open Epieos to run a reverse email search using its own interface and account.")
        st.caption("You may have meant Epieos by ‘Zepios’. This project does not have an Epieos API integration, so the button opens the provider directly.")
        st.link_button("Open Epieos email search", "https://epieos.com/")
        st.caption("The link is free to open. The provider may apply account, usage, or paid-tier limits to searches.")

    elif tool_name == "Password Tester":
        st.write("Test password strength locally and optionally check whether it appears in HIBP's compromised-password corpus.")
        st.caption("The password itself is not saved or sent. The optional breach check sends only the first five characters of its SHA-1 hash using HIBP's free k-anonymity range protocol.")
        password = st.text_input("Password to test", type="password", key="password_tester_input")
        if st.button("Test password", key="do_password_test"):
            if not password:
                st.error("Enter a password to test.")
            else:
                score, tips = password_strength(password)
                labels = ["Very weak", "Weak", "Fair", "Good", "Strong", "Very strong"]
                st.metric("Local strength estimate", labels[score])
                if tips:
                    st.write("Suggestions:")
                    for tip in tips:
                        st.write(f"- {tip}")
                try:
                    with st.spinner("Checking compromised-password corpus…"):
                        count = pwned_password_count(password)
                    if count:
                        st.error(f"This password appears {count:,} time(s) in known breach data. Do not use it.")
                    else:
                        st.success("No match was found in the current HIBP compromised-password corpus.")
                except Exception as exc:
                    st.warning(f"Strength estimate completed, but the online breach check failed: {exc}")

    st.markdown("---")
    st.caption("External lookup results can be incomplete. Use these tools only for addresses and passwords you are authorized to check.")

# ── Session state defaults ────────────────────────────────────────────────────
if "logged_in"  not in st.session_state:
    st.session_state.logged_in  = False
if "username"   not in st.session_state:
    st.session_state.username   = ""
if "auth_page"  not in st.session_state:
    st.session_state.auth_page  = "login"   # "login" | "signup"
if "data_loaded" not in st.session_state:
    st.session_state.data_loaded = False

# ══════════════════════════════════════════════════════════════════════════════
# GLOBAL CSS  (animations + dark theme)
# ══════════════════════════════════════════════════════════════════════════════
st.markdown(
    """
    <style>
    /* ── Base ──────────────────────────────────────────────────────────────── */
    .stApp { background-color: #0d1117; color: #e6edf3; }
    hr { border-color: #30363d; }
    h1 { color: #58a6ff !important; }
    h3 { color: #8b949e !important; font-weight: 400; }

    /* ── Animated background scan-line ─────────────────────────────────────── */
    .stApp::before {
        content: "";
        position: fixed;
        top: 0; left: 0;
        width: 100%; height: 3px;
        background: linear-gradient(90deg, transparent, #58a6ff, transparent);
        animation: scan 4s linear infinite;
        z-index: 9999;
        pointer-events: none;
    }
    @keyframes scan {
        0%   { top: 0; }
        100% { top: 100vh; }
    }

    /* ── Glowing animated title ─────────────────────────────────────────────── */
    .glow-title {
        font-size: 2.8rem;
        font-weight: 800;
        color: #58a6ff;
        text-align: center;
        letter-spacing: 0.06em;
        animation: glow 2.5s ease-in-out infinite alternate;
    }
    @keyframes glow {
        from { text-shadow: 0 0 6px #58a6ff88, 0 0 12px #58a6ff44; }
        to   { text-shadow: 0 0 18px #58a6ffcc, 0 0 36px #58a6ff88, 0 0 60px #58a6ff44; }
    }

    /* ── Pulsing ONLINE badge ───────────────────────────────────────────────── */
    .status-badge {
        display: inline-block;
        background-color: #1f6feb33;
        border: 1px solid #1f6feb;
        color: #58a6ff;
        padding: 4px 14px;
        border-radius: 20px;
        font-size: 0.8rem;
        font-weight: 600;
        animation: pulse-badge 2s ease-in-out infinite;
    }
    @keyframes pulse-badge {
        0%, 100% { box-shadow: 0 0 0 0 #1f6feb55; }
        50%       { box-shadow: 0 0 0 8px #1f6feb00; }
    }

    /* ── Fade-in card animation ─────────────────────────────────────────────── */
    @keyframes fadeInUp {
        from { opacity: 0; transform: translateY(18px); }
        to   { opacity: 1; transform: translateY(0); }
    }
    .fade-card { animation: fadeInUp 0.5s ease both; }

    /* ── Auth form card ─────────────────────────────────────────────────────── */
    .auth-card {
        background-color: #161b22;
        border: 1px solid #30363d;
        border-radius: 12px;
        padding: 36px 40px;
        max-width: 420px;
        margin: 60px auto 0 auto;
        animation: fadeInUp 0.6s ease both;
        box-shadow: 0 0 30px #58a6ff22;
    }
    .auth-card h2 {
        color: #58a6ff !important;
        text-align: center;
        margin-bottom: 6px;
        font-size: 1.6rem;
    }
    .auth-subtitle {
        text-align: center;
        color: #8b949e;
        font-size: 0.88rem;
        margin-bottom: 24px;
    }
    .auth-link {
        color: #58a6ff;
        cursor: pointer;
        text-decoration: underline;
        font-size: 0.88rem;
    }

    /* ── Metric cards ───────────────────────────────────────────────────────── */
    [data-testid="metric-container"] {
        background-color: #161b22;
        border: 1px solid #30363d;
        border-radius: 10px;
        padding: 20px;
        animation: fadeInUp 0.5s ease both;
        transition: box-shadow 0.3s;
    }
    [data-testid="metric-container"]:hover {
        box-shadow: 0 0 14px #58a6ff44;
    }
    [data-testid="metric-container"] label {
        color: #8b949e !important;
        font-size: 0.85rem !important;
        text-transform: uppercase;
        letter-spacing: 0.05em;
    }
    [data-testid="metric-container"] [data-testid="stMetricValue"] {
        color: #58a6ff !important;
        font-size: 2.2rem !important;
        font-weight: 700;
    }

    /* ── Table ──────────────────────────────────────────────────────────────── */
    [data-testid="stDataFrame"] {
        border: 1px solid #30363d;
        border-radius: 8px;
    }

    /* ── Buttons ────────────────────────────────────────────────────────────── */
    .stButton > button {
        background-color: #1f6feb;
        color: #ffffff;
        border: none;
        border-radius: 6px;
        padding: 8px 20px;
        font-weight: 600;
        transition: background-color 0.2s, box-shadow 0.2s;
    }
    .stButton > button:hover {
        background-color: #388bfd;
        box-shadow: 0 0 12px #388bfd88;
    }

    /* ── Warning box ────────────────────────────────────────────────────────── */
    .warn-box {
        background-color: #2d1b1b;
        border-left: 4px solid #f85149;
        border-radius: 6px;
        padding: 14px 18px;
        margin-bottom: 10px;
        color: #e6edf3;
        animation: fadeInUp 0.4s ease both;
    }
    .warn-box strong { color: #f85149; }
    .warn-box code {
        background-color: #3d2020;
        color: #ffa198;
        padding: 2px 6px;
        border-radius: 4px;
    }

    /* ── Alert card ─────────────────────────────────────────────────────────── */
    .alert-card {
        background-color: #161b22;
        border: 1px solid #30363d;
        border-radius: 8px;
        padding: 16px 20px;
        margin-bottom: 12px;
        animation: fadeInUp 0.45s ease both;
        transition: box-shadow 0.3s;
    }
    .alert-card:hover { box-shadow: 0 0 12px #f8514940; }
    .alert-card table { width: 100%; border-collapse: collapse; }
    .alert-card td { padding: 5px 10px 5px 0; vertical-align: top; color: #e6edf3; }
    .alert-card td:first-child {
        color: #8b949e; width: 160px;
        font-size: 0.85rem; text-transform: uppercase;
    }
    .alert-card code {
        background-color: #0d1117;
        color: #79c0ff;
        padding: 2px 7px;
        border-radius: 4px;
        font-size: 0.9rem;
    }

    /* ── Risk badges ────────────────────────────────────────────────────────── */
    .badge {
        display: inline-block; padding: 3px 12px;
        border-radius: 12px; font-size: 0.8rem;
        font-weight: 700; letter-spacing: 0.04em;
    }
    .badge-high   { background-color: #3d1212; color: #f85149; border: 1px solid #f85149; }
    .badge-medium { background-color: #2d1f00; color: #e3b341; border: 1px solid #e3b341; }
    .badge-low    { background-color: #0d2a1a; color: #3fb950; border: 1px solid #3fb950; }

    /* ── Disclaimer ─────────────────────────────────────────────────────────── */
    .disclaimer {
        background-color: #161b22;
        border: 1px solid #30363d;
        border-left: 4px solid #8b949e;
        border-radius: 6px;
        padding: 12px 16px;
        color: #8b949e;
        font-size: 0.88rem;
        line-height: 1.6;
        margin-top: 8px;
    }

    /* ── User pill (top-right) ──────────────────────────────────────────────── */
    .user-pill {
        display: inline-block;
        background-color: #1f2937;
        border: 1px solid #30363d;
        border-radius: 20px;
        padding: 4px 14px;
        font-size: 0.82rem;
        color: #58a6ff;
        font-weight: 600;
    }
    </style>
    """,
    unsafe_allow_html=True,
)

# ══════════════════════════════════════════════════════════════════════════════
# AUTH PAGES  (shown when not logged in)
# ══════════════════════════════════════════════════════════════════════════════

def show_login():
    """Render the Sign In form."""
    st.markdown(
        '<div class="auth-card">'
        '<h2>🛡️ AlphaProtector</h2>'
        '<p class="auth-subtitle">Sign in to access the security dashboard</p>',
        unsafe_allow_html=True,
    )

    username = st.text_input("Username", key="login_user", placeholder="Enter username")
    password = st.text_input("Password", key="login_pass",
                             placeholder="Enter password", type="password")

    if st.button("Sign In", key="btn_signin"):
        # check_password() reads from users.json and compares hashed passwords
        if check_password(username, password):
            st.session_state.logged_in = True
            st.session_state.username  = username
            st.rerun()
        else:
            st.error("❌ Invalid username or password.")

    st.markdown(
        '<p style="text-align:center; margin-top:16px; color:#8b949e; font-size:0.88rem;">'
        'No account? '
        '</p>',
        unsafe_allow_html=True,
    )
    if st.button("Create an account →", key="go_signup"):
        st.session_state.auth_page = "signup"
        st.rerun()

    st.markdown("</div>", unsafe_allow_html=True)

def show_signup():
    """Render the Sign Up form with real email validation."""
    # Persistent flags in session state
    for key, default in [
        ("signup_done", False),
        ("email_check_result", None),   # None | (bool, str)
        ("email_checked_value", ""),    # which email was last checked
    ]:
        if key not in st.session_state:
            st.session_state[key] = default

    st.markdown(
        '<div class="auth-card">'
        '<h2>🛡️ AlphaProtector</h2>'
        '<p class="auth-subtitle">Create a new account</p>',
        unsafe_allow_html=True,
    )

    # ── Success screen ────────────────────────────────────────────────────────
    if st.session_state.signup_done:
        st.success("✅ Account created! You can now sign in.")
        if st.button("Go to Sign In →", key="go_login_after"):
            st.session_state.signup_done        = False
            st.session_state.email_check_result = None
            st.session_state.auth_page          = "login"
            st.rerun()
        st.markdown("</div>", unsafe_allow_html=True)
        return

    # ── Sign-up form ──────────────────────────────────────────────────────────
    new_user = st.text_input("Choose a username", key="su_user",
                              placeholder="e.g. john_doe")

    # ── Email field + Check Email button ─────────────────────────────────────
    email_col, btn_col = st.columns([3, 1])
    with email_col:
        new_email = st.text_input("Email address", key="su_email",
                                   placeholder="you@example.com")
    with btn_col:
        st.markdown("<br>", unsafe_allow_html=True)   # align button vertically
        check_clicked = st.button("Check Email", key="btn_check_email")

    # Run validation when button is clicked
    if check_clicked:
        if not new_email.strip():
            st.session_state.email_check_result = (False, "❌ Please enter an email address.")
            st.session_state.email_checked_value = new_email
        else:
            with st.spinner("🔍 Checking email — looking up DNS and mail server…"):
                ok, msg = validate_email(new_email)
            st.session_state.email_check_result  = (ok, msg)
            st.session_state.email_checked_value = new_email

    # Show the last email check result if it matches what's currently typed
    if (st.session_state.email_check_result is not None and
            st.session_state.email_checked_value == new_email):
        ok_result, msg_result = st.session_state.email_check_result
        if ok_result:
            st.success(msg_result)
        else:
            st.error(msg_result)

    # ── Password fields ───────────────────────────────────────────────────────
    new_pass = st.text_input("Choose a password", key="su_pass",
                              placeholder="Min. 6 characters", type="password")
    confirm  = st.text_input("Confirm password", key="su_conf",
                              placeholder="Repeat password", type="password")

    # ── Final Sign Up button ──────────────────────────────────────────────────
    if st.button("Sign Up", key="btn_signup"):
        users = load_users()

        # Validate all fields before registering
        if len(new_user.strip()) < 3:
            st.error("❌ Username must be at least 3 characters.")
        elif new_user in users:
            st.error("❌ Username already exists. Please choose another.")
        elif not new_email.strip():
            st.error("❌ Email address is required.")
        else:
            # Run email validation silently at submit time
            email_ok, email_msg = validate_email(new_email)
            if not email_ok:
                st.error(email_msg)
            elif len(new_pass) < 6:
                st.error("❌ Password must be at least 6 characters.")
            elif new_pass != confirm:
                st.error("❌ Passwords do not match.")
            else:
                ok = register_user(new_user, new_pass, email=new_email.strip().lower())
                if ok:
                    st.session_state.signup_done        = True
                    st.session_state.email_check_result = None
                    st.rerun()
                else:
                    st.error("❌ Username was just taken. Please choose another.")

    st.markdown("<br>", unsafe_allow_html=True)
    if st.button("← Back to Sign In", key="go_login"):
        st.session_state.auth_page = "login"
        st.rerun()

    st.markdown("</div>", unsafe_allow_html=True)


# ── Route to auth pages if not logged in ─────────────────────────────────────
if not st.session_state.logged_in:
    if st.session_state.auth_page == "signup":
        show_signup()
    else:
        show_login()
    st.stop()   # stop here — don't render the dashboard

# ── Security tool navigation ────────────────────────────────────────────────
if "active_tool" not in st.session_state:
    st.session_state.active_tool = "Overview"

tool_pages = [
    "Overview",
    "Free Email Breach Check",
    "Email Footprint (Behind the Email)",
    "Epieos Email OSINT",
    "Password Tester",
]
if st.session_state.active_tool not in tool_pages:
    st.session_state.active_tool = "Overview"
st.sidebar.markdown("## 🛡️ AlphaProtector")
st.sidebar.caption("Security tools")
for _page in tool_pages:
    if st.sidebar.button(_page, key=f"nav_{_page}", use_container_width=True):
        st.session_state.active_tool = _page
        st.rerun()

if st.session_state.active_tool != "Overview":
    render_security_tool(st.session_state.active_tool)
    if st.sidebar.button("Sign Out", key="tool_signout", use_container_width=True):
        st.session_state.logged_in = False
        st.session_state.username = ""
        st.session_state.active_tool = "Overview"
        st.rerun()
    st.stop()

# ══════════════════════════════════════════════════════════════════════════════
# DATA  (only runs after login)
# ══════════════════════════════════════════════════════════════════════════════

# ── 20 fake login records ─────────────────────────────────────────────────────
SAMPLE_RECORDS = [
    ("2024-06-01 08:02:11", "alice",  "192.168.1.10", "Success"),
    ("2024-06-01 08:14:33", "bob",    "192.168.1.22", "Success"),
    ("2024-06-01 08:31:05", "carol",  "10.0.0.5",     "Success"),
    ("2024-06-01 08:45:50", "dave",   "203.0.113.99", "Failed"),
    ("2024-06-01 08:46:12", "admin",  "203.0.113.99", "Failed"),
    ("2024-06-01 08:46:44", "root",   "203.0.113.99", "Failed"),
    ("2024-06-01 08:47:01", "admin",  "203.0.113.99", "Failed"),
    ("2024-06-01 08:47:29", "alice",  "203.0.113.99", "Failed"),
    ("2024-06-01 09:03:18", "eve",    "172.16.0.8",   "Success"),
    ("2024-06-01 09:15:44", "frank",  "192.168.1.44", "Success"),
    ("2024-06-01 09:28:02", "grace",  "10.0.0.12",    "Success"),
    ("2024-06-01 09:41:57", "henry",  "192.168.1.55", "Failed"),
    ("2024-06-01 10:05:30", "isabel", "10.0.0.21",    "Success"),
    ("2024-06-01 10:22:14", "jack",   "172.16.0.33",  "Success"),
    ("2024-06-01 10:38:49", "karen",  "192.168.1.66", "Success"),
    ("2024-06-01 11:00:05", "liam",   "10.0.0.30",    "Failed"),
    ("2024-06-01 11:17:33", "mia",    "192.168.1.77", "Success"),
    ("2024-06-01 11:35:20", "noah",   "172.16.0.50",  "Success"),
    ("2024-06-01 11:52:08", "olivia", "10.0.0.44",    "Success"),
    ("2024-06-01 12:10:47", "peter",  "192.168.1.88", "Success"),
]

SUSPICIOUS_THRESHOLD = 5

def find_suspicious_ips(records, threshold):
    failed_counts = {}
    for record in records:
        _, _, ip, result = record
        if result == "Failed":
            failed_counts[ip] = failed_counts.get(ip, 0) + 1
    return {ip: c for ip, c in failed_counts.items() if c >= threshold}

def get_risk_level(failed_count):
    if failed_count >= 10:
        return "High"
    elif failed_count >= 7:
        return "Medium"
    else:
        return "Low"

def build_alerts(records, suspicious_ips):
    alerts = []
    for ip, count in suspicious_ips.items():
        usernames_tried = []
        for record in records:
            _, username, record_ip, result = record
            if record_ip == ip and result == "Failed" and username not in usernames_tried:
                usernames_tried.append(username)
        risk   = get_risk_level(count)
        reason = (
            f"IP {ip} made {count} failed login attempts, "
            f"trying {len(usernames_tried)} different username(s). "
            f"This matches a pattern of repeated credential guessing."
        )
        alerts.append({
            "ip": ip, "usernames": ", ".join(usernames_tried),
            "failed": count, "risk": risk, "reason": reason,
        })
    risk_order = {"High": 0, "Medium": 1, "Low": 2}
    alerts.sort(key=lambda a: risk_order[a["risk"]])
    return alerts

def build_dataframe(records):
    return pd.DataFrame(records, columns=["Time", "Username", "IP Address", "Result"])

df             = build_dataframe(SAMPLE_RECORDS)
suspicious_ips = find_suspicious_ips(SAMPLE_RECORDS, SUSPICIOUS_THRESHOLD)
alerts         = build_alerts(SAMPLE_RECORDS, suspicious_ips)

total_logins      = len(df)
successful_logins = len(df[df["Result"] == "Success"])
failed_logins     = len(df[df["Result"] == "Failed"])
suspicious_acts   = len(suspicious_ips)

# ══════════════════════════════════════════════════════════════════════════════
# DASHBOARD UI
# ══════════════════════════════════════════════════════════════════════════════

# ── Header row ────────────────────────────────────────────────────────────────
hdr_left, hdr_right = st.columns([5, 1])
with hdr_left:
    st.markdown('<p class="glow-title">🛡️ AlphaProtector</p>', unsafe_allow_html=True)
    st.markdown("### Real-time Security Monitoring Dashboard")
    st.markdown('<span class="status-badge">● SYSTEM ONLINE</span>', unsafe_allow_html=True)
with hdr_right:
    st.markdown("<br><br>", unsafe_allow_html=True)
    _user_email   = get_email(st.session_state.username)
    _email_line   = (f"<br><small style='color:#8b949e;font-size:0.72rem;'>"
                     f"{_user_email}</small>") if _user_email else ""
    st.markdown(
        f'<div class="user-pill">👤 {st.session_state.username}{_email_line}</div>',
        unsafe_allow_html=True,
    )
    if st.button("Sign Out"):
        st.session_state.logged_in  = False
        st.session_state.username   = ""
        st.session_state.data_loaded = False
        st.rerun()

st.markdown("---")

# ── Four metric cards ─────────────────────────────────────────────────────────
col1, col2, col3, col4 = st.columns(4)
col1.metric("🔐 Total Logins",          f"{total_logins:,}")
col2.metric("✅ Successful Logins",     f"{successful_logins:,}")
col3.metric("❌ Failed Logins",         f"{failed_logins:,}",
            delta=f"+{failed_logins}",  delta_color="inverse")
col4.metric("⚠️ Suspicious Activities", f"{suspicious_acts:,}",
            delta=f"+{suspicious_acts}", delta_color="inverse")

st.markdown("---")

# ── Charts ────────────────────────────────────────────────────────────────────
st.markdown("## 📊 Login Analytics")
chart_col1, chart_col2 = st.columns(2)

with chart_col1:
    st.markdown("#### Login Results Overview")
    st.caption(
        "Compares successful vs failed logins. "
        "A high failed bar may indicate unauthorised access attempts."
    )
    login_summary = pd.DataFrame({
        "Result": ["Success", "Failed"],
        "Count":  [successful_logins, failed_logins],
    })
    chart1 = (
        alt.Chart(login_summary)
        .mark_bar(cornerRadiusTopLeft=4, cornerRadiusTopRight=4)
        .encode(
            x=alt.X("Result", axis=alt.Axis(labelColor="#8b949e", titleColor="#8b949e")),
            y=alt.Y("Count",  axis=alt.Axis(labelColor="#8b949e", titleColor="#8b949e")),
            color=alt.condition(
                alt.datum.Result == "Success",
                alt.value("#3fb950"),
                alt.value("#f85149"),
            ),
            tooltip=["Result", "Count"],
        )
        .properties(height=280, background="#161b22")
        .configure_view(strokeWidth=0)
        .configure_axis(gridColor="#30363d", domainColor="#30363d")
    )
    st.altair_chart(chart1, use_container_width=True)

with chart_col2:
    st.markdown("#### Failed Logins per IP Address")
    st.caption(
        "Shows failed login counts per IP, sorted highest first. "
        "Red bars are flagged as suspicious by the detection rule."
    )
    failed_by_ip = (
        df[df["Result"] == "Failed"]
        .groupby("IP Address").size()
        .reset_index(name="Failed Count")
    )
    chart2 = (
        alt.Chart(failed_by_ip)
        .mark_bar(cornerRadiusTopLeft=4, cornerRadiusTopRight=4)
        .encode(
            x=alt.X("IP Address", sort="-y",
                    axis=alt.Axis(labelColor="#8b949e", titleColor="#8b949e", labelAngle=-30)),
            y=alt.Y("Failed Count",
                    axis=alt.Axis(labelColor="#8b949e", titleColor="#8b949e")),
            color=alt.condition(
                alt.FieldOneOfPredicate(field="IP Address",
                                        oneOf=list(suspicious_ips.keys())),
                alt.value("#f85149"),
                alt.value("#58a6ff"),
            ),
            tooltip=["IP Address", "Failed Count"],
        )
        .properties(height=280, background="#161b22")
        .configure_view(strokeWidth=0)
        .configure_axis(gridColor="#30363d", domainColor="#30363d")
    )
    st.altair_chart(chart2, use_container_width=True)

st.markdown("---")

# ── Threat Detection ──────────────────────────────────────────────────────────
st.markdown("## 🚨 Threat Detection")
st.write(
    f"**Rule:** Any IP address with **{SUSPICIOUS_THRESHOLD} or more failed logins** "
    f"is automatically flagged as suspicious."
)

if len(suspicious_ips) == 0:
    st.success("✅ No suspicious IPs detected. All activity looks normal.")
else:
    for ip, count in suspicious_ips.items():
        st.markdown(
            f"""
            <div class="warn-box fade-card">
                <strong>⚠️ SUSPICIOUS IP DETECTED</strong><br><br>
                <b>IP Address:</b> <code>{ip}</code><br>
                <b>Failed Login Attempts:</b> {count}<br>
                <b>Threshold:</b> {SUSPICIOUS_THRESHOLD} attempts<br><br>
                <b>Why flagged:</b> This IP made <b>{count} failed login attempts</b>,
                meeting or exceeding the limit of {SUSPICIOUS_THRESHOLD}.
                This may indicate a <b>brute-force attack</b>.
            </div>
            """,
            unsafe_allow_html=True,
        )

st.markdown("---")

# ── Security Alerts ───────────────────────────────────────────────────────────
st.markdown("## 🔔 Security Alerts")
st.write("Each alert was generated automatically by the detection rule above.")

st.markdown(
    """
    <div class="disclaimer">
        <b>⚠️ Important:</b> These alerts are based on a simple pattern rule (failed login
        count). A suspicious login pattern does <b>not automatically prove a cyberattack</b>.
        A legitimate user may simply have forgotten their password. Alerts should always be
        reviewed by a person before any action is taken. For educational purposes only.
    </div>
    """,
    unsafe_allow_html=True,
)

st.markdown("<br>", unsafe_allow_html=True)

selected_risk = st.selectbox(
    "Filter alerts by risk level:",
    options=["All", "High", "Medium", "Low"],
    index=0,
)

filtered_alerts = alerts if selected_risk == "All" else [
    a for a in alerts if a["risk"] == selected_risk
]

if len(filtered_alerts) == 0:
    st.success("✅ No alerts match the selected filter.")
else:
    risk_style = {
        "High":   ("badge badge-high",   "🔴"),
        "Medium": ("badge badge-medium", "🟡"),
        "Low":    ("badge badge-low",    "🟢"),
    }
    for alert in filtered_alerts:
        badge_class, icon = risk_style[alert["risk"]]
        st.markdown(
            f"""
            <div class="alert-card">
                <table>
                    <tr><td>IP Address</td>     <td><code>{alert["ip"]}</code></td></tr>
                    <tr><td>Usernames Tried</td><td>{alert["usernames"]}</td></tr>
                    <tr><td>Failed Attempts</td><td><b>{alert["failed"]}</b></td></tr>
                    <tr><td>Risk Level</td>
                        <td>{icon} <span class="{badge_class}">{alert["risk"]}</span></td></tr>
                    <tr><td>Reason</td>
                        <td style="color:#8b949e;font-size:0.9rem;">{alert["reason"]}</td></tr>
                </table>
            </div>
            """,
            unsafe_allow_html=True,
        )

st.markdown("---")

# ── Login Records ─────────────────────────────────────────────────────────────
st.markdown("## 📋 Login Records")
st.write("Click the button below to load the latest login activity into the table.")

if st.button("🔄 Generate Sample Data"):
    st.session_state.data_loaded = True

result_filter = st.selectbox(
    "Filter records by login result:",
    options=["All", "Success", "Failed"],
    index=0,
)

display_df = df if result_filter == "All" else df[df["Result"] == result_filter]

if st.session_state.data_loaded:

    def highlight_result(val):
        if val == "Success":
            return "color: #3fb950; font-weight: 600;"
        return "color: #f85149; font-weight: 600;"

    def highlight_suspicious_row(row):
        if row["IP Address"] in suspicious_ips:
            return ["background-color: #2d1f0e"] * len(row)
        return [""] * len(row)

    styled_df = (
        display_df.style
        .map(highlight_result, subset=["Result"])
        .apply(highlight_suspicious_row, axis=1)
    )
    st.dataframe(styled_df, use_container_width=True, hide_index=True)
    shown = len(display_df)
    st.info(
        f"📊 Showing **{shown}** of {total_logins} records "
        f"(filter: **{result_filter}**). Orange rows come from a flagged IP."
    )
else:
    st.markdown(
        '<p style="color:#8b949e;">No data loaded yet. Press the button above.</p>',
        unsafe_allow_html=True,
    )

st.markdown("---")
st.caption("AlphaProtector v2.0 · Powered by Streamlit · Demo Data")
