import re
import socket
import ssl
from datetime import datetime
from urllib.parse import urlparse

import streamlit as st
import tldextract
import whois

st.set_page_config(page_title="Phishing URL Detector", page_icon="🛡️", layout="wide")


st.markdown(
    """
    <style>
        :root {
            --bg: #0f172a;
            --panel: rgba(15, 23, 42, 0.85);
            --panel-strong: #111827;
            --line: rgba(148, 163, 184, 0.2);
            --text: #e2e8f0;
            --muted: #94a3b8;
            --danger: #ef4444;
            --warning: #f59e0b;
            --success: #22c55e;
            --primary: #38bdf8;
            --shadow: rgba(15, 23, 42, 0.35);
        }

        .stApp {
            background: linear-gradient(135deg, #020817 0%, #0f172a 40%, #111827 100%);
            color: var(--text);
        }

        .main .block-container {
            padding-top: 2rem;
            padding-bottom: 2rem;
            max-width: 1200px;
        }

        .hero {
            background: rgba(15, 23, 42, 0.7);
            border: 1px solid var(--line);
            border-radius: 20px;
            padding: 1.6rem 1.7rem;
            box-shadow: 0 18px 45px var(--shadow);
            margin-bottom: 1.25rem;
        }

        .hero h1 {
            margin-bottom: 0.2rem;
            font-size: 2.3rem;
            letter-spacing: -0.05em;
        }

        .hero p {
            margin: 0;
            font-size: 1rem;
            color: var(--muted);
        }

        .glass-card {
            background: rgba(15, 23, 42, 0.8);
            border: 1px solid var(--line);
            border-radius: 18px;
            padding: 1rem 1.1rem;
            box-shadow: 0 10px 30px rgba(2, 6, 23, 0.35);
        }

        .tag {
            display: inline-block;
            padding: 0.35rem 0.7rem;
            border-radius: 999px;
            font-size: 0.75rem;
            font-weight: 700;
            letter-spacing: 0.04em;
            text-transform: uppercase;
        }

        .tag.low { background: rgba(34, 197, 94, 0.15); color: #86efac; }
        .tag.moderate { background: rgba(245, 158, 11, 0.14); color: #fbbf24; }
        .tag.high { background: rgba(239, 68, 68, 0.15); color: #fca5a5; }

        .score-ring {
            border-radius: 18px;
            background: linear-gradient(135deg, rgba(59,130,246,0.18), rgba(15,23,42,0.2));
            padding: 1.5rem;
            border: 1px solid var(--line);
            text-align: center;
        }

        .score-ring .big-score {
            font-size: 3rem;
            font-weight: 800;
            letter-spacing: -0.07em;
        }

        .finding-item {
            background: rgba(15, 23, 42, 0.8);
            border-left: 4px solid rgba(148, 163, 184, 0.8);
            border-radius: 12px;
            padding: 0.9rem 1rem;
            margin-bottom: 0.7rem;
            color: var(--text);
        }

        .finding-item.low { border-left-color: var(--success); }
        .finding-item.moderate { border-left-color: var(--warning); }
        .finding-item.high { border-left-color: var(--danger); }

        .warning-box {
            border-radius: 10px;
            padding: 0.8rem 1rem;
            border: 1px solid rgba(148, 163, 184, 0.25);
            background: rgba(15, 23, 42, 0.7);
        }

        [data-testid="stMetricValue"] {
            font-size: 2rem;
            font-weight: 700;
        }

        .stProgress > div > div {
            background: linear-gradient(90deg, #22c55e 0%, #f59e0b 48%, #ef4444 100%);
        }
    </style>
    """,
    unsafe_allow_html=True,
)

def normalize_url(raw_url: str) -> str:
    """Add a scheme when needed and strip whitespace."""
    cleaned = raw_url.strip()
    if not cleaned:
        return ""
    if not cleaned.startswith(("http://", "https://")):
        cleaned = "https://" + cleaned
    return cleaned


def is_ip_address(netloc: str) -> bool:
    """Detect direct IP-host URL usage."""
    host = netloc.split(":", 1)[0]
    ip_pattern = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
    return bool(ip_pattern.match(host))


def get_domain_age(domain_name: str):
    """Look up WHOIS data and return age in days."""
    try:
        whois_record = whois.whois(domain_name)
        creation_date = whois_record.creation_date

        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        if creation_date:
            age_days = (datetime.now() - creation_date).days
            return age_days, creation_date.strftime("%Y-%m-%d")
    except Exception:
        return None, "Unknown"

    return None, "Unknown"


def check_ssl(hostname: str):
    """Verify whether a valid SSL certificate is available."""
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=3) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                issuer = cert.get("issuer", ((),))[0][0][1]
                return True, issuer
    except Exception:
        return False, None


def risk_label(score: int) -> str:
    if score >= 60:
        return "High Risk"
    if score >= 30:
        return "Moderate Risk"
    return "Low Risk"


def risk_tone(score: int) -> str:
    if score >= 60:
        return "high"
    if score >= 30:
        return "moderate"
    return "low"


def analyze_url(url: str):
    """Run detection logic and return a clean result object."""
    normalized = normalize_url(url)
    parsed = urlparse(normalized)
    ext = tldextract.extract(normalized)
    domain = f"{ext.domain}.{ext.suffix}" if ext.domain and ext.suffix else "unknown-domain"
    hostname = parsed.netloc or ext.registered_domain or ext.domain or "unknown-host"
    findings = []
    risk_score = 0

    if not parsed.scheme:
        parsed = urlparse(f"https://{url}")

    if is_ip_address(hostname):
        risk_score += 35
        findings.append({
            "level": "high",
            "message": "Direct IP address is being used instead of a normal domain name.",
        })

    if len(normalized) > 75:
        risk_score += 15
        findings.append({
            "level": "moderate",
            "message": f"URL length is {len(normalized)} characters, which is unusually long for a legitimate site.",
        })

    if "@" in normalized:
        risk_score += 25
        findings.append({
            "level": "high",
            "message": "The '@' symbol is present, which can hide the real domain in browsers.",
        })

    subdomain_count = len(ext.subdomain.split('.')) if ext.subdomain else 0
    if subdomain_count >= 3:
        risk_score += 20
        findings.append({
            "level": "moderate",
            "message": f"Multiple subdomains were detected ({subdomain_count}), which is often used in phishing setups.",
        })

    sensitive_keywords = [
        "login",
        "verify",
        "banking",
        "secure",
        "account",
        "update",
        "signin",
        "pay",
        "wallet",
    ]
    detected_keywords = [kw for kw in sensitive_keywords if kw in normalized.lower()]
    if detected_keywords and ext.domain not in ["paypal", "google", "apple", "microsoft", "bankofamerica"]:
        risk_score += 15
        findings.append({
            "level": "moderate",
            "message": f"Suspicious keywords were found: {', '.join(detected_keywords)}.",
        })

    age_days, creation_date = get_domain_age(domain)
    if age_days is not None:
        if age_days < 30:
            risk_score += 35
            findings.append({
                "level": "high",
                "message": f"This domain is only {age_days} days old (created {creation_date}). Newly registered domains are common in phishing campaigns.",
            })
        elif age_days < 180:
            risk_score += 15
            findings.append({
                "level": "moderate",
                "message": f"The domain is relatively new at {age_days} days old.",
            })
        else:
            findings.append({
                "level": "low",
                "message": f"The domain appears established, with an age of {age_days} days.",
            })
    else:
        findings.append({
            "level": "low",
            "message": "WHOIS data was unavailable, so the registration age could not be verified.",
        })

    has_ssl, issuer = check_ssl(hostname)
    if not has_ssl and parsed.scheme.lower() == "http":
        risk_score += 15
        findings.append({
            "level": "moderate",
            "message": "The site is not providing a valid HTTPS certificate, which raises trust concerns.",
        })
    elif has_ssl:
        findings.append({
            "level": "low",
            "message": f"A valid SSL certificate was detected and issued by {issuer}.",
        })

    final_score = min(risk_score, 100)
    return {
        "score": final_score,
        "label": risk_label(final_score),
        "tone": risk_tone(final_score),
        "findings": findings,
        "domain": domain,
        "hostname": hostname,
        "normalized_url": normalized,
    }

st.markdown(
    """
    <div class="hero">
        <h1>🛡️ Phishing URL & Domain Analyzer</h1>
        <p>Check for phishing indicators such as suspicious keywords, short-lived domains, malformed hostnames, and weak SSL patterns.</p>
    </div>
    """,
    unsafe_allow_html=True,
)

sample_urls = [
    "",
    "https://paypal-security-update.com/login",
    "https://github.com/login",
    "http://192.168.1.10/login",
    "https://accounts-paypal-verification.com/secure",
]

selected_example = st.selectbox("Try an example URL", sample_urls, index=0)

if selected_example:
    user_input = selected_example
else:
    user_input = st.text_input(
        "Enter a URL to analyze",
        placeholder="https://example-security-update.com/login",
        help="Paste a suspicious link or a normal website URL to inspect it.",
    )

if user_input:
    with st.spinner("Analyzing the URL and checking phishing indicators..."):
        result = analyze_url(user_input)

    st.markdown(
        f"""
        <div class="warning-box">
            <strong>Selected URL:</strong> {result['normalized_url']}
        </div>
        """,
        unsafe_allow_html=True,
    )

    st.divider()

    col_score, col_domain, col_ssl, col_host = st.columns(4)
    with col_score:
        st.metric("Risk Score", f"{result['score']}%")
    with col_domain:
        st.metric("Domain Age", "Unknown" if get_domain_age(result['domain'])[0] is None else f"{get_domain_age(result['domain'])[0]} days")
    with col_ssl:
        ssl_state = check_ssl(result['hostname'])
        st.metric("SSL", "Valid" if ssl_state[0] else "Missing")
    with col_host:
        st.metric("Host", result['hostname'])

    st.progress(result['score'] / 100)

    verdict_col, score_col = st.columns([1.5, 3])
    with verdict_col:
        st.markdown(
            f"""
            <div class="score-ring">
                <div class="big-score">{result['score']}%</div>
                <div class="tag {result['tone']}">{result['label']}</div>
            </div>
            """,
            unsafe_allow_html=True,
        )
    with score_col:
        if result['score'] >= 60:
            st.error("High-risk pattern detected. This link looks highly suspicious and should not be trusted.")
        elif result['score'] >= 30:
            st.warning("This URL shows moderate risk indicators. Double-check the destination before entering credentials.")
        else:
            st.success("This site looks relatively safe based on the automated checks available here.")

    st.subheader("Inspection Details")
    info_col1, info_col2 = st.columns(2)
    with info_col1:
        st.markdown("### URL metadata")
        st.write(f"**Domain:** {result['domain']}")
        st.write(f"**Host:** {result['hostname']}")
        st.write(f"**Normalized URL:** {result['normalized_url']}")
    with info_col2:
        st.markdown("### Summary")
        if result['findings']:
            st.write(f"Detected {len(result['findings'])} signals related to safety and trust.")
        else:
            st.write("No major issues were detected by the current checks.")

    st.subheader("Findings")
    if result['findings']:
        for item in result['findings']:
            level = item["level"]
            st.markdown(
                f"<div class='finding-item {level}'><strong>{level.title()}:</strong> {item['message']}</div>",
                unsafe_allow_html=True,
            )
    else:
        st.info("No suspicious indicators were found in the provided URL.")

    st.caption("This checker is designed to flag suspicious patterns and should be used alongside browser caution and trusted verification tools.")

else:
    st.info("Paste a URL above to start the phishing analysis.")
