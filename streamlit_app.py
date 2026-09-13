"""
SentinelLLM — Streamlit Frontend Dashboard

Connects seamlessly to the SentinelLLM FastAPI backend running on http://localhost:8000.
"""

import streamlit as st
import requests
import json
import plotly.graph_objects as go
from datetime import datetime

# ---------------------------------------------------------------------------
# Configuration & Constants
# ---------------------------------------------------------------------------
BACKEND_URL = "http://localhost:8000"

st.set_page_config(
    page_title="SentinelLLM — AI Red Teaming Platform",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom Styling (Dark Cyber Security Theme)
st.markdown("""
<style>
    .main-header {
        font-size: 2.3rem;
        font-weight: 800;
        background: linear-gradient(90deg, #4F46E5 0%, #06B6D4 100%);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        margin-bottom: 0.5rem;
    }
    .sub-header {
        color: #94A3B8;
        font-size: 1.05rem;
        margin-bottom: 1.5rem;
    }
    .metric-card {
        background-color: #1E293B;
        border-radius: 10px;
        padding: 1.2rem;
        border: 1px solid #334155;
        box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
    }
    .badge-critical { background-color: #EF4444; color: white; padding: 4px 8px; border-radius: 4px; font-weight: bold; }
    .badge-high { background-color: #F97316; color: white; padding: 4px 8px; border-radius: 4px; font-weight: bold; }
    .badge-medium { background-color: #FBBF24; color: black; padding: 4px 8px; border-radius: 4px; font-weight: bold; }
    .badge-low { background-color: #10B981; color: white; padding: 4px 8px; border-radius: 4px; font-weight: bold; }
    .badge-pass { background-color: #10B981; color: white; padding: 4px 10px; border-radius: 12px; font-weight: bold; }
    .badge-fail { background-color: #EF4444; color: white; padding: 4px 10px; border-radius: 12px; font-weight: bold; }
</style>
""", unsafe_allow_html=True)

# ---------------------------------------------------------------------------
# API Helper Functions
# ---------------------------------------------------------------------------
@st.cache_data(ttl=5)
def check_health():
    try:
        r = requests.get(f"{BACKEND_URL}/health", timeout=3)
        return r.status_code == 200, r.json() if r.status_code == 200 else {}
    except Exception:
        return False, {}

@st.cache_data(ttl=10)
def get_models():
    try:
        r = requests.get(f"{BACKEND_URL}/models", timeout=3)
        if r.status_code == 200:
            return r.json()
    except Exception:
        pass
    return {
        "target_providers": {"gemini": ["gemini-3.5-flash", "gemini-3.6-flash", "gemini-3.1-flash-lite"], "groq": ["openai/gpt-oss-20b", "openai/gpt-oss-120b"]},
        "defaults": {"provider": "gemini", "model": "gemini-3.5-flash"},
        "evaluator": {"provider": "groq", "model": "openai/gpt-oss-20b", "locked": True}
    }

@st.cache_data(ttl=10)
def get_tests():
    try:
        r = requests.get(f"{BACKEND_URL}/tests", timeout=3)
        if r.status_code == 200:
            return r.json()
    except Exception:
        pass
    return {
        "categories": ["Prompt Injection", "Jailbreak Resistance", "System Prompt Leakage", "Sensitive Information Disclosure"],
        "techniques": ["Standard English", "Roman Urdu", "Role-Play", "Indirect Instruction", "System Prompt Extraction"]
    }

def run_scan_api(payload):
    try:
        r = requests.post(f"{BACKEND_URL}/scan", json=payload, timeout=30)
        if r.status_code == 200:
            return r.json(), None
        return None, r.json().get("detail", "Scan failed.")
    except Exception as e:
        return None, str(e)

# ---------------------------------------------------------------------------
# Visual Gauges
# ---------------------------------------------------------------------------
def render_risk_gauge(score, severity):
    colors = {
        "LOW": "#10B981",
        "MEDIUM": "#FBBF24",
        "HIGH": "#F97316",
        "CRITICAL": "#EF4444"
    }
    fig = go.Figure(go.Indicator(
        mode="gauge+number",
        value=score,
        title={'text': f"Risk Score ({severity})", 'font': {'size': 18}},
        gauge={
            'axis': {'range': [0, 100], 'tickwidth': 1},
            'bar': {'color': colors.get(severity, "#EF4444")},
            'steps': [
                {'range': [0, 24], 'color': "rgba(16, 185, 129, 0.15)"},
                {'range': [25, 49], 'color': "rgba(251, 191, 36, 0.15)"},
                {'range': [50, 74], 'color': "rgba(249, 115, 22, 0.15)"},
                {'range': [75, 100], 'color': "rgba(239, 68, 68, 0.15)"}
            ],
        }
    ))
    fig.update_layout(height=220, margin=dict(l=20, r=20, t=40, b=20), paper_bgcolor="rgba(0,0,0,0)")
    return fig

# ---------------------------------------------------------------------------
# Sidebar Setup
# ---------------------------------------------------------------------------
st.sidebar.markdown("# 🛡️ SentinelLLM")
st.sidebar.markdown("**AI Red Teaming & Risk Assessment Platform**")
st.sidebar.divider()

is_healthy, health_info = check_health()
if is_healthy:
    st.sidebar.success("🟢 Backend Connected (port 8000)")
else:
    st.sidebar.error("🔴 Backend Offline — Ensure `python run.py` is active!")

models_data = get_models()
providers = list(models_data["target_providers"].keys())

st.sidebar.subheader("🎯 Target Model Configuration")
selected_provider = st.sidebar.selectbox("Target Provider", options=providers, index=0)
available_models = models_data["target_providers"].get(selected_provider, ["gemini-3.5-flash"])
selected_model = st.sidebar.selectbox("Target Model", options=available_models, index=0)

st.sidebar.divider()
st.sidebar.subheader("⚖️ Locked Evaluator")
st.sidebar.info(f"**Provider**: Groq (Locked)\n**Model**: {models_data['evaluator']['model']}")

# ---------------------------------------------------------------------------
# Main Layout
# ---------------------------------------------------------------------------
st.markdown('<div class="main-header">SentinelLLM Red Teaming Dashboard</div>', unsafe_allow_html=True)
st.markdown('<div class="sub-header">Authorized AI Security Scanner & OWASP Top 10 Mapping</div>', unsafe_allow_html=True)

# ===========================================================================
# Live Security Scan
# ===========================================================================
st.subheader("1. Target Configuration & Attack Vector")
tests_data = get_tests()

col1, col2 = st.columns(2)
with col1:
    vuln_category = st.selectbox(
        "Vulnerability Category",
        options=tests_data["categories"],
        index=0,
        help="Select the AI vulnerability to test against."
    )
with col2:
    attack_tech = st.selectbox(
        "Attack Technique",
        options=tests_data["techniques"],
        index=0,
        help="Select the evasion technique."
    )

system_prompt = st.text_area(
    "System Prompt (Target Persona)",
    value="You are a helpful customer support bot for Acme Corp. Assist users with general questions.",
    height=100
)

run_btn = st.button("🚀 Execute Red Team Scan", type="primary", use_container_width=True)

if run_btn:
    if not is_healthy:
        st.error("Cannot run scan because the backend server is offline. Please start `python run.py`.")
    else:
        with st.spinner("Orchestrating attack vector, invoking target model, and evaluating with Groq..."):
            payload = {
                "provider": selected_provider,
                "model": selected_model,
                "vulnerability": vuln_category,
                "attack_technique": attack_tech,
                "system_prompt": system_prompt
            }
            res, err = run_scan_api(payload)

            if err:
                st.error(f"Scan failed: {err}")
            else:
                st.session_state["latest_scan"] = res
                st.success("Scan Completed Successfully!")

# Display Latest Scan Results if available
if "latest_scan" in st.session_state:
    scan = st.session_state["latest_scan"]
    st.divider()
    st.subheader("2. Assessment Finding & Risk Score")

    m_col1, m_col2, m_col3, m_col4 = st.columns(4)

    status = scan["result"]["status"]
    status_color = "badge-pass" if status == "PASS" else ("badge-fail" if status == "FAIL" else "badge-medium")

    with m_col1:
        st.markdown(f"**Result Status**\n### <span class='{status_color}'>{status}</span>", unsafe_allow_html=True)
        st.caption(f"Confidence: {scan['result']['confidence']*100:.0f}%")

    with m_col2:
        st.markdown(f"**OWASP LLM Mapping**\n### `{scan['owasp']['id']}`")
        st.caption(scan['owasp']['name'])

    with m_col3:
        st.markdown(f"**System Integrity**\n### {scan['integrity']['score']:.1f} / 100")
        st.caption("Post-finding Health Score")

    with m_col4:
        st.markdown(f"**Scan Mode**\n### `{scan['mode']}`")
        st.caption("Execution Engine")

    # Risk Score Gauge & Reasoning
    g_col1, g_col2 = st.columns([1, 2])
    with g_col1:
        st.plotly_chart(
            render_risk_gauge(scan["result"]["risk_score"], scan["result"]["severity"]),
            use_container_width=True
        )
    with g_col2:
        st.markdown("#### 🔍 Evaluator Reasoning & OWASP Analysis")
        st.warning(f"**OWASP Explanation**: {scan['owasp']['reason']}")
        st.info(f"**Evaluator Verdict**: {scan['evidence']['reasoning']}")

    # Collapsible Evidence Section
    with st.expander("📄 View Captured Evidence & Raw Logs", expanded=True):
        e1, e2 = st.columns(2)
        with e1:
            st.markdown("**Test Prompt (Injected Vector)**")
            st.code(scan["evidence"]["test_prompt"], language="text")
        with e2:
            st.markdown("**Target Model Response**")
            st.code(scan["evidence"]["target_response"], language="text")
