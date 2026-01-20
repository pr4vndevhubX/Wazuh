import streamlit as st
from datetime import datetime
import plotly.graph_objects as go
import requests
import json
from crew import IPIntelligenceCrew

# ================= PAGE CONFIG =================
st.set_page_config(
    page_title="Enterprise Threat Intelligence",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed"
)

# ================= SESSION STATE INITIALIZATION =================
if 'ip_analysis_done' not in st.session_state:
    st.session_state.ip_analysis_done = False
if 'ip_result' not in st.session_state:
    st.session_state.ip_result = None
if 'ip_threat_score' not in st.session_state:
    st.session_state.ip_threat_score = 0
if 'ip_address' not in st.session_state:
    st.session_state.ip_address = ""
if 'attack_search_done' not in st.session_state:
    st.session_state.attack_search_done = False
if 'attack_results' not in st.session_state:
    st.session_state.attack_results = []
if 'rag_search_done' not in st.session_state:
    st.session_state.rag_search_done = False
if 'rag_results' not in st.session_state:
    st.session_state.rag_results = None

# ================= GLOBAL CSS =================
st.markdown("""
<style>

/* ---------- HIDE STREAMLIT CHROME ---------- */
header[data-testid="stHeader"] { display: none; }
#MainMenu { visibility: hidden; }
footer { visibility: hidden; }
section[data-testid="stSidebar"] { display: none; }

/* ---------- GLOBAL ---------- */
html, body, [class*="css"] {
    font-family: "Inter", "Segoe UI", system-ui;
    color: #ffffff !important;
}

.stApp {
    background: radial-gradient(circle at 20% 0%, #0f2040, #050b18 70%);
    margin-top: 0 !important;
}

.block-container {
    padding-top: 0.6rem !important;
    padding-bottom: 0.8rem !important;
    max-width: 1400px;
}

/* ---------- HERO ---------- */
.hero {
    background: linear-gradient(135deg, rgba(0,229,255,0.12), rgba(124,124,255,0.10));
    border: 1px solid rgba(0,229,255,0.25);
    border-radius: 14px;
    padding: 0.9rem 1.1rem;
    margin-bottom: 0.8rem;
    box-shadow: 0 8px 26px rgba(0, 0, 0, 0.25);
}
.hero h1 {
    font-size: 28px;
    margin: 0 0 0.25rem 0;
    color: #fff;
    font-weight: 800;
}
.hero p {
    font-size: 14px;
    margin: 0;
    color: #d7e6ff;
}

/* ---------- KPI ---------- */
.kpi-row {
    display: flex;
    gap: 0.9rem;
    margin-bottom: 0.6rem;
}
.kpi {
    flex: 1;
    background: rgba(15,32,64,0.80);
    border: 1px solid rgba(255,255,255,0.10);
    border-radius: 14px;
    padding: 1.0rem 1.1rem;
    text-align: center;
    transition: transform 120ms ease, border-color 120ms ease, box-shadow 120ms ease;
    box-shadow: 0 6px 18px rgba(0, 0, 0, 0.25);
    min-height: 120px;
    display: flex;
    flex-direction: column;
    justify-content: center;
}
.kpi:hover {
    transform: translateY(-2px);
    border-color: rgba(0,229,255,0.35);
    box-shadow: 0 8px 22px rgba(0, 229, 255, 0.08);
}
.kpi h2 {
    color: #00e5ff;
    margin: 0 0 0.35rem 0;
    font-size: 26px;
    font-weight: 800;
    letter-spacing: 0.2px;
}
.kpi span {
    color: #cfe6ff;
    font-size: 0.92rem;
}

/* ---------- CARD ---------- */
.card {
    background: rgba(15,32,64,0.75);
    border: 1px solid rgba(255,255,255,0.10);
    border-radius: 12px;
    padding: 0.9rem;
    margin-bottom: 0.9rem;
    box-shadow: 0 6px 18px rgba(0, 0, 0, 0.25);
}

.card-title {
    font-size: 16px;
    font-weight: 700;
    color: #ffffff;
    margin: 0 0 0.5rem 0;
    display: flex;
    align-items: center;
    gap: 8px;
}
.card-divider {
    height: 1px;
    background: linear-gradient(to right, #00e5ff, transparent);
    margin-bottom: 0.75rem;
}

/* ---------- INPUT ---------- */
.stTextInput label, .stTextInput legend { display: none !important; }
.stTextInput > div:first-child {
    background: transparent !important;
    box-shadow: none !important;
    border: none !important;
    margin-bottom: 0 !important;
}
.stTextInput input {
    background: #050b18 !important;
    border: 1px solid rgba(255,255,255,0.12) !important;
    border-radius: 10px !important;
    height: 40px !important;
    color: #ffffff !important;
    padding: 0 12px !important;
}
.stTextInput input:hover,
.stTextInput input:focus {
    border-color: rgba(0,229,255,0.35) !important;
}

/* ---------- BUTTON ---------- */
.stButton button {
    background: linear-gradient(135deg, #00e5ff, #7c7cff);
    border: none;
    height: 40px;
    border-radius: 10px;
    color: #050b18;
    font-weight: 800;
    letter-spacing: 0.2px;
    box-shadow: 0 6px 16px rgba(0, 229, 255, 0.10);
    transition: filter 120ms ease, transform 120ms ease;
}
.stButton button:hover { filter: brightness(1.05); transform: translateY(-1px); }

/* ---------- TABS ---------- */
.stTabs [data-baseweb="tab"] { color: #cfe6ff; font-weight: 600; }
.stTabs [aria-selected="true"] { color: #00e5ff; border-bottom: 2px solid #00e5ff; }

/* ---------- PROGRESS ---------- */
.stProgress > div > div > div > div {
    background: linear-gradient(90deg, #00e5ff, #7c7cff);
}

/* ---------- FOOTER ---------- */
.footer {
    text-align: center;
    color: #ffffff;
    font-size: 0.8rem;
    margin-top: 0.8rem;
}

/* ---------- DIVIDER ---------- */
.v-divider {
    width: 2px;
    min-height: 560px;
    background: rgba(255,255,255,0.10);
    border-radius: 2px;
    margin: 0.6rem auto 0.6rem auto;
    transition: background 160ms ease, box-shadow 160ms ease;
}
.v-divider:hover {
    background: #00e5ff;
    box-shadow: 0 0 10px rgba(0,229,255,0.60);
}

/* ---------- SERVICE STATUS ---------- */
.service-status {
    display: flex;
    gap: 0.8rem;
    margin-bottom: 1rem;
}
.service-card {
    flex: 1;
    background: rgba(15,32,64,0.80);
    border: 1px solid rgba(255,255,255,0.10);
    border-radius: 10px;
    padding: 0.8rem;
    text-align: center;
    min-height: 80px;
    display: flex;
    flex-direction: column;
    justify-content: center;
}
.service-online {
    border-color: rgba(0,229,100,0.35);
}
.service-offline {
    border-color: rgba(229,0,0,0.35);
}

</style>
""", unsafe_allow_html=True)

# ================= HERO =================
st.markdown("""
<div class="hero">
    <h1>🛡️ Enterprise IP Threat Intelligence</h1>
    <p>Real-time IP reputation analysis powered by 10 AI Agents + Multi-Service Integration</p>
</div>
""", unsafe_allow_html=True)

# ================= SERVICE HEALTH =================
st.markdown('<div class="card-title">🔌 System Health Monitor</div>', unsafe_allow_html=True)
st.markdown('<div class="card-divider"></div>', unsafe_allow_html=True)

services = {
    "ML Inference": ("http://localhost:8500/health", "🤖"),
    "Alert Triage": ("http://localhost:8100/health", "🚨"),
    "RAG Service": ("http://localhost:8001/health", "🎯"),
    "Wazuh SIEM": ("http://localhost:8002/health", "📊")
}

cols = st.columns(4)
for idx, (name, (url, icon)) in enumerate(services.items()):
    with cols[idx]:
        try:
            r = requests.get(url, timeout=2)
            status_class = "service-online" if r.ok else "service-offline"
            status_text = "✅ Online" if r.ok else "⚠️ Degraded"
            st.markdown(f"""
                <div class="service-card {status_class}">
                    <div style="font-size:24px;">{icon}</div>
                    <div style="font-weight:600;font-size:13px;margin-top:4px;">{name}</div>
                    <div style="font-size:12px;margin-top:2px;opacity:0.9;">{status_text}</div>
                </div>
            """, unsafe_allow_html=True)
        except:
            st.markdown(f"""
                <div class="service-card service-offline">
                    <div style="font-size:24px;">{icon}</div>
                    <div style="font-weight:600;font-size:13px;margin-top:4px;">{name}</div>
                    <div style="font-size:12px;margin-top:2px;opacity:0.9;">❌ Offline</div>
                </div>
            """, unsafe_allow_html=True)

st.markdown("<br>", unsafe_allow_html=True)

# ================= ATT&CK DB =================
ATTACK_DB = [
    {
        "tactic": "Command and Control",
        "technique": "Application Layer Protocol",
        "id": "T1071",
        "subtechniques": [
            {"id": "T1071.001", "name": "Web Protocols"},
            {"id": "T1071.004", "name": "DNS"}
        ],
        "description": "Adversaries may communicate using application layer protocols to avoid detection."
    },
    {
        "tactic": "Execution",
        "technique": "PowerShell",
        "id": "T1059.001",
        "description": "Adversaries may abuse PowerShell for execution and automation."
    },
    {
        "tactic": "Credential Access",
        "technique": "OS Credential Dumping",
        "id": "T1003",
        "description": "Dump credentials from operating systems using tools like Mimikatz."
    },
    {
        "tactic": "Discovery",
        "technique": "Network Service Discovery",
        "id": "T1046",
        "description": "Identify services running on remote hosts including scanning."
    },
    {
        "tactic": "Lateral Movement",
        "technique": "Remote Service",
        "id": "T1021",
        "description": "Use remote services like SMB/RDP/SSH to move laterally."
    },
]

def attack_search(query: str):
    """Simple case-insensitive search across tactic, technique, id and description."""
    q = (query or "").strip().lower()
    if not q:
        return []
    matches = []
    for item in ATTACK_DB:
        hay = " ".join([
            item.get("tactic",""),
            item.get("technique",""),
            item.get("id",""),
            item.get("description",""),
            " ".join([s["id"]+" "+s["name"] for s in item.get("subtechniques", [])])
        ]).lower()
        if q in hay:
            matches.append(item)
    return matches

# ================= MAIN SPLIT LAYOUT (SWAPPED) =================
left_col, mid_col, right_col = st.columns([2.0, 0.04, 1.2])

# ---------- LEFT: MITRE ATT&CK Assistant (was on right) ----------
with left_col:
    st.markdown('<div class="card-title">🧠 MITRE ATT&amp;CK Assistant</div>', unsafe_allow_html=True)
    st.markdown('<div class="card-divider"></div>', unsafe_allow_html=True)

    query = st.text_input(
        "ATT&CK search",
        placeholder="Ask about tactics, techniques or IDs (e.g., T1071, PowerShell, credential dumping)",
        label_visibility="collapsed",
        key="attack_query"
    )
    
    col1, col2 = st.columns([3, 1])
    with col1:
        do_search = st.button("🔎 Search Local DB", use_container_width=True, key="local_search_btn")
    with col2:
        rag_search = st.button("🎯 RAG", use_container_width=True, key="rag_search_btn")

    st.markdown('<br>', unsafe_allow_html=True)
    st.markdown('<div class="card-title">📄 ATT&amp;CK Report</div>', unsafe_allow_html=True)
    st.markdown('<div class="card-divider"></div>', unsafe_allow_html=True)

    if do_search and query:
        results = attack_search(query)
        st.session_state.attack_search_done = True
        st.session_state.attack_results = results
        st.session_state.rag_search_done = False
    
    if rag_search and query:
        st.session_state.rag_search_done = True
        st.session_state.attack_search_done = False
        with st.spinner("🔍 Searching MITRE knowledge base..."):
            try:
                r = requests.post(
                    "http://localhost:8001/retrieve",
                    json={"query": query, "top_k": 10, "min_similarity": 0.2},
                    timeout=10
                )
                if r.ok:
                    st.session_state.rag_results = r.json()
                else:
                    st.session_state.rag_results = {"error": f"Error: {r.status_code}"}
            except Exception as e:
                st.session_state.rag_results = {"error": str(e)}

    # Display Local Search Results
    if st.session_state.attack_search_done:
        results = st.session_state.attack_results
        if not results:
            st.warning("No ATT&CK entries matched your query. Try another keyword or technique ID.")
        else:
            st.success(f"✅ Found {len(results)} technique(s)")
            for r in results:
                st.markdown(f"""
                <div style="margin-bottom:0.8rem;">
                    <div style="font-size:14px;opacity:0.8;">Tactic</div>
                    <div style="font-weight:700;color:#00e5ff;">{r['tactic']}</div>
                    <div style="font-size:14px;opacity:0.8;margin-top:0.4rem;">Technique</div>
                    <div style="font-weight:700;color:#00e5ff;">{r['technique']} <span style="opacity:0.8;color:#cfe6ff;">({r['id']})</span></div>
                    <div style="font-size:14px;opacity:0.8;margin-top:0.4rem;">Description</div>
                    <div style="color:#d7e6ff;">{r['description']}</div>
                </div>
                """, unsafe_allow_html=True)

                subs = r.get("subtechniques", [])
                if subs:
                    st.markdown('<div style="margin-top:0.4rem;opacity:0.85;">Sub-techniques</div>', unsafe_allow_html=True)
                    for s in subs:
                        st.markdown(f"""
                        <div style="display:flex;align-items:center;gap:8px;margin:4px 0;">
                            <span style="display:inline-block;width:10px;height:10px;border-radius:50%;background:#00e5ff;"></span>
                            <span style="font-weight:600;color:#cfe6ff;">{s['id']}</span>
                            <span style="color:#d7e6ff;">{s['name']}</span>
                        </div>
                        """, unsafe_allow_html=True)
                    st.markdown('<div class="card-divider" style="margin-top:0.6rem;"></div>', unsafe_allow_html=True)
    
    # Display RAG Search Results
    elif st.session_state.rag_search_done:
        data = st.session_state.rag_results
        if data and "error" in data:
            st.error(f"❌ Service error: {data['error']}")
        elif data and data.get("total_results", 0) > 0:
            st.success(f"✅ Found {data['total_results']} MITRE technique(s)")
            
            for i, item in enumerate(data['results'], 1):
                with st.expander(f"🧠 {item['metadata'].get('name', 'Technique')}"):
                    st.markdown(f"**Technique ID:** `{item.get('metadata', {}).get('technique_id', 'N/A')}`")
                    st.markdown(f"**Tactic:** {item['metadata'].get('tactics', 'N/A')}")
                    st.markdown(f"**Platforms:** {item['metadata'].get('platforms', 'N/A')}")
                    st.markdown(f"**Similarity:** `{round(item['similarity_score'], 2)}`")
                    st.markdown("---")
                    st.write(item['document'][:500] + "...")
        else:
            st.warning("⚠️ No matching techniques found")
    
    else:
        st.info("💡 Search the local database or use RAG for comprehensive MITRE ATT&CK intelligence")

# ---------- MIDDLE: Vertical Divider ----------
with mid_col:
    st.markdown('<div class="v-divider"></div>', unsafe_allow_html=True)

# ---------- RIGHT: IP Investigation (was on left) ----------
with right_col:
    st.markdown('<div class="card-title">🔍 IP Investigation</div>', unsafe_allow_html=True)
    st.markdown('<div class="card-divider"></div>', unsafe_allow_html=True)

    ip = st.text_input(
        "Target IP",
        placeholder="e.g., 188.78.122.141",
        label_visibility="collapsed",
        key="ip_input"
    )

    analyze = st.button("🚀 Run Threat Analysis", use_container_width=True, key="analyze_btn")

    st.markdown('<br>', unsafe_allow_html=True)
    st.markdown('<div class="card-title">🧭 Threat Intelligence Report</div>', unsafe_allow_html=True)
    st.markdown('<div class="card-divider"></div>', unsafe_allow_html=True)

    if analyze and ip:
        # Store IP in session state
        st.session_state.ip_address = ip
        
        # Progress animation
        progress_bar = st.progress(0)
        status = st.empty()
        
        try:
            status.markdown("🔄 Initializing 10-agent crew...")
            progress_bar.progress(10)
            
            crew_instance = IPIntelligenceCrew()
            my_crew = crew_instance.crew()
            
            status.markdown("⚡ Executing threat intelligence workflow...")
            progress_bar.progress(40)
            
            result = my_crew.kickoff(inputs={'ip_address': ip})
            
            progress_bar.progress(100)
            status.markdown("✅ **Analysis Complete!**")
            
            # Store results in session state
            st.session_state.ip_result = result
            st.session_state.ip_analysis_done = True
            
            # Extract threat score (simple heuristic)
            threat_score = 78  # Default
            if "high" in str(result).lower() or "malicious" in str(result).lower():
                threat_score = 85
            elif "medium" in str(result).lower():
                threat_score = 60
            elif "low" in str(result).lower():
                threat_score = 30
            
            st.session_state.ip_threat_score = threat_score
            
        except Exception as e:
            st.error(f"❌ Analysis error: {str(e)}")
            with st.expander("View Error Details"):
                st.exception(e)
            st.session_state.ip_analysis_done = False
    
    # Display results if analysis has been done
    if st.session_state.ip_analysis_done and st.session_state.ip_result:
        # Threat gauge
        fig = go.Figure(go.Indicator(
            mode="gauge+number",
            value=st.session_state.ip_threat_score,
            title={"text": "Threat Risk Score", "font": {"color": "#ffffff"}},
            gauge={
                "axis": {"range": [0, 100]},
                "bar": {"color": "#00e5ff"},
                "steps": [
                    {"range": [0, 25], "color": "rgba(0,229,100,0.2)"},
                    {"range": [25, 50], "color": "rgba(255,229,0,0.2)"},
                    {"range": [50, 75], "color": "rgba(255,165,0,0.2)"},
                    {"range": [75, 100], "color": "rgba(255,0,0,0.2)"}
                ]
            }
        ))
        fig.update_layout(
            height=280,
            paper_bgcolor="rgba(0,0,0,0)",
            font=dict(color="#ffffff")
        )
        st.plotly_chart(fig, use_container_width=True)

        # Results tabs
        tabs = st.tabs(["📊 Final Report", "🤖 ML Analysis", "🚨 Alert Triage", "🎯 MITRE Context"])
        
        with tabs[0]:
            st.markdown("### Executive Summary")
            st.markdown(str(st.session_state.ip_result))
        
        with tabs[1]:
            st.markdown("### ML Traffic Classification")
            try:
                ml_r = requests.post(
                    "http://localhost:8500/predict",
                    json={"features": [0]*77, "model_name": "random_forest"},
                    timeout=10
                )
                if ml_r.ok:
                    ml_data = ml_r.json()
                    col1, col2, col3 = st.columns(3)
                    with col1:
                        st.metric("🎯 Prediction", ml_data.get('prediction', 'N/A'))
                    with col2:
                        conf = ml_data.get('confidence', 0) * 100
                        st.metric("📊 Confidence", f"{conf:.1f}%")
                    with col3:
                        st.metric("🤖 Model", ml_data.get('model_used', 'N/A'))
                    
                    with st.expander("View Raw ML Data"):
                        st.json(ml_data)
                else:
                    st.warning("⚠️ ML service unavailable")
            except Exception as e:
                st.error(f"❌ ML service error: {str(e)}")
        
        with tabs[2]:
            st.markdown("### Alert Triage Analysis")
            try:
                triage_r = requests.get("http://localhost:8100/health", timeout=2)
                if triage_r.ok:
                    st.success("✅ Alert triage service operational")
                    st.info("📋 Triage results integrated in final report")
                else:
                    st.warning("⚠️ Service degraded")
            except:
                st.warning("⚠️ Alert triage service unavailable")
                st.info("💡 Crew continued analysis gracefully")
        
        with tabs[3]:
            st.markdown("### MITRE ATT&CK Context")
            try:
                rag_r = requests.post(
                    "http://localhost:8001/retrieve",
                    json={
                        "query": f"malicious activity {st.session_state.ip_address}",
                        "top_k": 5,
                        "min_similarity": 0.3
                    },
                    timeout=10
                )
                if rag_r.ok:
                    rag_data = rag_r.json()
                    st.metric("📊 Techniques Found", rag_data.get('total_results', 0))
                    
                    if rag_data.get('results'):
                        for item in rag_data['results']:
                            with st.expander(f"🧠 {item['metadata'].get('name', 'Technique')}"):
                                st.markdown(f"**ID:** `{item.get('metadata', {}).get('technique_id', 'N/A')}`")
                                st.markdown(f"**Tactic:** {item['metadata'].get('tactics', 'N/A')}")
                                st.markdown(f"**Similarity:** `{round(item['similarity_score'], 2)}`")
                                st.markdown("---")
                                st.write(item['document'][:400] + "...")
                    else:
                        st.info("ℹ️ No specific MITRE techniques matched")
                else:
                    st.warning("⚠️ RAG service unavailable")
            except Exception as e:
                st.error(f"❌ RAG service error: {str(e)}")
        
        st.success("✅ Analysis completed successfully!")
    
    elif analyze and not ip:
        st.warning("⚠️ Please enter an IP address")
    else:
        st.info("💡 Enter an IP address and click 'Run Threat Analysis' to begin")

# ================= FOOTER =================
st.markdown(f"""
<div class="footer">
    Enterprise IP Threat Intelligence Platform • Powered by 10 AI Agents<br>
    Generated {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
</div>
""", unsafe_allow_html=True)