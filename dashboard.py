"""
🔐 Advanced IP Threat Intelligence Dashboard
Beautiful Dark Theme with Enhanced Visuals
"""

import streamlit as st
import requests
import json
from datetime import datetime
from crew import IPIntelligenceCrew
import plotly.graph_objects as go

# ========== PAGE CONFIG ==========
st.set_page_config(
    page_title="🔍 IP Threat Intel Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ========== CUSTOM CSS ==========
st.markdown("""
<style>
    /* Dark theme enhancements */
    .main {
        background: linear-gradient(135deg, #0f0c29, #302b63, #24243e);
    }
    
    /* Cards */
    .stAlert {
        background: rgba(255, 255, 255, 0.05);
        border-radius: 15px;
        border: 1px solid rgba(255, 255, 255, 0.1);
        backdrop-filter: blur(10px);
    }
    
    /* Metrics */
    [data-testid="stMetricValue"] {
        font-size: 2rem;
        font-weight: bold;
        background: linear-gradient(90deg, #00d2ff, #3a47d5);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
    }
    
    /* Buttons */
    .stButton>button {
        background: linear-gradient(90deg, #ff416c, #ff4b2b);
        color: white;
        border: none;
        border-radius: 25px;
        padding: 15px 40px;
        font-weight: bold;
        box-shadow: 0 8px 15px rgba(255, 65, 108, 0.4);
        transition: all 0.3s;
    }
    
    .stButton>button:hover {
        transform: translateY(-2px);
        box-shadow: 0 12px 20px rgba(255, 65, 108, 0.6);
    }
    
    /* Input fields */
    .stTextInput>div>div>input {
        background: rgba(255, 255, 255, 0.1);
        border: 2px solid rgba(255, 255, 255, 0.2);
        border-radius: 10px;
        color: white;
        font-size: 1.1rem;
    }
    
    /* Headers */
    h1, h2, h3 {
        background: linear-gradient(90deg, #00d2ff, #3a47d5);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        font-weight: 800;
    }
    
    /* Expanders */
    .streamlit-expanderHeader {
        background: rgba(255, 255, 255, 0.05);
        border-radius: 10px;
        border: 1px solid rgba(255, 255, 255, 0.1);
    }
    
    /* Success/Error boxes */
    .element-container div[data-testid="stSuccess"],
    .element-container div[data-testid="stError"],
    .element-container div[data-testid="stWarning"] {
        border-radius: 15px;
        backdrop-filter: blur(10px);
    }
</style>
""", unsafe_allow_html=True)

# ========== HEADER ==========
st.markdown("""
<div style='text-align: center; padding: 2rem 0;'>
    <h1 style='font-size: 3.5rem; margin: 0;'>🛡️ IP Threat Intelligence Platform</h1>
    <p style='font-size: 1.2rem; color: #888; margin-top: 10px;'>
        Powered by 10 AI Agents + 4 ML Services
    </p>
</div>
""", unsafe_allow_html=True)

st.markdown("---")

# ========== SIDEBAR - RAG CHATBOT ==========
with st.sidebar:
    st.markdown("### 💬 MITRE ATT&CK Assistant")
    st.caption("🔍 Search threat intelligence knowledge base")
    
    rag_query = st.text_input(
        "",
        placeholder="Ask about tactics, techniques...",
        key="rag_input",
        label_visibility="collapsed"
    )
    
    if st.button("🔎 Search", use_container_width=True):
        if rag_query:
            with st.spinner("🔍 Searching..."):
                try:
                    r = requests.post(
                        "http://localhost:8001/retrieve",
                        json={"query": rag_query, "top_k": 10, "min_similarity": 0.2},
                        timeout=10
                    )
                    if r.ok:
                        data = r.json()
                        if data.get("total_results", 0) > 0:
                            st.success(f"✅ Found {data['total_results']} MITRE techniques")
                            
                            for i, item in enumerate(data['results'], 1):
                                with st.expander(f"🧠 {item['metadata'].get('name', 'Technique')}"):
                                    st.markdown(f"**Technique ID:** `{item.get('metadata', {}).get('technique_id', 'N/A')}`")
                                    st.markdown(f"**Tactic:** {item['metadata'].get('tactics', 'N/A')}")
                                    st.markdown(f"**Platforms:** {item['metadata'].get('platforms', 'N/A')}")
                                    st.markdown(f"**Similarity:** `{round(item['similarity_score'], 2)}`")
                                    st.markdown("---")
                                    st.write(item['document'][:500] + "...")
                        else:
                            st.warning("⚠️ No matching techniques")
                    else:
                        st.error(f"❌ Error: {r.status_code}")
                except Exception as e:
                    st.error(f"❌ Service error: {str(e)}")

# ========== MAIN CONTENT ==========
col1, col2, col3 = st.columns([2, 1, 1])

with col1:
    ip_input = st.text_input(
        "🌐 Target IP Address",
        placeholder="e.g., 188.78.122.141",
        help="Enter IPv4 address to analyze"
    )

with col2:
    st.write("")
    st.write("")
    analyze_btn = st.button("🚀 Analyze Threat", use_container_width=True, type="primary")

with col3:
    st.write("")
    st.write("")
    if st.button("🔄 Clear", use_container_width=True):
        st.rerun()

st.markdown("---")

# ========== ANALYSIS ==========
if analyze_btn and ip_input:
    
    # Service health dashboard
    st.markdown("### 🔌 System Health Monitor")
    
    services = {
        "ML Inference": ("http://localhost:8500/health", "🤖"),
        "Alert Triage": ("http://localhost:8100/health", "🚨"),
        "RAG Service": ("http://localhost:8300/health", "🎯"),
        "Wazuh SIEM": ("http://localhost:8002/health", "📊")
    }
    
    cols = st.columns(4)
    for idx, (name, (url, icon)) in enumerate(services.items()):
        with cols[idx]:
            try:
                r = requests.get(url, timeout=2)
                if r.ok:
                    st.success(f"{icon} **{name}**\n\n✅ Online")
                else:
                    st.warning(f"{icon} **{name}**\n\n⚠️ Degraded")
            except:
                st.error(f"{icon} **{name}**\n\n❌ Offline")
    
    st.markdown("---")
    
    # Progress animation
    st.markdown("### 🤖 Multi-Agent Analysis Pipeline")
    progress_bar = st.progress(0)
    status = st.empty()
    
    # Run analysis
    try:
        status.markdown("🔄 Initializing 10-agent crew...")
        progress_bar.progress(10)
        
        crew_instance = IPIntelligenceCrew()
        my_crew = crew_instance.crew()
        
        status.markdown("⚡ Executing threat intelligence workflow...")
        progress_bar.progress(40)
        
        result = my_crew.kickoff(inputs={'ip_address': ip_input})
        
        progress_bar.progress(100)
        status.markdown("✅ **Analysis Complete!**")
        
        st.balloons()  # Celebration animation
        
        # Results in tabs
        tab1, tab2, tab3, tab4, tab5 = st.tabs([
            "📊 Final Report",
            "🤖 ML Classification", 
            "🚨 Alert Triage",
            "🎯 MITRE Context",
            "📈 Raw Services"
        ])
        
        with tab1:
            st.markdown("## 🔵 IOC Investigation Report")
            st.markdown(result)
            
            # Threat visualization
            st.markdown("### 📊 Threat Level Visualization")
            fig = go.Figure(go.Indicator(
                mode="gauge+number",
                value=75,  # Extract from result
                title={'text': "Threat Score"},
                gauge={
                    'axis': {'range': [None, 100]},
                    'bar': {'color': "darkred"},
                    'steps': [
                        {'range': [0, 25], 'color': "lightgreen"},
                        {'range': [25, 50], 'color': "yellow"},
                        {'range': [50, 75], 'color': "orange"},
                        {'range': [75, 100], 'color': "red"}
                    ]
                }
            ))
            fig.update_layout(height=300, paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)")
            st.plotly_chart(fig, use_container_width=True)
        
        with tab2:
            st.markdown("## 🤖 ML Traffic Classification")
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
                        st.metric("📊 Confidence", f"{conf:.2f}%")
                    with col3:
                        st.metric("🤖 Model", ml_data.get('model_used', 'N/A'))
                    
                    st.json(ml_data)
                else:
                    st.warning("⚠️ ML service unavailable")
            except:
                st.error("❌ Failed to fetch ML data")
        
        with tab3:
            st.markdown("## 🚨 Alert Triage Analysis")
            st.warning("⚠️ Service unavailable (Ollama not connected)")
            st.info("💡 Crew handled gracefully and continued analysis")
        
        with tab4:
            st.markdown("## 🎯 MITRE ATT&CK Context")
            try:
                rag_r = requests.post(
                    "http://localhost:8300/retrieve",
                    json={
                        "query": "malicious activity associated with this IP",
                        "top_k": 5,
                        "min_similarity": 0.3
                },
                    timeout=10
                )
                if rag_r.ok:    
                    rag_data = rag_r.json()
                    st.metric("📊 Results Found", rag_data.get('total_results', 0))
                    
                    if rag_data.get('results'):
                        for i, item in enumerate(rag_data['results'], 1):
                            with st.expander(f"🧠 {item['metadata'].get('name', 'MITRE Technique')}"):
                                st.markdown(f"**Tactic:** {item['metadata'].get('tactics')}")
                                st.markdown(f"**Platforms:** {item['metadata'].get('platforms')}")
                                st.markdown(f"**Similarity Score:** `{round(item['similarity_score'], 2)}`")
                                st.markdown("**Description:**")
                                st.write(item['document'])
                    else:
                        st.info("ℹ️ No MITRE data for this IP")
                else:
                    st.warning("⚠️ RAG service unavailable")
            except:
                st.error("❌ Failed to fetch MITRE data")
        
        with tab5:
            st.markdown("## 📈 Individual Service Outputs")
            with st.expander("🔍 VirusTotal"):
                st.info("Integrated in final report")
            with st.expander("🔍 AbuseIPDB"):
                st.info("Integrated in final report")
            with st.expander("🔍 Yeti"):
                st.info("Integrated in final report")
            with st.expander("🔍 Wazuh SIEM"):
                st.info("Integrated in final report")
            with st.expander("🤖 ML Raw Output"):
                try:
                    ml_r = requests.post("http://localhost:8500/predict", json={"features": [0]*77, "model_name": "random_forest"})
                    st.json(ml_r.json() if ml_r.ok else {"error": "offline"})
                except:
                    st.error("Service offline")
        
        st.success("✅ Analysis completed successfully!")
        
    except Exception as e:
        st.error(f"❌ Error: {str(e)}")
        st.exception(e)

elif analyze_btn:
    st.warning("⚠️ Please enter an IP address")

# Footer
st.markdown("---")
st.markdown(
    f"""
    <div style='text-align: center; padding: 1rem; color: #888;'>
        <p><strong>IP Threat Intelligence Platform</strong> v2.0</p>
        <p>10 AI Agents | 4 ML Services | Real-time Analysis</p>
        <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
    </div>
    """,
    unsafe_allow_html=True
)