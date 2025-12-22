"""
IP Intelligence - Streamlit Web Interface
"""

import streamlit as st
import json
from datetime import datetime
from crew import IPIntelligenceCrew

st.set_page_config(
    page_title="IP Intelligence Platform",
    page_icon="🔍",
    layout="wide"
)

st.title("🔍 IP Threat Intelligence Platform")
st.markdown("Multi-source IP reputation analysis powered by AI agents")

# Sidebar
with st.sidebar:
    st.header("⚙️ Configuration")
    st.info("**Sources:**\n- VirusTotal\n- AbuseIPDB\n- Yeti (Internal)")
    
    if st.button("🔄 Clear History"):
        st.session_state.clear()
        st.rerun()

# Input
col1, col2 = st.columns([3, 1])
with col1:
    ip_input = st.text_input(
        "Enter IP Address(es)",
        placeholder="8.8.8.8, 1.1.1.1, 200.234.226.199",
        help="Comma-separated for multiple IPs"
    )

with col2:
    st.write("")
    st.write("")
    analyze_btn = st.button("🚀 Analyze", type="primary", use_container_width=True)

# Analysis
if analyze_btn and ip_input:
    with st.spinner("🤖 AI Agents analyzing threat intelligence..."):
        try:
            # Run crew
            crew_instance = IPIntelligenceCrew()
            my_crew = crew_instance.crew()
            result = my_crew.kickoff(inputs={'ip_addresses': ip_input})
            
            # Display results
            st.success("✅ Analysis Complete!")
            
            # Tabs for different views
            tab1, tab2, tab3 = st.tabs(["📊 Summary", "📝 Full Report", "🔧 Raw Data"])
            
            with tab1:
                st.markdown("### Threat Assessment")
                # Parse and display summary (you'll need to format result)
                st.markdown(str(result))
            
            with tab2:
                st.markdown("### Detailed Analysis")
                st.text_area("Full Report", str(result), height=400)
            
            with tab3:
                st.json({"result": str(result), "timestamp": datetime.now().isoformat()})
            
            # Download button
            st.download_button(
                label="📥 Download Report",
                data=str(result),
                file_name=f"ip_intel_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
                mime="text/plain"
            )
            
        except Exception as e:
            st.error(f"❌ Error: {e}")

# Footer
st.markdown("---")
st.caption("Powered by CrewAI + Groq + Yeti Threat Intelligence")