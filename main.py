"""
IP Intelligence Crew - Main Entry Point
Run IP threat intelligence analysis
"""

import os
from dotenv import load_dotenv
from crew import IPIntelligenceCrew

load_dotenv()


def main():
    print("🔍 IP Intelligence Analysis System")
    print("=" * 50)
    
    # Get IP addresses from user
    ip_input = input("\nEnter IP address(es) to analyze (comma-separated): ").strip()
    
    if not ip_input:
        print("❌ No IPs provided. Exiting.")
        return
    
    print(f"\n🚀 Starting analysis for: {ip_input}")
    print("=" * 50)
    
    try:
        # Initialize crew
        crew_instance = IPIntelligenceCrew()
        my_crew = crew_instance.crew()
        
        # Run analysis
        result = my_crew.kickoff(inputs={'ip_addresses': ip_input})
        
        print("\n" + "=" * 50)
        print("✅ ANALYSIS COMPLETE")
        print("=" * 50)
        print(result)
        
    except Exception as e:
        print(f"\n❌ Error: {e}")


if __name__ == "__main__":
    main()