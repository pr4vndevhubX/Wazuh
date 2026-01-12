"""
IP Intelligence Crew - Professional CrewBase Implementation
Uses @agent and @task decorators with YAML configuration
"""

import os
from dotenv import load_dotenv
from crewai import Agent, Task, Crew, Process, LLM
from crewai.project import CrewBase, agent, task, crew
#to generaet pdf
from utils.pdf_generator import generate_pdf_report

# Import tools
from tools.virustotal_tool import VirusTotalTool
from tools.abuseipdb_tool import AbuseIPDBTool
from tools.yeti_tool import YetiTool
from tools.wazuh_siem_tool import WazuhSIEMTool
from tools.ml_inference_tool import MLInferenceTool
from tools.alert_triage_tool import AlertTriageTool
from tools.rag_tool import RAGTool

load_dotenv()

Virus_total_tool = VirusTotalTool()
abuse_ip_tool = AbuseIPDBTool()
yeti_tool = YetiTool()
wazuh_siem_tool = WazuhSIEMTool()
ml_inference_tool = MLInferenceTool()
alert_triage_tool = AlertTriageTool()
rag_tool = RAGTool() 

# ===== Configure LLM =====
llm = LLM(
    model=os.getenv("OPENROUTER_MODEL"),
    api_key=os.getenv("OPENROUTER_API_KEY"),  # Groq uses OpenAI-compatible API
    base_url=os.getenv("OPENROUTER_API_BASE"),
    provider="openai",
    temperature=0.4,
    max_tokens=2048
)

@CrewBase
class IPIntelligenceCrew:
    """Multi-Source IP Threat Intelligence Analysis Crew"""
    
    agents_config = 'config/agents.yaml'
    tasks_config = 'config/tasks.yaml'
    
    # ===== AGENTS =====
    
    @agent
    def coordinator_agent(self) -> Agent:
        """Agent 1: Threat Intelligence Coordinator"""
        return Agent(
            config=self.agents_config['coordinator_agent'],
            llm=llm,
            verbose=True,
            allow_delegation=True
        )
    
    @agent
    def virustotal_agent(self) -> Agent:
        """Agent 2: VirusTotal Reputation Specialist"""
        return Agent(
            config=self.agents_config['virustotal_agent'],
            llm=llm,
            tools=[Virus_total_tool],
            verbose=True,
            allow_delegation=False
        )
    
    @agent
    def abuseipdb_agent(self) -> Agent:
        """Agent 3: AbuseIPDB Analyst"""
        return Agent(
            config=self.agents_config['abuseipdb_agent'],
            llm=llm,
            tools=[abuse_ip_tool],
            verbose=True,
            allow_delegation=False
        )
    
    @agent
    def yeti_agent(self) -> Agent:
        """Agent 4: Internal Threat Intelligence Analyst"""
        return Agent(
            config=self.agents_config['yeti_agent'],
            llm=llm,
            tools=[yeti_tool],
            verbose=True,
            allow_delegation=False
        )
    
    @agent
    def siem_agent(self) -> Agent:
        """Agent 5: SIEM Historical Analyst"""
        return Agent(
            config=self.agents_config['siem_agent'],
            llm=llm,
            tools=[wazuh_siem_tool],
            verbose=True,
            allow_delegation=False
        )
    
    @agent
    def ml_classifier_agent(self) -> Agent:
        """Agent 6: ML Traffic Classifier"""
        return Agent(
            config=self.agents_config['ml_classifier_agent'],
            llm=llm,
            tools=[ml_inference_tool],
            verbose=True,
            allow_delegation=False
        )

    @agent
    def analyst_agent(self) -> Agent:
        """Agent 7: Threat Correlation Analyst"""
        return Agent(
            config=self.agents_config['analyst_agent'],
            llm=llm,
            verbose=True,
            allow_delegation=False
        )
    
    @agent
    def reporter_agent(self) -> Agent:
        """Agent 8: Security Report Writer"""
        return Agent(
            config=self.agents_config['reporter_agent'],
            llm=llm,
            verbose=True,
            allow_delegation=False
        )
    
    @agent
    def alert_triage_agent(self) -> Agent:
        """Agent 9: Alert Triage Analyst"""
        return Agent(
            config=self.agents_config['alert_triage_agent'],
            llm=llm,
            tools=[alert_triage_tool],
            verbose=True,
            allow_delegation=False
        )
    
    @agent
    def mitre_context_agent(self) -> Agent:
        """Agent 10: MITRE ATT&CK Analyst"""
        return Agent(
            config=self.agents_config['mitre_context_agent'],
            llm=llm,
            tools=[rag_tool],
            verbose=True,
            allow_delegation=False
        )
        
 
    
    
    # ===== TASKS =====
    
    @task
    def task_coordinator(self) -> Task:
        """Task 1: Coordinate investigation workflow"""
        return Task(
            config=self.tasks_config['task_coordinator'],
            agent=self.coordinator_agent()
        )
    
    @task
    def task_virustotal_check(self) -> Task:
        """Task 2: Query VirusTotal"""
        return Task(
            config=self.tasks_config['task_virustotal_check'],
            agent=self.virustotal_agent(),
            context=[self.task_coordinator()]
        )
    
    @task
    def task_abuseipdb_check(self) -> Task:
        """Task 3: Query AbuseIPDB"""
        return Task(
            config=self.tasks_config['task_abuseipdb_check'],
            agent=self.abuseipdb_agent(),
            context=[self.task_coordinator()]
        )
    
    @task
    def task_yeti_check(self) -> Task:
        """Task 4: Query Yeti"""
        return Task(
            config=self.tasks_config['task_yeti_check'],
            agent=self.yeti_agent(),
            context=[self.task_coordinator()]
        )
    
    @task
    def task_siem_query(self) -> Task:
        """Task 5: Query Wazuh SIEM"""
        return Task(
            config=self.tasks_config['task_siem_query'],
            agent=self.siem_agent(),
            context=[self.task_coordinator()]
        )
    
    @task
    def task_ml_classification(self) -> Task:
        """Task 6: ML Traffic Classification"""
        return Task(
            config=self.tasks_config['task_ml_classification'],
            agent=self.ml_classifier_agent(),
            context=[self.task_coordinator()]
        )
    
    @task
    def task_alert_triage(self) -> Task:
        """Task 7: LLM Alert Analysis"""
        return Task(
            config=self.tasks_config['task_alert_triage'],
            agent=self.alert_triage_agent(),
            context=[self.task_coordinator()]
        )
    
    @task
    def task_mitre_context(self) -> Task:
        """Task 8: MITRE Context Retrieval"""
        return Task(
            config=self.tasks_config['task_mitre_context'],
            agent=self.mitre_context_agent(),
            context=[self.task_coordinator()]
        )
    
    @task
    def task_correlation_analysis(self) -> Task:
        """Task 9: Correlate all findings"""
        return Task(
            config=self.tasks_config['task_correlation_analysis'],
            agent=self.analyst_agent(),
            context=[
                self.task_coordinator(),
                self.task_virustotal_check(),
                self.task_abuseipdb_check(),
                self.task_yeti_check(),
                self.task_siem_query(),
                self.task_ml_classification(),
                self.task_alert_triage(),
                self.task_mitre_context()
            ]
        )
    
    @task
    def task_generate_report(self) -> Task:
        """Task 10: Generate final report"""
        return Task(
            config=self.tasks_config['task_generate_report'],
            agent=self.reporter_agent(),
            context=[
                self.task_coordinator(),
                self.task_virustotal_check(),
                self.task_abuseipdb_check(),
                self.task_yeti_check(),
                self.task_ml_classification(),
                self.task_correlation_analysis()
            ]
        )
    
    
    # ===== CREW =====
    
    @crew
    def crew(self) -> Crew:
        """Create the IP Intelligence Crew"""
        return Crew(
            agents=self.agents,
            tasks=self.tasks,
            process=Process.sequential,
            verbose=True,
            memory=False,
            cache=True
        )


# ===== TEST =====
if __name__ == "__main__":
    print("🏗️  Building IP Intelligence Crew...\n")
    
    try:
        crew_instance = IPIntelligenceCrew()
        my_crew = crew_instance.crew()
        print(f"✅ Crew initialized successfully!")
        print(f"   Agents: {len(my_crew.agents)}")
        print(f"   Tasks: {len(my_crew.tasks)}")
        # Remove this line - PDF is generated after crew runs, not here
        # pdf_filename = generate_pdf_report()
        
    except Exception as e:
        print(f"❌ Error: {e}")