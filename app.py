#!/usr/bin/env python3
"""
Namespace Dominance Engine - Semi-Autonomous Agentic DNS Intelligence Platform

Author: Offensive Cybersecurity Engineer
Version: 1.0.0
Classification: RESTRICTED - Passive Reconnaissance Only

This Streamlit application implements a 6-phase Domain & DNS Intelligence workflow
with dynamic LLM-powered command generation and human-in-the-loop approval.

Requirements:
streamlit>=1.28.0
google-generativeai>=0.3.0
requests>=2.31.0
python-dotenv>=1.0.0
graphviz>=0.20.1
rich>=13.6.0
asyncio
subprocess
json
datetime
re
os
sys
"""

import streamlit as st
import google.generativeai as genai
import requests
import subprocess
import asyncio
import json
import re
import os
import sys
import time
import threading
from datetime import datetime, timezone
from typing import Dict, List, Tuple, Optional, Any
from dataclasses import dataclass, asdict
from pathlib import Path
import graphviz
from rich.console import Console
from rich.text import Text
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table
from rich.tree import Tree
import io
import base64
from concurrent.futures import ThreadPoolExecutor

# Configure Streamlit page
st.set_page_config(
    page_title="Namespace Dominance Engine",
    page_icon="⚡",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for military C2 console aesthetic
st.markdown("""
<style>
    .stApp {
        background: linear-gradient(135deg, #0a0a0a 0%, #1a0000 100%);
        color: #ff0000;
    }
    .stTextInput > div > div > input {
        background-color: #1a0000;
        color: #ff0000;
        border: 1px solid #ff0000;
    }
    .stButton > button {
        background-color: #1a0000;
        color: #ff0000;
        border: 1px solid #ff0000;
        font-weight: bold;
    }
    .stButton > button:hover {
        background-color: #ff0000;
        color: #000000;
    }
    .stSelectbox > div > div > select {
        background-color: #1a0000;
        color: #ff0000;
        border: 1px solid #ff0000;
    }
    .stTextArea > div > div > textarea {
        background-color: #0a0a0a;
        color: #ff0000;
        border: 1px solid #ff0000;
    }
    .phase-complete {
        border: 2px solid #00ff00;
        background-color: #001100;
    }
    .phase-active {
        border: 2px solid #ffaa00;
        background-color: #1a1a00;
    }
    .phase-pending {
        border: 2px solid #666666;
        background-color: #0a0a0a;
    }
    .console-output {
        background-color: #000000;
        color: #00ff00;
        font-family: 'Courier New', monospace;
        padding: 10px;
        border: 1px solid #333333;
        max-height: 400px;
        overflow-y: auto;
    }
    .military-header {
        background: linear-gradient(90deg, #ff0000, #660000);
        padding: 20px;
        text-align: center;
        font-weight: bold;
        font-size: 24px;
        text-transform: uppercase;
        letter-spacing: 3px;
        margin-bottom: 20px;
    }
</style>
""", unsafe_allow_html=True)

@dataclass
class PhaseResult:
    """Structured result for each phase execution"""
    phase_number: int
    phase_name: str
    status: str  # PENDING, ACTIVE, COMPLETED, FAILED
    start_time: Optional[datetime]
    end_time: Optional[datetime]
    commands_executed: List[str]
    findings: Dict[str, Any]
    artifacts: List[str]
    confidence_score: float
    reasoning: str

@dataclass
class NamespaceMap:
    """Master namespace mapping structure"""
    target_domain: str
    discovery_phases: Dict[int, PhaseResult]
    infrastructure_skeleton: Dict[str, Any]
    temporal_analysis: Dict[str, Any]
    control_plane: Dict[str, Any]
    adversarial_posture: Dict[str, Any]
    predictive_model: Dict[str, Any]
    created_at: datetime
    last_updated: datetime

class AIAgent:
    """Agentic AI powered by Gemini for dynamic command generation"""
    
    def __init__(self, api_key: str):
        genai.configure(api_key=api_key)
        self.model = genai.GenerativeModel('gemini-2.0-flash-exp')
        self.console = Console()
        
    def generate_phase_commands(self, phase: int, target: str, context: Dict[str, Any]) -> Tuple[str, List[str], str]:
        """Dynamically generate commands for a specific phase"""
        
        phase_doctrine = {
            0: {
                "name": "Event Horizon Framing",
                "objectives": [
                    "Authority Surface Isolation",
                    "Temporal Ownership Compression", 
                    "Semantic Drift Mapping",
                    "Registrar Behavior Fingerprinting"
                ],
                "techniques": [
                    "WHOIS registrar analysis",
                    "Historical ownership records",
                    "DNS semantic variation analysis",
                    "Registration pattern fingerprinting"
                ]
            },
            1: {
                "name": "Inertial Enumeration",
                "objectives": [
                    "Historical Resolution Echoes",
                    "Cross-Zone Naming Symmetry",
                    "Delegation Entropy Analysis",
                    "Operational Laziness Exploitation"
                ],
                "techniques": [
                    "Passive DNS historical analysis",
                    "Subzone enumeration via public records",
                    "NS delegation pattern analysis",
                    "Infrastructure reuse detection"
                ]
            },
            2: {
                "name": "Temporal Parallax",
                "objectives": [
                    "Resolution Latency Phase-Shift",
                    "TTL Personality Profiling",
                    "Propagation Asymmetry Detection",
                    "Maintenance Window Inference"
                ],
                "techniques": [
                    "DNS resolution timing analysis",
                    "TTL variation fingerprinting",
                    "Geographic propagation analysis",
                    "Maintenance pattern detection"
                ]
            },
            3: {
                "name": "Infrastructure Skeletonization",
                "objectives": [
                    "Shared Fate Correlation",
                    "Negative Space Cartography",
                    "Protocol Behavior Residue",
                    "Fallback Path Reconstruction"
                ],
                "techniques": [
                    "IP infrastructure correlation",
                    "Unused subnet analysis",
                    "Service fingerprinting via passive data",
                    "Failover path reconstruction"
                ]
            },
            4: {
                "name": "Control Plane Inference",
                "objectives": [
                    "Update Velocity Measurement",
                    "Rollback Signature Detection",
                    "Blast Radius Estimation",
                    "Control-Key Shadowing (outcome only)"
                ],
                "techniques": [
                    "DNS change frequency analysis",
                    "Configuration rollback detection",
                    "Impact radius calculation",
                    "Control plane inference"
                ]
            },
            5: {
                "name": "Adversarial Posture Modeling",
                "objectives": [
                    "Countermeasure Reflex Profiling",
                    "Decoy Discrimination",
                    "Sensor Placement Inference",
                    "Escalation Threshold Mapping"
                ],
                "techniques": [
                    "Security posture analysis",
                    "Honeypot/decoy detection",
                    "Sensor network mapping",
                    "Response threshold analysis"
                ]
            },
            6: {
                "name": "Predictive Namespace Dominance",
                "objectives": [
                    "Future Domain Pre-Image Modeling",
                    "Lifecycle Exhaust Mapping",
                    "Strategic Choke Anticipation",
                    "Deterministic Collapse Triggering (outcome only)"
                ],
                "techniques": [
                    "Future domain prediction",
                    "Lifecycle pattern analysis",
                    "Chokepoint identification",
                    "Collapse prediction modeling"
                ]
            }
        }
        
        phase_info = phase_doctrine.get(phase, phase_doctrine[0])
        
        prompt = f"""
You are an elite offensive cybersecurity engineer executing Phase {phase}: {phase_info['name']} against target {target}.

DOCTRINE - ABSOLUTE LAW:
{chr(10).join(f"{i+1}. {obj}" for i, obj in enumerate(phase_info['objectives']))}

AUTHORIZED TECHNIQUES (PASSIVE ONLY):
{chr(10).join(f"- {tech}" for tech in phase_info['techniques'])}

CONTEXT FROM PREVIOUS PHASES:
{json.dumps(context, indent=2)}

MISSION:
Generate a comprehensive reasoning and exact shell commands to achieve all phase objectives.

RULES:
1. ALL TECHNIQUES MUST BE PASSIVE - no active DNS queries, port scans, or direct HTTP requests
2. Use public data sources: Certificate Transparency, SecurityTrails, Shodan, PassiveTotal, DNS dumps, Common Crawl
3. Each command must be complete and executable
4. Include proper error handling and output parsing
5. Commands must be dynamically generated - no hardcoded lists
6. Focus on evidence collection and correlation

RESPONSE FORMAT:
---REASONING---
[Detailed tactical reasoning for this phase execution]
---COMMANDS---
[Complete shell commands, one per line]
---EXPECTED_OUTCOME---
[Expected intelligence outcomes]
"""
        
        try:
            response = self.model.generate_content(prompt)
            response_text = response.text
            
            # Parse response
            reasoning_match = re.search(r'---REASONING---(.*?)---COMMANDS---', response_text, re.DOTALL)
            commands_match = re.search(r'---COMMANDS---(.*?)---EXPECTED_OUTCOME---', response_text, re.DOTALL)
            outcome_match = re.search(r'---EXPECTED_OUTCOME---(.*)', response_text, re.DOTALL)
            
            reasoning = reasoning_match.group(1).strip() if reasoning_match else "Reasoning not parsed"
            commands_text = commands_match.group(1).strip() if commands_match else ""
            expected_outcome = outcome_match.group(1).strip() if outcome_match else "Outcome not parsed"
            
            # Parse commands into list
            commands = [cmd.strip() for cmd in commands_text.split('\n') if cmd.strip() and not cmd.strip().startswith('#')]
            
            return reasoning, commands, expected_outcome
            
        except Exception as e:
            return f"AI Generation Error: {str(e)}", [], "Failed to generate commands"

class NamespaceDominanceEngine:
    """Main application class for the Namespace Dominance Engine"""
    
    def __init__(self):
        self.console = Console()
        self.executor = ThreadPoolExecutor(max_workers=4)
        
    def initialize_session_state(self):
        """Initialize Streamlit session state variables"""
        if 'target_domain' not in st.session_state:
            st.session_state.target_domain = ""
        if 'api_key' not in st.session_state:
            st.session_state.api_key = ""
        if 'current_phase' not in st.session_state:
            st.session_state.current_phase = 0
        if 'phase_results' not in st.session_state:
            st.session_state.phase_results = {}
        if 'namespace_map' not in st.session_state:
            st.session_state.namespace_map = None
        if 'operation_log' not in st.session_state:
            st.session_state.operation_log = []
        if 'ai_agent' not in st.session_state:
            st.session_state.ai_agent = None
        if 'execution_approved' not in st.session_state:
            st.session_state.execution_approved = False
        if 'current_reasoning' not in st.session_state:
            st.session_state.current_reasoning = ""
        if 'current_commands' not in st.session_state:
            st.session_state.current_commands = []
        if 'operation_start_time' not in st.session_state:
            st.session_state.operation_start_time = None
            
    def render_header(self):
        """Render the military-style header"""
        st.markdown("""
        <div class="military-header">
            ⚡ NAMESPACE DOMINANCE ENGINE ⚡
            <br><small>SEMI-AUTONOMOUS AGENTIC DNS INTELLIGENCE PLATFORM</small>
        </div>
        """, unsafe_allow_html=True)
        
    def render_sidebar(self):
        """Render the control sidebar"""
        st.sidebar.markdown("### ⚙️ CONFIGURATION")
        
        # API Key input
        api_key = st.sidebar.text_input(
            "🔑 Gemini API Key",
            type="password",
            value=st.session_state.api_key,
            help="Enter your Gemini API key for AI command generation"
        )
        st.session_state.api_key = api_key
        
        # Target domain input
        target_domain = st.sidebar.text_input(
            "🎯 Target Domain",
            value=st.session_state.target_domain,
            help="Enter the target domain for intelligence gathering"
        )
        st.session_state.target_domain = target_domain
        
        # Initialize AI agent if API key provided
        if api_key and not st.session_state.ai_agent:
            try:
                st.session_state.ai_agent = AIAgent(api_key)
                st.sidebar.success("✅ AI Agent Initialized")
            except Exception as e:
                st.sidebar.error(f"❌ AI Agent Failed: {str(e)}")
                
        # Phase progress indicator
        st.sidebar.markdown("### 📊 PHASE PROGRESS")
        
        phase_names = [
            "Event Horizon Framing",
            "Inertial Enumeration", 
            "Temporal Parallax",
            "Infrastructure Skeletonization",
            "Control Plane Inference",
            "Adversarial Posture Modeling",
            "Predictive Namespace Dominance"
        ]
        
        for i, name in enumerate(phase_names):
            if i < st.session_state.current_phase:
                status = "✅"
                css_class = "phase-complete"
            elif i == st.session_state.current_phase:
                status = "🔄"
                css_class = "phase-active"
            else:
                status = "⏳"
                css_class = "phase-pending"
                
            st.sidebar.markdown(f"""
            <div class="{css_class}" style="padding: 5px; margin: 2px; border-radius: 3px;">
                {status} Phase {i}: {name}
            </div>
            """, unsafe_allow_html=True)
            
        # Operation controls
        st.sidebar.markdown("### 🎮 OPERATION CONTROLS")
        
        if st.sidebar.button(
            "🚀 START OPERATION",
            disabled=not (api_key and target_domain),
            help="Initialize the intelligence operation"
        ):
            self.start_operation()
            
        if st.sidebar.button(
            "📥 EXPORT RESULTS",
            disabled=st.session_state.namespace_map is None,
            help="Export operation results as JSON"
        ):
            self.export_results()
            
        if st.sidebar.button(
            "🔄 RESET SESSION",
            help="Clear all session data and start fresh"
        ):
            self.reset_session()
            
    def start_operation(self):
        """Initialize a new operation"""
        if not st.session_state.target_domain or not st.session_state.api_key:
            st.error("❌ Target domain and API key required")
            return
            
        st.session_state.operation_start_time = datetime.now(timezone.utc)
        st.session_state.current_phase = 0
        st.session_state.phase_results = {}
        st.session_state.operation_log = []
        st.session_state.namespace_map = None
        
        self.log_event(f"🚀 Operation initiated against {st.session_state.target_domain}")
        st.rerun()
        
    def reset_session(self):
        """Reset the entire session"""
        for key in st.session_state.keys():
            del st.session_state[key]
        self.initialize_session_state()
        st.rerun()
        
    def log_event(self, message: str):
        """Add event to operation log"""
        timestamp = datetime.now(timezone.utc).isoformat()
        st.session_state.operation_log.append({
            "timestamp": timestamp,
            "message": message
        })
        
    def execute_command(self, command: str) -> Tuple[str, int, str]:
        """Execute a shell command and return output"""
        try:
            # Replace template variables
            command = command.replace("{TARGET}", st.session_state.target_domain)
            command = command.replace("{DOMAIN}", st.session_state.target_domain)
            
            # Execute command with timeout
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=300  # 5 minute timeout
            )
            
            return result.stdout, result.returncode, result.stderr
            
        except subprocess.TimeoutExpired:
            return "", 1, "Command timed out after 5 minutes"
        except Exception as e:
            return "", 1, str(e)
            
    def render_phase_execution(self):
        """Render the current phase execution interface"""
        if not st.session_state.ai_agent or not st.session_state.target_domain:
            st.warning("⚠️ Configure API key and target domain to begin")
            return
            
        if st.session_state.current_phase > 6:
            st.success("🎉 Operation Complete - All phases executed")
            self.render_final_results()
            return
            
        phase_names = [
            "Event Horizon Framing",
            "Inertial Enumeration", 
            "Temporal Parallax",
            "Infrastructure Skeletonization",
            "Control Plane Inference",
            "Adversarial Posture Modeling",
            "Predictive Namespace Dominance"
        ]
        
        current_phase_name = phase_names[st.session_state.current_phase]
        
        st.markdown(f"### 🎯 Phase {st.session_state.current_phase}: {current_phase_name}")
        
        # Generate phase commands if not already done
        if not st.session_state.current_reasoning and not st.session_state.current_commands:
            with st.spinner("🧠 AI Agent generating tactical approach..."):
                context = {
                    "previous_phases": {
                        str(k): asdict(v) for k, v in st.session_state.phase_results.items()
                    },
                    "target": st.session_state.target_domain,
                    "current_phase": st.session_state.current_phase
                }
                
                reasoning, commands, outcome = st.session_state.ai_agent.generate_phase_commands(
                    st.session_state.current_phase,
                    st.session_state.target_domain,
                    context
                )
                
                st.session_state.current_reasoning = reasoning
                st.session_state.current_commands = commands
                
        # Display AI reasoning
        if st.session_state.current_reasoning:
            st.markdown("#### 🧠 AI TACTICAL REASONING")
            st.markdown(f"""
            <div style="background-color: #1a0000; padding: 15px; border: 1px solid #ff0000; border-radius: 5px;">
            {st.session_state.current_reasoning}
            </div>
            """, unsafe_allow_html=True)
            
        # Display generated commands
        if st.session_state.current_commands:
            st.markdown("#### ⚡ DYNAMICALLY GENERATED COMMANDS")
            
            for i, cmd in enumerate(st.session_state.current_commands, 1):
                st.markdown(f"**Command {i}:**")
                st.code(cmd, language="bash")
                
            # Expected outcome
            if hasattr(st.session_state.ai_agent, 'model'):
                st.markdown("#### 🎯 EXPECTED OUTCOME")
                st.markdown(f"""
                <div style="background-color: #001100; padding: 10px; border: 1px solid #00ff00; border-radius: 5px; color: #00ff00;">
                Intelligence gathering will achieve the phase objectives through passive reconnaissance techniques.
                </div>
                """, unsafe_allow_html=True)
                
            # Human approval gate
            st.markdown("#### 🔐 HUMAN-IN-THE-LOOP APPROVAL")
            
            col1, col2 = st.columns(2)
            
            with col1:
                if st.button(
                    "✅ APPROVE & EXECUTE",
                    type="primary",
                    help="Execute the generated commands"
                ):
                    self.execute_phase()
                    
            with col2:
                if st.button(
                    "❌ REJECT & REGENERATE",
                    help="Reject these commands and generate new ones"
                ):
                    st.session_state.current_reasoning = ""
                    st.session_state.current_commands = []
                    st.rerun()
                    
    def execute_phase(self):
        """Execute the current phase commands"""
        if not st.session_state.current_commands:
            st.error("No commands to execute")
            return
            
        phase_number = st.session_state.current_phase
        phase_names = [
            "Event Horizon Framing",
            "Inertial Enumeration", 
            "Temporal Parallax",
            "Infrastructure Skeletonization",
            "Control Plane Inference",
            "Adversarial Posture Modeling",
            "Predictive Namespace Dominance"
        ]
        
        phase_result = PhaseResult(
            phase_number=phase_number,
            phase_name=phase_names[phase_number],
            status="ACTIVE",
            start_time=datetime.now(timezone.utc),
            end_time=None,
            commands_executed=[],
            findings={},
            artifacts=[],
            confidence_score=0.0,
            reasoning=st.session_state.current_reasoning
        )
        
        # Create execution log container
        log_container = st.container()
        
        with log_container:
            st.markdown("#### 📡 EXECUTION LOG")
            execution_log = st.empty()
            log_content = []
            
        # Execute each command
        for i, command in enumerate(st.session_state.current_commands, 1):
            self.log_event(f"🔄 Executing command {i}/{len(st.session_state.current_commands)}: {command[:50]}...")
            
            # Update execution log
            log_content.append(f"[{datetime.now().strftime('%H:%M:%S')}] Executing: {command}")
            execution_log.markdown(f"""
            <div class="console-output">
            {'<br>'.join(log_content)}
            </div>
            """, unsafe_allow_html=True)
            
            # Execute command
            stdout, returncode, stderr = self.execute_command(command)
            
            phase_result.commands_executed.append(command)
            
            # Log results
            if returncode == 0:
                log_content.append(f"[{datetime.now().strftime('%H:%M:%S')}] ✓ SUCCESS")
                if stdout.strip():
                    log_content.append(f"OUTPUT: {stdout[:200]}..." if len(stdout) > 200 else f"OUTPUT: {stdout}")
                phase_result.findings[f"command_{i}"] = {
                    "command": command,
                    "status": "success",
                    "output": stdout
                }
            else:
                log_content.append(f"[{datetime.now().strftime('%H:%M:%S')}] ✗ FAILED (code: {returncode})")
                if stderr.strip():
                    log_content.append(f"ERROR: {stderr[:200]}..." if len(stderr) > 200 else f"ERROR: {stderr}")
                phase_result.findings[f"command_{i}"] = {
                    "command": command,
                    "status": "failed",
                    "error": stderr
                }
                
            # Update display
            execution_log.markdown(f"""
            <div class="console-output">
            {'<br>'.join(log_content)}
            </div>
            """, unsafe_allow_html=True)
            
            # Small delay for visual effect
            time.sleep(0.5)
            
        # Complete phase
        phase_result.end_time = datetime.now(timezone.utc)
        phase_result.status = "COMPLETED"
        
        # Calculate confidence score based on success rate
        successful_commands = sum(1 for f in phase_result.findings.values() if f.get("status") == "success")
        phase_result.confidence_score = successful_commands / len(phase_result.commands_executed) if phase_result.commands_executed else 0.0
        
        # Store result
        st.session_state.phase_results[phase_number] = phase_result
        
        # Log completion
        self.log_event(f"✅ Phase {phase_number} completed with {phase_result.confidence_score:.1%} confidence")
        
        # Clear current commands and advance to next phase
        st.session_state.current_reasoning = ""
        st.session_state.current_commands = []
        st.session_state.current_phase += 1
        
        st.success(f"🎉 Phase {phase_number} completed successfully!")
        time.sleep(2)
        st.rerun()
        
    def render_operation_log(self):
        """Render the operation log"""
        st.markdown("### 📋 OPERATION LOG")
        
        if not st.session_state.operation_log:
            st.info("No operations logged yet")
            return
            
        log_container = st.container()
        
        with log_container:
            log_text = []
            for entry in reversed(st.session_state.operation_log[-20:]):  # Show last 20 entries
                timestamp = datetime.fromisoformat(entry["timestamp"]).strftime('%H:%M:%S')
                log_text.append(f"[{timestamp}] {entry['message']}")
                
            st.markdown(f"""
            <div class="console-output">
            {'<br>'.join(log_text)}
            </div>
            """, unsafe_allow_html=True)
            
    def render_phase_summary(self):
        """Render summary of completed phases"""
        st.markdown("### 📊 PHASE SUMMARY")
        
        if not st.session_state.phase_results:
            st.info("No phases completed yet")
            return
            
        for phase_num, result in st.session_state.phase_results.items():
            with st.expander(f"Phase {phase_num}: {result.phase_name} - {result.status}"):
                col1, col2 = st.columns(2)
                
                with col1:
                    st.markdown(f"**Status:** {result.status}")
                    st.markdown(f"**Confidence:** {result.confidence_score:.1%}")
                    st.markdown(f"**Duration:** {(result.end_time - result.start_time).total_seconds():.1f}s")
                    st.markdown(f"**Commands Executed:** {len(result.commands_executed)}")
                    
                with col2:
                    st.markdown("**Reasoning:**")
                    st.markdown(f"<small>{result.reasoning[:200]}...</small>" if len(result.reasoning) > 200 else f"<small>{result.reasoning}</small>", unsafe_allow_html=True)
                    
                if result.findings:
                    st.markdown("**Findings:**")
                    for key, finding in result.findings.items():
                        status_icon = "✅" if finding.get("status") == "success" else "❌"
                        st.markdown(f"{status_icon} {key}: {finding.get('status', 'unknown')}")
                        
    def render_namespace_map(self):
        """Render the master namespace map"""
        st.markdown("### 🗺️ MASTER NAMESPACE MAP")
        
        if not st.session_state.phase_results:
            st.info("Namespace map will populate as phases complete")
            return
            
        # Create visual representation
        try:
            dot = graphviz.Digraph(comment='Namespace Map', format='png')
            dot.attr(bgcolor='black', fontcolor='red', node_color='red', edge_color='red')
            
            # Add target domain
            dot.node(st.session_state.target_domain, st.session_state.target_domain, color='red', fontcolor='red')
            
            # Add phase nodes
            for phase_num, result in st.session_state.phase_results.items():
                phase_label = f"Phase {phase_num}\n{result.status}"
                dot.attr('node', shape='box', color='green' if result.status == 'COMPLETED' else 'yellow')
                dot.node(f"phase_{phase_num}", phase_label)
                dot.edge(st.session_state.target_domain, f"phase_{phase_num}")
                
            # Render graph
            st.graphviz_chart(dot)
            
        except Exception as e:
            st.error(f"Graph rendering failed: {str(e)}")
            
        # Show structured data
        if st.button("📋 Show Raw Data"):
            st.json({
                str(k): asdict(v) for k, v in st.session_state.phase_results.items()
            })
            
    def render_final_results(self):
        """Render final operation results"""
        st.markdown("### 🎉 OPERATION COMPLETE")
        
        if st.session_state.operation_start_time:
            duration = datetime.now(timezone.utc) - st.session_state.operation_start_time
            st.markdown(f"**Total Duration:** {duration.total_seconds():.1f} seconds")
            
        # Calculate overall confidence
        if st.session_state.phase_results:
            total_confidence = sum(r.confidence_score for r in st.session_state.phase_results.values())
            avg_confidence = total_confidence / len(st.session_state.phase_results)
            st.markdown(f"**Overall Confidence:** {avg_confidence:.1%}")
            
        # Export options
        col1, col2, col3 = st.columns(3)
        
        with col1:
            if st.button("📄 Export JSON"):
                self.export_json()
                
        with col2:
            if st.button("📊 Export Report"):
                self.export_report()
                
        with col3:
            if st.button("🔄 New Operation"):
                self.reset_session()
                
    def export_json(self):
        """Export results as JSON"""
        if not st.session_state.phase_results:
            st.error("No results to export")
            return
            
        export_data = {
            "target_domain": st.session_state.target_domain,
            "operation_start_time": st.session_state.operation_start_time.isoformat() if st.session_state.operation_start_time else None,
            "phase_results": {
                str(k): asdict(v) for k, v in st.session_state.phase_results.items()
            },
            "operation_log": st.session_state.operation_log,
            "export_timestamp": datetime.now(timezone.utc).isoformat()
        }
        
        json_str = json.dumps(export_data, indent=2, default=str)
        st.download_button(
            label="📥 Download JSON",
            data=json_str,
            file_name=f"namespace_dominance_{st.session_state.target_domain}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
            mime="application/json"
        )
        
    def export_report(self):
        """Export a formatted report"""
        if not st.session_state.phase_results:
            st.error("No results to export")
            return
            
        report = f"""
# NAMESPACE DOMINANCE ENGINE - OPERATION REPORT

**Target Domain:** {st.session_state.target_domain}
**Operation Start:** {st.session_state.operation_start_time}
**Operation Duration:** {(datetime.now(timezone.utc) - st.session_state.operation_start_time).total_seconds():.1f} seconds

## EXECUTIVE SUMMARY

Operation completed {len(st.session_state.phase_results)} phases of intelligence gathering.

## PHASE RESULTS

"""
        
        for phase_num, result in st.session_state.phase_results.items():
            report += f"""
### Phase {phase_num}: {result.phase_name}
- **Status:** {result.status}
- **Confidence Score:** {result.confidence_score:.1%}
- **Duration:** {(result.end_time - result.start_time).total_seconds():.1f} seconds
- **Commands Executed:** {len(result.commands_executed)}

**Key Findings:**
"""
            
            for key, finding in result.findings.items():
                if finding.get("status") == "success":
                    report += f"- {key}: SUCCESS\n"
                else:
                    report += f"- {key}: FAILED - {finding.get('error', 'Unknown error')}\n"
                    
        report += f"""

## OPERATION LOG

"""
        
        for entry in st.session_state.operation_log:
            timestamp = datetime.fromisoformat(entry["timestamp"]).strftime('%Y-%m-%d %H:%M:%S UTC')
            report += f"[{timestamp}] {entry['message']}\n"
            
        report += f"""

---
Generated by Namespace Dominance Engine on {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}
Classification: RESTRICTED - Passive Reconnaissance Only
"""
        
        st.download_button(
            label="📥 Download Report",
            data=report,
            file_name=f"namespace_report_{st.session_state.target_domain}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md",
            mime="text/markdown"
        )
        
    def export_results(self):
        """Export all results"""
        self.export_json()
        
    def run(self):
        """Main application runner"""
        self.initialize_session_state()
        self.render_header()
        self.render_sidebar()
        
        # Main content area
        if st.session_state.target_domain and st.session_state.api_key:
            # Phase execution
            self.render_phase_execution()
            
            # Operation log
            self.render_operation_log()
            
            # Phase summary
            self.render_phase_summary()
            
            # Namespace map
            self.render_namespace_map()
            
            # Final results if complete
            if st.session_state.current_phase > 6:
                self.render_final_results()
        else:
            st.markdown("""
            ### 🎯 MISSION BRIEFING
            
            Welcome to the **Namespace Dominance Engine** - a semi-autonomous agentic platform for 
            comprehensive DNS and domain intelligence gathering.
            
            **CAPABILITIES:**
            - 🔍 6-Phase intelligence workflow
            - 🧠 AI-powered dynamic command generation
            - 🔒 100% passive reconnaissance
            - 👤 Human-in-the-loop approval
            - 📊 Real-time progress tracking
            - 🗺️ Master namespace mapping
            
            **GET STARTED:**
            1. Enter your Gemini API key in the sidebar
            2. Specify your target domain
            3. Click "START OPERATION" to begin
            
            **DOCTRINE:**
            This platform operates under strict passive reconnaissance protocols.
            All intelligence is gathered from publicly available sources without 
            direct interaction with target infrastructure.
            """)
            
def main():
    """Main entry point"""
    app = NamespaceDominanceEngine()
    app.run()
    
if __name__ == "__main__":
    main()
