#!/usr/bin/env python3
"""
Elite Web3 Orchestrator - Central coordination system for bug bounty hunting
Based on the elite audit flow with specialized agents for Web3 vulnerability research.
"""

import json
import os
import sys
import time
import asyncio
from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from datetime import datetime

# Add the parent directory to the path to import the advanced modules
sys.path.append(str(Path(__file__).parent.parent.parent))

from advanced.llm_reasoning_engine import AdvancedLLMReasoner
from advanced.langgraph_orchestrator import LangGraphOrchestrator
from advanced.financial_flow_analyzer import FinancialFlowAnalyzer
from advanced.dual_phase_llm import AuditorAgent, CriticAgent


@dataclass
class AgentResult:
    """Result from an agent execution"""
    agent_name: str
    phase: str
    status: str  # "success", "failed", "pending"
    findings: List[Dict[str, Any]]
    confidence: float
    execution_time: float
    error: Optional[str] = None


@dataclass
class OrchestratorConfig:
    """Configuration for the orchestrator"""
    max_concurrent_agents: int = 4
    max_retries: int = 3
    phase_timeout: int = 300  # 5 minutes
    confidence_threshold: float = 0.8
    enable_financial_analysis: bool = True
    enable_disproof_council: bool = True
    enable_mastermind: bool = True


class EliteWeb3Orchestrator:
    """
    Elite Web3 Orchestrator - Central coordination system for bug bounty hunting
    Manages the 10-phase audit lifecycle with specialized agents
    """
    
    def __init__(self, config: OrchestratorConfig = None):
        self.config = config or OrchestratorConfig()
        self.agents = {}
        self.results = {}
        self.current_phase = 0
        self.active_agents = []
        self.run_id = f"bounty-{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        # Initialize LLM reasoning engine
        self.llm_reasoner = AdvancedLLMReasoner()
        
        # Initialize specialized agents
        self._initialize_agents()
        
    def _initialize_agents(self):
        """Initialize all specialized agents"""
        # Reconnaissance agents
        self.agents['recon-alpha'] = {
            'name': 'Architecture Intelligence Lead',
            'phase': 0,
            'batch': 1,
            'description': 'Codebase architecture and surface mapping'
        }
        self.agents['recon-beta'] = {
            'name': 'Static Analysis Lead', 
            'phase': 0,
            'batch': 1,
            'description': 'Static analysis and pattern detection'
        }
        self.agents['recon-gamma'] = {
            'name': 'Access Control Intelligence Lead',
            'phase': 0, 
            'batch': 2,
            'description': 'Access control and permissions analysis'
        }
        self.agents['recon-delta'] = {
            'name': 'Integration Intelligence Lead',
            'phase': 0,
            'batch': 2, 
            'description': 'External integrations and dependencies'
        }
        self.agents['recon-epsilon'] = {
            'name': 'Protocol Classification Lead',
            'phase': 0,
            'batch': 2,
            'description': 'Protocol classification and attack surface'
        }
        
        # Build agents
        self.agents['build-alpha'] = {
            'name': 'Build Alpha',
            'phase': 1,
            'batch': 1,
            'description': 'Project detection and build setup'
        }
        self.agents['build-beta'] = {
            'name': 'Build Beta', 
            'phase': 1,
            'batch': 1,
            'description': 'Dependency installation and compilation'
        }
        self.agents['build-gamma'] = {
            'name': 'Build Gamma',
            'phase': 1,
            'batch': 1,
            'description': 'Test execution and validation'
        }
        
        # Hunter agents
        hunter_agents = [
            'hunter-alpha', 'hunter-beta', 'hunter-gamma', 'hunter-delta',
            'hunter-epsilon', 'hunter-zeta', 'hunter-eta', 'hunter-theta',
            'hunter-iota', 'hunter-kappa'
        ]
        
        for i, agent in enumerate(hunter_agents):
            batch = (i // 3) + 1
            self.agents[agent] = {
                'name': f'Hunter {agent.split("-")[1].title()}',
                'phase': 3,
                'batch': batch,
                'description': f'Vulnerability hunting - {agent.split("-")[1]}'
            }
        
        # Validator agents
        self.agents['validator-alpha'] = {
            'name': 'Vulnerability Validator',
            'phase': 5,
            'batch': 1,
            'description': 'Vulnerability validation and PoC execution'
        }
        self.agents['validator-beta'] = {
            'name': 'Economic Validator',
            'phase': 5,
            'batch': 1,
            'description': 'Economic validation and impact assessment'
        }
        
        # Skeptic agents
        self.agents['skeptic-alpha'] = {
            'name': 'Logical Denier',
            'phase': 6,
            'batch': 1,
            'description': 'Logical analysis and claim refutation'
        }
        self.agents['skeptic-beta'] = {
            'name': 'Economic Reality Check',
            'phase': 6,
            'batch': 1,
            'description': 'Economic viability assessment'
        }
        self.agents['skeptic-gamma'] = {
            'name': 'Defense Analyst',
            'phase': 6,
            'batch': 1,
            'description': 'Defense mechanism analysis'
        }
        
        # Mastermind
        self.agents['the-mastermind'] = {
            'name': 'The Mastermind',
            'phase': 9,
            'batch': 1,
            'description': 'Final logic synthesis and arbiter'
        }
        
    async def run_audit(self, target_path: str, output_dir: str = None) -> Dict[str, Any]:
        """
        Run the complete elite audit process
        """
        if not output_dir:
            output_dir = f"bug_bounty_results_{self.run_id}"
        
        os.makedirs(output_dir, exist_ok=True)
        
        print(f"🚀 Starting Elite Web3 Bug Bounty Audit")
        print(f"📁 Target: {target_path}")
        print(f"📊 Run ID: {self.run_id}")
        print(f"📁 Output: {output_dir}")
        print("=" * 60)
        
        # Phase 0: Pre-Build Recon
        await self._execute_phase(0, target_path, output_dir)
        
        # Phase 1: Build & Compile
        await self._execute_phase(1, target_path, output_dir)
        
        # Phase 2: Context & Architecture
        await self._execute_phase(2, target_path, output_dir)
        
        # Phase 3: Hunting
        await self._execute_phase(3, target_path, output_dir)
        
        # Phase 4: Triage Gate
        await self._execute_phase(4, target_path, output_dir)
        
        # Phase 5-7: Disproof Council
        if self.config.enable_disproof_council:
            await self._execute_disproof_council(target_path, output_dir)
        
        # Phase 8: Economic Deep Dive
        if self.config.enable_financial_analysis:
            await self._execute_phase(8, target_path, output_dir)
        
        # Phase 9: Mastermind Synthesis
        if self.config.enable_mastermind:
            await self._execute_phase(9, target_path, output_dir)
        
        # Phase 10: Reporting
        await self._execute_phase(10, target_path, output_dir)
        
        # Generate final report
        final_report = await self._generate_final_report(output_dir)
        
        print("=" * 60)
        print("✅ Elite Web3 Bug Bounty Audit Complete!")
        print(f"📊 Final Report: {output_dir}/final_report.json")
        
        return final_report
    
    async def _execute_phase(self, phase: int, target_path: str, output_dir: str):
        """Execute a specific phase with batched agents"""
        phase_agents = [name for name, info in self.agents.items() if info['phase'] == phase]
        
        if not phase_agents:
            return
        
        print(f"\n🔍 Phase {phase}: Executing {len(phase_agents)} agents")
        
        # Group agents by batch
        batches = {}
        for agent in phase_agents:
            batch = self.agents[agent]['batch']
            if batch not in batches:
                batches[batch] = []
            batches[batch].append(agent)
        
        # Execute batches sequentially
        for batch_num in sorted(batches.keys()):
            batch_agents = batches[batch_num]
            print(f"  📦 Batch {batch_num}: {', '.join(batch_agents)}")
            
            # Execute agents in parallel (up to max_concurrent_agents)
            await self._execute_agent_batch(batch_agents, target_path, output_dir)
    
    async def _execute_agent_batch(self, agent_names: List[str], target_path: str, output_dir: str):
        """Execute a batch of agents in parallel"""
        tasks = []
        
        for agent_name in agent_names:
            task = asyncio.create_task(
                self._execute_agent(agent_name, target_path, output_dir)
            )
            tasks.append(task)
        
        # Wait for all agents in batch to complete
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Process results
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                print(f"  ❌ {agent_names[i]} failed: {result}")
            else:
                print(f"  ✅ {agent_names[i]} completed")
    
    async def _execute_agent(self, agent_name: str, target_path: str, output_dir: str) -> AgentResult:
        """Execute a single agent"""
        start_time = time.time()
        
        try:
            # Simulate agent execution (replace with actual agent logic)
            await asyncio.sleep(1)  # Simulate work
            
            # For now, return a mock result
            result = AgentResult(
                agent_name=agent_name,
                phase=self.agents[agent_name]['phase'],
                status="success",
                findings=[],
                confidence=0.8,
                execution_time=time.time() - start_time
            )
            
            # Store result
            self.results[agent_name] = result
            
            return result
            
        except Exception as e:
            result = AgentResult(
                agent_name=agent_name,
                phase=self.agents[agent_name]['phase'],
                status="failed",
                findings=[],
                confidence=0.0,
                execution_time=time.time() - start_time,
                error=str(e)
            )
            
            self.results[agent_name] = result
            return result
    
    async def _execute_disproof_council(self, target_path: str, output_dir: str):
        """Execute the Disproof Council (Phases 5-7)"""
        print(f"\n🛡️ Disproof Council: Validating findings")
        
        # Phase 5: Validators
        await self._execute_phase(5, target_path, output_dir)
        
        # Phase 6: Skeptics
        await self._execute_phase(6, target_path, output_dir)
        
        # Phase 7: Adversaries
        await self._execute_phase(7, target_path, output_dir)
    
    async def _generate_final_report(self, output_dir: str) -> Dict[str, Any]:
        """Generate the final comprehensive report"""
        report = {
            "run_id": self.run_id,
            "timestamp": datetime.now().isoformat(),
            "phases_completed": list(range(11)),
            "agents_executed": len(self.results),
            "findings": [],
            "summary": {
                "total_findings": 0,
                "critical_findings": 0,
                "high_findings": 0,
                "medium_findings": 0,
                "low_findings": 0
            }
        }
        
        # Aggregate findings from all agents
        for agent_name, result in self.results.items():
            if result.status == "success":
                report["findings"].extend(result.findings)
        
        # Calculate summary statistics
        for finding in report["findings"]:
            severity = finding.get("severity", "low")
            if severity == "critical":
                report["summary"]["critical_findings"] += 1
            elif severity == "high":
                report["summary"]["high_findings"] += 1
            elif severity == "medium":
                report["summary"]["medium_findings"] += 1
            else:
                report["summary"]["low_findings"] += 1
        
        report["summary"]["total_findings"] = len(report["findings"])
        
        # Save report
        report_path = os.path.join(output_dir, "final_report.json")
        with open(report_path, 'w') as f:
            json.dump(report, f, indent=2)
        
        return report


async def main():
    """Main entry point for the orchestrator"""
    if len(sys.argv) < 2:
        print("Usage: python elite-web3-orchestrator.py <target_path> [output_dir]")
        sys.exit(1)
    
    target_path = sys.argv[1]
    output_dir = sys.argv[2] if len(sys.argv) > 2 else None
    
    # Create orchestrator
    config = OrchestratorConfig(
        max_concurrent_agents=4,
        enable_financial_analysis=True,
        enable_disproof_council=True,
        enable_mastermind=True
    )
    
    orchestrator = EliteWeb3Orchestrator(config)
    
    # Run audit
    try:
        report = await orchestrator.run_audit(target_path, output_dir)
        print(f"\n🎯 Audit completed successfully!")
        print(f"📊 Total findings: {report['summary']['total_findings']}")
        print(f"🔴 Critical: {report['summary']['critical_findings']}")
        print(f"🟠 High: {report['summary']['high_findings']}")
        
    except Exception as e:
        print(f"❌ Audit failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
