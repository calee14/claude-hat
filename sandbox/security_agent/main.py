#!/usr/bin/env python3
"""
Security Testing Agent - Automated Vulnerability Discovery
Orchestrates iterative security testing using AI-guided exploit generation
"""

import os
import json
import time
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional
import anthropic


class SecurityAgent:
    def __init__(self, target_url: str = "http://localhost:3000", api_key: Optional[str] = None):
        """Initialize the security testing agent."""
        self.target_url = target_url
        self.client = anthropic.Anthropic(api_key=api_key or os.environ.get("ANTHROPIC_API_KEY"))
        self.base_dir = Path(__file__).parent
        self.exploits_dir = self.base_dir / "exploits"
        self.results_dir = self.base_dir / "results"
        self.prompts_dir = self.base_dir / "prompts"

        # Ensure directories exist
        self.exploits_dir.mkdir(exist_ok=True)
        self.results_dir.mkdir(exist_ok=True)
        self.prompts_dir.mkdir(exist_ok=True)

        # State tracking
        self.findings = []
        self.tested_vectors = set()
        self.iteration = 0
        self.max_iterations = 10

        # Vulnerability categories to test
        self.vuln_categories = [
            "Authentication Bypass",
            "SQL Injection",
            "XSS (Cross-Site Scripting)",
            "Command Injection",
            "Path Traversal",
            "SSRF (Server-Side Request Forgery)",
            "IDOR (Insecure Direct Object Reference)",
            "Information Disclosure",
            "Privilege Escalation",
            "Missing Authorization"
        ]

    def log(self, message: str, level: str = "INFO"):
        """Log messages with timestamp."""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"[{timestamp}] [{level}] {message}")

    def save_results(self, data: Dict, filename: str):
        """Save results to JSON file."""
        filepath = self.results_dir / filename
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2)
        self.log(f"Results saved to {filepath}")

    def load_prompt(self, phase: str) -> str:
        """Load prompt template for a specific phase."""
        prompt_file = self.prompts_dir / f"{phase}.txt"
        if prompt_file.exists():
            return prompt_file.read_text()
        return ""

    def reconnaissance(self) -> Dict:
        """Phase 1: Analyze application structure and enumerate attack surface."""
        self.log("=== PHASE 1: RECONNAISSANCE ===", "PHASE")

        prompt = f"""You are a security testing AI analyzing a web application for vulnerabilities.

Target: {self.target_url}

Your task is to perform reconnaissance on this Next.js application. Analyze the following:

1. **Application Structure:**
   - Identify all API routes and endpoints
   - Find server actions and their parameters
   - Map out client-side pages
   - Identify authentication mechanisms

2. **Technology Stack:**
   - Framework version and configuration
   - Dependencies and libraries
   - Environment variable usage

3. **Attack Surface:**
   - List all user inputs (query params, form fields, headers, cookies)
   - Identify file paths and operations
   - Note any external integrations

Based on the following codebase snapshot, provide a JSON response with your findings:

API Routes Found:
- /api/users (GET, POST)
- /api/admin (GET, POST, DELETE)

Application Type: Next.js with TypeScript

Provide your analysis in this JSON format:
{{
  "endpoints": [
    {{
      "path": "/api/users",
      "methods": ["GET", "POST"],
      "parameters": ["username", "id"],
      "authentication": "none"
    }}
  ],
  "input_vectors": [
    {{
      "location": "/api/users?username=",
      "type": "query_parameter",
      "purpose": "user lookup"
    }}
  ],
  "interesting_findings": [
    "Description of anything unusual or potentially vulnerable"
  ],
  "technology_stack": {{
    "framework": "Next.js",
    "language": "TypeScript",
    "runtime": "Node.js"
  }}
}}
"""

        message = self.client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=4096,
            messages=[{"role": "user", "content": prompt}]
        )

        response_text = message.content[0].text

        # Extract JSON from response
        try:
            # Try to find JSON in the response
            start_idx = response_text.find('{')
            end_idx = response_text.rfind('}') + 1
            if start_idx != -1 and end_idx > start_idx:
                recon_data = json.loads(response_text[start_idx:end_idx])
            else:
                recon_data = {"raw_response": response_text}
        except json.JSONDecodeError:
            recon_data = {"raw_response": response_text}

        self.save_results(recon_data, f"recon_{self.iteration}.json")
        return recon_data

    def generate_hypotheses(self, recon_data: Dict) -> List[Dict]:
        """Phase 2: Generate vulnerability hypotheses based on reconnaissance."""
        self.log("=== PHASE 2: HYPOTHESIS GENERATION ===", "PHASE")

        prompt = f"""Based on the reconnaissance data below, generate specific vulnerability hypotheses.

Reconnaissance Data:
{json.dumps(recon_data, indent=2)}

For each potential vulnerability, provide:
1. Vulnerability type (from OWASP Top 10)
2. Specific location in the application
3. Attack vector description
4. Expected impact
5. Confidence level (high/medium/low)

Focus on these vulnerability types:
{', '.join(self.vuln_categories)}

Return a JSON array of hypotheses:
[
  {{
    "id": "VULN-001",
    "type": "SQL Injection",
    "location": "/api/users?username=",
    "description": "Username parameter may be vulnerable to SQL injection",
    "attack_vector": "Manipulate username parameter with SQL payloads",
    "impact": "Data exfiltration, authentication bypass",
    "confidence": "high",
    "test_payload_idea": "admin' OR '1'='1"
  }}
]

Generate at least 5 hypotheses based on common Next.js vulnerabilities.
"""

        message = self.client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=4096,
            messages=[{"role": "user", "content": prompt}]
        )

        response_text = message.content[0].text

        try:
            start_idx = response_text.find('[')
            end_idx = response_text.rfind(']') + 1
            if start_idx != -1 and end_idx > start_idx:
                hypotheses = json.loads(response_text[start_idx:end_idx])
            else:
                hypotheses = []
        except json.JSONDecodeError:
            hypotheses = []
            self.log("Failed to parse hypotheses JSON", "ERROR")

        self.save_results(hypotheses, f"hypotheses_{self.iteration}.json")
        return hypotheses

    def generate_exploit_script(self, hypothesis: Dict) -> Optional[str]:
        """Phase 3: Generate Python exploit script for a hypothesis."""
        self.log(f"=== PHASE 3: EXPLOIT GENERATION for {hypothesis.get('id', 'UNKNOWN')} ===", "PHASE")

        prompt = f"""Generate a Python exploit script to test this vulnerability hypothesis:

Hypothesis:
{json.dumps(hypothesis, indent=2)}

Target URL: {self.target_url}

Requirements:
1. Use the 'requests' library
2. Include clear comments explaining each step
3. Return results in JSON format
4. Handle errors gracefully
5. Include the vulnerability ID in output
6. Be non-destructive (read-only when possible)

The script should:
- Test the specific vulnerability
- Capture the response
- Determine if the vulnerability exists
- Report findings in JSON format

Output a complete, executable Python script starting with:
```python
#!/usr/bin/env python3
import requests
import json
import sys

def exploit():
    # Exploit code here
    pass

if __name__ == "__main__":
    result = exploit()
    print(json.dumps(result, indent=2))
```

Provide ONLY the Python code, no additional explanation.
"""

        message = self.client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=4096,
            messages=[{"role": "user", "content": prompt}]
        )

        script_text = message.content[0].text

        # Extract Python code from markdown code blocks if present
        if "```python" in script_text:
            start_idx = script_text.find("```python") + 9
            end_idx = script_text.find("```", start_idx)
            script_text = script_text[start_idx:end_idx].strip()
        elif "```" in script_text:
            start_idx = script_text.find("```") + 3
            end_idx = script_text.find("```", start_idx)
            script_text = script_text[start_idx:end_idx].strip()

        # Save exploit script
        vuln_id = hypothesis.get('id', f'VULN-{self.iteration}')
        script_path = self.exploits_dir / f"{vuln_id}.py"

        with open(script_path, 'w') as f:
            f.write(script_text)

        # Make executable
        os.chmod(script_path, 0o755)

        self.log(f"Exploit script saved to {script_path}")
        return str(script_path)

    def execute_exploit(self, script_path: str, hypothesis: Dict) -> Dict:
        """Phase 4: Execute the exploit script and capture results."""
        self.log(f"=== PHASE 4: EXPLOIT EXECUTION for {hypothesis.get('id', 'UNKNOWN')} ===", "PHASE")

        try:
            # Run the exploit script
            result = subprocess.run(
                ['python3', script_path],
                capture_output=True,
                text=True,
                timeout=30
            )

            # Parse output
            if result.returncode == 0:
                try:
                    exploit_result = json.loads(result.stdout)
                except json.JSONDecodeError:
                    exploit_result = {
                        "status": "error",
                        "message": "Failed to parse exploit output",
                        "raw_output": result.stdout
                    }
            else:
                exploit_result = {
                    "status": "error",
                    "message": "Exploit execution failed",
                    "stderr": result.stderr,
                    "stdout": result.stdout
                }

            # Add metadata
            exploit_result['hypothesis'] = hypothesis
            exploit_result['timestamp'] = datetime.now().isoformat()
            exploit_result['script_path'] = script_path

            return exploit_result

        except subprocess.TimeoutExpired:
            return {
                "status": "timeout",
                "message": "Exploit execution timed out",
                "hypothesis": hypothesis
            }
        except Exception as e:
            return {
                "status": "error",
                "message": str(e),
                "hypothesis": hypothesis
            }

    def analyze_results(self, exploit_result: Dict) -> Dict:
        """Phase 5: Analyze exploit results and learn."""
        self.log(f"=== PHASE 5: RESULT ANALYSIS ===", "PHASE")

        prompt = f"""Analyze the results of this security test:

Exploit Result:
{json.dumps(exploit_result, indent=2)}

Determine:
1. Was the vulnerability confirmed? (yes/no/uncertain)
2. What evidence supports your conclusion?
3. What is the severity? (critical/high/medium/low/info)
4. What data was exposed or what access was gained?
5. What should be tested next based on these findings?

Provide your analysis in JSON format:
{{
  "vulnerability_confirmed": true,
  "evidence": ["List of evidence items"],
  "severity": "high",
  "impact_description": "What can an attacker do",
  "data_exposed": ["list of exposed data"],
  "recommendations": ["What to test next"],
  "cvss_score": 7.5
}}
"""

        message = self.client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=2048,
            messages=[{"role": "user", "content": prompt}]
        )

        response_text = message.content[0].text

        try:
            start_idx = response_text.find('{')
            end_idx = response_text.rfind('}') + 1
            if start_idx != -1 and end_idx > start_idx:
                analysis = json.loads(response_text[start_idx:end_idx])
            else:
                analysis = {"raw_analysis": response_text}
        except json.JSONDecodeError:
            analysis = {"raw_analysis": response_text}

        # Combine exploit result and analysis
        finding = {
            **exploit_result,
            "analysis": analysis,
            "iteration": self.iteration
        }

        # Save finding
        if analysis.get("vulnerability_confirmed"):
            self.findings.append(finding)
            self.log(f"✓ Vulnerability confirmed: {exploit_result.get('hypothesis', {}).get('type')}", "SUCCESS")

        return finding

    def run(self):
        """Main orchestration loop."""
        self.log("Starting Security Testing Agent", "START")
        self.log(f"Target: {self.target_url}")

        # Initial reconnaissance
        recon_data = self.reconnaissance()

        # Main testing loop
        while self.iteration < self.max_iterations:
            self.iteration += 1
            self.log(f"\n{'='*60}\nITERATION {self.iteration}/{self.max_iterations}\n{'='*60}", "ITERATION")

            # Generate hypotheses
            hypotheses = self.generate_hypotheses(recon_data)

            if not hypotheses:
                self.log("No hypotheses generated, ending iteration", "WARNING")
                break

            # Test each hypothesis
            for hypothesis in hypotheses[:3]:  # Test top 3 per iteration
                vuln_id = hypothesis.get('id', 'UNKNOWN')

                # Skip if already tested
                if vuln_id in self.tested_vectors:
                    self.log(f"Skipping already tested: {vuln_id}", "SKIP")
                    continue

                self.tested_vectors.add(vuln_id)

                # Generate exploit
                script_path = self.generate_exploit_script(hypothesis)
                if not script_path:
                    continue

                # Execute exploit
                exploit_result = self.execute_exploit(script_path, hypothesis)

                # Analyze results
                finding = self.analyze_results(exploit_result)

                # Save individual finding
                self.save_results(finding, f"finding_{vuln_id}.json")

                # Brief pause between tests
                time.sleep(2)

        # Generate final report
        self.generate_final_report()

    def generate_final_report(self):
        """Generate comprehensive security assessment report."""
        self.log("=== GENERATING FINAL REPORT ===", "REPORT")

        report = {
            "assessment_metadata": {
                "target": self.target_url,
                "start_time": datetime.now().isoformat(),
                "iterations": self.iteration,
                "total_tests": len(self.tested_vectors),
                "vulnerabilities_found": len(self.findings)
            },
            "findings": self.findings,
            "summary": {
                "critical": len([f for f in self.findings if f.get('analysis', {}).get('severity') == 'critical']),
                "high": len([f for f in self.findings if f.get('analysis', {}).get('severity') == 'high']),
                "medium": len([f for f in self.findings if f.get('analysis', {}).get('severity') == 'medium']),
                "low": len([f for f in self.findings if f.get('analysis', {}).get('severity') == 'low']),
                "info": len([f for f in self.findings if f.get('analysis', {}).get('severity') == 'info'])
            },
            "tested_categories": list(self.tested_vectors)
        }

        self.save_results(report, f"FINAL_REPORT_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")

        # Print summary
        print("\n" + "="*60)
        print("SECURITY ASSESSMENT COMPLETE")
        print("="*60)
        print(f"Target: {self.target_url}")
        print(f"Total Tests: {len(self.tested_vectors)}")
        print(f"Vulnerabilities Found: {len(self.findings)}")
        print(f"\nSeverity Breakdown:")
        print(f"  Critical: {report['summary']['critical']}")
        print(f"  High: {report['summary']['high']}")
        print(f"  Medium: {report['summary']['medium']}")
        print(f"  Low: {report['summary']['low']}")
        print(f"  Info: {report['summary']['info']}")
        print(f"\nDetailed results saved to: {self.results_dir}")
        print("="*60 + "\n")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="AI-Powered Security Testing Agent")
    parser.add_argument("--target", default="http://localhost:3000", help="Target URL")
    parser.add_argument("--iterations", type=int, default=10, help="Max iterations")
    parser.add_argument("--api-key", help="Anthropic API key (or set ANTHROPIC_API_KEY env var)")

    args = parser.parse_args()

    agent = SecurityAgent(target_url=args.target, api_key=args.api_key)
    agent.max_iterations = args.iterations

    try:
        agent.run()
    except KeyboardInterrupt:
        print("\n\nAgent interrupted by user")
        agent.generate_final_report()
    except Exception as e:
        print(f"\n\nAgent encountered an error: {e}")
        import traceback
        traceback.print_exc()
        agent.generate_final_report()
