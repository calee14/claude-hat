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
import requests


class SecurityAgent:
    def __init__(
        self, target_url: str = "http://localhost:3000", api_key: Optional[str] = None
    ):
        """Initialize the security testing agent."""
        self.target_url = target_url
        self.client = anthropic.Anthropic(
            api_key=api_key or os.environ.get("ANTHROPIC_API_KEY")
        )
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
            "Missing Authorization",
        ]

    def log(self, message: str, level: str = "INFO"):
        """Log messages with timestamp."""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"[{timestamp}] [{level}] {message}")

    def save_results(self, data: Dict, filename: str):
        """Save results to JSON file."""
        filepath = self.results_dir / filename
        with open(filepath, "w") as f:
            json.dump(data, f, indent=2)
        self.log(f"Results saved to {filepath}")

    def load_prompt(self, phase: str) -> str:
        """Load prompt template for a specific phase."""
        prompt_file = self.prompts_dir / f"{phase}.txt"
        if prompt_file.exists():
            return prompt_file.read_text()
        return ""

    def simple_route_probe(self) -> Dict:
        """Fallback: Directly probe common Next.js routes."""
        self.log("Using fallback route probing...", "INFO")

        common_routes = [
            "/",
            "/profile",
            "/api/users",
            "/api/admin",
            "/api/auth",
            "/api/graphql",
            "/api/search",
        ]

        endpoints = []
        api_routes = []
        pages = []

        for route in common_routes:
            try:
                url = f"{self.target_url}{route}"
                response = requests.get(url, timeout=5)

                endpoint = {
                    "path": route,
                    "full_url": url,
                    "status_code": response.status_code,
                    "methods": ["GET"],  # We know GET works
                    "parameters": [],
                    "depth": 0,
                }

                # Try to detect parameters from URL
                if "?" in route:
                    params = route.split("?")[1].split("&")
                    endpoint["parameters"] = [p.split("=")[0] for p in params]

                endpoints.append(endpoint)

                if route.startswith("/api/"):
                    api_routes.append(route)
                else:
                    pages.append(route)

                self.log(f"  ✓ Found: {route} (status: {response.status_code})")

            except Exception as e:
                self.log(f"  ✗ {route} not accessible", "DEBUG")

        return {
            "endpoints": endpoints,
            "api_routes": api_routes,
            "pages": pages,
            "input_vectors": [],
            "technology_detected": "Next.js",
            "method": "fallback_probe",
        }

    def reconnaissance(self) -> Dict:
        """Phase 1: Generate and run route discovery script to map attack surface."""
        self.log("=== PHASE 1: RECONNAISSANCE (Route Discovery) ===", "PHASE")

        # Step 1: Generate route discovery script
        self.log("Generating route discovery script with AI...")

        prompt = f"""Generate a Python script that discovers routes and endpoints on a web application.

Target URL: {self.target_url}

Requirements:
1. **Spider/Crawl the application** starting from the base URL
2. **Discover routes** by:
   - Following links (href, src)
   - Parsing JavaScript for API endpoints
   - Checking common paths (/api/*, /_next/*, /admin/*, etc.)
   - Finding form actions
   - Detecting AJAX endpoints

3. **Prevent infinite loops**:
   - Track visited URLs in a set
   - Implement max depth limit (default: 3)
   - URL normalization (remove fragments, sort query params)
   - Timeout per request (5 seconds)
   - Overall timeout (60 seconds)
   - Skip external domains

4. **Output JSON** with discovered routes:
   {{
     "endpoints": [
       {{
         "url": "/api/users",
         "methods": ["GET"],
         "parameters": ["username", "id"],
         "forms": [],
         "depth": 1
       }}
     ],
     "pages": ["/", "/profile"],
     "api_routes": ["/api/users", "/api/admin"],
     "input_vectors": [],
     "technology_detected": "Next.js"
   }}

5. **Handle errors gracefully** - don't crash on 404s or timeouts

Generate a complete, executable Python script using:
- requests library
- BeautifulSoup for HTML parsing
- re for regex patterns
- urllib.parse for URL handling

The script should be defensive and robust. Include the script ONLY, no explanation.

Start with:
```python
#!/usr/bin/env python3
import requests
from bs4 import BeautifulSoup
import json
import re
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
import time
import sys

def discover_routes(base_url, max_depth=3, timeout=60):
    # Implementation here
    pass

if __name__ == "__main__":
    result = discover_routes("{self.target_url}")
    print(json.dumps(result, indent=2))
```
"""

        message = self.client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=8192,
            messages=[{"role": "user", "content": prompt}],
        )

        script_text = message.content[0].text

        # Extract Python code
        if "```python" in script_text:
            start_idx = script_text.find("```python") + 9
            end_idx = script_text.find("```", start_idx)
            script_text = script_text[start_idx:end_idx].strip()
        elif "```" in script_text:
            start_idx = script_text.find("```") + 3
            end_idx = script_text.find("```", start_idx)
            script_text = script_text[start_idx:end_idx].strip()

        # Save reconnaissance script
        script_path = self.exploits_dir / f"route_discovery_{self.iteration}.py"
        with open(script_path, "w") as f:
            f.write(script_text)
        os.chmod(script_path, 0o755)

        self.log(f"Route discovery script saved to {script_path}")

        # Step 2: Execute route discovery script
        self.log("Executing route discovery script...")

        try:
            result = subprocess.run(
                ["python3", str(script_path)],
                capture_output=True,
                text=True,
                timeout=90,  # Generous timeout for initial discovery
            )

            if result.returncode == 0:
                try:
                    recon_data = json.loads(result.stdout)
                    self.log(
                        f"Discovered {len(recon_data.get('endpoints', []))} endpoints"
                    )
                    self.log(
                        f"Discovered {len(recon_data.get('api_routes', []))} API routes"
                    )
                except json.JSONDecodeError:
                    self.log("Failed to parse route discovery output", "WARNING")
                    recon_data = {
                        "raw_output": result.stdout,
                        "error": "JSON parse failed",
                    }
            else:
                self.log(f"Route discovery script failed: {result.stderr}", "ERROR")
                recon_data = {
                    "error": "Script execution failed",
                    "stderr": result.stderr,
                    "stdout": result.stdout,
                }

        except subprocess.TimeoutExpired:
            self.log("Route discovery timed out, using fallback", "WARNING")
            recon_data = self.simple_route_probe()
        except Exception as e:
            self.log(f"Route discovery error: {e}, using fallback", "ERROR")
            recon_data = self.simple_route_probe()

        # If script failed or returned no endpoints, use fallback
        if not recon_data.get("endpoints"):
            self.log("No endpoints discovered, using fallback probe", "WARNING")
            recon_data = self.simple_route_probe()

        # Add metadata
        recon_data["script_path"] = (
            str(script_path) if "script_path" in locals() else "fallback"
        )
        recon_data["target_url"] = self.target_url
        recon_data["timestamp"] = datetime.now().isoformat()

        # Log summary of what was found
        num_endpoints = len(recon_data.get("endpoints", []))
        num_api = len(recon_data.get("api_routes", []))
        num_pages = len(recon_data.get("pages", []))

        self.log(f"\n📊 Reconnaissance Summary:")
        self.log(f"  Total endpoints: {num_endpoints}")
        self.log(f"  API routes: {num_api}")
        self.log(f"  Pages: {num_pages}")

        if num_endpoints > 0:
            self.log(f"\n🎯 Discovered routes:")
            for endpoint in recon_data.get("endpoints", []):
                path = endpoint.get("url", "unknown")
                status = endpoint.get("status_code", "?")
                self.log(f"  • {path} (HTTP {status})")

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
{", ".join(self.vuln_categories)}

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
            messages=[{"role": "user", "content": prompt}],
        )

        response_text = message.content[0].text

        try:
            start_idx = response_text.find("[")
            end_idx = response_text.rfind("]") + 1
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
        self.log(
            f"=== PHASE 3: EXPLOIT GENERATION for {hypothesis.get('id', 'UNKNOWN')} ===",
            "PHASE",
        )

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
            messages=[{"role": "user", "content": prompt}],
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
        vuln_id = hypothesis.get("id", f"VULN-{self.iteration}")
        script_path = self.exploits_dir / f"{vuln_id}.py"

        with open(script_path, "w") as f:
            f.write(script_text)

        # Make executable
        os.chmod(script_path, 0o755)

        self.log(f"Exploit script saved to {script_path}")
        return str(script_path)

    def execute_exploit(self, script_path: str, hypothesis: Dict) -> Dict:
        """Phase 4: Execute the exploit script and capture results."""
        self.log(
            f"=== PHASE 4: EXPLOIT EXECUTION for {hypothesis.get('id', 'UNKNOWN')} ===",
            "PHASE",
        )

        try:
            # Run the exploit script
            result = subprocess.run(
                ["python3", script_path], capture_output=True, text=True, timeout=30
            )

            # Parse output
            if result.returncode == 0:
                try:
                    exploit_result = json.loads(result.stdout)
                except json.JSONDecodeError:
                    exploit_result = {
                        "status": "error",
                        "message": "Failed to parse exploit output",
                        "raw_output": result.stdout,
                    }
            else:
                exploit_result = {
                    "status": "error",
                    "message": "Exploit execution failed",
                    "stderr": result.stderr,
                    "stdout": result.stdout,
                }

            # Add metadata
            exploit_result["hypothesis"] = hypothesis
            exploit_result["timestamp"] = datetime.now().isoformat()
            exploit_result["script_path"] = script_path

            return exploit_result

        except subprocess.TimeoutExpired:
            return {
                "status": "timeout",
                "message": "Exploit execution timed out",
                "hypothesis": hypothesis,
            }
        except Exception as e:
            return {"status": "error", "message": str(e), "hypothesis": hypothesis}

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
            messages=[{"role": "user", "content": prompt}],
        )

        response_text = message.content[0].text

        try:
            start_idx = response_text.find("{")
            end_idx = response_text.rfind("}") + 1
            if start_idx != -1 and end_idx > start_idx:
                analysis = json.loads(response_text[start_idx:end_idx])
            else:
                analysis = {"raw_analysis": response_text}
        except json.JSONDecodeError:
            analysis = {"raw_analysis": response_text}

        # Combine exploit result and analysis
        finding = {**exploit_result, "analysis": analysis, "iteration": self.iteration}

        # Save finding
        if analysis.get("vulnerability_confirmed"):
            self.findings.append(finding)
            self.log(
                f"✓ Vulnerability confirmed: {exploit_result.get('hypothesis', {}).get('type')}",
                "SUCCESS",
            )

        return finding

    def select_top_routes(self, recon_data: Dict, limit: int = 7) -> List[Dict]:
        """Select the most promising routes to test based on reconnaissance."""
        self.log(f"Selecting top {limit} routes for testing...")

        endpoints = recon_data.get("endpoints", [])
        api_routes = recon_data.get("api_routes", [])

        # Score routes based on interesting characteristics
        scored_routes = []

        for endpoint in endpoints:
            path = endpoint.get("path", "")
            score = 0

            # Higher priority for API routes
            if path.startswith("/api/"):
                score += 10

            # Higher priority for routes with parameters
            params = endpoint.get("parameters", [])
            score += len(params) * 3

            # Higher priority for specific vulnerable-looking paths
            if "admin" in path.lower():
                score += 15
            if "auth" in path.lower():
                score += 12
            if "user" in path.lower():
                score += 8
            if "graphql" in path.lower():
                score += 10
            if "search" in path.lower():
                score += 7

            # Multiple HTTP methods = more attack surface
            methods = endpoint.get("methods", [])
            score += len(methods) * 2

            scored_routes.append({"route": endpoint, "score": score, "path": path})

        # Sort by score and take top N
        scored_routes.sort(key=lambda x: x["score"], reverse=True)
        top_routes = [r["route"] for r in scored_routes[:limit]]

        self.log(f"Selected {len(top_routes)} routes:")
        for i, route in enumerate(top_routes, 1):
            self.log(f"  {i}. {route.get('url')} (methods: {route.get('methods', [])})")

        return top_routes

    def generate_route_hypotheses(self, route: Dict) -> List[Dict]:
        """Generate ALL applicable vulnerability hypotheses for a specific route."""
        path = route.get("url", "")
        methods = route.get("methods", [])
        parameters = route.get("parameters", [])

        self.log(f"Generating hypotheses for route: {path}")

        prompt = f"""You are a security testing AI. Generate ALL applicable vulnerability hypotheses for this specific route.

Route Details:
- Path: {path}
- HTTP Methods: {methods}
- Parameters: {parameters}

Generate hypotheses for EVERY vulnerability type that could apply to this route:

1. **Injection Vulnerabilities:**
   - SQL Injection (if parameters present)
   - NoSQL Injection (if search/filter parameters)
   - Command Injection (if file operations)
   - XSS (if output rendered)
   - Template Injection (if templates used)

2. **Authentication & Authorization:**
   - Authentication Bypass (especially for /admin, /auth paths)
   - JWT Vulnerabilities (for /auth paths)
   - Missing Authorization (all routes)
   - Privilege Escalation (user management routes)

3. **Data Exposure:**
   - Information Disclosure (all routes)
   - PII Exposure (user/profile routes)
   - GraphQL Introspection (if GraphQL)

4. **Access Control:**
   - IDOR (routes with IDs)
   - Path Traversal (file operations)
   - SSRF (URL parameters)

For each applicable vulnerability, provide:
{{
  "id": "unique-id-{path}-type",
  "type": "Vulnerability Type",
  "location": "{path}",
  "description": "Specific description for this route",
  "attack_vector": "How to exploit on this route",
  "test_payload_idea": "Concrete payload",
  "confidence": "high/medium/low",
  "applicable": true
}}

Return a JSON array of ALL applicable hypotheses (aim for 5-10 per route):
[...]

Be thorough - test everything that could possibly be vulnerable on this route.
"""

        try:
            message = self.client.messages.create(
                model="claude-sonnet-4-20250514",
                max_tokens=6144,
                messages=[{"role": "user", "content": prompt}],
            )

            response_text = message.content[0].text

            # Extract JSON array
            start_idx = response_text.find("[")
            end_idx = response_text.rfind("]") + 1
            if start_idx != -1 and end_idx > start_idx:
                hypotheses = json.loads(response_text[start_idx:end_idx])
            else:
                hypotheses = []

            self.log(f"Generated {len(hypotheses)} hypotheses for {path}")
            return hypotheses

        except Exception as e:
            self.log(f"Error generating hypotheses: {e}", "ERROR")
            return []

    def run(self):
        """Main orchestration loop - route-based testing."""
        self.log("Starting Security Testing Agent", "START")
        self.log(f"Target: {self.target_url}")
        self.log(
            "Strategy: Systematic route-based testing (7 routes, all vulnerabilities per route)"
        )

        # Phase 1: Reconnaissance
        recon_data = self.reconnaissance()

        if not recon_data.get("endpoints"):
            self.log("No endpoints discovered, cannot continue", "ERROR")
            return

        # Select top 7 most promising routes
        top_routes = self.select_top_routes(recon_data, limit=7)

        if not top_routes:
            self.log("No routes selected for testing", "ERROR")
            return

        self.log(f"\n{'=' * 60}")
        self.log(f"Testing {len(top_routes)} routes systematically")
        self.log(f"{'=' * 60}\n")

        # Test each route thoroughly
        for route_num, route in enumerate(top_routes, 1):
            path = route.get("url", "unknown")

            self.log(f"\n{'=' * 60}")
            self.log(f"ROUTE {route_num}/{len(top_routes)}: {path}")
            self.log(f"{'=' * 60}")

            # Generate ALL applicable hypotheses for this route
            hypotheses = self.generate_route_hypotheses(route)

            if not hypotheses:
                self.log(f"No hypotheses generated for {path}", "WARNING")
                continue

            self.log(f"Testing {len(hypotheses)} vulnerabilities on {path}")

            # Test EVERY hypothesis for this route
            for hyp_num, hypothesis in enumerate(hypotheses, 1):
                vuln_id = hypothesis.get("id", f"VULN-{route_num}-{hyp_num}")
                vuln_type = hypothesis.get("type", "Unknown")

                self.log(f"\n--- Test {hyp_num}/{len(hypotheses)}: {vuln_type} ---")

                # Generate exploit
                script_path = self.generate_exploit_script(hypothesis)
                if not script_path:
                    self.log(f"Failed to generate exploit for {vuln_type}", "WARNING")
                    continue

                # Execute exploit
                exploit_result = self.execute_exploit(script_path, hypothesis)

                # Analyze results
                finding = self.analyze_results(exploit_result)

                # Save individual finding
                self.save_results(finding, f"finding_{vuln_id}.json")

                # Brief pause between tests
                time.sleep(1)

            self.log(f"\nCompleted testing route: {path}")
            self.log(
                f"Found {len([f for f in self.findings if path in str(f)])} vulnerabilities\n"
            )

        # Generate final report
        self.generate_final_report()

    def generate_final_report(self):
        """Generate comprehensive security assessment report."""
        self.log("=== GENERATING FINAL REPORT ===", "REPORT")

        # Group findings by route
        findings_by_route = {}
        for finding in self.findings:
            location = finding.get("hypothesis", {}).get("location", "unknown")
            if location not in findings_by_route:
                findings_by_route[location] = []
            findings_by_route[location].append(finding)

        report = {
            "assessment_metadata": {
                "target": self.target_url,
                "timestamp": datetime.now().isoformat(),
                "strategy": "Systematic route-based testing",
                "routes_tested": len(findings_by_route),
                "total_vulnerabilities_found": len(self.findings),
            },
            "findings_by_route": findings_by_route,
            "all_findings": self.findings,
            "summary": {
                "critical": len(
                    [
                        f
                        for f in self.findings
                        if f.get("analysis", {}).get("severity") == "critical"
                    ]
                ),
                "high": len(
                    [
                        f
                        for f in self.findings
                        if f.get("analysis", {}).get("severity") == "high"
                    ]
                ),
                "medium": len(
                    [
                        f
                        for f in self.findings
                        if f.get("analysis", {}).get("severity") == "medium"
                    ]
                ),
                "low": len(
                    [
                        f
                        for f in self.findings
                        if f.get("analysis", {}).get("severity") == "low"
                    ]
                ),
                "info": len(
                    [
                        f
                        for f in self.findings
                        if f.get("analysis", {}).get("severity") == "info"
                    ]
                ),
            },
        }

        self.save_results(
            report, f"FINAL_REPORT_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        )

        # Print summary
        print("\n" + "=" * 60)
        print("SECURITY ASSESSMENT COMPLETE")
        print("=" * 60)
        print(f"Target: {self.target_url}")
        print(f"Strategy: Route-based systematic testing")
        print(f"Routes Tested: {len(findings_by_route)}")
        print(f"Total Vulnerabilities Found: {len(self.findings)}")

        print(f"\n Severity Breakdown:")
        print(f"  Critical: {report['summary']['critical']}")
        print(f"  High: {report['summary']['high']}")
        print(f"  Medium: {report['summary']['medium']}")
        print(f"  Low: {report['summary']['low']}")
        print(f"  Info: {report['summary']['info']}")

        print(f"\nVulnerabilities by Route:")
        for route, route_findings in findings_by_route.items():
            print(f"  {route}: {len(route_findings)} vulnerabilities")
            for finding in route_findings:
                vuln_type = finding.get("hypothesis", {}).get("type", "Unknown")
                severity = finding.get("analysis", {}).get("severity", "unknown")
                print(f"    - [{severity.upper()}] {vuln_type}")

        print(f"\nDetailed results saved to: {self.results_dir}")
        print("=" * 60 + "\n")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="AI-Powered Security Testing Agent")
    parser.add_argument("--target", default="http://localhost:3000", help="Target URL")
    parser.add_argument("--iterations", type=int, default=10, help="Max iterations")
    parser.add_argument(
        "--api-key", help="Anthropic API key (or set ANTHROPIC_API_KEY env var)"
    )

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
