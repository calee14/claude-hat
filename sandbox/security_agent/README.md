# AI-Powered Security Testing Agent

An autonomous security testing agent that uses Claude to discover vulnerabilities in web applications through iterative reconnaissance, hypothesis generation, and exploit execution.

## Overview

This agent automates the security testing workflow:

```
┌─────────────────┐
│ Reconnaissance  │ → Analyze app structure, enumerate endpoints
└────────┬────────┘
         ↓
┌─────────────────┐
│   Hypothesis    │ → Generate vulnerability theories
└────────┬────────┘
         ↓
┌─────────────────┐
│ Script Gen      │ → Claude writes exploit scripts
└────────┬────────┘
         ↓
┌─────────────────┐
│   Execution     │ → Run exploits, capture results
└────────┬────────┘
         ↓
┌─────────────────┐
│    Learning     │ → Analyze results, adapt approach
└────────┬────────┘
         ↓
      (Loop back)
```

## Features

- **Autonomous Testing**: Runs iteratively without manual intervention
- **AI-Guided Exploits**: Claude generates targeted exploit scripts
- **Comprehensive Coverage**: Tests OWASP Top 10 vulnerabilities
- **Detailed Reporting**: JSON logs for every finding
- **Learning Loop**: Adapts based on previous results
- **Non-Destructive**: Prefers read-only tests when possible

## Installation

### Prerequisites

- Python 3.8+
- Anthropic API key
- Target application running (default: http://localhost:3000)

### Setup

```bash
# Navigate to security_agent directory
cd security_agent

# Install dependencies
pip install -r requirements.txt

# Set your API key
export ANTHROPIC_API_KEY="your-api-key-here"
```

## Usage

### Basic Usage

```bash
# Run against default target (localhost:3000)
python main.py

# Specify custom target
python main.py --target http://localhost:8080

# Limit iterations
python main.py --iterations 5

# Provide API key via argument
python main.py --api-key sk-ant-...
```

### Example Output

```
[2025-11-16 13:00:00] [START] Starting Security Testing Agent
[2025-11-16 13:00:00] [INFO] Target: http://localhost:3000
[2025-11-16 13:00:01] [PHASE] === PHASE 1: RECONNAISSANCE ===
[2025-11-16 13:00:05] [INFO] Results saved to results/recon_1.json
[2025-11-16 13:00:06] [PHASE] === PHASE 2: HYPOTHESIS GENERATION ===
[2025-11-16 13:00:10] [INFO] Results saved to results/hypotheses_1.json
[2025-11-16 13:00:11] [PHASE] === PHASE 3: EXPLOIT GENERATION for VULN-001 ===
[2025-11-16 13:00:15] [INFO] Exploit script saved to exploits/VULN-001.py
[2025-11-16 13:00:16] [PHASE] === PHASE 4: EXPLOIT EXECUTION for VULN-001 ===
[2025-11-16 13:00:17] [PHASE] === PHASE 5: RESULT ANALYSIS ===
[2025-11-16 13:00:20] [SUCCESS] ✓ Vulnerability confirmed: Authentication Bypass
...

============================================================
SECURITY ASSESSMENT COMPLETE
============================================================
Target: http://localhost:3000
Total Tests: 12
Vulnerabilities Found: 8

Severity Breakdown:
  Critical: 2
  High: 4
  Medium: 2
  Low: 0
  Info: 0

Detailed results saved to: security_agent/results
============================================================
```

## Directory Structure

```
security_agent/
├── main.py              # Main orchestration loop
├── requirements.txt     # Python dependencies
├── README.md           # This file
│
├── prompts/            # AI prompt templates
│   ├── reconnaissance.txt
│   ├── hypothesis.txt
│   ├── exploit_generation.txt
│   └── analysis.txt
│
├── exploits/           # Generated exploit scripts
│   ├── example_auth_bypass.py
│   ├── example_sqli.py
│   └── VULN-*.py      # Auto-generated scripts
│
└── results/            # Test results and findings
    ├── recon_*.json
    ├── hypotheses_*.json
    ├── finding_*.json
    └── FINAL_REPORT_*.json
```

## Vulnerability Categories Tested

The agent tests for these vulnerability types:

1. **Authentication Bypass** - Query params, cookies, weak tokens
2. **SQL Injection** - Parameter injection, eval() usage
3. **XSS (Cross-Site Scripting)** - Reflected, stored, DOM-based
4. **Command Injection** - Shell command execution
5. **Path Traversal** - Directory traversal, file disclosure
6. **SSRF** - Server-side request forgery
7. **IDOR** - Insecure direct object references
8. **Information Disclosure** - Exposed secrets, verbose errors
9. **Privilege Escalation** - Role manipulation
10. **Missing Authorization** - Unprotected endpoints

## How It Works

### Phase 1: Reconnaissance
- Enumerates API endpoints and routes
- Identifies authentication mechanisms
- Maps input vectors (query params, headers, cookies)
- Analyzes technology stack

### Phase 2: Hypothesis Generation
- Uses recon data to generate vulnerability theories
- Prioritizes by likelihood and impact
- Suggests specific test payloads
- Assigns confidence levels

### Phase 3: Script Generation
- Claude writes Python exploit scripts
- Scripts use the `requests` library
- Include error handling and JSON output
- Non-destructive when possible

### Phase 4: Execution
- Runs exploit scripts in isolated subprocess
- Captures stdout/stderr
- Enforces 30-second timeout
- Handles failures gracefully

### Phase 5: Analysis
- Claude analyzes exploit results
- Confirms vulnerability existence
- Assesses severity (CVSS scoring)
- Identifies exposed data
- Suggests next tests

### Learning Loop
- Tracks tested vectors to avoid duplication
- Builds on previous findings
- Adapts testing strategy based on results
- Iterates until max iterations or no new hypotheses

## Example Exploit Scripts

### Test Authentication Bypass
```bash
python exploits/example_auth_bypass.py
```

### Test SQL Injection
```bash
python exploits/example_sqli.py
```

## Output Files

### Reconnaissance Results
```json
{
  "endpoints": [...],
  "input_vectors": [...],
  "interesting_findings": [...],
  "technology_stack": {...}
}
```

### Hypotheses
```json
[
  {
    "id": "VULN-001",
    "type": "SQL Injection",
    "location": "/api/users?username=",
    "confidence": "high",
    "test_payload_idea": "admin' OR '1'='1"
  }
]
```

### Findings
```json
{
  "hypothesis": {...},
  "status": "vulnerable",
  "analysis": {
    "vulnerability_confirmed": true,
    "severity": "high",
    "evidence": [...],
    "data_exposed": [...]
  }
}
```

### Final Report
```json
{
  "assessment_metadata": {...},
  "findings": [...],
  "summary": {
    "critical": 2,
    "high": 4,
    "medium": 2,
    "low": 0
  }
}
```

## Advanced Usage

### Custom Prompts
Modify prompts in `prompts/` to customize the agent's behavior:
- `reconnaissance.txt` - What to look for during recon
- `hypothesis.txt` - How to generate vulnerability theories
- `exploit_generation.txt` - Script generation guidelines
- `analysis.txt` - Result analysis criteria

### Running Specific Exploits
```bash
# Run a single exploit script
python exploits/VULN-001.py

# Run and save output
python exploits/VULN-001.py > results/manual_test.json
```

### Integration with CI/CD
```bash
# Run agent and exit with error code if vulnerabilities found
python main.py --target http://staging.example.com && \
  [ $(jq '.summary.critical' results/FINAL_REPORT_*.json) -eq 0 ]
```

## Safety and Ethics

**⚠️ IMPORTANT**: This tool is for authorized security testing only.

- Only test applications you own or have permission to test
- Use in isolated environments (Docker, VMs)
- Do not expose target applications to the internet
- Respect rate limits and system resources
- Review generated exploits before running
- Follow responsible disclosure practices

## Troubleshooting

### "No module named 'anthropic'"
```bash
pip install -r requirements.txt
```

### "ANTHROPIC_API_KEY not set"
```bash
export ANTHROPIC_API_KEY="your-key-here"
```

### "Connection refused"
Ensure the target application is running:
```bash
# For the vulnerable Next.js app
cd ..
npm run dev
```

### Scripts timeout
Increase timeout in `main.py`:
```python
subprocess.run(..., timeout=60)  # Increase from 30 to 60
```

## Future Enhancements

- [ ] Browser automation for XSS testing
- [ ] Network traffic analysis
- [ ] Fuzzing capabilities
- [ ] Screenshot capture of findings
- [ ] HTML report generation
- [ ] Integration with Burp Suite / OWASP ZAP
- [ ] Parallel exploit execution
- [ ] Machine learning for pattern detection

## Contributing

This is a hackathon project. Feel free to extend and improve!

## License

MIT License - Use responsibly for authorized testing only.
