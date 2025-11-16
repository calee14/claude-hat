# Quick Start Guide

## 5-Minute Setup

### 1. Install Dependencies
```bash
cd security_agent
pip install -r requirements.txt
```

### 2. Set API Key
```bash
export ANTHROPIC_API_KEY="your-anthropic-api-key-here"
```

### 3. Start Target App
```bash
# In another terminal
cd ..
npm run dev
```

### 4. Run Agent
```bash
./run.sh
```

That's it! The agent will start testing automatically.

## What Happens Next?

1. **Reconnaissance** - Agent maps your app (30s)
2. **Hypothesis** - Generates vulnerability theories (30s)
3. **Exploit** - Creates test scripts (1-2 min)
4. **Execute** - Runs tests (10-30s per test)
5. **Analyze** - Evaluates results (30s)
6. **Repeat** - Loops 10 times or until done

Total runtime: ~15-20 minutes for full scan

## Expected Output

```
[2025-11-16 13:00:00] [START] Starting Security Testing Agent
[2025-11-16 13:00:00] [INFO] Target: http://localhost:3000

============================================================
ITERATION 1/10
============================================================

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
```

## Where to Find Results

After the scan completes:

- **Exploit Scripts**: `exploits/VULN-*.py`
- **Individual Findings**: `results/finding_*.json`
- **Final Report**: `results/FINAL_REPORT_*.json`

## View Results

```bash
# View final report
cat results/FINAL_REPORT_*.json | jq

# View specific finding
cat results/finding_VULN-001.json | jq

# Count vulnerabilities by severity
cat results/FINAL_REPORT_*.json | jq '.summary'
```

## Run Example Exploits

```bash
# Test auth bypass manually
python exploits/example_auth_bypass.py

# Test SQL injection manually
python exploits/example_sqli.py
```

## Customize

### Change Target
```bash
./run.sh --target http://localhost:8080
```

### Limit Iterations
```bash
./run.sh --iterations 3
```

### Custom Config
Edit `config.json` to modify:
- Vulnerability categories to test
- Number of tests per iteration
- Timeouts and delays
- Reporting options

## Troubleshooting

### Target Not Running
```bash
# Terminal 1: Start the vulnerable app
cd ..
npm run dev

# Terminal 2: Run agent
cd security_agent
./run.sh
```

### API Key Issues
```bash
# Check if set
echo $ANTHROPIC_API_KEY

# Set for this session
export ANTHROPIC_API_KEY="sk-ant-..."

# Or use .env file
cp .env.example .env
# Edit .env and add your key
```

### Permission Denied
```bash
chmod +x run.sh main.py exploits/*.py
```

## Next Steps

1. **Review findings** in `results/` directory
2. **Inspect exploit scripts** in `exploits/`
3. **Customize prompts** in `prompts/` for better results
4. **Extend main.py** to add new vulnerability types
5. **Integrate with CI/CD** for continuous security testing

## Tips

- Run with `--iterations 3` first to test quickly
- Review generated exploit scripts before trusting results
- Check `results/` directory after each run
- Use Docker to isolate testing environment
- Monitor target app logs for errors

## Help

```bash
python main.py --help
```

For more details, see [README.md](README.md)
