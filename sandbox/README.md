# 🔓 Vulnerable Next.js Test Application

**⚠️ WARNING: This application is INTENTIONALLY VULNERABLE for security testing purposes. DO NOT deploy to production or expose to the internet!**

## Purpose

This Next.js application contains multiple common security vulnerabilities found in vibe-coded applications. It's designed to be used as a target for automated security testing tools and AI-powered security agents.

## Setup

```bash
# Install dependencies
npm install

# Run the development server
npm run dev

# The app will be available at http://localhost:3000
```

## Vulnerability Catalog

### Core Injection Vulnerabilities

### 1. **SQL Injection** (Simulated)
- **Location:** `/api/users?username=<input>`
- **Description:** Username parameter vulnerable to injection via eval()
- **Test:** `/api/users?username=admin' OR '1'='1`
- **Impact:** Data exfiltration, authentication bypass

### 2. **NoSQL Injection**
- **Location:** `/api/search?category=<input>`
- **Description:** MongoDB-style operators ($ne, $gt, $or) bypass filters
- **Test:** `/api/search?category={"$ne":null}`
- **Impact:** Return all data, bypass filters

### 3. **Command Injection**
- **Location:** Server action `searchFiles()`
- **Description:** Unsanitized input passed to shell commands
- **Test:** `; cat /etc/passwd` or `| whoami`
- **Impact:** Remote code execution

### 4. **XML External Entity (XXE)**
- **Location:** `/api/xml` (POST)
- **Description:** XML parsed without disabling external entities
- **Test:** Send XML with `<!ENTITY xxe SYSTEM "file:///etc/passwd">`
- **Impact:** File disclosure, SSRF, DoS

### 5. **Server-Side Template Injection (SSTI)**
- **Location:** Server action `renderTemplate()`
- **Description:** User templates evaluated with eval()
- **Test:** `${process.env.SECRET}` or `${require('child_process').execSync('whoami')}`
- **Impact:** Remote code execution, data exfiltration

### Authentication & Authorization

### 6. **Authentication Bypass**
- **Location:** `/api/admin`
- **Bypass Methods:**
  - Query parameter: `?admin=true`
  - Cookie: `isAdmin=true`
  - Header: `Authorization: Bearer admin_super_secret_token`
- **Test:** `/api/admin?admin=true`
- **Impact:** Complete admin access

### 7. **JWT Vulnerabilities**
- **Location:** `/api/auth`
- **Issues:**
  - Algorithm 'none' accepted
  - No signature verification
  - Sensitive data in payload
  - Client-modifiable roles
- **Test:** Modify JWT payload to set `role: "admin"`
- **Impact:** Privilege escalation, impersonation

### 8. **Missing Authorization**
- **Location:** All server actions in `app/actions.tsx`
- **Description:** No authentication or authorization checks
- **Test:** Call any server action directly
- **Impact:** Unauthorized data access/modification

### 9. **Privilege Escalation**
- **Location:** `updateProfile()` and `createUser()` server actions
- **Description:** Users can set their own role to admin
- **Test:** Submit `role=admin` in form data
- **Impact:** Full administrative access

### 10. **Mass Assignment**
- **Location:** Server action `createUser()`
- **Description:** All form fields accepted without filtering
- **Test:** Add `isAdmin=true` or `accountBalance=999999` to form
- **Impact:** Privilege escalation, data manipulation

### Data Exposure & Information Disclosure

### 11. **Information Disclosure**
- **Locations:**
  - `/api/users` - All users with passwords
  - `/api/admin` - Environment variables
  - `/api/graphql` - Passwords, SSN, credit cards
  - All error messages - Stack traces
- **Test:** Call any API endpoint
- **Impact:** Credential theft, PII exposure

### 12. **Exposed Secrets**
- **Locations:** `.env`, API responses, error messages
- **Description:**
  - NEXT_PUBLIC_* variables in client
  - Hardcoded credentials
  - API keys in responses
- **Test:** Check browser console, API responses
- **Impact:** Complete system compromise

### 13. **Verbose Error Messages**
- **Location:** All endpoints
- **Description:** Stack traces, file paths, internal details
- **Test:** Send malformed requests
- **Impact:** Information gathering for attacks

### 14. **GraphQL Introspection**
- **Location:** `/api/graphql`
- **Description:** Full schema exposed including sensitive fields
- **Test:** Query `__schema` or `__type`
- **Impact:** Complete API surface mapping

### Injection & Request Manipulation

### 15. **Cross-Site Scripting (XSS)**
- **Location:** `/profile` page (bio field)
- **Description:** User input rendered via `dangerouslySetInnerHTML`
- **Test:** `<img src=x onerror=alert('XSS')>`
- **Impact:** Session hijacking, phishing

### 16. **Server-Side Request Forgery (SSRF)**
- **Location:** Server action `fetchExternalData()`
- **Description:** Fetches arbitrary URLs without validation
- **Test:** `http://localhost:3000/api/admin` or `http://169.254.169.254/metadata`
- **Impact:** Internal network access, cloud metadata

### 17. **Open Redirect**
- **Location:** `/api/redirect`
- **Description:** Redirects to any URL via query params
- **Test:** `/api/redirect?url=http://evil.com`
- **Impact:** Phishing, OAuth token theft

### Access Control & Business Logic

### 18. **Insecure Direct Object Reference (IDOR)**
- **Locations:**
  - Server action `deleteUser(userId)`
  - Server action `getDocument(docId)`
- **Description:** No ownership validation
- **Test:** Access/delete other users' resources
- **Impact:** Unauthorized data access/deletion

### 19. **Path Traversal**
- **Locations:**
  - Server action `readFile()`
  - `/api/upload?path=<input>`
- **Description:** No path validation
- **Test:** `../../etc/passwd` or `../../../.env`
- **Impact:** Arbitrary file read

### 20. **Unrestricted File Upload**
- **Location:** `/api/upload` (POST)
- **Issues:**
  - No file type validation
  - No size limits
  - Executable files allowed
  - Filename path traversal
- **Test:** Upload `.php`, `.jsp`, `.sh` files
- **Impact:** Remote code execution, defacement

### Cryptographic & Timing Vulnerabilities

### 21. **Insecure Randomness**
- **Location:** Server action `generateToken()`
- **Description:** Math.random() used for security tokens
- **Test:** Generate multiple tokens, predict pattern
- **Impact:** Session hijacking, token prediction

### 22. **Timing Attack**
- **Location:** Server action `checkPassword()`
- **Description:** Character-by-character comparison leaks info
- **Test:** Measure response times for different inputs
- **Impact:** Password brute-forcing

### 23. **Insecure Deserialization**
- **Location:** `/api/deserialize`
- **Description:** eval() on user input, untrusted object methods
- **Test:** Send `(function(){ return process.env })()`
- **Impact:** Remote code execution

### Business Logic & Race Conditions

### 24. **Race Condition**
- **Location:** Server action `withdraw()`
- **Description:** TOCTOU flaw in balance check
- **Test:** Send multiple concurrent withdraw requests
- **Impact:** Overdraft, logic bypass

### 25. **HTTP Parameter Pollution**
- **Location:** `/api/search` (POST)
- **Description:** Multiple params with same name, unclear precedence
- **Test:** Send `?id=1&id=2` or `{"id": "user", "id": "admin"}`
- **Impact:** Filter bypass, unexpected behavior

### 26. **Rate Limiting Missing**
- **Location:** All endpoints
- **Description:** No throttling on sensitive operations
- **Test:** Automated high-volume requests
- **Impact:** Brute force, DoS, resource exhaustion

### Configuration & Deployment

### 27. **CORS Misconfiguration**
- **Location:** All API endpoints
- **Description:** No CORS restrictions
- **Test:** Cross-origin requests to sensitive endpoints
- **Impact:** CSRF, data theft

### 28. **Regex Injection (ReDoS)**
- **Location:** `/api/search?q=<input>`
- **Description:** User input in regex without escaping
- **Test:** `(a+)+$` or `(a*)*b`
- **Impact:** Denial of Service

## API Endpoints

### `/api/users`
- **GET** - List all users (with passwords!)
  - Query params: `username`, `id`
- **POST** - Login endpoint (returns admin token)
  - Body: `{ "username": "admin", "password": "admin123" }`

### `/api/admin`
- **GET** - Admin panel (bypassable auth)
  - Exposes environment variables
  - Exposes system information
- **POST** - Execute commands (no auth required)
- **DELETE** - Delete users (weak auth)

### `/api/upload`
- **GET** - List uploaded files (directory traversal)
  - Query param: `path`
- **POST** - Upload files (no validation)
  - Accepts any file type including executables
  - No size limits

### `/api/auth`
- **GET** - Verify JWT (no actual verification)
  - Header: `Authorization: Bearer <token>`
- **POST** - Generate JWT (algorithm 'none', no signature)
  - Body: `{ "username": "user", "password": "pass" }`

### `/api/redirect`
- **GET** - Open redirect
  - Query params: `url`, `returnTo`, `next`
- **POST** - POST-based redirect
  - Body: `{ "destination": "http://..." }`

### `/api/xml`
- **GET** - XXE documentation
- **POST** - Parse XML (XXE vulnerable)
  - Content-Type: `application/xml`
  - Body: XML with external entities

### `/api/graphql`
- **GET** - GraphQL playground info
- **POST** - GraphQL endpoint
  - Introspection enabled
  - No authentication
  - Exposes PII (SSN, credit cards, passwords)

### `/api/deserialize`
- **GET** - Deserialize session cookie
  - Cookie: `session=<base64>`
- **POST** - Deserialize arbitrary data
  - Body: `{ "serialized": "..." }`
  - Uses eval() on input

### `/api/search`
- **GET** - Search with NoSQL injection
  - Query params: `q`, `filter`, `category`
  - Supports MongoDB operators ($ne, $gt, etc.)
- **POST** - HTTP parameter pollution
  - Body: Multiple params with same name

## Pages

### `/` - Home

- Lists all vulnerabilities and test endpoints
- Quick API testing interface

### `/profile` - Profile Page

- XSS vulnerable bio field
- Command injection via file search
- Path traversal via file read
- SSRF via external data fetch

## Server Actions

All located in `app/actions.tsx`:

- `deleteUser()` - IDOR, missing auth
- `searchFiles()` - Command injection
- `readFile()` - Path traversal
- `updateProfile()` - XSS, privilege escalation, mass assignment
- `fetchExternalData()` - SSRF
- `createUser()` - Mass assignment, privilege escalation
- `getDocument()` - IDOR, no ownership check
- `withdraw()` - Race condition, TOCTOU flaw
- `generateToken()` - Insecure randomness (Math.random)
- `renderTemplate()` - Server-side template injection, eval()
- `checkPassword()` - Timing attack vulnerability
- `processLogin()` - Open redirect
- `processPayment()` - Information disclosure via errors

## Security Agent Test Strategy

Your security agent should be able to:

1. **Reconnaissance:**
   - Enumerate all routes and API endpoints
   - Identify server actions
   - Detect exposed environment variables

2. **Authentication Testing:**
   - Test auth bypass methods on `/api/admin`
   - Test missing auth on server actions
   - Test privilege escalation via role changes

3. **Injection Attacks:**
   - SQL injection on `/api/users?username`
   - Command injection on `searchFiles()`
   - Path traversal on `readFile()`
   - XSS on profile bio field

4. **Information Gathering:**
   - Extract secrets from API responses
   - Find NEXT_PUBLIC_ variables
   - Enumerate users and credentials

5. **SSRF Testing:**
   - Test internal service access via `fetchExternalData()`
   - Test proxy endpoint in config

## Expected Findings

Your agent should discover:

- ✅ **28 distinct vulnerability types** across multiple categories
- ✅ **Multiple authentication bypass methods** (query params, cookies, JWT)
- ✅ **Exposed credentials and API keys** (env vars, hardcoded secrets)
- ✅ **User enumeration capabilities** (timing attacks, error messages)
- ✅ **Privilege escalation paths** (mass assignment, JWT manipulation)
- ✅ **Injection vectors:**
  - SQL injection (simulated with eval)
  - NoSQL injection ($ne, $gt operators)
  - Command injection (shell commands)
  - XML External Entity (XXE)
  - Template injection (SSTI)
  - Regex injection (ReDoS)
- ✅ **SSRF opportunities** (fetchExternalData, XXE, open redirect)
- ✅ **XSS vulnerabilities** (dangerouslySetInnerHTML)
- ✅ **IDOR flaws** (deleteUser, getDocument)
- ✅ **Business logic issues** (race conditions, timing attacks)
- ✅ **Cryptographic weaknesses** (insecure randomness, no JWT verification)
- ✅ **File handling issues** (path traversal, unrestricted upload)
- ✅ **GraphQL vulnerabilities** (introspection, no auth, PII exposure)
- ✅ **Deserialization attacks** (eval on untrusted data)

## Safe Testing Guidelines

- Run only in Docker containers
- No external network access
- Automated scans should respect rate limits
- Log all findings for analysis
- Never use discovered vulnerabilities maliciously

## License

This is educational software for security testing. Use responsibly.
