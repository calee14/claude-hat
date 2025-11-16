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

### 1. **SQL Injection** (Simulated)

- **Location:** `/api/users?username=<input>`
- **Description:** Username parameter is vulnerable to injection attacks due to eval() usage
- **Test:** `/api/users?username=admin' OR '1'='1`

### 2. **Authentication Bypass**

- **Location:** `/api/admin`
- **Bypass Methods:**
  - Query parameter: `?admin=true`
  - Cookie: `isAdmin=true`
  - Header: `Authorization: Bearer admin_super_secret_token`
- **Test:** `/api/admin?admin=true`

### 3. **Cross-Site Scripting (XSS)**

- **Location:** `/profile` page (bio field)
- **Description:** User input rendered via `dangerouslySetInnerHTML`
- **Test:** Enter `<img src=x onerror=alert('XSS')>` in bio field

### 4. **Command Injection** (Simulated)

- **Location:** Server action `searchFiles()`
- **Description:** Unsanitized input would be passed to shell commands
- **Test:** Use profile page search with input like `; cat /etc/passwd`

### 5. **Path Traversal**

- **Location:** Server action `readFile()`
- **Description:** No path validation on file reads
- **Test:** Try reading `../../etc/passwd` or `../../../.env`

### 6. **Server-Side Request Forgery (SSRF)**

- **Location:** Server action `fetchExternalData()`
- **Description:** Fetches arbitrary URLs without validation
- **Test:** Try fetching `http://localhost:3000/api/admin` or internal services

### 7. **Insecure Direct Object Reference (IDOR)**

- **Location:** Server action `deleteUser()`
- **Description:** No authorization checks on user deletion
- **Test:** Call deleteUser with any user ID

### 8. **Information Disclosure**

- **Locations:** Multiple
  - `/api/users` - Exposes all users with passwords
  - `/api/admin` - Exposes environment variables and system info
  - All API responses include sensitive data
- **Test:** Call any API endpoint

### 9. **Exposed Secrets**

- **Location:** `.env` file and API responses
- **Description:**
  - NEXT_PUBLIC_* variables exposed to client
  - Secrets in API responses
  - Hardcoded credentials in code
- **Test:** Check browser console and API responses

### 10. **Missing Authorization**

- **Location:** All server actions in `app/actions.ts`
- **Description:** No authentication or authorization checks
- **Test:** Call any server action without credentials

### 11. **Privilege Escalation**

- **Location:** `updateProfile()` server action
- **Description:** Users can set their own role to admin
- **Test:** Submit profile form with role="admin"

### 12. **Open Redirect/Proxy** (Configuration)

- **Location:** `next.config.js` rewrites
- **Description:** Proxy endpoint that forwards to any URL
- **Test:** Access `/api/proxy/<any-url>`

### 13. **CORS Misconfiguration** (Implicit)

- **Description:** No CORS restrictions on sensitive endpoints
- **Test:** Make cross-origin requests to API endpoints

### 14. **Verbose Error Messages**

- **Location:** Global configuration
- **Description:** Source maps and detailed errors exposed
- **Test:** Trigger errors and inspect responses

### 15. **Rate Limiting Missing**

- **Location:** All endpoints
- **Description:** No rate limiting on sensitive operations
- **Test:** Automated requests to any endpoint

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

All located in `app/actions.ts`:

- `deleteUser()` - IDOR, missing auth
- `searchFiles()` - Command injection
- `readFile()` - Path traversal
- `updateProfile()` - XSS, privilege escalation
- `fetchExternalData()` - SSRF

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

- ✅ 15+ distinct vulnerability types
- ✅ Multiple authentication bypass methods
- ✅ Exposed credentials and API keys
- ✅ User enumeration capabilities
- ✅ Privilege escalation paths
- ✅ Command/SQL injection vectors
- ✅ SSRF opportunities
- ✅ XSS vulnerabilities

## Safe Testing Guidelines

- Run only in Docker containers
- No external network access
- Automated scans should respect rate limits
- Log all findings for analysis
- Never use discovered vulnerabilities maliciously

## License

This is educational software for security testing. Use responsibly.
