'use client'

import Link from 'next/link';
import { useState } from 'react';

export default function Home() {
  const [apiResponse, setApiResponse] = useState('');

  async function testAPI(endpoint: string) {
    try {
      const response = await fetch(endpoint);
      const data = await response.json();
      setApiResponse(JSON.stringify(data, null, 2));
    } catch (error) {
      setApiResponse(`Error: ${error}`);
    }
  }

  return (
    <div style={{ padding: '20px', fontFamily: 'sans-serif' }}>
      <h1>🔓 Vulnerable Next.js Test App</h1>
      <p style={{ color: '#666', marginBottom: '30px' }}>
        This application is intentionally vulnerable for security testing purposes.
        <br />
        <strong>DO NOT deploy this to production!</strong>
      </p>

      <div style={{ marginBottom: '30px' }}>
        <h2>🎯 Test Endpoints</h2>

        <div style={{ marginBottom: '20px' }}>
          <h3>Pages with Vulnerabilities:</h3>
          <ul>
            <li><Link href="/profile" style={{ color: 'blue' }}>Profile Page</Link> - XSS, Command Injection, Path Traversal, SSRF</li>
          </ul>
        </div>

        <div style={{ marginBottom: '20px' }}>
          <h3>API Endpoints:</h3>
          <ul style={{ lineHeight: '2' }}>
            <li>
              <button onClick={() => testAPI('/api/users')} style={{ padding: '5px 10px', marginRight: '10px' }}>
                Test
              </button>
              <code>/api/users</code> - SQL Injection, Info Disclosure
            </li>
            <li>
              <button onClick={() => testAPI('/api/users?username=admin')} style={{ padding: '5px 10px', marginRight: '10px' }}>
                Test
              </button>
              <code>/api/users?username=admin</code> - SQL Injection via username
            </li>
            <li>
              <button onClick={() => testAPI('/api/admin')} style={{ padding: '5px 10px', marginRight: '10px' }}>
                Test
              </button>
              <code>/api/admin</code> - Weak Authentication
            </li>
            <li>
              <button onClick={() => testAPI('/api/admin?admin=true')} style={{ padding: '5px 10px', marginRight: '10px' }}>
                Test
              </button>
              <code>/api/admin?admin=true</code> - Auth Bypass
            </li>
            <li>
              <button onClick={() => testAPI('/api/upload')} style={{ padding: '5px 10px', marginRight: '10px' }}>
                Test
              </button>
              <code>/api/upload</code> - Unrestricted File Upload, Path Traversal
            </li>
            <li>
              <button onClick={() => testAPI('/api/auth')} style={{ padding: '5px 10px', marginRight: '10px' }}>
                Test
              </button>
              <code>/api/auth</code> - JWT Vulnerabilities (algorithm 'none', no verification)
            </li>
            <li>
              <button onClick={() => testAPI('/api/redirect')} style={{ padding: '5px 10px', marginRight: '10px' }}>
                Test
              </button>
              <code>/api/redirect</code> - Open Redirect
            </li>
            <li>
              <button onClick={() => testAPI('/api/xml')} style={{ padding: '5px 10px', marginRight: '10px' }}>
                Test
              </button>
              <code>/api/xml</code> - XML External Entity (XXE)
            </li>
            <li>
              <button onClick={() => testAPI('/api/graphql')} style={{ padding: '5px 10px', marginRight: '10px' }}>
                Test
              </button>
              <code>/api/graphql</code> - GraphQL Introspection, PII Exposure
            </li>
            <li>
              <button onClick={() => testAPI('/api/deserialize')} style={{ padding: '5px 10px', marginRight: '10px' }}>
                Test
              </button>
              <code>/api/deserialize</code> - Insecure Deserialization, RCE
            </li>
            <li>
              <button onClick={() => testAPI('/api/search')} style={{ padding: '5px 10px', marginRight: '10px' }}>
                Test
              </button>
              <code>/api/search</code> - NoSQL Injection, ReDoS, Code Execution
            </li>
          </ul>
        </div>
      </div>

      <div style={{ marginBottom: '30px' }}>
        <h2>🔍 Vulnerability Categories (28+ Types)</h2>

        <h3 style={{ marginTop: '20px', color: '#dc3545' }}>🔴 Injection Vulnerabilities</h3>
        <ul>
          <li><strong>SQL Injection:</strong> /api/users?username parameter (eval-based)</li>
          <li><strong>NoSQL Injection:</strong> /api/search?category ($ne, $gt operators)</li>
          <li><strong>Command Injection:</strong> searchFiles() server action</li>
          <li><strong>XXE (XML External Entity):</strong> /api/xml (POST)</li>
          <li><strong>Template Injection (SSTI):</strong> renderTemplate() server action</li>
          <li><strong>Regex Injection (ReDoS):</strong> /api/search?q parameter</li>
          <li><strong>XSS:</strong> Profile page bio field (dangerouslySetInnerHTML)</li>
          <li><strong>Code Injection:</strong> Multiple eval() uses on user input</li>
        </ul>

        <h3 style={{ marginTop: '20px', color: '#fd7e14' }}>🟠 Authentication & Authorization</h3>
        <ul>
          <li><strong>Auth Bypass:</strong> /api/admin (query param, cookie, bearer token)</li>
          <li><strong>JWT Vulnerabilities:</strong> /api/auth (algorithm 'none', no signature)</li>
          <li><strong>Missing Authorization:</strong> All server actions</li>
          <li><strong>Privilege Escalation:</strong> updateProfile(), createUser() (role manipulation)</li>
          <li><strong>Mass Assignment:</strong> createUser() accepts any field</li>
          <li><strong>Weak Session Management:</strong> Cookie deserialization without verification</li>
        </ul>

        <h3 style={{ marginTop: '20px', color: '#ffc107' }}>🟡 Data Exposure</h3>
        <ul>
          <li><strong>Information Disclosure:</strong> /api/users, /api/admin, /api/graphql</li>
          <li><strong>GraphQL Schema Exposure:</strong> /api/graphql introspection enabled</li>
          <li><strong>PII Exposure:</strong> SSN, credit cards, passwords in responses</li>
          <li><strong>Exposed Secrets:</strong> Environment variables, API keys, hardcoded credentials</li>
          <li><strong>Verbose Errors:</strong> Stack traces, file paths in all error responses</li>
        </ul>

        <h3 style={{ marginTop: '20px', color: '#28a745' }}>🟢 Access Control</h3>
        <ul>
          <li><strong>IDOR:</strong> deleteUser(), getDocument() (no ownership check)</li>
          <li><strong>Path Traversal:</strong> readFile(), /api/upload?path</li>
          <li><strong>Unrestricted File Upload:</strong> /api/upload (any file type, no validation)</li>
          <li><strong>Directory Listing:</strong> /api/upload exposes file paths</li>
        </ul>

        <h3 style={{ marginTop: '20px', color: '#17a2b8' }}>🔵 Request Manipulation</h3>
        <ul>
          <li><strong>SSRF:</strong> fetchExternalData() server action</li>
          <li><strong>Open Redirect:</strong> /api/redirect (GET & POST)</li>
          <li><strong>HTTP Parameter Pollution:</strong> /api/search (POST)</li>
          <li><strong>CORS Misconfiguration:</strong> All endpoints allow cross-origin</li>
        </ul>

        <h3 style={{ marginTop: '20px', color: '#6610f2' }}>🟣 Business Logic & Crypto</h3>
        <ul>
          <li><strong>Race Condition:</strong> withdraw() server action (TOCTOU)</li>
          <li><strong>Timing Attack:</strong> checkPassword() character-by-character comparison</li>
          <li><strong>Insecure Randomness:</strong> generateToken() uses Math.random()</li>
          <li><strong>Insecure Deserialization:</strong> /api/deserialize (RCE via eval)</li>
          <li><strong>Rate Limiting Missing:</strong> All endpoints (brute force possible)</li>
        </ul>
      </div>

      <div style={{ marginBottom: '30px' }}>
        <h2>📋 API Response</h2>
        <pre style={{
          background: '#f5f5f5',
          padding: '15px',
          border: '1px solid #ddd',
          borderRadius: '5px',
          overflow: 'auto',
          maxHeight: '400px'
        }}>
          {apiResponse || 'Click a "Test" button to see API responses'}
        </pre>
      </div>

      <div style={{
        background: '#fff3cd',
        padding: '15px',
        border: '1px solid #ffc107',
        borderRadius: '5px',
        marginTop: '30px'
      }}>
        <h3>⚠️ Warning</h3>
        <p>
          This application contains <strong>28+ intentional security vulnerabilities</strong> for educational and testing purposes.
          Includes: SQL/NoSQL injection, XXE, SSTI, JWT flaws, GraphQL issues, deserialization attacks, and more.
          <br /><br />
          <strong>Use only in isolated, sandboxed environments. Never expose to the internet.</strong>
        </p>
        <p style={{ marginTop: '10px', fontSize: '14px' }}>
          📚 Full documentation: See <code>README.md</code> for complete vulnerability catalog
          <br />
          🧪 Testing guide: See <code>TESTING_GUIDE.md</code> for step-by-step exploitation
          <br />
          🤖 Security Agent: Run <code>cd security_agent && ./run.sh</code> for automated testing
        </p>
      </div>

      {/* VULNERABILITY: Secrets exposed in client-side code */}
      <script dangerouslySetInnerHTML={{
        __html: `
          // VULNERABILITY: Hardcoded credentials in JavaScript
          const API_KEY = '${process.env.NEXT_PUBLIC_API_KEY}';
          const ADMIN_PASSWORD = '${process.env.NEXT_PUBLIC_ADMIN_PASSWORD}';
          console.log('API Key:', API_KEY);
          console.log('Admin Password:', ADMIN_PASSWORD);
        `
      }} />
    </div>
  );
}
