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
          </ul>
        </div>
      </div>

      <div style={{ marginBottom: '30px' }}>
        <h2>🔍 Vulnerability Categories</h2>
        <ul>
          <li><strong>SQL Injection:</strong> /api/users?username parameter</li>
          <li><strong>Authentication Bypass:</strong> /api/admin (multiple methods)</li>
          <li><strong>XSS:</strong> Profile page bio field</li>
          <li><strong>Command Injection:</strong> searchFiles server action</li>
          <li><strong>Path Traversal:</strong> readFile server action</li>
          <li><strong>SSRF:</strong> fetchExternalData server action</li>
          <li><strong>Information Disclosure:</strong> All endpoints leak sensitive data</li>
          <li><strong>Insecure Direct Object Reference:</strong> deleteUser action</li>
          <li><strong>Missing Authorization:</strong> Server actions lack auth checks</li>
          <li><strong>Exposed Secrets:</strong> Check .env and API responses</li>
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
          This application contains <strong>intentional security vulnerabilities</strong> for educational purposes.
          Use only in isolated, sandboxed environments. Never expose to the internet.
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
