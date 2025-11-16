import { NextRequest, NextResponse } from 'next/server';

// Mock database (in reality this would be SQL injection vulnerable)
const users = [
  { id: 1, username: 'admin', password: 'admin123', role: 'admin', email: 'admin@example.com' },
  { id: 2, username: 'user', password: 'user123', role: 'user', email: 'user@example.com' },
  { id: 3, username: 'guest', password: 'guest123', role: 'guest', email: 'guest@example.com' },
];

// VULNERABILITY: SQL Injection via string concatenation
export async function GET(request: NextRequest) {
  const searchParams = request.nextUrl.searchParams;
  const username = searchParams.get('username');
  const id = searchParams.get('id');

  if (username) {
    // VULNERABILITY: Direct string interpolation (simulating SQL injection)
    // In real scenario: `SELECT * FROM users WHERE username = '${username}'`
    const user = users.find(u => {
      // This simulates vulnerable SQL by evaluating the input directly
      const query = `u.username === '${username}'`;
      try {
        // VULNERABILITY: Using eval (extremely dangerous)
        return eval(query);
      } catch {
        return false;
      }
    });

    if (user) {
      // VULNERABILITY: Returning sensitive data including passwords
      return NextResponse.json({ success: true, user });
    }
  }

  if (id) {
    // VULNERABILITY: No input validation
    const user = users[parseInt(id)];
    if (user) {
      return NextResponse.json({ success: true, user });
    }
  }

  // VULNERABILITY: Exposing all users with full data
  return NextResponse.json({
    success: true,
    users,
    // VULNERABILITY: Leaking server info
    server: {
      nodeVersion: process.version,
      platform: process.platform,
      env: process.env
    }
  });
}

// VULNERABILITY: No authentication required for POST
export async function POST(request: NextRequest) {
  const body = await request.json();

  // VULNERABILITY: No input sanitization
  const { username, password } = body;

  // VULNERABILITY: Passwords in plain text comparison
  const user = users.find(u => u.username === username && u.password === password);

  if (user) {
    return NextResponse.json({
      success: true,
      message: 'Login successful',
      user,
      // VULNERABILITY: Exposing secret token
      token: process.env.ADMIN_TOKEN,
    });
  }

  return NextResponse.json({ success: false, message: 'Invalid credentials' }, { status: 401 });
}
