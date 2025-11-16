import { NextRequest, NextResponse } from 'next/server';

// VULNERABILITY: Weak JWT implementation (simulated)
export async function POST(request: NextRequest) {
  const body = await request.json();
  const { username, password } = body;

  // VULNERABILITY: Weak password check
  if (username && password) {
    // VULNERABILITY: Predictable JWT structure
    // VULNERABILITY: No signature verification
    // VULNERABILITY: Using 'none' algorithm
    const fakeJWT = {
      header: {
        alg: 'none', // VULNERABILITY: Algorithm 'none' accepted
        typ: 'JWT'
      },
      payload: {
        sub: username,
        role: 'user', // VULNERABILITY: Role in JWT can be modified
        iat: Date.now(),
        exp: Date.now() + 3600000,
        // VULNERABILITY: Sensitive data in JWT
        password: password,
        apiKey: 'sk_live_' + username
      },
      signature: 'not-verified' // VULNERABILITY: Signature not checked
    };

    const token = Buffer.from(JSON.stringify(fakeJWT)).toString('base64');

    return NextResponse.json({
      success: true,
      token: token,
      // VULNERABILITY: Exposing JWT structure
      decoded: fakeJWT,
      warnings: [
        'JWT uses algorithm "none"',
        'Signature not verified',
        'Sensitive data in payload',
        'Role can be modified by client'
      ]
    });
  }

  return NextResponse.json({ error: 'Invalid credentials' }, { status: 401 });
}

// VULNERABILITY: JWT verification bypass
export async function GET(request: NextRequest) {
  const authHeader = request.headers.get('authorization');

  if (!authHeader) {
    return NextResponse.json({ error: 'No token provided' }, { status: 401 });
  }

  // VULNERABILITY: No actual verification
  // VULNERABILITY: Trusting client-provided data
  try {
    const token = authHeader.replace('Bearer ', '');
    const decoded = JSON.parse(Buffer.from(token, 'base64').toString());

    // VULNERABILITY: Accepting any token without verification
    // VULNERABILITY: Trusting role from JWT without validation
    if (decoded.payload?.role === 'admin') {
      return NextResponse.json({
        success: true,
        message: 'Admin access granted',
        // VULNERABILITY: Exposing all user data
        adminData: {
          users: ['user1', 'user2', 'admin'],
          apiKeys: ['key1', 'key2', 'key3'],
          secrets: process.env
        }
      });
    }

    return NextResponse.json({
      success: true,
      message: 'Token accepted',
      user: decoded.payload,
      // VULNERABILITY: Hint about privilege escalation
      hint: 'Try changing the role to "admin" in your JWT payload'
    });
  } catch {
    // VULNERABILITY: Still accepting invalid tokens
    return NextResponse.json({
      success: true,
      message: 'Invalid token format but access granted anyway',
      warning: 'Token verification failed but request allowed'
    });
  }
}
