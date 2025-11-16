import { NextRequest, NextResponse } from 'next/server';

// VULNERABILITY: Weak authentication check
function isAdmin(request: NextRequest) {
  const authHeader = request.headers.get('authorization');

  // VULNERABILITY: Hardcoded credentials
  if (authHeader === 'Bearer admin_super_secret_token') {
    return true;
  }

  // VULNERABILITY: Checking for admin cookie without proper validation
  const adminCookie = request.cookies.get('isAdmin');
  if (adminCookie?.value === 'true') {
    return true;
  }

  // VULNERABILITY: Query parameter authentication (easily bypassable)
  const isAdminParam = request.nextUrl.searchParams.get('admin');
  if (isAdminParam === 'true') {
    return true;
  }

  return false;
}

export async function GET(request: NextRequest) {
  // VULNERABILITY: Weak authentication that can be easily bypassed
  if (!isAdmin(request)) {
    return NextResponse.json({
      error: 'Unauthorized',
      // VULNERABILITY: Leaking how to authenticate
      hint: 'Try setting isAdmin cookie to true or add ?admin=true parameter'
    }, { status: 401 });
  }

  // VULNERABILITY: Exposing sensitive system information
  return NextResponse.json({
    success: true,
    message: 'Welcome admin!',
    systemInfo: {
      // VULNERABILITY: Exposing environment variables
      env: process.env,
      // VULNERABILITY: Exposing system details
      cwd: process.cwd(),
      platform: process.platform,
      version: process.version,
      memory: process.memoryUsage(),
    },
    // VULNERABILITY: Exposing database credentials
    database: {
      url: process.env.NEXT_PUBLIC_DATABASE_URL,
      user: 'admin',
      password: 'admin123',
    },
    // VULNERABILITY: List of all "users" with passwords
    users: [
      { id: 1, username: 'admin', password: 'admin123', apiKey: 'sk_admin_12345' },
      { id: 2, username: 'user', password: 'user123', apiKey: 'sk_user_67890' },
    ]
  });
}

export async function POST(request: NextRequest) {
  // VULNERABILITY: No authentication at all for POST
  const body = await request.json();

  // VULNERABILITY: Arbitrary command execution potential
  const { command, filename, userId } = body;

  return NextResponse.json({
    success: true,
    message: 'Command executed',
    command: command,
    // VULNERABILITY: Would execute arbitrary commands
    result: `Would execute: ${command}`,
  });
}

// VULNERABILITY: DELETE endpoint with weak auth
export async function DELETE(request: NextRequest) {
  const userId = request.nextUrl.searchParams.get('userId');

  // VULNERABILITY: Only checking if header exists, not validating it
  const hasAuth = request.headers.has('authorization');

  if (!hasAuth) {
    return NextResponse.json({ error: 'Missing auth header' }, { status: 401 });
  }

  // VULNERABILITY: Would delete user without proper authorization check
  return NextResponse.json({
    success: true,
    message: `User ${userId} would be deleted`,
    deletedBy: 'unknown', // No actual user verification
  });
}
