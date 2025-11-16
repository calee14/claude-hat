import { NextRequest, NextResponse } from 'next/server';

// VULNERABILITY: Open Redirect
export async function GET(request: NextRequest) {
  const url = request.nextUrl.searchParams.get('url');
  const returnTo = request.nextUrl.searchParams.get('returnTo');
  const next = request.nextUrl.searchParams.get('next');

  // VULNERABILITY: No URL validation - redirects to any URL
  // VULNERABILITY: Multiple redirect parameters
  const redirectUrl = url || returnTo || next;

  if (redirectUrl) {
    // VULNERABILITY: Redirecting to external URLs without validation
    // VULNERABILITY: No whitelist of allowed domains
    return NextResponse.redirect(redirectUrl, 302);
  }

  return NextResponse.json({
    message: 'Redirect endpoint',
    usage: '?url=http://evil.com or ?returnTo=http://phishing.site',
    // VULNERABILITY: Documenting the vulnerability
    warning: 'This endpoint redirects to any URL without validation',
    examples: [
      '/api/redirect?url=http://evil.com',
      '/api/redirect?returnTo=javascript:alert(1)',
      '/api/redirect?next=//attacker.com'
    ]
  });
}

// VULNERABILITY: POST-based open redirect
export async function POST(request: NextRequest) {
  const body = await request.json();
  const { destination, callback, webhook } = body;

  const redirectUrl = destination || callback || webhook;

  if (redirectUrl) {
    // VULNERABILITY: Server-side redirect based on POST data
    // Could be used for SSRF as well
    return NextResponse.json({
      success: true,
      message: 'Redirecting...',
      location: redirectUrl,
      // VULNERABILITY: Leaking that redirect will happen
      warning: `Will redirect to: ${redirectUrl}`
    });
  }

  return NextResponse.json({ error: 'No destination specified' }, { status: 400 });
}
