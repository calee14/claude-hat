import { NextRequest, NextResponse } from 'next/server';

// VULNERABILITY: Insecure Deserialization
export async function POST(request: NextRequest) {
  try {
    const body = await request.json();
    const { serialized, data, payload } = body;

    const input = serialized || data || payload;

    if (!input) {
      return NextResponse.json({ error: 'No data provided' }, { status: 400 });
    }

    // VULNERABILITY: Deserializing untrusted data
    // VULNERABILITY: Using eval on user input
    // VULNERABILITY: No type validation

    let result;
    if (typeof input === 'string' && input.startsWith('{')) {
      // VULNERABILITY: Direct eval of JSON-like strings
      try {
        result = eval('(' + input + ')'); // Extremely dangerous
      } catch {
        result = JSON.parse(input);
      }
    } else {
      result = input;
    }

    // VULNERABILITY: Executing functions from deserialized data
    if (result && typeof result === 'object') {
      if (result.constructor && result.constructor.name !== 'Object') {
        // VULNERABILITY: Allowing arbitrary constructor calls
        return NextResponse.json({
          success: true,
          message: 'Custom object deserialized',
          result: result,
          warning: 'Arbitrary constructor execution possible',
          danger: 'Could execute malicious code during deserialization'
        });
      }

      // VULNERABILITY: Calling methods from deserialized objects
      if (typeof result.toString === 'function') {
        try {
          const output = result.toString();
          return NextResponse.json({
            success: true,
            deserialized: result,
            output: output,
            warning: 'Methods called on untrusted objects'
          });
        } catch (e) {
          // Continue
        }
      }
    }

    // VULNERABILITY: Reflecting back malicious content
    return NextResponse.json({
      success: true,
      original: input,
      deserialized: result,
      type: typeof result,
      warnings: [
        'Data deserialized without validation',
        'eval() used on user input',
        'Arbitrary code execution possible',
        'Object methods called without sanitization'
      ],
      // VULNERABILITY: Providing RCE examples
      exampleExploit: {
        rce: '{"toString": function(){ return global.process.mainModule.require("child_process").execSync("whoami").toString() }}',
        prototypePoIlution: '{"__proto__": {"isAdmin": true}}',
        functionExecution: '(function(){ return process.env })()'
      }
    });

  } catch (error) {
    // VULNERABILITY: Verbose error messages exposing stack traces
    return NextResponse.json({
      error: 'Deserialization failed',
      message: error instanceof Error ? error.message : String(error),
      stack: error instanceof Error ? error.stack : undefined,
      // VULNERABILITY: Exposing Node.js internals
      nodeVersion: process.version,
      platform: process.platform
    }, { status: 500 });
  }
}

// VULNERABILITY: Cookie deserialization
export async function GET(request: NextRequest) {
  const sessionCookie = request.cookies.get('session');

  if (sessionCookie) {
    try {
      // VULNERABILITY: Deserializing cookies without signature verification
      const session = JSON.parse(
        Buffer.from(sessionCookie.value, 'base64').toString()
      );

      // VULNERABILITY: Trusting deserialized session data
      if (session.isAdmin) {
        return NextResponse.json({
          success: true,
          message: 'Admin session detected',
          session: session,
          // VULNERABILITY: Granting access based on cookie content
          adminAccess: true,
          hint: 'Session cookie deserialized without verification'
        });
      }

      return NextResponse.json({
        success: true,
        session: session,
        hint: 'Try setting isAdmin=true in your session cookie'
      });
    } catch {
      // VULNERABILITY: Still processing on error
      return NextResponse.json({
        error: 'Invalid session',
        hint: 'Session should be base64-encoded JSON: {"user": "...", "isAdmin": true}'
      });
    }
  }

  return NextResponse.json({
    message: 'Deserialization endpoint',
    usage: 'POST serialized data or set session cookie',
    vulnerabilities: [
      'Insecure deserialization',
      'eval() on user input',
      'No signature verification',
      'Arbitrary code execution',
      'Prototype pollution possible'
    ]
  });
}
