import { NextRequest, NextResponse } from 'next/server';

// VULNERABILITY: XML External Entity (XXE) Injection (simulated)
export async function POST(request: NextRequest) {
  const contentType = request.headers.get('content-type');

  if (!contentType?.includes('xml')) {
    return NextResponse.json({
      error: 'Expected XML content',
      hint: 'Send Content-Type: application/xml'
    }, { status: 400 });
  }

  try {
    const xmlData = await request.text();

    // VULNERABILITY: XXE - parsing XML without disabling external entities
    // VULNERABILITY: No input validation
    // In real scenario, this would use xml2js or similar with XXE vulnerability

    // Check for XXE payload indicators
    const hasEntity = xmlData.includes('<!ENTITY');
    const hasSystemEntity = xmlData.includes('SYSTEM');
    const hasExternalRef = xmlData.includes('file://') || xmlData.includes('http://');

    return NextResponse.json({
      success: true,
      message: 'XML processed',
      // VULNERABILITY: Echoing back user input
      receivedXML: xmlData,
      warnings: [
        'XML parsed without disabling external entities',
        'SYSTEM entities would be resolved',
        'Could read local files via file:// protocol',
        'Could make HTTP requests to internal services'
      ],
      vulnerabilityDetected: hasEntity && hasSystemEntity,
      // VULNERABILITY: Simulating what would happen
      simulation: hasExternalRef ? {
        message: 'XXE payload detected',
        wouldAccess: xmlData.match(/(?:file|http):\/\/[^\s"'<>]+/g),
        impact: 'Could read /etc/passwd, access internal services, or exfiltrate data'
      } : null,
      // VULNERABILITY: Providing exploit examples
      examplePayload: `<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<data>&xxe;</data>`
    });
  } catch (error) {
    // VULNERABILITY: Verbose error messages
    return NextResponse.json({
      error: 'XML parsing failed',
      details: error instanceof Error ? error.message : String(error),
      stack: error instanceof Error ? error.stack : undefined
    }, { status: 500 });
  }
}

export async function GET(request: NextRequest) {
  return NextResponse.json({
    endpoint: '/api/xml',
    method: 'POST',
    contentType: 'application/xml',
    vulnerability: 'XXE (XML External Entity Injection)',
    description: 'This endpoint parses XML without disabling external entities',
    testPayload: `<?xml version="1.0"?>
<!DOCTYPE data [
  <!ENTITY file SYSTEM "file:///etc/passwd">
]>
<root>
  <data>&file;</data>
</root>`,
    impact: [
      'Read local files',
      'SSRF to internal services',
      'Denial of Service',
      'Data exfiltration'
    ]
  });
}
