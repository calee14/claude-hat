import { NextRequest, NextResponse } from 'next/server';

// VULNERABILITY: Unrestricted File Upload
export async function POST(request: NextRequest) {
  try {
    const formData = await request.formData();
    const file = formData.get('file') as File;
    const filename = formData.get('filename') as string || file?.name;

    if (!file) {
      return NextResponse.json({ error: 'No file provided' }, { status: 400 });
    }

    // VULNERABILITY: No file type validation
    // VULNERABILITY: No file size limits
    // VULNERABILITY: No antivirus scanning
    // VULNERABILITY: Filename not sanitized (path traversal)
    // VULNERABILITY: Executable files allowed (.sh, .exe, .php, .jsp)

    const allowedPath = '/uploads/' + filename; // Path traversal possible

    return NextResponse.json({
      success: true,
      message: 'File uploaded successfully',
      // VULNERABILITY: Leaking upload path
      uploadedTo: allowedPath,
      fileInfo: {
        name: file.name,
        size: file.size,
        type: file.type,
        // VULNERABILITY: No MIME type validation
        warning: 'No validation - any file type accepted including executables'
      }
    });
  } catch (error) {
    // VULNERABILITY: Verbose error messages
    return NextResponse.json({
      error: 'Upload failed',
      details: error instanceof Error ? error.message : String(error),
      stack: error instanceof Error ? error.stack : undefined
    }, { status: 500 });
  }
}

// VULNERABILITY: Public file listing
export async function GET(request: NextRequest) {
  const path = request.nextUrl.searchParams.get('path') || '/uploads';

  // VULNERABILITY: Directory traversal - no path sanitization
  // VULNERABILITY: Exposing full file system structure
  return NextResponse.json({
    success: true,
    path: path,
    warning: `Would list files from: ${path}`,
    // VULNERABILITY: Exposing system info
    systemPaths: {
      home: process.env.HOME,
      pwd: process.cwd(),
      temp: process.env.TMPDIR
    }
  });
}
