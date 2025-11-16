'use server'

// VULNERABILITY: No proper authentication in server actions
export async function deleteUser(userId: string) {
  // VULNERABILITY: No authorization check
  // In real app, this would delete from database
  console.log(`Deleting user ${userId}`);

  return {
    success: true,
    message: `User ${userId} deleted`,
    // VULNERABILITY: Leaking internal paths
    deletedFrom: __dirname,
  };
}

// VULNERABILITY: Command injection via unsanitized input
export async function searchFiles(query: string) {
  // VULNERABILITY: Direct execution of user input
  // Simulating: exec(`find . -name "${query}"`)

  return {
    success: true,
    query: query,
    // VULNERABILITY: Would execute arbitrary commands
    warning: 'This would execute: find . -name "' + query + '"',
  };
}

// VULNERABILITY: Path traversal
export async function readFile(filename: string) {
  // VULNERABILITY: No path validation
  // In real scenario: fs.readFileSync(`./uploads/${filename}`)

  return {
    success: true,
    filename: filename,
    // VULNERABILITY: Could read any file
    warning: 'This would read: ./uploads/' + filename,
  };
}

// VULNERABILITY: Missing rate limiting and input validation
export async function updateProfile(formData: FormData) {
  const username = formData.get('username') as string;
  const bio = formData.get('bio') as string;
  const role = formData.get('role') as string; // VULNERABILITY: User can set their own role

  // VULNERABILITY: No authentication, anyone can update any profile
  // VULNERABILITY: XSS via unsanitized bio
  return {
    success: true,
    username,
    bio, // Would be stored and rendered without sanitization
    role, // User could make themselves admin
  };
}

// VULNERABILITY: SSRF via unvalidated URL
export async function fetchExternalData(url: string) {
  // VULNERABILITY: No URL validation, can access internal services
  // In real scenario: fetch(url)

  return {
    success: true,
    url: url,
    warning: 'This would fetch from: ' + url + ' (SSRF risk)',
  };
}
