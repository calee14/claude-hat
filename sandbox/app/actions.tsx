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

// VULNERABILITY: Mass Assignment
export async function createUser(formData: FormData) {
  // VULNERABILITY: Accepting all form fields without filtering
  const userData: Record<string, any> = {};

  // VULNERABILITY: Automatically assigning all fields from form
  formData.forEach((value, key) => {
    userData[key] = value;
  });

  // VULNERABILITY: User can set sensitive fields like isAdmin, role, credits, etc.
  return {
    success: true,
    message: 'User created',
    user: userData,
    warning: 'All form fields accepted - user can set isAdmin, role, balance, etc.',
    // VULNERABILITY: Leaking what fields are dangerous
    dangerousFields: ['isAdmin', 'role', 'accountBalance', 'permissions', 'apiKey']
  };
}

// VULNERABILITY: Insecure Direct Object Reference (IDOR)
export async function getDocument(docId: string) {
  // VULNERABILITY: No ownership check
  // VULNERABILITY: Direct access to any document by ID
  const documents = {
    '1': { title: 'Public Doc', content: 'Public content', owner: 'user1' },
    '2': { title: 'Private Doc', content: 'Secret information', owner: 'admin', ssn: '123-45-6789' },
    '3': { title: 'Confidential', content: 'Company secrets', owner: 'admin', apiKey: 'sk_live_12345' },
  };

  return {
    success: true,
    document: documents[docId as keyof typeof documents],
    // VULNERABILITY: No authentication or authorization
    warning: 'Any document accessible by ID without auth check',
    hint: 'Try docId 1, 2, or 3'
  };
}

// VULNERABILITY: Race Condition
let accountBalance = 1000;
export async function withdraw(amount: number) {
  // VULNERABILITY: No transaction locking
  // VULNERABILITY: Time-of-check to time-of-use (TOCTOU) flaw

  // Check if sufficient balance
  if (accountBalance >= amount) {
    // VULNERABILITY: Race window here - multiple requests can pass the check
    // Simulate some processing time
    await new Promise(resolve => setTimeout(resolve, 100));

    // Deduct amount
    accountBalance -= amount;

    return {
      success: true,
      withdrawn: amount,
      newBalance: accountBalance,
      warning: 'Race condition - concurrent requests can overdraw account'
    };
  }

  return {
    success: false,
    message: 'Insufficient funds',
    currentBalance: accountBalance
  };
}

// VULNERABILITY: Insecure Randomness
export async function generateToken() {
  // VULNERABILITY: Using Math.random() for security-critical operations
  // VULNERABILITY: Predictable token generation
  const token = Math.random().toString(36).substring(2);

  return {
    success: true,
    token: token,
    sessionId: Math.floor(Math.random() * 1000000),
    // VULNERABILITY: Exposing that random is weak
    warning: 'Token generated with Math.random() - predictable and insecure',
    recommendation: 'Use crypto.randomBytes() for security tokens'
  };
}

// VULNERABILITY: Server-Side Template Injection (simulated)
export async function renderTemplate(template: string, data: Record<string, any>) {
  // VULNERABILITY: Evaluating user-provided templates
  // VULNERABILITY: Template injection leading to RCE

  try {
    // VULNERABILITY: Using eval to render templates
    const rendered = eval('`' + template + '`');

    return {
      success: true,
      template: template,
      rendered: rendered,
      data: data,
      warning: 'Template rendered with eval - code execution possible',
      example: 'Template: Hello ${data.name}${process.env.SECRET}'
    };
  } catch (error) {
    return {
      success: false,
      error: error instanceof Error ? error.message : String(error),
      template: template,
      // VULNERABILITY: Stack traces leak information
      stack: error instanceof Error ? error.stack : undefined
    };
  }
}

// VULNERABILITY: Timing Attack
export async function checkPassword(password: string) {
  const correctPassword = 'super_secret_password_123';

  // VULNERABILITY: Character-by-character comparison
  // Allows timing attacks to brute force password
  for (let i = 0; i < Math.min(password.length, correctPassword.length); i++) {
    if (password[i] !== correctPassword[i]) {
      return {
        success: false,
        message: 'Incorrect password',
        // VULNERABILITY: Leaking how many characters were correct via timing
        warning: 'Timing attack possible - comparison stops at first mismatch',
        charactersChecked: i + 1
      };
    }
    // Simulate some processing that takes time
    await new Promise(resolve => setTimeout(resolve, 10));
  }

  if (password.length !== correctPassword.length) {
    return {
      success: false,
      message: 'Incorrect password length',
      warning: 'Length leaked via timing'
    };
  }

  return {
    success: true,
    message: 'Password correct!',
    secretData: 'Access granted to admin panel'
  };
}

// VULNERABILITY: Unvalidated Redirects in Server Action
export async function processLogin(username: string, redirectUrl: string) {
  // VULNERABILITY: No validation of redirect URL
  // VULNERABILITY: Open redirect after login

  if (username) {
    return {
      success: true,
      username: username,
      // VULNERABILITY: Redirecting to user-controlled URL
      redirectTo: redirectUrl,
      warning: 'No redirect URL validation - phishing risk',
      example: 'Can redirect to http://evil.com after login'
    };
  }

  return {
    success: false,
    message: 'Login failed'
  };
}

// VULNERABILITY: Information Disclosure via Error Messages
export async function processPayment(amount: number, cardNumber: string) {
  // VULNERABILITY: Detailed error messages reveal system state

  if (!cardNumber) {
    return {
      success: false,
      error: 'Card number required',
      // VULNERABILITY: Leaking payment processor details
      processor: 'Stripe API v3',
      endpoint: 'https://api.stripe.com/v1/charges',
      apiKeyPrefix: 'sk_live_',
    };
  }

  if (cardNumber.length !== 16) {
    return {
      success: false,
      error: 'Invalid card number',
      received: cardNumber,
      expectedLength: 16,
      // VULNERABILITY: Echoing back sensitive input
      yourInput: cardNumber,
      hint: 'Card should be 16 digits'
    };
  }

  if (amount > 10000) {
    return {
      success: false,
      error: 'Amount exceeds limit',
      // VULNERABILITY: Revealing business logic
      dailyLimit: 10000,
      yourAmount: amount,
      accountType: 'basic',
      upgradeUrl: '/upgrade'
    };
  }

  return {
    success: true,
    message: 'Payment processed',
    amount: amount,
    // VULNERABILITY: Exposing transaction details
    transactionId: 'txn_' + cardNumber.slice(-4),
    processorFee: amount * 0.029,
    netAmount: amount * 0.971
  };
}
