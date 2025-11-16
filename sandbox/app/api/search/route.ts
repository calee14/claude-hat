import { NextRequest, NextResponse } from 'next/server';

const mockData = [
  { id: 1, title: 'Admin Panel Access', category: 'admin', secret: 'admin_key_12345' },
  { id: 2, title: 'User Data Export', category: 'user', secret: 'user_key_67890' },
  { id: 3, title: 'Database Backup', category: 'system', secret: 'db_password_abc123' },
];

// VULNERABILITY: NoSQL Injection (simulated)
export async function GET(request: NextRequest) {
  const query = request.nextUrl.searchParams.get('q');
  const filter = request.nextUrl.searchParams.get('filter');
  const category = request.nextUrl.searchParams.get('category');

  // VULNERABILITY: Building query from user input without sanitization
  // Simulating MongoDB-style query: db.collection.find({category: userInput})

  let results = mockData;

  if (category) {
    // VULNERABILITY: NoSQL injection via object injection
    // In real MongoDB: db.find({category: {$ne: null}}) returns everything
    try {
      // VULNERABILITY: eval on user input (simulating NoSQL injection)
      const categoryFilter = category;

      if (categoryFilter.includes('$ne') || categoryFilter.includes('$gt') || categoryFilter.includes('$or')) {
        // Simulating NoSQL injection success
        return NextResponse.json({
          success: true,
          message: 'NoSQL injection detected',
          query: category,
          results: mockData, // Return all data
          warning: 'Query operators like $ne, $gt, $or bypass filters',
          exploitation: {
            payload: category,
            impact: 'Bypassed category filter, returned all documents',
            wouldWork: 'db.collection.find({category: ' + category + '})'
          }
        });
      }

      results = mockData.filter(item => item.category === categoryFilter);
    } catch {
      // Continue
    }
  }

  if (filter) {
    try {
      // VULNERABILITY: Dangerous eval creating injection point
      const filterFunc = eval('(item) => ' + filter);
      results = results.filter(filterFunc);
    } catch (error) {
      return NextResponse.json({
        error: 'Invalid filter',
        hint: 'Filter should be a function: item => item.id > 0',
        warning: 'eval() used on user input - code execution possible'
      }, { status: 400 });
    }
  }

  if (query) {
    // VULNERABILITY: Regex injection
    try {
      // VULNERABILITY: Creating regex from user input without escaping
      const regex = new RegExp(query, 'i');
      results = results.filter(item => regex.test(item.title));
    } catch {
      return NextResponse.json({
        error: 'Invalid regex',
        hint: 'Query uses regex without sanitization - ReDoS possible'
      }, { status: 400 });
    }
  }

  return NextResponse.json({
    success: true,
    count: results.length,
    results: results, // VULNERABILITY: Exposing secret fields
    query: { q: query, filter: filter, category: category },
    warnings: [
      'NoSQL operators not filtered ($ne, $gt, $regex, etc.)',
      'eval() used on filter parameter',
      'Regex created from user input (ReDoS risk)',
      'Secret fields exposed in results'
    ],
    examples: {
      nosqlInjection: '/api/search?category={"$ne":null}',
      codeExecution: '/api/search?filter=item => (console.log(process.env), true)',
      regexDos: '/api/search?q=(a+)+$'
    }
  });
}

// VULNERABILITY: HTTP Parameter Pollution
export async function POST(request: NextRequest) {
  const body = await request.json();

  // VULNERABILITY: Multiple parameters with same name
  const { id, id2, userId, user_id } = body;

  // VULNERABILITY: Unclear which parameter takes precedence
  const actualId = id || id2 || userId || user_id;

  // VULNERABILITY: Using first, last, or concatenated values unpredictably
  return NextResponse.json({
    success: true,
    message: 'Parameter pollution detected',
    receivedParams: { id, id2, userId, user_id },
    usedValue: actualId,
    warning: 'Multiple similar parameters - behavior undefined',
    vulnerability: 'HTTP Parameter Pollution',
    exploitation: {
      description: 'Submit multiple values for same parameter',
      example: '?id=1&id=2 or {"id": "user", "id": "admin"}',
      impact: 'Can bypass filters, access unauthorized data, or cause errors'
    }
  });
}
