import { NextRequest, NextResponse } from 'next/server';

// Mock data
const users = [
  { id: 1, username: 'admin', password: 'admin123', email: 'admin@test.com', ssn: '123-45-6789', creditCard: '4532-1234-5678-9010' },
  { id: 2, username: 'user', password: 'user123', email: 'user@test.com', ssn: '987-65-4321', creditCard: '4532-9876-5432-1098' },
];

// VULNERABILITY: GraphQL with multiple security issues
export async function POST(request: NextRequest) {
  try {
    const body = await request.json();
    const { query, variables } = body;

    if (!query) {
      return NextResponse.json({ error: 'No query provided' }, { status: 400 });
    }

    // VULNERABILITY: No query depth limiting (allows nested queries)
    // VULNERABILITY: No query cost analysis
    // VULNERABILITY: No rate limiting
    // VULNERABILITY: Introspection enabled in production
    // VULNERABILITY: Exposing entire schema

    // Handle introspection query
    if (query.includes('__schema') || query.includes('__type')) {
      return NextResponse.json({
        data: {
          __schema: {
            types: [
              {
                name: 'User',
                fields: [
                  { name: 'id', type: 'Int' },
                  { name: 'username', type: 'String' },
                  { name: 'password', type: 'String' }, // VULNERABILITY: Password in schema
                  { name: 'email', type: 'String' },
                  { name: 'ssn', type: 'String' }, // VULNERABILITY: SSN exposed
                  { name: 'creditCard', type: 'String' }, // VULNERABILITY: Credit card exposed
                ]
              },
              {
                name: 'Admin',
                fields: [
                  { name: 'secretKey', type: 'String' },
                  { name: 'apiToken', type: 'String' }
                ]
              }
            ]
          }
        },
        // VULNERABILITY: Introspection enabled
        warning: 'GraphQL introspection is enabled - full schema exposed'
      });
    }

    // VULNERABILITY: No authentication required
    // VULNERABILITY: Batch query allowed (can cause DoS)
    if (query.includes('users')) {
      return NextResponse.json({
        data: {
          users: users, // VULNERABILITY: Returning all sensitive data including passwords
        },
        // VULNERABILITY: Exposing query execution details
        debug: {
          query: query,
          variables: variables,
          executionTime: '5ms',
          warnings: [
            'No authentication required',
            'Passwords returned in plaintext',
            'PII (SSN, credit cards) exposed',
            'No field-level authorization'
          ]
        }
      });
    }

    // VULNERABILITY: SQL injection via GraphQL variables
    if (query.includes('user') && variables?.id) {
      const userId = variables.id;
      // VULNERABILITY: Direct variable interpolation (SQLi risk)
      const user = users.find(u => eval(`u.id === ${userId}`)); // Dangerous eval

      return NextResponse.json({
        data: { user },
        warning: 'User ID processed without sanitization - SQL injection possible'
      });
    }

    return NextResponse.json({
      data: null,
      error: 'Query not recognized',
      hint: 'Try querying: { users { id username password email ssn creditCard } }'
    });

  } catch (error) {
    // VULNERABILITY: Verbose error messages with stack traces
    return NextResponse.json({
      errors: [{
        message: error instanceof Error ? error.message : String(error),
        stack: error instanceof Error ? error.stack : undefined,
        // VULNERABILITY: Exposing internal paths
        path: __filename,
      }]
    }, { status: 500 });
  }
}

export async function GET(request: NextRequest) {
  // VULNERABILITY: GraphQL IDE exposed in production
  return NextResponse.json({
    message: 'GraphQL endpoint',
    playground: 'Available at /api/graphql (POST)',
    // VULNERABILITY: Documenting vulnerabilities
    vulnerabilities: [
      'Introspection enabled',
      'No authentication',
      'No query depth limiting',
      'No rate limiting',
      'Batch queries allowed',
      'Sensitive data exposed (passwords, SSN, credit cards)',
      'SQL injection via variables',
      'Verbose error messages'
    ],
    exampleQueries: {
      getAllUsers: '{ users { id username password email ssn creditCard } }',
      introspection: '{ __schema { types { name fields { name type } } } }',
      sqlInjection: '{ user(id: "1 OR 1=1") { username password } }'
    }
  });
}
