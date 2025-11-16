import type { Metadata } from 'next'

export const metadata: Metadata = {
  title: 'Vulnerable Next.js App',
  description: 'Intentionally vulnerable app for security testing',
}

export default function RootLayout({
  children,
}: {
  children: React.ReactNode
}) {
  return (
    <html lang="en">
      <body style={{ margin: 0, fontFamily: 'system-ui, sans-serif' }}>
        <nav style={{
          background: '#333',
          color: 'white',
          padding: '15px 20px',
          marginBottom: '20px'
        }}>
          <a href="/" style={{ color: 'white', marginRight: '20px', textDecoration: 'none' }}>Home</a>
          <a href="/profile" style={{ color: 'white', marginRight: '20px', textDecoration: 'none' }}>Profile</a>
          <a href="/api/users" style={{ color: 'white', marginRight: '20px', textDecoration: 'none' }}>Users API</a>
          <a href="/api/admin" style={{ color: 'white', textDecoration: 'none' }}>Admin API</a>
        </nav>
        {children}
      </body>
    </html>
  )
}
