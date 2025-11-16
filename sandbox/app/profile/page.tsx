'use client'

import { useState } from 'react';
import { updateProfile, searchFiles, readFile, fetchExternalData } from '../actions';

export default function ProfilePage() {
  const [message, setMessage] = useState('');
  const [searchResult, setSearchResult] = useState('');
  const [fileContent, setFileContent] = useState('');
  const [fetchResult, setFetchResult] = useState('');

  async function handleUpdateProfile(formData: FormData) {
    const result = await updateProfile(formData);
    setMessage(JSON.stringify(result));
  }

  async function handleSearch(formData: FormData) {
    const query = formData.get('query') as string;
    const result = await searchFiles(query);
    setSearchResult(JSON.stringify(result));
  }

  async function handleReadFile(formData: FormData) {
    const filename = formData.get('filename') as string;
    const result = await readFile(filename);
    setFileContent(JSON.stringify(result));
  }

  async function handleFetch(formData: FormData) {
    const url = formData.get('url') as string;
    const result = await fetchExternalData(url);
    setFetchResult(JSON.stringify(result));
  }

  return (
    <div style={{ padding: '20px', fontFamily: 'sans-serif' }}>
      <h1>User Profile</h1>

      {/* VULNERABILITY: XSS via dangerouslySetInnerHTML */}
      <div
        dangerouslySetInnerHTML={{ __html: message }}
        style={{ background: '#f0f0f0', padding: '10px', margin: '10px 0' }}
      />

      <div style={{ marginBottom: '30px' }}>
        <h2>Update Profile</h2>
        <form action={handleUpdateProfile}>
          <input
            name="username"
            placeholder="Username"
            style={{ display: 'block', margin: '10px 0', padding: '5px' }}
          />
          {/* VULNERABILITY: Bio will be rendered without sanitization */}
          <textarea
            name="bio"
            placeholder="Bio (HTML allowed!)"
            style={{ display: 'block', margin: '10px 0', padding: '5px', width: '300px' }}
          />
          {/* VULNERABILITY: User can set their own role */}
          <select name="role" style={{ display: 'block', margin: '10px 0', padding: '5px' }}>
            <option value="user">User</option>
            <option value="admin">Admin</option>
            <option value="superadmin">Super Admin</option>
          </select>
          <button type="submit" style={{ padding: '5px 15px' }}>Update</button>
        </form>
      </div>

      <div style={{ marginBottom: '30px' }}>
        <h2>Search Files (Command Injection Risk)</h2>
        <form action={handleSearch}>
          <input
            name="query"
            placeholder="Search query (try: *.txt)"
            style={{ display: 'block', margin: '10px 0', padding: '5px', width: '300px' }}
          />
          <button type="submit" style={{ padding: '5px 15px' }}>Search</button>
        </form>
        {/* VULNERABILITY: Displaying unsanitized search results */}
        <div dangerouslySetInnerHTML={{ __html: searchResult }} />
      </div>

      <div style={{ marginBottom: '30px' }}>
        <h2>Read File (Path Traversal Risk)</h2>
        <form action={handleReadFile}>
          <input
            name="filename"
            placeholder="Filename (try: ../../etc/passwd)"
            style={{ display: 'block', margin: '10px 0', padding: '5px', width: '300px' }}
          />
          <button type="submit" style={{ padding: '5px 15px' }}>Read</button>
        </form>
        <pre style={{ background: '#f0f0f0', padding: '10px' }}>{fileContent}</pre>
      </div>

      <div style={{ marginBottom: '30px' }}>
        <h2>Fetch External Data (SSRF Risk)</h2>
        <form action={handleFetch}>
          <input
            name="url"
            placeholder="URL (try: http://localhost:3000/api/admin)"
            style={{ display: 'block', margin: '10px 0', padding: '5px', width: '300px' }}
          />
          <button type="submit" style={{ padding: '5px 15px' }}>Fetch</button>
        </form>
        <pre style={{ background: '#f0f0f0', padding: '10px' }}>{fetchResult}</pre>
      </div>

      {/* VULNERABILITY: Exposing sensitive info in comments */}
      {/* Admin password: admin123 */}
      {/* API endpoint: /api/admin?admin=true */}
    </div>
  );
}
