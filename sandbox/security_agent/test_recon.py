#!/usr/bin/env python3
"""
Quick test script for reconnaissance phase
Tests if route discovery works
"""

import requests
import json

def test_simple_probe():
    """Test the fallback route probing approach."""
    target_url = "http://localhost:3000"

    common_routes = [
        '/',
        '/profile',
        '/api/users',
        '/api/admin',
        '/api/auth',
        '/api/graphql',
        '/api/search'
    ]

    print(f"Testing route discovery on {target_url}")
    print("="*60)

    endpoints = []
    api_routes = []
    pages = []

    for route in common_routes:
        try:
            url = f"{target_url}{route}"
            response = requests.get(url, timeout=5)

            endpoint = {
                'path': route,
                'full_url': url,
                'status_code': response.status_code,
                'methods': ['GET'],
                'parameters': []
            }

            endpoints.append(endpoint)

            if route.startswith('/api/'):
                api_routes.append(route)
            else:
                pages.append(route)

            print(f"✓ {route} - Status: {response.status_code}")

        except requests.exceptions.ConnectionError:
            print(f"✗ {route} - Connection refused (app not running?)")
        except requests.exceptions.Timeout:
            print(f"✗ {route} - Timeout")
        except Exception as e:
            print(f"✗ {route} - Error: {e}")

    print("\n" + "="*60)
    print(f"Discovered {len(endpoints)} endpoints")
    print(f"  - API routes: {len(api_routes)}")
    print(f"  - Pages: {len(pages)}")
    print("="*60)

    result = {
        'endpoints': endpoints,
        'api_routes': api_routes,
        'pages': pages,
        'technology_detected': 'Next.js'
    }

    print("\nResult JSON:")
    print(json.dumps(result, indent=2))

    return result


if __name__ == "__main__":
    print("Route Discovery Test")
    print("Make sure your app is running at http://localhost:3000")
    print()

    try:
        result = test_simple_probe()

        if result['endpoints']:
            print("\n✅ SUCCESS: Route discovery working!")
        else:
            print("\n❌ FAILED: No routes discovered")
            print("Is the app running? Try: npm run dev")

    except KeyboardInterrupt:
        print("\n\nTest interrupted")
    except Exception as e:
        print(f"\n❌ ERROR: {e}")
        import traceback
        traceback.print_exc()
