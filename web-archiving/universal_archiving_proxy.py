#!/usr/bin/env python3
"""
Universal Archiving Proxy
For sites with dual DNS issues - routes domain name to correct IP with proper Host header
"""

from http.server import HTTPServer, BaseHTTPRequestHandler
import urllib.request
import sys
import os
import argparse
import subprocess

class ProxyHandler(BaseHTTPRequestHandler):
    target_ip = None
    target_domain = None
    
    def do_GET(self):
        # Build the target URL using IP but with correct Host header
        target_url = f"http://{self.target_ip}{self.path}"
        
        print(f"Proxying: {self.path}")
        
        try:
            # Create request with proper headers
            headers = {
                'Host': self.target_domain,
                'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
                'Connection': 'keep-alive',
            }
            
            # Forward original headers except Host
            for header, value in self.headers.items():
                if header.lower() not in ['host', 'connection']:
                    headers[header] = value
            
            # Make request
            req = urllib.request.Request(target_url, headers=headers)
            
            with urllib.request.urlopen(req, timeout=30) as response:
                # Send response status
                self.send_response(response.status)
                
                # Send response headers
                for header, value in response.headers.items():
                    if header.lower() not in ['transfer-encoding', 'connection']:
                        self.send_header(header, value)
                self.end_headers()
                
                # Send response body
                self.wfile.write(response.read())
                
        except Exception as e:
            print(f"Error: {e}")
            self.send_error(502, f"Proxy Error: {str(e)}")
    
    def do_POST(self):
        self.do_GET()
    
    def log_message(self, format, *args):
        print(f"{args[0]}")

def resolve_ip(domain):
    """Resolve domain to IP using public DNS"""
    import subprocess
    try:
        result = subprocess.run(['dig', '@8.8.8.8', domain, '+short'], 
                              capture_output=True, text=True, timeout=10)
        ip = result.stdout.strip().split('\n')[0]
        if ip and ip.count('.') == 3:  # Basic IP validation
            return ip
        return None
    except:
        return None

def setup_hosts(domain):
    """Add 127.0.0.1 mapping for target domain"""
    print(f"Adding to /etc/hosts: 127.0.0.1 {domain}")
    os.system(f'echo "127.0.0.1 {domain}" | sudo tee -a /etc/hosts > /dev/null')
    print(f"✓ Added")

def cleanup_hosts(domain):
    """Remove the hosts entry"""
    print(f"\nRemoving from /etc/hosts: {domain}")
    os.system(f"sudo sed -i.bak '/127.0.0.1.*{domain}/d' /etc/hosts")
    print(f"✓ Removed")

def main():
    parser = argparse.ArgumentParser(
        description='Universal Archiving Proxy for dual-DNS sites',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  # Auto-resolve IP using public DNS
  %(prog)s www.example.com
  
  # Specify IP manually
  %(prog)s www.example.com --ip 123.456.789.123
  
  # Use custom port (no sudo required)
  %(prog)s www.example.com --port 8080
  
  # Then in browser with ArchiveWeb.page:
  # - Start recording
  # - Browse to http://www.example.com (or http://www.example.com:8080 if using custom port)
  # - Navigate pages
  # - Save WARC (will have correct URLs for Archive-It!)
        '''
    )
    
    parser.add_argument('domain', help='Domain name to archive (e.g., www.example.com)')
    parser.add_argument('--ip', help='Target IP address (auto-resolves if not provided)')
    parser.add_argument('--port', type=int, default=80, 
                       help='Proxy port (default: 80, use 8080 to avoid sudo)')
    parser.add_argument('--no-hosts', action='store_true',
                       help='Skip /etc/hosts modification (you must add manually)')
    
    args = parser.parse_args()
    
    # Clean up domain (remove http://, https://, trailing slash)
    domain = args.domain.replace('http://', '').replace('https://', '').rstrip('/')
    
    # Resolve IP if not provided
    if args.ip:
        target_ip = args.ip
        print(f"Using provided IP: {target_ip}")
    else:
        print(f"Resolving {domain} via public DNS...")
        target_ip = resolve_ip(domain)
        if not target_ip:
            print(f"✗ Could not resolve {domain}")
            print("Please provide IP manually with --ip flag")
            sys.exit(1)
        print(f"✓ Resolved to: {target_ip}")
    
    # Set class variables for handler
    ProxyHandler.target_ip = target_ip
    ProxyHandler.target_domain = domain
    
    print()
    print("=" * 60)
    print("Universal Archiving Proxy")
    print("=" * 60)
    print(f"Domain: {domain}")
    print(f"Target IP: {target_ip}")
    print(f"Proxy Port: {args.port}")
    print("=" * 60)
    print()
    
    # Setup hosts file
    if not args.no_hosts:
        print("SETUP:")
        print(f"Adding '127.0.0.1 {domain}' to /etc/hosts...")
        if args.port == 80:
            print("(Running on port 80 requires sudo)")
        print()
        
        setup_hosts(domain)
        print()
    
    # Determine URL user should visit
    if args.port == 80:
        visit_url = f"http://{domain}"
    else:
        visit_url = f"http://{domain}:{args.port}"
    
    print("=" * 60)
    print("ARCHIVING INSTRUCTIONS:")
    print("=" * 60)
    print(f"1. Open browser with ArchiveWeb.page extension")
    print(f"2. Start recording")
    print(f"3. Browse to: {visit_url}")
    print(f"4. Navigate all pages you want to archive")
    print(f"5. Stop recording and save WARC")
    print(f"6. Press Ctrl+C here to stop proxy")
    print()
    print("The WARC will contain correct URLs for Archive-It!")
    print(f"Archive-It seed URL: {visit_url}")
    print("=" * 60)
    print()
    
    try:
        server = HTTPServer(('127.0.0.1', args.port), ProxyHandler)
        
        if args.port == 80:
            print("Note: Port 80 requires sudo - you may be asked for password")
        
        print(f"✓ Proxy listening on 127.0.0.1:{args.port}")
        print(f"  Access via: {visit_url}")
        print()
        print("Press Ctrl+C to stop")
        print()
        
        server.serve_forever()
        
    except PermissionError:
        print(f"\n✗ Permission denied for port {args.port}")
        if args.port == 80:
            print("Run with: sudo python3 universal_archiving_proxy.py", ' '.join(sys.argv[1:]))
            print("Or use custom port: --port 8080")
        if not args.no_hosts:
            cleanup_hosts(domain)
        sys.exit(1)
        
    except KeyboardInterrupt:
        print("\n\nShutting down proxy...")
        server.shutdown()
        print("✓ Proxy stopped")
        
    finally:
        if not args.no_hosts:
            cleanup_hosts(domain)

if __name__ == "__main__":
    main()
