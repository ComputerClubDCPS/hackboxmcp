#!/usr/bin/env python3
"""
HackBox MCP Server with Web Panel
A Model Context Protocol server that creates temporary Kali Linux instances
with web panel management and authentication.
"""

import asyncio
import json
import time
import uuid
import hashlib
import secrets
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, List
import docker
from docker.models.containers import Container
from fastmcp import FastMCP
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
import urllib.parse
import os

# Configuration
DEFAULT_TIMEOUT_MINUTES = 5
DEFAULT_WEB_PORT = 8080
DEFAULT_WEB_USERNAME = "admin"
DEFAULT_WEB_PASSWORD = "admin123"  # Should be changed on first login

class HackBoxWebPanel:
    """Web panel for managing HackBox instances"""
    
    def __init__(self, mcp_server, port: int = DEFAULT_WEB_PORT):
        self.mcp_server = mcp_server
        self.port = port
        self.username = DEFAULT_WEB_USERNAME
        self.password_hash = self._hash_password(DEFAULT_WEB_PASSWORD)
        self.access_token = secrets.token_urlsafe(32)
        self.server = None
        self.thread = None
        
    def _hash_password(self, password: str) -> str:
        """Hash password using SHA-256"""
        return hashlib.sha256(password.encode()).hexdigest()
    
    def verify_password(self, password: str) -> bool:
        """Verify password against stored hash"""
        return self._hash_password(password) == self.password_hash
    
    def change_password(self, old_password: str, new_password: str) -> bool:
        """Change web panel password"""
        if self.verify_password(old_password):
            self.password_hash = self._hash_password(new_password)
            return True
        return False
    
    def generate_new_token(self) -> str:
        """Generate new access token"""
        self.access_token = secrets.token_urlsafe(32)
        return self.access_token
    
    def start(self):
        """Start the web panel server"""
        handler = self._create_handler()
        self.server = HTTPServer(('0.0.0.0', self.port), handler)
        self.thread = threading.Thread(target=self.server.serve_forever)
        self.thread.daemon = True
        self.thread.start()
        print(f"Web panel started on http://0.0.0.0:{self.port}")
        print(f"Default credentials: {self.username} / {DEFAULT_WEB_PASSWORD}")
        print(f"Access token: {self.access_token}")
    
    def stop(self):
        """Stop the web panel server"""
        if self.server:
            self.server.shutdown()
            self.server.server_close()
    
    def _create_handler(self):
        """Create HTTP request handler with closure to access web panel instance"""
        web_panel = self
        
        class WebPanelHandler(BaseHTTPRequestHandler):
            
            def do_GET(self):
                """Handle GET requests"""
                parsed_path = urllib.parse.urlparse(self.path)
                path = parsed_path.path
                
                # Check authentication for protected routes
                if path not in ['/login', '/static/login.js'] and not self._is_authenticated():
                    self._redirect_to_login()
                    return
                
                if path == '/':
                    self._serve_dashboard()
                elif path == '/login':
                    self._serve_login_page()
                elif path == '/api/instances':
                    self._serve_instances_api()
                elif path == '/api/terminate':
                    self._terminate_instance()
                elif path == '/api/settings':
                    self._serve_settings_api()
                elif path == '/api/change_password':
                    self._change_password()
                elif path == '/api/regenerate_token':
                    self._regenerate_token()
                else:
                    self._serve_static(path)
            
            def do_POST(self):
                """Handle POST requests"""
                parsed_path = urllib.parse.urlparse(self.path)
                path = parsed_path.path
                
                if path == '/api/login':
                    self._handle_login()
                elif path == '/api/change_password':
                    self._change_password()
                elif path == '/api/regenerate_token':
                    self._regenerate_token()
                else:
                    self._send_error(404, "Not Found")
            
            def _is_authenticated(self):
                """Check if user is authenticated"""
                cookie = self.headers.get('Cookie', '')
                return 'hackbox_auth=1' in cookie
            
            def _redirect_to_login(self):
                """Redirect to login page"""
                self.send_response(302)
                self.send_header('Location', '/login')
                self.end_headers()
            
            def _serve_login_page(self):
                """Serve login page"""
                html = '''
                <!DOCTYPE html>
                <html>
                <head>
                    <title>HackBox MCP - Login</title>
                    <style>
                        body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background: #1a1a1a; color: white; }
                        .login-container { max-width: 400px; margin: 100px auto; background: #2d2d2d; padding: 30px; border-radius: 8px; }
                        .form-group { margin-bottom: 15px; }
                        label { display: block; margin-bottom: 5px; }
                        input { width: 100%; padding: 8px; border: 1px solid #444; background: #1a1a1a; color: white; border-radius: 4px; }
                        button { width: 100%; padding: 10px; background: #007acc; color: white; border: none; border-radius: 4px; cursor: pointer; }
                        .error { color: #ff4444; margin-top: 10px; }
                    </style>
                </head>
                <body>
                    <div class="login-container">
                        <h2>HackBox MCP - Login</h2>
                        <form id="loginForm">
                            <div class="form-group">
                                <label>Username:</label>
                                <input type="text" name="username" value="admin" required>
                            </div>
                            <div class="form-group">
                                <label>Password:</label>
                                <input type="password" name="password" required>
                            </div>
                            <button type="submit">Login</button>
                            <div id="error" class="error"></div>
                        </form>
                    </div>
                    <script>
                        document.getElementById('loginForm').addEventListener('submit', async (e) => {
                            e.preventDefault();
                            const formData = new FormData(e.target);
                            const response = await fetch('/api/login', {
                                method: 'POST',
                                headers: { 'Content-Type': 'application/json' },
                                body: JSON.stringify({
                                    username: formData.get('username'),
                                    password: formData.get('password')
                                })
                            });
                            
                            if (response.ok) {
                                window.location.href = '/';
                            } else {
                                document.getElementById('error').textContent = 'Invalid credentials';
                            }
                        });
                    </script>
                </body>
                </html>
                '''
                self._send_html(html)
            
            def _serve_dashboard(self):
                """Serve main dashboard"""
                html = '''
                <!DOCTYPE html>
                <html>
                <head>
                    <title>HackBox MCP - Dashboard</title>
                    <style>
                        body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background: #1a1a1a; color: white; }
                        .header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 30px; }
                        .card { background: #2d2d2d; padding: 20px; border-radius: 8px; margin-bottom: 20px; }
                        .instance { border: 1px solid #444; padding: 15px; margin: 10px 0; border-radius: 4px; }
                        .btn { padding: 8px 16px; border: none; border-radius: 4px; cursor: pointer; margin: 5px; }
                        .btn-danger { background: #dc3545; color: white; }
                        .btn-primary { background: #007acc; color: white; }
                        .btn-success { background: #28a745; color: white; }
                        .settings-section { margin: 20px 0; }
                        .token-display { background: #1a1a1a; padding: 10px; border-radius: 4px; font-family: monospace; margin: 10px 0; }
                    </style>
                </head>
                <body>
                    <div class="header">
                        <h1>HackBox MCP Dashboard</h1>
                        <button class="btn btn-primary" onclick="location.reload()">Refresh</button>
                    </div>
                    
                    <div class="card">
                        <h2>Active Kali Instances</h2>
                        <div id="instances">Loading...</div>
                    </div>
                    
                    <div class="card">
                        <h2>Settings</h2>
                        <div class="settings-section">
                            <h3>Change Password</h3>
                            <form id="passwordForm">
                                <input type="password" placeholder="Current Password" name="currentPassword" required>
                                <input type="password" placeholder="New Password" name="newPassword" required>
                                <button type="submit" class="btn btn-primary">Change Password</button>
                            </form>
                        </div>
                        
                        <div class="settings-section">
                            <h3>Access Token</h3>
                            <div class="token-display" id="currentToken">Loading...</div>
                            <button class="btn btn-success" onclick="regenerateToken()">Generate New Token</button>
                        </div>
                    </div>
                    
                    <script>
                        async function loadInstances() {
                            const response = await fetch('/api/instances');
                            const instances = await response.json();
                            
                            const container = document.getElementById('instances');
                            if (instances.length === 0) {
                                container.innerHTML = '<p>No active instances</p>';
                                return;
                            }
                            
                            container.innerHTML = instances.map(instance => `
                                <div class="instance">
                                    <h4>Instance: ${instance.id}</h4>
                                    <p><strong>Created:</strong> ${new Date(instance.created_at * 1000).toLocaleString()}</p>
                                    <p><strong>Expires:</strong> ${new Date(instance.expires_at * 1000).toLocaleString()}</p>
                                    <p><strong>Container ID:</strong> ${instance.container_id}</p>
                                    <button class="btn btn-danger" onclick="terminateInstance('${instance.id}')">Terminate</button>
                                </div>
                            `).join('');
                        }
                        
                        async function terminateInstance(instanceId) {
                            if (confirm('Are you sure you want to terminate this instance?')) {
                                await fetch(`/api/terminate?instance_id=${instanceId}`);
                                loadInstances();
                            }
                        }
                        
                        async function loadToken() {
                            const response = await fetch('/api/settings');
                            const settings = await response.json();
                            document.getElementById('currentToken').textContent = settings.access_token;
                        }
                        
                        async function regenerateToken() {
                            if (confirm('Are you sure you want to generate a new token? Existing MCP clients will need to update their configuration.')) {
                                const response = await fetch('/api/regenerate_token', { method: 'POST' });
                                const result = await response.json();
                                if (result.success) {
                                    document.getElementById('currentToken').textContent = result.new_token;
                                    alert('New token generated: ' + result.new_token);
                                }
                            }
                        }
                        
                        document.getElementById('passwordForm').addEventListener('submit', async (e) => {
                            e.preventDefault();
                            const formData = new FormData(e.target);
                            const response = await fetch('/api/change_password', {
                                method: 'POST',
                                headers: { 'Content-Type': 'application/json' },
                                body: JSON.stringify({
                                    current_password: formData.get('currentPassword'),
                                    new_password: formData.get('newPassword')
                                })
                            });
                            
                            if (response.ok) {
                                alert('Password changed successfully');
                                e.target.reset();
                            } else {
                                alert('Failed to change password');
                            }
                        });
                        
                        // Load initial data
                        loadInstances();
                        loadToken();
                        // Refresh instances every 30 seconds
                        setInterval(loadInstances, 30000);
                    </script>
                </body>
                </html>
                '''
                self._send_html(html)
            
            def _serve_instances_api(self):
                """Serve instances data as JSON"""
                instances = web_panel.mcp_server.instance_manager.get_all_instances()
                self._send_json([{
                    'id': instance_id,
                    'container_id': data['container'].id[:12],
                    'created_at': data['created_at'],
                    'expires_at': data['expires_at']
                } for instance_id, data in instances.items()])
            
            def _terminate_instance(self):
                """Terminate a specific instance"""
                query = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
                instance_id = query.get('instance_id', [None])[0]
                
                if instance_id:
                    success = web_panel.mcp_server.instance_manager._cleanup_instance(instance_id)
                    self._send_json({'success': success})
                else:
                    self._send_error(400, "Missing instance_id parameter")
            
            def _serve_settings_api(self):
                """Serve settings data"""
                self._send_json({
                    'access_token': web_panel.access_token,
                    'username': web_panel.username
                })
            
            def _handle_login(self):
                """Handle login request"""
                content_length = int(self.headers['Content-Length'])
                post_data = self.rfile.read(content_length)
                data = json.loads(post_data.decode())
                
                if (data.get('username') == web_panel.username and 
                    web_panel.verify_password(data.get('password', ''))):
                    self.send_response(200)
                    self.send_header('Set-Cookie', 'hackbox_auth=1; Path=/; HttpOnly')
                    self.end_headers()
                else:
                    self.send_response(401)
                    self.end_headers()
            
            def _change_password(self):
                """Handle password change"""
                content_length = int(self.headers['Content-Length'])
                post_data = self.rfile.read(content_length)
                data = json.loads(post_data.decode())
                
                success = web_panel.change_password(
                    data.get('current_password', ''),
                    data.get('new_password', '')
                )
                
                self._send_json({'success': success})
            
            def _regenerate_token(self):
                """Handle token regeneration"""
                new_token = web_panel.generate_new_token()
                self._send_json({
                    'success': True,
                    'new_token': new_token
                })
            
            def _serve_static(self, path):
                """Serve static files (minimal implementation)"""
                self._send_error(404, "Not Found")
            
            def _send_html(self, html):
                """Send HTML response"""
                self.send_response(200)
                self.send_header('Content-type', 'text/html')
                self.end_headers()
                self.wfile.write(html.encode())
            
            def _send_json(self, data):
                """Send JSON response"""
                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps(data).encode())
            
            def _send_error(self, code, message):
                """Send error response"""
                self.send_response(code)
                self.send_header('Content-type', 'text/plain')
                self.end_headers()
                self.wfile.write(message.encode())
            
            def log_message(self, format, *args):
                """Override to reduce log noise"""
                pass
        
        return WebPanelHandler


class KaliInstanceManager:
    """Manages temporary Kali Linux Docker instances"""
    
    def __init__(self, timeout_minutes: int = DEFAULT_TIMEOUT_MINUTES):
        self.client = docker.from_env()
        self.instances: Dict[str, Dict[str, Any]] = {}
        self.timeout_minutes = timeout_minutes
    
    def create_instance(self) -> str:
        """Create a new Kali Linux instance"""
        instance_id = str(uuid.uuid4())
        
        try:
            # Pull Kali Linux image if not exists
            try:
                self.client.images.get('kalilinux/kali-rolling')
            except docker.errors.ImageNotFound:
                print("Pulling Kali Linux image...")
                self.client.images.pull('kalilinux/kali-rolling')
            
            # Create container
            container = self.client.containers.run(
                'kalilinux/kali-rolling',
                command='/bin/bash -c "apt update && apt install -y python3 curl wget net-tools && tail -f /dev/null"',
                detach=True,
                tty=True,
                stdin_open=True,
                name=f'hackbox-{instance_id[:8]}',
                auto_remove=False
            )
            
            # Store instance data
            self.instances[instance_id] = {
                'container': container,
                'created_at': time.time(),
                'expires_at': time.time() + (self.timeout_minutes * 60),
                'last_used': time.time()
            }
            
            print(f"Created Kali instance {instance_id} (Container: {container.id[:12]})")
            return instance_id
            
        except Exception as e:
            print(f"Error creating Kali instance: {e}")
            raise
    
    def execute_command(self, instance_id: str, command: str) -> Dict[str, Any]:
        """Execute a command in a Kali instance"""
        if instance_id not in self.instances:
            return {
                'success': False,
                'error': f'Instance {instance_id} not found',
                'output': '',
                'exit_code': 1
            }
        
        instance = self.instances[instance_id]
        instance['last_used'] = time.time()
        
        try:
            # Execute command in container
            result = instance['container'].exec_run(
                f'/bin/bash -c "{command}"',
                workdir='/root'
            )
            
            output = result.output.decode('utf-8') if result.output else ''
            
            return {
                'success': result.exit_code == 0,
                'output': output,
                'exit_code': result.exit_code,
                'instance_id': instance_id
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'output': '',
                'exit_code': 1
            }
    
    def _cleanup_instance(self, instance_id: str) -> bool:
        """Clean up a specific instance"""
        if instance_id not in self.instances:
            return False
        
        instance = self.instances[instance_id]
        
        try:
            # Stop and remove container
            instance['container'].stop()
            instance['container'].remove()
            del self.instances[instance_id]
            print(f"Cleaned up instance {instance_id}")
            return True
            
        except Exception as e:
            print(f"Error cleaning up instance {instance_id}: {e}")
            return False
    
    def cleanup_expired_instances(self):
        """Clean up instances that have expired"""
        current_time = time.time()
        expired_instances = []
        
        for instance_id, instance_data in self.instances.items():
            if current_time > instance_data['expires_at']:
                expired_instances.append(instance_id)
        
        for instance_id in expired_instances:
            self._cleanup_instance(instance_id)
    
    def get_all_instances(self) -> Dict[str, Dict[str, Any]]:
        """Get all active instances"""
        return self.instances
    
    def cleanup_all_instances(self):
        """Clean up all instances"""
        for instance_id in list(self.instances.keys()):
            self._cleanup_instance(instance_id)


class HackBoxMCPServer:
    """Main MCP server class"""
    
    def __init__(self, timeout_minutes: int = DEFAULT_TIMEOUT_MINUTES, web_port: int = DEFAULT_WEB_PORT):
        self.mcp = FastMCP("HackBox MCP Server")
        self.instance_manager = KaliInstanceManager(timeout_minutes)
        self.web_panel = HackBoxWebPanel(self, web_port)
        
        # Register MCP tools
        self._register_tools()
        
        # Start web panel
        self.web_panel.start()
    
    def _register_tools(self):
        """Register MCP tools with authentication"""
        
        @self.mcp.tool(
            name="create_kali_instance",
            description="Create a new temporary Kali Linux instance"
        )
        def create_kali_instance(access_token: str) -> str:
            """Create a new Kali Linux instance"""
            if access_token != self.web_panel.access_token:
                raise ValueError("Invalid access token")
            
            return self.instance_manager.create_instance()
        
        @self.mcp.tool(
            name="execute_in_kali",
            description="Execute a command in a Kali Linux instance"
        )
        def execute_in_kali(instance_id: str, command: str, access_token: str) -> Dict[str, Any]:
            """Execute a command in a Kali instance"""
            if access_token != self.web_panel.access_token:
                raise ValueError("Invalid access token")
            
            return self.instance_manager.execute_command(instance_id, command)
        
        @self.mcp.tool(
            name="list_kali_instances",
            description="List all active Kali Linux instances"
        )
        def list_kali_instances(access_token: str) -> List[Dict[str, Any]]:
            """List all active instances"""
            if access_token != self.web_panel.access_token:
                raise ValueError("Invalid access token")
            
            instances = self.instance_manager.get_all_instances()
            return [{
                'instance_id': instance_id,
                'container_id': data['container'].id[:12],
                'created_at': datetime.fromtimestamp(data['created_at']).isoformat(),
                'expires_at': datetime.fromtimestamp(data['expires_at']).isoformat()
            } for instance_id, data in instances.items()]
        
        @self.mcp.tool(
            name="cleanup_kali_instance",
            description="Clean up a specific Kali Linux instance"
        )
        def cleanup_kali_instance(instance_id: str, access_token: str) -> bool:
            """Clean up a specific instance"""
            if access_token != self.web_panel.access_token:
                raise ValueError("Invalid access token")
            
            return self.instance_manager._cleanup_instance(instance_id)
        
        @self.mcp.tool(
            name="cleanup_all_instances",
            description="Clean up all Kali Linux instances"
        )
        def cleanup_all_instances(access_token: str) -> bool:
            """Clean up all instances"""
            if access_token != self.web_panel.access_token:
                raise ValueError("Invalid access token")
            
            self.instance_manager.cleanup_all_instances()
            return True
        
        @self.mcp.resource("hackbox://config")
        def get_hackbox_config() -> Dict[str, Any]:
            """Get server configuration"""
            return {
                "timeout_minutes": self.instance_manager.timeout_minutes,
                "web_panel_url": f"http://localhost:{self.web_panel.port}",
                "access_token": self.web_panel.access_token,
                "instructions": "Use the access_token parameter with all MCP tool calls"
            }
    
    async def periodic_cleanup(self):
        """Periodically clean up expired instances"""
        while True:
            await asyncio.sleep(60)  # Check every minute
            self.instance_manager.cleanup_expired_instances()
    
    def run(self):
        """Run the MCP server"""
        print("Starting HackBox MCP Server with Web Panel...")
        print(f"Web Panel: http://localhost:{self.web_panel.port}")
        print(f"Default username: {DEFAULT_WEB_USERNAME}")
        print(f"Default password: {DEFAULT_WEB_PASSWORD}")
        print(f"Access Token: {self.web_panel.access_token}")
        print("\nChange the default password immediately in the web panel!")
        
        # Start periodic cleanup task
        asyncio.create_task(self.periodic_cleanup())
        
        # Run MCP server
        self.mcp.run(transport="stdio")
    
    def stop(self):
        """Stop the server and clean up"""
        self.web_panel.stop()
        self.instance_manager.cleanup_all_instances()


if __name__ == "__main__":
    # Create and run server
    server = HackBoxMCPServer()
    
    try:
        server.run()
    except KeyboardInterrupt:
        print("\nShutting down HackBox MCP Server...")
        server.stop()
    except Exception as e:
        print(f"Error running server: {e}")
        server.stop()
