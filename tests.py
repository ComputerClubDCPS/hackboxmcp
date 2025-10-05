
import pytest
from unittest.mock import Mock, patch
from http.server import HTTPServer
from .hackbox_mcp_server import HackBoxWebPanel, KaliInstanceManager, HackBoxMCPServer

# Mock classes and functions that use external resources
@pytest.fixture
def mock_server():
    with patch.object(HTTPServer, 'serve_forever'), \
         patch.object(HackBoxWebPanel, 'start'), \
         patch.object(HackBoxWebPanel, 'stop'):
        yield

@pytest.fixture
def mock_kali_instance_manager():
    with patch.object(KaliInstanceManager, 'create_instance', return_value='mock_instance_id'), \
         patch.object(KaliInstanceManager, 'execute_command', return_value={'success': True}), \
         patch.object(KaliInstanceManager, '_cleanup_instance', return_value=True), \
         patch.object(KaliInstanceManager, 'get_all_instances', return_value={}):
        yield

@pytest.fixture
def web_panel(mock_server):
    return HackBoxWebPanel(Mock())

def test_hash_password():
    panel = HackBoxWebPanel(Mock())
    assert panel._hash_password("password") == panel._hash_password("password")

def test_verify_password_successful():
    panel = HackBoxWebPanel(Mock())
    assert panel.verify_password("admin123")

def test_verify_password_failed():
    panel = HackBoxWebPanel(Mock())
    assert not panel.verify_password("wrongpassword")

def test_change_password_successful(web_panel):
    assert web_panel.change_password("admin123", "newpassword")
    assert web_panel.verify_password("newpassword")

def test_change_password_failed(web_panel):
    assert not web_panel.change_password("wrongpassword", "newpassword")

def test_generate_new_token(web_panel):
    old_token = web_panel.access_token
    new_token = web_panel.generate_new_token()
    assert old_token != new_token
    assert web_panel.access_token == new_token

def test_create_instance(mock_kali_instance_manager):
    manager = KaliInstanceManager()
    instance_id = manager.create_instance()
    assert instance_id == 'mock_instance_id'

def test_execute_command_successful(mock_kali_instance_manager):
    manager = KaliInstanceManager()
    result = manager.execute_command('mock_instance_id', 'ls')
    assert result['success']

def test_execute_command_failed_invalid_instance(mock_kali_instance_manager):
    manager = KaliInstanceManager()
    result = manager.execute_command('invalid_instance_id', 'ls')
    assert not result['success']
    assert 'Instance invalid_instance_id not found' == result['error']

def test_cleanup_instance_successful(mock_kali_instance_manager):
    manager = KaliInstanceManager()
    result = manager._cleanup_instance('mock_instance_id')
    assert result

def test_cleanup_instance_failed_invalid_instance(mock_kali_instance_manager):
    manager = KaliInstanceManager()
    result = manager._cleanup_instance('invalid_instance_id')
    assert not result

def test_hackbox_mcp_server(mock_server, mock_kali_instance_manager):
    server = HackBoxMCPServer()
    assert server.web_panel.mcp_server == server assert isinstance(server.instance_manager, KaliInstanceManager)

def test_hackbox_mcp_server_running(mock_server, mock_kali_instance_manager):
    server = HackBoxMCPServer()
    assert server.web_panel.server is None
    server.web_panel.start()
    assert server.web_panel.thread is not None
