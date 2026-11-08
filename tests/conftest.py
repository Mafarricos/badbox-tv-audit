import os
import sys
import pytest

# Assegurar que a raiz e a pasta tools/ estão no sys.path
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TOOLS_DIR = os.path.join(PROJECT_ROOT, "tools")
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)
if TOOLS_DIR not in sys.path:
    sys.path.insert(0, TOOLS_DIR)

# Definir TV_HOST falso para que tv.py consiga ser importado sem sys.exit
os.environ.setdefault("TV_HOST", "127.0.0.1")

from tests.fakes import FakeTransport

@pytest.fixture(autouse=True)
def prevent_real_network_connections(monkeypatch):
    """
    Regra Inviolável 1: Nenhum dispositivo real, nenhuma rede real.
    Garante que qualquer tentativa de ligar sockets reais via tv.connect falha imediatamente
    se não tiver sido configurado um FakeTransport.
    """
    import socket
    real_socket_connect = socket.socket.connect

    def guarded_connect(self, address):
        host, port = address[0], address[1]
        # Permitir apenas conexões loopback locais para testes controlados se necessário
        if host not in ("127.0.0.1", "localhost", "::1"):
            raise RuntimeError(f"REGRA 1 VIOLADA: Tentativa de ligar socket de rede real a {host}:{port} bloqueada nos testes!")
        return real_socket_connect(self, address)

    monkeypatch.setattr(socket.socket, "connect", guarded_connect)

@pytest.fixture(autouse=True)
def fast_sleep(monkeypatch):
    """Acelera a execução dos testes eliminando pausas reais de time.sleep."""
    import time
    monkeypatch.setattr(time, "sleep", lambda s: None)
