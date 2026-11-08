import re
from typing import Dict, List, Optional, Tuple, Union, Callable

READ_ONLY_PREFIXES = (
    "getprop",
    "settings get",
    "pm list",
    "pm path",
    "dumpsys",
    "ls ",
    "ls -",
    "cat ",
    "content query",
    "netstat",
    "ss ",
    "ps ",
    "ps -",
    "which ",
)

def is_mutating(cmd: str) -> bool:
    """
    Classificador rigoroso de comandos de shell Android.
    Retorna False para comandos estritamente de leitura;
    Retorna True para qualquer comando com potencial modificador.
    """
    stripped = cmd.strip()
    # Se houver comando composto ou encadeado (;, &&, ||), analisar cada subcomando
    # Mas comandos que apenas fazem pipe (|) para grep/sed/awk continuam na avaliação do comando base
    subcmds = re.split(r";|&&|\|\|", stripped)
    for sub in subcmds:
        s = sub.strip()
        if not s:
            continue
        # Se for pipe, extrair o comando principal à esquerda
        base = s.split("|")[0].strip()
        # Verificar se o comando base começa por um dos prefixos de leitura
        is_ro = any(base == ro or base.startswith(ro if ro.endswith(" ") else ro + " ") for ro in READ_ONLY_PREFIXES)
        if not is_ro:
            return True
    return False


class TransportError(Exception):
    """Exceção simulada de transporte ADB."""
    pass


class FakeTransport:
    """
    Transporte ADB simulado em memória para testes unitários e de integração.
    Permite registar comandos, simular saídas por padrão e injetar falhas de rede/reboot.
    """

    def __init__(self, host: str = "127.0.0.1", port: int = 5555):
        self.host = host
        self.port = port
        self.commands: List[str] = []
        self.pushed_files: List[Tuple[str, str]] = []
        self.pulled_files: List[Tuple[str, str]] = []
        self.connected: bool = True
        self.rebooted: bool = False
        
        # Mapeamento de respostas: lista de tuplos (critério, resposta, exit_code)
        # O critério pode ser string (prefixo/substring), regex ou função
        self._rules: List[Tuple[Union[str, re.Pattern, Callable[[str], bool]], str, int]] = []
        self.default_response: str = ""
        self.default_rc: int = 0
        self.fs: Dict[str, bytes] = {}  # Sistema de ficheiros simulado para pull/push

    def add_rule(self, matcher: Union[str, re.Pattern, Callable[[str], bool]], response: str, exit_code: int = 0):
        self._rules.append((matcher, response, exit_code))

    def set_specs(
        self,
        brand: str = "FakeBrand",
        model: str = "FakeModel",
        sdk: str = "34",
        version: str = "14",
        security_patch: str = "2026-05-05",
        fingerprint: str = "FakeBrand/FakeModel/fake:14/UKQ1/1:user/release-keys",
        serialno: str = "FAKESERIAL12345",
        tags: str = "release-keys",
    ):
        """Configura respostas padrão de propriedades de hardware para getprop."""
        self.add_rule("getprop ro.product.brand", brand)
        self.add_rule("getprop ro.product.model", model)
        self.add_rule("getprop ro.build.version.sdk", sdk)
        self.add_rule("getprop ro.build.version.release", version)
        self.add_rule("getprop ro.build.version.security_patch", security_patch)
        self.add_rule("getprop ro.build.fingerprint", fingerprint)
        self.add_rule("getprop ro.serialno", serialno)
        self.add_rule("getprop ro.build.tags", tags)
        self.add_rule("getprop sys.boot_completed", "1")

    def shell(self, cmd: str, read_timeout_s: int = 30) -> str:
        if not self.connected:
            raise TransportError(f"Connection refused to {self.host}:{self.port}")

        self.commands.append(cmd)

        has_rc_marker = "; echo __RC=$?" in cmd
        clean_cmd = cmd.replace("; echo __RC=$?", "").strip()

        matched_resp = self.default_response
        matched_rc = self.default_rc

        for matcher, resp, rc in self._rules:
            if callable(matcher):
                if matcher(clean_cmd):
                    matched_resp = resp
                    matched_rc = rc
                    break
            elif isinstance(matcher, re.Pattern):
                if matcher.search(clean_cmd):
                    matched_resp = resp
                    matched_rc = rc
                    break
            elif isinstance(matcher, str):
                if clean_cmd.startswith(matcher) or matcher in clean_cmd:
                    matched_resp = resp
                    matched_rc = rc
                    break

        if has_rc_marker:
            return f"{matched_resp}\n__RC={matched_rc}"
        return matched_resp

    def push(self, local_path: str, remote_path: str, **kwargs) -> bool:
        if not self.connected:
            raise TransportError("Not connected")
        self.pushed_files.append((local_path, remote_path))
        try:
            with open(local_path, "rb") as f:
                self.fs[remote_path] = f.read()
        except Exception:
            self.fs[remote_path] = b""
        return True

    def pull(self, remote_path: str, local_path: str, **kwargs) -> bool:
        if not self.connected:
            raise TransportError("Not connected")
        self.pulled_files.append((remote_path, local_path))
        if remote_path in self.fs:
            import os
            os.makedirs(os.path.dirname(os.path.abspath(local_path)), exist_ok=True)
            with open(local_path, "wb") as f:
                f.write(self.fs[remote_path])
            return True
        return False
