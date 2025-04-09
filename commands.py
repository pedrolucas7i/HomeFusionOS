import subprocess
from pathlib import Path
import socket


def run_command(command, password=None):
    """Executa um comando no terminal e retorna a saída."""
    if password:
        # Use echo e pipe para fornecer a senha ao sudo
        command = f"echo {password} | sudo -S {command}"
    process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = process.communicate()
    if process.returncode != 0:
        print(f"Erro ao executar comando: {stderr.decode().strip()}")
    return stdout.decode().strip()

def get_local_ip():
    try:
        # Conecta-se a um servidor externo (por exemplo, Google DNS) para obter o IP local
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
    except Exception as e:
        return f"Erro ao tentar obter o IP local: {e}"
    
    return ip

def create_directory(path):
    """
    Cria diretórios e subdiretórios especificados no caminho.
    
    Args:
        path (str): O caminho do diretório a ser criado.
    """
    directory = Path(path).expanduser()  # Expande ~ para o diretório home do usuário
    directory.mkdir(parents=True, exist_ok=True)
    print(f"Diretório criado: {directory}")