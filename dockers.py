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

def install_docker_linux(password):
    """Instala Docker em sistemas Linux."""
    passw = password
    print("Instalando Docker no Linux...")

    output = run_command("apt update -y", password=passw)
    print(output)
    output = run_command("apt install apt-transport-https ca-certificates curl software-properties-common -y", password=passw)
    print(output)
    output = run_command('curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo apt-key add -')
    print(output)
    output = run_command('add-apt-repository "deb [arch=amd64] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable"', password=passw)
    print(output)
    output = run_command('apt update -y', password=passw)
    print(output)
    output = run_command('apt-cache policy docker-ce')
    print(output)
    output = run_command('apt install docker-ce -y', password=passw)
    print(output)
    output = run_command('systemctl status docker', password=passw)
    print(output)
    output = run_command('usermod -aG docker ${USER}', password=passw)
    print(output)

def install_docker_windows():
    """Instala Docker no Windows usando winget."""
    print("Instalando Docker no Windows...")
    run_command("winget install -e --id Docker.DockerDesktop")

def start_docker_service_linux():
    """Inicia o serviço Docker em sistemas Linux."""
    print("Iniciando o serviço Docker no Linux...")
    run_command("sudo systemctl start docker")
    run_command("sudo systemctl enable docker")


def run_openwebui_container(password):
    print("Running the Open WebUI container...")
    open_webui_command = (
        "docker run -d --network=host -v open-webui:/app/backend/data -e OLLAMA_BASE_URL=http://127.0.0.1:11434 --name open-webui --restart always ghcr.io/open-webui/open-webui:main"
    )
    open_webui_output = run_command(open_webui_command, password=password)
    print(f"Open WebUI output: {open_webui_output}")


def start_ollama_container(password):
    print(run_command("docker start ollama", password=password))

def run_ollama_container(password):
    """Executes the Ollama and Open WebUI containers."""
    try:
        print("Running the Ollama container...")
        ollama_command = (
            "docker run -d -v ollama:/root/.ollama "
            "-e OLLAMA_HOST=0.0.0.0 "
            "-p 11434:11434 --name ollama ollama/ollama"
        )
        ollama_output = run_command(ollama_command, password=password)
        print(f"Ollama output: {ollama_output}")

        print("Ollama installation finished!")
    except Exception as e:
        print(f"Error occurred: {e}")

def run_pihole_container(password):
    """Executa o container Pi-hole."""
    print("Criando diretórios para o Pi-hole...")
    create_directory("~/docker/pihole/config")
    create_directory("~/docker/pihole/dnsmasq.d")
    print("Rodando o container Pi-hole...")
    command = (
        f"docker run -d "
        f"--name pihole "
        f"-p 8053:53/tcp "
        f"-p 8053:53/udp "
        f"-p 8090:80 "
        f"-p 8453:443 "
        f"-e TZ='America/New_York' "
        f"-e WEBPASSWORD='{password}' "
        f"-v ~/docker/pihole/config:/etc/pihole "
        f"-v ~/docker/pihole/dnsmasq.d:/etc/dnsmasq.d "
        f"--dns=127.0.0.1 "
        f"--dns=1.1.1.1 "
        f"--restart=unless-stopped "
        f"pihole/pihole"
    )
    run_command(command, password=password)