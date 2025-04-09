import utils



def install_ollama(password):
    """Executes the Ollama and Open WebUI containers."""
    try:
        print("Running the Ollama installer...")
        ollama_commands = [
            "apt update",
            "curl -L https://ollama.com/download/ollama-linux-amd64 -o /usr/bin/ollama",
            "chmod +x /usr/bin/ollama",
            "useradd -r -s /bin/false -m -d /usr/share/ollama ollama"
        ]

        for cmd in ollama_commands:
            output = utils.run_command(cmd, password=password)
            print(output)

        ollama_command = """bash -c 'cat <<'EOF' >> /etc/systemd/system/ollama.service
            [Unit]
            Description=Ollama Service
            After=network-online.target

            [Service]
            ExecStart=/usr/bin/ollama serve
            User=ollama
            Group=ollama
            Restart=always
            RestartSec=3
            #Environment="OLLAMA_HOST=0.0.0.0:11434"

            [Install]
            WantedBy=default.target

            EOF'"""

        ollama_output = utils.run_command(ollama_command, password=password)
        print(ollama_output)
        
        systemctl_commands = [
            "systemctl daemon-reload",
            "systemctl enable ollama",
            "systemctl start ollama"
        ]

        for cmd in systemctl_commands:
            output = utils.run_command(cmd, password=password)
            print(output)

        print("Ollama installed!!!")


        """
        print("Running the Open WebUI installer...")

        open_webui_commands = [
            "apt update",
            "apt install npm python3-pip python3-venv git -y",
            "git clone https://github.com/open-webui/open-webui.git"
        ]

        for cmd in open_webui_commands:
            output = utils.run_command(cmd, password=password)
            print(output)

        open_webui_commands = [
            "cd open-webui && cp -RPp .env.example .env",
            "cd open-webui && npm i && npm run build",
            "cd open-webui/backend && python3 -m venv venv && source venv/bin/activate",
            "cd open-webui/backend && pip install -r requirements.txt -U",
            "cd open-webui/backend && bash start.sh"
        ]

        for cmd in open_webui_commands:
            output = utils.run_command(cmd, password=password)
            print(output)

        print("Ollama and Open WebUI installation finished!")
        """
        
    except Exception as e:
        print(f"Error occurred: {e}")
