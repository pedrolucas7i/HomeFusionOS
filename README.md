# HomeFusionOS

**HomeFusionOS** is an open-source, web-based system designed to manage and monitor Docker containers, file storage, user access, and system resources. It’s being developed as a comprehensive operating system for home server setups, offering an easy-to-use interface to control and manage various services and applications.

![HomefusionOS Dashboard](screenshots/dashboard.png)

---

## Features

- **User Authentication**: Secure login and account management for multiple users.
- **Docker Management**: Easily install and manage Docker applications.
- **File Management**: Upload, organize, and manage your files and folders.
- **System Monitoring**: View real-time statistics on CPU, RAM, and network usage.
- **Access to Command Shell**: Real-time terminal access for advanced operations.
- **Good Interface**: A clean and user-friendly dashboard.

---

## Supported Apps

### **Storage**
- **Nextcloud**  
  Personal cloud platform for file sync and sharing.  
  Docker Image: `nextcloud`  
  Port: 8003

### **Network**
- **Pi-hole**  
  Network-wide ad blocker.  
  Docker Image: `pihole/pihole`  
  Port: 8006

### **Media**
- **Jellyfin**  
  Open-source media server for streaming movies, TV shows, and music.  
  Docker Image: `jellyfin/jellyfin`  
  Port: 8022

### **Automation**
- **Home Assistant**  
  Home automation platform for managing smart devices.  
  Docker Image: `ghcr.io/home-assistant/home-assistant:stable`  
  Port: 8123

### **Development**
- **code-server**  
  Visual Studio Code in the browser for remote development.  
  Docker Image: `linuxserver/code-server`  
  Port: 8011
- **Gitea**  
  Self-hosted Git service for managing code repositories.  
  Docker Image: `gitea/gitea`  
  Port: 8012

### **Utilities**
- **Calibre Web**  
  Web-based ebook management and reading interface.  
  Docker Image: `linuxserver/calibre-web`  
  Port: 8018

### **Browsers**
- **Firefox**  
  Mozilla Firefox browser running in a container.  
  Docker Image: `jlesage/firefox`  
  Port: 8020
- **Tor Browser**  
  Anonymous browsing with Tor.  
  Docker Image: `domistyle/tor-browser`  
  Port: 5800

### **CMS**
- **WordPress**  
  Content management system for creating websites and blogs.  
  Docker Image: `wordpress`  
  Port: 8023

---

## Future Vision

HomeFusionOS aims to evolve into a fully-featured operating system for building and managing home servers. It will provide users with a seamless experience for running a wide variety of services by networks. The goal is to offer easy setup and management for different applications, whether for file sharing, media streaming, automation, development, or more, with a clean design, making it the ideal platform for home server enthusiasts.

---

## Installation

1. Clone the repository:
    ```bash
    git clone https://github.com/pedrolucas7i/HomeFusionOS.git
    cd HomeFusionOS
    ```

2. Install dependencies:
    ```bash
    pip install -r requirements.txt
    ```

3. Set up environment variables in a `.env` file:
    ```
    SECRET_KEY=<your-secret-key>
    HOST_DB=<your-database-host>
    USER_DB=<your-database-username>
    PASS_DB=<your-database-password>
    DB=<your-database-name>
    ```

4. Start the app:
    ```bash
    python main.py
    ```

5. Access the app at `http://localhost:9900`.

---

## License

MIT License - see the [LICENSE](LICENSE) file for details.

---

## Contributors

- **Pedro Lucas** ([pedrolucas7i](https://github.com/pedrolucas7i))

---

With ❤️, **HomeFusionOS** is your future-proof solution for home server management. Whether you're managing storage, media, or development tools, HomeFusionOS has got your back!
