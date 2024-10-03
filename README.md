# Dedicated-Server-Project
### **PROJECT GOAL**

To create a secure dedicated server capable of hosting a web application and a database. 

### **PROJECT OVERVIEW**

With the rising costs of web hosting and cloud services, I decided to build my own dedicated server to host my database and deploy my software engineering portfolio.  By setting up my own server, I have complete control over my own data and communication infrastructure, I can reduce costs, and I can easily scale my current server to host future projects.



### **TOOLS & TECHNOLOGIES**

**Operating System** 

- Linux Mint

**Server**  

- Apache2 - server for hosting web applications & databases

**Database**

- PostgreSQL - for relational database

**Security**

- Wireguard VPN for secure connections to the VPS
- UFW - uncomplicated firewall
- Fail2Ban for brute-force attacks
- ModSecurity - for web application firewall (WAF), request filtering and access control, real-time traffic monitoring, and attack detection and prevention

**Cloudflare**

- DNS
- DDNS
- DDOS
- SSL
- WAF

**OpenSSH**

- SSH

**Services**

- Web Hosting - Serving static and dynamic web content
- Database - PostgreSQL Relational Database Management

## INSTALLATION, INSTRUCTIONS, & SETUP

---

### OPERATING SYSTEM SETUP

Install a Linux Distribution like Linux Mint or Ubuntu on the server machine.

### PORT FORWARDING

Forward ports 80 and 443 on your modem

### **CLOUDFLARE DNS, DDNS, DDOS, WAF FIREWALL RULES. SSL CERTIFICATE**

**CONFIGURE CLOUDFLARE DNS**

1. Create a cloudflare account and select the Free plan (paid if you prefer)
2. Log into your domain name registrar and update your nameservers to —`alice.ns.cloudflare.com` and `bob.ns.cloudflare.com`
3. Allow 24 hours for DNS Propagation
4. Go to DNS in your Cloudflare Dashboard
5. Add the following DNS 
    
    
    | Type | Name | Content (IP Address or Host) | TTL | Proxy Status |
    | --- | --- | --- | --- | --- |
    | A | @ | <Your_Server_IP> | Auto | Proxied |
    | CNAME | www | <Your_Domain_Name> | Auto | Proxied |

**CONFIGURE DYNAMIC DNS (DDNS) FOR CLOUDFLARE**

1. Create a Cloudflare API Token
    1. Go to My Profile / API Tokens
    2. Create a token
    3. Set permissions to Zone:DNS:Edit then restrict to your_domain
    4. Generate the Token and Save it in a secure location
2. Install a DDNS client (example: ddclient)
    1. `sudo apt install ddclient -y`
3. Configure ddclient
    1. `sudo nano /etc/ddclient.conf`
4. Add the following to the ddclient.conf file

```bash
protocol=cloudflare
use=web, web=dynamic
server=api.cloudflare.com/client/v4
ssl=yes
login=<YOUR_CLOUDFLARE_EMAIL>
password=<CLOUDFLARE_API_TOKEN>
zone=<your_domain>
```

1. Save the File and start ddclient
    1. `sudo systemctl start ddclient`

**CLOUDFLARE DDOS PROTECTION**
— Cloudflare’s free plan automatically enables DDOS protection

**CLOUDFLARE WAF FIREWALL RULES**

1. Go to Security and click on WAF
2. Create a Custom Rule
3. Rule Examples:
    1. Block Known Bad IPs Using Threat Scores
    2. Block SQL Injection Attempts
    3. Block Cross-Site Scripting
    4. Block Directory Traversal Attempts

**CLOUDFLARE SSL CERTIFICATE**

1. Go to SSL/TLS
2. Set SSL mode to Full(Strict)
3. Generate a Cloudflare Origin SSL Certificate
    1. Go to Origin Server and Create Certificate
    2. Copy certificate and private key values
4. Save the origin server certificate and private key on your server
    1. `sudo nano /etc/ss/certs/cloudflare-origin.crt`
    2. `sudo nano /etc/ssl/private/cloudflare-origin.key`
5. Configure Apache to Use Cloudflare’s SSL
    1. Modify your_domain.conf file for HTTPS (See WEB SERVER INSTALLATION & CONFIGURATION)
    
    ```bash
    <VirtualHost *:443>
        ServerName your_domain.com
        ServerAlias www.your_domain.com
        DocumentRoot /var/www/your_domain
        SSLEngine on
        SSLCertificateFile /etc/ssl/certs/cloudflare-origin.crt
        SSLCertificateKeyFile /etc/ssl/private/cloudflare-origin.key
    </VirtualHost>
    
    ```
    
6. Enable SSL and Headers Modules and Restart Apache
    1. `sudo a2enmod ssl`
    2. `sudo a2enmod headers`
    3. `sudo systemctl restart apache2`
### WEB SERVER INSTALLATION & CONFIGURATION

Install latest version of the Apache2 Web Server.

**COMMON APACHE SERVER COMMANDS**

| Command | Starting, Stopping, and Restarting Apache |
| --- | --- |
| sudo systemctl start apache2 | Start Apache2 Service |
| sudo systemctl stop apache2 | Stop Apache2 Service |
| sudo systemctl restart apache2 | Restart Apache2 Service |
| sudo systemctl enable apache2 | Enable Apache2 to start on boot |
| sudo systemctl disable apache2 | Disable Apache2 from starting on boot |
| sudo systemctl status apache2 | Check the status of the Apache2 service |
| Command | Checking Apache Configuration |
| sudo apachectl configtest | Test Apache2 for syntax errors |
| sudo apache2ctl -S | Check enabled virtual hosts |
| Command | Managing Apache Modules |
| sudo a2enmod <module> | Enable a module |
| sudo a2dismod <module> | Disable a module |
| sudo a2enmod -f | Enable all available modules |
| sudo a2dismod -f | Disable all available modules |
| Command | Managing Apache Sites |
| sudo a2ensite mysite.conf  | Enable a site configuration |
| sudo a2dissite mysite.conf | Disable a site configuration |
| sudo ls /etc/apache2/sites-enabled | List enabled sites |
| sudo ls /etc/apache2/sites-available | List available sites |
| Command | Log Management and Troubleshooting |
| sudo tail -f /var/log/apache2/access.log | View the Apache2 access log |
| sudo tail -f /var/log/apache2/error.log | View the Apache2 error log |
| sudo tail -n 20 /var/log/apache2/error.log | View the last 20 lines of the error log |

**SETTING UP A NEW VIRTUAL HOST CONFIGURATION FILE**

— default apache virtual host file called 000-dafult.conf 

1. Create a new virtual host config file
    
    *sudo nano /etc/apache2/sites-available/<your_domain>.conf*
    
2. Configure the virtual host file
    
    ```bash
    <VirtualHost *:80>
        ServerAdmin webmaster@<your_domain>
        ServerName <your_domain>
        ServerAlias www.<your_domain>
        DocumentRoot /var/www/<your_domain>
        
        # Error log file
        ErrorLog ${APACHE_LOG_DIR}/<your_domain>-error.log
        
        # Custom access log file
        CustomLog ${APACHE_LOG_DIR}/<your_domain>-access.log combined
    
        # Optional: Directory settings
        <Directory /var/www/<your_domain>>
            Options Indexes FollowSymLinks MultiViews
            AllowOverride All
            Require all granted
        </Directory>
    </VirtualHost>
    
    <VirtualHost *:443>
        ServerName your_domain.com
        ServerAlias www.your_domain.com
        DocumentRoot /var/www/your_domain
        SSLEngine on
        SSLCertificateFile /etc/ssl/certs/cloudflare-origin.crt
        SSLCertificateKeyFile /etc/ssl/private/cloudflare-origin.key
    </VirtualHost>
    ```
    
3. Create the root directory where you will store your website files
    
    `sudo mkdir -p /var/www/<your_domain>`
    
4. Set ownership and permissions so that the Apache2 server can access the files
    
    `sudo chown -R $USER:$USER /var/www/<your_domain>`
    `sudo chmod -R 755 /var/www/<your_domain>`
    
5. Enable the new virtual host file
    
    `sudo a2ensite <your_domain>.conf`
    
6. Check Apache for syntax errors
    
    `sudo apachectl configtest`
    
7. Restart Apache to apply changes
    
    `sudo systemctl restart apache2`
    
8. Check Apache Server Status & navigate to your domain
    
    `sudo systemctl status apache2`
    
    http://your_domain.com
    

### SETTING UP UFW (UNCOMPLICATED FIREWALL)

1. Install ufw
    1. `sudo apt install ufw -y`
2. Check ufw status
    1. `sudo ufw status`
3. If Status: inactive
    1. `sudo ufw enable`
    2. `sudo ufw status`
4. Allow Essential Ports (List not complete)
    1. `sudo ufw allow ssh`
    2. `sudo ufw allow ‘Apache Full’`
    3. `sudo ufw allow 80/tcp`
    4. `sudo ufw allow 443/tcp`
    5. `sudo ufw allow 51820/udp`
    6. `sudo ufw allow http`
    7. `sudo ufw allow https`
5. Enable Logging 
    1. `sudo ufw logging on`
    2. `sudo ufw logging high`
6. Manage ufw Rules
    1. `sudo ufw status numbered`
    2. `sudo ufw delete 1` (or rule number)

### SETTING UP FAIL2BAN FOR BRUTE FORCE ATTACKS

1. Install Fail2Ban
    1. `sudo apt install fail2ban -y`
2. Start and enable Fail2Ban
    1. `sudo systemctl start fail2ban`
    2. `sudo systemctl enable fail2ban`
    3. `sudo systemctl status fail2ban`
    4. `sudo fail2ban-client status`
3. Configure the Fail2Ban jail.local file
    1. Do not modify jail.conf directly, instead create a local override configuration file called jail.local
    2. Create the jail.local file
        1. `sudo cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local`
    3. Open the file
        1. `sudo nano /etc/fail2ban/jail.local`
    4. Enter Configuration and Save File
        
        ```bash
          GNU nano 7.2                            jail.local                                     
        [DEFAULT]
        
        #IPs that are exempt from banning
        ignoreip = 73.67.255.236
        
        #Set ban time (1hr)
        bantime = 1h
        
        #Set the time period during which the failed login attempts are counted
        findtime = 10m
        
        #Set the maximum number of failed attempts allowed
        maxretry = 3
        
        #Logging Settings
        loglevel = INFO
        
        #Ban action (using iptables)
        banaction = iptables-multiport
        
        #Enable Recidive jail for persistent offenders
        [recidive]
        enabled = true
        logpath = /var/log/fail2ban.log
        bantime = 2w
        findtime = 1d
        maxretry = 5
        
        #Configure SSH protection
        [sshd]
        enabled = true
        port = ssh
        filter = sshd
        logpath = /var/log/auth.log
        maxretry = 3
        findtime = 10m
        bantime = 1h
        action = %(action_mwl)s
        
        #Configure Apache Protection 
        [apache-auth]
        enabled = true
        port = http,https
        filter = apache-auth
        logpath = /usr/local/apache2/logs/error.log
        maxretry = 5
        findtime = 10m
        bantime = 1h
        
        #Configure Wireguard Protection
        [wireguard]
        enabled = true
        port = 51820
        protocol = udp
        filter = wireguard
        logpath = /var/log/syslog
        maxretry = 5
        findtime = 10m
        bantime = 1h
        
        ```
        
4. Restart and enable fail2ban-client
    1. `sudo systemctl restart fail2ban`
    2. `sudo systemctl status fail2ban`
    3. `sudo fail2ban-client status`

### SETTING UP WIREGUARD VPN

1. Install Wireguard VPN
    1. `sudo apt install wireguard`
2. Generate Server Keys
    1. `umask`
    2. `wg genkey | tee server_private.key | wg pubkey > server_public.key`
3. Create Wireguard configuration file
    1. `sudo nano /etc/wireguard/wg0.conf`
    
    ```jsx
    [Interface]
    Address = 10.0.0.1/24  # Server VPN IP address
    ListenPort = 51820      # Listening port
    PrivateKey = <server_private_key>  # Replace with the content of server_private.key
    
    [Peer]
    PublicKey = <client_public_key>  # Replace with client's public key
    AllowedIPs = 10.0.0.2/32         # Client VPN IP address
    
    ```
    
4. Enable IP Forwarding
    1. `echo "net.ipv4.ip_forward = 1" | sudo tee -a /etc/sysctl.conf`
    2. `sudo sysctl -p`
5. Start Wireguard
    1. `sudo wg-quick up wg0`
6. Enable Wireguard to start on boot
    1. `sudo systemctl enable wg-quick@wg0`
7. Configure the Wireguard client
    1. `umask 077`
    2. `wg genkey | tee client_private.key | wg pubkey > client_public.key`
8. Create Wireguard client configuration file
    1. `sudo nano ~/wg-client.conf`

```jsx
[Interface]
Address = 10.0.0.2/24       # Client VPN IP address
PrivateKey = <client_private_key>  # Replace with the content of client_private.key

[Peer]
PublicKey = <server_public_key>  # Replace with the server's public key
Endpoint = <server_ip>:51820      # Replace <server_ip> with your server's public IP
AllowedIPs = 0.0.0.0/0            # Route all traffic through VPN

```

1. Restart Wireguard Server
    1. `sudo wg-quick down wg0`
    2. `sudo wg-quick up wg0`
2. Starting the Wireguard Client
    1. `sudo wg-quick up ~/wg-client.conf`
3. Check Wireguard Status
    1. `sudo wg OR sudo systemctl status wireguard`
4. Configure ufw and iptables to allow PORT 51820/udp
    1. `sudo ufw allow 51820/udp`
    2. `sudo iptables -A INPUT -p udp --dport 51820 -j ACCEPT`

### SETTING UP MODSECURITY & MODSECURITY CORE RULE SET

1. Install ModSecurity
    1. `sudo apt install libapache2-mod-security2`
2. Enable ModSecurity
    1. `sudo a2enmod security2`
3. Configure ModSecurity
    1. `sudo nano /etc/modsecurity/modsecurity.conf`
    2. Set `SecRuleEngine On`
    3. Adjust other settings as necessary
    4. Save and Exit
4. Install the OWASP ModSecurity Core Rule Set(CRS)
    1. `sudo git clone https://github.com/coreruleset/coreruleset.git /etc/modsecurity/owasp-crs`
5. Change to the CRS directory to copy crs example file
    1. `cd /etc/modsecurity/owasp-crs`
    2. `sudo cp crs-setup.conf.example crs-setup.conf`
6.  Include the CRS in the ModSecurity Configuration
    1. `sudo nano /etc/modsecurity/modsecurity.conf`
    2. Add the following lines to the end of modsecurity.conf
        1. `Include /etc/modsecurity/owasp-crs/crs-setup.conf`
        2. `Include /etc/modsecurity/owasp-crs/rules/*.conf`
7. Restart Apache
    1. `sudo systemctl restart apache2`
8. Verify ModSecurity Installation
    1. `sudo tail -f /var/log/apache2/error.log` 
9. Install ModSecurity Core Rule Set
    1. `sudo git clone https://github.com/coreruleset/coreruleset.git /etc/modsecurity/owasp-crs`
10. Copy crs-setup.conf.example to crs-setup.conf
    1. `sudo cp crs-setup.conf.example crs-setup.conf`
11. Include the CRS in ModSecurity Configuration
    1. Add the following to modsecurity.conf
        1. `Include /etc/modsecurity/owasp-crs/crs-setup.conf`
        2. `Include /etc/modsecurity/owasp-crs/rules/*.conf`
12. Restart Apache
    1. `sudo systemctl restart apache2`
    2. `sudo systemctl status apache2`
13. Check security logs to make sure ModSecurity loads correctly
    1. `sudo tail -f /var/log/apache2/error.log`  
14. Monitor Logs
    1. `sudo tail -f /var/log/modsecurity/audit.log`
15. Run a test
    1. Create a test rule file 
        1. `sudo nano /etc/modsecurity/modsecurity-test.conf`
    2. Add a new rule
        1. `SecRule REQUEST_URI "@streq /test" "id:1001,phase:1,log,deny,status:403"`
    3. Include the test configuration in modsecurity.conf
        1. `Include /etc/modsecurity/modsecurity-test.conf`
16. Restart Apache
    1. `sudo systemctl restart apache2`
    2. `sudo systemctl status apache2`
17. To test your configuration go to: http://<your_server>/test

### SETTING UP SSH

1. Install OpenSSH
    1. `sudo apt install openssh-server -y`
2. Start and Enable SSH Service
    1. `sudo systemctl start ssh`
    2. `sudo systemctl enable ssh`
3. Check SSH status
    1. `sudo systemctl status ssh`
4. Configure SSH Settings
    1. Open SSH config file
        1. `sudo nano /etc/ssh/sshd_config`
    2. Modify or add the following
        1. `Port 22`
        2. `PermitRootLogin no`
        3. `AllowUsers <your_username>`
        4. `PasswordAuthentication no`
    3. Restart SSH
        1. `sudo systemctl restart ssh`
    4. Open SSH Port for UFW
        1. `sudo ufw allow 2222/tcp`
    5. Test Connection
        1. `ssh username@server-ip-address`

### SETTING UP DOCKER FOR WIREGUARD VPN

**COMMON DOCKER COMMANDS**

| Command | Docker Version, Info, Logs, and Help |
| --- | --- |
| docker --version | Check Docker version |
| docker info | Display System Wide Information |
| docker --help | List all Docker Commands |
| docker logs [OPTIONS] CONTAINER | Fetches Docker Logs |
| docker inspect [OPTIONS] CONTAINER | Displays Detailed Info About a Container |
| docker attach [OPTIONS] CONTAINER | Attach’s to a running container’s console |
| Command | Container Management Commands |
| docker ps | List Running Containers |
| docker ps -a | List All Containers - Running or Stopped |
| docker start <container_name_or_id> | Start a Container |
| docker stop <container_name_or_id> | Stop a Container |
| docker restart <container_name_or_id> | Restart a Container |
| docker rm <container_name_or_id> | Remove a Container |
| docker buildx build -t <image_name> . | Build Docker Image |
| docker run -d --name <container_name> -p 51820:51820/udp <image_name> | Create and Run Docker Container |
| Command | Docker Images |
| docker images | List all Docker Images |
| docker rmi <image_id> | Delete Docker Image |
| docker image prune | Remove All Unused Images |
| docker system prune -a | Remove All Unused Images, Containers, Volumes, and Networks |
1. Install Docker
    1. `sudo apt -y docker.io`
2. Start and Enable Docker
    1. `sudo systemctl start docker`
    2. `sudo systemctl enable docker`
3. Create a Dockerfile

```bash
# Base Image
FROM debian:latest

# Install WireGuard and necessary dependencies
RUN apt-get update && \
    apt-get install -y wireguard iproute2 qrencode iptables && \
    apt-get clean

# Expose WireGuard's default port (UDP 51820)
EXPOSE 51820/udp

# Copy entrypoint script to container
COPY entrypoint.sh /usr/local/bin/

# Make the script executable
RUN chmod +x /usr/local/bin/entrypoint.sh

# Set entrypoint to the script, runs WireGuard in foreground
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
```

1. Create an [entrypoint.sh](http://entrypoint.sh) file

```bash
#!/bin/bash

# Enable IP forwarding
sysctl -w net.ipv4.ip_forward=1
sysctl -w net.ipv6.conf.all.forwarding=1

# Start WireGuard
wg-quick up wg0-server

# Keep the container running
tail -f /dev/null

# Keep the container running
exec "$@"
```

1. Make sure [entrypoint.sh](http://entrypoint.sh) has executable permissions
    1. `chmod +x [entrypoint.sh](http://entrypoint.sh/)`
2. Create a Build 
    1. `sudo docker buildx build -t test-image`
3. Create and Run Docker Image
    1. `sudo docker run -d -- name <container_name> -p PORT:PORT <image_name>`
4. Start Container
    1. `sudo docker start <container_name>`

### SETTING UP POSTGRESQL FOR APACHE SERVER

1. Install PostgreSQL
    1. `sudo apt-get install postgresql postgresql-contrib`
2. Start and enable PostgreSQL
    1.  `systemctl start postgresql`
    2. `sudo systemctl enable postgresql`


