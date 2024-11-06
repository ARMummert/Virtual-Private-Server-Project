This report is an overview of my virtual private server project including, technologies used, security best practices, challenges faced, and lessons learned.  My primary goal for this project was to create a secure virtual private server capable of hosting a web application and a database. 

### **PROJECT GOALS**

1. Create a scalable but stable server environment.
2. Create a robust set of security features to prevent vulnerabilities and attacks.
3. To create a dedicated server to host my web applications and databases.
4. To optimize server performance.

### **PROJECT OVERVIEW**

With the rising costs of web hosting and cloud services, I decided to build my own virtual private server to host my database and deploy my software engineering portfolio and postgreSQL database.  By setting up my own server, I have complete control over my own data and communication infrastructure, I can reduce costs, and I can easily scale my current server to host future projects.  I worked independently on this project for continued learning in server administration.

![Virtual Private Server Flow](https://raw.githubusercontent.com/ARMummert/Dedicated-Server-Project/refs/heads/main/Dedicated-Server.png)

### **PROJECT DEVELOPMENT TIME FRAME**

September 1, 2024 to December 1, 2024 (projected done date)

### **TOOLS & TECHNOLOGIES**

**Operating System** 

- Linux Mint

**Server**  

- Apache2 server for hosting web applications & databases

**Database**

- PostgreSQL for relational database
- PgAdmin for managing postgresql databases

**Security**

- Wireguard VPN for secure connections to the server
- UFW - uncomplicated firewall
- Fail2Ban for brute-force attacks
- ModSecurity for web application firewall (WAF), request filtering and access control, real-time traffic monitoring, and attack detection and prevention
- Cowrie for SSH honeypot
- Snort3 for IPS/IDS (changing to suricata soon)
- Wazuh for unified XDR and SIEM capabilities

**Cloudflare**

- DNS
- DDNS
- DDOS
- SSL
- WAF

**OpenSSH**

- SSH

**Containerization**

- Docker

**Server Performance & Optimization**

- Cloudflare for compression and caching

**Backup & Recovery**

- Bacula for backup and recovery

Password Manager

- BitWarden for storing passwords securely

**Services**

- Web Hosting - Serving static and dynamic web content
- Database - PostgreSQL Relational Database Management

## WHAT I LEARNED

Creating a virtual private server environment was a challenging but rewarding project.  I began this project with the goal of building a secure, reliable, and robust virtual private server to host my webpage and my PostgreSQL database.  The project started with researching server administration, networking, and security best practices.  During this time, I gained continued learning experiences with building an Apache server, setting up a Docker container, setting up a PostgreSQL database, and how to implement security measures.

### SECURITY BEST PRACTICES

To ensure that my server remains secure, I implemented a robust combination of security measures.  I felt this was an essential step to protect my server from attacks and vulnerabilities.  

**NETWORK SECURITY**

For network security I created strict firewall rules for both incoming and outgoing traffic allowing only necessary connections.  I also setup an SSL certificate, DDoS protection, DDNS, and WAF firewall rules through Cloudflare.  These tools offered me the opportunity to enhance my servers security while also protecting any sensitive data.  

**I used the following tools:**

1. Fail2Ban to actively monitor login attempts and blocked IP addresses minimizing the risk of brute-force attacks
2. ModSecurity to have a server-side web application firewall to prevent attacks such as, SQL Injection and cross-site scripting.
3. Wireguard VPN to provide a secure tunnel between the server and any client devices
4. UFW (uncomplicated firewall) to allow or deny ports
5. Snort for intrusion detection system (IPS/IDS)

By utilizing these tools I was able to create a robust and secure server environment.

**MULTI-FACTOR AUTHENTICATION**

I utilized Google Authenticator to enable 2FA for my secure shell (ssh) setup. 

**PASSWORD BEST PRACTICES**

1. MFA
2. Bitwarden for password management
3. Passwords set at 16 characters
4. Complexity using special characters

**PROBLEM SOLVING & TROUBLESHOOTING**

My approach to problem solving involves exploring various sources so I can gain a general understanding of a piece of software or a program, including documentation and tutorials.  As a developer, I prioritized learning about all of the services I have worked with on this project.  

**Network Connectivity Issues** - I encountered a double NAT situation while port forwarding.  To resolve this I placed my modem in to bridge mode and port forwarded my router instead.  This allowed me to eliminate the double NAT situation and establish a successful connection to my server.

To troubleshoot issues in regards to my apache server, I carefully read through the logs, config files, and system metrics.  I isolated the issue, consulted documentation, and researched online to find a solution.

### PERFORMANCE & OPTIMIZATION

While building the server utilized Cloudflare’s Cache Rules and Caching Configuration to store copies of large or frequently accessed data and their compression configuration to reduce data size without losing quality.

### SCALABILITY

The server’s capability of scaling was an important part of my project.  I implemented vertical scaling by adding more RAM and utilizing an SSD for improved performance.  

### **CONCLUSION**

Successful creation of a virtual private server reflects my understanding of server technologies and security practices.  By utilizing tools such as Apache, Docker, Wireguard VPN, ModSecurity, Fail2Ban, UFW, Snort3, and Wazuh along side Cloudflare for DNS management, caching and compression, the project delivers a scalable, secure, and performance optimized server environment.  The deployment of SSH, SSL, and advanced firewall rules enable to the server to remain secure and keep data private.  This project not only meets its goals but shows my abilities to design and implement complex server architectures.

## INSTALLATION, INSTRUCTIONS, & SETUP

---

### OPERATING SYSTEM SETUP

Install a Linux Distribution like Linux Mint or Ubuntu on the server machine.

### PORT FORWARDING

Forward ports 80 and 443 on your router / modem

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
    Address = 10.0.0.1/24  
    ListenPort = 51820     
    PrivateKey = <server_private_key>  
    
    [Peer]
    PublicKey = <client_public_key>  
    AllowedIPs = 10.0.0.2/32         
    
    ```
4. Start Wireguard
    1. `sudo wg-quick up wg0`
5. Enable Wireguard to start on boot
    1. `sudo systemctl enable wg-quick@wg0`
6. Configure the Wireguard client
    1. `umask 077`
    2. `wg genkey | tee client_private.key | wg pubkey > client_public.key`
7. Create Wireguard client configuration file
    1. `sudo nano ~/wg-client.conf`

```jsx
[Interface]
Address = 10.0.0.2/24      
PrivateKey = <client_private_key> 

[Peer]
PublicKey = <server_public_key>  
Endpoint = <server_ip>:51820     
AllowedIPs = 0.0.0.0/0          

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
    1. `sudo cp /etc/modsecurity/modsecurity.conf-recommended /etc/modsecurity/modsecurity.conf`
    2. `sudo nano /etc/modsecurity/modsecurity.conf`
    3. Set `SecRuleEngine On`
    4. Adjust other settings as necessary
    5. Save and Exit
4. Install the OWASP ModSecurity Core Rule Set(CRS)
    1. `wget https://github.com/coreruleset/coreruleset/archive/v3.3.0.zip`
    2. Verify checksum: `certutil -hashfile vFileName.zip sha1; echo ProvidedChecksum`
    3. `unzip FileName.zip`
    4. `mv coreruleset-3.3.0/crs-setup.conf.example /etc/modsecurity/crs-setup.conf`
    5. `mv coreruleset-3.3.0/rules/ /etc/modsecurity/`
5. Configure Apache2 config file for modsec
    1. `sudo nano /etc/apache2/mods-enabled/security2.conf`
    2. Make sure both rules are set: 
        1. `IncludeOptional /etc/modsecurity/*.conf*`
        2. `Include /etc/modsecurity/rules/.conf`
6. Restart Apache
    1. `sudo systemctl restart apache2`
7. Verify ModSecurity Installation
    1. `sudo tail -f /var/log/apache2/error.log` 
8. Run a test
    1. Create a test rule file 
        1. `sudo nano /etc/modsecurity/modsecurity-test.conf`
    2. Add a new rule
        1. `SecRule REQUEST_URI "@streq /test" "id:1001,phase:1,log,deny,status:403"`
    3. Include the test configuration in modsecurity.conf
        1. `Include /etc/modsecurity/modsecurity-test.conf`
9. Restart Apache
    1. `sudo systemctl restart apache2`
10. To test your configuration go to: `http://<your_server>/test`

### SETTING UP COWRIE (HONEYPOT FOR SSH)

https://cowrie.readthedocs.io/en/latest/INSTALL.html

### SETTING UP SNORT

https://docs.snort.org/start/installation

### SETTING UP SURICATA

https://docs.suricata.io/en/latest/quickstart.html

### SETTING UP WAZUH

https://documentation.wazuh.com/current/installation-guide/wazuh-agent/wazuh-agent-package-linux.html

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
RUN apt update && \
    apt install -y wireguard iproute2 qrencode iptables && \
    apt clean

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

**COMMON PSQL COMMANDS**

| Command | Basic Commands |
| --- | --- |
| sudo -u usernamae psql -d db_name | Login in to psql |
| \q | Quit  |
| \h | Help |
| \l | List all Databases |
| \dt | List all tables in the current database |
| \d |  |
| \conninfo | View current connection info |
| \c db_name username | Switch user |
| \c db_name | Connect to database |
| \dn | List all schemas |
| \d table_name | Show tables schema |
| \du  | List all users |
| \di | List all indexes |
| \dv | List all views |
| \dv+ view_name | View details of specific view |
| \ds | List all sequences |
| \df | List all functions |
| \s | Show command history |
| Command | Creating and Deleting a Database |
| CREATE DATABASE <db_name>; | Create database |
| DROP DATABASE <db_name>; | Delete a database |
| Command | Query and Output Commands |
| SELECT * from table_name;  | Execute SQL query |
| \timing | Display query execution time |
| \o filename | Set output to a file |
| \x | Show query results in a vertical format |
| Command | Transaction Management |
| BEGIN; | Begin a transaction |
| COMMIT; | Commit a transaction |
|  ROLLBACK: | Rollback a transaction |
| Command | System and General Info Commands |
| SELECT version(); | View PostgreSQL version |
| \h | List all available SQL commands |
| \h SQL_command | Get help for a specific command |
| \? | Show all psql commands |
| Command | Session and File Management |
| \o output_file.sql | Save an SQL script |
| \i filename.sql | Run an SQL script file |
| SHOW ALL | View all configuration settings |
| Command | User and Permission Management |
| CREATE USER username WITH PASSWORD 'password'; | Create a new user |
| GRANT ALL PRIVILEGES ON TABLE table_name TO username; | Grant privileges on a table |
| REVOKE ALL PRIVILEGES ON TABLE table_name FROM username; | Revoke privileges on table |
| Command | Backup and Restore |
| pg_dump database_name > backup_file.sql | Backup a database |
| psql database_name < backup_file.sql | Restore a database |
| Command | PostgreSQL Server Commands |
| sudo systemctl status postgresql | Check postgresql status |
| sudo systemctl start postgresql | Start postgresql |
| sudo systemctl stop postgresql | Stop postgresql |
| sudo systemctl restart postgresql | Restart postgresql |
1. Configuration of PostgreSQL for Apache Server
    1. Add Proxy for PostgreSQL
        1. `ProxyPreserveHost On
        ProxyPass /api http://localhost:5000/api
        ProxyPassReverse /api http://localhost:5000/api`
    2. Reload Apache
        1. `sudo systemctl restart apache2`
2. Build and Deploy Backend
    1. `Example: run npm build`
    2. `npm run export`
    3. `sudo mv out/* /var/www/html/your_frontend)/`

### SECURITY TESTING

1. Check open ports & verify that ufw is properly configured
    1. `sudo lsof -i -P -n`
    2. `sudo ufw status verbose`
2. Install nmap to scan for open ports
    1. `sudo apt install nmap`
3. Perform external scan for open ports
    1. `nmap -sV -A [Your_Server_IP]`

### CREATING A STAGING ENVIRONMENT FOR PENETRATION TESTING

1. Add staging subdomain to cloudflare DNS
    1. staging.your_domain.com

### CITATIONS

Cloudflare "Cloudflare Connectivity Cloud." Cloudflare. Cloudflare, 2024. [www.cloudflare.com](https://www.cloudflare.com/). Accessed 28 Sept. 2024.

The Apache Software Foundation™. "Apache HTTP Server Documentation." The Apache Software Foundation, 2024. https://httpd.apache.org/docs-project/. Accessed 1 Sept. 2024.

Dedicated-Server.png "Lucidchart." Lucidchart. Lucidchart, 2024. [www.lucidchart.com](https://www.lucidchart.com/). Accessed 25 Sept. 2024.

fail2ban.org. "Fail2ban." GitHub, GitHub, Feb. 20, 2024. https://github.com/fail2ban/fail2ban. Accessed 15 Sept. 2024.

OWASP ModSecurity. "ModSecurity v3.0.12." GitHub, GitHub, 2024. https://github.com/owasp-modsecurity/ModSecurity/tree/v3.0.12. Accessed 3 Oct. 2024.

PhoenixNAP. "How to Setup and Configure ModSecurity on Apache." PhoenixNAP Knowledge Base, PhoenixNAP, 2024. https://phoenixnap.com/kb/setup-configure-modsecurity-on-apache. Accessed 3 Oct. 2024.

PostgreSQL Global Development Group. "PostgreSQL Documentation." PostgreSQL, PostgreSQL Global Development Group, 2024. https://www.postgresql.org/docs/. Accessed 3 Oct. 2024.

PostgreSQL Global Development Group. "psql Command." PostgreSQL Documentation, PostgreSQL Global Development Group, 2024. https://www.postgresql.org/docs/current/app-psql.html. Accessed 3 Oct. 2024.

Ubuntu Documentation Team. "UFW - How to configure UFW firewall." Ubuntu Documentation, Ubuntu.com, 2024. https://help.ubuntu.com/community/UFW. Accessed 15 Sept. 2024.

WireGuard Technologies. "WireGuard Quickstart Guide." WireGuard, 2024. https://www.wireguard.com/quickstart/. Accessed 15 Sept. 2024.

The OpenSSH Project. "OpenSSH Manual." OpenSSH, 2024. https://www.openssh.com/manual.html. Accessed 15 Sept. 2024.

Xfinity. "How to Enable or Disable Bridge Mode on Your Wireless Gateway." Xfinity Support, Comcast, 21 Apr. 2023, [www.xfinity.com/support/articles/wireless-gateway-enable-disable-bridge-mode](http://www.xfinity.com/support/articles/wireless-gateway-enable-disable-bridge-mode).

u/viPro. "Is Xfinity/Comcast Xfi Gateway on Bridge Mode a Problem?" Reddit, 28 Dec. 2013, [www.reddit.com/r/homelab/comments/1ctxoxo/is_xfinitycomcast_xfi_gateway_on_bridgemode_a/](http://www.reddit.com/r/homelab/comments/1ctxoxo/is_xfinitycomcast_xfi_gateway_on_bridgemode_a/).

Xfinity Forums. "Advanced Security and Other Questions." Xfinity, 16 Jan. 2023, [forums.xfinity.com/conversations/your-home-network/advanced-security-and-other-questions/65d7890f61dd3a25f37374de](http://forums.xfinity.com/conversations/your-home-network/advanced-security-and-other-questions/65d7890f61dd3a25f37374de).

InMotion Hosting. "Install ModSecurity Apache Module." InMotion Hosting Support,  Accessed October 10, 2024. https://www.inmotionhosting.com/support/edu/control-web-panel/cwp-user/account-management/mod-security-configuration/

Snort.org. "[Snort Website]." Accessed October 10, 2024. https://www.snort.org/

Project Honey Pot. "About Us." Project Honey Pot, Accessed October 10, 2024. https://www.projecthoneypot.org/

University of California Santa Barbara, IT Services. "Password Best Practices." UCSB IT Services, Accessed October 10, 2024. https://www.it.ucsb.edu/it-security-faculty-and-staff/best-practices-securing-campus-electronic-information

Red Switches. "Server Scaling: How to Scale Your Server Infrastructure Effectively." Red Switches, August 21, 2020. Accessed October 10, 2024. https://www.redswitches.com/

Stackify. "How to Optimize Server Performance." Stackify, Accessed October 10, 2024. https://stackify.com/site-performance-monitoring-best-practices/

CloudPanel. "Server Performance Optimization: Tips and Tricks for Faster Servers." CloudPanel, August 13, 2021. Accessed October 10, 2024. https://www.plesk.com/blog/various/server-optimization-how-to-increase-server-speed-performance/

Cloudflare. "Cache Rules Examples." Cloudflare Developers, Accessed October 10, 2024. https://developers.cloudflare.com/cache/how-to/cache-rules/
"Ddclient Documentation." *DDClient*, https://ddclient.net/. Accessed 4 Nov. 2024.

"Installation." *Cowrie Documentation*, https://cowrie.readthedocs.io/en/latest/INSTALL.html. Accessed 4 Nov. 2024

"Snort Installation Documentation." *Snort Documentation*, https://docs.snort.org/start/installation. Accessed 4 Nov. 2024.

"Installing the Wazuh Agent in Linux." *Wazuh Documentation*, https://documentation.wazuh.com/current/installation-guide/wazuh-agent/wazuh-agent-package-linux.html. Accessed 4 Nov. 2024.

"Quickstart Guide." *Suricata Documentation*, https://docs.suricata.io/en/latest/quickstart.html. Accessed 4 Nov. 2024.
