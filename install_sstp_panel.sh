#!/bin/bash
# install_sstp_panel.sh - SSTP VPN Server with Web Management Panel
# Optimized for sstp.alamindev.site domain integration
# Compatible with Ubuntu 22.04 LTS and 20.04 LTS

set -e

# Configuration variables
SCRIPT_NAME="SSTP VPN Panel Installer"
SCRIPT_VERSION="2.0.0"
LOG_FILE="/var/log/sstp_panel_install.log"
WEB_ROOT="/var/www/sstp-panel"
NGINX_SITE="sstp-panel"
DOMAIN="sstp.alamindev.site"
SSTP_CONFIG="/etc/pptpd.conf"
SSTP_OPTIONS="/etc/ppp/pptpd-options"
CHAP_SECRETS="/etc/ppp/chap-secrets"
PHP_VERSION=""
LETSENCRYPT_EMAIL=""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Enhanced logging function
log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - [$(basename $0)] $1" | tee -a "$LOG_FILE"
}

# Print colored output with enhanced formatting
print_status() {
    echo -e "${GREEN}✓ [SUCCESS]${NC} $1" | tee -a "$LOG_FILE"
}

print_warning() {
    echo -e "${YELLOW}⚠ [WARNING]${NC} $1" | tee -a "$LOG_FILE"
}

print_error() {
    echo -e "${RED}✗ [ERROR]${NC} $1" | tee -a "$LOG_FILE"
}

print_info() {
    echo -e "${BLUE}ℹ [INFO]${NC} $1" | tee -a "$LOG_FILE"
}

print_header() {
    echo
    echo -e "${PURPLE}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${PURPLE}║$(printf '%*s' $(((62-${#1})/2)) '')$1$(printf '%*s' $(((62-${#1})/2)) '')║${NC}"
    echo -e "${PURPLE}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo
}

print_banner() {
    echo -e "${CYAN}"
    cat << "EOF"
    ███████╗███████╗████████╗██████╗     ██╗   ██╗██████╗ ███╗   ██╗
    ██╔════╝██╔════╝╚══██╔══╝██╔══██╗    ██║   ██║██╔══██╗████╗  ██║
    ███████╗███████╗   ██║   ██████╔╝    ██║   ██║██████╔╝██╔██╗ ██║
    ╚════██║╚════██║   ██║   ██╔═══╝     ╚██╗ ██╔╝██╔═══╝ ██║╚██╗██║
    ███████║███████║   ██║   ██║          ╚████╔╝ ██║     ██║ ╚████║
    ╚══════╝╚══════╝   ╚═╝   ╚═╝           ╚═══╝  ╚═╝     ╚═╝  ╚═══╝
    
    SSTP VPN Server with Web Management Panel
    Domain: sstp.alamindev.site
    Version: 2.0.0
EOF
    echo -e "${NC}"
}

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_error "This script must be run as root. Use: sudo $0"
        exit 1
    fi
}

# Enhanced system check
check_system_requirements() {
    print_header "System Requirements Check"
    
    # Check Ubuntu version
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        if [[ "$ID" != "ubuntu" ]]; then
            print_error "This script is designed for Ubuntu only. Detected: $ID"
            exit 1
        fi
        
        case "$VERSION_ID" in
            "20.04"|"22.04")
                print_status "Ubuntu $VERSION_ID LTS detected and supported"
                ;;
            *)
                print_warning "Ubuntu $VERSION_ID detected. Tested on 20.04/22.04 LTS only"
                read -p "Continue anyway? (y/N): " -n 1 -r
                echo
                if [[ ! $REPLY =~ ^[Yy]$ ]]; then
                    exit 1
                fi
                ;;
        esac
    fi
    
    # Check memory
    MEMORY_GB=$(free -g | awk 'NR==2{printf "%.1f", $2}')
    if (( $(echo "$MEMORY_GB < 1.0" | bc -l 2>/dev/null || echo "1") )); then
        print_warning "Low memory detected: ${MEMORY_GB}GB. Minimum 1GB recommended"
    else
        print_status "Memory check passed: ${MEMORY_GB}GB available"
    fi
    
    # Check disk space
    DISK_SPACE=$(df / | awk 'NR==2 {printf "%.1f", $4/1048576}')
    if (( $(echo "$DISK_SPACE < 2.0" | bc -l 2>/dev/null || echo "1") )); then
        print_error "Insufficient disk space: ${DISK_SPACE}GB. Minimum 2GB required"
        exit 1
    else
        print_status "Disk space check passed: ${DISK_SPACE}GB available"
    fi
}

# Enhanced IP detection with domain verification
get_server_info() {
    print_header "Server Information Detection"
    
    # Get public IP from multiple sources
    local ip_sources=(
        "curl -s --max-time 10 ifconfig.me"
        "curl -s --max-time 10 ipinfo.io/ip"
        "curl -s --max-time 10 icanhazip.com"
        "curl -s --max-time 10 api.ipify.org"
    )
    
    for source in "${ip_sources[@]}"; do
        SERVER_IP=$(eval $source 2>/dev/null | head -1)
        if [[ -n "$SERVER_IP" && "$SERVER_IP" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            print_status "Public IP detected: $SERVER_IP"
            break
        fi
    done
    
    if [[ -z "$SERVER_IP" ]]; then
        print_error "Could not detect public IP address"
        read -p "Please enter your server's public IP: " SERVER_IP
        if [[ ! "$SERVER_IP" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            print_error "Invalid IP address format"
            exit 1
        fi
    fi
    
    # Check domain DNS resolution
    print_info "Checking domain DNS resolution for $DOMAIN..."
    DOMAIN_IP=$(dig +short $DOMAIN @8.8.8.8 2>/dev/null | tail -1)
    
    if [[ "$DOMAIN_IP" == "$SERVER_IP" ]]; then
        print_status "Domain $DOMAIN correctly points to this server ($SERVER_IP)"
        DOMAIN_VERIFIED=true
    elif [[ -n "$DOMAIN_IP" ]]; then
        print_warning "Domain $DOMAIN points to $DOMAIN_IP but server IP is $SERVER_IP"
        print_warning "Please update your DNS records to point $DOMAIN to $SERVER_IP"
        DOMAIN_VERIFIED=false
    else
        print_warning "Could not resolve domain $DOMAIN"
        print_info "Please ensure DNS records are configured correctly"
        DOMAIN_VERIFIED=false
    fi
}

# Enhanced user input collection
collect_user_input() {
    print_header "Configuration Setup"
    
    echo -e "${CYAN}Server Configuration:${NC}"
    echo "  Domain: $DOMAIN"
    echo "  Server IP: $SERVER_IP"
    echo "  Domain DNS Status: $([ "$DOMAIN_VERIFIED" = true ] && echo "✓ Verified" || echo "⚠ Needs Configuration")"
    echo
    
    # Admin credentials
    echo -e "${CYAN}Admin Panel Configuration:${NC}"
    read -p "Enter admin username for web panel [admin]: " ADMIN_USER
    ADMIN_USER=${ADMIN_USER:-admin}
    
    while true; do
        echo
        read -s -p "Enter admin password (min 8 characters): " ADMIN_PASS
        echo
        if [[ ${#ADMIN_PASS} -lt 8 ]]; then
            print_error "Password must be at least 8 characters long"
            continue
        fi
        
        read -s -p "Confirm admin password: " ADMIN_PASS_CONFIRM
        echo
        if [[ "$ADMIN_PASS" == "$ADMIN_PASS_CONFIRM" ]]; then
            break
        else
            print_error "Passwords do not match. Please try again."
        fi
    done
    
    # SSL Certificate option
    echo
    echo -e "${CYAN}SSL Certificate Configuration:${NC}"
    if [[ "$DOMAIN_VERIFIED" == true ]]; then
        echo "1) Let's Encrypt (Recommended for production)"
        echo "2) Self-signed certificate"
        read -p "Choose SSL option (1-2) [1]: " SSL_OPTION
        SSL_OPTION=${SSL_OPTION:-1}
        
        if [[ "$SSL_OPTION" == "1" ]]; then
            read -p "Enter email for Let's Encrypt notifications: " LETSENCRYPT_EMAIL
            while [[ ! "$LETSENCRYPT_EMAIL" =~ ^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$ ]]; do
                print_error "Invalid email format"
                read -p "Enter valid email for Let's Encrypt: " LETSENCRYPT_EMAIL
            done
            USE_LETSENCRYPT=true
        else
            USE_LETSENCRYPT=false
        fi
    else
        print_info "Using self-signed certificate (domain not verified)"
        USE_LETSENCRYPT=false
    fi
    
    # VPN Configuration
    echo
    echo -e "${CYAN}VPN Configuration:${NC}"
    read -p "Enter VPN IP range start [10.0.0.10]: " VPN_RANGE_START
    VPN_RANGE_START=${VPN_RANGE_START:-10.0.0.10}
    
    read -p "Enter VPN IP range end [10.0.0.50]: " VPN_RANGE_END
    VPN_RANGE_END=${VPN_RANGE_END:-10.0.0.50}
    
    print_info "Configuration summary:"
    echo "  Domain: $DOMAIN"
    echo "  Server IP: $SERVER_IP"
    echo "  Admin User: $ADMIN_USER"
    echo "  SSL: $([ "$USE_LETSENCRYPT" = true ] && echo "Let's Encrypt" || echo "Self-signed")"
    echo "  VPN Range: $VPN_RANGE_START - $VPN_RANGE_END"
    echo
    
    read -p "Proceed with installation? (Y/n): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Nn]$ ]]; then
        print_info "Installation cancelled by user"
        exit 0
    fi
    
    log "Configuration collected - Domain: $DOMAIN, IP: $SERVER_IP, Admin: $ADMIN_USER"
}

# Enhanced system update
update_system() {
    print_header "System Update"
    
    print_info "Updating package repositories..."
    apt update
    
    print_info "Upgrading system packages..."
    DEBIAN_FRONTEND=noninteractive apt upgrade -y
    
    print_info "Installing essential packages..."
    DEBIAN_FRONTEND=noninteractive apt install -y \
        curl \
        wget \
        gnupg \
        lsb-release \
        software-properties-common \
        apt-transport-https \
        ca-certificates \
        bc \
        dnsutils
    
    print_status "System update completed successfully"
}

# Enhanced package installation
install_packages() {
    print_header "Installing Required Packages"
    
    # Determine PHP version
    if [[ "$(lsb_release -rs)" == "22.04" ]]; then
        PHP_VERSION="8.1"
    else
        PHP_VERSION="7.4"
    fi
    
    print_info "Installing SSTP/PPTP server packages..."
    DEBIAN_FRONTEND=noninteractive apt install -y \
        pptpd \
        ppp \
        iptables-persistent \
        netfilter-persistent
    
    print_info "Installing web server packages..."
    DEBIAN_FRONTEND=noninteractive apt install -y \
        nginx \
        php${PHP_VERSION}-fpm \
        php${PHP_VERSION}-cli \
        php${PHP_VERSION}-common \
        php${PHP_VERSION}-sqlite3 \
        php${PHP_VERSION}-json \
        php${PHP_VERSION}-mbstring \
        php${PHP_VERSION}-curl \
        sqlite3
    
    print_info "Installing SSL certificate tools..."
    if [[ "$USE_LETSENCRYPT" == true ]]; then
        DEBIAN_FRONTEND=noninteractive apt install -y certbot python3-certbot-nginx
    fi
    DEBIAN_FRONTEND=noninteractive apt install -y openssl
    
    print_info "Installing firewall tools..."
    DEBIAN_FRONTEND=noninteractive apt install -y ufw fail2ban
    
    print_status "All packages installed successfully"
}

# Enhanced SSTP server configuration
configure_sstp_server() {
    print_header "Configuring SSTP/PPTP Server"
    
    # Backup original files
    [[ -f "$SSTP_CONFIG" ]] && cp "$SSTP_CONFIG" "${SSTP_CONFIG}.backup.$(date +%Y%m%d_%H%M%S)"
    [[ -f "$SSTP_OPTIONS" ]] && cp "$SSTP_OPTIONS" "${SSTP_OPTIONS}.backup.$(date +%Y%m%d_%H%M%S)"
    
    # Configure pptpd.conf with dynamic IP range
    cat > "$SSTP_CONFIG" << EOF
# SSTP VPN Configuration for $DOMAIN
# Generated on $(date)

# PPP options file
option /etc/ppp/pptpd-options

# Enable connection logging
logwtmp

# Local IP (server-side)
localip 10.0.0.1

# Remote IP range (client-side)
remoteip $VPN_RANGE_START-$(echo $VPN_RANGE_END | cut -d'.' -f4)

# Connection limits
connections 50
EOF
    
    # Configure enhanced pptpd-options
    cat > "$SSTP_OPTIONS" << EOF
# SSTP VPN PPP Options for $DOMAIN
# Generated on $(date)

# Server name
name pptpd

# Authentication
refuse-pap
refuse-chap
refuse-mschap
require-mschap-v2

# Encryption
require-mppe-128
nomppe-40

# DNS servers (Cloudflare and Google)
ms-dns 1.1.1.1
ms-dns 8.8.8.8
ms-dns 1.0.0.1
ms-dns 8.8.4.4

# Network settings
proxyarp
nodefaultroute
lock
nobsdcomp
novj
novjccomp

# Logging
nologfd
logfile /var/log/pptpd.log

# MTU settings
mtu 1490
mru 1490

# Timeouts
lcp-echo-failure 3
lcp-echo-interval 60
EOF
    
    # Initialize chap-secrets with header
    cat > "$CHAP_SECRETS" << EOF
# SSTP VPN Users for $DOMAIN
# Generated on $(date)
# Format: username [tab] server [tab] password [tab] IP
# Example: user1	pptpd	password123	*

EOF
    
    # Set proper permissions
    chmod 600 "$CHAP_SECRETS"
    chown root:root "$CHAP_SECRETS"
    
    # Enable IP forwarding permanently
    if ! grep -q "net.ipv4.ip_forward=1" /etc/sysctl.conf; then
        echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
    fi
    
    # Apply kernel parameters
    sysctl -p
    
    print_status "SSTP/PPTP server configured successfully"
}

# Enhanced firewall configuration
configure_firewall() {
    print_header "Configuring Advanced Firewall and NAT"
    
    # Get default network interface
    DEFAULT_INTERFACE=$(ip route show default | awk '/default/ {print $5}' | head -n1)
    
    if [[ -z "$DEFAULT_INTERFACE" ]]; then
        print_error "Could not determine default network interface"
        exit 1
    fi
    
    print_info "Default network interface: $DEFAULT_INTERFACE"
    
    # Flush existing iptables rules
    iptables -F
    iptables -X
    iptables -t nat -F
    iptables -t nat -X
    iptables -t mangle -F
    iptables -t mangle -X
    
    # Set default policies
    iptables -P INPUT ACCEPT
    iptables -P FORWARD ACCEPT
    iptables -P OUTPUT ACCEPT
    
    # Enable IP forwarding
    echo 1 > /proc/sys/net/ipv4/ip_forward
    
    # NAT configuration for VPN traffic
    iptables -t nat -A POSTROUTING -o "$DEFAULT_INTERFACE" -j MASQUERADE
    iptables -t nat -A POSTROUTING -s 10.0.0.0/24 -o "$DEFAULT_INTERFACE" -j MASQUERADE
    
    # Forward VPN traffic
    iptables -A FORWARD -i ppp+ -o "$DEFAULT_INTERFACE" -j ACCEPT
    iptables -A FORWARD -i "$DEFAULT_INTERFACE" -o ppp+ -m state --state RELATED,ESTABLISHED -j ACCEPT
    iptables -A FORWARD -s 10.0.0.0/24 -j ACCEPT
    iptables -A FORWARD -d 10.0.0.0/24 -j ACCEPT
    
    # Allow essential services
    iptables -A INPUT -i lo -j ACCEPT
    iptables -A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
    
    # SSH access
    iptables -A INPUT -p tcp --dport 22 -j ACCEPT
    
    # Web server ports
    iptables -A INPUT -p tcp --dport 80 -j ACCEPT
    iptables -A INPUT -p tcp --dport 443 -j ACCEPT
    
    # PPTP/SSTP ports
    iptables -A INPUT -p tcp --dport 1723 -j ACCEPT
    iptables -A INPUT -p gre -j ACCEPT
    
    # Allow VPN subnet
    iptables -A INPUT -s 10.0.0.0/24 -j ACCEPT
    
    # Save iptables rules
    netfilter-persistent save
    
    # Configure UFW as additional layer
    ufw --force reset
    ufw --force enable
    
    # UFW rules
    ufw allow 22/tcp comment 'SSH'
    ufw allow 80/tcp comment 'HTTP'
    ufw allow 443/tcp comment 'HTTPS'
    ufw allow 1723/tcp comment 'PPTP'
    ufw allow from 10.0.0.0/24 comment 'VPN subnet'
    
    # Configure fail2ban
    cat > /etc/fail2ban/jail.local << EOF
[DEFAULT]
bantime = 1h
findtime = 10m
maxretry = 3

[sshd]
enabled = true
port = 22
filter = sshd
logpath = /var/log/auth.log

[nginx-http-auth]
enabled = true
port = 80,443
filter = nginx-http-auth
logpath = /var/log/nginx/error.log

[pptpd]
enabled = true
port = 1723
filter = pptpd
logpath = /var/log/pptpd.log
maxretry = 3
EOF
    
    # Create pptpd fail2ban filter
    cat > /etc/fail2ban/filter.d/pptpd.conf << EOF
[Definition]
failregex = CTRL: Client <HOST> control connection finished
            CTRL: Client <HOST> control connection started
            CTRL: EOF or bad error reading ctrl packet length\.
ignoreregex =
EOF
    
    systemctl restart fail2ban
    
    print_status "Advanced firewall and NAT configured successfully"
}

# Enhanced SSL certificate generation
generate_ssl_certificate() {
    print_header "Configuring SSL Certificate"
    
    SSL_DIR="/etc/nginx/ssl"
    mkdir -p "$SSL_DIR"
    
    if [[ "$USE_LETSENCRYPT" == true ]]; then
        print_info "Obtaining Let's Encrypt certificate for $DOMAIN..."
        
        # Create temporary Nginx config for domain verification
        cat > "/etc/nginx/sites-available/temp-$DOMAIN" << EOF
server {
    listen 80;
    server_name $DOMAIN;
    
    location /.well-known/acme-challenge/ {
        root /var/www/html;
    }
    
    location / {
        return 301 https://\$server_name\$request_uri;
    }
}
EOF
        
        ln -sf "/etc/nginx/sites-available/temp-$DOMAIN" "/etc/nginx/sites-enabled/"
        systemctl reload nginx
        
        # Obtain certificate
        if certbot --nginx -d "$DOMAIN" --non-interactive --agree-tos --email "$LETSENCRYPT_EMAIL" --redirect; then
            print_status "Let's Encrypt certificate obtained successfully"
            
            # Setup auto-renewal
            (crontab -l 2>/dev/null; echo "0 12 * * * /usr/bin/certbot renew --quiet") | crontab -
            
            SSL_CERT_PATH="/etc/letsencrypt/live/$DOMAIN/fullchain.pem"
            SSL_KEY_PATH="/etc/letsencrypt/live/$DOMAIN/privkey.pem"
        else
            print_error "Failed to obtain Let's Encrypt certificate. Falling back to self-signed."
            USE_LETSENCRYPT=false
        fi
        
        # Remove temporary config
        rm -f "/etc/nginx/sites-enabled/temp-$DOMAIN"
    fi
    
    if [[ "$USE_LETSENCRYPT" == false ]]; then
        print_info "Generating self-signed certificate..."
        
        SSL_CERT_PATH="$SSL_DIR/sstp-panel.crt"
        SSL_KEY_PATH="$SSL_DIR/sstp-panel.key"
        
        openssl req -x509 -nodes -days 365 -newkey rsa:4096 \
            -keyout "$SSL_KEY_PATH" \
            -out "$SSL_CERT_PATH" \
            -subj "/C=US/ST=State/L=City/O=SSTP VPN/CN=$DOMAIN/subjectAltName=DNS:$DOMAIN,DNS:www.$DOMAIN,IP:$SERVER_IP"
        
        chmod 600 "$SSL_KEY_PATH"
        chmod 644 "$SSL_CERT_PATH"
        
        print_status "Self-signed certificate generated successfully"
    fi
}

# Enhanced web panel creation
create_enhanced_web_panel() {
    print_header "Creating Enhanced Web Management Panel"
    
    # Create web directory structure
    mkdir -p "$WEB_ROOT"/{data,assets,includes,logs}
    
    # Create enhanced SQLite database
    cat > "$WEB_ROOT/init_db.sql" << 'EOF'
-- SSTP VPN User Management Database
-- Generated for sstp.alamindev.site

PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    email TEXT,
    status INTEGER DEFAULT 1,
    connection_limit INTEGER DEFAULT 1,
    bandwidth_limit INTEGER DEFAULT 0,
    expiry_date DATETIME,
    last_login DATETIME,
    last_ip TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    created_by TEXT DEFAULT 'admin'
);

CREATE TABLE IF NOT EXISTS connection_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    ip_address TEXT,
    connect_time DATETIME DEFAULT CURRENT_TIMESTAMP,
    disconnect_time DATETIME,
    bytes_sent INTEGER DEFAULT 0,
    bytes_received INTEGER DEFAULT 0,
    session_duration INTEGER DEFAULT 0,
    status TEXT DEFAULT 'connected'
);

CREATE TABLE IF NOT EXISTS admin_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    admin_user TEXT NOT NULL,
    action TEXT NOT NULL,
    target_user TEXT,
    details TEXT,
    ip_address TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Create indexes for better performance
CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
CREATE INDEX IF NOT EXISTS idx_users_status ON users(status);
CREATE INDEX IF NOT EXISTS idx_connection_logs_username ON connection_logs(username);
CREATE INDEX IF NOT EXISTS idx_connection_logs_connect_time ON connection_logs(connect_time);

-- Insert sample data
INSERT OR IGNORE INTO users (username, password_hash, email, status) 
VALUES ('demo', '$2y$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi', 'demo@example.com', 0);
EOF
    
    sqlite3 "$WEB_ROOT/data/users.db" < "$WEB_ROOT/init_db.sql"
    rm "$WEB_ROOT/init_db.sql"
    
    # Create enhanced CSS
    cat > "$WEB_ROOT/assets/style.css" << 'EOF'
/* Enhanced SSTP VPN Panel Styles for sstp.alamindev.site */
:root {
    --primary-color: #2c3e50;
    --secondary-color: #3498db;
    --success-color: #27ae60;
    --warning-color: #f39c12;
    --danger-color: #e74c3c;
    --light-bg: #ecf0f1;
    --dark-bg: #34495e;
    --border-color: #bdc3c7;
    --text-color: #2c3e50;
    --light-text: #7f8c8d;
}

* {
    margin: 0;
    padding: 0;
    box-sizing: border-box;
}

body {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
    min-height: 100vh;
    color: var(--text-color);
}

.login-container {
    max-width: 400px;
    margin: 10vh auto;
    background: white;
    padding: 40px;
    border-radius: 15px;
    box-shadow: 0 10px 30px rgba(0,0,0,0.2);
    backdrop-filter: blur(10px);
}

.login-header {
    text-align: center;
    margin-bottom: 30px;
}

.login-header h1 {
    color: var(--primary-color);
    font-size: 2.5em;
    margin-bottom: 10px;
}

.login-header .domain {
    color: var(--secondary-color);
    font-size: 1.1em;
    font-weight: 500;
}

.container {
    max-width: 1400px;
    margin: 0 auto;
    background: white;
    min-height: 100vh;
    display: flex;
    flex-direction: column;
}

.header {
    background: var(--primary-color);
    color: white;
    padding: 20px 30px;
    display: flex;
    justify-content: space-between;
    align-items: center;
    box-shadow: 0 2px 10px rgba(0,0,0,0.1);
}

.header h1 {
    font-size: 1.8em;
    font-weight: 600;
}

.header .domain-info {
    font-size: 0.9em;
    opacity: 0.8;
}

.nav-menu {
    display: flex;
    gap: 20px;
    align-items: center;
}

.nav-item {
    color: white;
    text-decoration: none;
    padding: 8px 16px;
    border-radius: 5px;
    transition: background 0.3s;
}

.nav-item:hover, .nav-item.active {
    background: rgba(255,255,255,0.2);
}

.main-content {
    flex: 1;
    padding: 30px;
    background: #f8f9fa;
}

.stats-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
    gap: 20px;
    margin-bottom: 30px;
}

.stat-card {
    background: white;
    padding: 25px;
    border-radius: 10px;
    box-shadow: 0 2px 10px rgba(0,0,0,0.1);
    text-align: center;
    border-left: 4px solid var(--secondary-color);
}

.stat-card.success { border-left-color: var(--success-color); }
.stat-card.warning { border-left-color: var(--warning-color); }
.stat-card.danger { border-left-color: var(--danger-color); }

.stat-number {
    font-size: 2.5em;
    font-weight: bold;
    color: var(--secondary-color);
    margin-bottom: 10px;
}

.stat-card.success .stat-number { color: var(--success-color); }
.stat-card.warning .stat-number { color: var(--warning-color); }
.stat-card.danger .stat-number { color: var(--danger-color); }

.card {
    background: white;
    border-radius: 10px;
    box-shadow: 0 2px 10px rgba(0,0,0,0.1);*
