#!/bin/bash

# AI Fiesta's SSTP VPN Server & Web Panel Installer
# Target OS: Ubuntu 22.04 LTS & 20.04 LTS
#
# This script is designed to be idempotent and will log its output for debugging.

# --- Configuration & Constants ---
LOG_FILE="/var/log/sstp_panel_install.log"
SSTP_CONF="/etc/sstp.conf"
PPTPD_CONF="/etc/pptpd.conf"
PPTPD_OPTIONS="/etc/ppp/pptpd-options"
CHAP_SECRETS="/etc/ppp/chap-secrets"
WEB_PANEL_DIR="/var/www/html/sstp-admin"
NGINX_CONF="/etc/nginx/sites-available/sstp-panel"
HTPASSWD_FILE="/etc/nginx/.sstp_htpasswd"
SSL_CERT="/etc/ssl/certs/sstp-cert.pem"
SSL_KEY="/etc/ssl/private/sstp-key.pem"

# --- Colors for Output ---
C_RESET='\033[0m'
C_RED='\033[0;31m'
C_GREEN='\033[0;32m'
C_YELLOW='\033[0;33m'
C_BLUE='\033[0;34m'

# --- Script Execution Logic ---

# Function to print messages
log_message() {
    echo -e "$(date +"%Y-%m-%d %T") - $1" | tee -a "$LOG_FILE"
}

# Function to handle errors
handle_error() {
    log_message "${C_RED}ERROR: $1. Installation failed.${C_RESET}"
    log_message "${C_RED}Please check the log file for details: ${LOG_FILE}${C_RESET}"
    exit 1
}

# Ensure script is run as root
check_root() {
    if [[ "$EUID" -ne 0 ]]; then
        echo -e "${C_RED}This script must be run as root. Please use 'sudo ./install_sstp_panel.sh'.${C_RESET}"
        exit 1
    fi
}

# Trap errors
trap 'handle_error "An unexpected error occurred at line $LINENO"' ERR
set -e
set -o pipefail

# --- Main Installation Steps ---

main() {
    # Start logging to file
    exec > >(tee -a "$LOG_FILE") 2>&1

    clear
    log_message "${C_BLUE}=====================================================${C_RESET}"
    log_message "${C_BLUE}== AI Fiesta SSTP VPN Server & Web Panel Installer ==${C_RESET}"
    log_message "${C_BLUE}=====================================================${C_RESET}"
    log_message "Starting installation..."

    gather_user_input
    install_dependencies
    configure_sysctl
    configure_sstp_server
    configure_iptables
    generate_ssl_certificate
    configure_nginx_php
    create_web_panel
    start_and_enable_services
    display_summary

    log_message "${C_GREEN}Installation completed successfully!${C_RESET}"
    set +e
    trap - ERR
}

gather_user_input() {
    log_message "${C_YELLOW}--- Gathering System Information ---${C_RESET}"

    # Get Public IP
    DETECTED_IP=$(curl -s4 https://api.ipify.org || curl -s4 https://icanhazip.com)
    read -rp "Enter the public IP address for this server [${DETECTED_IP}]: " SERVER_IP
    SERVER_IP=${SERVER_IP:-$DETECTED_IP}
    if [[ -z "$SERVER_IP" ]]; then
        handle_error "Could not determine public IP address."
    fi

    # Get Hostname for SSL
    read -rp "Enter a hostname/domain for the SSL cert (e.g., vpn.example.com) [${SERVER_IP}]: " SSL_HOST
    SSL_HOST=${SSL_HOST:-$SERVER_IP}

    # Get Web Panel Admin Credentials
    log_message "${C_YELLOW}--- Web Panel Admin Credentials ---${C_RESET}"
    read -rp "Enter a username for the web panel admin: " ADMIN_USER
    while [[ -z "$ADMIN_USER" ]]; do
        echo -e "${C_RED}Admin username cannot be empty.${C_RESET}"
        read -rp "Enter a username for the web panel admin: " ADMIN_USER
    done

    read -rsp "Enter a password for the web panel admin: " ADMIN_PASS
    echo
    while [[ -z "$ADMIN_PASS" ]]; do
        echo -e "${C_RED}Admin password cannot be empty.${C_RESET}"
        read -rsp "Enter a password for the web panel admin: " ADMIN_PASS
        echo
    done
}

install_dependencies() {
    log_message "${C_YELLOW}--- Installing Dependencies ---${C_RESET}"
    log_message "Updating package lists..."
    apt-get update -y

    PACKAGES=(nginx php-fpm pptpd sstp-server iptables-persistent apache2-utils)
    for pkg in "${PACKAGES[@]}"; do
        if dpkg -s "$pkg" &> /dev/null; then
            log_message "${pkg} is already installed. Skipping."
        else
            log_message "Installing ${pkg}..."
            apt-get install -y "$pkg" || handle_error "Failed to install ${pkg}"
        fi
    done
}

configure_sysctl() {
    log_message "${C_YELLOW}--- Enabling Kernel IP Forwarding ---${C_RESET}"
    if ! grep -q "net.ipv4.ip_forward=1" /etc/sysctl.conf; then
        echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
    fi
    sysctl -p
}

configure_sstp_server() {
    log_message "${C_YELLOW}--- Configuring SSTP and PPP ---${C_RESET}"

    # Configure pptpd.conf
    log_message "Configuring ${PPTPD_CONF}"
    cat > "$PPTPD_CONF" << EOF
option /etc/ppp/pptpd-options
logwtmp
localip 192.168.240.1
remoteip 192.168.240.10-200
EOF

    # Configure pptpd-options
    log_message "Configuring ${PPTPD_OPTIONS}"
    cat > "$PPTPD_OPTIONS" << EOF
name pptpd
refuse-pap
refuse-chap
refuse-mschap
require-mschap-v2
require-mppe-128
ms-dns 1.1.1.1
ms-dns 8.8.8.8
proxyarp
lock
nobsdcomp
novj
novjccomp
nologfd
EOF

    # Configure chap-secrets (initialize empty file with correct permissions)
    log_message "Initializing ${CHAP_SECRETS}"
    touch "$CHAP_SECRETS"
    chmod 600 "$CHAP_SECRETS"
    # Add header comment
    echo "# username<TAB or SPACE>server<TAB or SPACE>password<TAB or SPACE>ip" > "$CHAP_SECRETS"
    echo "# --- Users below are managed by the web panel ---" >> "$CHAP_SECRETS"

    # Configure sstp-server
    log_message "Configuring ${SSTP_CONF}"
    cat > "$SSTP_CONF" << EOF
[listen]
host = 0.0.0.0
port = 443

[auth]
pppd-plugin = /usr/lib/pptpd/pptpd-logwtmp.so
pppd-option-file = /etc/ppp/pptpd-options

[ssl]
cert-file = ${SSL_CERT}
key-file = ${SSL_KEY}

[pppd]
# For debugging pppd
# log-file = /var/log/sstp-pppd.log
EOF
}

configure_iptables() {
    log_message "${C_YELLOW}--- Configuring Firewall (iptables) ---${C_RESET}"
    
    # Detect primary network interface
    INTERFACE=$(ip route | grep default | sed -e "s/^.*dev.//" -e "s/.proto.*//")
    if [[ -z "$INTERFACE" ]]; then
        handle_error "Could not detect primary network interface."
    fi
    log_message "Detected primary network interface: ${INTERFACE}"

    # Flush existing rules to start fresh (optional, but good for a clean setup)
    # iptables -F
    # iptables -t nat -F

    # Set rules
    iptables -I INPUT -p tcp --dport 443 -j ACCEPT
    iptables -I FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
    iptables -t nat -A POSTROUTING -s 192.168.240.0/24 -o "$INTERFACE" -j MASQUERADE
    iptables -A FORWARD -s 192.168.240.0/24 -p tcp -m tcp --syn -m conntrack --ctstate NEW -j ACCEPT
    iptables -A FORWARD -s 192.168.240.0/24 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

    # Persist rules
    netfilter-persistent save
}

generate_ssl_certificate() {
    log_message "${C_YELLOW}--- Generating Self-Signed SSL Certificate ---${C_RESET}"
    if [ -f "$SSL_CERT" ]; then
        log_message "SSL certificate already exists. Skipping generation."
        return
    fi
    
    # Create directory if it doesn't exist
    mkdir -p /etc/ssl/private
    chmod 700 /etc/ssl/private

    openssl req -x509 -nodes -days 3650 -newkey rsa:2048 \
        -keyout "$SSL_KEY" \
        -out "$SSL_CERT" \
        -subj "/CN=${SSL_HOST}"

    log_message "Self-signed certificate created. You can replace it later."
    log_message "Cert: ${SSL_CERT}"
    log_message "Key:  ${SSL_KEY}"
    log_message "${C_YELLOW}To use Let's Encrypt, stop sstp-server, run certbot, then update the paths in ${SSTP_CONF} and ${NGINX_CONF}.${C_RESET}"
}

configure_nginx_php() {
    log_message "${C_YELLOW}--- Configuring Nginx and PHP ---${C_RESET}"

    # Create htpasswd file for web panel admin
    htpasswd -cb "$HTPASSWD_FILE" "$ADMIN_USER" "$ADMIN_PASS"
    chmod 600 "$HTPASSWD_FILE"

    # Find PHP-FPM socket path
    PHP_VERSION=$(php -r 'echo PHP_MAJOR_VERSION.".".PHP_MINOR_VERSION;')
    PHP_FPM_SOCK="/run/php/php${PHP_VERSION}-fpm.sock"
    if [ ! -S "$PHP_FPM_SOCK" ]; then
        handle_error "Could not find PHP-FPM socket at ${PHP_FPM_SOCK}"
    fi
    log_message "Using PHP-FPM socket: ${PHP_FPM_SOCK}"

    # Create Nginx server block
    cat > "$NGINX_CONF" << EOF
server {
    listen 80;
    server_name ${SSL_HOST} _;
    return 301 https://\$host\$request_uri;
}

server {
    listen 443 ssl http2;
    server_name ${SSL_HOST} _;

    ssl_certificate ${SSL_CERT};
    ssl_certificate_key ${SSL_KEY};

    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers 'TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384';
    
    root /var/www/html;
    index index.php index.html;

    location / {
        # Redirect root to admin panel for convenience
        return 302 /sstp-admin;
    }

    location /sstp-admin {
        auth_basic "SSTP Admin Panel";
        auth_basic_user_file ${HTPASSWD_FILE};

        try_files \$uri \$uri/ =404;
        
        location ~ \.php$ {
            include snippets/fastcgi-php.conf;
            fastcgi_pass unix:${PHP_FPM_SOCK};
        }
    }
}
EOF

    # Enable the site
    if [ ! -L "/etc/nginx/sites-enabled/sstp-panel" ]; then
        ln -s "$NGINX_CONF" /etc/nginx/sites-enabled/
    fi

    # Test Nginx config
    nginx -t || handle_error "Nginx configuration test failed."
}

create_web_panel() {
    log_message "${C_YELLOW}--- Creating Web Management Panel ---${C_RESET}"
    mkdir -p "$WEB_PANEL_DIR"

    # Create the PHP web panel file
    cat > "${WEB_PANEL_DIR}/index.php" << 'EOF'
<?php
// SSTP VPN User Management Panel by AI Fiesta
// This panel manages users in /etc/ppp/chap-secrets

session_start();
$chap_file = '/etc/ppp/chap-secrets';

// --- Helper Functions ---
function get_users() {
    global $chap_file;
    $lines = file($chap_file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    $users = [];
    foreach ($lines as $line) {
        $line = trim($line);
        if (empty($line)) continue;
        
        $status = 'active';
        if (strpos($line,
        }
        
        $parts = preg_split('/\s+/', $line);
        if (count($parts) >= 3) {
            $users[] = [
                'username' => $parts[0],
                'server' => $parts[1],
                'password' => $parts[2],
                'ip' => isset($parts[3]) ? $parts[3] : '*',
                'status' => $status
            ];
        }
    }
    return $users;
}

function save_users($users) {
    global $chap_file;
    $content = "# username<TAB or SPACE>server<TAB or SPACE>password<TAB or SPACE>ip\n";
    $content .= "# --- Users below are managed by the web panel ---\n";
    foreach ($users as $user) {
        $line = $user['username'] . "\t*\t" . $user['password'] . "\t*";
        if ($user['status'] === 'inactive') {
            $line = '# ' . $line;
        }
        $content .= $line . "\n";
    }
    // Use a temporary file and rename for atomicity
    $temp_file = $chap_file . '.tmp';
    if (file_put_contents($temp_file, $content) !== false) {
        // Set secure permissions before moving
        chmod($temp_file, 0600);
        if (rename($temp_file, $chap_file)) {
            return true;
        }
    }
    return false;
}

function user_exists($username) {
    $users = get_users();
    foreach ($users as $user) {
        if ($user['username'] === $username) {
            return true;
        }
    }
    return false;
}

function generate_password($length = 12) {
    $chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()';
    return substr(str_shuffle($chars), 0, $length);
}

// --- Handle POST Requests ---
$message = '';
$message_type = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $action = $_POST['action'] ?? '';
    
    if ($action === 'add_user') {
        $username = trim($_POST['username']);
        $password = trim($_POST['password']);

        if (empty($password)) {
            $password = generate_password();
        }

        if (!empty($username) && !preg_match('/[^a-zA-Z0-9_.-]/', $username)) {
            if (!user_exists($username)) {
                $users = get_users();
                $users[] = [
                    'username' => $username,
                    'server' => '*',
                    'password' => $password,
                    'ip' => '*',
                    'status' => 'active'
                ];
                if (save_users($users)) {
                    $_SESSION['message'] = "User '{$username}' added successfully. Password: <strong>{$password}</strong>";
                    $_SESSION['message_type'] = 'success';
                } else {
                    $_SESSION['message'] = "Error writing to {$chap_file}. Check permissions.";
                    $_SESSION['message_type'] = 'error';
                }
            } else {
                $_SESSION['message'] = "User '{$username}' already exists.";
                $_SESSION['message_type'] = 'error';
            }
        } else {
            $_SESSION['message'] = 'Invalid username. Use only letters, numbers, underscore, dot, or hyphen.';
            $_SESSION['message_type'] = 'error';
        }
    }
    header("Location: " . $_SERVER['PHP_SELF']);
    exit();
}

if ($_SERVER['REQUEST_METHOD'] === 'GET') {
    $action = $_GET['action'] ?? '';
    $username = $_GET['user'] ?? '';

    if (!empty($username)) {
        $users = get_users();
        $user_found = false;
        
        foreach ($users as $i => &$user) {
            if ($user['username'] === $username) {
                $user_found = true;
                if ($action === 'delete') {
                    unset($users[$i]);
                    $_SESSION['message'] = "User '{$username}' has been deleted.";
                    $_SESSION['message_type'] = 'success';
                } elseif ($action === 'toggle') {
                    $user['status'] = ($user['status'] === 'active') ? 'inactive' : 'active';
                     $_SESSION['message'] = "User '{$username}' status changed to {$user['status']}.";
                     $_SESSION['message_type'] = 'success';
                }
                break;
            }
        }

        if ($user_found) {
            save_users(array_values($users));
        }
        header("Location: " . $_SERVER['PHP_SELF']);
        exit();
    }
}

if (isset($_SESSION['message'])) {
    $message = $_SESSION['message'];
    $message_type = $_SESSION['message_type'];
    unset($_SESSION['message']);
    unset($_SESSION['message_type']);
}

$all_users = get_users();

?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SSTP User Management</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif; background-color: #f4f7f6; color: #333; margin: 0; padding: 2em; }
        .container { max-width: 800px; margin: 0 auto; background-color: #fff; padding: 2em; border-radius: 8px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }
        h1, h2 { color: #2c3e50; border-bottom: 2px solid #e0e0e0; padding-bottom: 10px; }
        table { width: 100%; border-collapse: collapse; margin-top: 1em; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background-color: #f2f2f2; }
        .action-btn { color: #fff; padding: 5px 10px; border-radius: 4px; text-decoration: none; font-size: 0.9em; }
        .delete-btn { background-color: #e74c3c; }
        .toggle-btn-active { background-color: #27ae60; }
        .toggle-btn-inactive { background-color: #f39c12; }
        .status-active { color: #27ae60; font-weight: bold; }
        .status-inactive { color: #e67e22; font-weight: bold; }
        form { margin-top: 1em; padding: 1.5em; background-color: #ecf0f1; border-radius: 5px; }
        input[type="text"], input[type="password"] { width: 250px; padding: 8px; margin-right: 10px; border: 1px solid #ccc; border-radius: 4px; }
        input[type="submit"] { background-color: #3498db; color: #fff; border: none; padding: 10px 15px; border-radius: 4px; cursor: pointer; }
        input[type="submit"]:hover { background-color: #2980b9; }
        .message { padding: 1em; border-radius: 5px; margin-bottom: 1em; }
        .message.success { background-color: #d4edda; color: #155724; border: 1px solid #c3e6cb; }
        .message.error { background-color: #f8d7da; color: #721c24; border: 1px solid #f5c6cb; }
        .password-note { font-size: 0.9em; color: #7f8c8d; }
    </style>
    <script>
        function confirmDelete(username) {
            return confirm('Are you sure you want to delete the user "' + username + '"?');
        }
    </script>
</head>
<body>
    <div class="container">
        <h1>SSTP User Management</h1>
        
        <?php if ($message): ?>
            <div class="message <?php echo htmlspecialchars($_
