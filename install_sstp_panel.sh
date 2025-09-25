#!/bin/bash

# install_sstp_panel.sh (Refactored Version)
# Installs and configures SoftEther-based SSTP VPN server with a web management panel on Ubuntu 20.04/22.04 LTS.
# Integrated with domain: sstp.alamindev.site

set -e  # Exit on error

# Constants
LOG_FILE="/var/log/sstp_panel_install.log"
DOMAIN="sstp.alamindev.site"
SOFETHER_DIR="/usr/local/vpnserver"
SOFETHER_VERSION="4.42-9792-beta"
SOFETHER_DATE="2023.03.14"
SOFETHER_ARCH="linux-x64-64bit"
SOFETHER_URL="https://github.com/SoftEtherVPN/SoftEtherVPN_Stable/releases/download/v$SOFETHER_VERSION/softether-vpnserver-v$SOFETHER_VERSION-$SOFETHER_DATE-$SOFETHER_ARCH.tar.gz"

# Logging function
log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $*" >> "$LOG_FILE"
    echo "$*"
}

error() {
    log "ERROR: $*"
    exit 1
}

# Check Ubuntu version
check_ubuntu_version() {
    UBUNTU_VERSION=$(lsb_release -rs)
    if [[ "$UBUNTU_VERSION" != "20.04" && "$UBUNTU_VERSION" != "22.04" ]]; then
        error "This script is only for Ubuntu 20.04 or 22.04 LTS."
    fi
    if [[ "$UBUNTU_VERSION" == "20.04" ]]; then
        PHP_VERSION="7.4"
    else
        PHP_VERSION="8.1"
    fi
}

# Install packages idempotently
install_packages() {
    log "Updating system and installing prerequisites..."
    sudo apt update && sudo apt upgrade -y
    PACKAGES="curl wget tar make build-essential lsb-release net-tools apache2-utils iptables-persistent openssl nginx php$PHP_VERSION php$PHP_VERSION-fpm php$PHP_VERSION-cli"
    sudo apt install -y $PACKAGES
}

# Detect public IP (interactive)
detect_public_ip() {
    PUBLIC_IP=$(curl -s ifconfig.me) || error "Failed to detect public IP."
    log "Detected public IP: $PUBLIC_IP"
    read -p "Confirm public IP or enter manually: " -i "$PUBLIC_IP" -e PUBLIC_IP
}

# Prompt for admin credentials
prompt_admin_creds() {
    read -p "Enter admin username for web panel: " ADMIN_USER
    read -s -p "Enter admin password for web panel: " ADMIN_PASS
    echo
}

# Install and configure SoftEther
setup_softether() {
    if [ -d "$SOFETHER_DIR" ]; then
        log "SoftEther already installed, skipping."
        return
    fi

    log "Downloading and installing SoftEther VPN Server..."
    wget "$SOFETHER_URL" -O softether.tar.gz || error "Failed to download SoftEther."
    tar xzf softether.tar.gz
    cd vpnserver
    make i_read_and_agree_the_license_agreement || error "SoftEther build failed."
    sudo mv . "$SOFETHER_DIR"
    cd "$SOFETHER_DIR"
    sudo chmod -R 755 .
}

# Create systemd service for SoftEther
setup_systemd_service() {
    SERVICE_FILE="/etc/systemd/system/vpnserver.service"
    if [ -f "$SERVICE_FILE" ]; then
        log "vpnserver systemd service already exists, skipping."
        return
    fi

    log "Creating systemd service for vpnserver..."
    cat <<EOF | sudo tee "$SERVICE_FILE"
[Unit]
Description=SoftEther VPN Server
After=network.target

[Service]
ExecStart=$SOFETHER_DIR/vpnserver start
ExecStop=$SOFETHER_DIR/vpnserver stop
Type=forking
Restart=always

[Install]
WantedBy=multi-user.target
EOF
    sudo systemctl daemon-reload
    sudo systemctl enable vpnserver
    sudo systemctl start vpnserver
    log "SoftEther VPN Server started."
}

# Configure SoftEther VPN (idempotent)
configure_softether() {
    log "Configuring SoftEther..."
    VPNSERVER="$SOFETHER_DIR/vpncmd /SERVER localhost"
    VPNSERVER_HUB="$VPNSERVER /HUB:VPN"

    # Set no server password
    $VPNSERVER /CMD ServerPasswordSet none

    # Enable SSTP
    $VPNSERVER /CMD SstpEnable yes

    # Create listener on 443 if not exists
    $VPNSERVER /CMD ListenerCreate 443
    $VPNSERVER /CMD ListenerEnable 443

    # Create hub if not exists
    if ! $VPNSERVER /CMD HubList | grep -q "VPN"; then
        $VPNSERVER /CMD HubCreate VPN /PASSWORD:none
    fi

    # Hub configuration
    $VPNSERVER_HUB /CMD DhcpEnable
    $VPNSERVER_HUB /CMD DhcpSet /START:192.168.30.10 /END:192.168.30.200 /MASK:255.255.255.0 /EXPIRE:7200 /GATEWAY:192.168.30.1 /DNS:1.1.1.1 /DNS2:8.8.8.8 /LOG:yes
    $VPNSERVER_HUB /CMD SecureNatDisable
}

# Enable IP forwarding and set iptables
setup_networking() {
    log "Enabling IP forwarding..."
    sudo sysctl -w net.ipv4.ip_forward=1
    if ! grep -q "net.ipv4.ip_forward=1" /etc/sysctl.conf; then
        echo "net.ipv4.ip_forward=1" | sudo tee -a /etc/sysctl.conf
    fi

    log "Setting up iptables NAT rules..."
    sudo iptables -t nat -A POSTROUTING -s 192.168.30.0/24 ! -d 192.168.30.0/24 -j MASQUERADE
    sudo iptables-save | sudo tee /etc/iptables/rules.v4
}

# Generate self-signed SSL certificate
generate_ssl_cert() {
    if [ -f "/etc/ssl/certs/sstp-panel.crt" ]; then
        log "SSL certificate already exists, skipping."
        return
    fi

    log "Generating self-signed SSL certificate for $DOMAIN..."
    sudo mkdir -p /etc/ssl/private /etc/ssl/certs
    sudo openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout /etc/ssl/private/sstp-panel.key -out /etc/ssl/certs/sstp-panel.crt -subj "/CN=$DOMAIN"
    # Comment: To use Let's Encrypt, install certbot: sudo apt install certbot python3-certbot-nginx, then run 'sudo certbot --nginx', and update the Nginx config with the new cert paths.
}

# Configure Nginx and web panel
setup_nginx_and_panel() {
    log "Configuring Nginx for web panel..."
    sudo mkdir -p /var/www/sstp-panel
    sudo chown -R www-data:www-data /var/www/sstp-panel
    sudo chmod -R 755 /var/www/sstp-panel

    # Create .htpasswd
    sudo htpasswd -b -c /etc/nginx/.htpasswd "$ADMIN_USER" "$ADMIN_PASS"

    # Nginx config
    CONFIG_FILE="/etc/nginx/sites-available/sstp-panel"
    cat <<EOF | sudo tee "$CONFIG_FILE"
server {
    listen 8443 ssl;
    server_name $DOMAIN;

    ssl_certificate /etc/ssl/certs/sstp-panel.crt;
    ssl_certificate_key /etc/ssl/private/sstp-panel.key;

    root /var/www/sstp-panel;
    index index.php;

    location / {
        auth_basic "Admin Area";
        auth_basic_user_file /etc/nginx/.htpasswd;
    }

    location ~ \.php$ {
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:/run/php/php$PHP_VERSION-fpm.sock;
    }
}
EOF

    # Enable site if not already
    if [ ! -L /etc/nginx/sites-enabled/sstp-panel ]; then
        sudo ln -s "$CONFIG_FILE" /etc/nginx/sites-enabled/
    fi
    sudo nginx -t || error "Nginx config test failed."
    sudo systemctl restart nginx

    # Create web panel PHP file (idempotent: overwrite if exists)
    log "Creating web panel files..."
    cat <<'EOF' | sudo tee /var/www/sstp-panel/index.php
<?php
// Simple SSTP User Management Panel
// Passwords are set in SoftEther, which stores them hashed internally.

$hub = 'VPN';
$vpncmd = '/usr/local/vpnserver/vpncmd /SERVER localhost /HUB:' . $hub . ' /CMD ';

function exec_cmd($cmd) {
    return shell_exec($vpncmd . $cmd);
}

function get_users() {
    $output = exec_cmd('UserList');
    $lines = explode("\n", $output);
    $users = [];
    $start = false;
    foreach ($lines as $line) {
        if (strpos($line, '----') !== false) {
            $start = !$start;
            continue;
        }
        if ($start && trim($line)) {
            $parts = array_map('trim', explode('|', $line));
            if (count($parts) >= 2) {
                $users[] = $parts[1];
            }
        }
    }
    return $users;
}

function get_user_status($username) {
    $output = exec_cmd('UserGet ' . escapeshellarg($username));
    if (preg_match('/Expires\s*\|\s*(.+)/', $output, $matches)) {
        $expires = trim($matches[1]);
        if ($expires == 'none' || strtotime($expires) > time()) {
            return 'Active';
        } else {
            return 'Inactive';
        }
    }
    return 'Unknown';
}

function generate_password() {
    return bin2hex(random_bytes(8));
}

$action = isset($_GET['action']) ? $_GET['action'] : '';
$user = isset($_GET['user']) ? $_GET['user'] : '';
$message = '';

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    if (isset($_POST['add_user'])) {
        $username = $_POST['username'];
        $password = !empty($_POST['password']) ? $_POST['password'] : generate_password();
        exec_cmd('UserCreate ' . escapeshellarg($username) . ' /GROUP: /REALNAME: /NOTE:');
        exec_cmd('UserPasswordSet ' . escapeshellarg($username) . ' /PASSWORD:' . escapeshellarg($password));
        $message = "User '$username' added with password '$password'.";
    } elseif (isset($_POST['delete_user'])) {
        $username = $_POST['username'];
        exec_cmd('UserDelete ' . escapeshellarg($username));
        $message = "User '$username' deleted.";
    } elseif (isset($_POST['toggle_user'])) {
        $username = $_POST['username'];
        $status = get_user_status($username);
        if ($status == 'Active') {
            exec_cmd('UserExpiresSet ' . escapeshellarg($username) . ' /EXPIRES:"2000/01/01 00:00:00"');
            $message = "User '$username' deactivated.";
        } else {
            exec_cmd('UserExpiresSet ' . escapeshellarg($username) . ' /EXPIRES:none');
            $message = "User '$username' activated.";
        }
    }
}
?>

<!DOCTYPE html>
<html>
<head>
    <title>SSTP User Management Panel</title>
    <style>
        body { font-family: Arial, sans-serif; }
        table { border-collapse: collapse; width: 100%; }
        th, td { border: 1px solid #ddd; padding: 8px; }
        th { background-color: #f2f2f2; }
    </style>
</head>
<body>
    <h1>SSTP User Management</h1>
    <?php if ($message) echo "<p style='color: green;'>$message</p>"; ?>

    <h2>View Users</h2>
    <table>
        <tr><th>Username</th><th>Status</th><th>Actions</th></tr>
        <?php foreach (get_users() as $u): ?>
            <tr>
                <td><?php echo htmlspecialchars($u); ?></td>
                <td><?php echo get_user_status($u); ?></td>
                <td>
                    <form method="post" style="display:inline;" onsubmit="return confirm('Confirm toggle status?');">
                        <input type="hidden" name="username" value="<?php echo htmlspecialchars($u); ?>">
                        <button type="submit" name="toggle_user">Toggle Active</button>
                    </form>
                    <form method="post" style="display:inline;" onsubmit="return confirm('Confirm delete?');">
                        <input type="hidden" name="username" value="<?php echo htmlspecialchars($u); ?>">
                        <button type="submit" name="delete_user">Delete</button>
                    </form>
                </td>
            </tr>
        <?php endforeach; ?>
    </table>

    <h2>Add User</h2>
    <form method="post">
        <label>Username: <input type="text" name="username" required></label><br>
        <label>Password (leave blank for auto-generated): <input type="text" name="password"></label><br>
        <button type="submit" name="add_user">Add User</button>
    </form>
</body>
</html>
EOF
}

# Cleanup temporary files
cleanup() {
    log "Cleaning up temporary files..."
    rm -f softether.tar.gz
    rm -rf vpnserver
}

# Print post-installation summary
print_summary() {
    log "Installation complete!"
    echo "
## Post-Installation Summary

- SSTP Server IP: $PUBLIC_IP (connects on port 443)
- Web Management Panel URL: https://$DOMAIN:8443/
- Admin Credentials: Username: $ADMIN_USER, Password: [the one you set]
- SSTP Service Commands:
  - Start: sudo systemctl start vpnserver
  - Stop: sudo systemctl stop vpnserver
  - Restart: sudo systemctl restart vpnserver
- Sample Client Connection (Windows):
  - GUI: Settings > Network & Internet > VPN > Add a VPN connection > VPN Provider: Windows (built-in), Connection name: MyVPN, Server: $PUBLIC_IP, VPN type: SSTP, Username/Password: [your user creds]
  - CLI: rasdial \"MyVPN\" username password

Note: The web panel uses a self-signed certificate. Ignore browser warnings or replace with Let's Encrypt as commented in the script.
Logs are in $LOG_FILE.
"
}

# Main execution
main() {
    check_ubuntu_version
    install_packages
    detect_public_ip
    prompt_admin_creds
    setup_softether
    setup_systemd_service
    configure_softether
    setup_networking
    generate_ssl_cert
    setup_nginx_and_panel
    cleanup
    print_summary
}

main
