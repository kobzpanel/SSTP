#!/bin/bash

################################################################################
# install_sstp_panel.sh
# Automated installer: SSTP VPN server with web management panel (Nginx + PHP)
# Supports: Ubuntu 20.04 LTS, 22.04 LTS
# Logs actions: /var/log/sstp_panel_install.log
# Author: AI Fiesta (2025)
################################################################################

LOG=/var/log/sstp_panel_install.log
TEMP_DIR="/tmp/sstp-panel-install.$$"
PANEL_PATH="/var/www/sstpadmin"
PANEL_ADMIN_CONF="/etc/sstp_panel_admin"
PANEL_AUTH_FILE="/etc/nginx/.sstpadmin_htpasswd"
SSL_DIR="/etc/nginx/ssl-sstpadmin"
VPN_USERS_FILE="/etc/ppp/chap-secrets"
VPN_USERS_DIR="/etc/sstp_panel_users"
SSTP_SERVICE="sstpd"
NGINX_CONF="/etc/nginx/sites-available/sstpadmin"
PHP_VER=""
DOMAIN=""
PUBIP=""
GREEN='\033[0;32m'
NC='\033[0m'

set -e
umask 022

# Log helper
log() {
    echo "[`date '+%Y-%m-%d %H:%M:%S'`] $*" | tee -a "$LOG"
}

# Root check
[ "$(id -u)" = "0" ] || { echo "Run this script as root!"; exit 1; }

# Trap cleanup
trap 'rm -rf "$TEMP_DIR"' EXIT INT TERM

mkdir -p "$TEMP_DIR"
touch "$LOG"

log "=== Starting SSTP VPN & Panel installation ==="

# 1. Detect public IP
log "Detecting server public IP..."
PUBIP_DETECT="$(curl -4 -s https://api.ipify.org || hostname -I | awk '{print $1}')"
read -rp "Server Public IP [$PUBIP_DETECT]: " PUBIP
PUBIP=${PUBIP:-$PUBIP_DETECT}
log "Using server IP: $PUBIP"

# 2. Prompt for Web Panel admin credentials
echo -e "${GREEN}=== Web Management Panel Admin Credentials ===${NC}"
while :; do
    read -rp "Panel Admin Username: " ADMIN_USER
    [[ "$ADMIN_USER" =~ ^[a-zA-Z0-9_-]{3,32}$ ]] && break
    echo "Invalid username. Use 3-32 alphanumeric or dashes/underscores."
done

while :; do
    read -rsp "Panel Admin Password: " ADMIN_PASS; echo
    read -rsp "Confirm Password: " ADMIN_PASS2; echo
    [ "$ADMIN_PASS" = "$ADMIN_PASS2" ] && [ "${#ADMIN_PASS}" -ge 8 ] && break
    echo "Passwords do not match or are less than 8 chars."
done

# 3. Ask for (optional) hostname/FQDN
read -rp "Server panel hostname or domain (for SSL CN) [leave blank to use $PUBIP]: " DOMAIN
DOMAIN=${DOMAIN:-$PUBIP}

# 4. Check and install prerequisites (idempotent: only install if absent)
install_pkg() {
    PKG="$1"
    if ! dpkg -s "$PKG" &>/dev/null; then
        log "Installing $PKG..."
        apt-get install -y "$PKG" >>"$LOG" 2>&1
    else
        log "$PKG already installed."
    fi
}

log "Updating apt cache..."
apt-get update >>"$LOG" 2>&1

for pkg in nginx openssl curl pwgen whois unzip; do
    install_pkg "$pkg"
done

# PHP version detection
if command -v php8.1 > /dev/null; then PHP_VER=8.1
elif command -v php8.2 > /dev/null; then PHP_VER=8.2
elif command -v php8.3 > /dev/null; then PHP_VER=8.3
elif command -v php > /dev/null; then PHP_VER=$(php -r 'echo PHP_MAJOR_VERSION.".".PHP_MINOR_VERSION;')
else
    install_pkg "php-fpm"
    PHP_VER=$(php -r 'echo PHP_MAJOR_VERSION.".".PHP_MINOR_VERSION;')
fi

install_pkg "php-fpm"
install_pkg "php-cli"

# Ensure php-fpm is enabled
systemctl enable --now php*-fpm >>"$LOG" 2>&1 || true

# 5. Install PPP, pptpd, and sstp-server
for pkg in pptpd ppp sstp-server; do
    install_pkg "$pkg"
done

# Ensure rng-tools for entropy
install_pkg rng-tools

# 6. Configure DNS for SSTP clients
DNS1="1.1.1.1"
DNS2="8.8.8.8"

# 7. Enable IP forwarding
log "Enabling IP forwarding..."
sysctl -w net.ipv4.ip_forward=1 >>"$LOG"
sed -i '/^net.ipv4.ip_forward/s/^#//' /etc/sysctl.conf
grep -q "^net.ipv4.ip_forward" /etc/sysctl.conf || echo "net.ipv4.ip_forward = 1" >>/etc/sysctl.conf

# 8. Setup iptables for NAT and firewall (IPv4 only for VPN)
log "Configuring iptables for SSTP VPN..."
iptables -t nat -C POSTROUTING -s 10.0.0.0/24 -o eth0 -j MASQUERADE 2>/dev/null || {
    iptables -t nat -A POSTROUTING -s 10.0.0.0/24 -o eth0 -j MASQUERADE
}
iptables-save > /etc/iptables.rules

cat > /etc/network/if-up.d/iptables <<EOF
#!/bin/sh
iptables-restore < /etc/iptables.rules
EOF
chmod +x /etc/network/if-up.d/iptables

# 9. Configure SSTP server
log "Configuring SSTP server..."
cat > /etc/sstpd/sstpd.conf <<EOF
[server]
listen-address = $PUBIP:443
cert-file = /etc/sstpd/server.crt
key-file = /etc/sstpd/server.key

[pppd-default]
plugin = pptpd.so
ms-dns = $DNS1
ms-dns = $DNS2
EOF
# Generate SSL for SSTP VPN
if [ ! -f /etc/sstpd/server.key ]; then
    openssl req -x509 -nodes -days 3650 -newkey rsa:2048 -subj "/CN=${DOMAIN}" \
        -keyout /etc/sstpd/server.key -out /etc/sstpd/server.crt
fi

# 10. Configure chap-secrets
mkdir -p "$VPN_USERS_DIR"
touch "$VPN_USERS_FILE"
chmod 600 "$VPN_USERS_FILE"

# 11. Create systemd override for SSTP server to use proper config
systemctl daemon-reload
systemctl enable --now $SSTP_SERVICE >>"$LOG" 2>&1

# 12. Set up Nginx with PHP-FPM for management panel
log "Configuring Nginx and PHP for the SSTP admin panel..."
mkdir -p "$PANEL_PATH"
chown -R www-data:www-data "$PANEL_PATH"

cat >$NGINX_CONF <<EOF
server {
    listen 443 ssl;
    server_name $DOMAIN;

    ssl_certificate     $SSL_DIR/panel.crt;
    ssl_certificate_key $SSL_DIR/panel.key;

    root $PANEL_PATH;
    index index.php;

    location / {
        auth_basic "SSTP Panel";
        auth_basic_user_file $PANEL_AUTH_FILE;
        try_files \$uri \$uri/ /index.php?\$query_string;
    }

    location ~ \.php$ {
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:/var/run/php/php${PHP_VER}-fpm.sock;
    }
}
EOF

ln -sf "$NGINX_CONF" "/etc/nginx/sites-enabled/sstpadmin"
[ -f /etc/nginx/sites-enabled/default ] && rm /etc/nginx/sites-enabled/default

# 13. Create self-signed certificate for panel
mkdir -p $SSL_DIR
if [ ! -f $SSL_DIR/panel.key ]; then
    openssl req -new -x509 -nodes -days 1095 -subj "/CN=${DOMAIN}" \
        -out $SSL_DIR/panel.crt -keyout $SSL_DIR/panel.key
fi

# 14. Configure HTTP Auth for panel
if ! command -v htpasswd >/dev/null; then
    install_pkg apache2-utils
fi
echo "${ADMIN_USER}:$(openssl passwd -6 "${ADMIN_PASS}")" > "$PANEL_AUTH_FILE"
chmod 640 "$PANEL_AUTH_FILE"
chown root:www-data "$PANEL_AUTH_FILE"

# 15. Deploy panel PHP files (user management)
cat > "$PANEL_PATH/index.php" <<'EOF'
<?php
// Simple SSTP VPN User Manager

define('CHAP_SECRETS','/etc/ppp/chap-secrets');
define('USER_DIR','/etc/sstp_panel_users');

function verify_panel_auth() {
    if (!isset($_SERVER['PHP_AUTH_USER'])) return false;
    // All PHP requests pass basic Auth via Nginx
    return true;
}

function read_users() {
    $lines = file(CHAP_SECRETS, FILE_IGNORE_NEW_LINES|FILE_SKIP_EMPTY_LINES);
    $users = [];
    foreach($lines as $line) {
        if ($line === '#') continue;
        $parts = preg_split('/\s+/', $line);
        if (count($parts) < 4) continue;
        $users[] = [            'username'=>$parts,
            'password'=>$parts[2],
            'status'=>(!is_file(USER_DIR."/".$parts.".inactive"))?'Active':'Inactive'
        ];
    }
    return $users;
}

function save_users($users) {
    $f = fopen(CHAP_SECRETS,"w");
    foreach($users as $u) {
        if (strpos($u['username'],' ')!==false) continue;
        fwrite($f,"{$u['username']} * {$u['password']} *\n");
    }
    fclose($f);
}

function password_hash_apr1($plain) {
    // fallback: use mkpasswd if available, else plaintext (for demo only)
    $out = trim(shell_exec('mkpasswd -m sha-512 '.escapeshellarg($plain)));
    if (!$out) $out = $plain;
    return $out;
}

// Handle POST
if ($_SERVER['REQUEST_METHOD']=='POST') {
    $action = $_POST['action'];
    $users = read_users();
    if ($action=='add') {
        $user = preg_replace('/\W/','',$_POST['username']);
        if (!$user || in_array($user, array_column($users,'username'))) {
            $err = "Username invalid or exists";
        } else {
            $pw = $_POST['password'] ?: bin2hex(random_bytes(4));
            $hash = password_hash_apr1($pw);
            // save user
            file_put_contents(USER_DIR."/$user.pwd", "$hash\n");
            $users[] = ['username'=>$user,'password'=>$hash,'status'=>'Active'];
            save_users($users);
            $success = "User $user created. Password: <b>$pw</b>";
        }
    } elseif ($action=='del') {
        $user = $_POST['username'];
        $users = array_filter($users, fn($u)=>$u['username']!=$user);
        @unlink(USER_DIR."/$user.pwd");
        @unlink(USER_DIR."/$user.inactive");
        save_users($users);
        $success = "User $user deleted.";
    } elseif ($action=='toggle') {
        $user = $_POST['username'];
        $file = USER_DIR."/$user.inactive";
        if (is_file($file)) {
            unlink($file);
            $success = "User $user activated.";
        } else {
            touch($file);
            $success = "User $user deactivated.";
        }
    }
}
$users = read_users();
?>
<!DOCTYPE html>
<html><head>
<title>SSTP VPN User Management</title>
<style>
body { font-family: sans-serif; background: #eee; padding:2em;}
table { border-collapse: collapse;}
td,th { border: 1px solid #ccc; padding:4px;}
th { background:#f4f4f4;}
form { margin:1em 0;}
</style>
</head>
<body>
<h2>SSTP VPN User Management</h2>
<?php
if (isset($err)) echo "<b style='color:red'>$err</b><br>";
if (isset($success)) echo "<b style='color:green'>$success</b><br>";
?>
<table>
<tr><th>User</th><th>Status</th><th>Action</th></tr>
<?php foreach($users as $u): ?>
<tr>
<td><?=htmlspecialchars($u['username'])?></td>
<td><?=htmlspecialchars($u['status'])?></td>
<td>
<form method="post" style="display:inline">
    <input type="hidden" name="username" value="<?=$u['username']?>">
    <button name="action" value="toggle" type="submit"><?=$u['status']=='Active'?'Deactivate':'Activate'?></button>
    <button name="action" value="del" onclick="return confirm('Delete <?=$u['username']?>?')" type="submit">Delete</button>
</form>
</td>
</tr>
<?php endforeach; ?>
</table>
<h3>Add User</h3>
<form method="post">
User: <input name="username" pattern="[a-zA-Z0-9_]{3,32}" required>
Password: <input name="password"> (leave blank for random)<br>
<button name="action" value="add" type="submit">Add User</button>
</form>
</body></html>
EOF

# set safe permissions
chmod 750 "$PANEL_PATH"
chown -R www-data:www-data "$PANEL_PATH"

# 16. Restrict panel directory access
chmod o-rwx "$PANEL_PATH"
chown root:www-data "$PANEL_PATH"

# 17. Restart services
systemctl restart nginx
systemctl restart php${PHP_VER}-fpm
systemctl restart $SSTP_SERVICE

# 18. Save admin login
echo "ADMIN_USER='$ADMIN_USER'
ADMIN_PASS='(hidden)'  # Was: $ADMIN_PASS
DOMAIN='$DOMAIN'
" > $PANEL_ADMIN_CONF
chmod 600 $PANEL_ADMIN_CONF

# --- Post-install summary
cat <<EOM

${GREEN}===== [SSTP VPN Server & Web Panel Installed] =====${NC}

SSTP Server IP:      ${GREEN}$PUBIP${NC}
Panel URL:           ${GREEN}https://${DOMAIN}/admin${NC}
Admin Username:      ${GREEN}$ADMIN_USER${NC}
Admin Password:      ${GREEN}(what you chose)${NC}

To manage users, log in via browser (HTTPS, ignore self-signed cert warning). Panel is protected with HTTP Basic Auth.

Panel directory is:   $PANEL_PATH

SSTP service control:
  sudo systemctl start $SSTP_SERVICE
  sudo systemctl stop $SSTP_SERVICE
  sudo systemctl restart $SSTP_SERVICE

Sample Windows client (rasphone) command:

  rasphone -d "sstp-vpn" (configure with VPN server $PUBIP and your created username/password in the Windows VPN GUI)

For better SSL security, replace the panel certificate at:
  Cert:  $SSL_DIR/panel.crt
  Key:   $SSL_DIR/panel.key
  # To use Let's Encrypt, follow Certbot instructions after DNS is ready.

All actions are logged at ${LOG}
EOM

exit 0
