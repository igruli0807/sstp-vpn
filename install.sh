#!/usr/bin/env bash
set -euo pipefail

VPNROOT="/usr/local/vpnserver"
VPNSRV="$VPNROOT/vpnserver/vpnserver"
VPNCMD="$VPNROOT/vpncmd/vpncmd"
SRCDIR="/usr/local/src/SoftEtherVPN_Stable"
UNIT="/etc/systemd/system/vpnserver.service"
STATE="/etc/softether-sstp.env"

# ----- helpers -----
need_root() { [ "${EUID:-0}" -eq 0 ] || { echo "Run as root"; exit 1; }; }
tty_read() { local var="$1"; local prompt="$2"; read -r -p "$prompt" "$var" < /dev/tty; }
save_state() {
  cat >"$STATE" <<EOF
ADMIN_PASS='${ADMIN_PASS}'
HUB_NAME='${HUB_NAME}'
VPN_USER='${VPN_USER}'
VPN_PASS='${VPN_PASS}'
PUBLIC_HOST='${PUBLIC_HOST}'
EOF
  chmod 600 "$STATE"
}
load_state() { [ -f "$STATE" ] && # shellcheck disable=SC1090
  source "$STATE" || true; }

run_vpncmd_server() {
  # $1.. = command tokens
  "$VPNCMD" localhost /SERVER /PASSWORD:"$ADMIN_PASS" /CMD "$@"
}
run_vpncmd_hub() {
  "$VPNCMD" localhost /SERVER /PASSWORD:"$ADMIN_PASS" /HUB:"$HUB_NAME" /CMD "$@"
}

# ----- actions -----
install_softether() {
  need_root
  apt-get update
  apt-get install -y git build-essential libreadline-dev libssl-dev zlib1g-dev unzip curl ca-certificates

  if [ ! -x "$VPNSRV" ] || [ ! -x "$VPNCMD" ]; then
    rm -rf "$SRCDIR"
    git clone --depth 1 https://github.com/SoftEtherVPN/SoftEtherVPN_Stable.git "$SRCDIR"
    cd "$SRCDIR"
    ./configure
    make -j"$(nproc)"

    mkdir -p "$VPNROOT/vpnserver" "$VPNROOT/vpncmd"
    cp -a "$SRCDIR/bin/vpnserver/"* "$VPNROOT/vpnserver/"
    cp -a "$SRCDIR/bin/vpncmd/"* "$VPNROOT/vpncmd/"
    chmod 700 "$VPNROOT/vpnserver/vpnserver" "$VPNROOT/vpncmd/vpncmd" || true
    chmod 600 "$VPNROOT/vpnserver/"*.key 2>/dev/null || true
  fi

  cat >"$UNIT" <<EOF
[Unit]
Description=SoftEther VPN Server
After=network-online.target
Wants=network-online.target

[Service]
Type=forking
WorkingDirectory=$VPNROOT/vpnserver
ExecStart=$VPNROOT/vpnserver/vpnserver start
ExecStop=$VPNROOT/vpnserver/vpnserver stop
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable --now vpnserver
}

initial_config() {
  need_root
  load_state

  : "${HUB_NAME:=VPN}"

  if [ -z "${ADMIN_PASS:-}" ]; then
    tty_read ADMIN_PASS "Set SoftEther SERVER admin password: "
  fi
  if [ -z "${PUBLIC_HOST:-}" ]; then
    tty_read PUBLIC_HOST "Public host for clients (IP or DNS name): "
  fi
  if [ -z "${VPN_USER:-}" ]; then
    tty_read VPN_USER "VPN username to create: "
  fi
  if [ -z "${VPN_PASS:-}" ]; then
    tty_read VPN_PASS "VPN password for user '$VPN_USER': "
  fi

  # ServerPasswordSet may prompt for old password; if empty, feed newline.
  # Command supports passing new password as parameter. :contentReference[oaicite:2]{index=2}
  echo | "$VPNCMD" localhost /SERVER /CMD ServerPasswordSet "$ADMIN_PASS" >/dev/null

  # make sure hub exists
  run_vpncmd_server HubCreate "$HUB_NAME" /PASSWORD:"hubpass" >/dev/null 2>&1 || true

  # create/update user
  run_vpncmd_hub UserCreate "$VPN_USER" /GROUP:none /REALNAME:none /NOTE:none >/dev/null 2>&1 || true
  run_vpncmd_hub UserPasswordSet "$VPN_USER" /PASSWORD:"$VPN_PASS" >/dev/null

  # enable SecureNAT (gives "just internet" NAT)
  run_vpncmd_hub SecureNatEnable >/dev/null

  # Enable SSTP
  # SSTP uses TCP 443 and needs valid cert for strict clients. :contentReference[oaicite:3]{index=3}
  run_vpncmd_server SstpEnable yes >/dev/null

  # Keep only 443 listener (optional hardening/cleanliness)
  run_vpncmd_server ListenerCreate 443 >/dev/null 2>&1 || true
  run_vpncmd_server ListenerEnable 443 >/dev/null 2>&1 || true
  for p in 5555 992 1194; do
    run_vpncmd_server ListenerDelete "$p" >/dev/null 2>&1 || true
  done

  # regenerate self-signed cert with CN = PUBLIC_HOST (so Windows SSTP won't choke on CN mismatch)
  # ServerCertRegenerate exists in vpncmd manual. :contentReference[oaicite:4]{index=4}
  run_vpncmd_server ServerCertRegenerate /CN:"$PUBLIC_HOST" /O:none /OU:none /C:none /ST:none /L:none >/dev/null 2>&1 || true

  save_state
  echo "OK: server configured (Hub=$HUB_NAME, User=$VPN_USER)"
}

export_clients() {
  need_root
  load_state
  mkdir -p /root/softether-clients

  # Export server cert (X.509) for Windows trust store. :contentReference[oaicite:5]{index=5}
  run_vpncmd_server ServerCertGet /root/softether-clients/server.cer >/dev/null

  cat > /root/softether-clients/windows-sstp.ps1 <<EOF
# Run in PowerShell (not CMD). No admin needed if using CurrentUser store.
\$VpnName = "SSTP-$PUBLIC_HOST"
\$Server  = "$PUBLIC_HOST"
\$User    = "$VPN_USER"
\$Pass    = "$VPN_PASS"
\$CertPath = Join-Path \$PSScriptRoot "server.cer"

# Trust cert (self-signed). If you don't want this, use SoftEther VPN Client instead.
Import-Certificate -FilePath \$CertPath -CertStoreLocation Cert:\\CurrentUser\\Root | Out-Null

# Create SSTP VPN profile
Add-VpnConnection -Name \$VpnName -ServerAddress \$Server -TunnelType SSTP -AuthenticationMethod MSChapv2 -EncryptionLevel Optional -Force | Out-Null

# Connect
rasdial "\$VpnName" "\$User" "\$Pass"
EOF

  cat > /root/softether-clients/linux-sstp.sh <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

SERVER="${1:-}"
USER="${2:-}"
PASS="${3:-}"

if [ -z "$SERVER" ] || [ -z "$USER" ] || [ -z "$PASS" ]; then
  echo "Usage: sudo ./linux-sstp.sh <server> <user> <pass>"
  exit 1
fi

apt-get update
apt-get install -y sstp-client ppp

# --cert-warn disables strict cert checks (matches your 'security doesn't matter' requirement). :contentReference[oaicite:6]{index=6}
sstpc --cert-warn --user "$USER" --password "$PASS" "$SERVER" usepeerdns require-mschap-v2 refuse-eap noipdefault defaultroute
EOF
  chmod +x /root/softether-clients/linux-sstp.sh

  cat > /root/softether-clients/README.txt <<EOF
SERVER: $PUBLIC_HOST
HUB:    $HUB_NAME
USER:   $VPN_USER
PASS:   $VPN_PASS

Windows:
  - Copy folder to PC
  - Run PowerShell: .\\windows-sstp.ps1

Linux:
  sudo ./linux-sstp.sh "$PUBLIC_HOST" "$VPN_USER" "$VPN_PASS"

Android:
  Use any SSTP client app:
    Server: $PUBLIC_HOST
    Username: $VPN_USER
    Password: $VPN_PASS
  If app asks about cert verification: disable verification or import server.cer.
EOF

  (cd /root && zip -r softether-clients.zip softether-clients >/dev/null)
  echo "Client bundle: /root/softether-clients.zip"
  echo "Download it with: scp root@$PUBLIC_HOST:/root/softether-clients.zip ."
}

add_user() {
  need_root
  load_state
  local u p
  tty_read u "New username: "
  tty_read p "Password for '$u': "
  run_vpncmd_hub UserCreate "$u" /GROUP:none /REALNAME:none /NOTE:none >/dev/null 2>&1 || true
  run_vpncmd_hub UserPasswordSet "$u" /PASSWORD:"$p" >/dev/null
  echo "User added: $u"
}

del_user() {
  need_root
  load_state
  local u
  tty_read u "Username to delete: "
  run_vpncmd_hub UserDelete "$u" >/dev/null
  echo "User deleted: $u"
}

uninstall_all() {
  need_root
  systemctl disable --now vpnserver 2>/dev/null || true
  rm -f "$UNIT"
  systemctl daemon-reload || true
  rm -rf "$VPNROOT" "$SRCDIR" /root/softether-clients /root/softether-clients.zip
  rm -f "$STATE"
  echo "Removed SoftEther + configs."
}

menu() {
  load_state
  cat <<'EOF'
1) Install SoftEther + configure SSTP + SecureNAT
2) Add user
3) Delete user
4) Export client bundle (Windows/Linux/Android notes)
5) Uninstall everything
EOF
  local c
  tty_read c "Select: "
  case "$c" in
    1) install_softether; initial_config; export_clients ;;
    2) add_user ;;
    3) del_user ;;
    4) export_clients ;;
    5) uninstall_all ;;
    *) echo "Nope." ;;
  esac
}

case "${1:-menu}" in
  install) install_softether; initial_config; export_clients ;;
  add-user) add_user ;;
  del-user) del_user ;;
  export) export_clients ;;
  uninstall) uninstall_all ;;
  menu|*) menu ;;
esac
