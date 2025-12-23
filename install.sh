#!/usr/bin/env bash
set -euo pipefail

SE_HUB="${SE_HUB:-VPN}"
SE_USER="${SE_USER:-vpn}"
SE_PASS="${SE_PASS:-vpn}"
SE_ADMIN_PASS="${SE_ADMIN_PASS:-}"
SE_PORT="${SE_PORT:-443}"


DEF_SRC_IP="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src"){print $(i+1); exit}}' || true)"
SE_CERT_CN="${SE_CERT_CN:-${DEF_SRC_IP}}"

# Генерим админ-пароль если не задан
if [[ -z "${SE_ADMIN_PASS}" ]]; then
  SE_ADMIN_PASS="$(tr -dc 'A-Za-z0-9' </dev/urandom | head -c 20)"
fi


if [[ "${EUID}" -ne 0 ]]; then
  echo "Run as root."
  exit 1
fi

if ss -lntp | awk '{print $4}' | grep -qE "[:.]${SE_PORT}$"; then
  echo "Port ${SE_PORT}/tcp is busy. Free it first."
  ss -lntp | grep -E "[:.]${SE_PORT} " || true
  exit 1
fi

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y git build-essential libreadline-dev libssl-dev zlib1g-dev \
  ca-certificates openssl unzip


cd /usr/local/src
rm -rf SoftEtherVPN_Stable
git clone --depth 1 https://github.com/SoftEtherVPN/SoftEtherVPN_Stable.git
cd SoftEtherVPN_Stable

./configure
# У SoftEther в этой ветке сборка не в build/, а в корне (у тебя это уже проявилось)
make -j"$(nproc)"


rm -rf /usr/local/vpnserver
mkdir -p /usr/local/vpnserver


cp -a ./bin/vpnserver /usr/local/vpnserver/
cp -a ./bin/vpncmd /usr/local/vpnserver/
chmod 700 /usr/local/vpnserver/vpnserver/vpnserver /usr/local/vpnserver/vpncmd/vpncmd


cat >/etc/systemd/system/vpnserver.service <<'EOF'
[Unit]
Description=SoftEther VPN Server
After=network.target

[Service]
Type=forking
WorkingDirectory=/usr/local/vpnserver/vpnserver
ExecStart=/usr/local/vpnserver/vpnserver/vpnserver start
ExecStop=/usr/local/vpnserver/vpnserver/vpnserver stop
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now vpnserver

VPNCMD="/usr/local/vpnserver/vpncmd/vpncmd"

# ========== Configure SoftEther ==========
# 1) Set server admin password (если его не было, vpncmd спросит "Password:" -> отправляем пустую строку)
printf "\n" | "${VPNCMD}" localhost /SERVER /CMD ServerPasswordSet "${SE_ADMIN_PASS}" >/dev/null

# 2) Create hub if not exists
set +e
"${VPNCMD}" localhost /SERVER /PASSWORD:"${SE_ADMIN_PASS}" /CMD HubCreate "${SE_HUB}" /PASSWORD:"hubpass" >/dev/null 2>&1
set -e

# 3) Create user (idempotent-ish)
set +e
"${VPNCMD}" localhost /SERVER /PASSWORD:"${SE_ADMIN_PASS}" /HUB:"${SE_HUB}" \
  /CMD UserCreate "${SE_USER}" /GROUP:none /REALNAME:none /NOTE:none >/dev/null 2>&1
set -e

"${VPNCMD}" localhost /SERVER /PASSWORD:"${SE_ADMIN_PASS}" /HUB:"${SE_HUB}" \
  /CMD UserPasswordSet "${SE_USER}" /PASSWORD:"${SE_PASS}" >/dev/null

# 4) Enable SecureNAT (интернет “наружу” без твоих iptables)
"${VPNCMD}" localhost /SERVER /PASSWORD:"${SE_ADMIN_PASS}" /HUB:"${SE_HUB}" \
  /CMD SecureNatEnable >/dev/null

# 5) Enable SSTP (TCP/443). Команда есть в vpncmd: SstpEnable yes/no 
"${VPNCMD}" localhost /SERVER /PASSWORD:"${SE_ADMIN_PASS}" /CMD SstpEnable yes >/dev/null

# 6) Regenerate server cert with CN = IP/hostname (важно для Windows SSTP) 
if [[ -n "${SE_CERT_CN}" ]]; then
  "${VPNCMD}" localhost /SERVER /PASSWORD:"${SE_ADMIN_PASS}" /CMD ServerCertRegenerate "${SE_CERT_CN}" >/dev/null
fi

# 7) Export current server cert (самоподписанный) для импорта на Windows
CERT_OUT="/root/softether-server.crt"
openssl s_client -connect 127.0.0.1:"${SE_PORT}" -showcerts </dev/null 2>/dev/null \
  | openssl x509 -outform PEM > "${CERT_OUT}"
chmod 600 "${CERT_OUT}"

echo
echo "================= READY ================="
echo "Welcome to free internet"
echo
echo "Connect (SSTP):"
echo "  Server: ${SE_CERT_CN:-<server-ip>}"
echo "  Port:   ${SE_PORT}"
echo "  User:   ${SE_USER}@${SE_HUB}"
echo "  Pass:   ${SE_PASS}"
echo
echo "Windows cert file (import once): ${CERT_OUT}"
echo "Server admin password: ${SE_ADMIN_PASS}"
echo "========================================"
