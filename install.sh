#!/usr/bin/env bash
set -euo pipefail

# ====== НАСТРОЙКИ (можно переопределять переменными окружения) ======
HUB_NAME="${HUB_NAME:-VPN}"
VPN_USER="${VPN_USER:-vpn}"
VPN_PASS="${VPN_PASS:-vpn}"
ADMIN_PASS="${ADMIN_PASS:-qwe895388}"
LISTEN_PORT="${LISTEN_PORT:-443}"
# что писать в remote в ovpn (лучше домен или публичный IP)
REMOTE_HOST="${REMOTE_HOST:-}"

# ====== ДЕПСЫ ======
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y git build-essential libreadline-dev libssl-dev zlib1g-dev unzip

# ====== СБОРКА/УСТАНОВКА SoftEther ======
SRC_DIR="/usr/local/src/SoftEtherVPN_Stable"
if [[ ! -d "$SRC_DIR" ]]; then
  git clone --depth 1 https://github.com/SoftEtherVPN/SoftEtherVPN_Stable.git "$SRC_DIR"
fi

cd "$SRC_DIR"
./configure

# сборка иногда просит подтвердить лицензию цифрой. "yes 1" это закрывает.
yes 1 | make -j"$(nproc)"

install -d /usr/local/vpnserver/vpnserver /usr/local/vpnserver/vpncmd
cp -a ./bin/vpnserver/* /usr/local/vpnserver/vpnserver/
cp -a ./bin/vpncmd/* /usr/local/vpnserver/vpncmd/

chmod 700 /usr/local/vpnserver/vpnserver/vpnserver /usr/local/vpnserver/vpncmd/vpncmd

# ====== systemd ======
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

# ====== НАСТРОЙКА SoftEther ======
# пароль администратора сервера
$VPNCMD localhost /SERVER /CMD ServerPasswordSet "$ADMIN_PASS" >/dev/null

# создать HUB (если уже есть — не падаем)
$VPNCMD localhost /SERVER /PASSWORD:"$ADMIN_PASS" /CMD HubCreate "$HUB_NAME" /PASSWORD:"" >/dev/null || true

# создать пользователя + пароль
$VPNCMD localhost /SERVER /PASSWORD:"$ADMIN_PASS" /HUB:"$HUB_NAME" /CMD UserCreate "$VPN_USER" /GROUP:none /REALNAME:none /NOTE:none >/dev/null || true
$VPNCMD localhost /SERVER /PASSWORD:"$ADMIN_PASS" /HUB:"$HUB_NAME" /CMD UserPasswordSet "$VPN_USER" /PASSWORD:"$VPN_PASS" >/dev/null

# включить SecureNAT (чтобы был “просто интернет”)
$VPNCMD localhost /SERVER /PASSWORD:"$ADMIN_PASS" /HUB:"$HUB_NAME" /CMD SecureNatEnable >/dev/null || true

# включить OpenVPN Clone (UDP-порты включатся, но мы будем юзать TCP 443)
$VPNCMD localhost /SERVER /PASSWORD:"$ADMIN_PASS" /CMD OpenVpnEnable yes /PORTS:1194 >/dev/null || true

# ====== СГЕНЕРИТЬ OVPN ZIP ======
WORKDIR="/root/softether-client"
mkdir -p "$WORKDIR"
cd "$WORKDIR"
rm -f ./*.zip 2>/dev/null || true

$VPNCMD localhost /SERVER /PASSWORD:"$ADMIN_PASS" /CMD OpenVpnMakeConfig >/dev/null

ZIP="$(ls -t ./*.zip 2>/dev/null | head -n1 || true)"
if [[ -z "$ZIP" ]]; then
  echo "Не найден zip после OpenVpnMakeConfig. Проверь права/логи SoftEther."
  exit 1
fi

rm -rf "$WORKDIR/unzip"
mkdir -p "$WORKDIR/unzip"
unzip -o "$ZIP" -d "$WORKDIR/unzip" >/dev/null

OVPN="$(find "$WORKDIR/unzip" -name "*openvpn_remote_access_l3*.ovpn" | head -n1 || true)"
if [[ -z "$OVPN" ]]; then
  echo "Не найден L3 ovpn в архиве. Посмотри содержимое: find $WORKDIR/unzip -name '*.ovpn'"
  exit 1
fi

# REMOTE_HOST: если не задан, оставим как есть (потом руками поправишь)
if [[ -n "$REMOTE_HOST" ]]; then
  sed -i -E "s/^remote[[:space:]].*/remote ${REMOTE_HOST} ${LISTEN_PORT}/" "$OVPN"
fi

# ПАТЧ под TCP 443 (самое важное)
sed -i -E 's/^proto[[:space:]].*/proto tcp-client/' "$OVPN"
sed -i -E '/^explicit-exit-notify/d' "$OVPN"

OUT_OVPN="/root/${HUB_NAME}_${VPN_USER}_tcp443.ovpn"
cp -a "$OVPN" "$OUT_OVPN"

echo
echo "=== ГОТОВО ==="
echo "OVPN файл (TCP 443): $OUT_OVPN"
echo "Логин: ${VPN_USER}@${HUB_NAME}"
echo "Пароль: ${VPN_PASS}"
echo
echo "Если remote не тот — открой $OUT_OVPN и пропиши: remote <IP_или_домен_сервера> 443"

