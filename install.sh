#!/usr/bin/env bash
set -euo pipefail

APP_NAME="SoftEther SSTP VPN Manager"
STATE_DIR="/root/.softether-sstp"
STATE_FILE="$STATE_DIR/state.env"

SRC_DIR="/usr/local/src/SoftEtherVPN_Stable"
INSTALL_DIR="/usr/local/vpnserver"
VPNCMD="$INSTALL_DIR/vpncmd/vpncmd"
VPNSERVER_BIN="$INSTALL_DIR/vpnserver/vpnserver"

# куда складываем "всё удобно в /root"
ROOT_OUT="/root"

log() { echo "[$(date '+%F %T')] $*"; }
err() { echo "ERROR: $*" >&2; }
die() { err "$*"; exit 1; }

need_root() {
  [ "${EUID:-0}" -eq 0 ] || die "Запусти от root."
}

has_tty() { [ -r /dev/tty ] && [ -w /dev/tty ]; }

read_tty() {
  # read from /dev/tty so curl|bash still works
  local __var="$1"; shift
  local __prompt="${1:-}"
  local __default="${2:-}"
  local __secret="${3:-no}"

  local val=""
  if [ -n "$__prompt" ]; then
    if [ -n "$__default" ]; then
      printf "%s [%s]: " "$__prompt" "$__default" > /dev/tty
    else
      printf "%s: " "$__prompt" > /dev/tty
    fi
  fi

  if [ "$__secret" = "yes" ]; then
    IFS= read -r -s val < /dev/tty || true
    printf "\n" > /dev/tty
  else
    IFS= read -r val < /dev/tty || true
  fi

  if [ -z "$val" ] && [ -n "$__default" ]; then
    val="$__default"
  fi

  printf -v "$__var" "%s" "$val"
}

pause_tty() {
  printf "Нажми Enter..." > /dev/tty
  IFS= read -r _ < /dev/tty || true
}

load_state() {
  if [ -f "$STATE_FILE" ]; then
    # shellcheck disable=SC1090
    source "$STATE_FILE"
  fi
}

save_state() {
  mkdir -p "$STATE_DIR"
  chmod 700 "$STATE_DIR"
  cat > "$STATE_FILE" <<EOF
# auto-generated
SE_HOST=${SE_HOST}
SE_PORT=${SE_PORT}
SE_ADMIN_PASS=${SE_ADMIN_PASS}
SE_HUB=${SE_HUB}
EOF
  chmod 600 "$STATE_FILE"
}

apt_wait() {
  # ждём освобождения dpkg lock
  local lock="/var/lib/dpkg/lock-frontend"
  local lock2="/var/lib/dpkg/lock"
  local i=0

  while fuser "$lock" >/dev/null 2>&1 || fuser "$lock2" >/dev/null 2>&1; do
    i=$((i+1))
    echo "Жду, dpkg занят (unattended-upgrades/apt)... ($i)" > /dev/tty
    sleep 3
  done
}

apt_install() {
  apt_wait
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -y
  apt_wait
  apt-get install -y \
    ca-certificates curl unzip zip \
    git build-essential libreadline-dev libssl-dev zlib1g-dev \
    rsync openssl
}

is_installed() {
  [ -x "$VPNCMD" ] && [ -x "$VPNSERVER_BIN" ] && systemctl list-unit-files | grep -q '^vpnserver\.service'
}

service_install_unit() {
  cat > /etc/systemd/system/vpnserver.service <<'EOF'
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
}

build_and_install_softether() {
  log "Ставлю зависимости..."
  apt_install

  log "Качаю исходники SoftEther..."
  rm -rf "$SRC_DIR"
  mkdir -p "$(dirname "$SRC_DIR")"
  git clone --depth 1 https://github.com/SoftEtherVPN/SoftEtherVPN_Stable.git "$SRC_DIR"

  log "Собираю SoftEther (это не быстро)..."
  ( cd "$SRC_DIR" && ./configure && make -j"$(nproc)" )

  log "Устанавливаю в $INSTALL_DIR ..."
  rm -rf "$INSTALL_DIR"
  mkdir -p "$INSTALL_DIR"

  # официальной "make install" в этом дереве часто нет, копируем bin как ты уже делал
  rsync -a --delete "$SRC_DIR/bin/" "$INSTALL_DIR/"

  chmod 700 "$INSTALL_DIR/vpnserver/vpnserver" "$INSTALL_DIR/vpncmd/vpncmd"

  log "Ставлю systemd unit..."
  service_install_unit

  log "SoftEther поднят."
}

vpncmd() {
  # $1.. args after localhost /SERVER /PASSWORD:...
  local admin="${SE_ADMIN_PASS:?admin pass not set}"
  "$VPNCMD" localhost /SERVER /PASSWORD:"$admin" /CMD "$@"
}

vpncmd_hub() {
  local admin="${SE_ADMIN_PASS:?admin pass not set}"
  local hub="${SE_HUB:?hub not set}"
  "$VPNCMD" localhost /SERVER /PASSWORD:"$admin" /HUB:"$hub" /CMD "$@"
}

get_ddns_hostname() {
  # пытаемся получить SoftEther DDNS hostname
  local out host
  out="$("$VPNCMD" localhost /SERVER /PASSWORD:"$SE_ADMIN_PASS" /CMD DynamicDnsGetStatus 2>/dev/null || true)"
  host="$(echo "$out" | awk -F'|' '/Hostname/ {gsub(/^[ \t]+|[ \t]+$/, "", $2); print $2}' | head -n1)"
  if [ -n "$host" ] && echo "$host" | grep -q '\.'; then
    echo "$host"
    return 0
  fi
  return 1
}

make_selfsigned_cert() {
  local host="$1"
  mkdir -p "$STATE_DIR"
  chmod 700 "$STATE_DIR"

  local cnf="$STATE_DIR/openssl.cnf"
  local crt="$STATE_DIR/server.crt"
  local key="$STATE_DIR/server.key"

  local is_ip="no"
  if echo "$host" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'; then
    is_ip="yes"
  fi

  cat > "$cnf" <<EOF
[req]
prompt = no
distinguished_name = dn
x509_extensions = v3

[dn]
CN = $host

[v3]
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt

[alt]
DNS.1 = $host
EOF

  if [ "$is_ip" = "yes" ]; then
    echo "IP.1 = $host" >> "$cnf"
  fi

  openssl req -x509 -newkey rsa:2048 -nodes -sha256 -days 3650 \
    -keyout "$key" -out "$crt" -config "$cnf" >/dev/null 2>&1

  chmod 600 "$key"
  chmod 644 "$crt"

  echo "$crt"
}

set_server_cert() {
  local crt="$1"
  local key="$2"
  log "Ставлю сертификат в SoftEther (CN = $SE_HOST)..."
  vpncmd ServerCertSet /LOADCERT:"$crt" /LOADKEY:"$key" >/dev/null
  systemctl restart vpnserver
}

listeners_only_443() {
  log "Оставляю слушатель только на TCP/443..."
  vpncmd ListenerCreate 443 >/dev/null 2>&1 || true
  vpncmd ListenerEnable 443 >/dev/null 2>&1 || true

  for p in 992 1194 5555; do
    vpncmd ListenerDisable "$p" >/dev/null 2>&1 || true
    vpncmd ListenerDelete "$p"  >/dev/null 2>&1 || true
  done
}

ensure_hub() {
  log "Проверяю/создаю HUB: $SE_HUB ..."
  # HubCreate ругнётся если существует, нам ок
  vpncmd HubCreate "$SE_HUB" /PASSWORD:"$SE_ADMIN_PASS" >/dev/null 2>&1 || true
}

ensure_user() {
  local u="$1"
  local p="$2"
  log "Создаю/обновляю пользователя: $u ..."
  vpncmd_hub UserCreate "$u" /GROUP:none /REALNAME:none /NOTE:none >/dev/null 2>&1 || true
  vpncmd_hub UserPasswordSet "$u" /PASSWORD:"$p" >/dev/null
}

delete_user() {
  local u="$1"
  log "Удаляю пользователя: $u ..."
  vpncmd_hub UserDelete "$u" >/dev/null
}

enable_securenat() {
  log "Включаю SecureNAT (чтобы был просто интернет)..."
  vpncmd_hub SecureNatEnable >/dev/null 2>&1 || true
}

gen_windows_ps1() {
  local user="$1"
  local pass="$2"
  local hub="$SE_HUB"
  local host="$SE_HOST"
  local port="$SE_PORT"

  local crt="$STATE_DIR/server.crt"
  [ -f "$crt" ] || die "Нет сертификата $crt"

  local cert_b64
  cert_b64="$(base64 -w0 "$crt")"

  local out="$ROOT_OUT/${user}_sstp_windows.ps1"

  cat > "$out" <<EOF
#requires -Version 5.1
# Автогенерация: SoftEther SSTP
# Запускать в PowerShell от имени пользователя (админ не обязателен, импорт в CurrentUser store).

\$Name = "SSTP-${host}-${user}"
\$Server = "${host}"
\$User = "${user}@${hub}"
\$Pass = "${pass}"
\$CertB64 = "${cert_b64}"

Write-Host "Импортирую сертификат в CurrentUser\\\\Root..."
\$bytes = [Convert]::FromBase64String(\$CertB64)
\$crtPath = Join-Path \$env:TEMP "softether_sstp_${host}.cer"
[IO.File]::WriteAllBytes(\$crtPath, \$bytes) | Out-Null
Import-Certificate -FilePath \$crtPath -CertStoreLocation "Cert:\\CurrentUser\\Root" | Out-Null

Write-Host "Создаю VPN-подключение: \$Name"
\$existing = Get-VpnConnection -Name \$Name -ErrorAction SilentlyContinue
if (-not \$existing) {
  Add-VpnConnection -Name \$Name -ServerAddress \$Server -TunnelType Sstp \\
    -AuthenticationMethod Pap,Chap,MSChapv2 -EncryptionLevel Optional \\
    -SplitTunneling \$false -RememberCredential -Force | Out-Null
} else {
  Set-VpnConnection -Name \$Name -ServerAddress \$Server -TunnelType Sstp \\
    -AuthenticationMethod Pap,Chap,MSChapv2 -EncryptionLevel Optional \\
    -SplitTunneling \$false -RememberCredential -Force | Out-Null
}

Write-Host "Пробую подключиться (и тем самым сохранить логин/пароль)..."
rasdial "\$Name" "\$User" "\$Pass" | Out-Host

Write-Host "Если подключилось, можно отключить командой:"
Write-Host "rasdial \"\$Name\" /disconnect"
EOF

  chmod 600 "$out"
  echo "$out"
}

gen_linux_sh() {
  local user="$1"
  local pass="$2"
  local hub="$SE_HUB"
  local host="$SE_HOST"
  local port="$SE_PORT"

  local out="$ROOT_OUT/${user}_sstp_linux.sh"
  local crt="$STATE_DIR/server.crt"

  cat > "$out" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

if [ "${EUID:-0}" -ne 0 ]; then
  echo "Запусти от root (или через sudo)." >&2
  exit 1
fi
EOF

  cat >> "$out" <<EOF

HOST="${host}"
PORT="${port}"
USER="${user}@${hub}"
PASS="${pass}"
CRT_SRC="/root/.softether-sstp/server.crt"
CRT_DST="/usr/local/share/ca-certificates/softether_sstp_${host}.crt"
PIDFILE="/run/sstpc-softether.pid"

apt_wait() {
  while fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1 || fuser /var/lib/dpkg/lock >/dev/null 2>&1; do
    echo "Жду dpkg lock..."
    sleep 3
  done
}

need_pkg() {
  apt_wait
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -y
  apt_wait
  apt-get install -y sstp-client ppp ca-certificates iproute2
}

install_ca() {
  if [ -f "\$CRT_SRC" ]; then
    cp -f "\$CRT_SRC" "\$CRT_DST"
    update-ca-certificates >/dev/null 2>&1 || true
  else
    echo "Не найден \$CRT_SRC. Сертификат не установлен, будет warning." >&2
  fi
}

connect() {
  need_pkg
  install_ca

  echo "Подключаюсь SSTP к \$HOST:\$PORT как \$USER"
  # sstpc сам поднимет ppp и сделает default route (defaultroute)
  # noauth чтобы pppd не требовал локальных секретов
  # usepeerdns чтобы DNS пришёл от SecureNAT (можно выключить если не надо)
  sstpc --log-level 3 --user "\$USER" --password "\$PASS" "\$HOST" \\
    usepeerdns require-mschap-v2 noauth defaultroute \\
    persist \\
    pidfile "\$PIDFILE" \\
    nodetach
}

disconnect() {
  if [ -f "\$PIDFILE" ]; then
    kill "\$(cat "\$PIDFILE")" 2>/dev/null || true
    rm -f "\$PIDFILE"
    echo "Отключено."
  else
    echo "PID не найден, похоже не подключено."
  fi
}

case "\${1:-connect}" in
  connect) connect ;;
  disconnect) disconnect ;;
  *) echo "Usage: \$0 [connect|disconnect]" ; exit 1 ;;
esac
EOF

  chmod 700 "$out"
  echo "$out"
}

print_where() {
  local user="$1"
  echo
  echo "Готово. Файлы лежат тут (как ты любишь, без квестов):"
  echo "  Windows: $ROOT_OUT/${user}_sstp_windows.ps1"
  echo "  Linux:   $ROOT_OUT/${user}_sstp_linux.sh"
  echo "  Cert:    $STATE_DIR/server.crt"
  echo
  echo "Windows: открой PowerShell и запусти .ps1 (лучше от пользователя, не обязательно админ)."
  echo "Linux:    sudo bash $ROOT_OUT/${user}_sstp_linux.sh connect"
  echo "          sudo bash $ROOT_OUT/${user}_sstp_linux.sh disconnect"
  echo
}

do_install_full() {
  load_state

  # Вводим только то, что реально нужно 1 раз, потом хранится в state
  if [ -z "${SE_ADMIN_PASS:-}" ]; then
    read_tty SE_ADMIN_PASS "Пароль администратора SoftEther (запомню)" "" "yes"
    [ -n "$SE_ADMIN_PASS" ] || die "Пароль администратора пустой."
  else
    echo "Использую сохранённый пароль администратора из $STATE_FILE" > /dev/tty
  fi

  read_tty SE_HUB "Имя HUB" "${SE_HUB:-VPN}" "no"
  read_tty SE_PORT "Порт" "${SE_PORT:-443}" "no"

  # Host: сначала попробуем DDNS, если нет - публичный IP
  local detected=""
  if [ -z "${SE_HOST:-}" ]; then
    detected="$(curl -4fsS https://api.ipify.org 2>/dev/null || true)"
    SE_HOST="${detected:-}"
  fi

  # если уже установлен SoftEther, можно сначала настроить DDNS и взять hostname
  if ! is_installed; then
    build_and_install_softether
  fi

  # после поднятия сервера пробуем DDNS hostname
  local ddns=""
  ddns="$(get_ddns_hostname || true)"
  if [ -n "$ddns" ]; then
    SE_HOST="$ddns"
  elif [ -z "$SE_HOST" ]; then
    die "Не смог определить host (ни DDNS, ни публичный IP). Заполни SE_HOST вручную в $STATE_FILE."
  fi

  save_state

  log "Настраиваю сервер (hub/users/securenat/listeners/cert)..."
  vpncmd ServerPasswordSet "$SE_ADMIN_PASS" >/dev/null 2>&1 || true

  ensure_hub
  enable_securenat
  listeners_only_443

  # сертификат под host, чтобы Windows SSTP не плевался
  local crt
  crt="$(make_selfsigned_cert "$SE_HOST")"
  set_server_cert "$crt" "$STATE_DIR/server.key"

  # пользователь
  local u p
  read_tty u "Логин пользователя" "vpn" "no"
  read_tty p "Пароль пользователя" "" "yes"
  [ -n "$p" ] || die "Пароль пользователя пустой."

  ensure_user "$u" "$p"

  # генерим клиентские скрипты
  local w l
  w="$(gen_windows_ps1 "$u" "$p")"
  l="$(gen_linux_sh "$u" "$p")"

  log "Сгенерировано:"
  log "  $w"
  log "  $l"
  print_where "$u"
}

do_add_user() {
  load_state
  is_installed || die "SoftEther не установлен. Сначала пункт 1."
  [ -n "${SE_ADMIN_PASS:-}" ] || die "Нет сохранённого admin pass. Запусти пункт 1."

  local u p
  read_tty u "Логин пользователя" "vpn" "no"
  read_tty p "Пароль пользователя" "" "yes"
  [ -n "$p" ] || die "Пароль пустой."

  ensure_hub
  enable_securenat
  listeners_only_443

  # сертификат если его нет (или если ты удалял state)
  if [ ! -f "$STATE_DIR/server.crt" ] || [ ! -f "$STATE_DIR/server.key" ]; then
    local ddns=""
    ddns="$(get_ddns_hostname || true)"
    if [ -n "$ddns" ]; then SE_HOST="$ddns"; fi
    save_state
    local crt
    crt="$(make_selfsigned_cert "$SE_HOST")"
    set_server_cert "$crt" "$STATE_DIR/server.key"
  fi

  ensure_user "$u" "$p"
  gen_windows_ps1 "$u" "$p" >/dev/null
  gen_linux_sh "$u" "$p" >/dev/null
  print_where "$u"
}

do_del_user() {
  load_state
  is_installed || die "SoftEther не установлен."
  [ -n "${SE_ADMIN_PASS:-}" ] || die "Нет сохранённого admin pass. Запусти пункт 1."

  local u
  read_tty u "Логин пользователя для удаления" "" "no"
  [ -n "$u" ] || die "Логин пустой."

  delete_user "$u"

  rm -f "$ROOT_OUT/${u}_sstp_windows.ps1" "$ROOT_OUT/${u}_sstp_linux.sh" 2>/dev/null || true
  log "Готово. Пользователь удалён, клиентские скрипты (если были) тоже."
}

do_uninstall_all() {
  read_tty ans "Точно удалить ВСЁ? (yes/no)" "no" "no"
  [ "$ans" = "yes" ] || { log "Отмена."; return 0; }

  log "Останавливаю сервис..."
  systemctl disable --now vpnserver >/dev/null 2>&1 || true

  log "Прибиваю процессы на всякий..."
  pkill -f "$VPNSERVER_BIN" >/dev/null 2>&1 || true
  pkill -f "$INSTALL_DIR" >/dev/null 2>&1 || true

  log "Удаляю unit..."
  rm -f /etc/systemd/system/vpnserver.service
  rm -f /etc/systemd/system/multi-user.target.wants/vpnserver.service
  systemctl daemon-reload >/dev/null 2>&1 || true

  log "Удаляю установленный SoftEther..."
  rm -rf "$INSTALL_DIR"

  log "Удаляю исходники сборки..."
  rm -rf "$SRC_DIR"

  log "Удаляю state и клиентские файлы из /root..."
  rm -rf "$STATE_DIR"
  rm -f "$ROOT_OUT/"*_sstp_windows.ps1 "$ROOT_OUT/"*_sstp_linux.sh 2>/dev/null || true

  log "Готово. Всё удалено."
}

menu() {
  while true; do
    cat > /dev/tty <<EOF

$APP_NAME
1) Установить/настроить сервер + создать пользователя + сгенерировать клиенты
2) Добавить пользователя (и сгенерировать клиенты)
3) Удалить пользователя
4) Удалить весь сервис
0) Выход

EOF
    local c
    read_tty c "Выбор" "" "no"
    case "$c" in
      1) do_install_full; pause_tty ;;
      2) do_add_user; pause_tty ;;
      3) do_del_user; pause_tty ;;
      4) do_uninstall_all; pause_tty ;;
      0) exit 0 ;;
      *) echo "Неверный выбор." > /dev/tty ;;
    esac
  done
}

# --- main ---
need_root

# Если запустили без tty (например, cron), меню не имеет смысла
if ! has_tty; then
  die "Нет /dev/tty. Запусти из терминала. Для curl используй: curl ... | bash"
fi

menu
