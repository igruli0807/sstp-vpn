#!/usr/bin/env bash
set -Eeuo pipefail

# SoftEther SSTP VPN (TCP/443) installer/manager for Debian/Ubuntu
# - Interactive menu
# - Non-interactive flags:
#   --install --host <PUBLIC_HOST_OR_IP> --adminpass <PASS> --user <VPN_USER> --pass <VPN_PASS>
#   --add-user --user <VPN_USER> --pass <VPN_PASS>
#   --del-user --user <VPN_USER>
#   --uninstall
#
# Creates client bundle:
#   /root/softether-clients.zip  (Windows PowerShell + Linux bash + server.cer)
#
# Notes:
# - Uses self-signed cert (server.cer) and imports it on Windows to avoid SSTP trust errors.
# - Security intentionally minimal.

SCRIPT_NAME="$(basename "$0")"
STATE_DIR="/etc/softether-sstp-vpn"
STATE_FILE="${STATE_DIR}/state.env"

SRC_DIR="/usr/local/src/SoftEtherVPN_Stable"
INSTALL_BASE="/usr/local/vpnserver"
VPNCMD_BIN="${INSTALL_BASE}/vpncmd/vpncmd"
VPNSERVER_BIN="${INSTALL_BASE}/vpnserver/vpnserver"

HUB_NAME_DEFAULT="VPN"
VPN_PORT_DEFAULT="443"
VPN_CONN_NAME_DEFAULT="SoftEther-SSTP"

CLIENT_WORKDIR="/root/softether-clients"
CLIENT_ZIP="/root/softether-clients.zip"

PUBLIC_HOST="${PUBLIC_HOST:-}"
ADMIN_PASS="${ADMIN_PASS:-}"
HUB_NAME="${HUB_NAME:-$HUB_NAME_DEFAULT}"
VPN_PORT="${VPN_PORT:-$VPN_PORT_DEFAULT}"
VPN_CONN_NAME="${VPN_CONN_NAME:-$VPN_CONN_NAME_DEFAULT}"

# -------- helpers --------
log() { echo -e "[*] $*"; }
warn() { echo -e "[!] $*" >&2; }
die() { echo -e "[x] $*" >&2; exit 1; }

need_root() {
  [[ "${EUID:-$(id -u)}" -eq 0 ]] || die "Запусти от root."
}

cmd_exists() { command -v "$1" >/dev/null 2>&1; }

os_check() {
  if [[ -r /etc/os-release ]]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    case "${ID:-}" in
      debian|ubuntu) : ;;
      *) warn "Не Debian/Ubuntu. Пытаюсь работать, но гарантии нет." ;;
    esac
  fi
}

apt_install() {
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -y
  apt-get install -y --no-install-recommends "$@"
}

save_state() {
  mkdir -p "$STATE_DIR"
  chmod 700 "$STATE_DIR"
  cat >"$STATE_FILE" <<EOF
PUBLIC_HOST=${PUBLIC_HOST}
ADMIN_PASS=${ADMIN_PASS}
HUB_NAME=${HUB_NAME}
VPN_PORT=${VPN_PORT}
VPN_CONN_NAME=${VPN_CONN_NAME}
EOF
  chmod 600 "$STATE_FILE"
}

load_state() {
  if [[ -f "$STATE_FILE" ]]; then
    # shellcheck disable=SC1090
    . "$STATE_FILE"
  fi
}

check_443_free_or_ours() {
  # If something else listens on 443, abort.
  # If vpnserver already listens, ok.
  local line
  line="$(ss -lntp 2>/dev/null | awk '$4 ~ /:443$/ {print}' || true)"
  if [[ -n "$line" ]]; then
    if echo "$line" | grep -q "vpnserver"; then
      return 0
    fi
    die "Порт 443 уже занят другим сервисом:\n$line\nОсвободи 443 или меняй порт (но ты просил 443)."
  fi
}

vpncmd_server() {
  # Requires ADMIN_PASS set
  "$VPNCMD_BIN" localhost /SERVER /PASSWORD:"$ADMIN_PASS" /CMD "$@"
}

vpncmd_hub() {
  # Requires ADMIN_PASS and HUB_NAME set
  "$VPNCMD_BIN" localhost /SERVER /PASSWORD:"$ADMIN_PASS" /HUB:"$HUB_NAME" /CMD "$@"
}

vpncmd_try_server() {
  set +e
  vpncmd_server "$@" >/dev/null 2>&1
  local rc=$?
  set -e
  return $rc
}

ensure_build_tools() {
  log "Ставлю зависимости..."
  apt_install ca-certificates curl git build-essential libreadline-dev libssl-dev zlib1g-dev unzip zip openssl ppp
}

clone_or_update_softether() {
  mkdir -p /usr/local/src
  if [[ -d "$SRC_DIR/.git" ]]; then
    log "Обновляю исходники SoftEther..."
    git -C "$SRC_DIR" fetch --depth 1 origin
    git -C "$SRC_DIR" reset --hard origin/master
  else
    log "Клонирую SoftEther..."
    git clone --depth 1 https://github.com/SoftEtherVPN/SoftEtherVPN_Stable.git "$SRC_DIR"
  fi
}

build_softether() {
  log "Собираю SoftEther..."
  cd "$SRC_DIR"

  ./configure >/dev/null

  # Different trees build differently. Try build/ first, else root.
  if [[ -f build/Makefile ]]; then
    # SoftEther make asks license acceptance; feed "1" repeatedly.
    yes 1 | make -C build
  else
    yes 1 | make
  fi

  # Validate artifacts
  if [[ ! -x ./bin/vpnserver/vpnserver || ! -x ./bin/vpncmd/vpncmd ]]; then
    die "Сборка не дала bin/vpnserver/vpnserver и bin/vpncmd/vpncmd. Проверь логи make."
  fi

  log "Устанавливаю в ${INSTALL_BASE}..."
  mkdir -p "$INSTALL_BASE"
  rm -rf "${INSTALL_BASE}/vpnserver" "${INSTALL_BASE}/vpncmd" "${INSTALL_BASE}/vpnclient" "${INSTALL_BASE}/vpnbridge" 2>/dev/null || true
  cp -a ./bin/vpnserver ./bin/vpncmd ./bin/vpnclient ./bin/vpnbridge "$INSTALL_BASE/"

  chmod 700 "${INSTALL_BASE}/vpnserver/vpnserver" "${INSTALL_BASE}/vpncmd/vpncmd"
}

install_systemd_service() {
  log "Создаю systemd unit vpnserver.service..."
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
  systemctl status vpnserver --no-pager -l >/dev/null || true
}

set_admin_password_first_time() {
  # If password already works, do nothing.
  if vpncmd_try_server HubList; then
    return 0
  fi

  log "Ставлю admin пароль на SoftEther (первичная настройка)..."
  # When password not set, vpncmd prompts "Password:"; send empty line.
  # Then set new password.
  echo | "$VPNCMD_BIN" localhost /SERVER /CMD ServerPasswordSet "$ADMIN_PASS" >/dev/null
}

ensure_hub_exists() {
  if vpncmd_server HubList | grep -qE "^Virtual Hub Name[[:space:]]+\|${HUB_NAME}\$"; then
    return 0
  fi
  log "Создаю HUB: ${HUB_NAME}"
  vpncmd_server HubCreate "$HUB_NAME" /PASSWORD:"hubpass" >/dev/null
}

enable_sstp_and_listener() {
  log "Включаю SSTP и listener ${VPN_PORT}/tcp"
  vpncmd_server SstpEnable yes >/dev/null || true

  # Make sure listener exists and enabled
  vpncmd_server ListenerCreate "$VPN_PORT" >/dev/null 2>&1 || true
  vpncmd_server ListenerEnable "$VPN_PORT" >/dev/null 2>&1 || true

  # Disable/delete other common listeners (optional cleanup)
  for p in 5555 992 1194; do
    vpncmd_server ListenerDisable "$p" >/dev/null 2>&1 || true
    vpncmd_server ListenerDelete "$p" >/dev/null 2>&1 || true
  done
}

enable_securenat() {
  log "Включаю SecureNAT (интернет через VPN, без построения сети)"
  vpncmd_hub SecureNatEnable >/dev/null 2>&1 || true
}

generate_and_set_cert() {
  # Self-signed cert for SSTP trust
  # If PUBLIC_HOST is IP, CN=IP. If domain, CN=domain.
  local cert_dir="/root/softether-cert"
  mkdir -p "$cert_dir"
  chmod 700 "$cert_dir"

  log "Генерирую самоподписанный сертификат CN=${PUBLIC_HOST}"
  openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout "${cert_dir}/server.key" \
    -out "${cert_dir}/server.crt" \
    -days 3650 \
    -subj "/CN=${PUBLIC_HOST}" >/dev/null 2>&1

  # DER for Windows import
  openssl x509 -in "${cert_dir}/server.crt" -outform der -out "${cert_dir}/server.cer" >/dev/null 2>&1

  # Apply to SoftEther if supported
  # Some builds support ServerCertSet /LOADCERT /LOADKEY.
  if vpncmd_try_server ServerCertSet /LOADCERT:"${cert_dir}/server.crt" /LOADKEY:"${cert_dir}/server.key"; then
    log "Сертификат установлен в SoftEther через ServerCertSet."
  else
    warn "Команда ServerCertSet не сработала (возможно другая версия). Продолжаю: SSTP может работать и с авто-сертом."
    warn "Если будут проблемы с CN/сертом, ставь вручную через vpncmd HELP ServerCertSet."
  fi
}

add_user() {
  local user="$1"
  local pass="$2"
  log "Создаю/обновляю пользователя: ${user}"
  vpncmd_hub UserCreate "$user" /GROUP:none /REALNAME:none /NOTE:none >/dev/null 2>&1 || true
  vpncmd_hub UserPasswordSet "$user" /PASSWORD:"$pass" >/dev/null
}

del_user() {
  local user="$1"
  log "Удаляю пользователя: ${user}"
  vpncmd_hub UserDelete "$user" >/dev/null
}

generate_clients_bundle() {
  local user="$1"
  local pass="$2"
  local out_zip="$3"

  rm -rf "$CLIENT_WORKDIR"
  mkdir -p "$CLIENT_WORKDIR"
  chmod 700 "$CLIENT_WORKDIR"

  # Copy cert
  local cert_dir="/root/softether-cert"
  if [[ -f "${cert_dir}/server.cer" ]]; then
    cp -a "${cert_dir}/server.cer" "${CLIENT_WORKDIR}/server.cer"
  else
    warn "Не нашёл server.cer. Генерю сейчас."
    generate_and_set_cert
    [[ -f "${cert_dir}/server.cer" ]] && cp -a "${cert_dir}/server.cer" "${CLIENT_WORKDIR}/server.cer" || true
  fi

  # Windows PowerShell script (built-in SSTP)
  cat > "${CLIENT_WORKDIR}/windows_sstp.ps1" <<EOF
#requires -RunAsAdministrator
\$ErrorActionPreference = "Stop"

\$Server = "${PUBLIC_HOST}"
\$Name   = "${VPN_CONN_NAME}"
\$User   = "${user}"
\$Pass   = "${pass}"

# Import server cert (self-signed) to CurrentUser Trusted Root
\$certPath = Join-Path \$PSScriptRoot "server.cer"
if (Test-Path \$certPath) {
  try {
    Import-Certificate -FilePath \$certPath -CertStoreLocation "Cert:\\CurrentUser\\Root" | Out-Null
  } catch {
    Write-Host "Не смог импортировать сертификат в CurrentUser\\Root: \$($_.Exception.Message)"
  }
} else {
  Write-Host "server.cer не найден рядом со скриптом. SSTP может ругаться на доверие."
}

# Create VPN connection if not exists
\$exists = Get-VpnConnection -Name \$Name -AllUserConnection -ErrorAction SilentlyContinue
if (-not \$exists) {
  # per-machine connection (AllUserConnection)
  Add-VpnConnection -Name \$Name -ServerAddress \$Server -TunnelType Sstp `
    -EncryptionLevel Optional -AuthenticationMethod Pap,MSChapv2 `
    -RememberCredential -AllUserConnection -Force | Out-Null
}

# Connect (credentials are provided here; many Windows builds then remember them due to -RememberCredential)
Write-Host "Connecting to \$Name (\$Server) ..."
rasdial "\$Name" "\$User" "\$Pass" | Out-Host

Write-Host ""
Write-Host "Disconnect: rasdial '\$Name' /disconnect"
EOF

  # Linux script (sstp-client)
  cat > "${CLIENT_WORKDIR}/linux_sstp.sh" <<EOF
#!/usr/bin/env bash
set -Eeuo pipefail

SERVER="${PUBLIC_HOST}"
USER="${user}"
PASS="${pass}"

if [[ "\${EUID:-\$(id -u)}" -ne 0 ]]; then
  echo "Run as root (sudo)." >&2
  exit 1
fi

export DEBIAN_FRONTEND=noninteractive
apt-get update -y >/dev/null
apt-get install -y --no-install-recommends sstp-client ppp ca-certificates >/dev/null

echo "[*] Connecting SSTP to \${SERVER} ..."
echo "[*] Stop with Ctrl+C"

# cert-warn: ignore cert verification (you said speed > security)
# usepeerdns: get DNS
# defaultroute: route all traffic via VPN
sstpc --cert-warn --user "\${USER}" --password "\${PASS}" "\${SERVER}" usepeerdns defaultroute noipdefault
EOF
  chmod +x "${CLIENT_WORKDIR}/linux_sstp.sh"

  cat > "${CLIENT_WORKDIR}/README_CLIENTS.txt" <<EOF
SoftEther SSTP Clients

Windows:
- Run windows_sstp.ps1 as Administrator (PowerShell)
  It imports server.cer into CurrentUser\\Root and creates SSTP VPN connection.
  Then connects via rasdial.

Linux (Debian/Ubuntu):
- sudo ./linux_sstp.sh
  Installs sstp-client and connects.

Server:
- ${PUBLIC_HOST}:${VPN_PORT}/tcp
User:
- ${user}
EOF

  rm -f "$out_zip"
  (cd "$CLIENT_WORKDIR" && zip -r "$out_zip" . >/dev/null)
  ln -sf "$out_zip" "$CLIENT_ZIP" 2>/dev/null || true

  log "Клиентский архив готов: ${out_zip}"
  log "Скачать на ПК: scp root@${PUBLIC_HOST}:${out_zip} ."
}

uninstall_all() {
  warn "Удаляю сервис SoftEther VPN..."
  systemctl disable --now vpnserver >/dev/null 2>&1 || true
  rm -f /etc/systemd/system/vpnserver.service
  systemctl daemon-reload >/dev/null 2>&1 || true

  rm -rf "$INSTALL_BASE" /root/softether-cert "$CLIENT_WORKDIR" "$CLIENT_ZIP" "$STATE_DIR"
  warn "Готово. Остались только пакеты (git/build-essential и т.п.) если хочешь чистить вручную."
}

# -------- interactive prompts --------
prompt_nonempty() {
  local var_name="$1"
  local prompt="$2"
  local default="${3:-}"
  local value=""
  while true; do
    if [[ -n "$default" ]]; then
      read -r -p "${prompt} [${default}]: " value
      value="${value:-$default}"
    else
      read -r -p "${prompt}: " value
    fi
    [[ -n "$value" ]] && break
    echo "Пусто нельзя."
  done
  printf -v "$var_name" '%s' "$value"
}

prompt_secret() {
  local var_name="$1"
  local prompt="$2"
  local value=""
  while true; do
    read -r -s -p "${prompt}: " value
    echo
    [[ -n "$value" ]] && break
    echo "Пусто нельзя."
  done
  printf -v "$var_name" '%s' "$value"
}

# -------- actions --------
do_install() {
  load_state

  check_443_free_or_ours

  if [[ -z "$PUBLIC_HOST" ]]; then
    # Try to auto-detect public IP, but don't depend on it.
    local guess=""
    guess="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '/src/ {print $7; exit}' || true)"
    prompt_nonempty PUBLIC_HOST "Публичный IP/домен для подключения клиентов (CN сертификата)" "${guess:-}"
  fi

  if [[ -z "$ADMIN_PASS" ]]; then
    prompt_secret ADMIN_PASS "Admin пароль SoftEther (будет сохранён в ${STATE_FILE} с chmod 600)"
  fi

  os_check
  ensure_build_tools
  clone_or_update_softether
  build_softether
  install_systemd_service

  # Configure
  set_admin_password_first_time

  # Verify we can auth with saved password
  if ! vpncmd_try_server HubList; then
    die "Не могу подключиться vpncmd с ADMIN_PASS. Пароль не применился или другой. Проверь вручную."
  fi

  ensure_hub_exists
  enable_sstp_and_listener

  generate_and_set_cert

  # SecureNAT requires hub context
  enable_securenat

  # Create initial user and generate clients
  local vpn_user vpn_pass
  prompt_nonempty vpn_user "Создать пользователя (логин)" "vpn"
  prompt_secret  vpn_pass "Пароль пользователя ${vpn_user}"

  add_user "$vpn_user" "$vpn_pass"
  save_state

  generate_clients_bundle "$vpn_user" "$vpn_pass" "/root/softether-clients-${vpn_user}.zip"

  log "Установка завершена."
  log "Проверка: ss -lntp | grep ':443'  (должен слушать vpnserver)"
}

do_add_user() {
  load_state
  [[ -x "$VPNCMD_BIN" ]] || die "SoftEther не установлен (нет ${VPNCMD_BIN}). Сначала пункт 1 (установка)."
  [[ -n "$ADMIN_PASS" ]] || prompt_secret ADMIN_PASS "Admin пароль SoftEther (нужен для управления)"

  local vpn_user vpn_pass
  prompt_nonempty vpn_user "Логин нового пользователя" "vpn"
  prompt_secret  vpn_pass "Пароль для ${vpn_user}"

  add_user "$vpn_user" "$vpn_pass"
  save_state
  generate_clients_bundle "$vpn_user" "$vpn_pass" "/root/softether-clients-${vpn_user}.zip"
  log "Пользователь добавлен."
}

do_del_user() {
  load_state
  [[ -x "$VPNCMD_BIN" ]] || die "SoftEther не установлен (нет ${VPNCMD_BIN})."
  [[ -n "$ADMIN_PASS" ]] || prompt_secret ADMIN_PASS "Admin пароль SoftEther (нужен для управления)"

  local vpn_user
  prompt_nonempty vpn_user "Логин пользователя для удаления" "vpn"

  del_user "$vpn_user"
  log "Пользователь удалён: ${vpn_user}"
}

menu() {
  echo
  echo "SoftEther SSTP VPN Manager"
  echo "1) Установить/настроить сервер + создать пользователя + сгенерировать клиенты"
  echo "2) Добавить пользователя (и сгенерировать клиенты)"
  echo "3) Удалить пользователя"
  echo "4) Удалить весь сервис"
  echo "0) Выход"
  echo

  local choice
  read -r -p "Выбор: " choice
  case "$choice" in
    1) do_install ;;
    2) do_add_user ;;
    3) do_del_user ;;
    4) uninstall_all ;;
    0) exit 0 ;;
    *) echo "Неверный выбор." ;;
  esac
}

# -------- CLI flags --------
AUTO_ACTION=""

VPN_USER_ARG=""
VPN_PASS_ARG=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --install) AUTO_ACTION="install"; shift ;;
    --add-user) AUTO_ACTION="add-user"; shift ;;
    --del-user) AUTO_ACTION="del-user"; shift ;;
    --uninstall) AUTO_ACTION="uninstall"; shift ;;
    --host) PUBLIC_HOST="${2:-}"; shift 2 ;;
    --adminpass) ADMIN_PASS="${2:-}"; shift 2 ;;
    --hub) HUB_NAME="${2:-}"; shift 2 ;;
    --port) VPN_PORT="${2:-}"; shift 2 ;;
    --conn-name) VPN_CONN_NAME="${2:-}"; shift 2 ;;
    --user) VPN_USER_ARG="${2:-}"; shift 2 ;;
    --pass) VPN_PASS_ARG="${2:-}"; shift 2 ;;
    -h|--help)
      cat <<EOF
Usage:
  Interactive:
    ./${SCRIPT_NAME}

  Non-interactive:
    ./${SCRIPT_NAME} --install --host <PUBLIC_HOST_OR_IP> --adminpass <PASS> --user <VPN_USER> --pass <VPN_PASS>
    ./${SCRIPT_NAME} --add-user --user <VPN_USER> --pass <VPN_PASS>
    ./${SCRIPT_NAME} --del-user --user <VPN_USER>
    ./${SCRIPT_NAME} --uninstall
EOF
      exit 0
      ;;
    *) die "Unknown arg: $1 (use --help)" ;;
  esac
done

main() {
  need_root

  if [[ -n "$AUTO_ACTION" ]]; then
    case "$AUTO_ACTION" in
      install)
        [[ -n "$PUBLIC_HOST" ]] || die "--host обязателен для --install"
        [[ -n "$ADMIN_PASS" ]] || die "--adminpass обязателен для --install"
        [[ -n "$VPN_USER_ARG" ]] || die "--user обязателен для --install"
        [[ -n "$VPN_PASS_ARG" ]] || die "--pass обязателен для --install"

        check_443_free_or_ours
        os_check
        ensure_build_tools
        clone_or_update_softether
        build_softether
        install_systemd_service

        set_admin_password_first_time

        ensure_hub_exists
        enable_sstp_and_listener
        generate_and_set_cert
        enable_securenat

        add_user "$VPN_USER_ARG" "$VPN_PASS_ARG"
        save_state
        generate_clients_bundle "$VPN_USER_ARG" "$VPN_PASS_ARG" "/root/softether-clients-${VPN_USER_ARG}.zip"
        log "Быстрая установка завершена."
        ;;
      add-user)
        load_state
        [[ -x "$VPNCMD_BIN" ]] || die "SoftEther не установлен. Сначала --install."
        [[ -n "$ADMIN_PASS" ]] || die "Не найден ADMIN_PASS в state. Запусти интерактивно или укажи --adminpass."
        [[ -n "$VPN_USER_ARG" ]] || die "--user обязателен для --add-user"
        [[ -n "$VPN_PASS_ARG" ]] || die "--pass обязателен для --add-user"
        add_user "$VPN_USER_ARG" "$VPN_PASS_ARG"
        generate_clients_bundle "$VPN_USER_ARG" "$VPN_PASS_ARG" "/root/softether-clients-${VPN_USER_ARG}.zip"
        ;;
      del-user)
        load_state
        [[ -x "$VPNCMD_BIN" ]] || die "SoftEther не установлен."
        [[ -n "$ADMIN_PASS" ]] || die "Не найден ADMIN_PASS в state. Запусти интерактивно."
        [[ -n "$VPN_USER_ARG" ]] || die "--user обязателен для --del-user"
        del_user "$VPN_USER_ARG"
        ;;
      uninstall)
        uninstall_all
        ;;
      *)
        die "Unknown action: $AUTO_ACTION"
        ;;
    esac
    exit 0
  fi

  # Interactive menu loop
  while true; do
    menu
  done
}

main "$@"
