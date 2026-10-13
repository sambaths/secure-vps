#!/usr/bin/env bash
#
# secure-vps.sh — interactively harden a fresh VPS for tailnet-only access.
#
# Workflow implemented (in order):
#   1. Tailscale mesh VPN join  (curl install.sh | sh, tailscale up --ssh,
#      tailscale ip -4, tailscale status)
#   2. Stop living as root      (adduser <name>, usermod -aG sudo, verify)
#   3. Take SSH off the public internet (ListenAddress <tail-ip>,
#      PasswordAuthentication no, PermitRootLogin no, restart ssh)
#   4. Firewall                 (ufw default deny/allow, allow in on
#      tailscale0, allow 41641/udp, enable)
#   5. Verify                   (public ssh times out, tailnet ssh works)
#
# Assumptions:
#   - You already have Tailscale on your MacBook / phone, logged into your
#     tailnet. Everything on that tailnet is treated as trusted.
#   - This script runs ON the new VPS (Debian 12/13 or Ubuntu 22.04/24.04),
#     initially as root over public SSH (root@<public-ip>).
#   - After hardening you connect only as <user>@<tailscale-ip> from a
#     device on the same tailnet.
#
# Usage on the fresh VPS:
#   curl -fsSL <url-to-this-file> -o secure-vps.sh   # or scp it over
#   chmod +x secure-vps.sh
#   sudo ./secure-vps.sh
#
# The script is idempotent — safe to re-run. It pauses wherever a human
# must do something (approve the device in the Tailscale admin console,
# open a second terminal to prove you are not locked out, ...) and it
# verifies each step before moving on.
#
set -euo pipefail

SECURE_VPS_VERSION="1.0"

# ---------------------------------------------------------------- helpers

# ANSI-C quoting ($'...') so these hold REAL escape bytes. That way they
# render through every channel — printf, echo, and cat-heredocs alike.
# (Plain '\033' in single quotes is literal text and only printf's format
# string would interpret it, which is why heredocs printed garbage.)
RED=$'\033[0;31m'; GREEN=$'\033[0;32m'; YELLOW=$'\033[1;33m'
BLUE=$'\033[0;34m'; BOLD=$'\033[1m'; DIM=$'\033[2m'; NC=$'\033[0m'

log_info() { printf "${BLUE}[i]${NC} %s\n" "$*"; }
log_ok()   { printf "${GREEN}[✓]${NC} %s\n" "$*"; }
log_warn() { printf "${YELLOW}[!]${NC} %s\n" "$*"; }
log_err()  { printf "${RED}[x]${NC} %s\n" "$*" >&2; }
step()     { printf "\n${BOLD}━━━ %s ━━━${NC}\n" "$*"; }
detail()   { printf "${DIM}    %s${NC}\n" "$*"; }

action_box() {
  # action_box "<title>" "<line>"... — yellow panel for human checkpoints.
  # Each line arg may contain color vars; they render because colors are
  # real escape bytes (see above).
  local title="$1"; shift
  local rule="━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  printf '\n  %s┏%s┓%s\n' "$YELLOW" "$rule" "$NC"
  printf '  %s┃  ▶ %s%s\n' "$YELLOW" "$title" "$NC"
  printf '  %s┣%s┫%s\n' "$YELLOW" "$rule" "$NC"
  local line
  for line in "$@"; do
    printf '  %s┃%s  %s\n' "$YELLOW" "$NC" "$line"
  done
  printf '  %s┗%s┛%s\n\n' "$YELLOW" "$rule" "$NC"
}

_spin_frames="|/-\\"
run_with_spinner() {
  # run_with_spinner "<message>" <command...> — animate while a long
  # command runs, logging its output; show the tail only on failure.
  # Falls back to plain execution when stdout is not a terminal.
  local msg="$1"; shift
  if [ ! -t 1 ]; then
    "$@"
    return
  fi
  local log
  log="$(mktemp /tmp/secure-vps.XXXXXX.log)"
  "$@" >"$log" 2>&1 &
  local pid
  pid=$!
  local i=0
  while kill -0 "$pid" 2>/dev/null; do
    printf '\r  %s%c%s %s' "$YELLOW" "${_spin_frames:i%4:1}" "$NC" "$msg"
    i=$((i + 1))
    sleep 0.12
  done
  printf '\r%*s\r' $((${#msg} + 6)) ' '
  local rc=0
  wait "$pid" || rc=$?
  if [ $rc -ne 0 ]; then
    log_err "Failed: $msg (exit $rc). Last output:"
    tail -n 20 "$log" >&2 || true
  else
    log_ok "$msg — done."
  fi
  rm -f "$log"
  return $rc
}

press_enter() {
  local msg="${1:-Press ENTER to continue...}"
  # shellcheck disable=SC2229,SC2034
  read -r -p "$(printf "${YELLOW}?${NC} %s " "$msg")" _dummy || true
}

ask() {
  # ask "<prompt>" "<default>" -> prints answer on stdout
  local prompt="$1" default="${2:-}" answer=""
  if [ -n "$default" ]; then
    read -r -p "$(printf "${YELLOW}?${NC} %s [%s]: " "$prompt" "$default")" answer || true
    [ -z "$answer" ] && answer="$default"
  else
    read -r -p "$(printf "${YELLOW}?${NC} %s: " "$prompt")" answer || true
  fi
  printf '%s' "$answer"
}

ask_yes_no() {
  # ask_yes_no "<prompt>" "<default Y|N>" -> returns 0 for yes
  local prompt="$1" default="${2:-Y}" yn suffix
  if [ "$default" = "Y" ]; then suffix="[Y/n]"; else suffix="[y/N]"; fi
  while true; do
    read -r -p "$(printf "${YELLOW}?${NC} %s %s " "$prompt" "$suffix")" yn || true
    [ -z "$yn" ] && yn="$default"
    case "$yn" in
      [Yy]*) return 0 ;;
      [Nn]*) return 1 ;;
      *) echo "Please answer y or n." ;;
    esac
  done
}

need_root() {
  if [ "$(id -u)" -ne 0 ]; then
    log_err "Run this script as root (or with sudo) on the VPS."
    log_err "Example: sudo ./secure-vps.sh"
    exit 1
  fi
}

have_cmd() { command -v "$1" >/dev/null 2>&1; }

_apt_busy() {
  # True (exit 0) while another process holds the apt/dpkg locks.
  if have_cmd fuser; then
    fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1 \
    || fuser /var/lib/dpkg/lock >/dev/null 2>&1 \
    || fuser /var/cache/apt/archives/lock >/dev/null 2>&1
  else
    # Minimal images may lack fuser: fall back to a process scan.
    # (grep, not pgrep, so this works even without procps installed.)
    # shellcheck disable=SC2009
    ps -eo args 2>/dev/null | grep -Ei '[a]pt-get|[a]ptitude|[d]pkg --|[u]nattended-upgr' >/dev/null
  fi
}

wait_for_apt_lock() {
  # Wait out competing apt/dpkg holders (fresh-boot cloud-init/apt-daily,
  # or the unattended-upgrades run this script just enabled). Never
  # force-remove lock files — that corrupts dpkg state.
  local timeout="${1:-600}" waited=0
  # Grace period: a just-triggered background run (e.g. the
  # unattended-upgrades start above) needs a moment to grab the lock
  # before we can detect it.
  sleep 2
  while _apt_busy; do
    if [ "$waited" -ge "$timeout" ]; then
      log_err "apt/dpkg lock still held after ${timeout}s."
      log_err "Inspect with: ps aux | grep -Ei 'apt|dpkg|unattended' (do NOT delete lock files)"
      return 1
    fi
    if [ "$waited" -eq 0 ]; then
      log_info "apt is busy (another installer running) — waiting for the lock..."
    elif [ $((waited % 30)) -eq 0 ]; then
      log_info "Still waiting for the apt lock (${waited}s)..."
    fi
    sleep 5
    waited=$((waited + 5))
  done
  return 0
}

apt_get() {
  # apt-get wrapper: wait for a free lock first, then run. Args pass through.
  wait_for_apt_lock || return 1
  apt-get "$@"
}

get_public_ip() {
  # Best-effort public IPv4, never fails the script.
  (curl -fsS --max-time 8 https://ifconfig.me 2>/dev/null \
    || curl -fsS --max-time 8 https://api.ipify.org 2>/dev/null \
    || hostname -I 2>/dev/null | awk '{print $1}') | head -n1 || true
}

get_tailscale_ipv4() {
  # Prints 100.x.y.z or empty. Never fails (caller checks emptiness).
  tailscale ip -4 2>/dev/null | head -n1 | tr -d '[:space:]' || true
}

tailscale_logged_in() {
  have_cmd tailscale && tailscale status >/dev/null 2>&1
}

sshd_effective() {
  # $1 = key like PasswordAuthentication (case-insensitive lookup via sshd -T)
  if have_cmd sshd && sshd -t 2>/dev/null; then
    sshd -T 2>/dev/null | grep -i -m1 "^${1} " | awk '{print $2}' || true
  fi
}

restart_ssh() {
  # Debian 13 / Ubuntu use "ssh", older images use "sshd". Try both.
  if systemctl list-unit-files 2>/dev/null | grep -q '^ssh\.service'; then
    systemctl restart ssh
  elif systemctl list-unit-files 2>/dev/null | grep -q '^sshd\.service'; then
    systemctl restart sshd
  else
    systemctl restart ssh 2>/dev/null || systemctl restart sshd
  fi
}

# ---------------------------------------------------------------- banner

print_banner() {
  cat <<'EOF'
  ┌──────────────────────────────────────────────────────────┐
  │  VPS lockdown                                            │
  │  Tailscale → user → SSH → firewall                       │
  └──────────────────────────────────────────────────────────┘
EOF
  echo "secure-vps.sh v${SECURE_VPS_VERSION}"
  echo ""
  echo "This script runs ON the new VPS. You start as root@<public-ip>."
  echo "You finish with root + public SSH dead and only"
  echo "<user>@<tailscale-ip> (100.x.y.z) reachable from your tailnet."
  echo ""
  echo "Human checkpoints (the script waits for you):"
  echo "  A. Approve this VPS in Tailscale (browser + admin console)."
  echo "  B. Prove the new sudo user works."
  echo "  C. Prove SSH still works in a SECOND terminal before we lock more."
  echo "  D. Prove public SSH times out at the end."
  echo ""
}

# ---------------------------------------------------------------- step 0

step_prereqs() {
  step "STEP 0/5 — Pre-flight and system update"

  need_root

  if [ -f /etc/os-release ]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    log_info "OS: ${PRETTY_NAME:-$ID}  |  kernel: $(uname -r)"
    case "${ID:-}" in
      debian|ubuntu) log_ok "Supported distro." ;;
      *) log_warn "Not Debian/Ubuntu — commands target apt/systemd; continuing anyway." ;;
    esac
  else
    log_warn "/etc/os-release not found; assuming apt-based system."
  fi

  PUBLIC_IP="$(get_public_ip)"
  if [ -n "${PUBLIC_IP:-}" ]; then
    log_info "Public IP (will be closed off): $PUBLIC_IP"
  else
    log_warn "Could not detect public IP (offline?). Continuing."
    PUBLIC_IP=""
  fi
  export PUBLIC_IP

  if ! ask_yes_no "Run apt update + upgrade now? (recommended on a fresh box)" "Y"; then
    log_warn "Skipping system update (not recommended)."
    return 0
  fi
  export DEBIAN_FRONTEND=noninteractive
  run_with_spinner "Updating package lists..." apt_get update
  # -y upgrade can take minutes on first boot; spinner keeps it lively.
  run_with_spinner "Upgrading packages (may take a few minutes)..." apt_get upgrade -y
  run_with_spinner "Installing base packages..." \
    apt_get install -y curl ca-certificates sudo openssh-server ufw \
    || apt_get install -y curl ca-certificates sudo openssh-server \
    || true
  log_ok "Base packages ready."
}

# ---------------------------------------------------------------- step 1

step_tailscale() {
  step "STEP 1/5 — Join the tailnet (Tailscale + --ssh)"

  if ! have_cmd tailscale; then
    # The Tailscale installer uses apt internally — wait out any holder first.
    wait_for_apt_lock
    run_with_spinner "Installing Tailscale..." \
      bash -c 'curl -fsSL https://tailscale.com/install.sh | sh'
  else
    log_ok "Tailscale already installed: $(tailscale version 2>/dev/null | head -n1 || echo present)"
  fi

  # No default hostname — always ask explicitly so nothing identifying
  # is baked in. Used as: tailscale up --ssh --hostname=<name>.
  if ! tailscale_logged_in; then
    TS_HOSTNAME=""
    while true; do
      TS_HOSTNAME="$(ask "Tailscale hostname for this VPS (shown in admin console). No default — type a name")"
      if printf '%s' "$TS_HOSTNAME" | grep -Eq '^[a-zA-Z0-9][a-zA-Z0-9-]{0,62}$'; then
        break
      fi
      log_err "Invalid hostname '$TS_HOSTNAME'. Use letters, digits, hyphens; start with a letter/digit; max 63 chars."
    done
    log_info "Bringing Tailscale up with SSH enabled..."
    detail "Command: tailscale up --ssh --hostname=$TS_HOSTNAME"
    detail "If your tailnet needs device approval, approve it in the admin console too."
    # tailscale up prints the login URL; run it in a loop until authed.
    while true; do
      echo ""
      log_warn ">>> ACTION NEEDED (human): a login URL appears below. Open it,"
      log_warn "    sign in with the SAME Tailscale account as your MacBook,"
      log_warn "    click Connect/Add device, and approve the machine if asked"
      log_warn "    (Admin console → Machines → … → Approve / enable Tailscale SSH)."
      echo ""
      # Don't fail the script if up exits non-zero while unauthenticated.
      tailscale up --ssh --hostname="$TS_HOSTNAME" || true
      echo ""
      if tailscale_logged_in && [ -n "$(get_tailscale_ipv4)" ]; then
        break
      fi
      log_warn "This VPS is not on the tailnet yet."
      press_enter "After approving in the browser/admin console, press ENTER to re-check (or Ctrl+C to abort)..."
      # Re-try; --ssh flag must be present every time.
      tailscale up --ssh --hostname="$TS_HOSTNAME" || true
      if tailscale_logged_in && [ -n "$(get_tailscale_ipv4)" ]; then
        break
      fi
    done
  else
    log_ok "Tailscale already logged in."
    if ! tailscale status 2>/dev/null | grep -qi -- "--ssh\|ssh.*enabled\|tailssh"; then
      # Ensure Tailscale SSH stays enabled even if previously joined without it.
      log_info "Re-applying 'tailscale up --ssh' so Tailnet SSH manages logins..."
      tailscale up --ssh || log_warn "'tailscale up --ssh' returned non-zero; check 'tailscale status'."
    fi
  fi

  TAIL_IP="$(get_tailscale_ipv4)"
  if [ -z "$TAIL_IP" ]; then
    log_err "Still no Tailscale IPv4. Run 'tailscale status' / 'tailscale up --ssh' manually, then re-run this script."
    exit 1
  fi
  export TAIL_IP
  log_ok "Tailnet IPv4 for this VPS: $TAIL_IP"
  detail "Verify on your MacBook (already on the tailnet):  ping $TAIL_IP"
  echo ""
  tailscale status || true
  echo ""
  if ask_yes_no "From your MacBook, can you 'ping $TAIL_IP' (or see this VPS in the Tailscale admin console)?" "Y"; then
    log_ok "Tailnet connectivity confirmed by human."
  else
    log_warn "Continuing anyway, but do NOT enable the firewall until the tailnet reaches this VPS."
    press_enter "Fix Tailscale (approve device / check login), then press ENTER to continue..."
    TAIL_IP="$(get_tailscale_ipv4)"
    export TAIL_IP
  fi
}

# ---------------------------------------------------------------- step 2

step_create_user() {
  step "STEP 2/5 — Stop living as root (create a sudo user)"

  local newuser=""
  # No default username — always ask explicitly so nothing personal
  # ever lands in the script or the box.
  while true; do
    newuser="$(ask "Non-root username to create/use (you'll SSH as this from now on). No default — type a name")"
    if printf '%s' "$newuser" | grep -Eq '^[a-z_][a-z0-9_-]{0,31}$'; then
      break
    fi
    log_err "Invalid username '$newuser'. Use lowercase, start with a letter or _, max 32 chars."
  done
  export DEPLOY_USER="$newuser"

  if id "$DEPLOY_USER" >/dev/null 2>&1; then
    log_ok "User '$DEPLOY_USER' already exists — reusing."
  else
    log_info "Creating user '$DEPLOY_USER' (command: adduser $DEPLOY_USER)..."
    detail "Pick a strong password — you need it for sudo until keys/Tailscale-SSH take over."
    adduser "$DEPLOY_USER"
  fi

  log_info "Granting sudo (command: usermod -aG sudo $DEPLOY_USER)..."
  usermod -aG sudo "$DEPLOY_USER"

  # Preserve SSH access: copy root's authorized_keys if the new user has none.
  if [ -f /root/.ssh/authorized_keys ] && [ ! -s "/home/$DEPLOY_USER/.ssh/authorized_keys" ]; then
    log_info "Copying /root/.ssh/authorized_keys → $DEPLOY_USER (so your existing key keeps working)..."
    mkdir -p "/home/$DEPLOY_USER/.ssh"
    cp /root/.ssh/authorized_keys "/home/$DEPLOY_USER/.ssh/authorized_keys"
    chmod 700 "/home/$DEPLOY_USER/.ssh"
    chmod 600 "/home/$DEPLOY_USER/.ssh/authorized_keys"
    chown -R "$DEPLOY_USER:$DEPLOY_USER" "/home/$DEPLOY_USER/.ssh"
    log_ok "Key copied."
  fi

  # Offer to paste the laptop's public key (helps once PasswordAuthentication no).
  if [ ! -s "/home/$DEPLOY_USER/.ssh/authorized_keys" ]; then
    echo ""
    log_warn "No SSH public key found for '$DEPLOY_USER'."
    detail "On your MacBook, run:  cat ~/.ssh/id_ed25519.pub  (or id_rsa.pub)"
    if ask_yes_no "Paste your MacBook's SSH public key now? (needed if you ever SSH without Tailscale-SSH)" "N"; then
      echo "Paste the single line starting with 'ssh-ed25519 ...' or 'ssh-rsa ...', then ENTER:"
      read -r pasted_key || true
      if printf '%s' "$pasted_key" | grep -Eq '^(ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp)'; then
        mkdir -p "/home/$DEPLOY_USER/.ssh"
        printf '%s\n' "$pasted_key" >> "/home/$DEPLOY_USER/.ssh/authorized_keys"
        chmod 700 "/home/$DEPLOY_USER/.ssh"
        chmod 600 "/home/$DEPLOY_USER/.ssh/authorized_keys"
        chown -R "$DEPLOY_USER:$DEPLOY_USER" "/home/$DEPLOY_USER/.ssh"
        log_ok "Key added."
      else
        log_warn "Didn't look like a public key — skipped. You rely on Tailscale SSH then."
      fi
    else
      detail "Skipped — Tailscale SSH (--ssh) still lets you in via your tailnet identity."
    fi
  else
    log_ok "authorized_keys present for '$DEPLOY_USER'."
  fi

  # Verify sudo works BEFORE we disable root (su - user, sudo whoami, exit).
  # NOTE: the script must NOT attempt password entry itself via 'su -c':
  # sudo needs a real terminal to read a password and fails with
  # "a terminal is required". So the fast path is passwordless-only,
  # otherwise the human proves it in a real shell.
  log_info "Verifying sudo for '$DEPLOY_USER'..."
  if su - "$DEPLOY_USER" -c 'sudo -n true' 2>/dev/null; then
    log_ok "sudo works without a password (fine). Safe to continue."
  else
    action_box "ACTION NEEDED — prove it yourself (one minute)" \
      "The script can't type your password for you, so:" \
      "1. You will land in a shell as '${DEPLOY_USER}'." \
      "2. Run:  ${BOLD}sudo whoami${NC}   (type the password; expect: ${BOLD}root${NC})" \
      "3. Run:  ${BOLD}exit${NC}   to return here as root."
    press_enter "Press ENTER to switch to '$DEPLOY_USER'..."
    su - "$DEPLOY_USER" || true
    # Back as root. Confirm before touching SSH.
    if ask_yes_no "Did 'sudo whoami' print 'root'?" "Y"; then
      log_ok "sudo works. Safe to continue."
    else
      log_err "sudo verification failed. Check the password ('passwd $DEPLOY_USER')"
      log_err "and group ('usermod -aG sudo $DEPLOY_USER'), then re-run."
      exit 1
    fi
  fi

  echo ""
  log_warn "From now on connect as:  ssh $DEPLOY_USER@$TAIL_IP  (on the tailnet)."
  detail "Keep THIS root session open until the very end — it's your safety net."
  press_enter "Got it? Press ENTER to harden SSH..."
}

# ---------------------------------------------------------------- step 3

step_ssh_hardening() {
  step "STEP 3/5 — Take SSH off the public internet"

  local cfg="/etc/ssh/sshd_config"
  local dropin="/etc/ssh/sshd_config.d/99-tailscale-only.conf"
  local backup
  backup="${cfg}.bak.$(date +%Y%m%d-%H%M%S)"

  [ -f "$cfg" ] || { log_err "$cfg not found — is openssh-server installed?"; exit 1; }

  log_info "Backing up $cfg → $backup"
  cp -a "$cfg" "$backup"

  # NOTE on Debian 12+/13: /etc/ssh/sshd_config.d/*.conf OVERRIDES the main
  # file (Include directive at top). A stray 60-cloudimg-settings.conf with
  # 'PasswordAuthentication yes' would silently win. So we write a
  # lexicographically-last drop-in AND patch the main file — belt and braces.
  log_info "Writing $dropin ..."
  mkdir -p /etc/ssh/sshd_config.d
  cat > "$dropin" <<EOF
# Managed by secure-vps.sh — tailnet-only SSH.
# Overrides any cloud-image defaults in sshd_config.d/.
ListenAddress $TAIL_IP
PasswordAuthentication no
PermitRootLogin no
PubkeyAuthentication yes
ChallengeResponseAuthentication no
UsePAM yes
X11Forwarding no
EOF
  chmod 600 "$dropin"

  # Also patch the main file so humans reading it see the intent. Comment out
  # conflicting active lines first, then append our block if missing.
  for key in ListenAddress PasswordAuthentication PermitRootLogin; do
    # Comment out any UNCOMMENTED occurrence; drop-in remains authoritative.
    sed -i -E "s|^([[:space:]]*)(${key}[[:space:]]+)|# secure-vps disabled: \2|" "$cfg" || true
  done
  if ! grep -Eq '^[[:space:]]*ListenAddress[[:space:]]' "$cfg"; then
    cat >> "$cfg" <<EOF

# secure-vps.sh: tailnet-only SSH (authoritative copy lives in $dropin)
ListenAddress $TAIL_IP
PasswordAuthentication no
PermitRootLogin no
EOF
  fi

  log_info "Validating with 'sshd -t'..."
  if sshd -t; then
    log_ok "sshd config syntax OK."
  else
    log_err "sshd -t FAILED — restoring backup, aborting before restart."
    cp -a "$backup" "$cfg"
    rm -f "$dropin"
    sshd -t || true
    exit 1
  fi

  log_info "Effective config (sshd -T):"
  echo "    listenaddress:            $(sshd_effective listenaddress || echo '?')"
  echo "    passwordauthentication:   $(sshd_effective passwordauthentication || echo '?')"
  echo "    permitrootlogin:          $(sshd_effective permitrootlogin || echo '?')"
  if [ "$(sshd_effective permitrootlogin || echo '')" != "no" ]; then
    log_warn "PermitRootLogin is not 'no' — a drop-in may still override. Check /etc/ssh/sshd_config.d/."
  fi

  log_info "Restarting SSH..."
  restart_ssh
  sleep 2
  if systemctl is-active --quiet ssh 2>/dev/null || systemctl is-active --quiet sshd 2>/dev/null; then
    log_ok "SSH service running."
  else
    log_err "SSH service not active after restart — restoring backup!"
    cp -a "$backup" "$cfg"
    rm -f "$dropin"
    restart_ssh || true
    exit 1
  fi

  action_box "ACTION NEEDED — anti-lockout check" \
    "1. Open a SECOND terminal on your MacBook (keep this root session open!)." \
    "2. Make sure Tailscale is connected there." \
    "3. Run:  ${BOLD}ssh ${DEPLOY_USER}@${TAIL_IP}${NC}" \
    "   It should log you in (key or Tailscale SSH identity — no root, no password-guessing)." \
    "4. Do NOT close this root session until that works."
  if ask_yes_no "Did 'ssh $DEPLOY_USER@$TAIL_IP' connect in the second terminal?" "Y"; then
    log_ok "New SSH path confirmed — safe to continue."
  else
    log_err "STOP. Fix SSH before continuing (check Tailscale, authorized_keys, 'sshd -T')."
    log_err "Restore if needed: cp -a $backup $cfg && rm -f $dropin && systemctl restart ssh"
    exit 1
  fi
}

# ---------------------------------------------------------------- step 4

step_firewall() {
  step "STEP 4/5 — Firewall: deny everything, allow the tailnet"

  if ! have_cmd ufw; then
    log_info "Installing ufw..."
    apt_get update && apt_get install -y ufw
  fi

  # Safety: firewall only makes sense once the tailnet path is proven.
  if [ -z "$(get_tailscale_ipv4)" ]; then
    log_err "No Tailscale IP — enabling a firewall now would lock you out. Aborting."
    exit 1
  fi
  if ! tailscale_logged_in; then
    log_err "Tailscale not logged in — refusing to enable firewall. Aborting."
    exit 1
  fi

  log_info "Applying:"
  detail "ufw default deny incoming"
  detail "ufw default allow outgoing"
  detail "ufw allow in on tailscale0"
  detail "ufw allow 41641/udp   (Tailscale direct connections)"
  ufw default deny incoming
  ufw default allow outgoing
  ufw allow in on tailscale0
  ufw allow 41641/udp comment 'Tailscale' || ufw allow 41641/udp

  echo ""
  ufw status verbose || true
  echo ""
  log_warn "About to run 'ufw enable' — this kills all non-tailnet access."
  log_warn "You must be able to reach this box via the tailnet RIGHT NOW."
  if ! ask_yes_no "Enable the firewall (ufw --force enable)?" "Y"; then
    log_warn "Firewall configured but NOT enabled. Re-run script to enable later."
    return 0
  fi
  ufw --force enable
  echo ""
  ufw status verbose
  log_ok "Firewall active. Public ingress denied; tailnet allowed."
}

# ---------------------------------------------------------------- step 5 (bonus, optional)

step_extras() {
  step "BONUS — Automatic security updates (+ optional fail2ban)"

  if ask_yes_no "Enable unattended security updates? (recommended, no downside on a VPS)" "Y"; then
    apt_get install -y unattended-upgrades apt-listchanges 2>/dev/null \
      || log_warn "unattended-upgrades install failed — continuing without it."
    # Enable the standard security update job; ignore failures on odd images.
    if [ -x /usr/bin/unattended-upgrade ]; then
      dpkg-reconfigure -plow unattended-upgrades 2>/dev/null || true
      systemctl enable --now unattended-upgrades 2>/dev/null || true
      log_ok "Unattended upgrades enabled."
    fi
  fi

  echo ""
  log_info "Why fail2ban? Behind Tailscale + UFW the public SSH port is already"
  detail "unreachable, so fail2ban is strictly a safety net — not the primary defense."
  detail "It earns its place if any of these ever happen:"
  detail "  • the firewall gets disabled/flushed during later debugging,"
  detail "  • a future change re-exposes SSH (or another service) publicly,"
  detail "  • an attacker is already inside the tailnet (stolen device/session)."
  detail "In those cases it rate-limits password-guessing instead of letting bots"
  detail "retry forever. Small, harmless, off by default."
  if ask_yes_no "Install fail2ban as a safety net?" "N"; then
    if apt_get install -y fail2ban; then
      systemctl enable --now fail2ban || true
      log_ok "fail2ban running."
    else
      log_warn "fail2ban install failed — continuing without it (Tailscale + UFW remain your defense)."
    fi
  fi
}

# ---------------------------------------------------------------- verify

step_verify() {
  step "VERIFY — Prove the box is gated off"

  echo "From your MacBook / phone (ON the tailnet) these should work:"
  echo "  ${BOLD}ssh ${DEPLOY_USER}@${TAIL_IP}${NC}        → connects"
  echo "  ping ${TAIL_IP}                    → replies"
  echo ""
  echo "From anywhere (or with Tailscale disconnected) these must FAIL:"
  if [ -n "${PUBLIC_IP:-}" ]; then
    echo "  ${BOLD}ssh root@${PUBLIC_IP}${NC}  → hang / timeout (no route)"
    echo "  ssh ${DEPLOY_USER}@${PUBLIC_IP}     → hang / timeout"
  else
    echo "  ssh root@<this-VPS-public-ip>    → hang / timeout"
  fi
  echo ""
  echo "On this VPS right now:"
  echo "  tailscale ip -4              → $(get_tailscale_ipv4)"
  echo "  ufw status                   → $(ufw status 2>/dev/null | head -n1 || echo unknown)"
  echo "  sshd PermitRootLogin         → $(sshd_effective permitrootlogin || echo '?')"
  echo "  sshd PasswordAuthentication  → $(sshd_effective passwordauthentication || echo '?')"
  echo ""

  log_warn ">>> ACTION NEEDED: run the timeout test yourself (script can't test YOUR network for you)."
  if [ -n "${PUBLIC_IP:-}" ]; then
    detail "New terminal on MacBook:  ssh -o ConnectTimeout=8 root@$PUBLIC_IP   (expect: timeout)"
  fi
  press_enter "After you've seen public SSH hang/timeout AND tailnet SSH connect, press ENTER..."

  if ask_yes_no "Confirm: public SSH timed out AND 'ssh $DEPLOY_USER@$TAIL_IP' works?" "Y"; then
    log_ok "Verified by human. Box is gated off. 🎉"
  else
    log_warn "Verification incomplete — re-check UFW ('ufw status verbose'), sshd ('sshd -T'), and Tailscale."
  fi

  cat <<EOF

${GREEN}Done. Your VPS is now hardened:${NC}
  • Tailscale up --ssh, tailnet IP ${BOLD}${TAIL_IP}${NC}
  • Root login over SSH disabled; password auth off; SSH listens on ${TAIL_IP} only
  • UFW: deny incoming / allow outgoing / allow tailscale0 / allow 41641-udp
  • Non-root sudo user: ${BOLD}${DEPLOY_USER}${NC}

${BOLD}Next:${NC}
  • Run agent installs as ${DEPLOY_USER}, NOT root.
  • Bind dashboards to the tailnet (or 0.0.0.0 + UFW tailscale0-only + basic-auth),
    ex: 'tailscale serve --bg 9119' for an https://<vps>.<tailnet>.ts.net URL.
  • Keep this VPS snapshot/backup.

Reconnect reminder:  ${BOLD}ssh ${DEPLOY_USER}@${TAIL_IP}${NC}   (Tailscale ON, same account)
EOF
}

# ---------------------------------------------------------------- main

main() {
  if [ "${1:-}" = "--help" ] || [ "${1:-}" = "-h" ]; then
    # Print the header comment block (lines starting with '#').
    sed -n '2,34p' "$0" | sed 's/^# \{0,1\}//'
    exit 0
  fi
  print_banner
  if ! ask_yes_no "This will harden THIS VPS (SSH + firewall changes). Proceed?" "Y"; then
    echo "Aborted."
    exit 0
  fi
  step_prereqs
  step_tailscale
  step_create_user
  step_ssh_hardening
  step_firewall
  step_extras
  step_verify
}

main "$@"
