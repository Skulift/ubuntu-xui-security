#!/usr/bin/env bash
set -Eeuo pipefail
export LC_ALL=C
umask 077

state=/run/ubuntu-xui-security
unit=ubuntu-xui-security-rollback
ssh_config=/etc/ssh/sshd_config.d/00-ubuntu-xui-security.conf
ca_keys=/etc/ssh/ubuntu-xui-user-ca.pub
jail=/etc/fail2ban/jail.d/99-ubuntu-xui-security.local

die() { printf 'Error: %s\n' "$*" >&2; exit 1; }

usage() {
    cat <<'EOF'
Ubuntu Server with systemd. Connect by SSH and run:
  sudo --preserve-env=SSH_CONNECTION bash ./ubuntu-xui-security.sh apply

Default: public-key login using your existing authorized_keys setup.
  apply --ca-pub /path/to/user-ca.pub   Require an OpenSSH user certificate.
                                       The CA can sign for any local account
                                       that is allowed to log in over SSH.
  apply --hy2-port PORT                Allow a different Hysteria 2 UDP port.

An independent SSH connection must run the printed confirmation command
within five minutes. Keep your first session open and avoid rebooting
while the rollback timer is armed. The script detects the SSH TCP port
of the current connection. Rules for TCP 80/443 and UDP 443 (or the
specified Hysteria 2 port) are added before UFW is enabled.

Install x-ui-pro with --skip-ufw and use the same --hy2-port if customized.
Apply the same inbound allowances in your VPS provider firewall, if used.
EOF
}

valid_port() { [[ $1 =~ ^[1-9][0-9]{0,4}$ ]] && (( $1 <= 65535 )); }

get_ssh_connection() {
    login=${SUDO_USER:-root}
    read -r peer peer_port local_addr ssh_port extra <<<"${SSH_CONNECTION:-}"
    [[ -n $peer && -n $local_addr && -z $extra ]] && valid_port "$peer_port" && valid_port "$ssh_port" ||
        die 'Run from SSH with sudo --preserve-env=SSH_CONNECTION.'
    connection_spec="user=$login,host=$peer,addr=$peer,laddr=$local_addr,lport=$ssh_port"
}

backup_file() {
    local path=$1
    [[ ! -L $path ]] || die "Refusing to replace symlink $path."
    if [[ -e $path ]]; then
        [[ -f $path ]] || die "Expected a regular file at $path."
        cp -pT -- "$path" "$state/${path##*/}.previous"
    fi
}

restore_file() {
    local path=$1 saved="$state/${1##*/}.previous"
    if [[ -f $saved ]]; then
        cp -pT -- "$saved" "$path"
    else
        rm -f -- "$path"
    fi
}

clear_pending() {
    rm -f -- "$state/pending"
    systemctl stop "$unit.timer" || true
}

rollback() {
    [[ -f $state/pending ]] || return 0
    local failed=0
    restore_file "$ssh_config" || failed=1
    restore_file "$ca_keys" || failed=1
    /usr/sbin/sshd -t && systemctl reload ssh.service || failed=1
    if [[ -f $state/jail-changed ]]; then
        restore_file "$jail" && systemctl restart fail2ban.service || failed=1
    fi
    if [[ -f $state/ufw-enabled-here ]]; then
        ufw --force disable || failed=1
    fi
    (( failed == 0 )) || die "Rollback failed. Check the provider console and backups in $state."
    clear_pending
    printf 'Restored previous SSH settings. Any added UFW allow rules are retained.\n'
}

assert_ssh_settings() {
    local settings=$'\n'${1,,}$'\n' directive
    local -a expected=('passwordauthentication no' 'kbdinteractiveauthentication no'
                       'pubkeyauthentication yes' 'authenticationmethods publickey' 'loglevel INFO')
    if [[ -f $state/cert-only ]]; then
        expected+=("trustedusercakeys $ca_keys" 'authorizedkeysfile none' 'authorizedkeyscommand none')
    fi
    for directive in "${expected[@]}"; do
        [[ $settings == *$'\n'"${directive,,}"$'\n'* ]] || die "Ineffective SSH setting: $directive. Check for an earlier directive."
    done
}

apply() {
    local ca_source='' hy2_port=443 current_ufw debug_config effective
    while (( $# )); do
        case $1 in
            --ca-pub) [[ $# -ge 2 ]] || die 'Missing CA public key path.'; ca_source=$2; shift 2 ;;
            --hy2-port) [[ $# -ge 2 ]] && valid_port "$2" || die 'Invalid Hysteria 2 UDP port.'; hy2_port=$2; shift 2 ;;
            *) die "Unknown option: $1." ;;
        esac
    done

    [[ ! -f $state/pending ]] || die 'An application is already awaiting confirmation.'
    get_ssh_connection
    [[ $ssh_port != 80 && $ssh_port != 443 ]] || die 'This SSH port conflicts with the x-ui-pro TCP listeners.'
    systemctl is-active --quiet ssh.service || die 'Expected an active Ubuntu ssh.service.'
    debug_config=$(/usr/sbin/sshd -ddd -t 2>&1) || die 'Current sshd configuration fails validation.'
    # Match can override global authentication for another user or source address.
    if grep -Eiq 'checking (syntax for .*Match|match for)' <<<"$debug_config"; then
        die 'Active sshd Match blocks need manual review before imposing a server-wide login policy.'
    fi

    rm -f -- "$state"/{cert-only,ufw-enabled-here,jail-changed,*.previous}
    if [[ -n $ca_source ]]; then
        [[ -f $ca_source ]] || die 'CA public key file not found.'
        awk 'NF && $1 !~ /^#/ {n++; if ($1 !~ /^(ssh-|ecdsa-|sk-)/ || $1 ~ /-cert-/ || NF < 2) exit 1}
             END {if (n != 1) exit 1}' "$ca_source" || die 'Supply one OpenSSH CA public key.'
        install -m 0600 -- "$ca_source" "$state/ca.candidate"
        ssh-keygen -l -f "$state/ca.candidate" >/dev/null || die 'Invalid CA public key.'
        touch "$state/cert-only"
    fi

    if ! command -v ufw >/dev/null || ! command -v fail2ban-client >/dev/null ||
        ! /usr/bin/python3 -c 'from systemd import journal' 2>/dev/null; then
        apt-get update
        DEBIAN_FRONTEND=noninteractive apt-get install -y ufw fail2ban python3-systemd
    fi
    current_ufw=$(ufw status)
    backup_file "$ssh_config"
    backup_file "$ca_keys"
    backup_file "$jail"

    install -m 0700 -- "${BASH_SOURCE[0]}" "$state/security.sh"
    printf '%s\n%s\n%s\n' "$login" "$SSH_CONNECTION" "$ssh_port" >"$state/session"
    systemd-run --quiet --unit="$unit" --on-active=5min --timer-property=AccuracySec=1s \
        /bin/bash "$state/security.sh" rollback
    touch "$state/pending"
    # The same lock protects the timer, manual rollback, and confirmation.
    trap 'trap - EXIT; rollback' EXIT

    {
        printf '%s\n' '# Managed by ubuntu-xui-security.sh' 'PasswordAuthentication no' \
            'KbdInteractiveAuthentication no' 'PubkeyAuthentication yes' \
            'AuthenticationMethods publickey' 'LogLevel INFO'
        if [[ -f $state/cert-only ]]; then
            printf '%s\n' "TrustedUserCAKeys $ca_keys" 'AuthorizedKeysFile none' 'AuthorizedKeysCommand none'
        fi
    } >"$state/sshd.candidate"
    if [[ -f $state/cert-only ]]; then
        install -m 0644 -- "$state/ca.candidate" "$ca_keys"
    fi
    install -m 0644 -- "$state/sshd.candidate" "$ssh_config"
    /usr/sbin/sshd -t
    effective=$(/usr/sbin/sshd -T)
    assert_ssh_settings "$effective"
    effective=$(/usr/sbin/sshd -T -C "$connection_spec")
    assert_ssh_settings "$effective"

    ufw allow "$ssh_port/tcp"
    ufw allow 80/tcp
    ufw allow 443/tcp
    ufw allow "$hy2_port/udp"
    if [[ $current_ufw == 'Status: inactive' ]]; then
        ufw default deny incoming
        touch "$state/ufw-enabled-here"
        ufw --force enable
    fi
    date +%s >"$state/applied-at"
    systemctl reload ssh.service
    trap - EXIT

    printf '\nOpen a fresh SSH connection on TCP %s from another terminal, then run:\n' "$ssh_port"
    printf '  sudo --preserve-env=SSH_CONNECTION bash %s/security.sh confirm\n' "$state"
    printf 'Keep this session open. Rollback is automatic if you do not confirm within five minutes.\n'
}

confirm() {
    local -a first
    local auth_log attempt
    [[ -f $state/pending ]] || die 'No change awaiting confirmation.'
    get_ssh_connection
    mapfile -t first <"$state/session"
    [[ $login == "${first[0]}" && $SSH_CONNECTION != "${first[1]}" && $ssh_port == "${first[2]}" ]] ||
        die 'Confirm from a new SSH connection as the same user on the same port.'
    auth_log=$(journalctl --quiet --unit=ssh.service --since="@$(cat "$state/applied-at")" --output=cat)
    grep -Fq "Accepted publickey for $login from $peer port $peer_port " <<<"$auth_log" ||
        die 'This new public-key login is not yet in the SSH journal. Retry from the new connection.'

    trap 'trap - EXIT; rollback' EXIT
    touch "$state/jail-changed"
    cat >"$jail" <<EOF
[sshd]
enabled = true
backend = systemd
port = $ssh_port
banaction = iptables-multiport
findtime = 10m
maxretry = 5
bantime = 1h
EOF
    fail2ban-client -t
    systemctl enable fail2ban.service
    systemctl restart fail2ban.service
    for attempt in {1..10}; do
        if fail2ban-client status sshd 2>/dev/null; then
            clear_pending
            trap - EXIT
            ufw status verbose
            printf 'SSH login confirmed. Fail2ban SSH protection is active.\n'
            return 0
        fi
        sleep 1
    done
    die 'The Fail2ban SSH jail did not start.'
}

case ${1:---help} in
    -h|--help) usage; exit 0 ;;
    apply|confirm|rollback) command=$1; shift ;;
    *) usage >&2; exit 2 ;;
esac

(( EUID == 0 )) || die 'Run with sudo.'
[[ -r /etc/os-release && -d /run/systemd/system ]] || die 'Ubuntu Server with systemd required.'
source /etc/os-release
[[ ${ID:-} == ubuntu ]] || die 'Ubuntu Server required.'
install -d -m 0700 -o root -g root -- "$state"
exec 9>"$state/lock"
flock 9
[[ $command == apply || $# == 0 ]] || die 'Unexpected arguments.'
"$command" "$@"
