#!/bin/bash
# Diagnostic only: apply upstream's native-systemd approach inside the exact
# product-owned WSL guest selected and proven by qualify-windows.ps1.
set -euo pipefail
test "$(id -u)" = 0
for file in /etc/wsl.conf /root/bootstrap /usr/local/bin/enterns; do
  test -f "$file" && test ! -L "$file"
done
test ! -e /usr/local/bin/enterns.ai-security-scanner-original
cp -p /usr/local/bin/enterns /usr/local/bin/enterns.ai-security-scanner-original
{
  printf '[boot]\nsystemd=true\n\n'
  cat /etc/wsl.conf
} > /etc/wsl.conf.ai-security-scanner
mv /etc/wsl.conf.ai-security-scanner /etc/wsl.conf
cat > /root/bootstrap <<'BOOTSTRAP'
#!/bin/bash
timeout 60 systemctl is-system-running --wait >/dev/null 2>&1 || true
BOOTSTRAP
chmod 755 /root/bootstrap
cat > /usr/local/bin/enterns <<'ENTERNS'
#!/bin/bash
SYSDPID=$(ps -eo cmd,pid | awk '$1 == "/lib/systemd/systemd" {print $NF; exit}')
if [ "$SYSDPID" != 1 ]; then
  exec /usr/local/bin/enterns.ai-security-scanner-original "$@"
fi
if [ "$#" = 3 ] && [ "$1" = systemctl ] && [ "$2" = exit ] && [ "$3" = 0 ]; then
  exec systemctl poweroff --no-block
fi
if [ "$#" = 0 ]; then
  exec /bin/bash -l
fi
exec "$@"
ENTERNS
chmod 755 /usr/local/bin/enterns
install -d -m 755 /etc/containers/containers.conf.d
printf '[engine]\ncgroup_manager="systemd"\n' > /etc/containers/containers.conf.d/99-ai-security-scanner-systemd.conf
printf 'Native systemd configuration installed in the product-owned guest.\n'
exit 0
