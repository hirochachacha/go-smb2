#!/usr/bin/env bash
set -euo pipefail

# Use the SMB server shipped with macOS and a disposable CI account.
sudo sysadminctl -addUser smbuser -password Smbpasswd12345
sudo pwpolicy -u smbuser -sethashtypes SMB-NT on
sudo dscl . -passwd /Users/smbuser Smbpasswd12345
if ! dscl . -read /Groups/com.apple.access_smb >/dev/null 2>&1; then
  sudo dseditgroup -o create com.apple.access_smb
fi
sudo dseditgroup -o edit -a smbuser -t user com.apple.access_smb

share_dir=/Users/Shared/go-smb2
sudo mkdir -p "$share_dir"
sudo chown smbuser:staff "$share_dir"
sudo chmod 0755 "$share_dir"
sudo sharing -a "$share_dir" -n tmp -S tmp -s 001 -g 000 -R 0
sudo sharing -a "$share_dir" -n tmp2 -S tmp2 -s 001 -g 000 -R 1

sudo defaults write /Library/Preferences/SystemConfiguration/com.apple.smb.server \
  EnabledServices -array disk
sudo launchctl enable system/com.apple.smbd
if ! sudo launchctl print system/com.apple.smbd >/dev/null 2>&1; then
  sudo launchctl bootstrap system /System/Library/LaunchDaemons/com.apple.smbd.plist
fi
sudo launchctl kickstart -k system/com.apple.smbd

cp .github/client_conf.json client_conf.json

for attempt in {1..30}; do
  if smbutil view -N //smbuser:Smbpasswd12345@localhost; then
    exit 0
  fi
  sleep 1
done

echo 'macOS SMB server did not become ready' >&2
sudo sharing -l
sudo launchctl print system/com.apple.smbd
exit 1
