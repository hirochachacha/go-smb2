#!/usr/bin/env bash
set -euo pipefail

readonly realm=SMB2.TEST
readonly domain=SMB2TEST
readonly administrator_password='Smb2Test-Only-Pass123!'
readonly user_password='Smbpasswd12345'

# Ubuntu installs a standalone-server configuration. Provisioning an AD DC
# requires samba-tool to create its own configuration and databases.
rm -f /etc/samba/smb.conf

samba-tool domain provision \
    --realm="$realm" \
    --domain="$domain" \
    --server-role=dc \
    --dns-backend=SAMBA_INTERNAL \
    --host-name=samba \
    --adminpass="$administrator_password" \
    --use-rfc2307 \
    --option='netbios aliases=127.0.0.2 127.0.0.3' \
    --option='server signing=mandatory'

samba-tool user create smbuser "$user_password"

install -d -m 0777 \
    /srv/smb-test/read-write \
    /srv/smb-test/read-only \
    /srv/smb-test/encrypted \
    /srv/smb-test/dfs \
    /srv/smb-test/dfs-target \
    /srv/smb-test/dfs-hop \
    /srv/smb-test/dfs-hop2 \
    /srv/smb-test/dfs-encrypted/nested

ln -s 'msdfs:127.0.0.2\dfs-target' /srv/smb-test/dfs/link
ln -s 'msdfs:127.0.0.2\dfs-target' /srv/smb-test/dfs/link-alias
ln -s 'msdfs:127.0.0.3\dfs-encrypted\nested' /srv/smb-test/dfs/link-extra
ln -s 'msdfs:127.0.0.2\dfs-hop\入口' /srv/smb-test/dfs/link-chain
ln -s 'msdfs:127.0.0.3\dfs-hop2\出口' /srv/smb-test/dfs-hop/入口
ln -s 'msdfs:127.0.0.3\dfs-encrypted\nested' /srv/smb-test/dfs-hop2/出口
ln -s 'msdfs:127.0.0.2\dfs-hop\cycle' /srv/smb-test/dfs/link-cycle
ln -s 'msdfs:127.0.0.1\dfs\link-cycle' /srv/smb-test/dfs-hop/cycle

cat >>/etc/samba/smb.conf <<'EOF'

[tmp]
	path = /srv/smb-test/read-write
	read only = no
	force user = root

[tmp2]
	path = /srv/smb-test/read-only
	read only = yes
	force user = root

[krbshare]
	path = /srv/smb-test/read-write
	read only = no
	force user = root

[krbencrypted]
	path = /srv/smb-test/encrypted
	read only = no
	force user = root
	smb encrypt = required

[dfs]
	path = /srv/smb-test/dfs
	read only = no
	msdfs root = yes

[dfs-target]
	path = /srv/smb-test/dfs-target
	read only = no
	force user = root

[dfs-hop]
	path = /srv/smb-test/dfs-hop
	read only = no
	msdfs root = yes

[dfs-hop2]
	path = /srv/smb-test/dfs-hop2
	read only = no
	msdfs root = yes

[dfs-encrypted]
	path = /srv/smb-test/dfs-encrypted
	read only = no
	force user = root
	smb encrypt = required
EOF

exec samba --foreground --no-process-group
