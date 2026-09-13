#!/usr/bin/env bash
set -euo pipefail

test_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo_dir=$(cd -- "$test_dir/../.." && pwd)
compose=(docker compose --file "$test_dir/compose.yaml")

cleanup() {
	"${compose[@]}" down --volumes --remove-orphans
}
trap cleanup EXIT

"${compose[@]}" up --build --detach --wait --wait-timeout 120

cd "$repo_dir"
env \
	SMB2_CLIENT_CONFIG="$test_dir/client_conf.json" \
	SMB2_KRB5_CONFIG="$test_dir/krb5.conf" \
	SMB2_KRB5_USER=Administrator \
	SMB2_KRB5_REALM=SMB2.TEST \
	SMB2_KRB5_PASSWORD='Smb2Test-Only-Pass123!' \
	SMB2_KRB5_ADDR=127.0.0.1:1445 \
	SMB2_KRB5_SPN=cifs/samba.smb2.test \
	SMB2_KRB5_SHARE=krbshare \
	SMB2_KRB5_ENCRYPTED_SHARE=krbencrypted \
	SMB2_DFS_ADDR=127.0.0.1:1445 \
	SMB2_DFS_SERVER=127.0.0.1 \
	SMB2_DFS_TARGET_ADDR=127.0.0.1:1445 \
	SMB2_DFS_TARGET_SERVER=127.0.0.2 \
	SMB2_DFS_USER=smbuser \
	SMB2_DFS_PASSWORD='Smbpasswd12345' \
	SMB2_DFS_DOMAIN=SMB2TEST \
	SMB2_DFS_SHARE=dfs \
	SMB2_DFS_LINK=link \
	go test -race -v ./...
