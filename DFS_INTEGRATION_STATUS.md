# DFS統合テストおよび設定管理の調査状況レポート

## 最新の実施結果（2026-09-21）

- A–C の実装は完了。DFS 設定を `client_conf.json` の `dfs` エントリへ移行し、
  `SMB2_DFS_*` の読み込みを削除。Docker 用設定・実行スクリプト・README も更新。
- `internal/path.ParseReferralTarget` で先頭 1 文字の区切りを UNC に変換し、
  残りの構造は厳密に検証。正常な wire target と不正な target の回帰テストを追加。
- `go test -short ./...`: PASS。
- `go test -v -run TestDFSIntegration .`: 7 サブテスト中 6 PASS、`multi_hop` FAIL。
  したがって「全サブテスト通過」の目標は未達。

### 新たに確認した阻害要因

Samba 4.24.6 の実応答を `Session.GetDFSReferrals` で確認したところ、
`\\127.0.0.1\dfs\link-chain` は `HeaderFlags=2`（StorageServers のみ）、
`ServerType=0`（link）、target `\127.0.0.2\dfs-hop\入口` として返る。
次のターゲットへの mkdir は `STATUS_PATH_NOT_COVERED` を返す。

[MS-DFSC] 3.1.5.1 は link target からのこの応答では元の I/O を失敗させるよう要求する。
3.1.5.4.5 の interlink 判定（ReferralServers=1、StorageServers=0）にも該当しない。
クライアントの規格準拠チェックを緩和せず、サーバー側で適切な interlink referral を
返す環境を用意する必要がある。共有・symlink の存在だけではチェーン動作を保証できない。

`referral_cycle` は PASS だが、現在の検証はエラー文字列中の `cycle` を確認するだけで、
パス自体にも同じ文字列が含まれるため、実際の循環検出を証明しない。

以下は作業開始時の調査記録。

---

## 1. 概要と目標
- **目標**:
  1. DFS統合テスト（`TestDFSIntegration`）の実行設定を環境変数（`SMB2_DFS_*`）から `client_conf.json` へ完全移行する（互換用フォールバックは残さずクリーンに置換）。
  2. ローカルのSamba DFS環境で `go test -v -run TestDFSIntegration .` が全サブテスト含め正常にパスすることを確認する。

---

## 2. ローカルSambaのDFS環境検証結果
`/etc/samba/smb.conf` および `/srv/samba` の実環境を調査済み：
- **NetBIOS Aliases**: `127.0.0.2`, `127.0.0.3`（`127.0.0.1` とともにローカルループバックでSambaに到達可能）
- **DFSルート共有**: `[dfs]` (`/srv/samba/dfs`, `msdfs root = Yes`)
  - `link` -> `msdfs:127.0.0.2\dfs-target`
  - `link-alias` -> `msdfs:127.0.0.2\dfs-target`
  - `link-chain` -> `msdfs:127.0.0.2\dfs-hop\入口`
  - `link-cycle` -> `msdfs:127.0.0.2\dfs-hop\cycle`
  - `link-extra` -> `msdfs:127.0.0.3\dfs-encrypted\nested`
- **ターゲット共有**:
  - `[dfs-target]` (`/srv/samba/dfs-target`)
  - `[dfs-encrypted]` (`/srv/samba/dfs-encrypted`, `server smb encrypt = required`)
  - `[dfs-hop]` (`/srv/samba/dfs-hop`, `msdfs root = Yes`)
  - `[dfs-hop2]` (`/srv/samba/dfs-hop2`, `msdfs root = Yes`)

必要な共有・シンボリックリンク・ディレクトリ構成はローカル環境に完全に揃っていることを確認済み。

---

## 3. 現状のテスト失敗と根本原因の特定

### 現象
DFSの接続パラメータを指定して `TestDFSIntegration` を実行したところ、全サブテストで以下のエラーとなり失敗した：
```
writefile \\127.0.0.1\dfs\link\go-smb2-dfs-...txt: invalid argument
```

### 根本原因の解析
1. **DFSリファラル要求の発行**:
   - `c.client.WriteFile` は `\\127.0.0.1\dfs\link\...` にアクセスし、Sambaから `STATUS_PATH_NOT_COVERED` を受け取ると、IPC$パイプ経由で `FSCTL_DFS_GET_REFERRALS` を送信する。
   - Sambaは正常にリファラル応答（`ReferralResponse`）を返す。
2. **`NetworkAddress` のフォーマット不一致**:
   - [MS-DFSC] 2.2.4 の仕様およびSambaの実装により、リファラルエントリの `NetworkAddress` は先頭バックスラッシュが1つの `\127.0.0.2\dfs-target` として返される。
   - 一方で、`client/client.go` の `installReferral`（898行目）において以下のようにパースしている：
     ```go
     target, err := pathpkg.ParseUNC(item.NetworkAddress)
     if err != nil {
         return nil, err
     }
     ```
   - `pathpkg.ParseUNC`（`SplitUNC`）はUNC形式（先頭が `\\` の2文字）を必須としており、`\127.0.0.2\dfs-target` に対して `os.ErrInvalid`（`"invalid argument"`）を返してしまう。
3. **結果**:
   - `installReferral` が `os.ErrInvalid` で失敗し、クライアントのリファラルキャッシュへの登録が中断。
   - その結果、後続のアクセスがすべて `invalid argument` で失敗していた。

---

## 4. 今後の対応手順

### A. `item.NetworkAddress` の正規化修正 (`client/client.go` または `internal/path`)
- `installReferral` 内で `item.NetworkAddress` をパースする際、先頭のバックスラッシュが1つの場合（あるいは `normalizePublicUNC` 等を利用して）UNCパス（`\\server\share\...`）に正規化してから `ParseUNC` に渡すよう修正する。

### B. `client_conf.json` の設定追加
`client_conf.json` にDFS統合テスト用のエントリを追加：
```json
{
  "name": "samba-dfs",
  "transport": {
    "type": "tcp",
    "host": "127.0.0.1",
    "port": 445
  },
  "session": {
    "type": "ntlm",
    "user": "smbuser",
    "passwd": "Smbpasswd12345",
    "domain": "SMB2TEST"
  },
  "tree_conn": {
    "share1": "dfs"
  },
  "dfs": {
    "target": "127.0.0.2",
    "second_target": "127.0.0.3",
    "link": "link"
  }
}
```

### C. `smb2_test.go` の設定読み込み部リファクタリング
- `type config` に `DFS *dfsConfig` を追加。
- `loadEnvs()` で `cfg.DFS != nil` の場合は `envs`（通常ファイルテスト用）には追加せず、グローバル変数 `dfsEnv` に格納する。
- `loadDFSIntegrationConfig(t *testing.T)` は `os.Getenv("SMB2_DFS_*")` を完全に廃止し、`dfsEnv` から直接ロードするように変更する（未設定時は `t.Skip`）。

### D. 検証
- `go test -short ./...`（ユニットテスト全通過の確認）
- `go test -v -run TestDFSIntegration .`（DFS統合テスト全サブテスト通過の確認）
