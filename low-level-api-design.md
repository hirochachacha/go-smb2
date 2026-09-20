# 低レベル API 公開案

ステータス: `x/wire` 移行済み。`x/protocol` への移行方針。

## 目的

利用者が RequestBuilder やパケット型にアクセスし、任意のリクエストを
組み立てて送信できるようにする。低レベル API の互換性や、任意の使い方の
動作は保証しない。メインの File API も同じ低レベル実装を利用する。

## パッケージ構成案

まずは同一モジュール内で分割し、独立したモジュールにはしない。
`x` は互換性保証の対象外であることを示し、その下は責務で命名する。

| 層 | パッケージ | 責務 |
|---|---|---|
| 上位 | `client` | 現在の `dfs`。DFS 解決、接続・共有の管理 |
| 中位 | `smb2`（ルート） | `Share`・`File` によるファイル操作 |
| 下位 | `x/protocol` | 接続・セッション・ツリー、RequestBuilder、応答管理 |
| ワイヤー形式 | `x/wire` | 旧 `internal/smb2`。パケット型・定数・エンコード・デコード |

依存方向は `client → smb2 → x/protocol → x/wire`。
低レベル層からルートパッケージへの依存は持たせない。
実装を移しても、接続やセッションの内部をすべて公開する必要はない。

`Dialer`・`Session`・認証・Transport の上位入口はルートに残す。
低レベル層が生成するエラー型は `x/protocol` に移し、旧名のエイリアスは残さない。
`dfs → client` の改名は今回の移行には含めない。

## 利用者向けの入口

入口は次の形。通常の File API もこの Request を利用する。

```go
func (s *Share) Request() *protocol.Request
```

`Request.Append` でパケットを末尾へ追加し、`Do(ctx)` で送受信する。
`WithFileID` と `WithFollowSymlinks` は Request 自身の設定を変更して返す。
非同期送受信は `Send(ctx)` と `PendingRequest.Receive()` に分ける。
Send から Receive 完了までは Request・パケット・借用バッファを変更しない。
通常送信ではクローンせず、symlink 再試行時だけ変更するリクエストをコピーする。
先頭 CREATE の解決後のパスは `Response.ResolvedPath()` から取得する。
`protocol.Dialer.Dial` は接続済み Transport 上でネゴシエーションと認証を行う。
パッケージコメントと `Share.Request` に、低レベル API は互換性保証の
対象外で、変更・削除される可能性があることを明記する。

## 動作と所有権

- シンボリックリンク追従は Request 単位で設定可能にする。
  低レベル API はデフォルトで追従せず、`WithFollowSymlinks(true)` で有効化する。
  通常の File API は現在の動作を維持する。
- 失敗時のハンドル回収はライブラリが行い、無効化オプションは設けない。
- 成功時に利用者へ渡したハンドルは利用者が管理する。
- 自動回収は、その Request の CREATE で生成された File ID だけを対象にする。
  既存ハンドルは自動 CLOSE しない。成功した CLOSE の対象も再回収しない。
- 応答は `Response.Close()` で解放する。取得したバイト列の有効期間は
  Close までとし、それ以降保持する場合は利用者がコピーする。

`Response.QueryInfo`・`QueryDir`・`Ioctl` は protocol の応答ラッパーを返す。
ラッパーの型付き payload アクセサーは、送信時に保存した情報クラス・IOCTL
コードと型が一致するか確認し、`IsInvalid()` を通した wire decoder を返す。
ディレクトリ一覧は全エントリを検証してから返す。検証はアクセサー呼び出し時に
行い、`Do()` 成功だけで全 payload の妥当性を保証するものではない。
未知の形式には `RawOutput()` を使う。RPC・DFS などの上位形式は引き続き
呼び出し側で解釈・検証する。
`RawOutput()`・`Response.Data()`・`Bytes()` から新たに作った decoder は
`IsInvalid()` が必要。検証済み decoder の再検証は不要。
応答ビューは変更せず、Close までに使用する。直接受信した READ は
`DirectData()` を使用し、連続した応答を必要とする `Read()` では扱わない。

受信データの検証、共有接続のライフサイクル、リクエスト単位のキャンセルは
引き続きライブラリが担う。低レベル API の公開によって既存の安全性を緩めない。

## 参考にする前例

- [MongoDB Go Driver の x/mongo/driver](https://pkg.go.dev/go.mongodb.org/mongo-driver/v2/x/mongo/driver):
  内部機能へのアクセスのために公開し、API の安定性・後方互換性を保証しない。
  今回の構成に最も近い前例。
- [gRPC-Go の experimental](https://pkg.go.dev/google.golang.org/grpc/experimental):
  実験的 API を同一モジュール内の専用パッケージで公開する例。
