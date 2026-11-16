# ADR-AUTH-001: 単回使い切り臨時鍵モデル

- **状態**: AUTH-008 / AUTH-009実装の技術設計決定
- **決定**: A案（単回使い切り・再利用不可の臨時鍵モデル）
- **正式基準**: `Mother_H セキュリティ強化計画 v0.5.1`を維持する。本ADRだけではv0.5.1の正式要件表やManifesto第9章を改訂しない。正式改訂はオーナーの明示承認待ち。
- **実装・検証状態**: コミット `5a4fe68` でAUTH API、ファイルベースのトランザクショナルRegistry、専用テストを追加。報告された検証実績はWindows MSYS2 UCRT64全体CTest 65/65 PASS、WSL2 Linux ASan + UBSan全体CTest 65/65 PASS、WSL2 Linux Standalone TSanでAUTH-008/009の20ケースPASS（データ競合の検出報告なし）。いずれも実行したテスト範囲に限る結果であり、未実行経路のメモリ安全性・データ競合不存在を証明しない。実運用の署名検証器・鍵管理・AuditSinkの独立性は別途構成が必要。

## 決定事項

### 1. A案: 単回使用・再利用不可の臨時鍵

鍵の状態遷移は次の一方向のみとする。

`PendingApproval` → `ApprovedUnused` → `InUseConsumed` → `Burned`

- 使用済み、期限切れ、取消済み、実行異常、監査失敗後の鍵を再利用・復活させない。
- `Burned`からの遷移を禁止する。新たなアクセスには新規申請、人間による再審査、新しい鍵の発行を必要とする。
- 過去の承認履歴は審査の参考資料に限り、次回の許可を自動的に構成しない。
- `InUseConsumed`への遷移は原子的に行い、競合する複数要求のうち使用を開始できるのは最大1件とする。

### 2. 法的判断と技術検証の分離

- AIは法的根拠の適法性を独断で判断しない。
- 技術的な責務は、AUTH-008の形式要件検証・不備拒否・監査記録、およびAUTH-009の承認範囲と数量上限の強制に限る。
- Human Gateによる審査・承認の事実を`human_approval_ref`と要求内容・scopeのダイジェストに結合して検証する。これは人間の判断を技術的に記録・照合するもので、AIによる適法性判断ではない。
- 承認者は申請で提示された各数量上限を超えて承認できない。Grantの有効上限は申請上限と承認上限の各項目の小さい値とし、承認による権限拡大を許さない。

### 3. 迂回不能な実行境界と二段階独立監査

- `ScopedExecutionGuard`は、生のリソースハンドルを実行コールバックに渡さない。協調セッション`BoundedResourceSession`のみを渡し、`bytes` / `steps` / `items`を外部操作またはデータ公開の前に計量・遮断する。
- 構造化監査レコードに、生トークン、秘密鍵、署名全体を含めない。
- 認可判定、実行開始intent、実行終了（`Burned`確定・実消費量・取得ハッシュ要約）を`IAuditLogSink`へ記録する。
- `append()`失敗時は許可を返さず、外部実行を開始しない。使用開始後にOutcome監査が失敗した場合は結果不確定として扱い、自動再実行を禁止する。
- 鍵が`Burned`になったかと、Outcome監査の記録に成功したかを別々に報告する。

## Manifesto第9章の検討用8原則

以下は検討案の記録であり、Manifesto第9章またはv0.5.1の正式要件を変更するものではない。

1. 法的判断は人間に留保し、AIは定義済みの形式検証だけを行う。
2. 要求元・認証・署名・対象・範囲・期間に不備がある要求はFail-Closedで拒否する。
3. 要求は対象、操作、期間、数量上限を明示し、単一の署名や命令から無制限の権限を導かない。
4. Human Gateの承認は要求内容とscopeに結び付け、承認参照だけを別要求へ流用できないようにする。
5. 臨時鍵は一回限りとし、使用・取消・期限切れ・異常後に再利用または復活させない。
6. 実行コードには生ハンドルを渡さず、すべての外部操作をscope付きの実行境界へ通す。
7. 監査記録には秘密情報を含めず、許可・拒否・intent・結果を人間が確認可能な形式で残す。
8. 認証、承認、監査、数量制限のいずれかを確認できない場合は許可せず、監査失敗後の実行再試行も自動化しない。

## 保証境界・未確定事項

- Request / Approval / Revocation / Scope / Grantのcanonical形式は`*_V1` domain separation、固定フィールド順、長さprefix付きUTF-8、big-endian整数で定義する。入力のUnicode正規化は行わず、UTF-8として不正な値を拒否するため、正規化形式の異なる文字列は別のscopeとして扱う。
- Request署名とHuman Approval/Revocation署名の暗号アルゴリズム・鍵運用は注入される検証器の責任であり、テスト用のmessage-binding Fakeは署名強度を証明しない。
- Grant MACは既存`ISecureKeyProvider`から鍵ID・version付きの`KeyMaterial`を取得し、OpenSSL HMAC-SHA-256で計算する。MAC秘密鍵はRegistryファイルに含めない。旧WALの検証には参照鍵versionが利用可能でなければならず、鍵取得・検証失敗時はFail-Closedとなる。
- `FileTransactionalRegistryStore`は状態SnapshotとOutboxを1イメージとして正規化し、安定した`.lock`ファイル上でOS排他ロックを取る。Windowsは`LockFileEx`、POSIX/WSL2は`flock`を用い、プロセス内mutexは同一プロセスの補助排他に限る。
- コミット順は、(1) WAL一時ファイル作成・flush、(2) WAL atomic replaceと親ディレクトリ同期、(3) 本体一時ファイル作成・flush、(4) 本体atomic replaceと親ディレクトリ同期、(5) WAL削除と親ディレクトリ同期。Windowsでは`FlushFileBuffers`と`MoveFileExW(MOVEFILE_WRITE_THROUGH)`、POSIXでは`fsync`と`rename`を使う。本体の永続化確認前にWALを削除しない。
- 起動時の読み込みではWALと本体のHMAC・transaction ID・revisionを照合する。旧本体の次revisionを持つ有効WALは本体へ適用し、既に同一transactionが本体に反映済みならWALを整理する。部分／不整合WAL、鍵取得失敗、HMAC不一致は`Indeterminate`またはIntegrity failureとして拒否し、操作を自動再実行しない。`InUseConsumed`や`Started`を`ApprovedUnused`へ戻さず、Started grantの再beginは拒否する。
- `ApprovalStatus`、`KeyTrustStatus`、`ExecutionPhase`は同一Registryトランザクション内で更新する。`revoke_approval`と`begin_execution`は同じファイルロック・WAL commit境界に属し、commit順が勝敗を決める。Outbox ACK更新は`outbox_ack_revision`のみを進め、Grant有効性に使うRegistry revisionを変えない。
- `IntentAuditReceipt`はevent ID、sink ID、event digest、受領時刻、MAC、key versionを持つ。Registryへのreceipt永続化前はbeginを許可しない。AuditSinkはevent ID重複配信に対して同じ受領結果を返す必要がある。Outbox永続化、Sink受領、receipt永続化、独立監査媒体への保存は別の保証である。
- セッションAPIごとにRegistry transactionで取消・期限・execution stateを確認し、`session_operation_sequence`を永続更新する。そのcommitが論理的なAPI呼び出し開始点である。取消commitが先なら拒否し、呼び出しpermit commitが先なら既に始まった同期操作の停止・rollbackは保証しない。
- HMACは保存データの改ざん検知であり、正当な過去Snapshot/WALの復元を検出する物理巻き戻し耐性ではない。独立した単調アンカーをこのバックエンドに接続していないため、バックアップ復元・ディスク巻き戻しへの耐性は未保証である。POSIXの親ディレクトリfsyncは行うが、WindowsではMoveFileExのwrite-throughに依存する。
- テスト用のSecureKeyProviderは固定鍵を返すFakeであり、実鍵管理を証明しない。多プロセステストは同一テスト鍵を利用してファイル排他・単回CASを検証するが、TPM/HSM、鍵失効運用、AuditSinkの物理的独立性は検証しない。
- 現行の`AuthenticatedEventJournal`は認証済みJournal記録の基盤だが、このADRが求める独立監査シンクそのものではない。
- 外部アクセス要求に含める権限・委任・法的根拠の詳細な形式、時計の信頼境界、実行中断不能な同期操作の扱いは、本番運用前に個別確認する。
