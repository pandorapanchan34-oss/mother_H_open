# Mother_H

**The Fail-Closed Safety Core for Personal AI — Phase 1 of [Pankunn OS](docs/PANKUNN_OS_MANIFESTO_v0.5.en.md)**

> *"Intelligence is free. User rights are guaranteed. The core of safety is unshakable."*

Mother_H is a C++17 safety core providing a Finite State Machine (FSM), authenticated event journaling, resource guards, and checkpoint/recovery mechanisms. Designed around the principle of **"separating AI intelligence from execution authority,"** it enforces a strict **Fail-Closed** posture—halting safely rather than expanding permissions whenever a state cannot be verified.

- **Vision & Philosophy:** Read the **[Pankunn OS Manifesto v0.5 (English)](docs/PANKUNN_OS_MANIFESTO_v0.5.en.md)** / **[日本語版マニフェスト](docs/PANKUNN_OS_MANIFESTO_v0.5.md)** to see the full roadmap from this safety core (Phase 1) to a personal AI OS (Phase 6: JARVIS).

---

Mother_H は、FSM（有限状態機械）、認証付きイベント記録、リソース制限、チェックポイントと復旧処理を提供する C++17 の安全コアです。**「AIの知能と権限を分離する」**という設計思想に基づき、検証できない状態では許可を広げず、安全側に停止（Fail-Closed）することを基本方針としています。

本リポジトリは、個人の生命・安全・プライバシーを守るオープンな AI 基盤 **[Pankunn OS](docs/PANKUNN_OS_MANIFESTO_v0.5.md)** の **Phase 1（安全基盤）** に位置づけられています。プロジェクト全体の理念やロードマップ（Phase 6: JARVIS への構想）については、**[Pankunn OS Manifesto v0.5](docs/PANKUNN_OS_MANIFESTO_v0.5.md)** を参照してください。
本リポジトリの領域 A（Mother_H 安全コアおよび公開契約仕様）として明示的に指定されたソースコードおよび仕様資産は、**Apache License 2.0 (Apache-2.0)** の下で公開されています。Apache-2.0 の適用範囲と除外対象については [NOTICE](NOTICE) を、ライセンス本文は [LICENSE](LICENSE) を参照してください。著作権・帰属表示は [NOTICE](NOTICE) を、依存ライブラリとライセンスの一覧は [第三者ライセンス一覧](docs/THIRD_PARTY_LICENSES.md) を参照してください。

## ビルド要件

- CMake 3.16 以降
- C++17 対応コンパイラー
- OpenSSL 3.x の Crypto ライブラリ
- Boost 1.70 以降（Boost.Multiprecision ヘッダー）
- OS のスレッドライブラリ
- Ninja を使う場合は Ninja が `PATH` 上にあること

## ビルドとテスト

標準の CMake とコンパイラーを利用する場合:

```sh
cmake -S . -B build -DBUILD_TESTING=ON
cmake --build build --parallel
ctest --test-dir build --output-on-failure
```

Ninja が `PATH` 上にあり、CMake Presets に対応する CMake 3.21 以降を利用する場合は、次のプリセットも使えます。

```sh
cmake --preset default
cmake --build --preset default
ctest --preset default
```

最適化ビルドでは `default` を `release` に置き換えてください。OpenSSL やコンパイラーが標準の検索パスにない環境では、各環境の CMake 標準設定（例: `CMAKE_PREFIX_PATH`）で場所を指定してください。プリセットにはマシン固有の絶対パスを含めていません。

## 期待されるテスト結果

`BUILD_TESTING=ON` の構成では、公開ツリー内の 49 個のテストソースからテストバイナリを作成します。CTest は通常のテストと、引数別に実行する ResourceGuard テストケースを含めて 60 項目を登録します。ビルドが成功した環境では、CTest の全項目が成功し、`100% tests passed` と表示されることが期待値です。テストには OpenSSL と C++17 対応環境が必要です。テスト時間や利用可能な OS API などは環境により異なります。

公開されたこと、ローカルで再現できたこと、独立した第三者検証を受けたことは別の評価です。テストの成功だけで安全性が証明されたり、プロジェクト全体の完了が示されたりするものではありません。

## 未実装事項と保証の限界

- プロジェクト全体の Phase 1 完了は宣言されていません。将来構想や仕様の記載は、実装済みまたは検証済みであることを意味しません。
- `src/main.cpp` は動作確認用のスモークエントリーポイントであり、常駐サービスや任意の外部操作を行う汎用エンジンではありません。
- 保護対象は定義されたアプリケーション権限・ポリシー境界です。ホスト OS の侵害、物理アクセス、端末自体の侵害に対する保護は保証しません。
- テスト用の鍵・署名・監査処理は、本番 KMS / TPM による鍵保護、実運用の鍵ローテーション・失効、または本番署名検証を証明しません。
- 保存データの改ざん検出は、独立した単調アンカーが接続されていない構成での過去状態への rollback 耐性を保証しません。
- 受領記録だけでは、監査記録が独立した媒体に保存されることや、その物理的独立性を保証しません。
- 単回の認可・開始は、外部サービス側の副作用が厳密に一度だけ実行されることや、外部操作の中断・rollback 耐性を保証しません。
- テスト結果は実際に実行されたテストと環境に限られ、未実行経路の安全性や、すべての環境での動作を証明しません。

依存関係とライセンスの詳細は [docs/THIRD_PARTY_LICENSES.md](docs/THIRD_PARTY_LICENSES.md) を参照してください。
