# Third-Party Licenses and Dependency Boundaries

本書は、Mother_H 公開リポジトリ（領域 A: 安全コアおよび公開契約仕様）が現行ビルドおよび公開ソースコード上で利用する外部依存ライブラリと、標準システム依存のライセンス境界を記録したものです（ADR-ARCH-001 第2節準拠）。

## 1. 現行公開コードの外部依存ライブラリ一覧

| ライブラリ名 | 確認バージョン（検証環境） | ライセンス | 利用箇所・用途 | 備考・リンク形態 |
| :--- | :--- | :--- | :--- | :--- |
| **OpenSSL Crypto** | MSYS2 UCRT64: 3.6.4-1<br>WSL2: 3.5.5-1ubuntu3.7 | Apache-2.0 | Journal / AUTH / Storage の暗号処理・検証テスト | CMakeLists.txt 上で OpenSSL::Crypto としてリンク。OpenSSL 3.x 系を前提とする。 |
| **Boost.Multiprecision** | MSYS2 UCRT64: 1.92.0-3<br>WSL2: 1.90.0.1ubuntu3 | BSL-1.0<br>(Boost Software License 1.0) | include/mother_H/common/numeric.hpp（および互換ヘッダー include/mother_H/numeric.hpp）の cpp_int と関連数値境界テスト | ヘッダーオンリー利用。共有ライブラリのリンクなし。 |

## 2. OS / コンパイラ標準システム依存（第三者ライブラリ対象外）

以下の要素はビルド・実行環境の OS または CMake 標準抽象機構に属するものであり、独立した第三者製ライブラリではありません。

- **CMake Threads (Threads::Threads)**: OS 標準スレッド機構への CMake 抽象ターゲット
- **Windows SDK (crypt32, windows.h)**: Windows 環境における暗号保護 API（DPAPI 等）および OS システムヘッダー
- **POSIX システム API (flock, unistd.h 等)**: POSIX 準拠環境におけるファイルロック・システムコール

## 3. 公開範囲外の外部資産に関する境界注記

本公開リポジトリには、出所・権利・ライセンス条件が個別に確定していない外部取り込み資産や非公開実装は一切同梱されていません。将来的に外部由来のコード・ライブラリを本公開リポジトリへ追加する場合は、事前に権利帰属と Apache-2.0 とのライセンス互換性を検証したうえで本一覧へ追記します。

## 4. 法的免責注記

本一覧は本公開リポジトリ内の技術的依存調査に基づく記録であり、法的助言を構成するものではありません。各外部ライブラリの配布・利用条件については、それぞれの原著作者が定める公式ライセンス本文に従ってください。
