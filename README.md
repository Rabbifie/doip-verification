# STM32 DoIP 実機検証スクリプト

STM32F767ZI + LAN8651 で構成した DoIP（Diagnostics over Internet Protocol）ECU に対し、
PC 側（EVB-LAN8670-USB）から診断通信を行って動作を確認するための Python スクリプトです。

Note 記事「STM32＋LAN8651でDoIPを実機検証：Vehicle IdentificationからUDSのVIN読み出しまで」
で使用した検証スクリプトを公開しています。

## 構成

| スクリプト | 対象レイヤ | 主な検証内容 |
|---|---|---|
| doip_test.py | DoIP トランスポート層 | Diagnostic Message の ACK/NACK、TCP 分割・連結受信、サイズ上限、初期タイムアウト |
| doip_uds_test.py | UDS サービス層 | セッション制御、TesterPresent、VIN 読み出し、Negative Response |

どちらも Python 標準ライブラリのみを使用し、doipclient / udsoncan などの
外部パッケージには依存しません。

## 必要環境

- Python 3.8 以上（標準ライブラリのみで動作）
- PC 側: Microchip EVB-LAN8670-USB（10BASE-T1S USB アダプタ）
- ECU 側: STM32F767ZI + LAN8651 上で動作する DoIP サーバ実装

## 既定の接続先

| 項目 | 既定値 | 変更オプション |
|---|---|---|
| ECU IPv4 アドレス | 192.168.1.10 | `--host` |
| DoIP TCP ポート | 13400 | `--port` |
| Tester Source Address | 0x0E00 | `--tester-sa` |
| ECU Logical Address | 0x1000 | `--ecu-sa` |
| VIN | TEST1234567890123 | `--vin` |

---

## doip_test.py（DoIP 通信処理の確認）

Diagnostic Message の ACK/NACK と TCP 受信処理を確認します。
UDS サービスの実行・判定は行いません。

| テスト | 内容 | 成功判定 |
|---|---|---|
| positive | 正常な Diagnostic Message（既定 22 F1 90）に対する ACK | 0x8002 ACK code 0x00 |
| fragmented | 1 メッセージを複数の TCP 送信片に分割して送信 | 分割後も ACK を受信 |
| concat | 2 つのメッセージを 1 回の send() で連結送信 | 2 件とも ACK を受信 |
| invalid-target | 不明な Target Address への診断要求 | NACK 0x8003 code 0x03 |
| wrong-source | Routing Activation と異なる Source Address で診断要求 | NACK 0x8003 code 0x02 または制御された切断 |
| oversized | サイズ上限を超えるペイロードを送信 | NACK 0x8003 code 0x04、または制御された切断 |
| inactivity | Routing Activation せず TCP 接続を放置 | ECU 側からの切断を確認 |

### 実行例（PowerShell）

```powershell
py .\doip_test.py --test positive
py .\doip_test.py --test fragmented
py .\doip_test.py --test concat
py .\doip_test.py --test invalid-target
py .\doip_test.py --test wrong-source
py .\doip_test.py --test oversized
py .\doip_test.py --test inactivity
```

### oversized テストの注意

`--oversize-uds-bytes` で UDS データ長を指定します（既定 100 → DoIP ペイロード 104 バイト）。
DoIP ペイロード長 1025 バイト（受信上限 1024 バイト超過）を試す場合は次のようにします。

```powershell
py .\doip_test.py --test oversized --oversize-uds-bytes 1021
```

（Source / Target Address の 4 バイトを加えて DoIP ペイロード 1025 バイトになります）

スクリプトは NACK 0x04 を受信した場合に成功判定しますが、
**接続が閉じた場合も "PASS/REVIEW" として扱います**。
接続が閉じたという結果だけでは、意図したプロトコル動作が実現できたとは
判断できないため、UART ログや Wireshark キャプチャとの照合が必要です。

### 主なオプション

| オプション | 既定値 | 説明 |
|---|---|---|
| `--test` | positive | テスト種別 |
| `--host` / `--port` | 192.168.1.10 / 13400 | 接続先 ECU |
| `--tester-sa` | 0x0E00 | Tester 論理アドレス |
| `--ecu-sa` | 0x1000 | ECU 論理アドレス（Routing Activation の期待値） |
| `--target` | 0x1000 | 診断要求の Target Address（invalid-target では自動で 0x1234 を使用） |
| `--diagnostic-sa` | 未指定 | 診断メッセージ内の SA 上書き（wrong-source 用。未指定時は tester-sa + 1 を自動使用） |
| `--uds` | 22 F1 90 | 送信する UDS バイト列 |
| `--second-uds` | 3E 00 | concat テストの 2 通目 |
| `--fragment-delay` | 0.05 秒 | 分割送信の間隔 |
| `--oversize-uds-bytes` | 100 | oversized テストの UDS データ長 |
| `--inactivity-wait` | 3.5 秒 | inactivity テストの監視時間 |
| `--timeout` / `--connect-timeout` | 3.0 / 5.0 秒 | 応答・接続タイムアウト |

既定の UDS ペイロードは 22 F1 90 ですが、Phase 6 は UDS サービスを実装・判定しません。
VIN が正しく返ることまで確認するには Phase 7 を使用してください。

---

## doip_uds_test.py（UDS サービスの確認）

TCP 接続と Routing Activation を行った後、UDS 要求を送信し、
**DoIP ACK の後続として返される UDS 応答（別の 0x8001 メッセージ）**まで検証します。

| テスト | UDS 要求 | 期待する応答 |
|---|---|---|
| session | 10 01 / 10 03 | 50 01 / 50 03 ＋ P2Server / P2*Server 値を表示して検証 |
| tester-present | 3E 00 | 7E 00 |
| vin | 22 F1 90 | 62 F1 90 ＋ VIN（`--vin` と完全一致判定） |
| negative | 22 F1 91 / 99 / 10 | 7F 22 31 / 7F 99 11 / 7F 10 13 |

### 実行例（PowerShell）

```powershell
py .\doip_uds_test.py --test all
py .\doip_uds_test.py --test session
py .\doip_uds_test.py --test tester-present
py .\doip_uds_test.py --test vin
py .\doip_uds_test.py --test negative
```

`--test all` は、1 回の TCP 接続・Routing Activation の中で
session → tester-present → vin → negative の順に実行します。

### 主なオプション

| オプション | 既定値 | 説明 |
|---|---|---|
| `--test` | all | テスト種別 |
| `--host` / `--port` | 192.168.1.10 / 13400 | 接続先 ECU |
| `--tester-sa` / `--ecu-sa` | 0x0E00 / 0x1000 | 論理アドレス |
| `--vin` | TEST1234567890123 | 期待する VIN（17 文字の ASCII 必須） |
| `--protocol-version` | 0x02 | DoIP プロトコルバージョン |
| `--timeout` / `--connect-timeout` | 4.0 / 4.0 秒 | 応答・接続タイムアウト |

---

## 終了コード

| コード | 意味 |
|---|---|
| 0 | PASS（oversized で接続切断を観測した PASS/REVIEW を含む） |
| 1 | FAIL またはタイムアウト |
| 2 | 判定保留（wrong-source で NACK なしの切断を観測した場合など）・使用方法エラー |

## 共通の注意

- 両スクリプトとも TCP 接続後の検証を対象としています。Vehicle Announcement や
  UDP による Vehicle Identification Request を網羅的に試験するスクリプトではありません。
- Alive Check Request（0x0007）を受信した場合は、スクリプトが自動で
  Alive Check Response（0x0008）を返します。
- DoIP 0x8002 ACK は要求のトランスポート処理が受け付けられたことを示すもので、
  UDS サービスの成功を保証するものではありません。
- 応答が期待と異なる場合は、UART ログと Wireshark キャプチャ
  （フィルタ例: `tcp.port == 13400`）での確認を推奨します。

## ライセンス

MIT License（詳細は [LICENSE](LICENSE) を参照）
