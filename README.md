# O-RAN CU-Plane IQ Analyzer
> O-RAN 5G Fronthaul IOT Tool

---

## Overview

PCAPファイルからO-RAN U-PlaneのBFP圧縮IQデータを抽出し、dBFS電力とコンスタレーションを表示するGUIツールです。

**対応フォーマット:**

| 項目 | 内容 |
|------|------|
| ファイル形式 | `.pcap` (libpcap) |
| トランスポート | eCPRI over Ethernet（802.1Q VLAN対応）|
| セクション | Section Type 1 |
| 圧縮方式 | BFP（IQ各9bit、指数部4bit）|
| SCS | 15 kHz / 30 kHz（FR1）|
| アンテナ | 最大 4T4R（RU_Port_ID 0〜3）|

---

## Installation

### オンライン環境

1. [Python 3.8以上](https://www.python.org/downloads/) をインストール

2. 依存ライブラリをインストール:
   ```bash
   pip install -r requirements.txt
   ```

3. 起動:
   ```bash
   python oran_iq_analyzer.py
   ```

### オフライン環境（依存ライブラリ同梱）

**オンライン環境でパッケージをダウンロード:**
```bash
mkdir wheels
pip download -r requirements.txt -d wheels --platform win_amd64 --python-version 38 --only-binary :all:
```

**オフライン環境でインストール・起動:**
```bash
pip install --no-index --find-links=wheels -r requirements.txt
python oran_iq_analyzer.py
```

---

## Usage

### 1. Input File
`[...]` ボタンで解析対象の `.pcap` ファイルを選択します。

### 2. Frame Range

| パラメータ | 説明 |
|-----------|------|
| Start | 解析開始フレーム番号（1始まり）|
| End | 解析終了フレーム番号（`-1` = 全フレーム）|

> 大容量pcapは範囲を絞ることを推奨します。

### 3. Filter

| パラメータ | 説明 |
|-----------|------|
| Direction | `DL` または `UL` を選択 |
| RU_Port_ID | `0`〜`3` を選択（4T4R）|

### 4. Signal Parameters

| パラメータ | 選択肢 |
|-----------|--------|
| BW (MHz) | 5 / 10 / 15 / 20 / 25 / 40 / 50 / 100... |
| SCS (kHz) | 15 / 30 |

### 5. Advanced (Parser)

| パラメータ | 説明 |
|-----------|------|
| eAxC mode | `standard`（O-RAN標準）または `custom`（bit幅を手動指定）|
| Sec Hdr | セクションヘッダサイズ（`4` または `8` bytes）— ベンダーに合わせて変更 |

### 6. 解析実行
`[▶ Analyze]` ボタンで解析を開始します。`[■ Stop]` で中断できます。

### 7. Power / dBFS タブ

- **上部数値:** 平均dBFS値（色でステータスを表示）
  - 🟢 緑: ±1 dB 以内
  - 🟡 黄: ±3 dB 以内
  - 🔴 赤: ±3 dB 超
- **グラフ:** スロット単位の時系列電力
- **Full-RB表示:** パケット内RB数 vs 期待RB数

### 8. Constellation タブ

IQコンスタレーションを表示します（最大50,000点）。DL/ULとRU_Port_IDの切り替えは左パネルから行います。

### 9. File メニュー

| メニュー項目 | 動作 |
|-------------|------|
| Save Graph (PNG) | 現在表示中のグラフをPNGで保存 |
| Save Graph (PDF) | 現在表示中のグラフをPDFで保存 |
| Export CSV | 全解析結果をCSVでエクスポート |

---

## Technical Notes

### BFP 復号式

```
復号値 = mantissa_signed_9bit × 2^exponent
dBFS  = 10 × log10( avg(I_raw² + Q_raw²) / (2 × 255²) )
```

> exponent はdBFS計算でキャンセルされるため、相対比較に最適です。

### 0dBFS 条件

全サブキャリア（12 SC × numRB 個）で `I = ±255`, `Q = ±255` のとき `dBFS ≈ 0 dB`

### セクションヘッダ（デフォルト: 4 bytes）

```
[section_id:12][rb:1][sym_inc:1][start_prbc:10]  = 3 bytes
[num_prbc:8]                                       = 1 byte
```

8バイトモードでは上記に加え: `reMask(12)` + `numSymbol(4)` + `ef(1)` + `beamId(15)`

### eAxC ID（標準構成）

```
[DU_Port:4][BandSector:4][CC:4][RU_Port:4] = 16 bits
```

フィルタは `RU_Port_ID` と `dataDirection` ビット（app header byte0 の MSB）で実施します。

---

## Troubleshooting

### "No data for dir=UL, RU_Port=0" と表示される
`Available keys` に表示されたdirectionとRU_Port_IDを確認してください。`dataDirection` ビットの解釈がベンダーにより異なる場合があります。**Direction を DL に切り替えて**みてください。

### dBFS値が極端に低い（-60 dB 以下）
セクションヘッダサイズを変更してください（`4` ↔ `8`）。パーサーがIQデータをずれた位置から読んでいる可能性があります。

### コンスタレーションが原点付近に密集する
上記と同様、セクションヘッダサイズを確認してください。

### 処理が遅い
Frame Range の End を指定して範囲を限定してください。
例: `Start=1`, `End=10000`（約10万パケット相当）

---

## Source Customization

本ツールはPython単一ファイル構成です。`oran_iq_analyzer.py` 冒頭の定数を変更することで動作をカスタマイズできます:

```python
IQ_WIDTH          = 9     # IQ bits per sample
NUM_SUBC_PER_PRB  = 12    # subcarriers per PRB
REF_POWER_0DBFS   = 2.0 * (255 ** 2)  # 0dBFS reference power
```
