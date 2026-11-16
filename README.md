# ♨ AI湯婆婆 (ai-yubaba)

SSH越しにLinuxサーバー／LXCコンテナの中身（OS・ポート・稼働サービス・Docker・セキュリティ更新状況）を監査し、ローカルLLM（Ollama）を使ってサーバーの役割を見抜き、ふさわしいシンプルなホスト名を命名・設定するCLIツールです。

外部のクラウドAPIには一切データを送信せず、手元のローカルLLM（Ollama）だけで完結するため、自宅ラボや社内インフラのサーバー構成情報を安全に監査できます。

## 主な機能

- **役割の自動監査:** 外部待ち受けポート、systemdサービス、稼働中のDockerコンテナからサーバー本来の働き（Web、DNS、監視、AI推論など）を見抜きます。
- **セキュリティ・衛生チェック:** `apt` の未適用アップデート件数、カーネル更新後の再起動忘れ、SSHのパスワード認証・`root` ログイン許可を検知し、深刻度に応じた温度感で湯婆婆が叱りつけます。
- **重複防止の契約台帳:** 命名したホスト名と由来を `used_names.txt` に記録し、同一環境内でのホスト名重複を防ぎます。
- **幅広い認証・コンテナ環境に対応:**
  - SSH公開鍵認証、FIDO2セキュリティキー（`ecdsa-sk`）、`~/.ssh/config`、パスワード認証に対応（`ControlMaster` による接続再利用）。
  - `hostnamectl` が使えないLXCコンテナや非systemd環境でもフォールバックしてホスト名・`/etc/hosts` を書き換えます。

## 動作要件

- **実行環境（クライアント側）:** Python 3.10 以上、OpenSSH クライアント
- **LLMバックエンド:** [Ollama](https://ollama.com/) が稼働しているローカルまたはLAN内のサーバー（構造化出力に対応した `gemma4:12b` や `mimo-v2.6:latest` など）
- **監査対象（ターゲット側）:** SSH接続可能な Linux サーバー / VM / LXC コンテナ（Debian / Ubuntu 系推奨）

## セットアップ

```bash
git clone [https://github.com/](https://github.com/)<your-username>/ai-yubaba.git
cd ai-yubaba

python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## 環境設定（.env）

- テンプレートをコピーして、お使いの Ollama サーバーのアドレスやモデル名を設定します。

```Bash
cp .env.example .env
コード スニペット
OLLAMA_HOST=http://localhost:11434
YUBABA_MODEL=gemma4:12b
YUBABA_LEDGER=used_names.txt
```

## 使い方


```Bash
# 基本の実行（~/.ssh/config のホスト名または user@ip を指定）
python ai_yubaba.py user@192.168.1.10

# 特定の秘密鍵ファイルを指定して接続する場合
python ai_yubaba.py -i ~/.ssh/id_ed25519 user@192.168.1.10

# 引数なしで起動して対話的に接続先を入力する場合

python ai_yubaba.py

実行例
```

```Plaintext
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  ♨  油屋 インフラ管理室 ―― AI湯婆婆 契約の儀  ♨
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
「ここで働きたいだって？まったく、どいつもこいつも…！
 さあ、契約書に書きな！あんたの『接続先（手形）』は何ていうんだい？」

▶ 差し出された手形（接続先）: user@192.168.1.10

「ふむ…ちょっと中身と身なりを改めさせてもらうよ…」

「ほう…契約書には『ubuntu-2404-template』と書いてあるのかい。」

--- 監査結果（中身・衛生状態） ---
=== HOSTNAME ===
ubuntu-2404-template
=== OS ===
Ubuntu 24.04.4 LTS
=== CPU/MEM ===
CPU: 4 cores / MEM: 7.8Gi
=== PUBLIC PORTS ===
tcp 0.0.0.0:22
tcp 0.0.0.0:80
tcp 0.0.0.0:443
=== SERVICES ===
docker.service
nginx.service
=== DOCKER ===
open-webui
ollama
=== SECURITY & UPDATES ===
aptリスト更新: 成功（最新状態を確認）
未適用アップデート: 合計 3件 (うちセキュリティ更新 3件)
再起動ステータス: 問題なし
----------------------------------

「ふむふむ…（gemma4:12b が品定め中）…」

┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
  「ほう、あんたはDockerでAIの知恵箱を捌く仕事ができるんだね。
   …それにしても！ふん、まあまあ身ぎれいにしてるじゃないか。ただ、細かい更新が数件残ってるから後でサッと片付けておきな。
   『ubuntu-2404-template』なんて贅沢な名だね。
   あんたは『知恵を蓄える社』だから、今日から『yashiro』だよ！」
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

「いいかい、返事は『はい』か『y』だけだよ！ホスト名を『yashiro』に書き換えるよ？」 [y/N]: y

「契約完了だ！『yashiro』、グズグズしないでさっさと働きな！！」
（※ 契約台帳 used_names.txt に由来とともに名を刻みました）
```

## セキュリティ上の注意

監査時にターゲットサーバー上のサーバー構成情報（ホスト名・OS・ポート一覧・コンテナ名）を OLLAMA_HOST へ送信します。機密性の高いインフラに対して実行する場合は、必ずローカル環境または信頼できる閉域ネットワーク上の Ollama インスタンスを指定してください。

契約台帳（used_names.txt）および環境設定ファイル（.env）は .gitignore によりGitの追跡対象から除外されています。

