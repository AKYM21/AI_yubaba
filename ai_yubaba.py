import argparse
import getpass
import os
from pathlib import Path
import subprocess
from ollama import Client
from pydantic import BaseModel, Field


def load_dotenv(env_path: Path = Path(".env")):
    """外部ライブラリ不要のシンプルな .env ローダー"""
    if not env_path.exists():
        return
    for line in env_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


load_dotenv()

# ==========================================
# 設定（.env または環境変数で上書き可能）
# ==========================================
OLLAMA_HOST = os.getenv("OLLAMA_HOST", "http://localhost:11434")
MODEL_NAME = os.getenv("YUBABA_MODEL", "gemma4:12b")
LEDGER_FILE = Path(os.getenv("YUBABA_LEDGER", "used_names.txt"))

class YubabaOutput(BaseModel):
    evaluation_line: str = Field(
        description="湯婆婆の口調によるサーバーの役割評価（例: 'フン、あんたはDockerでWebを捌くことができるのかい。' または 'まったく、何の仕事もしていないただの空き箱じゃないかい！'）"
    )
    scolding_line: str = Field(
        description="衛生状態へのコメント。問題の深刻度に合わせて口調を変えること。問題なしなら空文字 ''。"
    )
    new_name: str = Field(
        description="役割のみを表すシンプルな1単語の新しいホスト名（英小文字のみ、ハイフン禁止、3〜8文字。元のホスト名や小言の内容は含めないこと）"
    )
    role_title: str = Field(
        description="このサーバーの働きを表す10文字以内の短い二つ名・名詞句（例: '知恵を蓄える箱'、'まだ殻をかぶった種'）。文章や「〜に命名」は禁止。"
    )


# ==========================================
# 1. 契約台帳からの読み込み・追記
# ==========================================
def load_used_names() -> list[str]:
    if not LEDGER_FILE.exists():
        return []
    names = set()
    for line in LEDGER_FILE.read_text(encoding="utf-8").splitlines():
        clean_name = line.split("#")[0].strip().lower()
        if clean_name:
            names.add(clean_name)
    return sorted(list(names))


def save_used_name(new_name: str, reason: str):
    with LEDGER_FILE.open("a", encoding="utf-8") as f:
        f.write(f"{new_name.lower()} # {reason}\n")


# ==========================================
# 2. SSH実行ラッパー（公開鍵・TrustKey・パスワード全対応）
# ==========================================
def run_ssh_command(
    target: str, command: str, identity_file: str | None = None
) -> str:
    ssh_opts = [
        "-o", "ControlMaster=auto",
        "-o", "ControlPath=/tmp/yubaba_ssh_%r@%h:%p",
        "-o", "ControlPersist=60",
    ]
    if identity_file:
        ssh_opts.extend(["-i", identity_file])

    cmd = ["ssh", *ssh_opts, target, command]
    result = subprocess.run(cmd, stdout=subprocess.PIPE, text=True)
    if result.returncode != 0:
        raise RuntimeError(
            f"「チッ、扉が開かないじゃないか！接続に失敗したよ（終了コード: {result.returncode}）」"
        )
    return result.stdout


# ==========================================
# 3. サーバー状態の収集（役割監査 ＋ 脆弱性・衛生チェック）
# ==========================================
def inspect_server(
    target: str, identity_file: str | None = None
) -> tuple[str, str, str]:
    is_root = run_ssh_command(target, "id -u", identity_file).strip() == "0"
    sudo_prefix = ""
    if not is_root:
        try:
            run_ssh_command(target, "sudo -n true 2>/dev/null", identity_file)
            sudo_prefix = "sudo "
        except RuntimeError:
            sudo_pass = getpass.getpass(
                f"「フン、中を改めるのに権限がいるね。[{target}] の sudo パスワードをお出し！」: "
            )
            sudo_prefix = f"echo '{sudo_pass}' | sudo -S "

    audit_cmd = f"""
    echo "=== HOSTNAME ===" && hostname
    echo "=== OS ===" && grep PRETTY_NAME /etc/os-release 2>/dev/null | cut -d= -f2 | tr -d '"'
    echo "=== CPU/MEM ===" && echo "CPU: $(nproc) cores / MEM: $(free -h | awk '/^Mem:/ {{print $2}}')"

    # ループバック以外の外部待ち受けポート（重複除去・上位15件）
    echo "=== PUBLIC PORTS ==="
    PUBLIC_PORTS=$(ss -tuln 2>/dev/null | awk 'NR>1 && $5 !~ /^(127\\.|\\[::1\\])/ {{print $1, $5}}' | sort -u | head -n 15)
    if [ -n "$PUBLIC_PORTS" ]; then
        echo "$PUBLIC_PORTS"
    else
        echo "外部待ち受けなし"
    fi

    # 稼働サービス（OS標準デーモンとローカル専用postfixを除外）
    echo "=== SERVICES ==="
    SERVICES=$(systemctl list-units --type=service --state=running --no-pager --no-legend 2>/dev/null \\
        | awk '{{print $1}}' \\
        | grep -vE '^(systemd|dbus|user@|getty|container-getty|ssh|cron|rsyslog|console-getty|networking|ifup|networkd-dispatcher|postfix|unattended-upgrades|polkit|udisks2|accounts-daemon|snapd|ModemManager|multipathd|packagekit|upower|containerd|nvidia-persistenced|qemu-guest-agent)' \\
        | head -n 15)

    if echo "$PUBLIC_PORTS" | grep -Eq ':(25|465|587)\\b'; then
        SERVICES=$(printf "%s\\npostfix (外部メール受付中)" "$SERVICES" | sed '/^$/d')
    fi

    if [ -n "$SERVICES" ]; then
        echo "$SERVICES"
    else
        echo "特記事項なし"
    fi

    # Docker（DB・キャッシュ・Worker等の裏方サブコンテナは除外して主役のみ抽出）
    echo "=== DOCKER ==="
    if command -v docker >/dev/null 2>&1; then
        CONTAINERS=$(docker ps --format "{{{{.Names}}}}" 2>/dev/null | grep -vE '(-db|-postgres|-postgresql|-redis|-valkey|-worker|timescaledb)' | head -n 15)
        if [ -n "$CONTAINERS" ]; then
            echo "$CONTAINERS"
        else
            echo "稼働コンテナなし"
        fi
    else
        echo "Dockerなし"
    fi

    # 衛生・セキュリティ監査（確実にapt-get updateを実行して最新化）
    echo "=== SECURITY & UPDATES ==="
    if command -v apt >/dev/null 2>&1; then
        if {sudo_prefix}apt-get update -qq >/dev/null 2>&1; then
            echo "aptリスト更新: 成功（最新状態を確認）"
        else
            echo "aptリスト更新: 失敗（キャッシュから判定）"
        fi
        UPG_ALL=$(LC_ALL=C apt-get -s upgrade 2>/dev/null | grep -c '^Inst ' || true)
        UPG_SEC=$(LC_ALL=C apt-get -s upgrade 2>/dev/null | grep '^Inst ' | grep -ic 'security' || true)
        echo "未適用アップデート: 合計 ${{UPG_ALL}}件 (うちセキュリティ更新 ${{UPG_SEC}}件)"
    else
        echo "未適用アップデート: 確認不可(非apt系)"
    fi

    if [ -f /var/run/reboot-required ]; then
        echo "再起動ステータス: 要再起動（カーネル等の更新後に未再起動）"
    else
        echo "再起動ステータス: 問題なし"
    fi

    SSH_PASS=$(grep -Eis '^PasswordAuthentication[[:space:]]+yes' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf 2>/dev/null | head -n 1)
    SSH_ROOT=$(grep -Eis '^PermitRootLogin[[:space:]]+yes' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf 2>/dev/null | head -n 1)
    if [ -n "$SSH_PASS" ]; then
        echo "SSH警告: パスワード認証が有効になっている"
    fi
    if [ -n "$SSH_ROOT" ]; then
        echo "SSH警告: rootのパスワード直接ログインが許可されている"
    fi
    true
    """
    raw_report = run_ssh_command(target, audit_cmd, identity_file)

    current_hostname = "unknown"
    lines = raw_report.splitlines()
    for i, line in enumerate(lines):
        if line.strip() == "=== HOSTNAME ===" and i + 1 < len(lines):
            current_hostname = lines[i + 1].strip()
            break

    return current_hostname, raw_report, sudo_prefix


# ==========================================
# 4. ローカルLLM（gpusv）で役割要約・衛生チェック・命名
# ==========================================
def ask_local_yubaba(
    audit_report: str, used_names: list[str], current_host: str
) -> YubabaOutput:
    client = Client(host=OLLAMA_HOST)
    ng_text = (
        ", ".join(used_names) if used_names else "なし（これが最初の契約者）"
    )

    prompt = f"""
あなたは『千と千尋の神隠し』の湯婆婆として、Linuxサーバーの役割と衛生状態を見抜き、ふさわしいホスト名を付けるAIです。
一人称は「あたし」、二人称は「あんた」を使い、威厳ある女主人らしい口調（「〜だよ」「〜じゃないかい」「〜だね」）を徹底すること。

以下の調査レポートを読み取り、4つの項目をJSONで出力してください。

【ルール】
1. evaluation_line: 湯婆婆の口調でサーバーの働きぶり（Dockerコンテナや主要サービス）を評価する1文目。
   - 役割がある場合：「フン、あんたは〇〇を捌くことができるのかい。」「ほう、〇〇を見張る仕事ができるんだね。」
   - 何も動いていない素のサーバーの場合：「まったく、まだ何の仕事もできないただの空き箱じゃないかい！」
2. scolding_line: 「=== SECURITY & UPDATES ===」を見て、深刻度に応じて小言の温度感を変えること（1〜2文以内）。
   - 未適用アップデートが 0件 かつ 警告なし：空文字 "" にする。
   - 未適用アップデートが 1〜9件 程度（軽微）：「ふん、まあまあ身ぎれいにしてるじゃないか。ただ、細かい更新が数件残ってるから後でサッと片付けておきな。」のように軽く釘を刺す程度にする（絶対に大げさに怒らない）。
   - 未適用アップデートが 10〜29件 または 要再起動：「少しホコリが溜まってるねぇ。さっさと身ぎれいにしな！」と軽く叱る。
   - 未適用アップデートが 30件以上 または SSH警告あり：「まったく不潔だねぇ！泥棒に入られたいのかい！さっさと片付けな！」と厳しく叱りつける。
3. new_name: サーバーの【役割・機能のみ】を表すシンプルな1単語の「和風ローマ字」または「短い英単語」（英小文字のみ、ハイフン禁止、3〜8文字）。
   - 特定の役割がある場合：その役割の核心を表す名前（例：DNSなら案内や道標、監視なら番人や目、LLMなら知恵や社、統合管理なら大番頭など）。
   - 何も動いていない素のサーバーの場合：まだ一人前ではないことを示す名前（例：雛、種、卵、仮、無など）。
   - 【重要】小言の内容や、元のホスト名（{current_host}）の文字は絶対に混ぜないこと。
4. role_title: サーバーの【役割・機能のみ】を表す10文字以内の短い二つ名・名詞句（例: "AIの知恵箱"、"油屋の大番頭"、"まだ殻をかぶった種"）。句読点や「〜に命名」は禁止。
5. 【厳守】以下の使用済みホスト名は絶対に使わないこと：
{ng_text}

【サーバー調査レポート】
{audit_report}
"""
    response = client.chat(
        model=MODEL_NAME,
        messages=[{"role": "user", "content": prompt}],
        format=YubabaOutput.model_json_schema(),
        think=False,
        options={
            "temperature": 0.4,
            "repeat_penalty": 1.15,
            "num_predict": 512,
        },
    )
    return YubabaOutput.model_validate_json(response.message.content)


# ==========================================
# 5. ホスト名の変更（LXC・非systemd環境フォールバック付き）
# ==========================================
def apply_hostname(
    target: str,
    old_name: str,
    new_name: str,
    sudo_prefix: str,
    identity_file: str | None = None,
):
    cmd = (
        f"({sudo_prefix}hostnamectl set-hostname {new_name} 2>/dev/null || "
        f"({sudo_prefix}hostname {new_name} && echo '{new_name}' | {sudo_prefix}tee /etc/hostname >/dev/null)) && "
        f"{sudo_prefix}sed -i 's/\\b{old_name}\\b/{new_name}/g' /etc/hosts"
    )
    run_ssh_command(target, cmd, identity_file)


# ==========================================
# メイン処理
# ==========================================
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="AI湯婆婆 サーバー監査・命名ツール")
    parser.add_argument("target", nargs="?", help="接続先 (例: user@192.168.1.10)")
    parser.add_argument("-i", "--identity", help="使用するSSH秘密鍵のパス")
    args = parser.parse_args()

    print("\n" + "━" * 62)
    print("  ♨  油屋 インフラ管理室 ―― AI湯婆婆 契約の儀  ♨")
    print("━" * 62)
    print("「ここで働きたいだって？まったく、どいつもこいつも…！")
    print(" さあ、契約書に書きな！あんたの『接続先（手形）』は何ていうんだい？」\n")

    if args.target:
        target_host = args.target.strip()
        print(f"▶ 差し出された手形（接続先）: {target_host}")
    else:
        target_host = ""
        while not target_host:
            target_host = input(
                "▶ 契約書に記入する接続先 (例: user@<IP_ADDRESS>): "
            ).strip()

    print("\n「ふむ…ちょっと中身と身なりを改めさせてもらうよ…」")
    current_host, report, sudo_prefix = inspect_server(
        target_host, args.identity
    )

    print(f"\n「ほう…契約書には『{current_host}』と書いてあるのかい。」")

    print("\n--- 監査結果（中身・衛生状態） ---")
    print(report.strip())
    print("----------------------------------\n")

    print(f"「ふむふむ…（{MODEL_NAME} が品定め中）…」")
    used_names = load_used_names()
    decision = ask_local_yubaba(report, used_names, current_host)

    # 元のホスト名の長さに応じてセリフを変える
    if len(current_host) >= 4:
        name_comment = f"『{current_host}』なんて贅沢な名だね。"
    else:
        name_comment = f"『{current_host}』だって？味も素っ気もない名前だね。"

    scolding_block = (
        f"\n …それにしても！{decision.scolding_line}\n"
        if decision.scolding_line.strip()
        else "\n"
    )

    clean_title = decision.role_title.rstrip("。、.,！! だです")
    serif = (
        f"「{decision.evaluation_line}"
        f"{scolding_block}"
        f" {name_comment}\n"
        f" あんたは『{clean_title}』だから、今日から『{decision.new_name}』だよ！」"
    )

    print("\n" + "┏" + "━" * 60 + "┓")
    for line in serif.splitlines():
        print(f"  {line}")
    print("┗" + "━" * 60 + "┛\n")

    if decision.new_name.lower() in used_names:
        print(
            f"「おや、ダメだね！『{decision.new_name}』って子はもううちにいるよ。やり直しだ！」"
        )
    else:
        ans = input(
            f"「いいかい、返事は『はい』か『y』だけだよ！ホスト名を『{decision.new_name}』に書き換えるよ？」 [y/N]: "
        )
        if ans.lower() == "y":
            apply_hostname(
                target_host,
                current_host,
                decision.new_name,
                sudo_prefix,
                args.identity,
            )
            save_used_name(decision.new_name, clean_title)
            print(
                f"\n「契約完了だ！『{decision.new_name}』、グズグズしないでさっさと働きな！！」"
            )
            print(f"（※ 契約台帳 {LEDGER_FILE} に由来とともに名を刻みました）")
        else:
            print(
                "\n「なんだい、契約しないのかい！とっとと帰りな！！」"
            )
