#!/usr/bin/env python3
"""
Snort Rule Builder - 対話的にSnortルールを作成するGUIアプリケーション
"""

import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import re


class SnortRuleBuilder:
    def __init__(self, root):
        self.root = root
        self.root.title("Snort Rule Builder")
        self.root.geometry("900x750")
        self.root.minsize(800, 700)

        # メインフレーム
        main_frame = ttk.Frame(root, padding="10")
        main_frame.grid(row=0, column=0, sticky="nsew")
        root.columnconfigure(0, weight=1)
        root.rowconfigure(0, weight=1)

        # スクロール可能なキャンバス
        canvas = tk.Canvas(main_frame)
        scrollbar = ttk.Scrollbar(main_frame, orient="vertical", command=canvas.yview)
        self.scrollable_frame = ttk.Frame(canvas)

        self.scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )

        canvas.create_window((0, 0), window=self.scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)

        canvas.grid(row=0, column=0, sticky="nsew")
        scrollbar.grid(row=0, column=1, sticky="ns")
        main_frame.columnconfigure(0, weight=1)
        main_frame.rowconfigure(0, weight=1)

        # マウスホイールスクロール
        canvas.bind_all("<MouseWheel>", lambda e: canvas.yview_scroll(-1*(e.delta//120), "units"))

        self.create_widgets()

    def create_widgets(self):
        row = 0

        # === ヘッダー部分 ===
        header_frame = ttk.LabelFrame(self.scrollable_frame, text="ルールヘッダー", padding="10")
        header_frame.grid(row=row, column=0, columnspan=2, sticky="ew", pady=5)
        row += 1

        # アクション
        ttk.Label(header_frame, text="アクション:").grid(row=0, column=0, sticky="w", padx=5, pady=2)
        self.action_var = tk.StringVar(value="alert")
        action_combo = ttk.Combobox(header_frame, textvariable=self.action_var, width=15,
                                     values=["alert", "log", "pass", "drop", "reject", "sdrop"])
        action_combo.grid(row=0, column=1, sticky="w", padx=5, pady=2)
        ttk.Label(header_frame, text="alert=警告, drop=破棄, pass=通過",
                  foreground="gray").grid(row=0, column=2, sticky="w", padx=5)

        # プロトコル
        ttk.Label(header_frame, text="プロトコル:").grid(row=1, column=0, sticky="w", padx=5, pady=2)
        self.protocol_var = tk.StringVar(value="tcp")
        protocol_combo = ttk.Combobox(header_frame, textvariable=self.protocol_var, width=15,
                                       values=["tcp", "udp", "icmp", "ip"])
        protocol_combo.grid(row=1, column=1, sticky="w", padx=5, pady=2)

        # 送信元IP
        ttk.Label(header_frame, text="送信元IP:").grid(row=2, column=0, sticky="w", padx=5, pady=2)
        self.src_ip_var = tk.StringVar(value="any")
        ttk.Entry(header_frame, textvariable=self.src_ip_var, width=20).grid(row=2, column=1, sticky="w", padx=5, pady=2)
        ttk.Label(header_frame, text="例: any, $HOME_NET, 192.168.1.0/24, !10.0.0.0/8",
                  foreground="gray").grid(row=2, column=2, sticky="w", padx=5)

        # 送信元ポート
        ttk.Label(header_frame, text="送信元ポート:").grid(row=3, column=0, sticky="w", padx=5, pady=2)
        self.src_port_var = tk.StringVar(value="any")
        ttk.Entry(header_frame, textvariable=self.src_port_var, width=20).grid(row=3, column=1, sticky="w", padx=5, pady=2)
        ttk.Label(header_frame, text="例: any, 80, 1:1024, !80, [80,443]",
                  foreground="gray").grid(row=3, column=2, sticky="w", padx=5)

        # 方向
        ttk.Label(header_frame, text="方向:").grid(row=4, column=0, sticky="w", padx=5, pady=2)
        self.direction_var = tk.StringVar(value="->")
        direction_combo = ttk.Combobox(header_frame, textvariable=self.direction_var, width=15,
                                        values=["->", "<>"])
        direction_combo.grid(row=4, column=1, sticky="w", padx=5, pady=2)
        ttk.Label(header_frame, text="-> 一方向, <> 双方向",
                  foreground="gray").grid(row=4, column=2, sticky="w", padx=5)

        # 宛先IP
        ttk.Label(header_frame, text="宛先IP:").grid(row=5, column=0, sticky="w", padx=5, pady=2)
        self.dst_ip_var = tk.StringVar(value="any")
        ttk.Entry(header_frame, textvariable=self.dst_ip_var, width=20).grid(row=5, column=1, sticky="w", padx=5, pady=2)

        # 宛先ポート
        ttk.Label(header_frame, text="宛先ポート:").grid(row=6, column=0, sticky="w", padx=5, pady=2)
        self.dst_port_var = tk.StringVar(value="any")
        ttk.Entry(header_frame, textvariable=self.dst_port_var, width=20).grid(row=6, column=1, sticky="w", padx=5, pady=2)

        # === オプション部分 ===
        options_frame = ttk.LabelFrame(self.scrollable_frame, text="ルールオプション", padding="10")
        options_frame.grid(row=row, column=0, columnspan=2, sticky="ew", pady=5)
        row += 1

        # メッセージ
        ttk.Label(options_frame, text="msg (メッセージ):").grid(row=0, column=0, sticky="w", padx=5, pady=2)
        self.msg_var = tk.StringVar(value="")
        ttk.Entry(options_frame, textvariable=self.msg_var, width=50).grid(row=0, column=1, sticky="w", padx=5, pady=2)

        # SID
        ttk.Label(options_frame, text="sid (ルールID):").grid(row=1, column=0, sticky="w", padx=5, pady=2)
        self.sid_var = tk.StringVar(value="1000001")
        ttk.Entry(options_frame, textvariable=self.sid_var, width=20).grid(row=1, column=1, sticky="w", padx=5, pady=2)
        ttk.Label(options_frame, text="ローカルルールは1000000以上",
                  foreground="gray").grid(row=1, column=2, sticky="w", padx=5)

        # Rev
        ttk.Label(options_frame, text="rev (リビジョン):").grid(row=2, column=0, sticky="w", padx=5, pady=2)
        self.rev_var = tk.StringVar(value="1")
        ttk.Entry(options_frame, textvariable=self.rev_var, width=20).grid(row=2, column=1, sticky="w", padx=5, pady=2)

        # Classtype
        ttk.Label(options_frame, text="classtype:").grid(row=3, column=0, sticky="w", padx=5, pady=2)
        self.classtype_var = tk.StringVar(value="")
        classtype_combo = ttk.Combobox(options_frame, textvariable=self.classtype_var, width=30,
                                        values=["", "attempted-admin", "attempted-user", "shellcode-detect",
                                                "successful-admin", "successful-user", "trojan-activity",
                                                "unsuccessful-user", "web-application-attack", "attempted-dos",
                                                "attempted-recon", "bad-unknown", "denial-of-service",
                                                "misc-attack", "non-standard-protocol", "rpc-portmap-decode",
                                                "successful-dos", "successful-recon-largescale",
                                                "successful-recon-limited", "suspicious-filename-detect",
                                                "suspicious-login", "system-call-detect", "unusual-client-port-connection",
                                                "web-application-activity", "icmp-event", "misc-activity",
                                                "network-scan", "not-suspicious", "protocol-command-decode",
                                                "string-detect", "unknown", "tcp-connection"])
        classtype_combo.grid(row=3, column=1, sticky="w", padx=5, pady=2)

        # Priority
        ttk.Label(options_frame, text="priority:").grid(row=4, column=0, sticky="w", padx=5, pady=2)
        self.priority_var = tk.StringVar(value="")
        priority_combo = ttk.Combobox(options_frame, textvariable=self.priority_var, width=10,
                                       values=["", "1", "2", "3", "4"])
        priority_combo.grid(row=4, column=1, sticky="w", padx=5, pady=2)
        ttk.Label(options_frame, text="1=高, 4=低",
                  foreground="gray").grid(row=4, column=2, sticky="w", padx=5)

        # === コンテンツ検出 ===
        content_frame = ttk.LabelFrame(self.scrollable_frame, text="コンテンツ検出", padding="10")
        content_frame.grid(row=row, column=0, columnspan=2, sticky="ew", pady=5)
        row += 1

        # Content
        ttk.Label(content_frame, text="content:").grid(row=0, column=0, sticky="w", padx=5, pady=2)
        self.content_var = tk.StringVar(value="")
        ttk.Entry(content_frame, textvariable=self.content_var, width=50).grid(row=0, column=1, sticky="w", padx=5, pady=2)
        ttk.Label(content_frame, text="HEX: |00 01 02| 文字列: \"text\"",
                  foreground="gray").grid(row=0, column=2, sticky="w", padx=5)

        # Content修飾子
        self.nocase_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(content_frame, text="nocase (大文字小文字無視)",
                        variable=self.nocase_var).grid(row=1, column=1, sticky="w", padx=5)

        # HTTP修飾子
        ttk.Label(content_frame, text="HTTP修飾子:").grid(row=2, column=0, sticky="w", padx=5, pady=2)
        self.http_modifier_var = tk.StringVar(value="")
        http_combo = ttk.Combobox(content_frame, textvariable=self.http_modifier_var, width=25,
                                   values=["", "http_uri", "http_header", "http_client_body",
                                          "http_cookie", "http_method", "http_stat_code", "http_stat_msg"])
        http_combo.grid(row=2, column=1, sticky="w", padx=5, pady=2)

        # PCRE
        ttk.Label(content_frame, text="pcre (正規表現):").grid(row=3, column=0, sticky="w", padx=5, pady=2)
        self.pcre_var = tk.StringVar(value="")
        ttk.Entry(content_frame, textvariable=self.pcre_var, width=50).grid(row=3, column=1, sticky="w", padx=5, pady=2)
        ttk.Label(content_frame, text="例: /pattern/i",
                  foreground="gray").grid(row=3, column=2, sticky="w", padx=5)

        # === フロー制御 ===
        flow_frame = ttk.LabelFrame(self.scrollable_frame, text="フロー制御", padding="10")
        flow_frame.grid(row=row, column=0, columnspan=2, sticky="ew", pady=5)
        row += 1

        # Flow
        ttk.Label(flow_frame, text="flow:").grid(row=0, column=0, sticky="w", padx=5, pady=2)
        self.flow_var = tk.StringVar(value="")
        flow_combo = ttk.Combobox(flow_frame, textvariable=self.flow_var, width=30,
                                   values=["", "to_server,established", "to_client,established",
                                          "from_server,established", "from_client,established",
                                          "established", "stateless", "to_server", "to_client"])
        flow_combo.grid(row=0, column=1, sticky="w", padx=5, pady=2)

        # Flags (TCPフラグ)
        ttk.Label(flow_frame, text="flags (TCPフラグ):").grid(row=1, column=0, sticky="w", padx=5, pady=2)
        self.flags_var = tk.StringVar(value="")
        ttk.Entry(flow_frame, textvariable=self.flags_var, width=20).grid(row=1, column=1, sticky="w", padx=5, pady=2)
        ttk.Label(flow_frame, text="S=SYN, A=ACK, F=FIN, R=RST, P=PSH, U=URG",
                  foreground="gray").grid(row=1, column=2, sticky="w", padx=5)

        # Threshold
        ttk.Label(flow_frame, text="threshold:").grid(row=2, column=0, sticky="w", padx=5, pady=2)
        threshold_inner = ttk.Frame(flow_frame)
        threshold_inner.grid(row=2, column=1, columnspan=2, sticky="w", padx=5)

        self.threshold_type_var = tk.StringVar(value="")
        ttk.Label(threshold_inner, text="type:").pack(side="left")
        ttk.Combobox(threshold_inner, textvariable=self.threshold_type_var, width=10,
                     values=["", "limit", "threshold", "both"]).pack(side="left", padx=2)

        self.threshold_track_var = tk.StringVar(value="by_src")
        ttk.Label(threshold_inner, text="track:").pack(side="left", padx=(10,0))
        ttk.Combobox(threshold_inner, textvariable=self.threshold_track_var, width=10,
                     values=["by_src", "by_dst"]).pack(side="left", padx=2)

        self.threshold_count_var = tk.StringVar(value="")
        ttk.Label(threshold_inner, text="count:").pack(side="left", padx=(10,0))
        ttk.Entry(threshold_inner, textvariable=self.threshold_count_var, width=5).pack(side="left", padx=2)

        self.threshold_seconds_var = tk.StringVar(value="")
        ttk.Label(threshold_inner, text="seconds:").pack(side="left", padx=(10,0))
        ttk.Entry(threshold_inner, textvariable=self.threshold_seconds_var, width=5).pack(side="left", padx=2)

        # === 追加オプション ===
        extra_frame = ttk.LabelFrame(self.scrollable_frame, text="追加オプション", padding="10")
        extra_frame.grid(row=row, column=0, columnspan=2, sticky="ew", pady=5)
        row += 1

        ttk.Label(extra_frame, text="カスタムオプション:").grid(row=0, column=0, sticky="w", padx=5, pady=2)
        self.extra_options_var = tk.StringVar(value="")
        ttk.Entry(extra_frame, textvariable=self.extra_options_var, width=60).grid(row=0, column=1, sticky="w", padx=5, pady=2)
        ttk.Label(extra_frame, text="セミコロン区切り: dsize:>500; offset:0;",
                  foreground="gray").grid(row=1, column=1, sticky="w", padx=5)

        # === プレビュー ===
        preview_frame = ttk.LabelFrame(self.scrollable_frame, text="生成されたルール", padding="10")
        preview_frame.grid(row=row, column=0, columnspan=2, sticky="ew", pady=5)
        row += 1

        self.preview_text = tk.Text(preview_frame, height=5, width=100, wrap="word", font=("Consolas", 10))
        self.preview_text.grid(row=0, column=0, sticky="ew", padx=5, pady=5)
        preview_frame.columnconfigure(0, weight=1)

        # === ボタン ===
        button_frame = ttk.Frame(self.scrollable_frame)
        button_frame.grid(row=row, column=0, columnspan=2, pady=10)
        row += 1

        ttk.Button(button_frame, text="ルール生成", command=self.generate_rule).pack(side="left", padx=5)
        ttk.Button(button_frame, text="クリップボードにコピー", command=self.copy_to_clipboard).pack(side="left", padx=5)
        ttk.Button(button_frame, text="ファイルに保存", command=self.save_to_file).pack(side="left", padx=5)
        ttk.Button(button_frame, text="リセット", command=self.reset_fields).pack(side="left", padx=5)

        # 変更時に自動更新
        for var in [self.action_var, self.protocol_var, self.src_ip_var, self.src_port_var,
                    self.direction_var, self.dst_ip_var, self.dst_port_var, self.msg_var,
                    self.sid_var, self.rev_var, self.classtype_var, self.priority_var,
                    self.content_var, self.nocase_var, self.http_modifier_var, self.pcre_var,
                    self.flow_var, self.flags_var, self.threshold_type_var, self.threshold_count_var,
                    self.threshold_seconds_var, self.extra_options_var]:
            var.trace_add("write", lambda *args: self.generate_rule())

        # 初期ルール生成
        self.generate_rule()

    def generate_rule(self):
        """Snortルールを生成"""
        # ヘッダー部分
        header = f"{self.action_var.get()} {self.protocol_var.get()} "
        header += f"{self.src_ip_var.get()} {self.src_port_var.get()} "
        header += f"{self.direction_var.get()} "
        header += f"{self.dst_ip_var.get()} {self.dst_port_var.get()}"

        # オプション部分
        options = []

        # msg
        if self.msg_var.get():
            msg = self.msg_var.get().replace('"', '\\"')
            options.append(f'msg:"{msg}"')

        # content
        if self.content_var.get():
            content = self.content_var.get()
            if not (content.startswith('"') or content.startswith('|')):
                content = f'"{content}"'
            options.append(f'content:{content}')

            if self.nocase_var.get():
                options.append('nocase')

            if self.http_modifier_var.get():
                options.append(self.http_modifier_var.get())

        # pcre
        if self.pcre_var.get():
            pcre = self.pcre_var.get()
            if not pcre.startswith('"'):
                pcre = f'"{pcre}"'
            options.append(f'pcre:{pcre}')

        # flow
        if self.flow_var.get():
            options.append(f'flow:{self.flow_var.get()}')

        # flags
        if self.flags_var.get():
            options.append(f'flags:{self.flags_var.get()}')

        # threshold
        if self.threshold_type_var.get() and self.threshold_count_var.get() and self.threshold_seconds_var.get():
            threshold = f'threshold:type {self.threshold_type_var.get()}, '
            threshold += f'track {self.threshold_track_var.get()}, '
            threshold += f'count {self.threshold_count_var.get()}, '
            threshold += f'seconds {self.threshold_seconds_var.get()}'
            options.append(threshold)

        # classtype
        if self.classtype_var.get():
            options.append(f'classtype:{self.classtype_var.get()}')

        # priority
        if self.priority_var.get():
            options.append(f'priority:{self.priority_var.get()}')

        # 追加オプション
        if self.extra_options_var.get():
            extra = self.extra_options_var.get().strip()
            if extra:
                # セミコロンで分割して追加
                for opt in extra.split(';'):
                    opt = opt.strip()
                    if opt:
                        options.append(opt)

        # sid, rev（必須）
        options.append(f'sid:{self.sid_var.get()}')
        options.append(f'rev:{self.rev_var.get()}')

        # ルール組み立て
        rule = f"{header} ({'; '.join(options)};)"

        # プレビュー更新
        self.preview_text.delete("1.0", tk.END)
        self.preview_text.insert("1.0", rule)

        return rule

    def copy_to_clipboard(self):
        """クリップボードにコピー"""
        rule = self.generate_rule()
        self.root.clipboard_clear()
        self.root.clipboard_append(rule)
        messagebox.showinfo("コピー完了", "ルールをクリップボードにコピーしました")

    def save_to_file(self):
        """ファイルに保存"""
        rule = self.generate_rule()
        filename = filedialog.asksaveasfilename(
            defaultextension=".rules",
            filetypes=[("Snort Rules", "*.rules"), ("All Files", "*.*")],
            title="ルールを保存"
        )
        if filename:
            with open(filename, "a", encoding="utf-8") as f:
                f.write(rule + "\n")
            messagebox.showinfo("保存完了", f"ルールを {filename} に保存しました")

    def reset_fields(self):
        """フィールドをリセット"""
        self.action_var.set("alert")
        self.protocol_var.set("tcp")
        self.src_ip_var.set("any")
        self.src_port_var.set("any")
        self.direction_var.set("->")
        self.dst_ip_var.set("any")
        self.dst_port_var.set("any")
        self.msg_var.set("")
        self.sid_var.set("1000001")
        self.rev_var.set("1")
        self.classtype_var.set("")
        self.priority_var.set("")
        self.content_var.set("")
        self.nocase_var.set(False)
        self.http_modifier_var.set("")
        self.pcre_var.set("")
        self.flow_var.set("")
        self.flags_var.set("")
        self.threshold_type_var.set("")
        self.threshold_track_var.set("by_src")
        self.threshold_count_var.set("")
        self.threshold_seconds_var.set("")
        self.extra_options_var.set("")


def main():
    root = tk.Tk()
    app = SnortRuleBuilder(root)
    root.mainloop()


if __name__ == "__main__":
    main()
