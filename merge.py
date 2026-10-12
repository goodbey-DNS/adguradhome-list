#!/usr/bin/env python3
"""合并多个上游规则源 -> 去重 -> 清洗 -> 输出 AdGuard Home 拦截规则

设计目标：稳定优先、长期免维护、支持大量规则源、支持超大输出（50M+）。
- 仅使用 Python 标准库，无第三方依赖
- 单个源失败自动跳过并重试，不中断整体任务
- 单文件优先：默认汇总为一个 adguard-filter.txt；仅当文件超过 GitHub
  100MB 硬限制的安全线（90MB）时才应急分片，保证推送永不失败

清洗策略（严格保留基础规则）：
- 保留：基础 adblock 阻止规则（||domain^ 形态，含 ||*.*.com^ 通配）
  统一小写输出（风格一致，符合 adblock 书写惯例），父域子域均不动
- 删除：@@ 白名单放行、注释（含 #@# 元素例外行）、## 装饰、$修饰符、路径规则、
  正则规则、dnsmasq、|http 等其余一切非 ||域名^ 形态（AdGuard Home 无法解析）
- 转换：基础 hosts 语法（0.0.0.0/127.0.0.1/::1 域名，含一行多域名）-> ||域名^（统一小写）；
  localhost 等本机域名、非合法域名/IP 的脏数据除外
- 去重：完全去重（已统一小写）

运维加固：
- 拉取解码用 utf-8-sig：自动剥除部分源文件开头的 BOM，
  否则该源第一条规则会因 \ufeff 前缀被误判为非法而丢失
- 单源响应超过 256MB 直接判失败跳过，防超大响应耗尽 runner 内存
- sources.txt 缺失或为空时给出明确报错信息（而非裸 FileNotFoundError）
"""
import glob
import math
import os
import re
from concurrent.futures import ThreadPoolExecutor
import sys
import time
import urllib.request
from datetime import datetime, timezone

SOURCES_FILE = "sources.txt"
OUTPUT_SINGLE = "adguard-filter.txt"        # 默认单文件汇总输出
OUTPUT_PART_FMT = "adguard-filter-{}.txt"   # 超限时应急分片输出（从 1 开始编号）
SIZE_LIMIT_MB = 90                           # 单文件安全上限（GitHub 硬限制 100MB）
PART_TARGET_MB = 45                          # 应急分片时每片目标大小
MIN_RULES = 100_000                          # 结果少于此行数视为异常，终止且不覆盖线上版本
MAX_SOURCE_BYTES = 256 * 1024 * 1024         # 单源响应上限：超此值判失败跳过，防 OOM

COMMENT_PREFIXES = ("!", "#", "[")
LOCAL_NAMES = {"localhost", "local", "broadcasthost", "localhost.localdomain"}
# hosts 目标为回环/未指定地址本身时无拦截意义，||127.0.0.1^ 还会误伤本机回环解析
LOCAL_IPS = {"0.0.0.0", "127.0.0.1", "::1"}
IP_PREFIXES = ("0.0.0.0", "127.0.0.1", "::1")
# hosts 行：0.0.0.0 domain [domain...] [# comment]，支持一行多域名
HOSTS_RE = re.compile(r"^(?:0\.0\.0\.0|127\.0\.0\.1|::1)(?:\s+([^#]+))?")
# hosts 域名位合法性校验：合法域名（label 不允许 - 开头/结尾、不含通配）或 IPv4，
# 防止 -example.com 等脏数据混入输出
HOSTS_DOMAIN_RE = re.compile(
    r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$",
    re.IGNORECASE,
)
HOSTS_IP_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
# 基础 adblock 阻止规则：||域名^ 形态，域名部分允许字母数字连字符下划线点与 *
BASIC_RULE_RE = re.compile(r"^\|\|[A-Za-z0-9._*-]+\^$")

def fetch(url, retries=2):
    for attempt in range(retries + 1):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=120) as r:
                data = r.read(MAX_SOURCE_BYTES + 1)   # 多读 1 字节探测超限
                if len(data) > MAX_SOURCE_BYTES:
                    print(f"  [warn] 源超过 {MAX_SOURCE_BYTES // 1024 // 1024}MB 上限，跳过: {url}",
                          file=sys.stderr)
                    return None
                # utf-8-sig：自动剥除部分源文件开头的 BOM，
                # 否则该源第一条规则会因 \ufeff 前缀被误判为非法行而丢失
                return data.decode("utf-8-sig", errors="ignore")
        except Exception as e:
            print(f"  [warn] 第 {attempt + 1} 次拉取失败: {e}", file=sys.stderr)
            if attempt < retries:
                time.sleep(5)
    return None  # 单个源失败不中断整体任务

def fetch_all(urls, workers=5):
    """5 路并发拉取全部源，返回 {url: text or None}，保持输入顺序。

    串行最坏耗时：20 源 × (3 次尝试 × 120s + 2 次间隔 × 5s) ≈ 123 分钟，会撞上
    工作流 90 分钟超时；5 路并发后最坏 ≈ ceil(20/5) × 370s ≈ 25 分钟，余量充足。"""
    results = {}
    with ThreadPoolExecutor(max_workers=workers) as ex:
        for url, text in zip(urls, ex.map(fetch, urls)):
            results[url] = text
    return results

def hosts_rules(line):
    """hosts 行解析：0.0.0.0 domain [domain...] [# comment] -> 多条 ||域名^"""
    m = HOSTS_RE.match(line)
    if not m or not m.group(1):   # 裸 IP / 纯注释行 / 无空格脏数据
        return []
    out = []
    for tok in m.group(1).split():
        d = tok.rstrip(".")
        if not d or d.lower() in LOCAL_NAMES or d in LOCAL_IPS:
            continue
        if HOSTS_DOMAIN_RE.match(d) or HOSTS_IP_RE.match(d):   # 脏数据丢弃
            out.append(f"||{d.lower()}^")
    return out

def normalize(line):
    """严格保留基础规则：返回规则列表（基础规则单条/hosts 转换零或多条/其余为空）"""
    line = line.strip()
    # 空行、注释行（! # [Adblock Plus] 等来源标记）
    if not line or line.startswith(COMMENT_PREFIXES):
        return []
    # 白名单放行规则：@@ 例外，删除
    if line.startswith("@@"):
        return []
    # hosts 语法：0.0.0.0 domain [domain...] [# comment] -> ||域名^（可能多条）
    if line.startswith(IP_PREFIXES):
        return hosts_rules(line)
    # 基础 adblock 阻止规则（||域名^ 含通配）：统一小写输出（风格一致，符合 adblock 书写惯例）
    if BASIC_RULE_RE.match(line):
        return [line.lower()]
    # 其余一切非基础形态（##装饰、$修饰符、路径、正则、dnsmasq、|http、裸域名等）：删除
    return []

def dedupe_key(rule):
    """去重键：规则已统一小写，直接完全去重"""
    return rule

def write_output(path, rules, part=None, total_parts=None, total_rules=None):
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    header = ["! Title: Merged AdGuard Home Filter (block rules only)"]
    if part is not None:
        header[0] += f" [Part {part}/{total_parts}]"
    header += [
        f"! Updated: {now} UTC",
        f"! Rules: {len(rules)}" + (f" (total {total_rules})" if total_rules else ""),
        "! Expires: 1 day",
        "! Homepage: auto-generated by GitHub Actions",
        "",
    ]
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(header + rules) + "\n")
    size_mb = os.path.getsize(path) / 1024 / 1024
    print(f"  写入 {path}: {len(rules)} 条, {size_mb:.1f} MB")

def main():
    # 清理上一次运行遗留的输出文件，避免残留过期分片
    for old in glob.glob("adguard-filter*.txt"):
        os.remove(old)

    if not os.path.exists(SOURCES_FILE):
        print(f"[error] 缺少 {SOURCES_FILE}：请确认它已提交到仓库根目录（与 merge.py 同级），"
              f"每行一个规则源 URL，# 开头为注释。", file=sys.stderr)
        sys.exit(1)
    with open(SOURCES_FILE, encoding="utf-8") as f:
        urls = [l.strip() for l in f if l.strip() and not l.startswith("#")]
    if not urls:
        print(f"[error] {SOURCES_FILE} 为空：没有可用的规则源。", file=sys.stderr)
        sys.exit(1)
    print(f"共 {len(urls)} 个规则源")

    rules, seen = [], set()
    failed = 0
    texts = fetch_all(urls)
    for url in urls:
        print(f"处理: {url}")
        text = texts[url]
        if text is None:
            failed += 1
            print(f"  [skip] 源不可用，跳过: {url}", file=sys.stderr)
            continue
        kept = 0
        for line in text.splitlines():
            for r in normalize(line):
                k = dedupe_key(r)
                if k not in seen:   # 有序去重（大小写不敏感）
                    seen.add(k)
                    rules.append(r)
                    kept += 1
        print(f"  有效规则: {kept}")

    # 保底检查：大面积源失效时结果必然残缺，宁可任务失败也不覆盖线上完好版本
    if failed * 2 > len(urls):
        print(f"[error] {failed}/{len(urls)} 个源拉取失败（过半），终止推送，保留线上现有版本",
              file=sys.stderr)
        sys.exit(1)
    if len(rules) < MIN_RULES:
        print(f"[error] 合并结果仅 {len(rules)} 条（低于 {MIN_RULES}），疑似异常，终止推送",
              file=sys.stderr)
        sys.exit(1)

    # 单文件优先：先汇总写入一个文件
    write_output(OUTPUT_SINGLE, rules)
    size_mb = os.path.getsize(OUTPUT_SINGLE) / 1024 / 1024

    if size_mb > SIZE_LIMIT_MB:
        # 应急分片：仅当超过 GitHub 100MB 硬限制的安全线才拆分
        print(f"[warn] 单文件 {size_mb:.1f} MB 超过 {SIZE_LIMIT_MB} MB 安全线，自动分片", file=sys.stderr)
        os.remove(OUTPUT_SINGLE)
        parts_count = math.ceil(size_mb / PART_TARGET_MB)
        chunk_lines = math.ceil(len(rules) / parts_count)
        parts = [rules[i:i + chunk_lines] for i in range(0, len(rules), chunk_lines)]
        for i, chunk in enumerate(parts, 1):
            write_output(OUTPUT_PART_FMT.format(i), chunk,
                         part=i, total_parts=len(parts), total_rules=len(rules))

    print(f"完成，共 {len(rules)} 条拦截规则（{len(urls) - failed}/{len(urls)} 个源成功）")
    if failed:
        print(f"注意：{failed} 个源拉取失败已跳过", file=sys.stderr)

if __name__ == "__main__":
    main()
