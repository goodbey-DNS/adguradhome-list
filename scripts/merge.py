#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AdGuard Home 规则合并去重脚本（GitHub 增强版）

功能：
  拉取 sources.txt 列出的多个源规则列表，
  从 adblock 规则（||domain^）与 hosts 语法（0.0.0.0 domain）
  中提取阻止域名，按裸域名去重后统一输出为 ||domain^ 阻止列表，
  供 AdGuard Home 订阅。

  - 只保留阻止规则，丢弃 @@ 白名单、/regex/ 正则、注释、原 hosts 行
  - ||domain^ 后不带任何修饰符（如 $third-party 一律丢弃）
  - hosts 列表自动转换为纯 ||domain^ 输出
  - 同一域名来自不同源只保留一条
  - 短域名优先去重：example.com 已拦，则所有 *.example.com 删除（体积大减）
  - 单个源下载失败不影响整体合并
  - 纯标准库实现，无需 pip install
  - 长期运行优化：
      * 并发下载（ThreadPoolExecutor, max_workers=8）—— 解决串行超时痛点
      * 3 次重试 + 指数退避（2s/4s/8s）
      * 120s 单次下载超时
      * header 去时间戳，规则无变化时不产生无意义 commit
      * 全源失败不写空文件，避免破坏现有订阅
      * 短域名优先去重，大幅减小规则体积
"""

import os
import re
import json
import sys
import time
from datetime import datetime
from urllib.request import urlopen, Request
from urllib.error import URLError
from concurrent.futures import ThreadPoolExecutor, as_completed

# 可用环境变量覆盖默认路径
SOURCES_FILE = os.environ.get("SOURCES_FILE", "sources.txt")
OUTPUT_FILE = os.environ.get("OUTPUT_FILE", "adguard-merged.txt")
STATS_FILE = os.environ.get("STATS_FILE", "stats.json")

TIMEOUT = 120
MAX_RETRIES = 3
RETRY_BACKOFF = 2
MAX_WORKERS = 8  # 并发下载数；太大易触发源限流(429)，8 为安全值
UA = "Mozilla/5.0 (AdGuard-Merge-Bot/1.0)"

# 匹配 ||domain^ 开头的屏蔽规则，捕获域名部分
# 例：||ads.example.com^  ||ads.example.com^$third-party
BLOCK_RE = re.compile(r'^\|\|([a-zA-Z0-9.\-]+)\^')

# 匹配 hosts 格式：阻塞 IP + 域名，捕获域名部分
# 例：0.0.0.0 ads.example.com  127.0.0.1 ads.example.com  0.0.0.0 ads.example.com # comment
HOSTS_RE = re.compile(r'^(?:0\.0\.0\.0|127\.0\.0\.1|::1?|0)\s+([a-zA-Z0-9.\-]+)')

# 系统本地保留域名，不作为阻止目标
LOCAL_DOMAINS = {
    "localhost", "ip6-localhost", "ip6-loopback", "broadcasthost",
    "local", "localdomain", "ip6-localnet", "ip6-mcastprefix",
    "ip6-allnodes", "ip6-allrouters", "ip6-allhosts",
}

# 纯 IPv4 形式（hosts 行第二字段也可能是 IP，需跳过）
IPV4_RE = re.compile(r'^\d+\.\d+\.\d+\.\d+$')


def read_sources():
    """读取 sources.txt，跳过注释行和空行。"""
    sources = []
    with open(SOURCES_FILE, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            sources.append(line)
    return sources


def fetch(url):
    """下载 URL 内容，3 次重试 + 指数退避，全失败抛最后异常。"""
    last_err = None
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            req = Request(url, headers={"User-Agent": UA})
            with urlopen(req, timeout=TIMEOUT) as resp:
                data = resp.read()
                return data.decode("utf-8", errors="ignore")
        except Exception as e:
            last_err = e
            if attempt < MAX_RETRIES:
                wait = RETRY_BACKOFF ** attempt
                time.sleep(wait)
    raise last_err


def parse_blocks(text):
    """提取所有阻止域名（小写），返回 set。

    支持两种语法：
      - adblock：||domain^
      - hosts：  0.0.0.0 domain / 127.0.0.1 domain
    跳过 @@ 白名单例外、注释行、正则规则、空行、本地保留域名、纯 IP。
    """
    domains = set()
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        # 跳过注释行（adblock 用 !，hosts 用 #）
        if line.startswith("!") or line.startswith("#"):
            continue
        # 跳过白名单例外 @@||domain^
        if line.startswith("@@"):
            continue
        # adblock ||domain^（修饰符如 $third-party 被 BLOCK_RE 自动忽略）
        m = BLOCK_RE.match(line)
        if m:
            d = m.group(1).lower()
            if d not in LOCAL_DOMAINS:
                domains.add(d)
            continue
        # hosts：IP domain
        m = HOSTS_RE.match(line)
        if m:
            d = m.group(1).lower()
            if d in LOCAL_DOMAINS:
                continue
            if IPV4_RE.match(d):
                continue
            domains.add(d)
    return domains


def dedup_short_domain(domains):
    """短域名优先去重：example.com 已拦，则所有 *.example.com 删除。

    对每个域名，检查它的所有父域名（跳过纯 TLD 单标签）是否在集合里，
    若任一父域名在集合里，则该域名被更短的父域名覆盖，删除之。
    例：集合有 example.com 和 a.example.com -> 只保留 example.com
    """
    result = set()
    for d in domains:
        parts = d.split('.')
        keep = True
        # 从直接父域往根走，range 末尾 -1 跳过最后一个标签（纯 TLD，不作为有效父域）
        for i in range(1, len(parts) - 1):
            parent = '.'.join(parts[i:])
            if parent in domains:
                keep = False
                break
        if keep:
            result.add(d)
    return result


def main():
    start = time.time()
    # sources.txt 与输出文件相对仓库根目录（脚本所在目录的上一级）解析
    base = os.path.dirname(os.path.abspath(__file__))
    root = os.path.dirname(base)  # 仓库根目录
    global SOURCES_FILE, OUTPUT_FILE, STATS_FILE
    if not os.path.isabs(SOURCES_FILE):
        SOURCES_FILE = os.path.join(root, SOURCES_FILE)
    if not os.path.isabs(OUTPUT_FILE):
        OUTPUT_FILE = os.path.join(root, OUTPUT_FILE)
    if not os.path.isabs(STATS_FILE):
        STATS_FILE = os.path.join(root, STATS_FILE)

    sources = read_sources()
    print(f"共 {len(sources)} 个源，并发下载（max_workers={MAX_WORKERS}）")
    if not sources:
        print("sources.txt 为空，退出", file=sys.stderr)
        sys.exit(1)

    all_domains = set()
    per_source = []
    ok_count = 0

    # 并发下载 + 解析（ThreadPoolExecutor 纯标准库，GitHub Actions 零依赖）
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
        future_to_meta = {ex.submit(fetch, url): (idx, url)
                          for idx, url in enumerate(sources)}
        for future in as_completed(future_to_meta):
            idx, url = future_to_meta[future]
            try:
                text = future.result()
                blocks = parse_blocks(text)
                all_domains |= blocks
                per_source.append({"url": url, "status": "ok", "count": len(blocks)})
                ok_count += 1
                print(f"[{idx+1}/{len(sources)}] OK  {len(blocks):>7}  {url}")
            except (URLError, Exception) as e:
                per_source.append({"url": url, "status": "fail", "error": str(e), "count": 0})
                print(f"[{idx+1}/{len(sources)}] FAIL         {url}  ({e})", file=sys.stderr)

    # 全源失败：不写空文件，避免破坏现有订阅
    if ok_count == 0:
        print("错误：所有源下载失败，不写入空文件，保留现有输出", file=sys.stderr)
        sys.exit(1)

    total_before = sum(p["count"] for p in per_source)
    after_merge = len(all_domains)
    # 短域名优先去重
    all_domains = dedup_short_domain(all_domains)
    total_after = len(all_domains)
    short_removed = after_merge - total_after

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    # header 去时间戳：规则无变化时不产生无意义 commit
    header = (
        "! Title: AdGuard Merged Blocklist\n"
        "! Description: Auto-merged & deduplicated, block-only\n"
        f"! Sources: {len(sources)}\n"
        f"! Rules: {total_after}\n"
        "\n"
    )
    with open(OUTPUT_FILE, "w", encoding="utf-8", newline="\n") as f:
        f.write(header)
        for d in sorted(all_domains):
            f.write(f"||{d}^\n")

    stats = {
        "generated_at": now,
        "sources_total": len(sources),
        "sources_ok": ok_count,
        "sources_failed": sum(1 for p in per_source if p["status"] == "fail"),
        "total_before_dedup": total_before,
        "after_merge_dedup": after_merge,
        "total_after_dedup": total_after,
        "duplicates_removed": total_before - total_after,
        "short_domain_removed": short_removed,
        "per_source": per_source,
        "elapsed_seconds": round(time.time() - start, 2),
    }
    with open(STATS_FILE, "w", encoding="utf-8") as f:
        json.dump(stats, f, ensure_ascii=False, indent=2)

    print()
    print(f"合并前合计:     {total_before}")
    print(f"合并去重后:     {after_merge}")
    print(f"短域名去重后:   {total_after}")
    print(f"短域名剔除:     {short_removed}")
    print(f"耗时:           {stats['elapsed_seconds']}s")
    print(f"输出:           {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
