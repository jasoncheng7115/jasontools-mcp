"""SearXNG → MCP 包裝層。

讓 OpenCode 的地端模型能搜尋網路，查詢全部經由自架 SearXNG 送出，
不經過任何第三方搜尋 API。

Author: Jason Cheng (Jason Tools)
License: MIT
Version: 1.0.0
"""

__version__ = "1.0.0"
import os
import time
import collections
import asyncio
import html
import re
import httpx
from mcp.server import MCPServer

SEARXNG = os.environ.get("SEARXNG_URL", "http://searxng:8080")
TIMEOUT = float(os.environ.get("SEARCH_TIMEOUT", "45"))

# 2026-11-20：快取與限速，避免同一個 IP 爆量被搜尋引擎封鎖（10/28 單日數百次後 duckduckgo／google cse 被擋）
CACHE_TTL = int(os.environ.get("SEARCH_CACHE_TTL", "86400"))      # 相同查詢 24 小時內用快取
CACHE_MAX = int(os.environ.get("SEARCH_CACHE_MAX", "2000"))
LIMIT_PER_MIN = int(os.environ.get("SEARCH_LIMIT_PER_MIN", "10"))
LIMIT_PER_HOUR = int(os.environ.get("SEARCH_LIMIT_PER_HOUR", "100"))
# 2026-11-20：一般網頁引擎全部暫停時設這個（docker-compose 的 WEB_SEARCH_PAUSED），web_search 只剩維基百科，查不到就明講
WEB_SEARCH_PAUSED = os.environ.get("WEB_SEARCH_PAUSED", "").strip()

# 2026-11-20：一般網頁暫停時的補充來源 —— 都是官方提供、免註冊、免 API key 的 API
UA = {"User-Agent": "jt-searxng-mcp/1.0 (internal AI search helper)"}
SE_SITES = ["stackoverflow", "serverfault"]
SE_MIN_QUOTA = 30          # Stack Exchange 免 key 每個 IP 每天 300 次，剩這麼少就先不用
_se_state = {"quota": None, "backoff_until": 0.0}


async def _fb_ddg(c, query):
    r = await c.get("https://api.duckduckgo.com/", params={"q": query, "format": "json", "no_html": 1, "skip_disambig": 1})
    d = r.json()
    out = []
    if d.get("AbstractText"):
        out.append({"title": d.get("Heading") or query, "url": d.get("AbstractURL", ""),
                    "content": d["AbstractText"], "engines": ["duckduckgo 摘要"]})
    def walk(items):
        for t in items:
            if "Topics" in t:
                yield from walk(t["Topics"])
            elif t.get("Text") and t.get("FirstURL"):
                yield t
    for t in list(walk(d.get("RelatedTopics", [])))[:3]:
        out.append({"title": t["Text"][:80], "url": t["FirstURL"], "content": t["Text"], "engines": ["duckduckgo 相關"]})
    return out


async def _fb_stackexchange(c, query):
    now = time.time()
    if now < _se_state["backoff_until"]:
        return []
    if _se_state["quota"] is not None and _se_state["quota"] < SE_MIN_QUOTA:
        return []
    out = []
    for site in SE_SITES:
        r = await c.get("https://api.stackexchange.com/2.3/search/advanced",
                        params={"q": query, "site": site, "order": "desc", "sort": "relevance", "pagesize": 3})
        d = r.json()
        _se_state["quota"] = d.get("quota_remaining", _se_state["quota"])
        if d.get("backoff"):
            _se_state["backoff_until"] = time.time() + int(d["backoff"])
        for it in d.get("items", []):
            tags = ",".join(it.get("tags", [])[:5])
            ans = "已解答" if it.get("is_answered") else "未解答"
            out.append({"title": html.unescape(it.get("title", "")), "url": it.get("link", ""),
                        "content": f"[{tags}] {ans}，分數 {it.get('score', 0)}", "engines": [site]})
    return out


async def _fb_hn(c, query):
    r = await c.get("https://hn.algolia.com/api/v1/search", params={"query": query, "hitsPerPage": 3, "tags": "story"})
    out = []
    for h in r.json().get("hits", []):
        url = h.get("url") or f"https://news.ycombinator.com/item?id={h.get('objectID')}"
        out.append({"title": h.get("title", ""), "url": url,
                    "content": f"Hacker News 討論，{h.get('points', 0)} 分、{h.get('num_comments', 0)} 則留言（{(h.get('created_at') or '')[:10]}）",
                    "engines": ["hacker news"]})
    return out


_STOP = {"the", "and", "for", "with", "how", "what", "why", "not", "from", "can", "does", "into", "use", "using"}


def _keywords(query):
    return {w for w in re.findall(r"[a-z0-9][a-z0-9.+#_-]{2,}", query.lower()) if w not in _STOP}


async def _fallback(query):
    kw = _keywords(query)
    async with httpx.AsyncClient(timeout=15, headers=UA) as c:
        jobs = [_fb_ddg(c, query)]
        if kw:  # Stack Exchange／HN 是英文站，查詢沒有英文關鍵字就不送
            jobs += [_fb_stackexchange(c, query), _fb_hn(c, query)]
        got = await asyncio.gather(*jobs, return_exceptions=True)
    results = []
    for g in got:
        if isinstance(g, list):
            results.extend(g)
    # 相關性過濾：英文站的結果，標題至少要含一個查詢關鍵字
    def ok(r):
        if r["engines"][0].startswith("duckduckgo"):
            return True
        return any(w in r["title"].lower() for w in kw)
    return [r for r in results if ok(r)]
_cache: "collections.OrderedDict[tuple, tuple[float, str]]" = collections.OrderedDict()
_sent: "collections.deque[float]" = collections.deque()


def _cache_get(key):
    hit = _cache.get(key)
    if hit and time.time() - hit[0] < CACHE_TTL:
        _cache.move_to_end(key)
        return hit[1]
    _cache.pop(key, None)
    return None


def _cache_put(key, text):
    _cache[key] = (time.time(), text)
    _cache.move_to_end(key)
    while len(_cache) > CACHE_MAX:
        _cache.popitem(last=False)


def _rate_check():
    now = time.time()
    while _sent and now - _sent[0] > 3600:
        _sent.popleft()
    last_min = sum(1 for t in _sent if now - t <= 60)
    if last_min >= LIMIT_PER_MIN or len(_sent) >= LIMIT_PER_HOUR:
        wait = 60 if last_min >= LIMIT_PER_MIN else int(3600 - (now - _sent[0])) + 1
        raise RuntimeError(
            f"搜尋次數已達上限（每分鐘 {LIMIT_PER_MIN} 次、每小時 {LIMIT_PER_HOUR} 次），約 {wait} 秒後才能再搜尋。"
            "請不要重試；先用已經查到的結果或你已知的資訊回答（註明未經網路查證），或告知使用者稍後再查。")
    _sent.append(now)

mcp = MCPServer("searxng")


async def _search(query: str, max_results: int, language: str, categories: str) -> str:
    key = (" ".join(query.lower().split()), max_results, language, categories)
    cached = _cache_get(key)
    if cached is not None:
        return cached
    _rate_check()
    text = await _search_live(query, max_results, language, categories)
    if not text.startswith("搜尋失敗"):
        _cache_put(key, text)
    return text


async def _search_live(query: str, max_results: int, language: str, categories: str) -> str:
    params = {"q": query, "format": "json", "language": language}
    if categories:
        params["categories"] = categories
    try:
        async with httpx.AsyncClient(timeout=TIMEOUT) as c:
            r = await c.get(f"{SEARXNG}/search", params=params)
            r.raise_for_status()
            data = r.json()
    except Exception as e:
        return f"搜尋失敗：{type(e).__name__}: {e}"

    out = []
    for ib in data.get("infoboxes", [])[:1]:
        if ib.get("content"):
            out.append(f"【摘要】{ib.get('infobox','')}\n{ib['content'][:500]}\n")

    results = data.get("results", [])
    if not categories and WEB_SEARCH_PAUSED:
        results = results + await _fallback(query)
    results = results[:max_results]
    # 2026-11-20：引擎被擋（驗證碼／限流）時明講，避免模型以為是關鍵字問題而一直重搜
    failed = [f"{e[0]}（{e[1]}）" for e in data.get("unresponsive_engines", []) if isinstance(e, (list, tuple)) and len(e) >= 2]
    if not results and not out:
        if failed:
            raise RuntimeError(
                "搜尋引擎暫時無法使用：" + "、".join(failed) +
                "。這不是關鍵字的問題，換關鍵字重搜也不會有結果，請不要重試；"
                "改用你已知的資訊回答並註明未經網路查證，或直接告知使用者搜尋服務暫時無法使用。")
        return f"找不到「{query}」的結果。可以換個關鍵字，或改用英文查詢。"

    if results:
        out.append(f"「{query}」的搜尋結果（{len(results)} 筆）：\n")
    for i, r in enumerate(results, 1):
        title = (r.get("title") or "").strip()
        url = (r.get("url") or "").strip()
        content = (r.get("content") or "").strip()
        src = ",".join(r.get("engines", []))
        out.append(f"{i}. {title}\n   網址：{url}")
        if content:
            out.append(f"   摘要：{content[:320]}")
        if src:
            out.append(f"   來源：{src}")
        out.append("")
    if failed:
        out.append("（注意：部分搜尋引擎沒有回應：" + "、".join(failed) + "，結果可能不完整）")
    return "\n".join(out)


@mcp.tool()
async def web_search(query: str, max_results: int = 8, language: str = "zh-TW") -> str:
    """網路搜尋（預設用這個）。

    適用於絕大多數查詢，包含技術問題 —— 一般搜尋引擎的相關性排序
    通常比站內搜尋更準。查不到理想結果時，再改用 code_search。

    Args:
        query: 搜尋關鍵字
        max_results: 最多回傳幾筆（預設 8）
        language: 語言偏好，例如 zh-TW、en-US
    """
    text = await _search(query, max_results, language, "")
    if WEB_SEARCH_PAUSED:
        if text.startswith("找不到"):
            raise RuntimeError(
                f"一般網頁搜尋暫停中：{WEB_SEARCH_PAUSED}。目前只能查到維基百科、DuckDuckGo 摘要、Stack Exchange 與 Hacker News，這題都沒有結果。請不要換關鍵字重試；"
                "技術問題可改用 code_search，其他請用你已知的資訊回答並註明未經網路查證，或告知使用者搜尋暫時無法使用。")
        text += f"\n（注意：一般網頁搜尋暫停中：{WEB_SEARCH_PAUSED}。以上來自維基百科、DuckDuckGo 摘要、Stack Exchange、Hacker News，不含一般網頁、新聞與廠商官網）"
    return text


@mcp.tool()
async def code_search(query: str, max_results: int = 8) -> str:
    """限定在技術站內搜尋：Stack Overflow、GitHub、MDN、npm、Packagist、Docker Hub。

    只有在 web_search 找不到、或你明確想看某個技術站的內容時才用。
    注意：站內搜尋是關鍵字比對，相關性通常不如 web_search，
    查詢請用精確的英文技術名詞（例如函式名、錯誤訊息原文、套件名）。

    Args:
        query: 技術關鍵字，例如 "PHP 8 readonly property" 或 "vitest mock timer"
        max_results: 最多回傳幾筆（預設 8）
    """
    return await _search(query, max_results, "en-US", "it")


if __name__ == "__main__":
    mcp.run(transport="streamable-http", host="0.0.0.0", port=8021)
