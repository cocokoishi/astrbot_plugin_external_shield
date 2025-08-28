from __future__ import annotations
import re, json, asyncio, urllib.request, urllib.error, urllib.parse
from typing import List, Optional, Any, Tuple

from astrbot.api.event import filter, AstrMessageEvent
from astrbot.api.star import Context, Star, register
from astrbot.api import logger

try:
    from astrbot.api.provider import LLMResponse as ProviderResponse
except Exception:
    from astrbot.api.provider import ProviderResponse


#全局实例
INSTANCE: "KWShieldPlugin | None" = None


@register("astrbot_plugin_external_shield", "you", "外置屏蔽词过滤（OpenAI兼容HTTP + LLM并联）", "2.1.0")
class KWShieldPlugin(Star):

    def __init__(self, context: Context, config=None):
        super().__init__(context)
        cfg = config or {}

        # 基础
        self.apply_to: str = cfg.get("apply_to", "both")  # both | input_only | output_only
        self.keyword_action: str = cfg.get("keyword_action", "reply")  # reply | silent
        self.custom_text: str = cfg.get("custom_text", "这个呢，咱也不知道呢喵")
        self.debug_log: bool = bool(cfg.get("debug_log_enable", True))

        # 关键词
        self.keyword_enable: bool = bool(cfg.get("keyword_enable", True))
        self.keywords: List[str] = self._load_keywords_list_first(cfg)
        self.keywords = self._dedup_clean(self.keywords)

        # LLM（HTTP）并联判定
        self.llm_check_enable: bool = bool(cfg.get("llm_check_enable", False))
        self.llm_scope: str = cfg.get("llm_scope", "both")  # both | input_only | output_only
        self.llm_timeout_sec: float = float(cfg.get("llm_timeout_sec", 6.0))
        self.llm_yes_char: str = (cfg.get("llm_yes_char", "Y") or "Y")[:1]
        self.llm_no_char: str = (cfg.get("llm_no_char", "N") or "N")[:1]
        self.llm_system_prompt: str = cfg.get(
            "llm_system_prompt",
            "你是内容安全判定器。仅返回一个字符：Y 表示违规；N 表示不违规。不要解释、不要输出多余字符。"
            "如果用户/回复内容包含不适当、违法、暴力、辱骂、仇恨、成人或平台禁止内容，则返回 Y；否则返回 N。"
        )

        self.api_endpoint: str = (cfg.get("api_endpoint", "") or "").strip()  # e.g. https://api.deepseek.com/v1/chat/completions
        self.model_name: str = (cfg.get("model_name", "") or "").strip()
        self.api_key: str = (cfg.get("api_key", "") or "").strip()            # 你的 API Key
        # Key 放置方式：Authorization Bearer / Header 自定义 / Query
        self.api_key_in: str = cfg.get("api_key_in", "authorization_bearer")  # authorization_bearer | header | query
        self.api_key_header_name: str = cfg.get("api_key_header_name", "X-API-Key")
        self.api_key_query_name: str = cfg.get("api_key_query_name", "api_key")

        self._log(
            "INIT apply_to=%s action=%s kw_enable=%s kw_count=%d llm_enable=%s llm_scope=%s endpoint=%r model=%r key_in=%s",
            self.apply_to, self.keyword_action, self.keyword_enable, len(self.keywords),
            self.llm_check_enable, self.llm_scope, self.api_endpoint or "<unset>", self.model_name or "<unset>",
            self.api_key_in
        )


        global INSTANCE
        INSTANCE = self

    #工具：日志
    def _log(self, msg: str, *args):
        if self.debug_log:
            logger.info("[ExtShield] " + msg, *args)

    #工具：解析
    def _load_keywords_list_first(self, cfg) -> List[str]:
        v = cfg.get("extra_keywords", None)
        if isinstance(v, list):
            return [str(x) for x in v]
        if isinstance(v, str) and v.strip():
            try:
                parsed = json.loads(v)
                if isinstance(parsed, list):
                    return [str(x) for x in parsed]
            except Exception:
                pass
            parts = re.split(r"[,\n\r;]+", v.strip())
            return [p for p in (s.strip() for s in parts) if p]
        return ["8964", "跳跳虎"]

    def _dedup_clean(self, items: List[str]) -> List[str]:
        seen, out = set(), []
        for x in items:
            s = x.strip()
            if s and s not in seen:
                seen.add(s); out.append(s)
        return out

    #关键词命中
    def _hit_keywords(self, s: str | None) -> Optional[str]:
        if not (self.keyword_enable and s and self.keywords):
            return None
        for kw in self.keywords:
            if kw in s:
                return kw
        return None

    #发送 HTTP（标准库；放线程避免阻塞事件循环）
    async def _http_json(self, url: str, method: str, headers: dict, body_obj: dict, timeout_sec: float) -> Optional[dict]:
        def _do_request():
            data = json.dumps(body_obj, ensure_ascii=False).encode("utf-8")
            hdrs = {"Content-Type": "application/json"}
            hdrs.update({str(k): str(v) for k, v in (headers or {}).items()})
            req = urllib.request.Request(url=url, data=data, headers=hdrs, method=method)
            with urllib.request.urlopen(req, timeout=timeout_sec) as resp:
                raw = resp.read().decode("utf-8", "ignore")
                return json.loads(raw)
        try:
            return await asyncio.to_thread(_do_request)
        except Exception as e:
            self._log("HTTP error: %s", e)
            return None

    #构造 URL（处理 query key 注入）
    def _build_url_with_query_key(self, base_url: str) -> str:
        if self.api_key_in != "query" or not self.api_key:
            return base_url
        try:
            parsed = urllib.parse.urlparse(base_url)
            q = dict(urllib.parse.parse_qsl(parsed.query, keep_blank_values=True))
            q[self.api_key_query_name or "api_key"] = self.api_key
            new_query = urllib.parse.urlencode(q)
            return urllib.parse.urlunparse(parsed._replace(query=new_query))
        except Exception:
            return base_url

    #构造 Headers（注入 key）
    def _build_headers(self) -> dict:
        if not self.api_key:
            return {}
        if self.api_key_in == "authorization_bearer":
            return {"Authorization": f"Bearer {self.api_key}"}
        if self.api_key_in == "header":
            name = self.api_key_header_name.strip() or "X-API-Key"
            return {name: self.api_key}
        # query 模式不在 header 放 key
        return {}

    #LLM 并联路径：HTTP 判定（OpenAI 兼容 Chat Completions）
    async def _llm_flag(self, text: str) -> bool:
        if not self.llm_check_enable:
            return False
        if not (self.api_endpoint and self.model_name and self.api_key):
            self._log("LLM check not configured (endpoint/model/api_key missing).")
            return False

        url = self._build_url_with_query_key(self.api_endpoint)
        headers = self._build_headers()

        body = {
            "model": self.model_name,
            "messages": [
                {"role": "system", "content": self.llm_system_prompt},
                {"role": "user", "content": text}
            ],
            "temperature": 0.0,
            "max_tokens": 1,
            "stream": False
        }

        self._log("HTTP POST %s body_keys=%s", url, list(body.keys()))
        resp = await self._http_json(url, "POST", headers, body, self.llm_timeout_sec)
        if resp is None:
            return False

        # 期望 OpenAI 兼容返回：choices[0].message.content
        try:
            out = resp.get("choices", [{}])[0].get("message", {}).get("content", "")
        except Exception:
            out = ""
        c = (str(out).strip()[:1]) if out is not None else ""
        self._log("HTTP resp char=%r raw=%r", c, out)

        if c == self.llm_yes_char:
            return True
        if c == self.llm_no_char:
            return False
        return False

    async def _do_action_and_stop(self, event: AstrMessageEvent, reason: str):
        self._log("ACTION %s reason=%s", self.keyword_action.upper(), reason)
        if self.keyword_action == "silent":
            event.stop_event()
        else:
            await event.send(event.plain_result(self.custom_text))
            event.stop_event()


#参数归一化工具：兼容不同钩子调用签名
def _as_plugin(obj: Any) -> Optional[KWShieldPlugin]:
    if isinstance(obj, KWShieldPlugin):
        return obj
    if hasattr(obj, "_hit_keywords") and hasattr(obj, "keyword_action"):
        try:
            if isinstance(obj, Star):
                return obj  # type: ignore
        except Exception:
            pass
    return None


def _normalize_input_args(args: Tuple[Any, ...]) -> Tuple[Optional[KWShieldPlugin], Optional[AstrMessageEvent]]:
    if len(args) == 1:
        return (INSTANCE, args[0])
    if len(args) >= 2:
        plug = _as_plugin(args[0])
        if plug:
            return (plug, args[1])
        else:
            return (INSTANCE, args[0])
    return (INSTANCE, None)


def _normalize_output_args(args: Tuple[Any, ...]) -> Tuple[Optional[KWShieldPlugin], Optional[AstrMessageEvent], Optional[ProviderResponse]]:
    if len(args) == 2:
        return (INSTANCE, args[0], args[1])
    if len(args) >= 3:
        plug = _as_plugin(args[0])
        if plug:
            return (plug, args[1], args[2])
        else:
            return (INSTANCE, args[0], args[1])
    return (INSTANCE, None, None)


# A. 输入并联（最高优先级）
@filter.event_message_type(filter.EventMessageType.ALL, priority=999999)
async def main_guard_input(*args):
    plugin, event = _normalize_input_args(args)
    if plugin is None or event is None:
        return

    if plugin.apply_to == "output_only":
        return
    text = (getattr(event, "message_str", "") or "")
    plugin._log("INPUT text[0:60]=%r", text[:60])

    kw = plugin._hit_keywords(text)
    llm_task = None
    if plugin.llm_check_enable and plugin.llm_scope in ("both", "input_only"):
        llm_task = asyncio.create_task(plugin._llm_flag(text))

    if kw is not None:
        plugin._log("INPUT kw-hit=%r", kw)
        if llm_task:
            llm_task.cancel()
            plugin._log("INPUT cancel llm task due to kw-hit")
        await plugin._do_action_and_stop(event, reason=f"kw:{kw}")
        return

    if llm_task:
        try:
            flagged = await llm_task
        except Exception:
            flagged = False
        if flagged:
            await plugin._do_action_and_stop(event, reason="llm:Y")


# B. 输出并联（最高优先级）
@filter.on_llm_response(priority=999999)
async def main_guard_output(*args):
    plugin, event, resp = _normalize_output_args(args)
    if plugin is None or event is None or resp is None:
        return

    if plugin.apply_to == "input_only":
        return

    out = getattr(resp, "completion_text", None) or getattr(resp, "text", None)
    if not isinstance(out, str):
        return
    plugin._log("OUTPUT text[0:60]=%r", out[:60])

    kw = plugin._hit_keywords(out)
    llm_task = None
    if plugin.llm_check_enable and plugin.llm_scope in ("both", "output_only"):
        llm_task = asyncio.create_task(plugin._llm_flag(out))

    if kw is not None:
        plugin._log("OUTPUT kw-hit=%r", kw)
        if llm_task:
            llm_task.cancel()
            plugin._log("OUTPUT cancel llm task due to kw-hit")
        await plugin._do_action_and_stop(event, reason=f"kw:{kw}")
        return

    if llm_task:
        try:
            flagged = await llm_task
        except Exception:
            flagged = False
        if flagged:
            await plugin._do_action_and_stop(event, reason="llm:Y")
