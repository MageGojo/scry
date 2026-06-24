#!/usr/bin/env python3
"""Scry 进程扩展示例(Python)。

通过 stdin/stdout 的 newline-delimited JSON 与 scry 通信(一问一答)。
- manifest:自述元数据(scry 握手时读取)。
- on_request:给请求加一个 X-Scry-Py 头(演示改写实时流量)。
- on_flow_complete:
    * 响应状态 >= 400 时上报一个 finding;
    * 若请求路径为 /active-probe,则**反向调用宿主** send_request 主动发一个请求(演示主动扫描)。
仅用 Python 标准库,无第三方依赖。stdout 只输出 JSON 行;调试信息走 stderr。
"""
import sys
import json

MANIFEST = {
    "id": "py-demo",
    "name": "Python 演示扩展",
    "version": "0.1.0",
    "description": "示例:加头 + 4xx/5xx 报 finding + /active-probe 主动发包(纯标准库)",
    "abi": 1,
    "permissions": ["traffic.modify", "net.outbound"],
    "hooks": ["on_request", "on_flow_complete"],
}

_call_id = [0]


def host_send_request(req):
    """反向调用宿主发一个 HTTP 请求(双向 RPC):写一条 call,再读一行 result。"""
    _call_id[0] += 1
    sys.stdout.write(json.dumps({"id": _call_id[0], "call": "send_request", "request": req}) + "\n")
    sys.stdout.flush()
    line = sys.stdin.readline()
    if not line:
        return {"status": 0, "error": "no result"}
    try:
        return json.loads(line).get("result", {})
    except Exception:
        return {"status": 0, "error": "bad result"}


def _url(flow):
    scheme = flow.get("scheme", "http")
    host = flow.get("host", "")
    port = int(flow.get("port", 0) or 0)
    path = flow.get("path", "")
    if (scheme == "https" and port == 443) or (scheme == "http" and port == 80):
        return "%s://%s%s" % (scheme, host, path)
    return "%s://%s:%d%s" % (scheme, host, port, path)


def handle(msg):
    hook = msg.get("hook")
    rid = msg.get("id", 0)

    if hook == "manifest":
        return {"id": rid, "manifest": MANIFEST}

    flow = msg.get("flow") or {}

    if hook == "on_request":
        headers = flow.get("req_headers") or []
        headers.append(["X-Scry-Py", "1"])
        flow["req_headers"] = headers
        return {
            "id": rid,
            "action": "continue",
            "flow": flow,
            "logs": [{"level": "Debug", "msg": "py: tagged %s %s" % (flow.get("method", ""), flow.get("host", ""))}],
        }

    if hook == "on_flow_complete":
        status = int(flow.get("status") or 0)
        out = {"id": rid, "action": "continue", "logs": [], "findings": []}
        if status >= 400:
            out["findings"].append({
                "severity": "Medium" if status >= 500 else "Low",
                "title": "HTTP %d" % status,
                "detail": "Python 扩展观测到错误响应",
                "url": _url(flow),
            })
        # 主动扫描演示:对 /active-probe 的流量,主动发一个请求验证目标。
        if flow.get("path") == "/active-probe":
            resp = host_send_request({"method": "GET", "url": "https://example.com/", "headers": [], "body": []})
            st = int(resp.get("status") or 0)
            out["logs"].append({"level": "Info", "msg": "py active-probe -> %d" % st})
            out["findings"].append({
                "severity": "Info",
                "title": "主动探测完成",
                "detail": "probe status %d" % st,
                "url": "https://example.com/",
            })
        return out

    # on_response 或未知钩子:放行
    return {"id": rid, "action": "continue"}


def main():
    while True:
        line = sys.stdin.readline()
        if not line:
            break
        line = line.strip()
        if not line:
            continue
        try:
            reply = handle(json.loads(line))
        except Exception as e:  # noqa: BLE001 - 演示:任何异常都放行,不打断流量
            reply = {"id": 0, "action": "continue",
                     "logs": [{"level": "Error", "msg": "py error: %s" % e}]}
        sys.stdout.write(json.dumps(reply, ensure_ascii=False) + "\n")
        sys.stdout.flush()


if __name__ == "__main__":
    main()
