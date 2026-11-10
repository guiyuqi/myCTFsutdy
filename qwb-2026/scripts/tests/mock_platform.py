#!/usr/bin/env python3
"""本地假 DASCTF 平台：只用于离线验证 scripts/ycb.py 的解析/闸门，不碰真平台。"""
import json, sys
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs

TOKEN = "mock-token-1234567890abcdef"
MATCH = "1750"
STAGE = "9001"

EXERCISES = [
    {"exerciseId": "1001", "name": "签到", "corpusClassify": "MISC", "score": 100,
     "solvedCount": 88, "status": "OPEN", "corpusDifficulty": "简单"},
    {"exerciseId": "1002", "name": "BabyMenu", "corpusClassify": "PWN", "score": 500,
     "solvedCount": 2, "status": "OPEN", "corpusDifficulty": "困难"},
]
DETAILS = {e["exerciseId"]: dict(e, description=f"描述：{e['name']}",
                                 flagType="CONSTANT", attachmentCode="code-" + e["exerciseId"],
                                 relatedSceneVersion=["v1"]) for e in EXERCISES}
state = {"submitted": [], "env": {}, "events": {}, "port": 18080}

class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass

    def _json(self, obj, code=200):
        b = json.dumps(obj, ensure_ascii=False).encode()
        self.send_response(code)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def _auth(self):
        got = (self.headers.get("authorization") or "").strip()
        # 真实平台是 "Bearer <jwt>"；mock 同时接受裸 token，方便手工/脚本测试
        if got not in (TOKEN, "Bearer " + TOKEN):
            self._json({"code": "40401", "data": {}, "message": "未能读取到有效Token"})
            return False
        if self.headers.get("matchid") != MATCH:
            self._json({"code": "40402", "message": "matchId 不对"})
            return False
        return True

    def do_GET(self):
        if not self._auth(): return
        u = urlparse(self.path); q = parse_qs(u.query); p = u.path
        if p.endswith("/player/stage/status-list"):
            return self._json({"code": "00000", "data": json.dumps(
                [{"id": STAGE, "name": "初赛", "status": "RUNNING"}], ensure_ascii=False)})
        if p.endswith("/player/ctf/exercise-list"):
            assert q.get("stageId", [""])[0] == STAGE, "stageId 必须带上"
            return self._json({"code": "00000", "data": EXERCISES})
        if p.endswith("/player/ctf/exercise"):
            eid = q.get("exerciseId", [""])[0]
            d = dict(DETAILS.get(eid, {}))
            # 真实平台的 endpoints 形状（见 notes/ch-meta/ch_12061/detail.json）
            st = state["env"].get(eid, "NONE")
            if st == "RUNNING":
                d["endpoints"] = [{
                    "objectId": "endpoint_mock_" + eid,
                    "exposeIps": [f"127.0.0.1:{state.get('port', 18080)}"],
                    "serviceStatus": "UP", "status": "running",
                    "ports": ["http/3000"],
                    "portMappings": [{"type": "http", "port": "3000", "proxy": "mock"}],
                    "proxyIps": ["127.0.0.1"], "isProxy": True,
                    "expireTime": 1792834200000,
                }]
            else:
                d["endpoints"] = []      # CREATING / NONE 都返回空 —— 也就是"幽灵态"
            return self._json({"code": "00000", "data": d})
        if p.endswith("/player/match/user/detail"):
            return self._json({"code": "00000", "data": {"nickname": "测试队", "username": "mock"}})
        if p.endswith("/player/answer-panel/monitor-answer-result"):
            eid = int(q.get("eventId", ["0"])[0] or 0)
            r = state["events"].get(eid)
            if not r:
                return self._json({"code": "00000", "data": {"result": False}})
            return self._json({"code": "00000", "data": {"score": 100, "result": True}})
        if p.endswith("/player/ctf/check-exercise-env"):
            eid = q.get("exerciseId", [""])[0]
            return self._json({"code": "00000", "data": {"status": state["env"].get(eid, "NONE")}})
        if p.endswith("/player/match/notice/now-list"):
            return self._json({"code": "00000", "data": [{"title": "开赛公告", "content": "10:00 开始"}]})
        return self._json({"code": "40400", "message": "unknown " + p})

    def do_POST(self):
        if not self._auth(): return
        n = int(self.headers.get("content-length") or 0)
        body = json.loads(self.rfile.read(n) or b"{}")
        p = urlparse(self.path).path
        if p.endswith("/player/answer-panel/answer"):
            state["submitted"].append(body)
            ok = body.get("flag") == "flag{right}"
            eid = len(state["submitted"])
            state["events"][eid] = ok
            data = {"result": ok}
            if ok:
                data = {"eventId": eid}          # 模拟"正确但只给 eventId"
            return self._json({"code": "00000", "data": data})
        if p.endswith("/player/ctf/build-exercise-env"):
            eid = str(body.get("exerciseId"))
            # 2001 = 幽灵容器：start 成功但永远不 running（复现本场 12061/12066）
            state["env"][eid] = "CREATING" if eid == "2001" else "RUNNING"
            return self._json({"code": "00000", "message": "环境已创建", "data": {}})
        if p.endswith("/player/ctf/recover-exercise-env"):
            # ★ 权威语义（notes/ENV-DEFECTS.md）：recover = 销毁 / expire = 续期（名字相反）
            state["env"][str(body.get("exerciseId"))] = "NONE"
            return self._json({"code": "00000", "message": "销毁靶机成功"})
        if p.endswith("/player/ctf/expire-exercise-env"):
            # 续期：保持原状态
            return self._json({"code": "00000", "message": "已续期"})
        if p.endswith("/exercise/ctf-download"):
            b = b"PK\x03\x04mock-attachment"
            self.send_response(200)
            self.send_header("content-type", "application/octet-stream")
            self.send_header("content-disposition", 'attachment; filename="mock.zip"')
            self.send_header("content-length", str(len(b)))
            self.end_headers()
            self.wfile.write(b)
            return
        return self._json({"code": "40400", "message": "unknown " + p})

if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 18080
    state["port"] = port
    HTTPServer(("127.0.0.1", port), H).serve_forever()
