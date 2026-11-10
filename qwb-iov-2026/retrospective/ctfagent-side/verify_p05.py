#!/usr/bin/env python3
"""P0-5 端到端验证：worker 的 pi 启动参数里技能是否真的被加载。

做的事：
  1. 用 muteki 自己的 resolver 生成 pi-agent/models.json（真凭据路径）；
  2. 在临时目录里按 muteki 的方式投影 .pi/skills / .agents/skills（指向 engine/muteki/skills）；
  3. 用 PiDriver 生成 argv（默认开关），apply_runtime_argv 补 provider/model；
  4. 跑一次真调用，解析 agent_end 里的 system sections，断言出现 skills 且含 playbook。

退出码 0/3。一次调用约几百 token。
"""
from __future__ import annotations

import json
import os
import pathlib
import subprocess
import sys

HOME = pathlib.Path.home()
ROOT = HOME / ".ctfagent"
ENGINE = ROOT / "engine" / "muteki"
WORK = pathlib.Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else pathlib.Path.cwd() / "p05-verify"


def stage_models(work: pathlib.Path) -> dict:
    sys.path.insert(0, str(ENGINE))
    from muteki.solver.credential_accounts import runtime_env_for_engine
    r = runtime_env_for_engine(
        "pi",
        account_root=ROOT / "state" / "muteki" / "_secrets" / "accounts",
        account_id="pi-main",
        env={},
        agent_state_dir=work / "pi-agent",
        model="deepseek-flash",
    )
    return dict(r.env or {})


def stage_skills(work: pathlib.Path) -> None:
    for root in (".pi/skills", ".agents/skills"):
        dst = work / root
        dst.mkdir(parents=True, exist_ok=True)
        for name in ("muteki-ctf-local-playbook", "muteki-blackboard", "muteki-waf-bypass"):
            link = dst / name
            if link.is_symlink() or link.exists():
                continue
            link.symlink_to(ENGINE / "skills" / name)


def main() -> int:
    WORK.mkdir(parents=True, exist_ok=True)
    env = stage_models(WORK)
    stage_skills(WORK)

    sys.path.insert(0, str(ENGINE))
    from muteki.solver.cli_engines.engines.pi import PiDriver
    from muteki.solver.cli_engines.argv import apply_runtime_argv

    os.environ["MUTEKI_PI_BIN"] = str(ROOT / ".s1-tools" / "bin" / "pi")
    d = PiDriver()
    print("[pi bin]", d.bin)
    argv = d.build_execute("Reply with the single word OK.", None)
    argv = apply_runtime_argv(argv, driver=d, env=env)
    print("[argv]", " ".join(a if not a.startswith("You ") else "<prompt>" for a in argv)[:400])
    print("[has --no-skills]", "--no-skills" in argv, "| [has --approve]", "--approve" in argv)

    run_env = dict(os.environ)
    run_env.update(env)
    proc = subprocess.run(argv, cwd=WORK, capture_output=True, text=True,
                          timeout=180, env=run_env)
    if proc.returncode != 0:
        print("[FAIL] pi rc=", proc.returncode, (proc.stderr or "")[:400])
        return 3
    sections = None
    for line in (proc.stdout or "").splitlines():
        try:
            ev = json.loads(line)
        except json.JSONDecodeError:
            continue
        if ev.get("type") == "agent_end":
            sections = (ev.get("messages") or [{}])[0].get("sections") or {}
            break
    if sections is None:
        print("[FAIL] 没有 agent_end")
        return 3
    names = [k for k in sections]
    skills = str(sections.get("skills") or "")
    ok = "skills" in sections and "muteki-ctf-local-playbook" in skills
    print("[system sections]", names)
    print("[skills 里含 playbook]", "muteki-ctf-local-playbook" in skills)
    if ok:
        print("[PASS] worker 现在能看到 muteki 自带的 CTF playbook")
        return 0
    print("[FAIL] skills 段缺失或不含 playbook")
    return 3


if __name__ == "__main__":
    raise SystemExit(main())
