#!/usr/bin/env python3
"""守护化启动 scry_app GUI。

本环境下 Cursor 会回收后台 shell 的进程组,普通 & / nohup 都会被杀;
用双 fork + os.setsid() 让 GUI 脱离会话常驻,窗口仍显示在用户的 Aqua 会话里。
"""
import os
import sys
import time

BIN = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                   "target", "debug", "scry_app")
LOG = "/tmp/scry_gui.log"


def main() -> None:
    if not os.path.exists(BIN):
        sys.stderr.write(f"二进制不存在: {BIN}\n")
        sys.exit(1)

    # 第一次 fork:父进程稍等后退出,让调用方的 shell 立即返回。
    if os.fork() > 0:
        time.sleep(0.5)
        sys.exit(0)

    os.setsid()  # 脱离控制终端会话与进程组,避免被回收。

    # 第二次 fork:确保不是会话首进程,彻底守护化。
    if os.fork() > 0:
        sys.exit(0)

    log = open(LOG, "a")
    os.dup2(log.fileno(), 1)
    os.dup2(log.fileno(), 2)
    with open(os.devnull, "r") as devnull:
        os.dup2(devnull.fileno(), 0)
    os.execv(BIN, [BIN])


if __name__ == "__main__":
    main()
