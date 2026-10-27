#!/bin/bash

# 启动命令，需在attend-demo目录下执行, 如在阿里云上则需要通过lxqy_start.sh shell脚本启动方可保证后台启动而不被终端关闭强制下线
nohup node server.js > app.log 2>&1 &