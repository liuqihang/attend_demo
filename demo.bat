@echo off
chcp 65001 >nul
echo 正在运行 RSA encryptLong 兼容加密演示...
echo.
node "%~dp0demo.js"
if errorlevel 1 (
  echo.
  echo [错误] 运行失败, 请确认已安装 Node.js 并加入 PATH
)
echo.
echo ---------- 命令行用法 ----------
node "%~dp0encrypt.js" --help
echo.
pause
