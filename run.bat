@echo off
echo ============================================
echo  文件句柄监控工具 - 启动脚本
echo ============================================
echo.

REM 检查 handle.exe 是否存在
if not exist "%~dp0handle.exe" (
    echo [提示] 未在当前目录找到 handle.exe
    echo 请从以下地址下载 Sysinternals handle.exe 并放到本目录:
    echo https://learn.microsoft.com/sysinternals/downloads/handle
    echo.
)

REM 检查 Python
python --version >nul 2>&1
if errorlevel 1 (
    echo [错误] 未找到 Python，请先安装 Python 3.10+
    pause
    exit /b 1
)

REM 以管理员权限启动
net session >nul 2>&1
if errorlevel 1 (
    echo 正在请求管理员权限 ...
    powershell -Command "Start-Process -FilePath 'python' -ArgumentList '\"%~dp0handle_monitor.py\"' -Verb RunAs"
) else (
    python "%~dp0handle_monitor.py"
)
