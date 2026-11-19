@echo off
setlocal
chcp 65001 >nul
cd /d "%~dp0"

set "PY="
if exist "C:\Python314\python.exe" set "PY=C:\Python314\python.exe"
if not defined PY (where py >nul 2>nul && set "PY=py -3")
if not defined PY (where python >nul 2>nul && set "PY=python")
if not defined PY (
  echo [错误] 没有找到 Python。请安装 Python 3.8+ 并勾选 "Add to PATH"。
  pause
  exit /b 1
)

rem ---- 双击（无参数）: 直接启动 Web 界面 ----
if "%~1"=="" goto web

rem ---- argdecode.bat cli : 命令行交互模式 ----
if /i "%~1"=="cli" goto cli

rem ---- 其它参数: 直接转发给 CLI；参数是文件则按文件读取 ----
if exist "%~1" (
  %PY% "%~dp0argdecode.py" -f "%~1" %2 %3 %4 %5 %6 %7 %8 %9
) else (
  %PY% "%~dp0argdecode.py" %*
)
echo.
pause
exit /b 0

:cli
echo.
set "CIPHER="
set /p "CIPHER=密文: "
if errorlevel 1 exit /b 0
if not defined CIPHER exit /b 0
echo.
%PY% "%~dp0argdecode.py" "%CIPHER%" --top 15
echo.
echo 提示：可把文件直接拖到本 bat 图标上破解；复杂情况建议用 Web 界面。
pause
exit /b 0

:web
echo 正在启动 Web 界面，浏览器会自动打开；关闭本窗口即停止服务。
%PY% "%~dp0argdecode_gui.py"
echo.
pause
exit /b 0
