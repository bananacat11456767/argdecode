@echo off
setlocal
chcp 65001 >nul
cd /d "%~dp0"
set "PY="
if exist "C:\Python314\python.exe" set "PY=C:\Python314\python.exe"
if not defined PY (where py >nul 2>nul && set "PY=py -3")
if not defined PY (where python >nul 2>nul && set "PY=python")
if not defined PY (
  echo [错误] 没有找到 Python。
  pause
  exit /b 1
)
echo 正在启动 argdecode Web GUI ...
%PY% "%~dp0argdecode_gui.py" %*
echo.
pause
