@echo off
cd /d "%~dp0"
if not exist m365.local.env (
  echo Configure m365.local.env first. See MICROSOFT_365_SETUP.md
  exit /b 2
)
for /f "usebackq tokens=1,* delims==" %%A in ("m365.local.env") do (
  if not "%%A"=="" set "%%A=%%B"
)
if exist .venv\Scripts\python.exe (
  .venv\Scripts\python.exe sync_watchlist.py
) else (
  python sync_watchlist.py
)
exit /b %ERRORLEVEL%
