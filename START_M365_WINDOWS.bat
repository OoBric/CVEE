@echo off
cd /d "%~dp0"
if not exist m365.local.env (
  echo Create m365.local.env from m365.local.env.example and fill in the tenant/application/list values.
  echo Do NOT share m365.local.env or your client secret.
  pause
  exit /b 1
)
for /f "usebackq tokens=1,* delims==" %%A in ("m365.local.env") do (
  if not "%%A"=="" set "%%A=%%B"
)
call START_WINDOWS.bat
