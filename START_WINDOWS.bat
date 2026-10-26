@echo off
cd /d "%~dp0"
where py >nul 2>nul
if %ERRORLEVEL% EQU 0 (set "PY=py -3") else (set "PY=python")
if not exist .venv\Scripts\python.exe (
    echo Creating Python environment...
    %PY% -m venv .venv
    if errorlevel 1 goto :fail
)
echo Installing requirements...
.venv\Scripts\python.exe -m pip install -r requirements.txt
if errorlevel 1 goto :fail
echo.
echo Open http://127.0.0.1:8000
start "" "http://127.0.0.1:8000"
.venv\Scripts\python.exe -m uvicorn app:app --host 127.0.0.1 --port 8000
goto :end
:fail
echo Setup failed. Check Python 3.10+ and internet access.
pause
:end
