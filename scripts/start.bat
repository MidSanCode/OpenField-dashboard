@echo off
REM OpenField Admin Panel - Windows launcher
cd /d "%~dp0.."

REM Install only when the environment is missing, and never silently upgrade.
REM This unconditionally ran `pip install -r requirements.txt` on every start,
REM reaching the network each time and possibly replacing a working, tested
REM version with whatever upstream had published that day. requirements.txt is
REM now version-pinned; pass --install to run the install explicitly.
python -c "import flask, psycopg2, bcrypt" >nul 2>&1
if errorlevel 1 goto :install
if /i "%~1"=="--install" goto :install
echo [1/2] Dependencies already installed (pass --install to reinstall).
goto :run

:install
echo [1/2] Installing Python dependencies (pinned)...
python -m pip install -r requirements.txt
if errorlevel 1 goto :error

:run
echo [2/2] Starting admin panel at http://127.0.0.1:1343
python app.py
goto :eof

:error
echo Failed to start. Check Python installation.
pause
