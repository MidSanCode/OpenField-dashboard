@echo off
REM OpenField Admin Panel - Windows launcher
cd /d "%~dp0.."

echo [1/2] Installing Python dependencies...
python -m pip install -r requirements.txt
if errorlevel 1 goto :error

echo [2/2] Starting admin panel at http://127.0.0.1:5001
python app.py
goto :eof

:error
echo Failed to start. Check Python installation.
pause
