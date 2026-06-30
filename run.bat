@echo off
REM Run the attack map from source (Windows). Needs Python 3.8+ on PATH.
REM Config is read from a .env file in this folder (auto-loaded by app.py).
cd /d "%~dp0"
python app.py %*
pause
