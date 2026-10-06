@echo off
REM One-time setup: creates a virtual environment and installs everything (Windows).
cd /d "%~dp0"
echo ==^> Creating virtual environment...
python -m venv venv || (echo Python was not found. Install it from python.org and tick "Add Python to PATH". & pause & exit /b 1)
echo ==^> Installing dependencies...
venv\Scripts\python.exe -m pip install --upgrade pip -q
venv\Scripts\python.exe -m pip install -r requirements-dev.txt -q || (echo Install failed. & pause & exit /b 1)
echo ==^> Setup complete. Start the app by double-clicking run.bat
pause
