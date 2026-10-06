@echo off
REM Starts the app at http://127.0.0.1:5000 (Windows). No PowerShell permission changes needed.
cd /d "%~dp0"
if not exist venv\Scripts\python.exe (echo Run setup.bat first. & pause & exit /b 1)
if "%SECRET_KEY%"=="" (
  if not exist .secret_key venv\Scripts\python.exe -c "import secrets; print(secrets.token_hex(32))" > .secret_key
  set /p SECRET_KEY=<.secret_key
)
if "%PORT%"=="" set PORT=5000
echo ==^> Open http://127.0.0.1:%PORT% in your browser (Ctrl+C to stop)
venv\Scripts\python.exe app.py
pause
