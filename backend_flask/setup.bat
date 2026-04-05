@echo off
REM CyberMind Sentinel - Complete Flask Backend Setup (Windows)
REM Run this script to set up the entire backend environment
REM Usage: setup.bat

setlocal enabledelayedexpansion

echo ================================
echo CyberMind Sentinel - Backend Setup (Windows)
echo ================================
echo.

REM Check if in correct directory
if not exist "requirements.txt" (
    echo Error: requirements.txt not found
    echo Please run this script from the backend_flask directory
    pause
    exit /b 1
)

echo Step 1: Checking Python installation
python --version >nul 2>&1
if errorlevel 1 (
    echo Error: Python not found
    echo Install Python 3.8+ from https://www.python.org/
    pause
    exit /b 1
)
for /f "tokens=*" %%i in ('python --version') do echo ✓ %%i
echo.

echo Step 2: Creating virtual environment
if not exist "venv" (
    python -m venv venv
    echo ✓ Virtual environment created
) else (
    echo → Virtual environment already exists
)
echo.

echo Step 3: Activating virtual environment
call venv\Scripts\activate.bat
echo ✓ Virtual environment activated
echo.

echo Step 4: Upgrading pip
python -m pip install --upgrade pip setuptools wheel >nul 2>&1
echo ✓ pip upgraded
echo.

echo Step 5: Installing dependencies
pip install -r requirements.txt
echo ✓ All dependencies installed
echo.

echo Step 6: Creating directories
if not exist "logs" mkdir logs
if not exist "data" mkdir data
if not exist "data\honeypot_logs" mkdir data\honeypot_logs
if not exist "data\alerts" mkdir data\alerts
if not exist "config" mkdir config
echo ✓ Directories created
echo.

echo Step 7: Setting up environment configuration
if not exist ".env" (
    if exist ".env.example" (
        copy .env.example .env >nul
        echo ✓ Created .env from template
        echo → Edit .env with your configuration
    ) else (
        echo Error: .env.example not found
    )
) else (
    echo → .env already exists
)
echo.

echo Step 8: Verifying package structure
python -c "import os; packages = ['app/__init__.py', 'app/core/firewall_manager.py', 'app/services/ai_translator.py', 'app/api/routes.py']; missing = [p for p in packages if not os.path.exists(p)]; print('✓ All files present' if not missing else f'✗ Missing: {missing}')"
echo.

echo Step 9: Running setup verification
python setup.py
echo.

echo ================================
echo ✓ Setup completed successfully!
echo ================================
echo.
echo Next steps:
echo 1. Edit .env with your configuration:
echo    notepad .env
echo.
echo 2. Start the backend server:
echo    python run.py
echo.
echo 3. In another terminal, start the frontend:
echo    cd ..\frontend ^&^& npm run dev
echo.
echo 4. Access the API:
echo    http://localhost:5000/api/health
echo.
pause
