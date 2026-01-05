@echo off
echo ====================================
echo WarpNET Security Scanner Builder
echo With Activation System
echo ====================================
echo.

python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo ERROR: Python is not installed
    pause
    exit /b 1
)

echo [1/3] Installing dependencies...
pip install -r requirements.txt
if %errorlevel% neq 0 (
    echo ERROR: Failed to install dependencies
    pause
    exit /b 1
)

echo [2/3] Building executable...
pyinstaller WarpNET_Security_Scanner.spec --clean --noconfirm
if %errorlevel% neq 0 (
    echo ERROR: Build failed
    pause
    exit /b 1
)

echo [3/3] Build complete!
echo.
echo Executable: dist\WarpNET_Security_Scanner.exe
echo.
pause