@echo off
REM FenrisHub - Development Server Startup Script for Windows

echo.
echo ====================================
echo FenrisHub - Development Server
echo ====================================
echo.

REM Activate virtual environment
call .\venv\Scripts\activate.bat

REM Run the development server
python manage.py runserver

pause
