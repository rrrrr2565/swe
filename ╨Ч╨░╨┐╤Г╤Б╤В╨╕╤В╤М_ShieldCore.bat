@echo off
chcp 65001 >nul
cd /d "%~dp0"
where py >nul 2>nul
if %errorlevel%==0 (
  py -3 shieldcore_gui.py
) else (
  python shieldcore_gui.py
)
if errorlevel 1 pause
