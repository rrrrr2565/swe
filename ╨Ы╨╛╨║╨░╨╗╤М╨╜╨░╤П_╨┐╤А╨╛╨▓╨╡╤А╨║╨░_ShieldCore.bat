@echo off
chcp 65001 >nul
setlocal
cd /d "%~dp0"
set "OUT=%USERPROFILE%\Desktop\ShieldCore-local-check.txt"
set "PY=python"
where py >nul 2>nul
if not errorlevel 1 set "PY=py -3"
echo ShieldCore local diagnostic > "%OUT%"
echo Date: %DATE% %TIME% >> "%OUT%"
echo Folder: %CD% >> "%OUT%"
echo. >> "%OUT%"
echo === Python version === >> "%OUT%"
%PY% --version >> "%OUT%" 2>&1
if errorlevel 1 (
  echo ERROR: Python 3 was not found. Install Python 3 and enable Tcl/Tk. >> "%OUT%"
  goto done
)
echo. >> "%OUT%"
echo === Compile checks === >> "%OUT%"
%PY% -m py_compile shieldcore.py shieldcore_gui.py signature_feed.py windows_defender.py tests\test_shieldcore.py >> "%OUT%" 2>&1
if errorlevel 1 echo Compile check FAILED. >> "%OUT%"
echo. >> "%OUT%"
echo === Automated safe tests === >> "%OUT%"
%PY% -m unittest discover -s tests -v >> "%OUT%" 2>&1
if errorlevel 1 (echo Automated tests FAILED. >> "%OUT%") else (echo Automated tests PASSED. >> "%OUT%")
echo. >> "%OUT%"
echo === Local signature database status === >> "%OUT%"
%PY% shieldcore.py db-info >> "%OUT%" 2>&1
echo. >> "%OUT%"
echo No remote connection or data upload was performed. >> "%OUT%"
echo No personal folders or full disks were scanned. >> "%OUT%"
echo To share results, attach this file in your chat. >> "%OUT%"
:done
echo.
echo Local diagnostics complete. Report: "%OUT%"
echo No files were uploaded and no remote access was enabled.
pause
