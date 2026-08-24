@echo off
setlocal
cd /d "%~dp0"

echo ===================================================
echo   TCP/53 Block Watch
echo ===================================================
echo.
echo   [1] Watch continuously  (Ctrl+C to stop)
echo   [2] Run one diagnosis and write a report
echo   [3] Run the self-test
echo.

set "choice="
set /p choice=Select [1]:
if "%choice%"=="" set choice=1

if "%choice%"=="2" goto diagnose
if "%choice%"=="3" goto selftest

:watch
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0Start-Tcp53Watch.ps1"
goto done

:diagnose
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0Invoke-Tcp53Diagnose.ps1"
goto done

:selftest
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0Test-Tcp53SelfTest.ps1"
goto done

:done
echo.
pause
