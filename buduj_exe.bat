@echo off
chcp 65001 >nul
title Budowanie Szyfrator.exe - Karol Kościelniak
echo ============================================================
echo   BUDOWANIE NOWEJ WERSJI SZYFRATOR.EXE (PyInstaller)
echo ============================================================
echo.
echo Kompilowanie programu do jednego pliku .exe...
python -m PyInstaller --onefile --name szyfrator --distpath ".\dist" "szyfrator.py"

if %ERRORLEVEL% EQU 0 (
    copy /Y ".\dist\szyfrator.exe" ".\szyfrator.exe" >nul
    echo.
    echo ============================================================
    echo   [SUKCES] Nowy plik szyfrator.exe zostal utworzony!
    echo ============================================================
) else (
    echo.
    echo [BLAD] Cos poszlo nie tak podczas budowania. Sprawdz bledy powyzej.
)
echo.
pause
