@echo off
REM Windows packaged release build for lancer-hydra.
REM Output: dist\lancer-hydra-windows-x86_64\bin\lancer-hydra.exe

set "BIN=lancer-hydra"
set "DIST=dist\%BIN%-windows-x86_64"

echo === Building lancer-hydra (release) for Windows x86_64 ===
cargo build --release -p lancer-hydra
if errorlevel 1 exit /b 1

echo === Packaging ===
if exist "%DIST%" rmdir /s /q "%DIST%"
mkdir "%DIST%"
mkdir "%DIST%\bin"

copy "target\release\%BIN%.exe" "%DIST%\bin\" >nul
copy "target\release\%BIN%-cli.exe" "%DIST%\bin\" >nul 2>nul
copy LICENSE "%DIST%\" >nul 2>nul
copy README.md "%DIST%\" >nul 2>nul

echo === Done. Binary: %DIST%\bin ===
dir "%DIST%\bin"
exit /b 0
