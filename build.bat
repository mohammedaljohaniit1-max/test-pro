@echo off
rem ---------------------------------------------------------------------------
rem  SysPulse build script
rem  Produces a single self-contained dist\syspulse.exe (web UI embedded).
rem
rem  Usage:  build.bat [version] [arch]
rem          build.bat                -> version 3.0.0, amd64
rem          build.bat 1.2.0 arm64    -> version 1.2.0, arm64
rem  Env:    SKIP_TESTS=1 to skip go vet / go test
rem  Needs:  Go 1.23+ on PATH (https://go.dev/dl/)
rem ---------------------------------------------------------------------------
setlocal EnableExtensions

set "VERSION=%~1"
if "%VERSION%"=="" set "VERSION=3.0.0"
set "ARCH=%~2"
if "%ARCH%"=="" set "ARCH=amd64"
set "MODULE=github.com/mohammedaljohaniit1-max/test-pro"
set "OUT=dist\syspulse.exe"
if /I not "%ARCH%"=="amd64" set "OUT=dist\syspulse-%ARCH%.exe"

cd /d "%~dp0"

where go >nul 2>nul
if errorlevel 1 (
  echo [x] Go toolchain not found on PATH. Install Go 1.23+ from https://go.dev/dl/
  exit /b 1
)
for /f "tokens=3" %%v in ('go version') do echo [i] Using %%v

echo [1/4] Downloading modules...
go mod download
if errorlevel 1 goto :fail

if "%SKIP_TESTS%"=="1" (
  echo [2/4] Skipping vet
  echo [3/4] Skipping tests
) else (
  echo [2/4] go vet
  go vet ./...
  if errorlevel 1 goto :fail
  echo [3/4] go test
  go test -count=1 ./...
  if errorlevel 1 goto :fail
)

echo [4/4] Building %OUT% ^(v%VERSION%, windows/%ARCH%^)
if not exist dist mkdir dist
set "CGO_ENABLED=0"
set "GOOS=windows"
set "GOARCH=%ARCH%"
go build -trimpath -ldflags "-s -w -X %MODULE%/internal/server.Version=%VERSION%" -o "%OUT%" ./cmd/syspulse
if errorlevel 1 goto :fail

for %%F in ("%OUT%") do echo [ok] %%~fF  (%%~zF bytes)
echo.
echo Run it:   %OUT%
echo Then open http://localhost:9099  (opens automatically; use -no-browser to disable)
echo Tip: run from an elevated prompt to see details of all processes.
endlocal
exit /b 0

:fail
echo [x] Build failed.
endlocal
exit /b 1
