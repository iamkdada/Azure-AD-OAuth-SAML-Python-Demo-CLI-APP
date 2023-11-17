@echo off
setlocal

set "dir=%~dp0"

if "%PYTHONPATH%" == "" (
    set "PYTHONPATH=%dir%"
) else (
    set "PYTHONPATH=%dir%;%PYTHONPATH%"
)

python -m dada_cli %*

endlocal