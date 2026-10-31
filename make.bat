@echo off
if "%1"=="test" (
    python tests\security
    python tests\regression
) else if "%1"=="demo" (
    python run_demo.py
) else if "%1"=="security" (
    python tests\security
) else if "%1"=="regression" (
    python tests\regression
) else (
    python run_demo.py
)
