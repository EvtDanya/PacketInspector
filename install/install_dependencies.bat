::Windows only
@echo off
python --version 3>NUL
if %errorlevel% equ 0 (
    echo Python is installed! Continue...
    pip install -r requirements.txt
    echo Dependencies installed successfully! Now you can run PacketInspector.py!
) else (
    echo Python is not installed. Please download and install Python from https://www.python.org/downloads/
)