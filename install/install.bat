<<<<<<< HEAD:install/install.bat
::Windows only
@echo off
python --version 3>NUL
if %errorlevel% equ 0 (
    echo Python is installed! Continue...
    pip install -r requirements.txt
    echo Dependencies installed successfully! Now you can run tcp-proxy.py and close this window!
) else (
    echo Python is not installed. Please download and install Python from https://www.python.org/downloads/
)
=======
::Windows only
@echo off
python --version 3>NUL
if %errorlevel% equ 0 (
    echo Python is installed! Continue...
    pip install -r requirements.txt
    echo Dependencies installed successfully! Now you can run packet_inspector.py and close this window!
) else (
    echo Python is not installed. Please download and install Python from https://www.python.org/downloads/
)
>>>>>>> 1816e615cdd3890e6bc432071a30d5bb06757eae:install/install_dependencies.bat
cmd /k