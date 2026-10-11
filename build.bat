@echo off
echo Building Temporal Forgery Detector - Phase 1
pyinstaller --noconsole --onefile app.py -n "Temporal_Forgery_Detector"
echo Build complete. Executable should be in the 'dist' folder.
pause
