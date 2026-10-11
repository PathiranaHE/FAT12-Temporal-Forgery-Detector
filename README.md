# FAT12-Temporal-Forgery-Detector

## Overview
This repository contains the Proof of Concept (PoC) for a specialized digital forensics tool designed to detect "timestomping" attacks on FAT12 filesystems. 

Standard forensics tools rely on logical OS metadata (which can be manipulated). This tool bypasses OS APIs to parse the raw hex of the FAT12 Root Directory. It maps the physical 32-byte write-order of files and compares it mathematically against the logical Creation Time (offsets `0x0E-0x11`) to detect chronological anomalies.

## Repository Contents
* `app.py`: The main Python application (includes the hex parser, heuristic comparison engine, and Tkinter UI).
* `Temporal_Forgery_Detector.exe`: A compiled, ready-to-run executable version of the tool.
* `5mbvhd.vhd`: A sandboxed FAT12 virtual hard drive containing a controlled timestomping attack for testing purposes.
* `UI.png`: Visual proof of the UI highlighting a true temporal forgery (Red) and a benign OS formatting delay (Yellow).
* `build.bat` & `Temporal_Forgery_Detector.spec`: PyInstaller build scripts used to compile the executable.

## How to Run the PoC
**Option 1: Run the Executable (No Python Required)**
1. Download `Temporal_Forgery_Detector.exe` and `5mbvhd.vhd`.
2. Double-click the `.exe` to launch the UI.
3. Click "Select FAT12 Image" and load the included `5mbvhd.vhd` file.

**Option 2: Run from Source**
1. Ensure Python 3.x is installed on your system.
2. Clone or download this repository.
3. Run the application: `python app.py`
4. Load the `5mbvhd.vhd` file via the UI.
