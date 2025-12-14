# Virtual Aggregated Drive Manager

A Windows-based virtual storage aggregation system that allows multiple removable drives to behave as a single logical storage pool, with strong fault tolerance, checksum verification, and safe pause/resume handling.

Built using Python, Tkinter (ttkbootstrap), and multithreaded background workers.

---

## Overview

Virtual Aggregated Drive Manager lets you distribute files and folders across multiple removable drives while presenting them as a single virtual structure inside the application.

The system splits files proportionally based on available free space, tracks metadata in a replicated index, and safely reconstructs data even after interruptions, drive removal, or system restarts.

---

## Key Features

* Aggregates 2 or more removable drives into one virtual storage pool
* Proportional file splitting based on free space
* Background uploads and downloads using ThreadPoolExecutor
* Responsive pause and resume (manual and drive-based)
* Automatic detection of drive removal and reconnection
* SHA-256 checksum generation and verification per part
* Retry or abort options on checksum mismatch
* Folder and file upload support
* Folder and file download support
* Index replication across all selected drives
* Dark / light theme toggle
* Optional drag-and-drop support
* GUI-based activity logging

---

## How It Works

1. User selects multiple removable drives
2. Files are split into `.part` files and distributed across drives
3. SHA-256 checksums are generated for each part
4. Metadata is written to a hidden index folder
5. The index is replicated to all selected drives
6. During download, parts are verified and merged
7. Compressed files are automatically extracted if enabled

---

## Architecture Overview

GUI Layer

* Tkinter + ttkbootstrap UI
* Tree-based virtual file view
* Progress bars, ETA display, and logging

Core Engine

* Stream-based file splitting and merging
* Checksum computation and verification
* Pause, resume, and cancel handling

Storage Layer

* Physical removable drives
* Distributed `.part` files
* Replicated index metadata

---

## Index Structure

The index is stored on each selected drive under:

```
<DRIVE>/.vdrive_meta/index.json
```

Example index entry:

```json
"videos/movie.mkv": {
  "parts": [
    "E:/movie.mkv.part1",
    "F:/movie.mkv.part2"
  ],
  "compressed": false,
  "format": "store",
  "orig_name": "movie.mkv",
  "size": 2147483648,
  "status": "complete",
  "checksums": {
    "movie.mkv.part1": "9a3f...",
    "movie.mkv.part2": "d81c..."
  },
  "verified": true
}
```

---

## Pause and Resume Logic

Two independent pause mechanisms are implemented.

* user_pause_flag
  Triggered manually by the user.
  Does not auto-resume.

* drive_pause_flag
  Triggered automatically when a drive is removed.
  Clears automatically when all drives are reconnected.

Transfers pause safely between 32 KB sub-block writes for maximum responsiveness.

---

## Checksum and Integrity Verification

* SHA-256 checksum is computed for every `.part` file
* Checksums are stored in the index
* Verification happens before merging during download
* If a mismatch is detected:

  * User is prompted to Retry or Abort
  * Retry mode keeps rechecking until fixed or canceled

This design prevents silent data corruption.

---

## Installation

### Requirements

* Windows 10 or Windows 11
* Python 3.10 or higher
* At least two removable drives

### Dependencies

```bash
pip install ttkbootstrap
pip install tkinterdnd2   # optional (drag & drop)
pip install pywin32       # optional (accurate drive detection)
```

---

## Usage Guide

1. Launch the application

```bash
python main.py
```

2. Select at least two removable drives and click Confirm

3. Choose upload options such as chunk size and compression mode

4. Upload files or folders

5. Pause, resume, or cancel transfers at any time

6. Download files or folders with automatic integrity verification

---

## Supported Operations

* Upload single files
* Upload entire folders
* Download single files
* Download entire folders
* Delete files or folders
* Purge all virtual data
* Pause, resume, and cancel transfers

---

## Error Handling and Recovery

* Drive removal triggers automatic pause
* Drive reconnection triggers automatic resume
* Checksum mismatch triggers retry/abort prompt
* Cancel operation safely cleans up temporary files
* Index replication allows recovery after crashes

---

## Limitations

* Windows-only (uses Win32 APIs)
* No encryption (data stored in plaintext)
* Application-level storage aggregation, not a filesystem driver
* No redundancy or parity (RAID-like features not implemented)

---

## Roadmap

* File-level encryption
* Redundancy and parity support
* Linux compatibility
* CLI interface
* Integrity scan and repair tools
