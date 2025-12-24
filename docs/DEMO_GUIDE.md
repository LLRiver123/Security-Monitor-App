# 🛡️ Security Monitor - Demo Guide

This guide outlines how to demonstrate the new capabilities of the Security Monitor Agent, focusing on the visual Ransomware simulation and Auto-Remediation features.

## Prerequisites
- Ensure the app is running (`npm start` in `ui/`).
- Ensure Python environment is set up.

## Scenario 1: Manual Remediation (The "Panic" Mode)

**Goal:** Show that the Agent detects threats and allows the user to take action, while the Ransomware is visibly active.

1.  **Launch the App:** Start the Security Monitor UI.
2.  **Start Agent:** Click **"Start Agent"**. Wait for "System ready".
3.  **Ensure Auto-Remediation is OFF:** Check the toggle switch in the header. It should be grey.
4.  **Launch Attack:**
    *   Open a terminal.
    *   Run: `python simulations/safe_ransomware.py`
5.  **Observe:**
    *   A **Red Ransomware Window** appears, showing a progress bar encrypting files.
    *   **Agent UI:** The screen flashes **RED**. "THREAT DETECTED" appears.
    *   **Logs:** You see "CRITICAL: Ransomware detected!".
    *   **Pending Action:** An orange/red box appears in the left sidebar asking to "BLOCK PROCESS".
6.  **Resolve:**
    *   Click the **"⛔ BLOCK PROCESS"** button in the Agent UI.
    *   **Result:** The Ransomware window should instantly disappear (process killed). The Agent logs "Remediation completed".

## Scenario 2: Auto-Remediation (The "Instant Protection" Mode)

**Goal:** Show the power of automated policy enforcement.

1.  **Reset:** Close the Ransomware window if it's still open (or let the Agent kill it). Clear logs if desired.
2.  **Enable Auto-Pilot:** Toggle the **"AUTO-REMEDIATION"** switch to **ON** (Red).
3.  **Launch Attack:**
    *   Run: `python simulations/safe_ransomware.py` again.
4.  **Observe:**
    *   The Ransomware window might appear for a split second (or not at all).
    *   **Agent UI:** Flashes Red briefly.
    *   **Logs:** You see "CRITICAL: Ransomware detected!" followed immediately by "Request auto-approved" and "Process killed".
    *   **Result:** The threat is neutralized instantly without user intervention.

## Troubleshooting
- If the Ransomware window doesn't appear, ensure you have `tkinter` installed (usually included with Python).
- If the Agent doesn't detect it, wait a few seconds; the detection relies on file modification bursts (threshold: 5 files in 3 seconds).
