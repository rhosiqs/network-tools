# Network Connection Test App

A user-friendly, modern web application for monitoring your network connection status. This tool automatically tests various network points (Loopback, Gateway, ISP DNS, Google DNS) and reports status and latency in real-time.

## Features

-   **Dashboard Interface**: Visual status indicators for all network checks.
-   **Real-time Monitoring**: Automatically refreshes status every few seconds.
-   **Failure Detection**: Instantly alerts you if any check fails.
-   **Continuous Monitoring Mode**: If a failure occurs, the system switches to rapid monitoring until stability is restored.
-   **CSV Logging**: Automatically saves connection logs to `C:\Users\huang\OneDrive\Code\Internet Test` (or local folder if unavailable).

## How to Use

1.  **Start the App**:
    -   Double-click the **`run_app.bat`** file in this folder.
    -   The script will automatically set up the environment and open the dashboard in your browser.

2.  **Monitoring**:
    -   The app starts monitoring immediately.
    -   Status cards will show green (OK) or red (FAIL) along with latency.
    -   You can manually Stop/Start monitoring using the buttons at the top.

3.  **Logs**:
    -   Recent activity is shown at the bottom of the page.
    -   Full logs are saved as CSV files when you close the app or stop monitoring.

## Technical Details

-   **Backend**: Python (Flask)
-   **Frontend**: HTML, CSS (Dark Mode), JavaScript
-   **Requirements**: Python 3.x

## Troubleshooting

-   If the browser doesn't open, manually go to `http://127.0.0.1:5000`.
-   If you see "Offline" immediately, ensure the backend window (command prompt) is running.
