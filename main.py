import os
from datetime import datetime, timezone, timedelta

import functions_framework
import requests
from google.cloud import logging

GEMINI_MODEL = os.environ.get("GEMINI_MODEL", "gemini-2.0-flash")
MAX_LOG_ENTRIES = 50

DEFAULT_LOGS = {
    "security": """
2023-04-01 09:15:27.123 ERROR Failed login attempt from IP 198.51.100.123: Invalid credentials
2023-04-01 09:15:29.456 CRITICAL Multiple failed login attempts detected: Possible brute force attack
2023-04-01 09:16:00.789 ERROR Unauthorized access attempt to /admin endpoint
""",
    "dev": """
2023-04-01 10:15:27.123 ERROR Uncaught TypeError: Cannot read property 'data' of undefined at UserService.getUser
2023-04-01 10:15:29.456 ERROR API rate limit exceeded for endpoint /api/users
2023-04-01 10:16:00.789 CRITICAL Application crashed: Out of memory exception in worker thread
""",
    "database": """
2023-04-01 11:15:27.123 ERROR Failed to connect to database: Connection refused
2023-04-01 11:15:29.456 CRITICAL Database deadlock detected in transaction #45982
2023-04-01 11:16:00.789 ERROR Query performance degradation: Full table scan on users_table
""",
}

MODE_PROMPTS = {
    "security": "You are a security analyst in a SOC (Security Operations Center). Review these logs from a security perspective. First provide a clear SUMMARY of what happened. Then under ATTACK PATTERNS, identify and explain potential security threats, unauthorized access attempts, suspicious activities, and attack vectors. Finally, under IMPACT ASSESSMENT, evaluate the potential impact and provide specific, actionable recommendations to improve security posture.",

    "dev": "You are a developer analyzing application logs. Review these logs from an application development perspective. First provide a clear SUMMARY of what happened. Then under ERROR ANALYSIS, identify software bugs, performance issues, error patterns, or application failures. Finally, under IMPACT ASSESSMENT, evaluate the impact on the application and provide specific, actionable recommendations to improve code quality and application reliability.",

    "database": "You are a database administrator. Review these logs from a database management perspective. First provide a clear SUMMARY of what happened. Then under PERFORMANCE ANALYSIS, identify database connectivity issues, query problems, or performance bottlenecks. Finally, under IMPACT ASSESSMENT, evaluate the impact on database operations and provide specific, actionable recommendations to improve database health and performance.",
}


def _read_param(request_json, request_args, name, default=None):
    """Read a parameter from either the JSON body or the query string."""
    if request_json and name in request_json:
        return request_json[name]
    if request_args and name in request_args:
        return request_args[name]
    return default


def _fetch_logs(timeframe, mode):
    """Return (logs_text, entry_count) for ERROR-or-worse entries in the window."""
    logging_client = logging.Client()

    since = datetime.now(timezone.utc) - timedelta(hours=timeframe)
    log_filter = f'severity >= ERROR AND timestamp >= "{since.isoformat()}"'

    logs_text = ""
    entry_count = 0

    for entry in logging_client.list_entries(filter_=log_filter):
        entry_count += 1

        timestamp = entry.timestamp.isoformat() if getattr(entry, "timestamp", None) else "Unknown time"
        severity = getattr(entry, "severity", None) or "ERROR"
        message = str(getattr(entry, "payload", entry))

        logs_text += f"{timestamp} {severity} {message}\n"

        if entry_count >= MAX_LOG_ENTRIES:
            logs_text += "... (additional logs truncated) ...\n"
            break

    # Fall back to sample logs so the function is demoable on an empty project.
    if not logs_text.strip():
        logs_text = DEFAULT_LOGS[mode].strip()

    return logs_text, entry_count


def _build_prompt(logs_text, timeframe, mode, chat_query):
    """Analysis prompt for the chosen persona, or a direct answer to a question."""
    preamble = (
        f"You are analyzing system logs. The following logs cover a {timeframe} hour period:\n\n"
        f"{logs_text}\n\n"
    )

    if chat_query:
        return (
            preamble
            + f"A user has asked the following question about these logs:\n{chat_query}\n\n"
            "Please answer their question directly and specifically based on the log data. "
            "Provide as much relevant detail as possible from the logs to support your answer."
        )

    return preamble + MODE_PROMPTS[mode]


def _call_gemini(prompt):
    """Send the prompt to Gemini and return the generated text."""
    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        raise RuntimeError("GEMINI_API_KEY is not set")

    url = (
        "https://generativelanguage.googleapis.com/v1beta/models/"
        f"{GEMINI_MODEL}:generateContent"
    )

    response = requests.post(
        url,
        headers={"Content-Type": "application/json", "x-goog-api-key": api_key},
        json={"contents": [{"parts": [{"text": prompt}]}]},
        timeout=60,
    )

    if response.status_code != 200:
        raise RuntimeError(f"Gemini API request failed with status {response.status_code}: {response.text}")

    return response.json()["candidates"][0]["content"]["parts"][0]["text"]


@functions_framework.http
def logs_story(request):
    """HTTP Cloud Function that returns a Gemini analysis of recent error logs."""
    request_json = request.get_json(silent=True)
    request_args = request.args

    try:
        timeframe = int(_read_param(request_json, request_args, "timeframe", 1))
    except (TypeError, ValueError):
        return ("Error: timeframe must be an integer number of hours", 400)

    mode = str(_read_param(request_json, request_args, "mode", "dev")).lower()
    if mode not in MODE_PROMPTS:
        return (f"Error: Invalid mode. Available modes: {', '.join(MODE_PROMPTS)}", 400)

    chat_query = _read_param(request_json, request_args, "chat")

    try:
        logs_text, entry_count = _fetch_logs(timeframe, mode)
    except Exception as e:
        return (f"Error querying logs: {e}", 500)

    prompt = _build_prompt(logs_text, timeframe, mode, chat_query)

    try:
        story_text = _call_gemini(prompt)
    except Exception as e:
        return (f"Error processing request: {e}", 500)

    header = "LOG ANALYSIS CHAT" if chat_query else "LOG ANALYSIS"
    output = f"{header}: {mode.upper()} MODE\n"
    output += f"Time period: Past {timeframe} hour(s)\n"
    output += f"Logs analyzed: {entry_count} entries\n"
    if chat_query:
        output += f"Question: {chat_query}\n"
    output += "-" * 50 + "\n\n"
    output += story_text

    return (output, 200, {"Content-Type": "text/plain"})
