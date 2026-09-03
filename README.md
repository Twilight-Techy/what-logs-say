# What Logs Say

A Google Cloud Function that reads your recent error logs and has Gemini explain what actually
happened, as a security analyst, a developer, or a DBA, depending on who's asking.

Log volume is the problem: by the time an incident is worth investigating, there is far more
log data than anyone wants to read. This pulls the `ERROR`-and-worse entries from a time window
and returns a narrative with a summary, an analysis, and concrete recommendations.

---

## Three readers, three readings

The same logs mean different things to different people, so the persona is a parameter:

| `mode` | Reads as | Analysis section |
|---|---|---|
| `security` | SOC analyst | **ATTACK PATTERNS**: threats, unauthorized access, attack vectors |
| `dev` *(default)* | Application developer | **ERROR ANALYSIS**: bugs, error patterns, failures |
| `database` | DBA | **PERFORMANCE ANALYSIS**: connectivity, query problems, bottlenecks |

Each ends with an **IMPACT ASSESSMENT** and actionable recommendations.

## Asking a specific question

Pass `chat` and the function answers that question against the logs instead of producing the
standard analysis:

```bash
curl "$FUNCTION_URL?mode=security&timeframe=6&chat=Which+IPs+attempted+the+most+logins"
```

## Parameters

Accepted in either the query string or a JSON body.

| Parameter | Default | Meaning |
|---|---|---|
| `timeframe` | `1` | How many hours back to read |
| `mode` | `dev` | `security`, `dev`, or `database` |
| `chat` | none | A specific question; overrides the standard analysis |

Reading is capped at 50 entries per request to keep token cost bounded, and the response says
how many were analyzed. On a project with no matching logs, a small built-in sample is used so
the function is still demoable.

## Deploying

```bash
gcloud functions deploy logs-story \
  --gen2 --runtime python311 \
  --entry-point logs_story \
  --trigger-http \
  --set-env-vars GEMINI_API_KEY=your-key
```

The runtime service account needs the **Logs Viewer** role. `GEMINI_MODEL` optionally overrides
the default (`gemini-2.0-flash`).

## Generating test logs

An empty project produces nothing to analyze, so `generate_logs.py` writes realistic synthetic
logs to Cloud Logging, including a staged intrusion sequence that escalates from failed logins
to a successful breach, which is what makes `security` mode worth reading.

```bash
python generate_logs.py
```

## Layout

```
main.py            the Cloud Function: log fetch, prompt construction, Gemini call
generate_logs.py   synthetic log generator for testing
```
