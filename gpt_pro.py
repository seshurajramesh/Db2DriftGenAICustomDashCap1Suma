import os
import json
import csv
import socket
import requests
import ibm_db
from datetime import datetime
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.templating import Jinja2Templates
from dotenv import load_dotenv

load_dotenv()

app = FastAPI(title="Multi-App DB2 AI Drift Engine")
templates = Jinja2Templates(directory="templates")

AUDIT_CSV_PATH = "db2_drift_audit.csv"

# Register node inventory mapping
NODE_INVENTORY = {
    "appa_primary": {
        "app": "App A", "role": "Primary", "name": "primary-appa-01",
        "host_env": "APPA_PRIMARY_HOST", "port_env": "APPA_PRIMARY_PORT",
        "db_env": "APPA_PRIMARY_DB", "user_env": "APPA_PRIMARY_USER", "pwd_env": "APPA_PRIMARY_PWD"
    },
    "appa_standby": {
        "app": "App A", "role": "Standby", "name": "secondary-appa-02",
        "host_env": "APPA_STANDBY_HOST", "port_env": "APPA_STANDBY_PORT",
        "db_env": "APPA_STANDBY_DB", "user_env": "APPA_STANDBY_USER", "pwd_env": "APPA_STANDBY_PWD"
    },
    "appb_primary": {
        "app": "App B", "role": "Primary", "name": "primary-appb-01",
        "host_env": "APPB_PRIMARY_HOST", "port_env": "APPB_PRIMARY_PORT",
        "db_env": "APPB_PRIMARY_DB", "user_env": "APPB_PRIMARY_USER", "pwd_env": "APPB_PRIMARY_PWD"
    },
    "appb_standby": {
        "app": "App B", "role": "Standby", "name": "secondary-appb-02",
        "host_env": "APPB_STANDBY_HOST", "port_env": "APPB_STANDBY_PORT",
        "db_env": "APPB_STANDBY_DB", "user_env": "APPB_STANDBY_USER", "pwd_env": "APPB_STANDBY_PWD"
    }
}

def log_drift_to_csv(scanned_nodes: list, ai_result: dict):
    """Appends scan execution metadata and drift results to a persistent CSV audit log."""
    file_exists = os.path.isfile(AUDIT_CSV_PATH)

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    nodes_str = ", ".join(scanned_nodes)
    drift_status = ai_result.get("driftStatus", "UNKNOWN")
    overall_risk = ai_result.get("overallRisk", "None")

    items = ai_result.get("items", [])
    drifted_params = "; ".join([item.get("parameter", "") for item in items]) if items else "None"

    requires_cr = "YES" if drift_status == "DRIFT" else "NO"

    fieldnames = [
        "Timestamp",
        "ScannedNodes",
        "DriftStatus",
        "OverallRisk",
        "DriftedParameters",
        "RequiresServiceNowCR"
    ]

    try:
        with open(AUDIT_CSV_PATH, mode="a", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            if not file_exists:
                writer.writeheader()

            writer.writerow({
                "Timestamp": timestamp,
                "ScannedNodes": nodes_str,
                "DriftStatus": drift_status,
                "OverallRisk": overall_risk,
                "DriftedParameters": drifted_params,
                "RequiresServiceNowCR": requires_cr
            })
        print(f"[AUDIT LOGGED] Recorded run to {AUDIT_CSV_PATH}")
    except Exception as ex:
        print(f"[AUDIT ERROR] Failed to write CSV log: {ex}")

def check_tcp_port(host: str, port: int, timeout=2) -> bool:
    """Verifies TCP network connectivity to the DB2 instance."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False

def fetch_db2_raw_config(host: str, port: str, db: str, user: str, pwd: str) -> dict:
    """Extracts raw DB2 database (DBCFG) and database manager (DBMCFG) configuration parameters."""
    conn_str = f"DATABASE={db};HOSTNAME={host};PORT={port};PROTOCOL=TCPIP;UID={user};PWD={pwd};"
    conn = ibm_db.connect(conn_str, "", "")

    db_cfg_params = (
        'logfilsiz', 'logprimary', 'logsecond', 'buffpage', 'sortheap', 'hadr_timeout', 'stmtheap',
        'maxappls', 'autorestart', 'archretrydelay', 'num_db_backups', 'numarchretry', 'connect_proc'
    )

    dbm_cfg_params = (
        'diaglevel', 'notifylevel', 'authentication', 'catalog_noauth', 'max_connections',
        'max_coordagents', 'srvcon_auth', 'trust_allclnts', 'trust_clntauth', 'audit_buf_sz'
    )

    db_cfg = {}
    dbm_cfg = {}

    db_sql = f"""
        SELECT name, value FROM sysibmadm.dbcfg
        WHERE name IN ({','.join([f"'{p}'" for p in db_cfg_params])})
    """
    stmt_db = ibm_db.exec_immediate(conn, db_sql)
    row = ibm_db.fetch_assoc(stmt_db)
    while row:
        val = row["VALUE"].strip() if row["VALUE"] is not None else None
        db_cfg[row["NAME"].strip().lower()] = val
        row = ibm_db.fetch_assoc(stmt_db)

    dbm_sql = f"""
        SELECT name, value FROM sysibmadm.dbmcfg
        WHERE name IN ({','.join([f"'{p}'" for p in dbm_cfg_params])})
    """
    stmt_dbm = ibm_db.exec_immediate(conn, dbm_sql)
    row = ibm_db.fetch_assoc(stmt_dbm)
    while row:
        val = row["VALUE"].strip() if row["VALUE"] is not None else None
        dbm_cfg[row["NAME"].strip().lower()] = val
        row = ibm_db.fetch_assoc(stmt_dbm)

    ibm_db.close(conn)

    return {
        "db_cfg": db_cfg,
        "dbm_cfg": dbm_cfg
    }

def analyze_payload_with_ai(scanned_payload: dict) -> dict:
    """Submits multi-node raw payloads to Azure AI Foundry DeepSeek-V3 using a junior DBA mentor persona."""
    endpoint = os.getenv("FOUNDRY_ENDPOINT", "").rstrip('/')
    deployment = os.getenv("FOUNDRY_DEPLOYMENT", "")
    api_key = os.getenv("FOUNDRY_API_KEY", "")

    TARGET_DATABASE = "KYDB2"
    APP_NAME = "Enterprise Application"
    APP_CRITICALITY = "Tier 1"
    MAINTENANCE_WINDOW_START = "00:00"
    MAINTENANCE_WINDOW_END = "04:00"
    APP_TEAM_GROUP = "AppOpsTeam"
    DBA_TEAM_GROUP = "DB2OPS"

    if "appa_primary" in scanned_payload:
        TARGET_DATABASE = scanned_payload['appa_primary'].get('database', 'KYDB2A')
        APP_NAME = scanned_payload['appa_primary'].get('appName', 'App A')
        APP_CRITICALITY = "Tier 1"
        MAINTENANCE_WINDOW_START = "00:00"
        MAINTENANCE_WINDOW_END = "04:00"
        APP_TEAM_GROUP = "PaymentOPS"
        DBA_TEAM_GROUP = "DB2OPS"
    elif "appb_primary" in scanned_payload:
        TARGET_DATABASE = scanned_payload['appb_primary'].get('database', 'KYDB2B')
        APP_NAME = scanned_payload['appb_primary'].get('appName', 'App B')
        APP_CRITICALITY = "Tier 2"
        MAINTENANCE_WINDOW_START = "02:00"
        MAINTENANCE_WINDOW_END = "06:00"
        APP_TEAM_GROUP = "InsuranceOPS"
        DBA_TEAM_GROUP = "DB2OPS"

    # CHANGE 1: Switched to Azure AI Model Inference API endpoint for DeepSeek models
    url = f"{endpoint}/openai/responses?api-version=2025-04-01-preview"

    system_prompt = f"""
    You are an expert DB2 HADR advisor, advanced Db2 LUW DBA, mentor, and a ServiceNow Change Management expert.
    Your audience is a junior DBA who is new to DB2, and you are providing them with actionable insights and a complete, ready-to-deploy Change Request.
    Never address a DBA/engineer as junior anywhere in this, eventhough they are junior, dont make awkard to them by mentioning junior or any word related.
    Also make sure there are no Spelling or Grammatical errors while structuring steps and sentences.

    Input Data Provided by Automation System:
    - Raw JSON payloads for Database (db_cfg) and Database Manager (dbm_cfg) configurations.
    - App Name: {APP_NAME}
    - App Criticality: {APP_CRITICALITY}
    - Maintenance Window Start: {MAINTENANCE_WINDOW_START}
    - Maintenance Window End: {MAINTENANCE_WINDOW_END}
    - App Team Support Group: {APP_TEAM_GROUP}
    - DBA Support Group: {DBA_TEAM_GROUP}
    - Target Database / CI: {TARGET_DATABASE}

    Core Rules & Logic:
    1. SOURCE OF TRUTH: Always treat the PRIMARY node as the source of truth. Any remediation must align the STANDBY node to match the PRIMARY.
    2. AUTOMATIC VALUES: DB2 parameters often have an "AUTOMATIC" flag (e.g., "8192 AUTOMATIC" or simply "AUTOMATIC"). If BOTH the Primary and Standby evaluate to AUTOMATIC, treat them as IN SYNC (NO_DRIFT), regardless of any differing underlying calculated numerical values. Do not confuse them. If remediating a parameter to automatic, explicitly include the "AUTOMATIC" keyword in the db2 command.
    3. REMEDIATION COMMANDS: Always include the database name in the commands (e.g., `db2 update db cfg for {TARGET_DATABASE} using <PARAM> <VAL>`).
    4. BACKOUT VALUES: The backout plan must ALWAYS revert the parameter to the Standby's existing (old) value.

    Tasks & Requirements:
    1. Evaluate Drift: Summarize the drift status clearly as either "DRIFT" or "NO_DRIFT".
    2. If DRIFT exists:
       - Mentor Summary: Explain the business and technical risk of the drift in simple, beginner-friendly terms.
       - Classification: Analyze each drifted parameter to determine if the update is dynamic (IMMEDIATE) or requires a restart (DEFERRED). If ANY parameter is DEFERRED, set `requiresOutage` to true.
       - Remediation: Provide step-by-step commands using exact DB2 syntax. Include `IMMEDIATE` or `DEFERRED`.
    3. Generate the ServiceNow CR & CTASKs (ONLY if DRIFT exists):
       - Timeline Calculation: Strictly Calculate the total time duration of the provided Maintenance Window. Allocate the first 75% of the time window to the Implementation Plan, and the final 25% of the time window to the Backout Plan and gets followed in the both Implementation steps and backout steps.
       - Conditional Execution Skeleton: Use the skeleton below.
         * IF DEFERRED (Outage Required): Include ALL steps (App Stop, DB Restart, App Start).
         * IF IMMEDIATE (No Outage): REMOVE Step 2, Step 4, and Step 6 from the Implementation Plan, and REMOVE the Stop/Restart/Start steps from the Backout Plan. The App Team only performs Pre/Post checks. But dont forget to attach the immediate keyword for the immediate keyword and attach to schema for immediate loading of that parameter.
       - Mapping: Generate exact CTASKs for the App Team and DBA Team based on the steps required.
    4. If NO_DRIFT:
       - Confirm nodes are in sync and provide HADR monitoring best practices. Leave CR fields empty.

    Output Schema Constraints:
    STRICTLY return a valid JSON object matching this structure. Ensure all strings are properly escaped.

    {{
      "driftStatus": "DRIFT | NO_DRIFT",
      "overallRisk": "High | Medium | Low | None",
      "mentorSummary": "Clear, encouraging explanation tailored for a junior DBA.",
      "monitoringAdvice": "If NO_DRIFT, provide best practices here. Otherwise, leave empty.",
      "topDifferences": [
        {{
          "parameter": "parameter_name",
          "impactArea": "Performance | Recovery Time | Failover Reliability",
          "explanation": "Beginner-friendly explanation of why this difference matters"
        }}
      ],
      "items": [
        {{
          "parameter": "db_cfg.param OR dbm_cfg.param",
          "updateType": "IMMEDIATE | DEFERRED",
          "primaryValue": "val1",
          "standbyValue": "val2 (old value)",
          "risk": "High | Medium | Low",
          "impact": "Simple explanation of impact",
          "remediation": "Exact db2 update command for the Standby node"
        }}
      ],
      "validationCheck": "Step-by-step commands to validate sync post-remediation.",
      "servicenowCR": {{
        "coreFields": {{
          "shortDescription": "Align DB2 Parameters for {APP_NAME} ({TARGET_DATABASE})",
          "description": "Detailed description of the drift and required alignment.",
          "category": "Database",
          "ci": "{TARGET_DATABASE}",
          "risk": "Calculated based on App Criticality and Update Type",
          "assignmentGroup": "{DBA_TEAM_GROUP}",
          "requiresOutage": true and also mention the risk calculated from the "risk": "Calculated based on App Criticality and Update Type", for better understanding ..
        }},
        "implementationPlan": "Step 1: DB2 & Application Pre-Checks... and strictly follow the steps with calclauted timeline . ex: step1,step 2 ..",
        "backoutPlan": "Step 1: Application Stop... and strictly follow the steps with calclauted timeline. ex: step1,step 2 ..",
        "testPlan": "Pre-test and Post-test notes. Also generate the deatiled staeps what exactly to do or run according to plan including for both after implementation and backout if required ",
        "ctasks": [
          {{
            "taskName": "DBA Execution Tasks",
            "assignmentGroup": "{DBA_TEAM_GROUP}",
            "expectedState": "Work in Progress"
          }},
          {{
            "taskName": "Application Team Execution Tasks",
            "assignmentGroup": "{APP_TEAM_GROUP}",
            "expectedState": "Open"
          }}
        ]
      }}
    }}
    """

    headers = {
    "api-key": api_key,
    "Content-Type": "application/json"
}

    body = {
        # This MUST be your deployment name
        "model": deployment,

        "input": [
            {
                "role": "system",
                "content": [
                    {
                        "type": "input_text",
                        "text": system_prompt
                    }
                ]
            },
            {
                "role": "user",
                "content": [
                    {
                        "type": "input_text",
                        "text": json.dumps(scanned_payload, indent=2)
                    }
                ]
            }
        ]
    }

    resp = requests.post(url, headers=headers, json=body)
    resp.raise_for_status()

    data = resp.json()


    content = None

    for item in data.get("output", []):
        if item.get("type") == "message":
            for part in item.get("content", []):
                if part.get("type") == "output_text":
                    content = part["text"]
                    break
        if content:
            break

    if content is None:
        raise ValueError("No assistant response found.")

    result = json.loads(content)

    return result

@app.get("/", response_class=HTMLResponse)
async def serve_dashboard(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

@app.get("/api/node-status")
async def get_node_statuses():
    """Returns real-time TCP port connectivity for registered nodes."""
    status_report = {}
    for node_key, meta in NODE_INVENTORY.items():
        host = os.getenv(meta["host_env"], "127.0.0.1")
        port = int(os.getenv(meta["port_env"], "50000"))
        is_online = check_tcp_port(host, port)
        status_report[node_key] = {
            "name": meta["name"],
            "app": meta["app"],
            "role": meta["role"],
            "host": host,
            "port": port,
            "status": "online" if is_online else "offline"
        }
    return {"nodes": status_report}

@app.post("/api/run-drift-check")
async def run_drift_check(request: Request):
    """Fetches configs for selected nodes, sends them to AI, and logs run to CSV."""
    try:
        body = await request.json()
        selected_node_keys = body.get("nodes", [])

        if not selected_node_keys:
            return {"status": "error", "message": "No target nodes selected."}

        collected_data = {}
        for key in selected_node_keys:
            if key in NODE_INVENTORY:
                meta = NODE_INVENTORY[key]
                host = os.getenv(meta["host_env"])
                port = os.getenv(meta["port_env"])
                db = os.getenv(meta["db_env"])
                user = os.getenv(meta["user_env"])
                pwd = os.getenv(meta["pwd_env"])

                try:
                    raw_cfg = fetch_db2_raw_config(host, port, db, user, pwd)
                    collected_data[key] = {
                        "appName": meta["app"],
                        "role": meta["role"],
                        "nodeName": meta["name"],
                        "database": db,
                        "config": raw_cfg
                    }
                except Exception as ex:
                    collected_data[key] = {
                        "appName": meta["app"],
                        "role": meta["role"],
                        "error": f"Failed to fetch config: {str(ex)}"
                    }

        ai_analysis = analyze_payload_with_ai(collected_data)

        # Log execution to CSV audit file
        log_drift_to_csv(selected_node_keys, ai_analysis)

        return {"status": "success", "data": ai_analysis}

    except Exception as ex:
        return {"status": "error", "message": str(ex)}

@app.get("/api/download-audit-log")
async def download_audit_log():
    """Allows downloading the persistent CSV audit file."""
    if os.path.exists(AUDIT_CSV_PATH):
        return FileResponse(
            path=AUDIT_CSV_PATH,
            filename=f"db2_drift_audit_{datetime.now().strftime('%Y%m%d')}.csv",
            media_type="text/csv"
        )
    return {"status": "error", "message": "No audit log records available yet."}
