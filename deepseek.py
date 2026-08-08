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

def log_drift_to_csv(scanned_nodes: list, ai_result: dict, hadr_summary: str):
    """Appends scan execution metadata, HADR connection status, and drift results to a persistent CSV audit log."""
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
        "HADRConnectionStatus",
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
                "HADRConnectionStatus": hadr_summary,
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
    """Extracts raw DB2 database (DBCFG), database manager (DBMCFG), and live HADR operational health."""
    conn_str = f"DATABASE={db};HOSTNAME={host};PORT={port};PROTOCOL=TCPIP;UID={user};PWD={pwd};"
    
    try:
        conn = ibm_db.connect(conn_str, "", "")
    except Exception as ex:
        return {
            "error": f"Failed to connect to DB2 at {host}:{port}/{db}: {str(ex)}",
            "db_cfg": {}, "dbm_cfg": {},
            "hadr_health": {"hadr_state": "DISCONNECTED", "hadr_connect_status": "NO_CONNECTION"}
        }

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
    hadr_health = {}

    # 1. Query Database Configuration
    db_sql = f"""
        SELECT name, value FROM sysibmadm.dbcfg
        WHERE name IN ({','.join([f"'{p}'" for p in db_cfg_params])})
    """
    try:
        stmt_db = ibm_db.exec_immediate(conn, db_sql)
        row = ibm_db.fetch_assoc(stmt_db)
        while row:
            val = row["VALUE"].strip() if row["VALUE"] is not None else None
            db_cfg[row["NAME"].strip().lower()] = val
            row = ibm_db.fetch_assoc(stmt_db)
    except Exception as ex:
        db_cfg = {"error": str(ex)}

    # 2. Query Database Manager Configuration
    dbm_sql = f"""
        SELECT name, value FROM sysibmadm.dbmcfg
        WHERE name IN ({','.join([f"'{p}'" for p in dbm_cfg_params])})
    """
    try:
        stmt_dbm = ibm_db.exec_immediate(conn, dbm_sql)
        row = ibm_db.fetch_assoc(stmt_dbm)
        while row:
            val = row["VALUE"].strip() if row["VALUE"] is not None else None
            dbm_cfg[row["NAME"].strip().lower()] = val
            row = ibm_db.fetch_assoc(stmt_dbm)
    except Exception as ex:
        dbm_cfg = {"error": str(ex)}

    # 3. Query HADR State (With Fallback from HADR_HEALTH to MON_HADR)
    hadr_health = fetch_hadr_status_safe(conn, db)

    ibm_db.close(conn)

    return {
        "db_cfg": db_cfg,
        "dbm_cfg": dbm_cfg,
        "hadr_health": hadr_health
    }

def fetch_hadr_status_safe(conn, db_name: str) -> dict:
    """Queries HADR health with fallback across multiple DB2 administrative views."""
    # Attempt 1: Try MON_HADR
    sql_mon_hadr = """
        SELECT HADR_ROLE, HADR_STATE, HADR_CONNECT_STATUS, HADR_SYNCMODE FROM TABLE(SYSPROC.MON_GET_HADR(NULL))"""
    try:
        stmt = ibm_db.exec_immediate(conn, sql_mon_hadr)
        row = ibm_db.fetch_assoc(stmt)
        if row:
            return {
                "hadr_role": str(row.get("HADR_ROLE", "")).strip(),
                "hadr_state": str(row.get("HADR_STATE", "")).strip(),
                "hadr_connect_status": str(row.get("HADR_CONNECT_STATUS", "")).strip(),
                "hadr_syncmode": str(row.get("HADR_SYNCMODE", "")).strip(),
                "view_used": "MON_HADR"
            }
    except Exception:
        pass  # Fall through to next view

    # Attempt 2: Try HADR_HEALTH
    sql_hadr_health = """
        SELECT HADR_ROLE, HADR_STATE, HADR_CONNECT_STATUS, HADR_SYNCMODE
        FROM SYSIBMADM.HADR_HEALTH
    """
    try:
        stmt = ibm_db.exec_immediate(conn, sql_hadr_health)
        row = ibm_db.fetch_assoc(stmt)
        if row:
            return {
                "hadr_role": str(row.get("HADR_ROLE", "")).strip(),
                "hadr_state": str(row.get("HADR_STATE", "")).strip(),
                "hadr_connect_status": str(row.get("HADR_CONNECT_STATUS", "")).strip(),
                "hadr_syncmode": str(row.get("HADR_SYNCMODE", "")).strip(),
                "view_used": "HADR_HEALTH"
            }
    except Exception:
        pass

    # Attempt 3: If no view exists or HADR is inactive
    return {
        "hadr_role": "UNKNOWN",
        "hadr_state": "VIEW_MISSING_OR_INACTIVE",
        "hadr_connect_status": "UNCONFIGURED_OR_STOPPED",
        "diagnostic_note": f"HADR administrative views not available or HADR not started on database {db_name}. Run 'db2pd -db {db_name} -hadr' directly on host."
    }

def analyze_payload_with_ai(scanned_payload: dict) -> dict:
    """Submits multi-node raw payloads to Azure AI Foundry DeepSeek-V3 using a mentor persona."""
    endpoint = os.getenv("FOUNDRY_ENDPOINT", "").rstrip('/')
    deployment = os.getenv("FOUNDRY_DEPLOYMENT", "")
    api_key = os.getenv("FOUNDRY_API_KEY", "")


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

    url = f"{endpoint}/models/chat/completions?api-version=2024-05-01-preview"

    system_prompt = f"""
    You are an expert DB2 HADR advisor, advanced Db2 LUW DBA, mentor, and a ServiceNow Change Management expert.
    Your audience is a DBA, and you are providing them with actionable insights and a complete, ready-to-deploy Change Request.
    Do not use terms like 'junior' in your response output. Ensure there are no spelling or grammatical errors.

    Input Data Provided by Automation System:
    - Raw JSON payloads for Database (db_cfg), Database Manager (dbm_cfg), and HADR Health (hadr_health) states.
    - App Name: {APP_NAME}
    - App Criticality: {APP_CRITICALITY}
    - Maintenance Window Start: {MAINTENANCE_WINDOW_START}
    - Maintenance Window End: {MAINTENANCE_WINDOW_END}
    - App Team Support Group: {APP_TEAM_GROUP}
    - DBA Support Group: {DBA_TEAM_GROUP}
    - Target Database / CI: {TARGET_DATABASE}

    Core Rules & Logic:
    1. HADR STATE VALIDATION & OUTAGE IMPACT:
       - Inspect the 'hadr_health' object across nodes.
       - Expected Healthy HADR State: HADR_STATE = 'PEER' and HADR_CONNECT_STATUS = 'CONNECTED'.
       - If HADR_STATE is NOT 'PEER' (e.g., 'REMOTE_CATCHUP_PENDING', 'DISCONNECTED', or 'STANDBY_RECOVERY_FAILED'):
         * Set `hadrHealthy` to false.
         * Populate `hadrWarning` with a clear explanation of what to do (e.g., "HADR replication is currently in state X. Verify network connectivity and inspect HADR recovery using `db2pd -db {TARGET_DATABASE} -hadr` before executing remediation.").
         * Force `overallRisk` to "High".
    2. SOURCE OF TRUTH: Always treat the PRIMARY node as the source of truth. Any remediation must align the STANDBY node to match the PRIMARY.
    3. AUTOMATIC VALUES: DB2 parameters often have an "AUTOMATIC" flag (e.g., "8192 AUTOMATIC" or "AUTOMATIC"). If BOTH the Primary and Standby evaluate to AUTOMATIC, treat them as IN SYNC (NO_DRIFT), regardless of any differing calculated numerical values.
    4. REMEDIATION COMMANDS: Always include the database name in the commands (e.g., `db2 update db cfg for {TARGET_DATABASE} using <PARAM> <VAL>`).
    5. BACKOUT VALUES: The backout plan must ALWAYS revert the parameter to the Standby's existing (old) value.

    Tasks & Requirements:
    1. Evaluate Drift & Health: Summarize the drift status clearly as either "DRIFT" or "NO_DRIFT".
    2. If DRIFT or HADR Unhealthy exists:
       - Mentor Summary: Explain business/technical risks in simple, actionable terms.
       - Classification: Determine if updates are IMMEDIATE or DEFERRED.
       - Remediation: Provide step-by-step commands using exact DB2 syntax.
    3. Generate ServiceNow CR & CTASKs (ONLY if DRIFT exists):
       - Allocate 75% of the maintenance window to Implementation, and 25% to Backout.
       - Generate CTASKs for App Team and DBA Team.
    4. If NO_DRIFT and HADR is healthy:
       - Confirm nodes are in sync and provide HADR monitoring best practices. Leave CR fields empty.

    Output Schema Constraints:
    STRICTLY return a valid JSON object matching this structure. Ensure all strings are properly escaped.

    {{
      "driftStatus": "DRIFT | NO_DRIFT",
      "overallRisk": "High | Medium | Low | None",
      "hadrHealthy": true | false,
      "hadrSummary": "Short text of HADR State across nodes (e.g. PEER / CONNECTED or REMOTE_CATCHUP_PENDING / DISCONNECTED)",
      "hadrWarning": "Warning and action plan if HADR is not PEER/CONNECTED, otherwise empty",
      "mentorSummary": "Clear, encouraging explanation.",
      "monitoringAdvice": "If NO_DRIFT, provide best practices here. Otherwise, leave empty.",
      "topDifferences": [
        {{
          "parameter": "parameter_name",
          "impactArea": "Performance | Recovery Time | Failover Reliability",
          "explanation": "Explanation of why this difference matters"
        }}
      ],
      "items": [
        {{
          "application": "{APP_NAME}",
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
          "description": "Detailed description of drift and required alignment.",
          "category": "Database",
          "ci": "{TARGET_DATABASE}",
          "risk": "Calculated based on App Criticality and Update Type",
          "assignmentGroup": "{DBA_TEAM_GROUP}",
          "requiresOutage": true
        }},
        "implementationPlan": "Step-by-step timeline execution plan...",
        "backoutPlan": "Step-by-step backout plan...",
        "testPlan": "Pre-test and post-test verification steps.",
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

    body = {
        "model": deployment,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": json.dumps(scanned_payload, indent=2)}
        ],
        "response_format": {"type": "json_object"},
        "temperature": 0.1
    }

    headers = {
        "Authorization": f"Bearer {api_key}",
        "api-key": api_key,
        "Content-Type": "application/json"
    }

    resp = requests.post(url, json=body, headers=headers, timeout=45)
    resp.raise_for_status()

    content = resp.json()["choices"][0]["message"]["content"]
    if content.startswith("```json"):
        content = content.replace("```json", "", 1).rstrip("` \n")
    elif content.startswith("```"):
        content = content.replace("```", "", 1).rstrip("` \n")

    return json.loads(content)

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
    """Fetches configs & HADR state, sends to AI, and logs run to CSV."""
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

        # Extract HADR summary for CSV logging
        hadr_summary = ai_analysis.get("hadrSummary", "PEER / CONNECTED")

        # Log execution to CSV audit file
        log_drift_to_csv(selected_node_keys, ai_analysis, hadr_summary)

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
