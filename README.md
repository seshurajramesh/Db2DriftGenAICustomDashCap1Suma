# Enterprise DB2 LUW AI Configuration Drift Engine & ServiceNow Change Automation

![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-0.110%2B-009688?logo=fastapi&logoColor=white)
![DB2](https://img.shields.io/badge/DB2-HADR-FF6B35)
![Azure AI](https://img.shields.io/badge/Azure%20AI-Foundry-0078D4)

An enterprise-grade automation system for IBM DB2 LUW HADR environments. This project connects to primary and standby DB2 nodes, inspects raw database configuration, evaluates drift, checks HADR health, and uses Azure AI Foundry to generate risk explanations, exact DB2 remediation commands, and ServiceNow change artifacts.

## What the project does

This solution helps database and platform teams answer critical operational questions such as:

- Are the primary and standby DB2 nodes still in sync?
- Which configuration parameters have drifted?
- Is HADR healthy and connected?
- What exact DB2 commands should be used to restore alignment?
- Should a ServiceNow change request be raised for remediation?

The application is built around a FastAPI backend, a Bootstrap-based dashboard, and Azure AI model inference. It reads raw DB2 configuration via the native `ibm_db` driver, compares primary and standby state, and produces structured JSON output for operational decision support.

## Why the project is useful

### Key features

- Direct raw DB2 parameter inspection from `sysibmadm.dbcfg` and `sysibmadm.dbmcfg`
- HADR health validation across primary and standby nodes
- Automatic detection of DB2 `AUTOMATIC` values to avoid false drift alerts
- AI-generated risk summaries and best-practice guidance
- Top-difference analysis categorized by performance, recovery time, and failover reliability
- Auto-generated ServiceNow change request content and CTASKs
- Persistent audit logging in CSV format for review and traceability
- Browser-based operational dashboard for quick DBA review

### Benefits

- Reduces manual DB2 diffing and validation effort
- Helps catch drift before failover or recovery issues
- Speeds up remediation planning for critical HADR environments
- Improves consistency between DBA operations and change management workflow

## Architecture and workflow

```text
App Server: FastAPI UI + API
    │
    ├── Checks node reachability (TCP / DB2 listener)
    ├── Queries DB2 database and manager configuration
    ├── Reads HADR status and health
    ├── Sends raw payload to Azure AI Foundry
    ├── Evaluates drift and remediation risk
    └── Logs output to db2_drift_audit.csv

Primary/Standby DB2 Nodes
    │
    └── Raw DBCFG / DBMCFG / HADR health payload

Azure AI Foundry
    │
    ├── Drift analysis
    ├── Operational mentoring summary
    ├── ServiceNow CR and CTASK generation
    └── Remediation guidance
```

## Repository structure

- [app.py](app.py): FastAPI backend, DB2 queries, HADR checks, AI orchestration, and API routes
- [templates/index.html](templates/index.html): browser-based dashboard and operational console
- [requirements.txt](requirements.txt): Python dependencies
- [db2_drift_audit.csv](db2_drift_audit.csv): generated CSV audit log
- [deepseek.py](deepseek.py): alternate implementation path for the AI drift workflow
- [gpt_pro.py](gpt_pro.py): additional AI-driven drift logic variant

## Prerequisites

Before running the application, ensure the following are available:

- Python 3.10 or later
- Access to DB2 primary and standby hosts with valid credentials
- IBM DB2 client libraries available in the runtime environment
- Azure AI Foundry endpoint, deployment name, and API key
- Network connectivity from the app server to the DB2 listener ports
- A DB2 HADR environment or a non-production equivalent for validation

## Getting started

### 1. Clone the repository

```bash
git clone <your-repository-url>
cd Db2DriftGenAICustomDashCap1Suma
```

### 2. Create and activate a virtual environment

```bash
python -m venv .venv

# Windows
.venv\Scripts\activate

# macOS / Linux
source .venv/bin/activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Configure environment variables

Create a `.env` file in the project root with the following values:

```env
FOUNDRY_ENDPOINT=https://<your-ai-endpoint>
FOUNDRY_DEPLOYMENT=<deployment-name>
FOUNDRY_API_KEY=<api-key>

APPA_PRIMARY_HOST=10.x.x.x
APPA_PRIMARY_PORT=50000
APPA_PRIMARY_DB=KYDB2A
APPA_PRIMARY_USER=db2inst1
APPA_PRIMARY_PWD=your-password

APPA_STANDBY_HOST=10.x.x.x
APPA_STANDBY_PORT=50000
APPA_STANDBY_DB=KYDB2A
APPA_STANDBY_USER=db2inst1
APPA_STANDBY_PWD=your-password

APPB_PRIMARY_HOST=10.x.x.x
APPB_PRIMARY_PORT=50000
APPB_PRIMARY_DB=KYDB2B
APPB_PRIMARY_USER=db2inst1
APPB_PRIMARY_PWD=your-password

APPB_STANDBY_HOST=10.x.x.x
APPB_STANDBY_PORT=50000
APPB_STANDBY_DB=KYDB2B
APPB_STANDBY_USER=db2inst1
APPB_STANDBY_PWD=your-password
```

> The application reads these values at runtime, so the exact DB2 hosts, ports, and credentials must match your environment.

### 5. Start the application

```bash
uvicorn app:app --host 0.0.0.0 --port 8000 --reload
```

Then open the dashboard in your browser:

```text
http://localhost:8000
```

### 6. Run a drift check

1. Open the dashboard.
2. Select the relevant DB2 node group.
3. Click the analysis action.
4. Review the AI-generated drift summary, HADR health, risk rating, and remediation guidance.
5. Download the CSV audit file if needed.

### API usage example

```bash
curl -X POST "http://localhost:8000/api/run-drift-check" \
  -H "Content-Type: application/json" \
  -d '{"nodes":["appa_primary","appa_standby"]}'
```

This returns a JSON payload containing the drift status, HADR state, risk summary, remediation commands, and ServiceNow change details when applicable.

## Azure AI and deployment notes

This project expects an Azure AI Foundry model deployment that supports chat-completion style inference. The application calls the configured endpoint using the environment variables above.

Typical deployment flow:

1. Create or reuse an Azure AI Foundry resource.
2. Deploy a supported model such as DeepSeek or a compatible Azure-hosted model.
3. Copy the endpoint URL, deployment name, and API key into the `.env` file.
4. Start the app and validate connectivity against the DB2 environment.

## DB2 HADR setup overview

The project is designed for IBM DB2 HADR environments on RHEL-style hosts. A standard production pattern is:

- Primary node: active write node
- Standby node: replicated secondary node
- DB2 listener on TCP port 50000
- HADR communication on service port 60000
- Automatic or manual failover based on operational policy

When used in live operations, the primary node is treated as the source of truth during configuration comparison.

## Operational safety

- Always validate the primary and standby node pairing before making any configuration change.
- Treat HADR state as a critical signal; poor connectivity or replication mismatch should be reviewed before remediation.
- Validate any DB2 remediation commands in a lower environment before production use.
- Use the CSV audit log as a traceable change record for compliance and troubleshooting.

## Where users can get help

For support and operational reference, use the following:

- [app.py](app.py) for backend logic and API behavior
- [templates/index.html](templates/index.html) for the dashboard UI
- [db2_drift_audit.csv](db2_drift_audit.csv) for audit history
- DB2 server logs and HADR validation commands for runtime troubleshooting
- GitHub issues or repository discussions for bugs and feature requests

## Maintainers and contributions

This project is intended for DBA, platform engineering, and operations teams responsible for DB2 availability and configuration governance.

### Contribution guidelines

- Keep changes focused and easy to validate.
- Prefer production-safe, operationally correct updates.
- Test DB2-related changes in a non-production environment first.
- Document environment variables and operational assumptions clearly.
- Open an issue before introducing major architecture or workflow changes.

Pull requests should describe the problem, the fix, and the validation performed.

## License

This repository does not currently include a license file. If you plan to distribute or publish the project publicly, add a separate LICENSE file before release.

## Summary

This project automates DB2 HADR configuration drift analysis, applies AI-powered reasoning to operational risk, and supports faster DBA remediation planning. It is best suited for teams running critical IBM DB2 environments that require governance, visibility, and rapid change decision support.
