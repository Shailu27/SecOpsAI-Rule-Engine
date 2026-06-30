# SecOpsAI Rule Engine

A modular **Rule-Based Detection Engine** developed for the **Sec-Ops-AI** cybersecurity platform.

The Rule Engine performs **baseline threat detection** using predefined security rules before forwarding unknown traffic to the Machine Learning Detection Engine.

---

## Features

- ✅ Brute Force Detection
- ✅ Port Scan Detection
- ✅ Data Exfiltration Detection
- ✅ Configurable Detection Thresholds
- ✅ Threat Severity Classification
- ✅ Threat Scoring
- ✅ Structured Alert Generation
- ✅ Logging Support
- ✅ FastAPI Integration Ready
- ✅ Modular & Extensible Design

---

# Project Architecture

```
                    Incoming Request
                           │
                           ▼
                Rule-Based Detection Engine
                           │
             ┌─────────────┴─────────────┐
             │                           │
       Threat Detected             No Threat
             │                           │
             ▼                           ▼
      Generate Alert             ML Detection Engine
             │                           │
             └─────────────┬─────────────┘
                           │
                           ▼
                    Response to API
```

---

# Project Structure

```
SecOpsAI-Rule-Engine/

│
├── schemas/
│   ├── alert.py
│   ├── detection.py
│   └── __init__.py
│
├── services/
│   ├── rule_engine.py
│   ├── rules_config.py
│   └── __init__.py
│
├── tests/
│   ├── test_rule_engine.py
│   └── __init__.py
│
├── docs/
├── examples/
│
├── README.md
├── requirements.txt
├── LICENSE
└── .gitignore
```

---

# Detection Rules

| Rule ID | Threat | Severity |
|---------|----------|----------|
| RB001 | Brute Force | HIGH |
| RB002 | Port Scan | HIGH |
| RB003 | Data Exfiltration | CRITICAL |

---

# Alert Example

```json
{
    "matched": true,
    "alert_count": 2,
    "overall_severity": "HIGH",
    "threat_score": 90,
    "alerts": [
        {
            "rule_id": "RB001",
            "category": "Authentication",
            "source": "RULE_ENGINE",
            "threat": "Brute Force",
            "severity": "HIGH",
            "threat_score": 90,
            "description": "Failed login attempts exceeded configured threshold.",
            "timestamp": "2026-06-30T18:45:00"
        }
    ]
}
```

---

# Running Tests

Clone the repository

```bash
git clone https://github.com/Shailu27/SecOpsAI-Rule-Engine.git
```

Move into the project

```bash
cd SecOpsAI-Rule-Engine
```

Run the test suite

```bash
python tests/test_rule_engine.py
```

---

# Rule Configuration

All thresholds are configurable in

```
services/rules_config.py
```

Current thresholds

| Rule | Threshold |
|-------|-----------|
| Failed Logins | > 5 |
| Ports Accessed | > 20 |
| Bytes Sent | > 1,000,000 |

---

# Future Enhancements

- SQL Injection Detection
- DNS Tunneling Detection
- Insider Threat Detection
- Privilege Escalation Rules
- Dynamic Rule Loading
- Threat Intelligence Integration
- SIEM Integration
- Docker Deployment
- Kubernetes Support

---

# Tech Stack

- Python
- Dataclasses
- Logging
- FastAPI (Integration Ready)

---

# Integration Workflow

```
FastAPI

        │

        ▼

Rule Engine

        │

Matched?

 ┌─────────────┴─────────────┐

 │                           │

YES                         NO

 │                           │

 ▼                           ▼

Alert                 ML Detection Engine

        │

        ▼

Response
```

---

# License

This project is released under the MIT License.

---

# Author

**Shailu27**

Cybersecurity | SOC | Digital Forensics | Threat Detection
