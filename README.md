# OT Security Agent Skills

**Open-Source AI Agent Skills for Industrial Control Systems (ICS) and Operational Technology (OT) Cybersecurity**

A collection of reusable AI Agent Skills designed to support industrial cybersecurity investigations, network forensics, incident response, operational impact analysis, and security research.

The project combines **AI-assisted investigation, industrial protocol expertise, and practical Python forensic tools** to help researchers, OT engineers, security analysts, and incident responders investigate industrial environments more effectively.

Each skill can operate independently using Python command-line tools or serve as a specialized capability within a compatible AI agent environment.

> **Project Status:** Experimental — v0.1.x. Intended for authorized, passive, offline forensic investigations. Findings require independent verification.

## Objectives

- Develop reusable, modular Agent Skills for ICS/OT cybersecurity investigations.
- Automate repetitive forensic analysis and evidence extraction.
- Support Modbus TCP, BACnet/IP, Siemens S7comm, and IEC 60870-5-104 analysis.
- Identify potentially suspicious commands and state-changing operations.
- Preserve protocol-specific evidence during normalization.
- Interpret potential operational consequences without assuming successful execution.
- Correlate security observations into chronological IT-to-OT investigation timelines.
- Promote transparent, reproducible, and evidence-based research.

## Available Agent Skills

The collection currently includes **eight specialized skills**.

| Skill | Description | Version |
|---|---|---|
| **[Modbus Forensics](skills/modbus-forensics/)** | Analyze Modbus TCP communications, register operations, coil writes, and potentially state-changing commands. | v0.1 |
| **[BACnet Forensics](skills/bacnet-forensics/)** | Investigate BACnet/IP communications, building controllers, and control operations. | v0.1 |
| **[Siemens S7 Forensics](skills/siemens-s7-forensics/)** | Examine S7comm traffic, PLC data access, CPU commands, and program operations. | v0.1.0 |
| **[IEC-104 Forensics](skills/iec104-forensics/)** | Analyze SCADA communications, ASDUs, IOAs, and control commands. | v0.1.0 |
| **[OT Application Forensics](skills/ot-application-forensics/)** | Analyze Node-RED, Grafana, InfluxDB, and MariaDB exported artifacts. | v0.1.0 |
| **[OT Evidence Normalizer](skills/ot-evidence-normalizer/)** | Normalize forensic findings while preserving protocol operation semantics and evidence references. | v0.1.1 |
| **[OT Process Analysis](skills/ot-process-analysis/)** | Interpret industrial control observations, including controller mode changes and program transfers. | v0.1.1 |
| **[Attack Chain Reconstruction](skills/attack-chain-reconstruction/)** | Correlate structured evidence into chronological IT-to-OT incident timelines. | v0.1 |

Each skill includes its own documentation, Python tools, and automated tests.

## How the Skills Work Together

The collection follows an **evidence-first forensic workflow**.

```text
             Industrial Security Evidence
                         |
          +--------------+--------------+
          |                             |
     Network Captures           Application Exports
      PCAP / PCAPNG              JSON / SQL / Text
          |                             |
          v                             v
   Protocol Forensics          OT Application Forensics
   - Modbus                            |
   - BACnet                            |
   - Siemens S7                        |
   - IEC-104                           |
          |                             |
          +--------------+--------------+
                         |
                         v
                Structured JSON Findings
                         |
                         v
                OT Evidence Normalizer
                         |
              +----------+----------+
              |                     |
              v                     v
       OT Process Analysis    Attack Chain
                              Reconstruction
              |                     |
              +----------+----------+
                         |
                         v
               Evidence-Based Findings
                   Analyst Review
```

### Evidence Normalization and Semantic Preservation

Beginning with **OT Evidence Normalizer v0.1.1**, supported Siemens S7 operations retain their specific meanings rather than being grouped under a generic state-change category.

| Siemens S7 operation | Normalized classification |
|---|---|
| PLC Stop | `controller_mode_change` |
| Write Var | `variable_write` |
| Request Download | `program_transfer` |
| Download Block | `program_transfer` |
| Download Ended | `program_transfer` |
| Unknown operation | `other`, with original details retained where available |

**OT Process Analysis v0.1.1** recognizes the new classifications and produces conditional operational risk descriptions.

For example, an observed PLC STOP request may indicate a potential interruption of controller logic execution **if the command is accepted and applied**.

The toolkit does not treat an observed request as proof of successful execution or physical impact.

These improvements were validated through automated tests and a targeted S7-to-normalizer-to-process-analysis integration test.

## How Each Agent Skill Works

Each skill generally contains:

- **`SKILL.md`** — Instructions describing when and how a compatible AI agent should use the skill.
- **`README.md`** — Human-facing installation, usage, and limitations documentation.
- **`scripts/`** — Reusable Python forensic analysis tools.
- **`references/`** — Protocol references, evidence schemas, and investigation guidance.
- **`tests/`** — Automated tests.
- **`examples/`** — Sample evidence where provided.

### Two Usage Modes

**Manual Analysis**

Security researchers can run the Python tools independently.

**AI-Assisted Analysis**

Compatible AI agents can use `SKILL.md` instructions to identify relevant capabilities, invoke analysis scripts, and interpret structured findings.

Automatic skill discovery depends on the agent platform and configuration. Full autonomous orchestration is not included in the current public release.

## Project Structure

```text
ot-security-agent-skills/
├── LICENSE
├── README.md
└── skills/
    ├── attack-chain-reconstruction/
    ├── bacnet-forensics/
    ├── iec104-forensics/
    ├── modbus-forensics/
    ├── ot-application-forensics/
    ├── ot-evidence-normalizer/
    ├── ot-process-analysis/
    └── siemens-s7-forensics/
```

## Requirements

- Python 3.9 or later.
- Python standard library.
- Local forensic evidence files.
- Windows 11, Linux, or macOS.

No additional Python packages are required for the included analyzers.

Wireshark or TShark is recommended for independent verification of complex network captures, especially when TCP segmentation or unsupported protocol features are involved.

## Installation

Clone the standalone repository:

```bash
git clone https://github.com/selmux/ot-security-agent-skills.git
cd ot-security-agent-skills
```

Alternatively, select **Code → Download ZIP** on GitHub.

### Windows 11 — PowerShell

Check Python:

```powershell
python --version
```

Run the Modbus Forensics tests:

```powershell
cd .\skills\modbus-forensics
python -m unittest discover -s tests -v
```

### Linux — Bash

```bash
python3 --version

cd ./skills/modbus-forensics
python3 -m unittest discover -s tests -v
```

Each skill's README contains additional commands and usage examples.

## Usage Examples

The following examples assume commands are run from the relevant skill directory.

### 1. Analyze Modbus Traffic

Windows:

```powershell
python scripts\analyze_modbus.py "C:\captures\modbus.pcap" --output modbus-report.json
```

Linux:

```bash
python3 scripts/analyze_modbus.py ~/captures/modbus.pcap --output modbus-report.json
```

### 2. Analyze Siemens S7 Traffic

Windows:

```powershell
python scripts\analyze_s7.py "C:\captures\s7-traffic.pcap" --output s7-report.json
```

Linux:

```bash
python3 scripts/analyze_s7.py ~/captures/s7-traffic.pcap --output s7-report.json
```

### 3. Normalize Forensic Evidence

From the `ot-evidence-normalizer` directory:

Windows:

```powershell
python scripts\normalize_evidence.py "C:\reports\modbus.json" "C:\reports\s7.json" --output-dir "C:\reports\normalized"
```

Linux:

```bash
python3 scripts/normalize_evidence.py ~/reports/modbus.json ~/reports/s7.json --output-dir ~/reports/normalized
```

The normalizer produces:

| File | Purpose |
|---|---|
| `normalization-summary.json` | Input information, processing counts, warnings, and limitations |
| `attack-chain-events.json` | Structured evidence for chronological investigation |
| `process-observations.json` | Structured observations for operational analysis |

### 4. Analyze Potential Operational Consequences

From the `ot-process-analysis` directory:

```bash
python3 scripts/analyze_process.py process-observations.json --output process-report.json
```

The input must follow the schema documented in `references/input-schema.md`.

### 5. Reconstruct an Attack Timeline

From the `attack-chain-reconstruction` directory:

```bash
python3 scripts/reconstruct_chain.py attack-chain-events.json --output timeline.json --markdown timeline.md
```

The input must follow `references/event-schema.md`.

**Note:** The examples demonstrate individual tools. File paths and output formats must be coordinated when combining multiple skills.

## Intended Use Cases

- ICS/OT network forensics
- Industrial protocol security analysis
- PLC command and register-write investigation
- Building automation security
- SCADA communication analysis
- OT application artifact investigation
- Evidence normalization and correlation
- Industrial process anomaly analysis
- IT-to-OT incident reconstruction
- Threat hunting and incident response
- Cybersecurity research and training

## Testing and Validation

Each skill includes automated tests using Python's built-in `unittest` framework.

From any skill's root directory:

Windows:

```powershell
python -m unittest discover -s tests -v
```

Linux/macOS:

```bash
python3 -m unittest discover -s tests -v
```

### Recent Updates — v0.1.1

**OT Evidence Normalizer**

- Improved Siemens S7 operation classification.
- Preserved original function names, function codes, and evidence references.
- Added mappings for controller mode changes, variable writes, and program transfers.
- Added regression tests for S7 normalization behavior.

**OT Process Analysis**

- Added support for the new normalized S7 operation categories.
- Introduced conditional risk interpretations for controller mode changes and program transfers.
- Preserved additional S7 context in processed observations.
- Added regression and integration tests.

Validation reported for these updates:

- OT Evidence Normalizer: 9 automated tests passed.
- OT Process Analysis: 14 automated tests passed.
- Targeted S7 normalization and process-analysis integration test passed.

These tests cover defined behaviors; they do not establish comprehensive accuracy against real-world industrial incidents.

## Current Limitations

The project remains experimental.

- Full TCP stream reassembly is not implemented in several protocol analyzers.
- Not all industrial protocol functions and fields are decoded.
- The normalizer supports selected JSON formats, not arbitrary vendor exports.
- Some mappings require additional analyst verification.
- OT Process Analysis does not automatically determine plant-specific operating limits.
- Attack Chain Reconstruction does not independently establish causal relationships.
- OT Application Forensics focuses on static artifact analysis.
- An observed industrial command does not prove successful execution.
- Comprehensive validation against diverse real-world incidents remains pending.

Analysts should independently verify important findings against original network evidence, controller diagnostics, application logs, and operational records.

## Security and Operational Safety

The tools are designed for **passive, offline analysis** of authorized evidence.

They do not intentionally interact with live PLCs, issue industrial control commands, or modify operational processes.

Users should:

- Preserve source evidence and cryptographic hashes.
- Maintain appropriate forensic chain-of-custody procedures.
- Protect sensitive credentials and industrial configurations.
- Distinguish observed events from inferred intentions and outcomes.
- Verify operational consequences using independent evidence.
- Obtain authorization before analyzing industrial environments.
- Avoid relying solely on AI-generated findings for safety-critical decisions.

## Roadmap

Future development may include:

- TCP stream reassembly for industrial protocols.
- Expanded protocol and application artifact decoding.
- More comprehensive request/response correlation.
- Additional adapters for SIEM, syslog, CSV, and OT monitoring platform exports.
- Standardized evidence schemas across all skills.
- Enhanced asset and process context integration.
- Broader real-world forensic regression tests.
- Optional AI-agent orchestration across the complete investigation workflow.

These are planned improvements rather than currently implemented capabilities.

## Contributing

Contributions involving industrial protocol analysis, evidence handling, forensic techniques, documentation, testing, and secure software development are welcome.

Please follow responsible security research practices.

Do not contribute private industrial captures, confidential operational configurations, credentials, or sensitive infrastructure data.

## Acknowledgments

Special thanks to **Mark Hyman** for reviewing the OT Security Agent Skills project and identifying an important issue in the Siemens S7 evidence normalization workflow.

His feedback highlighted the loss of operation-specific information when PLC STOP and program-download commands were normalized into generic events.

This contribution helped improve **OT Evidence Normalizer v0.1.1** and **OT Process Analysis v0.1.1**, strengthening the preservation of forensic evidence and operational context.

Community feedback like this is invaluable in improving the accuracy and reliability of open-source OT cybersecurity tools.

## License

This project is licensed under the **Apache License 2.0**.

See the [LICENSE](LICENSE) file for details.

Copyright 2026 Sulaiman Alhasawi.

## Maintainer

**Dr. Sulaiman Alhasawi**

ICS/OT Cybersecurity Researcher

- GitHub: https://github.com/selmux
- Website: https://zerontek.com
- OT/ICS Cybersecurity Training: https://zerontek.com/zt/training-2

## Disclaimer

This project is provided for educational, research, and authorized cybersecurity investigation purposes.

The software is experimental and provided without warranties or guarantees of accuracy, completeness, or suitability for operational decisions.

Users are responsible for complying with applicable laws, organizational policies, and industrial safety requirements.

---

**Building reusable AI capabilities for safer and more resilient industrial environments.**
