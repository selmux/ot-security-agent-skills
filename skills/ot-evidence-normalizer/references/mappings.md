# Supported input mappings (version 0.1)

- `modbus-forensics`: `events` plus `write_candidates`; uses `file`, `frame`, `time_utc`, `src`, `dst`, `function`, `direction`, and `write_candidate`.
- `bacnet-forensics`: `sample_events` plus `state_change_candidates`; uses `capture`, `frame`, `utc`, `service`, `service_id`, and `kind`.
- `siemens-s7-forensics`: `captures[].events`; uses source `file`, `frame`, `time_utc`, `function_name`, and `state_change_candidate`.
- `iec104-forensics`: `captures[].events`; uses `file`, `frame`, `time_utc`, `asdu` and `control_command_candidate`.
- `ot-application-forensics`: `findings` are processed only when each finding carries its own valid, timezone-aware timestamp. Static configurations commonly lack timestamps, so they are skipped with warnings rather than falsely placed on the attack timeline.
- `generic-events`: accepts a JSON array or `{ "events": [...] }` with per-record timezone-aware `timestamp` or `time_utc` and an `action`; existing evidence locations are retained if they comply with the attack-chain schema.

## Output

- `attack-chain-events.json` follows `attack-chain-reconstruction/references/event-schema.md`, including `events`, `timestamp`, `action`, and evidence locators.
- `process-observations.json` follows `ot-process-analysis/references/input-schema.md`, including `case_id`, `observations`, operation labels and evidence stages.
- `normalization-summary.json` records original input JSON SHA-256, counts, skipped items, and limitations.

This tool does not directly parse raw PCAPs, syslog, vendor APIs, CSV, or proprietary binary exports. Upstream extraction is required. Operation categories are provisional. In particular, protocol acknowledgements and physical effects are **not** inferred.

## Siemens S7 state-change mappings (v0.1.1)

The S7 source report's `state_change_candidate` must be true. Otherwise the
record may appear in the attack-chain timeline but is not emitted as a process
observation. This is a classification of observed *requests*, not successful
controller state changes.

| Observed function | S7 function code | Normalized operation | Target / notes |
|---|---|---|---|
| PLC Stop | `0x29` | `controller_mode_change` | `PLC CPU`, requested_mode=`STOP` |
| PLC Start (only when explicitly named) | N/A | `controller_mode_change` | `PLC CPU`, requested_mode=`START` |
| Write Var | `0x05` | `variable_write` | `PLC variables (address not resolved)` |
| Request Download | `0x1A` | `program_transfer` | `PLC program blocks` |
| Download Block | `0x1B` | `program_transfer` | `PLC program blocks` |
| Download Ended | `0x1C` | `program_transfer` | `PLC program blocks` |
| PLC Control (`0x28`) or unknown | other | `other` | Preserve function and flag unresolved mapping |

**Important:** `PLC Control (0x28)` is *not* automatically translated to
`PLC Start`. The S7 parser does not decode the operation-specific PLC Control
parameters needed to establish the requested mode.

For the S7 output, the attack-chain event's `details` and process observations
retain `original_operation`, `function_code` (when available), `mapping_status`,
and `requested_mode` (when established). Evidence source and packet frame are
preserved. `command_observed` is unchanged, and no control success or physical
effect is inferred.

**Cross-skill compatibility:** `ot-process-analysis` v0.1 rejects the three
new operation labels (`controller_mode_change`, `variable_write`,
`program_transfer`). Update its `OPERATIONS`/`RISKS` definitions and schema
before sending v0.1.1 S7 process observations to it. The attack-chain schema
remains compatible without changes.
