# Input format (JSON)

```json
{
  "case_id": "training-case",
  "observations": [
    {
      "id": "o1",
      "time_utc": "2026-09-08T02:17:00Z",
      "source": "capture.pcap frame 413",
      "protocol": "Modbus TCP",
      "actor": "10.0.0.30",
      "asset": "PLC-1",
      "target": "holding_register:100",
      "operation": "setpoint_write",
      "value": 920,
      "unit": null,
      "evidence_stage": "command_observed",
      "note": "Raw register value; scaling not established"
    }
  ]
}
```

Required fields: `id`, `source`, `asset`, `target`, `operation`, `evidence_stage`. Optional fields: `time_utc`, `protocol`, `actor`, `value`, `unit`, `note`, `original_operation`, `function_code`, `requested_mode`, `mapping_status` (the last four preserve protocol-specific S7 normalization details where supplied). Values are raw unless a supported engineering mapping is supplied. Allowed stages: `command_observed`, `protocol_acknowledged`, `state_observed`, `physical_effect_correlated`.

Supported operation labels include `setpoint_write`, `coil_write`, `start`, `stop`, `alarm_change`, `interlock_override`, `communications_control`, `controller_mode_change`, `variable_write`, `program_transfer`, `read`, and `other`. These are analyst annotations, not inferred packet decodes. The script checks contradictions and reports limitations but cannot infer plant safety on its own.

## Evidence strength
`command_observed` = request visible; `protocol_acknowledged` = corresponding reply shows protocol-level acceptance; `state_observed` = independent device state/telemetry; `physical_effect_correlated` = measured effect correlated in time and causality assessed by analyst. These are increasing evidence categories, **not automatic conclusions**. A protocol ACK does not establish physical change.

## S7 normalization compatibility (v0.1.1)

The OT Evidence Normalizer v0.1.1 emits these additional operation labels:

| Operation | Example source action | Interpretation |
|---|---|---|
| `controller_mode_change` | PLC Stop / PLC Start | Request for controller mode change; `requested_mode` may be STOP, START, or unknown |
| `variable_write` | Write Var | PLC memory write request; not necessarily a process setpoint |
| `program_transfer` | Request Download / Download Block / Download Ended | Program transfer activity; does not prove successful program modification |

Example process observation:

```json
{
  "id": "evt-000001",
  "source": "capture.pcap frame 1420",
  "asset": "10.0.0.10",
  "target": "PLC CPU",
  "operation": "controller_mode_change",
  "original_operation": "PLC Stop",
  "function_code": 41,
  "requested_mode": "STOP",
  "mapping_status": "mapped_by_name",
  "evidence_stage": "command_observed"
}
```

These fields are preserved in output for evidence traceability. They are source assertions, not independently verified controller outcomes. A command request never proves a corresponding physical effect.
