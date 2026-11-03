"""Regression cases for Siemens S7 observation taxonomy (v0.1.1)."""
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('process_v011', ROOT / 'scripts' / 'analyze_process.py')
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


def observation(operation, **fields):
    item = {
        'id': 'evt-000001', 'source': 'source.pcap frame 42',
        'time_utc': '2026-09-08T02:17:00Z',
        'protocol': 'S7comm', 'asset': '10.0.0.5', 'target': 'PLC CPU',
        'operation': operation, 'evidence_stage': 'command_observed',
        'original_operation': 'PLC Stop', 'function_code': 41,
        'mapping_status': 'mapped_by_name',
    }
    item.update(fields)
    return item


class S7NormalizedTests(unittest.TestCase):
    def run_one(self, event):
        return mod.analyze({'case_id': 's7-regression', 'observations': [event]})['findings'][0]

    def test_plc_stop_retains_semantics_and_source(self):
        row = self.run_one(observation('controller_mode_change', requested_mode='STOP'))
        self.assertEqual(row['operation'], 'controller_mode_change')
        self.assertEqual(row['original_operation'], 'PLC Stop')
        self.assertEqual(row['function_code'], 41)
        self.assertEqual(row['requested_mode'], 'STOP')
        self.assertEqual(row['source'], 'source.pcap frame 42')
        self.assertIn('cyclic program execution', row['potential_risk'])
        self.assertTrue(any('does not prove acceptance' in x for x in row['limitations']))

    def test_plc_start_mode_distinct(self):
        row = self.run_one(observation('controller_mode_change', requested_mode='START', original_operation='PLC Start'))
        self.assertIn('resume program execution', row['potential_risk'])
        self.assertNotIn('interrupt cyclic', row['potential_risk'])

    def test_unknown_mode_is_not_inferred(self):
        row = self.run_one(observation('controller_mode_change', requested_mode=None))
        self.assertTrue(any('mode is unknown' in x for x in row['limitations']))
        self.assertIn('may affect', row['potential_risk'].lower())

    def test_write_var_not_assumed_setpoint(self):
        row = self.run_one(observation('variable_write', original_operation='Write Var', function_code=5, target='PLC variables (address not resolved)', requested_mode=None))
        self.assertIn('memory contents', row['potential_risk'])
        self.assertNotIn('setpoint', row['potential_risk'].lower())
        self.assertEqual(row['mapping_status'], 'mapped_by_name')

    def test_program_transfer_not_success(self):
        row = self.run_one(observation('program_transfer', original_operation='Download Block', function_code=27, target='PLC program blocks'))
        self.assertIn('if a transfer is completed and applied', row['potential_risk'])
        self.assertTrue(any('does not establish download completion' in x for x in row['limitations']))

    def test_legacy_input_still_supported(self):
        row = self.run_one(observation('other'))
        self.assertIsNone(row['potential_risk'])

    def test_full_normalizer_to_process_integration(self):
        # Use the real corrected normalizer v0.1.1 when installed beside the
        # skill in our local validation environment. This test also runs on
        # a stand-alone public repository with sibling skill directories.
        roots = [ROOT.parents[1] / 'ot-evidence-normalizer', ROOT.parents[1] / 'ot-evidence-normalizer-v0.1.1']
        normalizer_script = next((r / 'scripts' / 'normalize_evidence.py' for r in roots
                                  if (r / 'scripts' / 'normalize_evidence.py').is_file()), None)
        if normalizer_script is None:
            self.skipTest('ot-evidence-normalizer v0.1.1 not found as sibling skill')
        norm_spec = importlib.util.spec_from_file_location('normalizer_v011', normalizer_script)
        norm = importlib.util.module_from_spec(norm_spec)
        norm_spec.loader.exec_module(norm)
        with tempfile.TemporaryDirectory() as td:
            report = Path(td) / 's7-report.json'
            report.write_text(json.dumps({'skill': 'siemens-s7-forensics', 'captures': [{
                'file': 'controller.pcap', 'events': [
                    {'frame': 50 + i, 'time_utc': f'2026-09-08T02:17:{i:02d}Z',
                     'src': '10.1.1.50', 'dst': '10.1.1.10',
                     'function_name': name, 'function_code': code,
                     'state_change_candidate': True}
                    for i, (name, code) in enumerate([
                        ('PLC Stop', 0x29), ('Write Var', 0x05),
                        ('Request Download', 0x1a), ('Download Block', 0x1b),
                    ])
                ]}]}), encoding='utf-8')
            summary, timeline, process = norm.normalize([report])
            result = mod.analyze(process)
            self.assertEqual(summary['observations_written'], 4)
            self.assertEqual(result['summary']['observation_count'], 4)
            self.assertEqual([x['operation'] for x in result['findings']],
                             ['controller_mode_change', 'variable_write', 'program_transfer', 'program_transfer'])
            for i, row in enumerate(result['findings']):
                self.assertEqual(row['source'], f'controller.pcap frame {50+i}')
                self.assertTrue(row['potential_risk'])
                self.assertEqual(row['evidence_stage'], 'command_observed')
                self.assertEqual(timeline['events'][i]['evidence'][0]['frame'], 50+i)


if __name__ == '__main__':
    unittest.main()
