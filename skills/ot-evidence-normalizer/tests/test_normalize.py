import json
import sys
import tempfile
import unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
from normalize_evidence import normalize,utc,detect,s7_operation
class NormalizerTests(unittest.TestCase):
    def test_utc(self):
        self.assertEqual(utc('2026-09-08T05:17:00+03:00'),'2026-09-08T02:17:00Z')
        self.assertIsNone(utc('2026-09-08T02:17:00'))
    def test_modbus(self):
        with tempfile.TemporaryDirectory() as t:
            p=Path(t)/'modbus.json'
            p.write_text(json.dumps({'file':'capture.pcap','decoded_pdus':1,'write_candidates':[{'frame':3,'time_utc':'2026-09-08T02:17:00Z','src':'10.0.0.1','dst':'10.0.0.2','direction':'request','function':6,'write_candidate':True,'address':100}],'events':[]}),encoding='utf8')
            summary,chain,process=normalize([p]);self.assertEqual(summary['events_written'],1);self.assertEqual(process['observations'][0]['operation'],'setpoint_write');self.assertEqual(chain['events'][0]['evidence'][0]['frame'],3)
    def test_bacnet_duplicate(self):
        with tempfile.TemporaryDirectory() as t:
            p=Path(t)/'bacnet.json';e={'frame':8,'utc':'2026-09-08T02:17:00Z','src':'1.1.1.1','dst':'2.2.2.2','kind':'confirmed-request','service_id':17,'service':'deviceCommunicationControl'}
            p.write_text(json.dumps({'capture':'x.pcap','bacnet_packets':2,'sample_events':[e],'state_change_candidates':[e]}))
            s,c,pr=normalize([p]);self.assertEqual(s['events_written'],1);self.assertEqual(pr['observations'][0]['operation'],'communications_control')
    def test_s7_iec(self):
        with tempfile.TemporaryDirectory() as t:
            p=Path(t)/'s7.json';p.write_text(json.dumps({'skill':'siemens-s7-forensics','captures':[{'file':'x.pcap','events':[{'frame':2,'time_utc':'2026-09-08T02:17:00Z','function_name':'Write Var','state_change_candidate':True}]}]}))
            q=Path(t)/'iec.json';q.write_text(json.dumps({'skill':'iec104-forensics','captures':[{'file':'y.pcap','events':[{'frame':4,'time_utc':'2026-09-08T02:17:01Z','control_command_candidate':True,'asdu':{'type_id':48,'type_name':'setpoint'}}]}]}))
            s,c,pr=normalize([p,q]);self.assertEqual(s['events_written'],2);self.assertEqual(len(pr['observations']),2)
    def test_s7_semantics_preserved(self):
        rows = [
            (0x29, 'PLC Stop', 'controller_mode_change', 'PLC CPU', 'STOP'),
            (0x05, 'Write Var', 'variable_write', 'PLC variables (address not resolved)', None),
            (0x1a, 'Request Download', 'program_transfer', 'PLC program blocks', None),
            (0x1b, 'Download Block', 'program_transfer', 'PLC program blocks', None),
            (0x1c, 'Download Ended', 'program_transfer', 'PLC program blocks', None),
            (0x28, 'PLC Control', 'other', 'unspecified target', None),
        ]
        with tempfile.TemporaryDirectory() as t:
            p=Path(t)/'s7.json'
            events=[{'frame':i+40,'time_utc':f'2026-09-08T02:17:{i:02d}Z',
                     'src':'10.0.0.4','dst':'10.0.0.5',
                     'function_code':code,'function_name':name,
                     'state_change_candidate':True} for i,(code,name,*_) in enumerate(rows)]
            p.write_text(json.dumps({'skill':'siemens-s7-forensics','captures':[{'file':'source.pcap','events':events}]}))
            summary,chain,process=normalize([p])
            self.assertEqual(summary['events_written'],len(rows))
            for i,(_,name,op,target,mode) in enumerate(rows):
                actual=process['observations'][i]
                self.assertEqual(actual['operation'],op)
                self.assertEqual(actual['target'],target)
                self.assertEqual(actual['original_operation'],name)
                self.assertEqual(actual['function_code'],rows[i][0])
                self.assertEqual(actual.get('requested_mode'),mode)
                self.assertEqual(actual['source'],f'source.pcap frame {40+i}')
                self.assertEqual(actual['evidence_stage'],'command_observed')
                timeline=chain['events'][i]
                self.assertEqual(timeline['evidence'][0]['frame'],40+i)
                self.assertEqual(timeline['details']['original_operation'],name)
                self.assertEqual(timeline['details']['normalized_operation'],op)
                self.assertIn('not established', timeline['details']['normalization_note'])
    def test_s7_non_candidate_does_not_become_process_event(self):
        with tempfile.TemporaryDirectory() as t:
            p=Path(t)/'s7.json'
            p.write_text(json.dumps({'skill':'siemens-s7-forensics',
                'captures':[{'file':'x.pcap','events':[{'frame':1,'time_utc':'2026-09-08T02:17:00Z',
                'function_code':0x29,'function_name':'PLC Stop','state_change_candidate':False}]}]}))
            summary, chain, process=normalize([p])
            self.assertEqual(summary['events_written'],1)
            self.assertEqual(summary['observations_written'],0)
            self.assertEqual(chain['events'][0]['details']['mapping_status'],'not_state_change_candidate')
    def test_s7_missing_name_uses_function_code(self):
        self.assertEqual(s7_operation({'state_change_candidate':True,'function_code':0x29}),
                         ('controller_mode_change','STOP','mapped_by_code'))
        self.assertEqual(s7_operation({'state_change_candidate':True,'function_code':'0x1b'}),
                         ('program_transfer',None,'mapped_by_code'))
        self.assertEqual(s7_operation({'state_change_candidate':True,'function_name':'Unknown'}),
                         ('other',None,'unresolved_s7_operation'))
    def test_skip_missing_timestamp_and_unknown(self):
        with tempfile.TemporaryDirectory() as t:
            p=Path(t)/'a.json';p.write_text(json.dumps({'events':[{'action':'unknown'}]}))
            q=Path(t)/'b.json';q.write_text(json.dumps({'surprise':1}))
            s,c,pr=normalize([p,q]);self.assertEqual(s['events_written'],0);self.assertEqual(len(s['warnings']),2)
    def test_app(self):
        with tempfile.TemporaryDirectory() as t:
            p=Path(t)/'app.json';p.write_text(json.dumps({'file':'flow.json','sha256':'a','findings':[{'type':'configuration','line':4}]}))
            s,c,pr=normalize([p]);self.assertEqual(s['events_written'],0);self.assertTrue(s['warnings'])
if __name__=='__main__':unittest.main()
