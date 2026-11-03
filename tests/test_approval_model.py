"""Synthetic, no-I/O model tests. No real GitHub/ledger/provenance claim."""
from dataclasses import FrozenInstanceError, replace
import importlib.util
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

path=Path(__file__).resolve().parents[1]/'models/approval_model.py'
spec=importlib.util.spec_from_file_location('gd005_model',path)
m=importlib.util.module_from_spec(spec);sys.modules[spec.name]=m;spec.loader.exec_module(m)
ID='00000000-0000-4000-8000-000000000001'
A='c'*40
B=m.Bindings('a'*40,'b'*64,'d'*40,'e'*64,'sha256:'+'f'*64,'1'*64)
CLOCK=m.Clock('2026-11-03T13:00:30Z','2026-11-03T13:00:00Z')


def record(**changes):
    data={**m.FIXED, **{f:getattr(B,f) for f in m.Bindings.__dataclass_fields__},
          'authorization_id':ID,'not_before':'2026-11-03T13:00:00Z',
          'expires_at':'2026-11-03T13:05:00Z','max_wall_seconds':120,'max_retries':0}
    data.update(changes)
    return data


def raw(**changes): return json.dumps(record(**changes))


def available():
    proposed=m.propose(m.Snapshot(),0,'register',raw=raw(),bindings=B,clock=CLOCK,publication_sha=A)
    return m.apply_candidate_model(m.Snapshot(),proposed).candidate


def claim(snapshot,**changes):
    kw={'authorization_id':ID,'record_digest':snapshot.entries[0].record_digest,
        'publication_sha':A,'run_id':'100:1','clock':CLOCK}
    kw.update(changes)
    return m.propose(snapshot,snapshot.revision,'claim',**kw)


def revoke(snapshot):
    return m.propose(snapshot,snapshot.revision,'revoke',authorization_id=ID,
        record_digest=snapshot.entries[0].record_digest,publication_sha=A)


class EnvelopeTests(unittest.TestCase):
    def test_hypothetical_valid_schema_never_authenticates_or_authorizes(self):
        check=m.check_envelope(raw(),B,CLOCK)
        self.assertTrue(check.schema_model_valid)
        self.assertEqual(check.reason,'model_valid_not_authenticated')
        self.assertFalse(check.execution_authorized)
        self.assertEqual(check.permitted_actions,())
        with self.assertRaises(TypeError): m.Check(True,'x',execution_authorized=True)
        with self.assertRaises((FrozenInstanceError,TypeError,AttributeError)): check.execution_authorized=True
        self.assertFalse(hasattr(check,'__dict__'))

    def test_unknown_missing_duplicate_fields_and_invalid_encoding(self):
        missing=record();del missing['source_sha']
        duplicate=raw()[:-1]+',"environment":"TEST"}'
        cases=[json.dumps(missing),raw(command='SYNTHETIC_PRIVATE'),duplicate,'[]','null',
               '{"x": NaN}', '\ud800', '', ' '*8193, b'{}', None, '{'*4000]
        for value in cases:
            with self.subTest(value=repr(value)[:40]):
                result=m.check_envelope(value,B,CLOCK)
                self.assertFalse(result.schema_model_valid)
                self.assertNotIn('SYNTHETIC_PRIVATE',repr(result))
                self.assertFalse(result.execution_authorized)

    def test_every_field_missing_or_wrong_type_fails_closed(self):
        for field in m.FIELDS:
            data=record();del data[field]
            self.assertFalse(m.check_envelope(json.dumps(data),B,CLOCK).schema_model_valid,field)
            for value in (None,[],{},True):
                result=m.check_envelope(raw(**{field:value}),B,CLOCK)
                self.assertFalse(result.schema_model_valid,(field,value))
                self.assertFalse(result.execution_authorized)

    def test_binding_scope_limits_and_identity_denials(self):
        cases=[{'environment':'PROD'},{'network':'allowed'},{'task_id':'pytest_core'},
               {'task_id':'form_write'},{'source_repository':'attacker/repo'},
               {'runner_repository':'attacker/repo'},{'workflow_path':'../../run.sh'},
               {'schema_version':'next'},{'payload_class':'user_data'},{'decision':'approved'},
               {'authorization_id':'arbitrary'},{'authorization_id':ID.upper()},
               {'max_retries':1},{'max_wall_seconds':0},{'max_wall_seconds':301},
               {'max_wall_seconds':1.5}]
        # UUID contains only numbers here; use a real uppercase hex variant.
        cases[11]={'authorization_id':'ABCDEFAB-0000-4000-8000-000000000001'}
        for field in m.Bindings.__dataclass_fields__:
            cases.append({field:'bad'})
        for change in cases:
            with self.subTest(change=change):
                self.assertFalse(m.check_envelope(raw(**change),B,CLOCK).schema_model_valid)

    def test_conservative_time_boundaries_and_merge_time(self):
        cases=[replace(CLOCK,now_utc='2026-11-03T12:59:59Z'),
               replace(CLOCK,now_utc='2026-11-03T13:05:00Z'),
               replace(CLOCK,merged_at_utc='2026-11-03T13:01:00Z'),
               replace(CLOCK,skew_seconds=True),replace(CLOCK,skew_seconds=31),
               replace(CLOCK,skew_seconds=-1),replace(CLOCK,now_utc='now'),
               replace(CLOCK,now_utc='2026-11-03T13:04:40Z',skew_seconds=30)]
        for clock in cases:
            self.assertFalse(m.check_envelope(raw(),B,clock).schema_model_valid,clock)
        for change in [{'not_before':'2026-11-03T13:00:00+00:00'},
                       {'not_before':'2026-02-30T13:00:00Z'},
                       {'expires_at':'2026-11-03T13:00:00Z'},
                       {'expires_at':'2026-11-03T14:00:01Z'}]:
            self.assertFalse(m.check_envelope(raw(**change),B,CLOCK).schema_model_valid)
        self.assertTrue(m.check_envelope(raw(),B,replace(CLOCK,skew_seconds=30)).schema_model_valid)

    def test_context_is_only_a_model_and_malformed_context_rejected(self):
        for bindings in [None,{},replace(B,source_sha='main'),replace(B,image_digest='python:latest')]:
            self.assertFalse(m.check_envelope(raw(),bindings,CLOCK).schema_model_valid)
        self.assertFalse(m.check_envelope(raw(),B,None).schema_model_valid)


class StateModelTests(unittest.TestCase):
    def test_registration_claim_and_crash_burn_without_real_execution(self):
        state=available();self.assertEqual(state.revision,1)
        transition=claim(state)
        self.assertTrue(transition.model_transition_valid)
        applied=m.apply_candidate_model(state,transition)
        self.assertEqual(applied.candidate.entries[0].state,'consumed')
        self.assertFalse(applied.execution_authorized)
        self.assertFalse(claim(applied.candidate).model_transition_valid)
        duplicate=m.propose(applied.candidate,2,'register',raw=raw(),bindings=B,clock=CLOCK,publication_sha=A)
        self.assertFalse(duplicate.model_transition_valid)
        with self.assertRaises(TypeError): m.Transition(True,'x',permitted_actions=('execute',))

    def test_two_claim_candidates_have_at_most_one_sequential_cas_winner(self):
        state=available();left=claim(state,run_id='100:1');right=claim(state,run_id='200:1')
        self.assertTrue(left.model_transition_valid and right.model_transition_valid)
        first=m.apply_candidate_model(state,left)
        second=m.apply_candidate_model(first.candidate,right)
        self.assertFalse(second.model_transition_valid)
        self.assertEqual(first.candidate.entries[0].run_id,'100:1')
        self.assertEqual(state.entries[0].state,'available') # pure: original snapshot untouched

    def test_revoke_first_denies_claim(self):
        state=available();pending=claim(state)
        revoked=m.apply_candidate_model(state,revoke(state)).candidate
        self.assertEqual(revoked.entries[0].state,'revoked')
        self.assertFalse(m.apply_candidate_model(revoked,pending).model_transition_valid)
        self.assertFalse(claim(revoked).model_transition_valid)

    def test_claim_first_then_revoke_is_cancelled_not_reusable(self):
        state=available();consumed=m.apply_candidate_model(state,claim(state)).candidate
        cancelled=m.apply_candidate_model(consumed,revoke(consumed)).candidate
        self.assertEqual(cancelled.entries[0].state,'consumed')
        self.assertTrue(cancelled.entries[0].cancelled)
        self.assertFalse(claim(cancelled).model_transition_valid)
        self.assertFalse(revoke(cancelled).model_transition_valid)

    def test_lost_ack_does_not_become_a_resumable_claim(self):
        state=available();candidate=claim(state)
        hypothetical_committed=m.apply_candidate_model(state,candidate).candidate
        self.assertFalse(m.apply_candidate_model(hypothetical_committed,candidate).model_transition_valid)
        self.assertFalse(claim(hypothetical_committed).model_transition_valid)

    def test_wrong_bindings_rerun_expiry_and_stale_state_rejected(self):
        state=available()
        changes=[{'record_digest':'a'*64},{'publication_sha':'a'*40},{'run_id':'100:2'},
                 {'run_id':'100;evil'},{'clock':replace(CLOCK,now_utc='2026-11-03T13:05:00Z')},
                 {'clock':replace(CLOCK,merged_at_utc='2026-11-03T12:59:59Z')}]
        for change in changes: self.assertFalse(claim(state,**change).model_transition_valid,change)
        self.assertFalse(m.propose(state,0,'claim').model_transition_valid)
        self.assertFalse(m.propose(state,True,'claim').model_transition_valid)
        self.assertFalse(m.propose(state,1,'complete_and_release').model_transition_valid)

    def test_malformed_snapshots_and_model_forged_revival_rejected(self):
        state=available()
        malformed=[None,{},m.Snapshot(True,()),m.Snapshot(0,[]),
                   m.Snapshot(1,(state.entries[0],state.entries[0])),
                   m.Snapshot(1,(replace(state.entries[0],state='consumed'),))]
        for snapshot in malformed: self.assertFalse(m.propose(snapshot,0,'claim').model_transition_valid)
        consumed=m.apply_candidate_model(state,claim(state)).candidate
        revival=m.Transition(True,'forged',m.snapshot_digest(consumed),
                             m.Snapshot(3,(replace(consumed.entries[0],state='available',run_id=''),)))
        self.assertFalse(m.apply_candidate_model(consumed,revival).model_transition_valid)
        removal=m.Transition(True,'forged',m.snapshot_digest(consumed),m.Snapshot(3,()))
        self.assertFalse(m.apply_candidate_model(consumed,removal).model_transition_valid)
        wrong_record=m.Transition(True,'forged',m.snapshot_digest(state),
                                 m.Snapshot(2,(replace(state.entries[0],publication_sha='f'*40,state='revoked'),)))
        self.assertFalse(m.apply_candidate_model(state,wrong_record).model_transition_valid)

    def test_revision_bound_and_malformed_operation_fail_closed(self):
        for revision in (-1,2**63,True):
            self.assertFalse(m.propose(m.Snapshot(revision),revision,'register').model_transition_valid)
        maximum=m.Snapshot(2**63-1)
        self.assertEqual(m.propose(maximum,maximum.revision,'register').reason,'revision_exhausted')
        self.assertFalse(m.propose(m.Snapshot(),0,[]).model_transition_valid)
        for value in (None,[],{}):
            state=available()
            bad=m.Snapshot(1,(replace(state.entries[0],state=value),))
            self.assertFalse(m.propose(bad,1,'claim').model_transition_valid)

    def test_model_does_not_read_clock_network_disk_or_spawn(self):
        # Runtime call guards verify the exercised model flow remains pure.
        with patch('builtins.open',side_effect=AssertionError('disk forbidden')),\
             patch('socket.socket',side_effect=AssertionError('network forbidden')),\
             patch('subprocess.Popen',side_effect=AssertionError('spawn forbidden')),\
             patch('time.time',side_effect=AssertionError('clock read forbidden')):
            state=available();transition=claim(state)
            self.assertTrue(m.apply_candidate_model(state,transition).model_transition_valid)


if __name__=='__main__': unittest.main()
