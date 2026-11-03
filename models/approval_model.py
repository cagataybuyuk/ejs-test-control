"""Pure GD-005 schema/state model, NOT approval authentication or a real ledger.

All bindings, clock and snapshots are hypothetical caller data. No I/O, current
clock reads, process calls, publication verification or concurrency guarantees.
Never use a model result to admit or dispatch an actual task.
"""
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import json
import re

SHA = re.compile(r'[0-9a-f]{40}\Z')
DIGEST = re.compile(r'[0-9a-f]{64}\Z')
UUID = re.compile(r'[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\Z')
STAMP = re.compile(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\Z')
RUN = re.compile(r'[1-9][0-9]{0,19}:1\Z')
STR_FIELDS = frozenset(('schema_version authorization_id source_repository source_sha '
    'proposal_sha256 task_id allowlist_sha256 runner_repository runner_sha workflow_path '
    'image_digest platform isolation_profile_sha256 environment payload_class network '
    'not_before expires_at decision').split())
FIELDS = STR_FIELDS | {'max_wall_seconds', 'max_retries'}
FIXED = {'schema_version':'GD005-TASK-APPROVAL-1',
         'source_repository':'cagataybuyuk/europe-job-scan',
         'runner_repository':'cagataybuyuk/ejs-test-control',
         'workflow_path':'.github/workflows/offline-test.yml', # hypothetical, no such runner is created
         'platform':'linux/amd64','task_id':'secret_scan','environment':'TEST',
         'payload_class':'synthetic_only','network':'denied','decision':'approved_for_one_offline_test'}


class NonAuthorizing:
    __slots__ = ()

    @property
    def execution_authorized(self):
        return False

    @property
    def permitted_actions(self):
        return ()


@dataclass(frozen=True, slots=True)
class Bindings:
    source_sha: str
    proposal_sha256: str
    runner_sha: str
    allowlist_sha256: str
    image_digest: str
    isolation_profile_sha256: str


@dataclass(frozen=True, slots=True)
class Clock:
    now_utc: str
    merged_at_utc: str
    skew_seconds: int = 0


@dataclass(frozen=True, slots=True)
class Check(NonAuthorizing):
    schema_model_valid: bool
    reason: str
    authorization_id: str = ''
    record_digest: str = ''
    not_before: str = ''
    expires_at: str = ''


@dataclass(frozen=True, slots=True)
class Entry:
    authorization_id: str
    record_digest: str
    publication_sha: str
    not_before: str
    expires_at: str
    merged_at: str
    state: str = 'available'
    run_id: str = ''
    cancelled: bool = False


@dataclass(frozen=True, slots=True)
class Snapshot:
    revision: int = 0
    entries: tuple[Entry, ...] = ()


@dataclass(frozen=True, slots=True)
class Transition(NonAuthorizing):
    model_transition_valid: bool
    reason: str
    parent_digest: str = ''
    candidate: Snapshot | None = None


def match(pattern, value):
    return type(value) is str and pattern.fullmatch(value) is not None


def timestamp(value):
    if not match(STAMP,value):
        raise ValueError('invalid timestamp')
    return datetime.strptime(value,'%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc)


def clock_valid(clock):
    if type(clock) is not Clock or type(clock.skew_seconds) is not int or not 0 <= clock.skew_seconds <= 30:
        return False
    try:
        timestamp(clock.now_utc); timestamp(clock.merged_at_utc)
        return True
    except (ValueError,TypeError):
        return False


def window_valid(start,end,clock):
    if not clock_valid(clock):
        return False
    try:
        begin,finish,now,merged=map(timestamp,(start,end,clock.now_utc,clock.merged_at_utc))
        margin=timedelta(seconds=clock.skew_seconds)
        return (timedelta(0) < finish-begin <= timedelta(hours=1)
                and now-margin >= max(begin,merged) and now+margin < finish)
    except (ValueError,TypeError):
        return False


def unique_keys(pairs):
    result={}
    for key,value in pairs:
        if key in result: raise ValueError('duplicate')
        result[key]=value
    return result


def reject_constant(_value):
    raise ValueError('non-json constant')


def check_envelope(raw,bindings,clock):
    """Structural/model equality only; all supplied context is unauthenticated."""
    deny=lambda reason: Check(False,reason)
    if type(bindings) is not Bindings or not clock_valid(clock):
        return deny('invalid_model_context')
    for field in ('source_sha','runner_sha'):
        if not match(SHA,getattr(bindings,field)): return deny('invalid_model_context')
    for field in ('proposal_sha256','allowlist_sha256','isolation_profile_sha256'):
        if not match(DIGEST,getattr(bindings,field)): return deny('invalid_model_context')
    if not match(re.compile(r'sha256:[0-9a-f]{64}\Z'),bindings.image_digest):
        return deny('invalid_model_context')
    if type(raw) is not str: return deny('invalid_encoding')
    try:
        encoded=raw.encode('utf-8')
        if not 0 < len(encoded) <= 8192: return deny('invalid_size')
        data=json.loads(raw,object_pairs_hook=unique_keys,parse_constant=reject_constant)
    except (ValueError,TypeError,UnicodeError,RecursionError):
        return deny('invalid_json')
    if type(data) is not dict or set(data) != FIELDS: return deny('invalid_fields')
    if any(type(data[f]) is not str for f in STR_FIELDS): return deny('invalid_types')
    if type(data['max_wall_seconds']) is not int or type(data['max_retries']) is not int:
        return deny('invalid_types')
    if any(data[f] != value for f,value in FIXED.items()): return deny('unsupported_scope')
    if not match(UUID,data['authorization_id']): return deny('invalid_identity')
    if any(data[f] != getattr(bindings,f) for f in Bindings.__dataclass_fields__):
        return deny('binding_mismatch')
    if not 1 <= data['max_wall_seconds'] <= 300 or data['max_retries'] != 0:
        return deny('invalid_limits')
    if not window_valid(data['not_before'],data['expires_at'],clock): return deny('invalid_window')
    return Check(True,'model_valid_not_authenticated',data['authorization_id'],
                 hashlib.sha256(encoded).hexdigest(),data['not_before'],data['expires_at'])


def snapshot_valid(snapshot):
    if (type(snapshot) is not Snapshot or type(snapshot.revision) is not int or not 0 <= snapshot.revision <= 2**63-1
            or type(snapshot.entries) is not tuple or len(snapshot.entries) > 1000):
        return False
    ids=set()
    for entry in snapshot.entries:
        if type(entry) is not Entry or not match(UUID,entry.authorization_id) or entry.authorization_id in ids:
            return False
        ids.add(entry.authorization_id)
        if not match(DIGEST,entry.record_digest) or not match(SHA,entry.publication_sha): return False
        if (type(entry.cancelled) is not bool or type(entry.state) is not str
                or type(entry.run_id) is not str or entry.state not in ('available','consumed','revoked')): return False
        if entry.state == 'consumed':
            if not match(RUN,entry.run_id): return False
        elif entry.run_id != '' or entry.cancelled: return False
        try:
            begin,end,merged=map(timestamp,(entry.not_before,entry.expires_at,entry.merged_at))
            if not timedelta(0) < end-begin <= timedelta(hours=1) or merged >= end: return False
        except (ValueError,TypeError): return False
    return True


def snapshot_digest(snapshot):
    # Called only on validated immutable snapshots, with stable tuple ordering.
    rows=[tuple(getattr(e,f) for f in Entry.__dataclass_fields__) for e in snapshot.entries]
    return hashlib.sha256(json.dumps([snapshot.revision,sorted(rows)],separators=(',',':')).encode()).hexdigest()


def deny_transition(reason):
    return Transition(False,reason)


def propose(snapshot,expected_revision,operation,*,raw='',bindings=None,clock=None,
            publication_sha='',authorization_id='',record_digest='',run_id=''):
    """Create a hypothetical child state. No real write or atomic commit occurs."""
    if not snapshot_valid(snapshot): return deny_transition('invalid_snapshot')
    if type(expected_revision) is not int or expected_revision != snapshot.revision:
        return deny_transition('stale_revision')
    if snapshot.revision == 2**63-1: return deny_transition('revision_exhausted')
    if type(operation) is not str or operation not in ('register','claim','revoke'):
        return deny_transition('unsupported_operation')
    entries=list(snapshot.entries)
    if operation == 'register':
        checked=check_envelope(raw,bindings,clock)
        if not checked.schema_model_valid: return deny_transition(checked.reason)
        if not match(SHA,publication_sha): return deny_transition('invalid_publication')
        if any(e.authorization_id == checked.authorization_id for e in entries):
            return deny_transition('identity_already_used')
        if len(entries) >= 1000: return deny_transition('model_capacity')
        entries.append(Entry(checked.authorization_id,checked.record_digest,publication_sha,
                             checked.not_before,checked.expires_at,clock.merged_at_utc))
    else:
        if not match(UUID,authorization_id): return deny_transition('invalid_identity')
        found=[i for i,e in enumerate(entries) if e.authorization_id == authorization_id]
        if len(found) != 1: return deny_transition('unknown_identity')
        index=found[0]; entry=entries[index]
        if entry.record_digest != record_digest or entry.publication_sha != publication_sha:
            return deny_transition('binding_mismatch')
        values={f:getattr(entry,f) for f in Entry.__dataclass_fields__}
        if operation == 'claim':
            if entry.state != 'available': return deny_transition('not_available')
            if not clock_valid(clock) or clock.merged_at_utc != entry.merged_at:
                return deny_transition('invalid_model_context')
            if not window_valid(entry.not_before,entry.expires_at,clock): return deny_transition('invalid_window')
            if not match(RUN,run_id): return deny_transition('invalid_run')
            values.update(state='consumed',run_id=run_id)
        else:
            if entry.state == 'revoked' or entry.cancelled: return deny_transition('already_revoked')
            if entry.state == 'consumed': values['cancelled']=True
            else: values['state']='revoked'
        entries[index]=Entry(**values)
    return Transition(True,'candidate_only_not_committed',snapshot_digest(snapshot),
                      Snapshot(snapshot.revision+1,tuple(entries)))


def monotonic_child(current,candidate):
    before={e.authorization_id:e for e in current.entries}
    after={e.authorization_id:e for e in candidate.entries}
    if not before.keys() <= after.keys(): return False
    added=after.keys()-before.keys()
    changed=[key for key in before if before[key] != after[key]]
    if len(added)+len(changed) != 1: return False
    if added:
        entry=after[next(iter(added))]
        return entry.state == 'available' and not entry.run_id and not entry.cancelled
    old,new=before[changed[0]],after[changed[0]]
    fields=('authorization_id','record_digest','publication_sha','not_before','expires_at','merged_at')
    if any(getattr(old,f) != getattr(new,f) for f in fields): return False
    if old.state == 'available': return new.state in ('consumed','revoked')
    return (old.state == new.state == 'consumed' and old.run_id == new.run_id
            and not old.cancelled and new.cancelled)


def apply_candidate_model(current,proposal):
    """Pure sequential CAS simulation. Does NOT prove distributed atomicity.

    A real trusted backend/writer is absent. Caller-constructed model objects
    are never authenticated approval or persistent state.
    """
    if not snapshot_valid(current) or type(proposal) is not Transition:
        return deny_transition('invalid_candidate')
    if (proposal.model_transition_valid is not True or not snapshot_valid(proposal.candidate)
            or proposal.parent_digest != snapshot_digest(current)
            or proposal.candidate.revision != current.revision+1
            or not monotonic_child(current,proposal.candidate)):
        return deny_transition('stale_or_invalid_candidate')
    return Transition(True,'model_applied_no_authority',proposal.parent_digest,proposal.candidate)
