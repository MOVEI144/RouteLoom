"""Small executable contract examples. NOT production crypto, routing, or storage."""
from __future__ import annotations
from dataclasses import dataclass

class ContractError(ValueError):
    pass

class PowerLoss(RuntimeError):
    pass

MAX64=(1<<64)-1

def integer(value: int) -> bool:
    return type(value) is int and 0 <= value <= MAX64


def permit_frame(spec: dict, state: str, kind: str, *, peer_member: bool=False,
                 authenticated: bool=False, authorized: bool=False,
                 bootstrap_transaction: bool=False) -> bool:
    """An allowlist is necessary but insufficient; proof flags stand for providers."""
    if kind not in spec['membership_allowlist'].get(state,[]):
        return False
    if kind in ('DISCOVER','OFFER'):
        return True  # Subject to local/global quotas; no authority conveyed.
    if kind in spec['member_only']:
        return state=='MEMBER' and peer_member and authenticated and authorized
    if kind in spec['bootstrap_requires_transaction']:
        return bootstrap_transaction
    return False


@dataclass
class AtomicHighWater:
    end: int=0
    valid: bool=True
    def commit(self, new: int, cut: str|None=None):
        if not self.valid or not integer(new) or new <= self.end:
            raise ContractError('STORE_UNSAFE')
        if cut=='before':
            raise PowerLoss('before commit')
        self.end=new
        if cut=='after':
            raise PowerLoss('after commit before acknowledgement')


class CounterReservation:
    def __init__(self, store: AtomicHighWater, block: int=256):
        if not store.valid or not integer(store.end) or not integer(block) or block==0:
            raise ContractError('CONTEXT_REESTABLISH_REQUIRED')
        self.store,self.block=store,block
        # Burn any old reservation; a cold boot never resumes a volatile cursor.
        self.cursor=self.limit=store.end
    def next(self, cut: str|None=None) -> int:
        if self.cursor==self.limit:
            start=self.store.end
            if start>MAX64-self.block:
                raise ContractError('COUNTER_EXHAUSTED')
            self.store.commit(start+self.block,cut)
            self.cursor,self.limit=start,start+self.block
        result=self.cursor
        self.cursor+=1
        return result


def resume_deadline(remaining_ms: int, elapsed_bounds: tuple[int,int]|None):
    if not integer(remaining_ms):
        raise ContractError('INVALID_TIME')
    if elapsed_bounds is None:
        return 'TIME_UNCERTAIN',None
    lo,hi=elapsed_bounds
    if not integer(lo) or not integer(hi) or lo>hi:
        raise ContractError('INVALID_TIME')
    return ('EXPIRED',0) if hi>=remaining_ms else ('READY',remaining_ms-hi)


def admit(capacity: dict[str,int], required: tuple[str,...], fail_at: str|None=None):
    """All-or-nothing reservation. A returned token models admission, not a MAC ACK."""
    taken=[]
    for item in required:
        if item==fail_at or capacity.get(item,0)<1:
            for previous in taken:
                capacity[previous]+=1
            return None
        capacity[item]-=1; taken.append(item)
    return tuple(taken)


def provider_failover_allowed(delivery: str, requested: bool,
                              shared_idempotency: bool=False, duplicate_effect_ok: bool=False):
    if not requested:
        return False
    return delivery!='APPLIED' or shared_idempotency or duplicate_effect_ok


class Credit:
    def __init__(self, session: str):
        self.session=session
        self.grant_frames=self.grant_bytes=0
        self.consumed_frames=self.consumed_bytes=0
        self.next_token=1
        self.partial=set()
    def grant(self, session: str, frames: int, octets: int, authenticated: bool):
        if session!=self.session or not authenticated:
            raise ContractError('SESSION_OR_AUTH')
        if not integer(frames) or not integer(octets):
            raise ContractError('INVALID_CREDIT')
        self.grant_frames=max(self.grant_frames,frames)
        self.grant_bytes=max(self.grant_bytes,octets)
    def begin(self, size: int) -> int:
        if not integer(size) or size==0:
            raise ContractError('INVALID_LENGTH')
        if self.consumed_frames+1>self.grant_frames or self.consumed_bytes+size>self.grant_bytes:
            raise ContractError('NO_CREDIT')
        self.consumed_frames+=1; self.consumed_bytes+=size
        token=self.next_token; self.next_token+=1; self.partial.add(token)
        return token
    def continue_write(self, token: int):
        if token not in self.partial:
            raise ContractError('UNKNOWN_PARTIAL_WRITE')
    def finish(self, token: int):
        self.continue_write(token); self.partial.remove(token)


class Idempotency:
    def __init__(self):
        self.entries={}
    def submit(self, principal: str, network: str, op_class: str, key: str, payload_hash: str):
        identity=(principal,network,op_class,key)
        if identity in self.entries:
            if self.entries[identity]!=payload_hash:
                raise ContractError('CONFLICT')
            return 'EXISTING'
        self.entries[identity]=payload_hash
        return 'ACCEPTED'


def seq_newer(new: int, old: int) -> bool:
    if type(new) is not int or type(old) is not int or not(0<=new<=65535 and 0<=old<=65535):
        raise ContractError('BAD_SEQUENCE')
    delta=(new-old)&65535
    if delta==32768:
        raise ContractError('SEQUENCE_UNCERTAIN')
    return 0<delta<32768


def feasible(seq: int, metric: int, fd: tuple[int,int]|None) -> bool:
    if type(metric) is not int or not 0<=metric<=65535:
        raise ContractError('BAD_METRIC')
    if metric==65535:
        return True  # Retraction is acceptable, never a DATA next hop.
    if fd is None:
        return True  # Only a genuinely new source, not lost/corrupt frontier.
    return seq_newer(seq,fd[0]) or (seq==fd[0] and metric<fd[1])


def advertise_fd(seq: int, metric: int, fd: tuple[int,int]|None):
    if metric==65535:
        return fd
    if fd is None or seq_newer(seq,fd[0]):
        return seq,metric
    if seq==fd[0]:
        return seq,min(metric,fd[1])
    return fd


def metric_add(advertised: int, positive_cost: int) -> int:
    if type(positive_cost) is not int or positive_cost<=0:
        raise ContractError('NONPOSITIVE_LINK_COST')
    return min(65535,advertised+positive_cost)


def runtime_board(board: dict, selected_functions: set[str]):
    if not board.get('runtime_generation_allowed') or board.get('qualified_runtime_profile') is None:
        raise ContractError('BOARD_NOT_QUALIFIED')
    for conflict in board.get('exclusive_functions',[]):
        if set(conflict)<=selected_functions:
            raise ContractError('PIN_CONFLICT')
    return board['qualified_runtime_profile']
