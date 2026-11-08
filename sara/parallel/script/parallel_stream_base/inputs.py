"""Private plain input ownership and lossless bounded trace decoding.

The file identity/hash implementation is inherited unchanged. Parsed JSON has
one private owner rather than repeated Frozen/deepcopy graphs. Nothing from
this module is installed in the serial comparison implementation.
"""
import codecs
import gzip
import hashlib
import io
import json
from pathlib import Path
import sys
import zlib
from contextlib import contextmanager

from script.execution.method_input_context import OwnInputContext


def need(value, message):
    if not value:
        raise ValueError('LLM parallel input: '+message)


class InputContext(OwnInputContext):
    def __init__(self, roots):
        self.own_roots = {name:Path(p).absolute() for name,p in roots.items()}
        need(all(p == p.resolve(strict=True) and p.is_dir() for p in self.own_roots.values()),
             'canonical actual own roots required')
        # The common root is used only for relative reporting. owns() enforces
        # the exact authorized roots, including their overlap/alias checks.
        import os
        super().__init__(Path(os.path.commonpath([str(p) for p in self.own_roots.values()])))
        self.method = 'sara'
        self.traces = {}

    def owns(self, path):
        p = Path(path).absolute()
        return any(p == root or root in p.parents for root in self.own_roots.values())

    def root_for(self, path):
        p=Path(path).absolute()
        found=[root for root in self.own_roots.values() if p == root or root in p.parents]
        need(bool(found),'path outside declared own roots')
        return max(found,key=lambda value:len(value.parts))

    def cached(self, path, role, loader):
        entry=self._entry(path)
        if role not in entry['derived']:
            entry['derived'][role]=loader()
        return entry['derived'][role]

    def summary(self):
        result=super().summary()
        result.update(schema='sara-llm-parallel-private-inputs-v1',
            immutable_parsed_inputs=False,private_plain_JSON_single_owner=True,
            legacy_Frozen_or_Group_authority_claimed=False,
            decoded_trace_payload_retained=False,
            original_file_identity_and_hash_checks_inherited=True)
        return result

    def __exit__(self,*exc):
        self.traces.clear()
        return super().__exit__(*exc)


def pairs(items):
    out={}
    for key,value in items:
        need(key not in out,'duplicate JSON key')
        out[sys.intern(key)] = value
    return out


def constant(value):
    raise ValueError('nonfinite trace JSON constant: '+value)


class Decoded:
    """Full single-member/CRC/hash verification without a full decoded copy."""
    def __init__(self, context, path, max_physical, max_decoded, tail_bytes):
        self.context,self.path=context,Path(path)
        context.check_size(path,max_physical)
        self.physical=context.read_bytes(path)
        self.maximum=max_decoded
        need(type(max_decoded) is int and max_decoded > 0,'positive decoded bound')
        self.tail_bytes=tail_bytes
        self.tail=b''
        self.result=None

    def chunks(self):
        from script.execution.trace_transport import SCHEMA
        codec='gzip' if self.physical[:2]==b'\x1f\x8b' else 'plain'
        inflater=zlib.decompressobj(16+zlib.MAX_WBITS) if codec=='gzip' else None
        digest=hashlib.sha256();total=0
        with io.BytesIO(self.physical) as stream:
            while True:
                block=stream.read(1024**2)
                if not block:break
                need(inflater is None or not inflater.eof,'trailing data or second gzip member')
                pending=block
                while pending:
                    if inflater is None:
                        part=pending;pending=b''
                    else:
                        try:part=inflater.decompress(pending,min(8*1024**2,self.maximum-total+1))
                        except zlib.error as error:raise ValueError('gzip CRC/format failure') from error
                        need(not inflater.unused_data,'trailing data or second gzip member')
                        pending=inflater.unconsumed_tail
                    total+=len(part)
                    need(total<=self.maximum,'complete decoded trace exceeds resource bound')
                    digest.update(part)
                    self.tail=(self.tail+part)[-self.tail_bytes:]
                    if part:yield part
        need(inflater is None or inflater.eof,'truncated gzip stream')
        descriptor=dict(schema=SCHEMA,codec=codec,physical_bytes=len(self.physical),
            physical_sha256=self.context.digest(self.path),decoded_bytes=total,
            decoded_sha256=digest.hexdigest(),close_succeeded=True)
        sidecar=Path(str(self.path)+'.completeness.json')
        actual=self.context.read_json(sidecar) if sidecar.exists() else {}
        declaration=actual.get('storage')
        if codec=='gzip' or declaration is not None:
            need(actual.get('trace_close_succeeded') is True and declaration==descriptor
                 and actual.get('trace_bytes')==total and actual.get('trace_sha256')==digest.hexdigest(),
                 'actual producer physical/decoded/close binding mismatch')
        self.result=dict(descriptor,producer_close_verified=declaration is not None,
            gzip_CRC_checked=codec=='gzip')
        if declaration is None:self.result['close_succeeded']=None
        self.context.count(self.path,'trace_transport_decodes')
        self.context.count(self.path,'trace_decoded_bytes',total)


class JSONReader:
    def __init__(self,chunks):
        self.chunks=iter(chunks);self.text='';self.pos=0;self.eof=False
        self.utf=codecs.getincrementaldecoder('utf-8')('strict')
        self.decoder=json.JSONDecoder(object_pairs_hook=pairs,parse_constant=constant)

    def refill(self):
        if self.eof:return False
        self.text=self.text[self.pos:];self.pos=0
        try:part=next(self.chunks)
        except StopIteration:
            self.text+=self.utf.decode(b'',final=True);self.eof=True
        else:self.text+=self.utf.decode(part,final=False)
        return True

    def space(self):
        while True:
            while self.pos<len(self.text) and self.text[self.pos] in ' \r\n\t':self.pos+=1
            if self.pos<len(self.text) or self.eof:return
            self.refill()

    def take(self,char):
        self.space();need(self.pos<len(self.text) and self.text[self.pos]==char,'expected JSON delimiter '+char)
        self.pos+=1

    def peek(self):
        self.space()
        return self.text[self.pos] if self.pos<len(self.text) else None

    def value(self):
        self.space()
        while True:
            try:result,end=self.decoder.raw_decode(self.text,self.pos)
            except json.JSONDecodeError:
                if self.eof:raise
                self.refill();continue
            # A primitive token may be split at a chunk boundary. Objects and
            # arrays self-delimit; waiting for one delimiter also handles both.
            if end==len(self.text) and not self.eof:
                self.refill();continue
            self.pos=end
            return result

    def document(self,on_event):
        self.take('{');root={};seen=set();events=0
        if self.peek()=='}':self.take('}')
        else:
            while True:
                key=self.value();need(type(key) is str and key not in seen,'unique root JSON key')
                seen.add(key);self.take(':')
                if key=='events':
                    self.take('[')
                    if self.peek()!=']':
                        while True:
                            row=self.value();need(type(row) is dict,'actual event object required')
                            on_event(row,events);events+=1
                            if self.peek()==']':break
                            self.take(',')
                    self.take(']')
                else:root[key]=self.value()
                if self.peek()=='}':self.take('}');break
                self.take(',')
        need('events' in seen,'complete event array missing')
        self.space();need(self.eof and self.pos==len(self.text),'trailing JSON data')
        return root,events


JOIN_ONLY=('dynamic_warp_instruction_uid','instruction_issue_cycle')


def canonical(row):
    # JSON tree came from the duplicate/nonfinite-rejecting decoder. Exact
    # bool/int/float and signed-zero tokens survive this canonical encoder.
    # Unknown/nested fields are retained; ONLY these two root fields differ.
    return json.dumps({k:v for k,v in row.items() if k not in JOIN_ONLY},
        sort_keys=True,ensure_ascii=True,allow_nan=False,separators=(',',':')).encode('ascii')+b'\n'


def same_spool(left,right):
    with gzip.open(left,'rb') as a,gzip.open(right,'rb') as b:
        while True:
            x,y=a.read(1024**2),b.read(1024**2)
            if x!=y:return False
            if not x:return True


@contextmanager
def ledger_tail_scope(context):
    """Only the existing closed-ledger consumer's suffix read is adapted.

    It still runs its full independent ledger/byte/checkpoint validation. The
    returned suffix is actual bytes from a FULL verified stream, never a
    synthetic full payload. Any call before stream closure is refused. Other
    consumers and the serial trace transport are untouched.
    """
    from script.execution import memory_effect_records as effects
    previous=effects.read_trace_payload
    def suffix(path):
        key=context.key(path)
        value=context.traces.get(key)
        need(value is not None and value['transport'] is not None,
             'closed-ledger suffix requires this invocation complete trace stream')
        context.verify_unchanged()
        return value['tail'],value['transport']
    effects.read_trace_payload=suffix
    try:yield
    finally:
        need(effects.read_trace_payload is suffix,'private suffix adapter identity changed')
        effects.read_trace_payload=previous
