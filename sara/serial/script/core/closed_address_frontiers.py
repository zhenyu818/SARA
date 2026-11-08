"""Small, exact native-memory cases; no alternate control-flow execution.

An alternative read is admitted only outside the entire clean access and host
assignment footprint, under the already bound fresh native zero-memory model.
A redirected store must be dead at its original location, and its new location
must also be outside that footprint. Later alternative reads overlapping any
such write are refused. All other address changes retain the base prediction.
"""
from bisect import bisect_right
from script.core.sparse_global_image import _contract,host_assignments,address
from script.core.reg_observed_analyzer import _build_ea_analysis,eval_effective_ea

def uses_global_backing(event):
    # The common register parser groups kernel parameters with global inputs.
    # Their numeric offsets belong to a separate native parameter memory, not
    # the global byte store. Preserve that physical distinction here.
    return (event.mem_space=='global'
        and getattr(event,'mem_space_raw',None) not in ('param_kernel','param_space_kernel')
        and not event.opcode.startswith(('ld.param.','st.param.')))

class AddressFrontiers:
    def __init__(self,events,image,boundaries):
        _contract(image)
        if image.get('native_memory_source_sha256')!='059e31cb4167b559bcdef39349b5d4b36e9a80b44f30dd09697444108c9cb947':
            raise ValueError('unwritten-zero proof requires bound native memory source')
        ranges=[];self.last_read={};self.access={}
        for row in host_assignments(image):
            lo=address(row['base']);ranges.append((lo,lo+len(bytes.fromhex(row['hexbytes']))))
        for row in boundaries:
            if row['kind'] in ('d2h','symbol_from','d2d','allocation_frontier'):
                lo=row['source'];hi=lo+row['count'];ranges.append((lo,hi))
                for byte in range(lo,hi):self.last_read[byte]=max(self.last_read.get(byte,-1),row['cursor'])
        for e in events:
            if not uses_global_backing(e) or e.kind not in ('load','store') or (e.pred is not None and not e.pred.val):continue
            count=e.mem_access_size_bytes if e.kind=='load' else e.store_size_bytes
            if not count or count<0:raise ValueError('complete native global access width')
            lo=e.mem_addr;hi=lo+count;ranges.append((lo,hi))
            if e.kind=='load':
                for byte in range(lo,hi):self.last_read[byte]=max(self.last_read.get(byte,-1),e.index)
        merged=[]
        for lo,hi in sorted(ranges):
            if not 0<=lo<hi<=1<<32:raise ValueError('32-bit native memory interval')
            if merged and lo<=merged[-1][1]:merged[-1]=(merged[-1][0],max(hi,merged[-1][1]))
            else:merged.append((lo,hi))
        self.ranges=merged;self.starts=[lo for lo,hi in merged]
    def untouched(self,lo,count):
        hi=lo+count
        if not 0<=lo<hi<=1<<32:return False
        i=bisect_right(self.starts,hi-1)-1
        return i<0 or self.ranges[i][1]<=lo
    def admit(self,event):
        if not uses_global_backing(event):return None
        try:
            a=_build_ea_analysis(event)
            if a.expr is None or a.effective_mask!=0xffffffff:return None
            if eval_effective_ea(event,ea_analysis=a)!=event.mem_addr:return None
            return a
        except (ValueError,IndexError,KeyError,NotImplementedError):return None
    def dead_original(self,event,count):
        return all(self.last_read.get(byte,-1)<=event.index for byte in range(event.mem_addr,event.mem_addr+count))
    def load(self,event,analysis,values,old_value,ignored_writes):
        count=event.mem_access_size_bytes
        ea=eval_effective_ea(event,values,ea_analysis=analysis)
        if ea==event.mem_addr:return old_value
        if not self.untouched(ea,count):return None
        if any(ea<hi and lo<ea+count for lo,hi in ignored_writes):return None
        return 0
    def store(self,event,analysis,values,ignored_writes):
        count=event.store_size_bytes
        if not self.dead_original(event,count):return False
        ea=eval_effective_ea(event,values,ea_analysis=analysis)
        if ea!=event.mem_addr:
            if not self.untouched(ea,count):return False
            ignored_writes.append((ea,ea+count))
        return True
