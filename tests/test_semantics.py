"""Small local-semantics regressions; full simulator smoke runs are separate."""
from pathlib import Path
import struct,sys,unittest
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'sara/serial'),str(ROOT/'sara/serial/script/core')]
from script.core.reg_observed_analyzer import eval_op,canonical_op

def evaluate(op,values,width):
    return eval_op(canonical_op(op),values,width)

class Semantics(unittest.TestCase):
    def test_carry(self):
        self.assertEqual(evaluate('add.u32',[3,1],32),4)
        self.assertEqual(evaluate('add.u32',[2,1],32),3)
    def test_signed_division(self):
        self.assertEqual(evaluate('div.s32',[(-7)&0xffffffff,3],32)&0xffffffff,(-2)&0xffffffff)
    def test_logical_mask(self):
        self.assertEqual(evaluate('and.b32',[0xabcd,15],32),13)
        self.assertEqual(evaluate('and.b32',[0xabcd^(1<<16),15],32),13)
    def test_float_rounding(self):
        bits=lambda x:struct.unpack('<I',struct.pack('<f',x))[0]
        self.assertEqual(evaluate('add.f32',[bits(1.0),bits(2**-25)],32),bits(1.0))
if __name__=='__main__':unittest.main()

