import test from 'node:test';
import assert from 'node:assert/strict';
import {parseWord64,word64ToWire,word64ToHex,word64Equal,WORD64_WIRE_SCHEMA} from '../providers/xavi-exec/word64.mjs';
test('word64 wire preserves values beyond JS safe integer exactly',()=>{
  const s='1234605616436508552';
  assert.equal(parseWord64(s),0x1122334455667788n);
  assert.equal(word64ToWire(0x1122334455667788n),s);
  assert.equal(word64ToHex(s),'0x1122334455667788');
  assert.equal(word64Equal(s,0x1122334455667788n),true);
  assert.equal(WORD64_WIRE_SCHEMA.encoding,'unsigned-decimal-string');
});
test('word64 wire rejects unsafe JS Number rather than silently rounding',()=>{
  assert.throws(()=>word64ToWire(1234605616436508552),/safe integer/);
  assert.throws(()=>word64ToWire('-1'),/(canonical|uint64 range)/);
  assert.throws(()=>word64ToWire('18446744073709551616'),/uint64 range/);
});
