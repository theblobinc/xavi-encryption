import test from 'node:test'; import assert from 'node:assert/strict';
import {executionTask} from '../providers/xavi-portable/encrypted-execution-task.js';
test('WASM task binds approved image and never grants authority',()=>{const t=executionTask({requestId:'r1',kind:'wasm',capability:'embed',imageDigest:'sha256:abc',entrypoint:'run',inputDigest:'sha256:in',returnKeyId:'sha256:key'});assert.equal(t.authority,false);assert.ok(t.digest);});
test('small-model task requires model digest',()=>{assert.throws(()=>executionTask({requestId:'r2',kind:'small-model',capability:'rank',inputDigest:'i',returnKeyId:'k'}));});
