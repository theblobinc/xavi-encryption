/**
 * Xavi Memory / DUO-Math integration adapter.
 * Canonical research home: /datastore3/math/numbers/duo-simulator
 * Production port target: /datastore3/wg-rnn/xavi-memory-js/src/core/duo-native.js
 */
import {
  DUO_REVISION, DUO_NATIVE_SCHEMA, DUO_MODULAR_STATE_SCHEMA,
  duoCountGlyph, parseDuoCountGlyph, duoBandsPerCycle,
  duoModularStateAt, duoNativeWalk, duoInvertModularToken,
  duoTokenRecurrence, duoCompareModuli, duoAmbiguityScan,
  duoStructuralLadder, duoLadderToken, duoTokenEventualPlateau,
  duoTokenPiecewiseLaw, duoRecurrenceSignature,
} from './duo-native.js';

export const XAVI_DUO_MEMORY_SCHEMA='xavi-memory-duo-native/v1';

export function duoMemoryCoordinate({count,modulus,hand='+'}){
  const state=duoModularStateAt(count,modulus,{hand});
  return Object.freeze({
    schema:XAVI_DUO_MEMORY_SCHEMA,
    revision:DUO_REVISION,
    authority:false,
    identity:false,
    native:state,
    address:Object.freeze({
      global:state.duoCount,
      modulus:state.duoModulus,
      modularToken:state.token,
      hand:state.hand,
    }),
    topology:Object.freeze({
      cycle:state.cycle,
      phase:state.phase,
      band:state.globalBand,
      width:state.width,
      bandsPerCycle:state.bandsPerCycle,
      rollover:state.rollover,
    }),
  });
}

export function duoMemoryTokenMeaning({token,modulus,hand='auto'}){
  const state=duoInvertModularToken(token,modulus,{hand});
  if(!state)return null;
  return duoMemoryCoordinate({count:state.count,modulus:state.modulus,hand:state.hand});
}

export function duoMemoryRecurrenceContext({token,maxModulus=100,moduli=null}){
  const signature=duoRecurrenceSignature(token,maxModulus,{moduli});
  return Object.freeze({
    schema:'xavi-memory-duo-recurrence-context/v1',
    revision:DUO_REVISION,
    authority:false,
    token,
    classification:signature.classification,
    distinctValues:signature.distinctValues,
    coverage:signature.occurrences,
    eventual:signature.eventual,
    signature,
  });
}

export {
  DUO_REVISION, DUO_NATIVE_SCHEMA, DUO_MODULAR_STATE_SCHEMA,
  duoCountGlyph, parseDuoCountGlyph, duoBandsPerCycle,
  duoModularStateAt, duoNativeWalk, duoInvertModularToken,
  duoTokenRecurrence, duoCompareModuli, duoAmbiguityScan,
  duoStructuralLadder, duoLadderToken, duoTokenEventualPlateau,
  duoTokenPiecewiseLaw, duoRecurrenceSignature,
};
