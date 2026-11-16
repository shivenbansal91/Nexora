import assert from 'node:assert/strict';
import { mergeSnapshot } from '../frontend/src/live/mergeSnapshot.ts';

const stale = { id: 'event', flagged: false };
const fresh = { id: 'event', flagged: true };
assert.deepEqual(mergeSnapshot([stale], [fresh], new Set()), [fresh]);
assert.deepEqual(mergeSnapshot([fresh], [stale], new Set(['event'])), [fresh]);
assert.equal(mergeSnapshot([fresh], [{ id: 'new' }], new Set()).length, 2);
console.log('Reconnect snapshot checks passed');
