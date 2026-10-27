import assert from 'node:assert/strict';
import { toAttackEvent } from '../frontend/src/live/useChoreography.ts';

const event = { id: 'check', event_type: 'api_call', timestamp: '2026-10-07T10:00:00Z',
  user: 'alice', ip: '10.0.0.1', session: 'session', severity: 0.1 };
assert.equal(toAttackEvent(event).severity, 'info');
assert.equal(toAttackEvent({ ...event, anomaly_score: 0.95 }).severity, 'medium');
assert.equal(toAttackEvent({ ...event, flagged: true, anomaly_score: 0.95 }).severity, 'critical');
assert.equal(toAttackEvent({ ...event, flagged: true, anomaly_score: 0.7 }).severity, 'high');
console.log('Event display checks passed');
