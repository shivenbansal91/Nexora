import assert from 'node:assert/strict';
import { bindPanelDismissal } from '../frontend/src/hooks/panelDismissal.ts';

const document = new EventTarget();
document.defaultView = new EventTarget();
const inside = {};
let closed = 0, focused = 0;
const root = {
  ownerDocument: document,
  contains: target => target === inside,
  querySelector: () => ({ focus: () => focused++ }),
};
const send = (type, target, key) => {
  const event = new Event(type, { cancelable: true });
  Object.defineProperty(event, 'target', { value: target });
  if (key) Object.defineProperty(event, 'key', { value: key });
  document.dispatchEvent(event);
  return event;
};
const cleanup = bindPanelDismissal(root, () => closed++);
send('pointerdown', inside);
send('focusin', inside);
assert.equal(closed, 0, 'Inside interactions must keep the panel open');
send('pointerdown', {});
assert.equal(closed, 1, 'Outside clicks close the panel');
send('focusin', {});
assert.equal(closed, 2, 'Tabbing out closes the panel');
assert.equal(send('keydown', inside, 'Escape').defaultPrevented, true);
assert.equal(closed, 3);
assert.equal(focused, 1, 'Escape returns focus to the trigger');
document.defaultView.dispatchEvent(new Event('popstate'));
assert.equal(closed, 4, 'Browser back/forward closes the panel');
cleanup();
send('pointerdown', {});
send('keydown', inside, 'Escape');
document.defaultView.dispatchEvent(new Event('popstate'));
assert.equal(closed, 4, 'Closing/unmounting removes document listeners');
console.log('Panel dismissal checks passed');
