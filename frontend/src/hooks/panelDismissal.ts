/** Bind only while a panel is open; return cleanup for unmount/close. */
export function bindPanelDismissal(root: HTMLElement, close: () => void) {
  const doc = root.ownerDocument;
  const capture = { capture: true };
  const outside = (event: Event) => {
    if (!root.contains(event.target as Node)) close();
  };
  const keydown = (event: KeyboardEvent) => {
    if (event.key !== 'Escape' || event.defaultPrevented) return;
    event.preventDefault();
    close();
    root.querySelector<HTMLButtonElement>('button')?.focus();
  };
  doc.addEventListener('pointerdown', outside, capture);
  doc.addEventListener('focusin', outside);
  doc.addEventListener('keydown', keydown);
  doc.defaultView?.addEventListener('popstate', close);
  return () => {
    doc.removeEventListener('pointerdown', outside, capture);
    doc.removeEventListener('focusin', outside);
    doc.removeEventListener('keydown', keydown);
    doc.defaultView?.removeEventListener('popstate', close);
  };
}
