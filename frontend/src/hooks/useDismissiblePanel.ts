import { useCallback, useEffect, useRef, useState } from 'react';
import { bindPanelDismissal } from './panelDismissal';

export function useDismissiblePanel() {
  const ref = useRef<HTMLDivElement>(null);
  const [open, setOpen] = useState(false);
  const close = useCallback(() => setOpen(false), []);
  const toggle = useCallback(() => setOpen(value => !value), []);
  useEffect(() => {
    if (open && ref.current) return bindPanelDismissal(ref.current, close);
  }, [open, close]);
  return { ref, open, close, toggle };
}
