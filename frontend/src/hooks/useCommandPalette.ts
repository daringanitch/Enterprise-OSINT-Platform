/**
 * useCommandPalette
 *
 * Global state hook for the ⌘K Command Palette.
 * Registers the keyboard shortcut and exposes open/close methods
 * so any component in the tree can open the palette programmatically.
 *
 * Usage:
 *   const { isOpen, open, close } = useCommandPalette();
 *
 * The shortcut is registered once on mount (in App.tsx) via
 * CommandPaletteProvider — other components just call open().
 */

import { useState, useEffect, useCallback, createContext, useContext } from 'react';

interface CommandPaletteContextValue {
  isOpen: boolean;
  /** Open the palette, optionally pre-filling a query */
  open: (initialQuery?: string) => void;
  close: () => void;
  initialQuery: string;
}

export const CommandPaletteContext = createContext<CommandPaletteContextValue>({
  isOpen: false,
  open: () => {},
  close: () => {},
  initialQuery: '',
});

export function useCommandPalette(): CommandPaletteContextValue {
  return useContext(CommandPaletteContext);
}

/**
 * Internal hook used by CommandPaletteProvider to own the state and
 * register the global keyboard shortcut.
 */
export function useCommandPaletteState(): CommandPaletteContextValue {
  const [isOpen, setIsOpen] = useState(false);
  const [initialQuery, setInitialQuery] = useState('');

  const open = useCallback((query = '') => {
    setInitialQuery(query);
    setIsOpen(true);
  }, []);

  const close = useCallback(() => {
    setIsOpen(false);
    setInitialQuery('');
  }, []);

  // Register ⌘K / Ctrl+K globally
  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key === 'k') {
        e.preventDefault();
        e.stopPropagation();
        setIsOpen((prev) => !prev);
        if (!isOpen) setInitialQuery('');
      }
      if (e.key === 'Escape') {
        setIsOpen(false);
        setInitialQuery('');
      }
    };
    window.addEventListener('keydown', handler, { capture: true });
    return () => window.removeEventListener('keydown', handler, { capture: true });
  }, [isOpen]);

  return { isOpen, open, close, initialQuery };
}

export default useCommandPalette;
