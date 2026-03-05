/**
 * Tests for src/hooks/useCommandPalette.ts
 */

import { renderHook, act } from '@testing-library/react';
import { useCommandPaletteState, CommandPaletteContext } from '../../hooks/useCommandPalette';
import { useContext } from 'react';

// ─────────────────────────────────────────────────────────────────────────────
// useCommandPaletteState — initial state
// ─────────────────────────────────────────────────────────────────────────────
describe('useCommandPaletteState — initial state', () => {
  it('is closed by default', () => {
    const { result } = renderHook(() => useCommandPaletteState());
    expect(result.current.isOpen).toBe(false);
    expect(result.current.initialQuery).toBe('');
  });

  it('exposes open and close functions', () => {
    const { result } = renderHook(() => useCommandPaletteState());
    expect(typeof result.current.open).toBe('function');
    expect(typeof result.current.close).toBe('function');
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// open()
// ─────────────────────────────────────────────────────────────────────────────
describe('useCommandPaletteState — open()', () => {
  it('opens the palette', () => {
    const { result } = renderHook(() => useCommandPaletteState());
    act(() => { result.current.open(); });
    expect(result.current.isOpen).toBe(true);
  });

  it('opens with an empty query by default', () => {
    const { result } = renderHook(() => useCommandPaletteState());
    act(() => { result.current.open(); });
    expect(result.current.initialQuery).toBe('');
  });

  it('opens with a pre-filled query when provided', () => {
    const { result } = renderHook(() => useCommandPaletteState());
    act(() => { result.current.open('192.168.1.1'); });
    expect(result.current.isOpen).toBe(true);
    expect(result.current.initialQuery).toBe('192.168.1.1');
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// close()
// ─────────────────────────────────────────────────────────────────────────────
describe('useCommandPaletteState — close()', () => {
  it('closes the palette', () => {
    const { result } = renderHook(() => useCommandPaletteState());
    act(() => { result.current.open('test'); });
    act(() => { result.current.close(); });
    expect(result.current.isOpen).toBe(false);
  });

  it('clears the initialQuery when closing', () => {
    const { result } = renderHook(() => useCommandPaletteState());
    act(() => { result.current.open('some query'); });
    act(() => { result.current.close(); });
    expect(result.current.initialQuery).toBe('');
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Keyboard shortcut — ⌘K / Ctrl+K
// ─────────────────────────────────────────────────────────────────────────────
describe('useCommandPaletteState — keyboard shortcuts', () => {
  it('toggles open on Ctrl+K', () => {
    const { result } = renderHook(() => useCommandPaletteState());
    expect(result.current.isOpen).toBe(false);

    act(() => {
      window.dispatchEvent(
        new KeyboardEvent('keydown', { key: 'k', ctrlKey: true, bubbles: true })
      );
    });
    expect(result.current.isOpen).toBe(true);

    act(() => {
      window.dispatchEvent(
        new KeyboardEvent('keydown', { key: 'k', ctrlKey: true, bubbles: true })
      );
    });
    expect(result.current.isOpen).toBe(false);
  });

  it('toggles open on Meta+K (⌘K)', () => {
    const { result } = renderHook(() => useCommandPaletteState());

    act(() => {
      window.dispatchEvent(
        new KeyboardEvent('keydown', { key: 'k', metaKey: true, bubbles: true })
      );
    });
    expect(result.current.isOpen).toBe(true);
  });

  it('closes on Escape', () => {
    const { result } = renderHook(() => useCommandPaletteState());
    act(() => { result.current.open(); });
    expect(result.current.isOpen).toBe(true);

    act(() => {
      window.dispatchEvent(
        new KeyboardEvent('keydown', { key: 'Escape', bubbles: true })
      );
    });
    expect(result.current.isOpen).toBe(false);
  });

  it('does not toggle on K without modifier', () => {
    const { result } = renderHook(() => useCommandPaletteState());
    act(() => {
      window.dispatchEvent(
        new KeyboardEvent('keydown', { key: 'k', bubbles: true })
      );
    });
    expect(result.current.isOpen).toBe(false);
  });

  it('cleans up the event listener on unmount', () => {
    const addSpy = jest.spyOn(window, 'addEventListener');
    const removeSpy = jest.spyOn(window, 'removeEventListener');

    const { unmount } = renderHook(() => useCommandPaletteState());
    const addCalls = addSpy.mock.calls.filter(([e]) => e === 'keydown').length;
    unmount();
    const removeCalls = removeSpy.mock.calls.filter(([e]) => e === 'keydown').length;

    // Should add and remove the same number of keydown listeners
    expect(addCalls).toBeGreaterThan(0);
    expect(removeCalls).toBeGreaterThanOrEqual(addCalls);

    addSpy.mockRestore();
    removeSpy.mockRestore();
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// CommandPaletteContext default values
// ─────────────────────────────────────────────────────────────────────────────
describe('CommandPaletteContext — default values', () => {
  it('provides safe default no-op implementations', () => {
    const { result } = renderHook(() => useContext(CommandPaletteContext));
    expect(result.current.isOpen).toBe(false);
    expect(result.current.initialQuery).toBe('');
    // Should not throw when called
    expect(() => result.current.open()).not.toThrow();
    expect(() => result.current.close()).not.toThrow();
  });
});
