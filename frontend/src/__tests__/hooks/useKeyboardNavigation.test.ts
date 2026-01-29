/**
 * Keyboard Navigation Hook Tests
 */

import { renderHook, act } from '@testing-library/react';
import { useKeyboardNavigation } from '../../hooks/useKeyboardNavigation';

describe('useKeyboardNavigation', () => {
  describe('Initialization', () => {
    it('initializes with default index', () => {
      const { result } = renderHook(() =>
        useKeyboardNavigation({ itemCount: 5 })
      );
      expect(result.current.focusedIndex).toBe(0);
    });

    it('initializes with custom initial index', () => {
      const { result } = renderHook(() =>
        useKeyboardNavigation({ itemCount: 5, initialIndex: 2 })
      );
      expect(result.current.focusedIndex).toBe(2);
    });
  });

  describe('Vertical Navigation', () => {
    it('moves down with ArrowDown', () => {
      const { result } = renderHook(() =>
        useKeyboardNavigation({ itemCount: 5, orientation: 'vertical' })
      );

      act(() => {
        result.current.handleKeyDown({
          key: 'ArrowDown',
          preventDefault: jest.fn(),
        } as unknown as React.KeyboardEvent);
      });

      expect(result.current.focusedIndex).toBe(1);
    });

    it('moves up with ArrowUp', () => {
      const { result } = renderHook(() =>
        useKeyboardNavigation({ itemCount: 5, orientation: 'vertical', initialIndex: 2 })
      );

      act(() => {
        result.current.handleKeyDown({
          key: 'ArrowUp',
          preventDefault: jest.fn(),
        } as unknown as React.KeyboardEvent);
      });

      expect(result.current.focusedIndex).toBe(1);
    });

    it('loops to end when moving up from first item', () => {
      const { result } = renderHook(() =>
        useKeyboardNavigation({ itemCount: 5, orientation: 'vertical', loop: true })
      );

      act(() => {
        result.current.handleKeyDown({
          key: 'ArrowUp',
          preventDefault: jest.fn(),
        } as unknown as React.KeyboardEvent);
      });

      expect(result.current.focusedIndex).toBe(4);
    });

    it('loops to start when moving down from last item', () => {
      const { result } = renderHook(() =>
        useKeyboardNavigation({ itemCount: 5, orientation: 'vertical', loop: true, initialIndex: 4 })
      );

      act(() => {
        result.current.handleKeyDown({
          key: 'ArrowDown',
          preventDefault: jest.fn(),
        } as unknown as React.KeyboardEvent);
      });

      expect(result.current.focusedIndex).toBe(0);
    });

    it('does not loop when loop is false', () => {
      const { result } = renderHook(() =>
        useKeyboardNavigation({ itemCount: 5, orientation: 'vertical', loop: false })
      );

      act(() => {
        result.current.handleKeyDown({
          key: 'ArrowUp',
          preventDefault: jest.fn(),
        } as unknown as React.KeyboardEvent);
      });

      expect(result.current.focusedIndex).toBe(0);
    });
  });

  describe('Horizontal Navigation', () => {
    it('moves right with ArrowRight', () => {
      const { result } = renderHook(() =>
        useKeyboardNavigation({ itemCount: 5, orientation: 'horizontal' })
      );

      act(() => {
        result.current.handleKeyDown({
          key: 'ArrowRight',
          preventDefault: jest.fn(),
        } as unknown as React.KeyboardEvent);
      });

      expect(result.current.focusedIndex).toBe(1);
    });

    it('moves left with ArrowLeft', () => {
      const { result } = renderHook(() =>
        useKeyboardNavigation({ itemCount: 5, orientation: 'horizontal', initialIndex: 2 })
      );

      act(() => {
        result.current.handleKeyDown({
          key: 'ArrowLeft',
          preventDefault: jest.fn(),
        } as unknown as React.KeyboardEvent);
      });

      expect(result.current.focusedIndex).toBe(1);
    });
  });

  describe('Grid Navigation', () => {
    it('moves down by column count in grid', () => {
      const { result } = renderHook(() =>
        useKeyboardNavigation({ itemCount: 9, orientation: 'grid', columns: 3 })
      );

      act(() => {
        result.current.handleKeyDown({
          key: 'ArrowDown',
          preventDefault: jest.fn(),
        } as unknown as React.KeyboardEvent);
      });

      expect(result.current.focusedIndex).toBe(3);
    });

    it('moves up by column count in grid', () => {
      const { result } = renderHook(() =>
        useKeyboardNavigation({ itemCount: 9, orientation: 'grid', columns: 3, initialIndex: 4 })
      );

      act(() => {
        result.current.handleKeyDown({
          key: 'ArrowUp',
          preventDefault: jest.fn(),
        } as unknown as React.KeyboardEvent);
      });

      expect(result.current.focusedIndex).toBe(1);
    });
  });

  describe('Home and End Keys', () => {
    it('moves to first item with Home', () => {
      const { result } = renderHook(() =>
        useKeyboardNavigation({ itemCount: 5, initialIndex: 3 })
      );

      act(() => {
        result.current.handleKeyDown({
          key: 'Home',
          preventDefault: jest.fn(),
        } as unknown as React.KeyboardEvent);
      });

      expect(result.current.focusedIndex).toBe(0);
    });

    it('moves to last item with End', () => {
      const { result } = renderHook(() =>
        useKeyboardNavigation({ itemCount: 5 })
      );

      act(() => {
        result.current.handleKeyDown({
          key: 'End',
          preventDefault: jest.fn(),
        } as unknown as React.KeyboardEvent);
      });

      expect(result.current.focusedIndex).toBe(4);
    });
  });

  describe('Selection', () => {
    it('calls onSelect with Enter', () => {
      const onSelect = jest.fn();
      const { result } = renderHook(() =>
        useKeyboardNavigation({ itemCount: 5, onSelect, initialIndex: 2 })
      );

      act(() => {
        result.current.handleKeyDown({
          key: 'Enter',
          preventDefault: jest.fn(),
        } as unknown as React.KeyboardEvent);
      });

      expect(onSelect).toHaveBeenCalledWith(2);
    });

    it('calls onSelect with Space', () => {
      const onSelect = jest.fn();
      const { result } = renderHook(() =>
        useKeyboardNavigation({ itemCount: 5, onSelect, initialIndex: 1 })
      );

      act(() => {
        result.current.handleKeyDown({
          key: ' ',
          preventDefault: jest.fn(),
        } as unknown as React.KeyboardEvent);
      });

      expect(onSelect).toHaveBeenCalledWith(1);
    });
  });

  describe('Focus Change Callback', () => {
    it('calls onFocusChange when focus changes', () => {
      const onFocusChange = jest.fn();
      const { result } = renderHook(() =>
        useKeyboardNavigation({ itemCount: 5, onFocusChange })
      );

      act(() => {
        result.current.handleKeyDown({
          key: 'ArrowDown',
          preventDefault: jest.fn(),
        } as unknown as React.KeyboardEvent);
      });

      expect(onFocusChange).toHaveBeenCalledWith(1);
    });
  });

  describe('Reset Focus', () => {
    it('resets focus to initial index', () => {
      const { result } = renderHook(() =>
        useKeyboardNavigation({ itemCount: 5, initialIndex: 0 })
      );

      act(() => {
        result.current.setFocusedIndex(3);
      });

      expect(result.current.focusedIndex).toBe(3);

      act(() => {
        result.current.resetFocus();
      });

      expect(result.current.focusedIndex).toBe(0);
    });
  });

  describe('getItemProps', () => {
    it('returns correct props for focused item', () => {
      const { result } = renderHook(() =>
        useKeyboardNavigation({ itemCount: 5, initialIndex: 2 })
      );

      const props = result.current.getItemProps(2);

      expect(props.tabIndex).toBe(0);
      expect(props['aria-selected']).toBe(true);
    });

    it('returns correct props for non-focused item', () => {
      const { result } = renderHook(() =>
        useKeyboardNavigation({ itemCount: 5, initialIndex: 2 })
      );

      const props = result.current.getItemProps(0);

      expect(props.tabIndex).toBe(-1);
      expect(props['aria-selected']).toBe(false);
    });
  });

  describe('Escape Key', () => {
    it('resets focus on Escape', () => {
      const { result } = renderHook(() =>
        useKeyboardNavigation({ itemCount: 5, initialIndex: 0 })
      );

      act(() => {
        result.current.setFocusedIndex(3);
      });

      act(() => {
        result.current.handleKeyDown({
          key: 'Escape',
          preventDefault: jest.fn(),
        } as unknown as React.KeyboardEvent);
      });

      expect(result.current.focusedIndex).toBe(0);
    });
  });
});
