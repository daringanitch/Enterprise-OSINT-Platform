/**
 * Keyboard Navigation Hooks
 *
 * Provides keyboard navigation support for lists, menus, and grids.
 */

import { useCallback, useEffect, useRef, useState } from 'react';

export interface UseKeyboardNavigationOptions {
  /** Total number of items */
  itemCount: number;
  /** Orientation of the list */
  orientation?: 'vertical' | 'horizontal' | 'grid';
  /** Number of columns for grid orientation */
  columns?: number;
  /** Enable wrap-around navigation */
  loop?: boolean;
  /** Callback when item is selected (Enter/Space) */
  onSelect?: (index: number) => void;
  /** Callback when focus changes */
  onFocusChange?: (index: number) => void;
  /** Initial focused index */
  initialIndex?: number;
  /** Enable type-ahead search */
  typeAhead?: boolean;
}

export interface UseKeyboardNavigationReturn {
  /** Currently focused index */
  focusedIndex: number;
  /** Set focused index manually */
  setFocusedIndex: (index: number) => void;
  /** Key down handler to attach to container */
  handleKeyDown: (event: React.KeyboardEvent) => void;
  /** Get props for an item at index */
  getItemProps: (index: number) => {
    tabIndex: number;
    'aria-selected': boolean;
    onFocus: () => void;
    onClick: () => void;
  };
  /** Reset focus to initial state */
  resetFocus: () => void;
}

export function useKeyboardNavigation({
  itemCount,
  orientation = 'vertical',
  columns = 1,
  loop = true,
  onSelect,
  onFocusChange,
  initialIndex = 0,
  typeAhead = false,
}: UseKeyboardNavigationOptions): UseKeyboardNavigationReturn {
  const [focusedIndex, setFocusedIndex] = useState(initialIndex);
  const typeAheadBuffer = useRef('');
  const typeAheadTimeout = useRef<NodeJS.Timeout>();

  const moveFocus = useCallback(
    (direction: 'up' | 'down' | 'left' | 'right' | 'home' | 'end') => {
      setFocusedIndex((current) => {
        let next = current;

        switch (direction) {
          case 'up':
            if (orientation === 'grid') {
              next = current - columns;
            } else if (orientation === 'vertical') {
              next = current - 1;
            }
            break;
          case 'down':
            if (orientation === 'grid') {
              next = current + columns;
            } else if (orientation === 'vertical') {
              next = current + 1;
            }
            break;
          case 'left':
            if (orientation === 'grid' || orientation === 'horizontal') {
              next = current - 1;
            }
            break;
          case 'right':
            if (orientation === 'grid' || orientation === 'horizontal') {
              next = current + 1;
            }
            break;
          case 'home':
            next = 0;
            break;
          case 'end':
            next = itemCount - 1;
            break;
        }

        // Handle boundaries
        if (next < 0) {
          next = loop ? itemCount - 1 : 0;
        } else if (next >= itemCount) {
          next = loop ? 0 : itemCount - 1;
        }

        return next;
      });
    },
    [itemCount, orientation, columns, loop]
  );

  useEffect(() => {
    onFocusChange?.(focusedIndex);
  }, [focusedIndex, onFocusChange]);

  const handleKeyDown = useCallback(
    (event: React.KeyboardEvent) => {
      const { key } = event;

      // Type-ahead search
      if (typeAhead && key.length === 1 && !event.ctrlKey && !event.metaKey) {
        event.preventDefault();
        typeAheadBuffer.current += key.toLowerCase();

        if (typeAheadTimeout.current) {
          clearTimeout(typeAheadTimeout.current);
        }
        typeAheadTimeout.current = setTimeout(() => {
          typeAheadBuffer.current = '';
        }, 500);

        return;
      }

      switch (key) {
        case 'ArrowUp':
          event.preventDefault();
          moveFocus('up');
          break;
        case 'ArrowDown':
          event.preventDefault();
          moveFocus('down');
          break;
        case 'ArrowLeft':
          event.preventDefault();
          moveFocus('left');
          break;
        case 'ArrowRight':
          event.preventDefault();
          moveFocus('right');
          break;
        case 'Home':
          event.preventDefault();
          moveFocus('home');
          break;
        case 'End':
          event.preventDefault();
          moveFocus('end');
          break;
        case 'Enter':
        case ' ':
          event.preventDefault();
          onSelect?.(focusedIndex);
          break;
        case 'Escape':
          event.preventDefault();
          setFocusedIndex(initialIndex);
          break;
      }
    },
    [moveFocus, focusedIndex, onSelect, initialIndex, typeAhead]
  );

  const getItemProps = useCallback(
    (index: number) => ({
      tabIndex: index === focusedIndex ? 0 : -1,
      'aria-selected': index === focusedIndex,
      onFocus: () => setFocusedIndex(index),
      onClick: () => {
        setFocusedIndex(index);
        onSelect?.(index);
      },
    }),
    [focusedIndex, onSelect]
  );

  const resetFocus = useCallback(() => {
    setFocusedIndex(initialIndex);
  }, [initialIndex]);

  return {
    focusedIndex,
    setFocusedIndex,
    handleKeyDown,
    getItemProps,
    resetFocus,
  };
}

/**
 * Hook for roving tabindex pattern
 */
export interface UseRovingTabIndexOptions {
  /** Ref to the container element */
  containerRef: React.RefObject<HTMLElement>;
  /** Selector for focusable items */
  itemSelector?: string;
  /** Enable wrap-around */
  loop?: boolean;
  /** Orientation */
  orientation?: 'vertical' | 'horizontal';
}

export function useRovingTabIndex({
  containerRef,
  itemSelector = '[role="option"], [role="menuitem"], [role="tab"], button, a',
  loop = true,
  orientation = 'vertical',
}: UseRovingTabIndexOptions) {
  const [activeIndex, setActiveIndex] = useState(0);

  const getItems = useCallback(() => {
    if (!containerRef.current) return [];
    return Array.from(containerRef.current.querySelectorAll(itemSelector)) as HTMLElement[];
  }, [containerRef, itemSelector]);

  const focusItem = useCallback(
    (index: number) => {
      const items = getItems();
      if (items[index]) {
        items[index].focus();
        setActiveIndex(index);
      }
    },
    [getItems]
  );

  const handleKeyDown = useCallback(
    (event: React.KeyboardEvent) => {
      const items = getItems();
      const count = items.length;

      if (count === 0) return;

      const prevKey = orientation === 'vertical' ? 'ArrowUp' : 'ArrowLeft';
      const nextKey = orientation === 'vertical' ? 'ArrowDown' : 'ArrowRight';

      let newIndex = activeIndex;

      switch (event.key) {
        case prevKey:
          event.preventDefault();
          newIndex = activeIndex - 1;
          if (newIndex < 0) newIndex = loop ? count - 1 : 0;
          break;
        case nextKey:
          event.preventDefault();
          newIndex = activeIndex + 1;
          if (newIndex >= count) newIndex = loop ? 0 : count - 1;
          break;
        case 'Home':
          event.preventDefault();
          newIndex = 0;
          break;
        case 'End':
          event.preventDefault();
          newIndex = count - 1;
          break;
        default:
          return;
      }

      focusItem(newIndex);
    },
    [activeIndex, getItems, loop, orientation, focusItem]
  );

  return {
    activeIndex,
    setActiveIndex,
    handleKeyDown,
    focusItem,
  };
}

export default useKeyboardNavigation;
