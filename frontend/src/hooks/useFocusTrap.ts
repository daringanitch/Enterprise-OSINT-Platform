/**
 * Focus Trap Hook
 *
 * Traps focus within a container element for modals and dialogs.
 * Implements WCAG 2.1 focus management requirements.
 */

import { useCallback, useEffect, useRef } from 'react';

const FOCUSABLE_SELECTORS = [
  'a[href]',
  'area[href]',
  'input:not([disabled]):not([type="hidden"])',
  'select:not([disabled])',
  'textarea:not([disabled])',
  'button:not([disabled])',
  'iframe',
  'object',
  'embed',
  '[contenteditable]',
  '[tabindex]:not([tabindex="-1"])',
].join(',');

export interface UseFocusTrapOptions {
  /** Whether the trap is active */
  enabled?: boolean;
  /** Return focus to trigger element on deactivate */
  returnFocus?: boolean;
  /** Initial element to focus (selector or element) */
  initialFocus?: string | HTMLElement | null;
  /** Element to focus when trap is deactivated */
  finalFocus?: string | HTMLElement | null;
  /** Allow focus to escape the trap */
  allowOutsideClick?: boolean;
  /** Callback when escape is pressed */
  onEscape?: () => void;
}

export interface UseFocusTrapReturn {
  /** Ref to attach to the container element */
  containerRef: React.RefObject<HTMLDivElement>;
  /** Activate the focus trap manually */
  activate: () => void;
  /** Deactivate the focus trap manually */
  deactivate: () => void;
  /** Check if an element is focusable */
  isFocusable: (element: HTMLElement) => boolean;
}

export function useFocusTrap({
  enabled = true,
  returnFocus = true,
  initialFocus,
  finalFocus,
  allowOutsideClick = false,
  onEscape,
}: UseFocusTrapOptions = {}): UseFocusTrapReturn {
  const containerRef = useRef<HTMLDivElement>(null);
  const previousActiveElement = useRef<HTMLElement | null>(null);
  const isActive = useRef(false);

  const getFocusableElements = useCallback(() => {
    if (!containerRef.current) return [];
    const elements = containerRef.current.querySelectorAll(FOCUSABLE_SELECTORS);
    return Array.from(elements).filter(
      (el) => !el.hasAttribute('disabled') && el.getAttribute('tabindex') !== '-1'
    ) as HTMLElement[];
  }, []);

  const getFirstFocusable = useCallback(() => {
    const elements = getFocusableElements();
    return elements[0] || null;
  }, [getFocusableElements]);

  const getLastFocusable = useCallback(() => {
    const elements = getFocusableElements();
    return elements[elements.length - 1] || null;
  }, [getFocusableElements]);

  const isFocusable = useCallback((element: HTMLElement) => {
    return element.matches(FOCUSABLE_SELECTORS) && !element.hasAttribute('disabled');
  }, []);

  const focusInitialElement = useCallback(() => {
    if (!containerRef.current) return;

    let elementToFocus: HTMLElement | null = null;

    if (typeof initialFocus === 'string') {
      elementToFocus = containerRef.current.querySelector(initialFocus);
    } else if (initialFocus instanceof HTMLElement) {
      elementToFocus = initialFocus;
    }

    if (!elementToFocus) {
      // Try to find element with autofocus
      elementToFocus = containerRef.current.querySelector('[autofocus]');
    }

    if (!elementToFocus) {
      elementToFocus = getFirstFocusable();
    }

    if (!elementToFocus) {
      // Focus the container itself if no focusable elements
      elementToFocus = containerRef.current;
      elementToFocus.setAttribute('tabindex', '-1');
    }

    elementToFocus?.focus();
  }, [initialFocus, getFirstFocusable]);

  const handleKeyDown = useCallback(
    (event: KeyboardEvent) => {
      if (!isActive.current || !containerRef.current) return;

      if (event.key === 'Escape') {
        event.preventDefault();
        onEscape?.();
        return;
      }

      if (event.key !== 'Tab') return;

      const focusableElements = getFocusableElements();
      if (focusableElements.length === 0) {
        event.preventDefault();
        return;
      }

      const firstElement = focusableElements[0];
      const lastElement = focusableElements[focusableElements.length - 1];
      const activeElement = document.activeElement;

      // Shift + Tab
      if (event.shiftKey) {
        if (activeElement === firstElement || !containerRef.current.contains(activeElement)) {
          event.preventDefault();
          lastElement.focus();
        }
      } else {
        // Tab
        if (activeElement === lastElement || !containerRef.current.contains(activeElement)) {
          event.preventDefault();
          firstElement.focus();
        }
      }
    },
    [getFocusableElements, onEscape]
  );

  const handleFocusIn = useCallback(
    (event: FocusEvent) => {
      if (!isActive.current || !containerRef.current || allowOutsideClick) return;

      const target = event.target as HTMLElement;
      if (!containerRef.current.contains(target)) {
        event.preventDefault();
        event.stopPropagation();
        focusInitialElement();
      }
    },
    [allowOutsideClick, focusInitialElement]
  );

  const handleClickOutside = useCallback(
    (event: MouseEvent) => {
      if (!isActive.current || !containerRef.current || allowOutsideClick) return;

      const target = event.target as HTMLElement;
      if (!containerRef.current.contains(target)) {
        event.preventDefault();
        event.stopPropagation();
      }
    },
    [allowOutsideClick]
  );

  const activate = useCallback(() => {
    if (isActive.current) return;

    previousActiveElement.current = document.activeElement as HTMLElement;
    isActive.current = true;

    // Small delay to ensure DOM is ready
    requestAnimationFrame(() => {
      focusInitialElement();
    });
  }, [focusInitialElement]);

  const deactivate = useCallback(() => {
    if (!isActive.current) return;

    isActive.current = false;

    if (returnFocus) {
      let elementToFocus: HTMLElement | null = null;

      if (typeof finalFocus === 'string') {
        elementToFocus = document.querySelector(finalFocus);
      } else if (finalFocus instanceof HTMLElement) {
        elementToFocus = finalFocus;
      } else {
        elementToFocus = previousActiveElement.current;
      }

      elementToFocus?.focus();
    }
  }, [returnFocus, finalFocus]);

  useEffect(() => {
    if (enabled) {
      activate();
    } else {
      deactivate();
    }

    return () => {
      deactivate();
    };
  }, [enabled, activate, deactivate]);

  useEffect(() => {
    if (!enabled) return;

    document.addEventListener('keydown', handleKeyDown);
    document.addEventListener('focusin', handleFocusIn);
    document.addEventListener('mousedown', handleClickOutside);

    return () => {
      document.removeEventListener('keydown', handleKeyDown);
      document.removeEventListener('focusin', handleFocusIn);
      document.removeEventListener('mousedown', handleClickOutside);
    };
  }, [enabled, handleKeyDown, handleFocusIn, handleClickOutside]);

  return {
    containerRef,
    activate,
    deactivate,
    isFocusable,
  };
}

export default useFocusTrap;
