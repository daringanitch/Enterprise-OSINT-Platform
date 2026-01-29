/**
 * Media Query Hooks
 *
 * Responsive design utilities for handling breakpoints
 * and media queries in React components.
 */

import { useCallback, useEffect, useState } from 'react';
import { designTokens } from '../utils/theme';

/**
 * Check if a media query matches
 */
export function useMediaQuery(query: string): boolean {
  const [matches, setMatches] = useState(() => {
    if (typeof window !== 'undefined') {
      return window.matchMedia(query).matches;
    }
    return false;
  });

  useEffect(() => {
    if (typeof window === 'undefined') return;

    const mediaQuery = window.matchMedia(query);
    setMatches(mediaQuery.matches);

    const handleChange = (event: MediaQueryListEvent) => {
      setMatches(event.matches);
    };

    // Modern browsers
    if (mediaQuery.addEventListener) {
      mediaQuery.addEventListener('change', handleChange);
      return () => mediaQuery.removeEventListener('change', handleChange);
    } else {
      // Legacy browsers
      mediaQuery.addListener(handleChange);
      return () => mediaQuery.removeListener(handleChange);
    }
  }, [query]);

  return matches;
}

/**
 * Breakpoint hooks based on design tokens
 */
export function useBreakpoint() {
  const isMobile = useMediaQuery(`(max-width: ${designTokens.breakpoints.sm - 1}px)`);
  const isTablet = useMediaQuery(
    `(min-width: ${designTokens.breakpoints.sm}px) and (max-width: ${designTokens.breakpoints.md - 1}px)`
  );
  const isDesktop = useMediaQuery(`(min-width: ${designTokens.breakpoints.md}px)`);
  const isLargeDesktop = useMediaQuery(`(min-width: ${designTokens.breakpoints.lg}px)`);
  const isExtraLarge = useMediaQuery(`(min-width: ${designTokens.breakpoints.xl}px)`);

  return {
    isMobile,
    isTablet,
    isDesktop,
    isLargeDesktop,
    isExtraLarge,
    // Convenience aliases
    isSmUp: !isMobile,
    isMdUp: isDesktop || isLargeDesktop || isExtraLarge,
    isLgUp: isLargeDesktop || isExtraLarge,
    isXlUp: isExtraLarge,
  };
}

/**
 * Check for reduced motion preference
 */
export function usePrefersReducedMotion(): boolean {
  return useMediaQuery('(prefers-reduced-motion: reduce)');
}

/**
 * Check for dark mode preference
 */
export function usePrefersDarkMode(): boolean {
  return useMediaQuery('(prefers-color-scheme: dark)');
}

/**
 * Check for high contrast preference
 */
export function usePrefersHighContrast(): boolean {
  return useMediaQuery('(prefers-contrast: more)');
}

/**
 * Get current breakpoint name
 */
export type BreakpointName = 'xs' | 'sm' | 'md' | 'lg' | 'xl';

export function useCurrentBreakpoint(): BreakpointName {
  const { isMobile, isTablet, isDesktop, isLargeDesktop, isExtraLarge } = useBreakpoint();

  if (isExtraLarge) return 'xl';
  if (isLargeDesktop) return 'lg';
  if (isDesktop) return 'md';
  if (isTablet) return 'sm';
  return 'xs';
}

/**
 * Responsive value selector
 */
export function useResponsiveValue<T>(values: Partial<Record<BreakpointName, T>>, defaultValue: T): T {
  const breakpoint = useCurrentBreakpoint();

  const getValue = useCallback((): T => {
    // Try current breakpoint and fall back to smaller ones
    const breakpoints: BreakpointName[] = ['xl', 'lg', 'md', 'sm', 'xs'];
    const currentIndex = breakpoints.indexOf(breakpoint);

    for (let i = currentIndex; i < breakpoints.length; i++) {
      const bp = breakpoints[i];
      if (values[bp] !== undefined) {
        return values[bp] as T;
      }
    }

    return defaultValue;
  }, [breakpoint, values, defaultValue]);

  return getValue();
}

/**
 * Window size hook
 */
export interface WindowSize {
  width: number;
  height: number;
}

export function useWindowSize(): WindowSize {
  const [size, setSize] = useState<WindowSize>(() => {
    if (typeof window !== 'undefined') {
      return {
        width: window.innerWidth,
        height: window.innerHeight,
      };
    }
    return { width: 0, height: 0 };
  });

  useEffect(() => {
    if (typeof window === 'undefined') return;

    let timeoutId: NodeJS.Timeout;

    const handleResize = () => {
      // Debounce resize events
      clearTimeout(timeoutId);
      timeoutId = setTimeout(() => {
        setSize({
          width: window.innerWidth,
          height: window.innerHeight,
        });
      }, 100);
    };

    window.addEventListener('resize', handleResize);
    return () => {
      window.removeEventListener('resize', handleResize);
      clearTimeout(timeoutId);
    };
  }, []);

  return size;
}

/**
 * Touch device detection
 */
export function useIsTouchDevice(): boolean {
  const [isTouch, setIsTouch] = useState(false);

  useEffect(() => {
    const checkTouch = () => {
      setIsTouch(
        'ontouchstart' in window ||
          navigator.maxTouchPoints > 0 ||
          (navigator as any).msMaxTouchPoints > 0
      );
    };

    checkTouch();
  }, []);

  return isTouch;
}

/**
 * Orientation detection
 */
export type Orientation = 'portrait' | 'landscape';

export function useOrientation(): Orientation {
  const isPortrait = useMediaQuery('(orientation: portrait)');
  return isPortrait ? 'portrait' : 'landscape';
}

export default useMediaQuery;
