/**
 * Accessibility Utilities
 *
 * Helper functions for accessibility features including
 * color contrast, focus management, and ARIA helpers.
 */

import { designTokens } from './theme';

// =============================================================================
// Color Contrast Utilities
// =============================================================================

/**
 * Calculate relative luminance of a color
 * Based on WCAG 2.1 specification
 */
export function getLuminance(hex: string): number {
  const rgb = hexToRgb(hex);
  if (!rgb) return 0;

  const [r, g, b] = [rgb.r, rgb.g, rgb.b].map((val) => {
    const normalized = val / 255;
    return normalized <= 0.03928
      ? normalized / 12.92
      : Math.pow((normalized + 0.055) / 1.055, 2.4);
  });

  return 0.2126 * r + 0.7152 * g + 0.0722 * b;
}

/**
 * Calculate contrast ratio between two colors
 * Returns a value between 1 and 21
 */
export function getContrastRatio(hex1: string, hex2: string): number {
  const lum1 = getLuminance(hex1);
  const lum2 = getLuminance(hex2);
  const lighter = Math.max(lum1, lum2);
  const darker = Math.min(lum1, lum2);
  return (lighter + 0.05) / (darker + 0.05);
}

/**
 * Check if contrast meets WCAG AA requirements
 * Normal text: 4.5:1, Large text: 3:1
 */
export function meetsWCAG_AA(
  foreground: string,
  background: string,
  isLargeText = false
): boolean {
  const ratio = getContrastRatio(foreground, background);
  return isLargeText ? ratio >= 3 : ratio >= 4.5;
}

/**
 * Check if contrast meets WCAG AAA requirements
 * Normal text: 7:1, Large text: 4.5:1
 */
export function meetsWCAG_AAA(
  foreground: string,
  background: string,
  isLargeText = false
): boolean {
  const ratio = getContrastRatio(foreground, background);
  return isLargeText ? ratio >= 4.5 : ratio >= 7;
}

/**
 * Convert hex color to RGB
 */
export function hexToRgb(hex: string): { r: number; g: number; b: number } | null {
  const result = /^#?([a-f\d]{2})([a-f\d]{2})([a-f\d]{2})$/i.exec(hex);
  return result
    ? {
        r: parseInt(result[1], 16),
        g: parseInt(result[2], 16),
        b: parseInt(result[3], 16),
      }
    : null;
}

/**
 * Get accessible text color for a background
 */
export function getAccessibleTextColor(backgroundColor: string): string {
  const luminance = getLuminance(backgroundColor);
  return luminance > 0.179 ? '#000000' : '#ffffff';
}

// =============================================================================
// Focus Management
// =============================================================================

const FOCUSABLE_SELECTOR = [
  'a[href]',
  'area[href]',
  'input:not([disabled]):not([type="hidden"])',
  'select:not([disabled])',
  'textarea:not([disabled])',
  'button:not([disabled])',
  'iframe',
  '[contenteditable]',
  '[tabindex]:not([tabindex="-1"])',
].join(',');

/**
 * Get all focusable elements within a container
 */
export function getFocusableElements(container: HTMLElement): HTMLElement[] {
  return Array.from(container.querySelectorAll(FOCUSABLE_SELECTOR)) as HTMLElement[];
}

/**
 * Get first focusable element
 */
export function getFirstFocusable(container: HTMLElement): HTMLElement | null {
  const elements = getFocusableElements(container);
  return elements[0] || null;
}

/**
 * Get last focusable element
 */
export function getLastFocusable(container: HTMLElement): HTMLElement | null {
  const elements = getFocusableElements(container);
  return elements[elements.length - 1] || null;
}

/**
 * Move focus to next/previous focusable element
 */
export function moveFocus(
  container: HTMLElement,
  direction: 'next' | 'previous',
  loop = true
): void {
  const elements = getFocusableElements(container);
  const currentIndex = elements.indexOf(document.activeElement as HTMLElement);

  let nextIndex: number;
  if (direction === 'next') {
    nextIndex = currentIndex + 1;
    if (nextIndex >= elements.length) {
      nextIndex = loop ? 0 : elements.length - 1;
    }
  } else {
    nextIndex = currentIndex - 1;
    if (nextIndex < 0) {
      nextIndex = loop ? elements.length - 1 : 0;
    }
  }

  elements[nextIndex]?.focus();
}

/**
 * Save and restore focus
 */
export function createFocusManager() {
  let savedElement: HTMLElement | null = null;

  return {
    save: () => {
      savedElement = document.activeElement as HTMLElement;
    },
    restore: () => {
      savedElement?.focus();
      savedElement = null;
    },
    clear: () => {
      savedElement = null;
    },
  };
}

// =============================================================================
// ARIA Helpers
// =============================================================================

/**
 * Generate unique ID for ARIA relationships
 */
let idCounter = 0;
export function generateId(prefix = 'aria'): string {
  return `${prefix}-${++idCounter}`;
}

/**
 * Set up ARIA relationship between elements
 */
export function linkAriaDescribedBy(
  element: HTMLElement,
  descriptionElement: HTMLElement
): () => void {
  const id = descriptionElement.id || generateId('description');
  descriptionElement.id = id;

  const existing = element.getAttribute('aria-describedby');
  const newValue = existing ? `${existing} ${id}` : id;
  element.setAttribute('aria-describedby', newValue);

  return () => {
    const current = element.getAttribute('aria-describedby');
    if (current) {
      const updated = current
        .split(' ')
        .filter((i) => i !== id)
        .join(' ');
      if (updated) {
        element.setAttribute('aria-describedby', updated);
      } else {
        element.removeAttribute('aria-describedby');
      }
    }
  };
}

/**
 * Create accessible name for an element
 */
export function getAccessibleName(element: HTMLElement): string {
  // Check aria-label
  const ariaLabel = element.getAttribute('aria-label');
  if (ariaLabel) return ariaLabel;

  // Check aria-labelledby
  const labelledBy = element.getAttribute('aria-labelledby');
  if (labelledBy) {
    const labels = labelledBy
      .split(' ')
      .map((id) => document.getElementById(id)?.textContent)
      .filter(Boolean);
    if (labels.length) return labels.join(' ');
  }

  // Check for associated label
  if (element.id) {
    const label = document.querySelector(`label[for="${element.id}"]`);
    if (label) return label.textContent || '';
  }

  // Check text content
  return element.textContent?.trim() || '';
}

// =============================================================================
// Reduced Motion
// =============================================================================

/**
 * Check if user prefers reduced motion
 */
export function prefersReducedMotion(): boolean {
  if (typeof window === 'undefined') return false;
  return window.matchMedia('(prefers-reduced-motion: reduce)').matches;
}

/**
 * Get animation duration based on reduced motion preference
 */
export function getAnimationDuration(normalDuration: number): number {
  return prefersReducedMotion() ? 0 : normalDuration;
}

/**
 * Get transition CSS based on reduced motion preference
 */
export function getTransition(property: string, duration: string): string {
  return prefersReducedMotion() ? 'none' : `${property} ${duration}`;
}

// =============================================================================
// Theme Contrast Verification
// =============================================================================

/**
 * Verify design token color contrasts
 */
export function verifyThemeContrast(): Record<string, { ratio: number; meetsAA: boolean }> {
  const results: Record<string, { ratio: number; meetsAA: boolean }> = {};
  const background = designTokens.colors.background.paper;

  // Check text colors
  results['text.primary'] = {
    ratio: getContrastRatio(designTokens.colors.text.primary, background),
    meetsAA: meetsWCAG_AA(designTokens.colors.text.primary, background),
  };

  results['text.secondary'] = {
    ratio: getContrastRatio(designTokens.colors.text.secondary, background),
    meetsAA: meetsWCAG_AA(designTokens.colors.text.secondary, background),
  };

  // Check status colors
  const statusColors = ['success', 'warning', 'error', 'info'] as const;
  for (const status of statusColors) {
    const color = designTokens.colors[status].main;
    results[`${status}.main`] = {
      ratio: getContrastRatio(color, background),
      meetsAA: meetsWCAG_AA(color, background, true), // Large text threshold
    };
  }

  return results;
}

export default {
  getLuminance,
  getContrastRatio,
  meetsWCAG_AA,
  meetsWCAG_AAA,
  hexToRgb,
  getAccessibleTextColor,
  getFocusableElements,
  getFirstFocusable,
  getLastFocusable,
  moveFocus,
  createFocusManager,
  generateId,
  linkAriaDescribedBy,
  getAccessibleName,
  prefersReducedMotion,
  getAnimationDuration,
  getTransition,
  verifyThemeContrast,
};
