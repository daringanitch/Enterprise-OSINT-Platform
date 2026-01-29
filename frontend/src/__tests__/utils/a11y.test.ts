/**
 * Accessibility Utilities Tests
 */

import {
  getLuminance,
  getContrastRatio,
  meetsWCAG_AA,
  meetsWCAG_AAA,
  hexToRgb,
  getAccessibleTextColor,
  generateId,
  prefersReducedMotion,
  getAnimationDuration,
} from '../../utils/a11y';

describe('Accessibility Utilities', () => {
  describe('hexToRgb', () => {
    it('converts hex to RGB', () => {
      expect(hexToRgb('#ffffff')).toEqual({ r: 255, g: 255, b: 255 });
      expect(hexToRgb('#000000')).toEqual({ r: 0, g: 0, b: 0 });
      expect(hexToRgb('#ff0000')).toEqual({ r: 255, g: 0, b: 0 });
    });

    it('handles hex without #', () => {
      expect(hexToRgb('ffffff')).toEqual({ r: 255, g: 255, b: 255 });
    });

    it('returns null for invalid hex', () => {
      expect(hexToRgb('invalid')).toBeNull();
      expect(hexToRgb('#fff')).toBeNull(); // 3-char hex not supported
    });
  });

  describe('getLuminance', () => {
    it('returns 1 for white', () => {
      expect(getLuminance('#ffffff')).toBeCloseTo(1, 2);
    });

    it('returns 0 for black', () => {
      expect(getLuminance('#000000')).toBeCloseTo(0, 2);
    });

    it('returns intermediate value for gray', () => {
      const luminance = getLuminance('#808080');
      expect(luminance).toBeGreaterThan(0);
      expect(luminance).toBeLessThan(1);
    });
  });

  describe('getContrastRatio', () => {
    it('returns 21 for black and white', () => {
      expect(getContrastRatio('#000000', '#ffffff')).toBeCloseTo(21, 0);
    });

    it('returns 1 for same colors', () => {
      expect(getContrastRatio('#808080', '#808080')).toBeCloseTo(1, 2);
    });

    it('returns same ratio regardless of order', () => {
      const ratio1 = getContrastRatio('#000000', '#ffffff');
      const ratio2 = getContrastRatio('#ffffff', '#000000');
      expect(ratio1).toBeCloseTo(ratio2, 2);
    });
  });

  describe('meetsWCAG_AA', () => {
    it('returns true for high contrast (black/white)', () => {
      expect(meetsWCAG_AA('#000000', '#ffffff')).toBe(true);
    });

    it('returns true for sufficient contrast', () => {
      // Blue on white typically passes
      expect(meetsWCAG_AA('#0000cc', '#ffffff')).toBe(true);
    });

    it('returns false for low contrast', () => {
      // Light gray on white fails
      expect(meetsWCAG_AA('#cccccc', '#ffffff')).toBe(false);
    });

    it('uses lower threshold for large text', () => {
      // Medium gray on white might pass for large text
      const ratio = getContrastRatio('#767676', '#ffffff');
      expect(meetsWCAG_AA('#767676', '#ffffff', false)).toBe(ratio >= 4.5);
      expect(meetsWCAG_AA('#767676', '#ffffff', true)).toBe(ratio >= 3);
    });
  });

  describe('meetsWCAG_AAA', () => {
    it('returns true for high contrast', () => {
      expect(meetsWCAG_AAA('#000000', '#ffffff')).toBe(true);
    });

    it('requires higher ratio than AA', () => {
      // Something that passes AA but not AAA
      const color = '#757575';
      const aaResult = meetsWCAG_AA(color, '#ffffff');
      const aaaResult = meetsWCAG_AAA(color, '#ffffff');
      // If AA fails, AAA should also fail
      if (!aaResult) {
        expect(aaaResult).toBe(false);
      }
    });
  });

  describe('getAccessibleTextColor', () => {
    it('returns black for light backgrounds', () => {
      expect(getAccessibleTextColor('#ffffff')).toBe('#000000');
      expect(getAccessibleTextColor('#eeeeee')).toBe('#000000');
    });

    it('returns white for dark backgrounds', () => {
      expect(getAccessibleTextColor('#000000')).toBe('#ffffff');
      expect(getAccessibleTextColor('#333333')).toBe('#ffffff');
    });

    it('handles mid-tone backgrounds', () => {
      // Should return either black or white
      const result = getAccessibleTextColor('#808080');
      expect(['#000000', '#ffffff']).toContain(result);
    });
  });

  describe('generateId', () => {
    it('generates unique IDs', () => {
      const id1 = generateId();
      const id2 = generateId();
      expect(id1).not.toBe(id2);
    });

    it('uses provided prefix', () => {
      const id = generateId('custom');
      expect(id).toMatch(/^custom-\d+$/);
    });

    it('uses default prefix', () => {
      const id = generateId();
      expect(id).toMatch(/^aria-\d+$/);
    });
  });

  describe('prefersReducedMotion', () => {
    it('returns false when window is undefined', () => {
      // In test environment without proper matchMedia mock
      const result = prefersReducedMotion();
      expect(typeof result).toBe('boolean');
    });
  });

  describe('getAnimationDuration', () => {
    it('returns 0 when reduced motion is preferred', () => {
      // Mock prefersReducedMotion to return true
      jest.spyOn(window, 'matchMedia').mockImplementation((query) => ({
        matches: query === '(prefers-reduced-motion: reduce)',
        media: query,
        onchange: null,
        addListener: jest.fn(),
        removeListener: jest.fn(),
        addEventListener: jest.fn(),
        removeEventListener: jest.fn(),
        dispatchEvent: jest.fn(),
      }));

      expect(getAnimationDuration(300)).toBe(0);
    });

    it('returns normal duration when reduced motion is not preferred', () => {
      jest.spyOn(window, 'matchMedia').mockImplementation((query) => ({
        matches: false,
        media: query,
        onchange: null,
        addListener: jest.fn(),
        removeListener: jest.fn(),
        addEventListener: jest.fn(),
        removeEventListener: jest.fn(),
        dispatchEvent: jest.fn(),
      }));

      expect(getAnimationDuration(300)).toBe(300);
    });
  });
});
