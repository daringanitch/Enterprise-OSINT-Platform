/**
 * Hooks Barrel Export
 */

// Keyboard Navigation
export {
  useKeyboardNavigation,
  useRovingTabIndex,
} from './useKeyboardNavigation';
export type {
  UseKeyboardNavigationOptions,
  UseKeyboardNavigationReturn,
  UseRovingTabIndexOptions,
} from './useKeyboardNavigation';

// Focus Trap
export { useFocusTrap } from './useFocusTrap';
export type { UseFocusTrapOptions, UseFocusTrapReturn } from './useFocusTrap';

// Announcements
export {
  useAnnounce,
  globalAnnouncer,
  announcePolite,
  announceAssertive,
} from './useAnnounce';
export type {
  UseAnnounceOptions,
  UseAnnounceReturn,
  AnnouncePolitenessSetting,
} from './useAnnounce';

// Media Queries
export {
  useMediaQuery,
  useBreakpoint,
  usePrefersReducedMotion,
  usePrefersDarkMode,
  usePrefersHighContrast,
  useCurrentBreakpoint,
  useResponsiveValue,
  useWindowSize,
  useIsTouchDevice,
  useOrientation,
} from './useMediaQuery';
export type { BreakpointName, WindowSize, Orientation } from './useMediaQuery';
