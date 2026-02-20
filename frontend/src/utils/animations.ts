/**
 * Animation Utilities - Framer Motion Presets
 *
 * Reusable animation configurations for consistent motion design.
 */

import { Variants, Transition, TargetAndTransition } from 'framer-motion';
import { cyberColors } from './theme';

// =============================================================================
// Transition Presets
// =============================================================================

export const transitions = {
  // Fast, snappy transitions
  fast: {
    type: 'spring',
    stiffness: 500,
    damping: 30,
  } as Transition,

  // Standard easing
  default: {
    type: 'spring',
    stiffness: 300,
    damping: 25,
  } as Transition,

  // Smooth, flowing transitions
  smooth: {
    type: 'tween',
    ease: [0.4, 0, 0.2, 1],
    duration: 0.3,
  } as Transition,

  // Slow, dramatic transitions
  slow: {
    type: 'tween',
    ease: [0.4, 0, 0.2, 1],
    duration: 0.5,
  } as Transition,

  // Bouncy, playful transitions
  bouncy: {
    type: 'spring',
    stiffness: 400,
    damping: 10,
  } as Transition,

  // Stiff, mechanical transitions
  stiff: {
    type: 'spring',
    stiffness: 600,
    damping: 40,
  } as Transition,
};

// =============================================================================
// Page Transition Variants
// =============================================================================

export const pageVariants: Variants = {
  initial: {
    opacity: 0,
    y: 20,
  },
  enter: {
    opacity: 1,
    y: 0,
    transition: {
      duration: 0.4,
      ease: [0.4, 0, 0.2, 1],
      when: 'beforeChildren',
      staggerChildren: 0.1,
    },
  },
  exit: {
    opacity: 0,
    y: -20,
    transition: {
      duration: 0.3,
      ease: [0.4, 0, 0.2, 1],
    },
  },
};

export const fadeInVariants: Variants = {
  initial: { opacity: 0 },
  enter: {
    opacity: 1,
    transition: { duration: 0.3 },
  },
  exit: {
    opacity: 0,
    transition: { duration: 0.2 },
  },
};

export const slideUpVariants: Variants = {
  initial: { opacity: 0, y: 30 },
  enter: {
    opacity: 1,
    y: 0,
    transition: transitions.default,
  },
  exit: {
    opacity: 0,
    y: -20,
    transition: transitions.fast,
  },
};

export const slideInFromRight: Variants = {
  initial: { opacity: 0, x: 50 },
  enter: {
    opacity: 1,
    x: 0,
    transition: transitions.default,
  },
  exit: {
    opacity: 0,
    x: 50,
    transition: transitions.fast,
  },
};

export const slideInFromLeft: Variants = {
  initial: { opacity: 0, x: -50 },
  enter: {
    opacity: 1,
    x: 0,
    transition: transitions.default,
  },
  exit: {
    opacity: 0,
    x: -50,
    transition: transitions.fast,
  },
};

// =============================================================================
// Container / Stagger Variants
// =============================================================================

export const staggerContainer: Variants = {
  initial: {},
  enter: {
    transition: {
      staggerChildren: 0.08,
      delayChildren: 0.1,
    },
  },
  exit: {
    transition: {
      staggerChildren: 0.05,
      staggerDirection: -1,
    },
  },
};

export const staggerContainerFast: Variants = {
  initial: {},
  enter: {
    transition: {
      staggerChildren: 0.05,
      delayChildren: 0.05,
    },
  },
  exit: {
    transition: {
      staggerChildren: 0.03,
      staggerDirection: -1,
    },
  },
};

export const staggerItem: Variants = {
  initial: { opacity: 0, y: 20 },
  enter: {
    opacity: 1,
    y: 0,
    transition: transitions.default,
  },
  exit: {
    opacity: 0,
    y: -10,
    transition: transitions.fast,
  },
};

// =============================================================================
// Card / Component Variants
// =============================================================================

export const cardVariants: Variants = {
  initial: {
    opacity: 0,
    y: 20,
    scale: 0.95,
  },
  enter: {
    opacity: 1,
    y: 0,
    scale: 1,
    transition: transitions.default,
  },
  exit: {
    opacity: 0,
    scale: 0.95,
    transition: transitions.fast,
  },
  hover: {
    y: -4,
    scale: 1.02,
    transition: transitions.fast,
  },
  tap: {
    scale: 0.98,
    transition: transitions.stiff,
  },
};

export const glassCardVariants: Variants = {
  initial: {
    opacity: 0,
    y: 30,
    backdropFilter: 'blur(0px)',
  },
  enter: {
    opacity: 1,
    y: 0,
    backdropFilter: 'blur(16px)',
    transition: {
      duration: 0.4,
      ease: [0.4, 0, 0.2, 1],
    },
  },
  exit: {
    opacity: 0,
    y: 20,
    backdropFilter: 'blur(0px)',
    transition: {
      duration: 0.3,
    },
  },
};

// =============================================================================
// Interactive Element Variants
// =============================================================================

export const buttonVariants: Variants = {
  initial: { scale: 1 },
  hover: {
    scale: 1.05,
    transition: transitions.fast,
  },
  tap: {
    scale: 0.95,
    transition: transitions.stiff,
  },
};

export const iconButtonVariants: Variants = {
  initial: { scale: 1, rotate: 0 },
  hover: {
    scale: 1.1,
    transition: transitions.bouncy,
  },
  tap: {
    scale: 0.9,
    rotate: -10,
    transition: transitions.stiff,
  },
};

// =============================================================================
// Cyber / Glow Effects
// =============================================================================

export const glowPulse: Variants = {
  initial: {
    boxShadow: `0 0 5px ${cyberColors.glow.cyan}`,
  },
  animate: {
    boxShadow: [
      `0 0 5px ${cyberColors.glow.cyan}`,
      `0 0 20px ${cyberColors.glow.cyan}`,
      `0 0 5px ${cyberColors.glow.cyan}`,
    ],
    transition: {
      duration: 2,
      repeat: Infinity,
      ease: 'easeInOut',
    },
  },
};

export const neonFlicker: Variants = {
  initial: { opacity: 1 },
  animate: {
    opacity: [1, 0.8, 1, 0.9, 1, 0.85, 1],
    transition: {
      duration: 0.5,
      repeat: Infinity,
      repeatDelay: 3,
    },
  },
};

export const scanlineVariants: Variants = {
  initial: { y: '-100%' },
  animate: {
    y: '100%',
    transition: {
      duration: 3,
      repeat: Infinity,
      ease: 'linear',
    },
  },
};

// =============================================================================
// Data Visualization Variants
// =============================================================================

export const chartBarVariants: Variants = {
  initial: { scaleY: 0, originY: 1 },
  enter: {
    scaleY: 1,
    transition: {
      type: 'spring',
      stiffness: 200,
      damping: 20,
    },
  },
};

export const chartLineVariants: Variants = {
  initial: { pathLength: 0, opacity: 0 },
  enter: {
    pathLength: 1,
    opacity: 1,
    transition: {
      pathLength: { duration: 1.5, ease: 'easeInOut' },
      opacity: { duration: 0.3 },
    },
  },
};

export const numberCountVariants: Variants = {
  initial: { opacity: 0, y: 10 },
  enter: {
    opacity: 1,
    y: 0,
    transition: { duration: 0.3 },
  },
};

export const gaugeNeedleVariants: Variants = {
  initial: { rotate: -135 },
  enter: (value: number) => ({
    rotate: -135 + (value / 100) * 270,
    transition: {
      type: 'spring',
      stiffness: 100,
      damping: 15,
      delay: 0.3,
    },
  }),
};

// =============================================================================
// Graph / Network Variants
// =============================================================================

export const nodeVariants: Variants = {
  initial: {
    scale: 0,
    opacity: 0,
  },
  enter: {
    scale: 1,
    opacity: 1,
    transition: {
      type: 'spring',
      stiffness: 300,
      damping: 20,
    },
  },
  exit: {
    scale: 0,
    opacity: 0,
    transition: { duration: 0.2 },
  },
  hover: {
    scale: 1.2,
    transition: transitions.fast,
  },
  selected: {
    scale: 1.3,
    transition: transitions.bouncy,
  },
};

export const edgeVariants: Variants = {
  initial: {
    pathLength: 0,
    opacity: 0,
  },
  enter: {
    pathLength: 1,
    opacity: 1,
    transition: {
      pathLength: { duration: 0.8, ease: 'easeOut' },
      opacity: { duration: 0.3 },
    },
  },
  exit: {
    opacity: 0,
    transition: { duration: 0.2 },
  },
  highlighted: {
    opacity: 1,
    stroke: cyberColors.neon.cyan,
    strokeWidth: 3,
    filter: `drop-shadow(0 0 10px ${cyberColors.neon.cyan})`,
    transition: { duration: 0.3 },
  },
};

export const rippleVariants: Variants = {
  initial: {
    scale: 0,
    opacity: 0.8,
  },
  animate: {
    scale: 3,
    opacity: 0,
    transition: {
      duration: 1.5,
      ease: 'easeOut',
    },
  },
};

// =============================================================================
// Modal / Overlay Variants
// =============================================================================

export const modalOverlayVariants: Variants = {
  initial: { opacity: 0 },
  enter: {
    opacity: 1,
    transition: { duration: 0.2 },
  },
  exit: {
    opacity: 0,
    transition: { duration: 0.2, delay: 0.1 },
  },
};

export const modalContentVariants: Variants = {
  initial: {
    opacity: 0,
    scale: 0.9,
    y: 20,
  },
  enter: {
    opacity: 1,
    scale: 1,
    y: 0,
    transition: {
      type: 'spring',
      stiffness: 300,
      damping: 25,
    },
  },
  exit: {
    opacity: 0,
    scale: 0.9,
    y: 20,
    transition: { duration: 0.2 },
  },
};

export const drawerVariants: Variants = {
  initial: { x: '-100%' },
  enter: {
    x: 0,
    transition: {
      type: 'spring',
      stiffness: 300,
      damping: 30,
    },
  },
  exit: {
    x: '-100%',
    transition: { duration: 0.2 },
  },
};

// =============================================================================
// Loading / Skeleton Variants
// =============================================================================

export const shimmerVariants: Variants = {
  initial: {
    backgroundPosition: '-200% 0',
  },
  animate: {
    backgroundPosition: '200% 0',
    transition: {
      repeat: Infinity,
      duration: 1.5,
      ease: 'linear',
    },
  },
};

export const pulseVariants: Variants = {
  initial: { opacity: 0.6 },
  animate: {
    opacity: [0.6, 1, 0.6],
    transition: {
      duration: 1.5,
      repeat: Infinity,
      ease: 'easeInOut',
    },
  },
};

export const spinnerVariants: Variants = {
  initial: { rotate: 0 },
  animate: {
    rotate: 360,
    transition: {
      duration: 1,
      repeat: Infinity,
      ease: 'linear',
    },
  },
};

// =============================================================================
// List / Table Variants
// =============================================================================

export const listItemVariants: Variants = {
  initial: { opacity: 0, x: -20 },
  enter: {
    opacity: 1,
    x: 0,
    transition: transitions.default,
  },
  exit: {
    opacity: 0,
    x: 20,
    transition: transitions.fast,
  },
};

export const tableRowVariants: Variants = {
  initial: { opacity: 0, backgroundColor: 'transparent' },
  enter: {
    opacity: 1,
    transition: { duration: 0.2 },
  },
  hover: {
    backgroundColor: `rgba(0, 255, 255, 0.05)`,
    transition: { duration: 0.15 },
  },
};

// =============================================================================
// Notification / Toast Variants
// =============================================================================

export const toastVariants: Variants = {
  initial: {
    opacity: 0,
    y: 50,
    scale: 0.9,
  },
  enter: {
    opacity: 1,
    y: 0,
    scale: 1,
    transition: {
      type: 'spring',
      stiffness: 400,
      damping: 25,
    },
  },
  exit: {
    opacity: 0,
    y: 20,
    scale: 0.9,
    transition: { duration: 0.2 },
  },
};

// =============================================================================
// Utility Functions
// =============================================================================

/**
 * Create a stagger delay based on index
 */
export const getStaggerDelay = (index: number, baseDelay = 0.05): number => {
  return index * baseDelay;
};

/**
 * Create custom spring transition
 */
export const createSpring = (
  stiffness = 300,
  damping = 25,
  mass = 1
): Transition => ({
  type: 'spring',
  stiffness,
  damping,
  mass,
});

/**
 * Create custom tween transition
 */
export const createTween = (
  duration = 0.3,
  ease: number[] | string = [0.4, 0, 0.2, 1]
): Transition => ({
  type: 'tween',
  duration,
  ease,
});

/**
 * Generate hover glow animation state
 */
export const hoverGlow = (color: string = cyberColors.neon.cyan): TargetAndTransition => ({
  boxShadow: `0 0 20px ${color}, 0 0 40px ${color}40`,
  transition: { duration: 0.3 },
});

/**
 * Generate path drawing animation for SVG
 */
export const drawPath = (duration = 1, delay = 0): Variants => ({
  initial: { pathLength: 0 },
  enter: {
    pathLength: 1,
    transition: {
      duration,
      delay,
      ease: 'easeInOut',
    },
  },
});

export default {
  transitions,
  pageVariants,
  fadeInVariants,
  slideUpVariants,
  cardVariants,
  glassCardVariants,
  buttonVariants,
  staggerContainer,
  staggerItem,
  nodeVariants,
  edgeVariants,
  modalOverlayVariants,
  modalContentVariants,
  toastVariants,
};
