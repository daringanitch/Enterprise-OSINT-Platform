/**
 * OSINT Platform Design System - Cyberpunk/Hacker Aesthetic
 *
 * Centralized theme configuration with CSS variables,
 * color palette, typography, spacing system, and glassmorphism effects.
 */

import { createTheme, ThemeOptions, alpha } from '@mui/material/styles';

// =============================================================================
// Cyberpunk Color Palette
// =============================================================================

export const cyberColors = {
  // Neon accent colors
  neon: {
    cyan: '#00ffff',
    magenta: '#ff00ff',
    electricBlue: '#00d4ff',
    green: '#00ff88',
    orange: '#ff8800',
    red: '#ff0044',
    yellow: '#ffff00',
    purple: '#bf00ff',
  },
  // Dark backgrounds
  dark: {
    void: '#000000',
    deepSpace: '#050505',
    charcoal: '#0a0a0a',
    midnight: '#0f1419',
    slate: '#111827',
    graphite: '#1a1a2e',
    steel: '#1f2937',
    ash: '#374151',
  },
  // Text colors
  text: {
    primary: '#e4e4e7',
    secondary: '#a1a1aa',
    muted: '#71717a',
    accent: '#00ffff',
    glowing: '#00ffff',
  },
  // Glow effects
  glow: {
    cyan: 'rgba(0, 255, 255, 0.5)',
    magenta: 'rgba(255, 0, 255, 0.5)',
    blue: 'rgba(0, 212, 255, 0.5)',
    green: 'rgba(0, 255, 136, 0.5)',
    red: 'rgba(255, 0, 68, 0.5)',
  },
  // Border colors
  border: {
    subtle: 'rgba(255, 255, 255, 0.1)',
    default: 'rgba(255, 255, 255, 0.2)',
    strong: 'rgba(255, 255, 255, 0.3)',
    glow: 'rgba(0, 255, 255, 0.3)',
  },
};

// =============================================================================
// Design Tokens (CSS Variables compatible)
// =============================================================================

export const designTokens = {
  colors: {
    // Primary palette - Cyan accent
    primary: {
      main: cyberColors.neon.cyan,
      light: '#66ffff',
      dark: '#00cccc',
      contrastText: '#000000',
    },
    // Secondary palette - Magenta accent
    secondary: {
      main: cyberColors.neon.magenta,
      light: '#ff66ff',
      dark: '#cc00cc',
      contrastText: '#000000',
    },
    // Status colors
    success: {
      main: cyberColors.neon.green,
      light: '#66ffaa',
      dark: '#00cc6a',
      contrastText: '#000000',
    },
    warning: {
      main: cyberColors.neon.orange,
      light: '#ffaa44',
      dark: '#cc6600',
      contrastText: '#000000',
    },
    error: {
      main: cyberColors.neon.red,
      light: '#ff4477',
      dark: '#cc0033',
      contrastText: '#ffffff',
    },
    info: {
      main: cyberColors.neon.electricBlue,
      light: '#66e5ff',
      dark: '#00a8cc',
      contrastText: '#000000',
    },
    // Risk levels
    risk: {
      critical: cyberColors.neon.magenta,
      high: cyberColors.neon.red,
      medium: cyberColors.neon.orange,
      low: cyberColors.neon.green,
    },
    // Dark theme backgrounds
    background: {
      default: cyberColors.dark.charcoal,
      paper: cyberColors.dark.slate,
      elevated: cyberColors.dark.steel,
      surface: cyberColors.dark.ash,
    },
    // Text colors
    text: {
      primary: cyberColors.text.primary,
      secondary: cyberColors.text.secondary,
      disabled: cyberColors.text.muted,
      hint: '#4b5563',
    },
    // Border colors
    border: {
      light: alpha(cyberColors.neon.cyan, 0.3),
      main: alpha(cyberColors.neon.cyan, 0.2),
      dark: alpha(cyberColors.neon.cyan, 0.1),
      glow: cyberColors.glow.cyan,
    },
    // Gradients
    gradients: {
      primary: `linear-gradient(135deg, ${cyberColors.neon.cyan}, ${cyberColors.neon.magenta})`,
      success: `linear-gradient(135deg, ${cyberColors.neon.green}, ${cyberColors.neon.cyan})`,
      danger: `linear-gradient(135deg, ${cyberColors.neon.red}, ${cyberColors.neon.orange})`,
      surface: `radial-gradient(ellipse at top, ${cyberColors.dark.graphite} 0%, ${cyberColors.dark.charcoal} 100%)`,
      cyber: `linear-gradient(90deg, ${cyberColors.neon.cyan}, ${cyberColors.neon.magenta}, ${cyberColors.neon.cyan})`,
      neonBorder: `linear-gradient(90deg, ${cyberColors.neon.cyan}, ${cyberColors.neon.magenta})`,
    },
    // Cyber-specific colors
    cyber: cyberColors,
  },
  typography: {
    fontFamily: {
      primary: '"Inter", "Segoe UI", -apple-system, BlinkMacSystemFont, sans-serif',
      mono: '"JetBrains Mono", "Fira Code", "Consolas", monospace',
      display: '"Orbitron", "Inter", sans-serif',
    },
    fontSizes: {
      xs: '0.75rem',    // 12px
      sm: '0.875rem',   // 14px
      md: '1rem',       // 16px
      lg: '1.125rem',   // 18px
      xl: '1.25rem',    // 20px
      '2xl': '1.5rem',  // 24px
      '3xl': '1.875rem', // 30px
      '4xl': '2.25rem', // 36px
      '5xl': '3rem',    // 48px
    },
    fontWeights: {
      normal: 400,
      medium: 500,
      semibold: 600,
      bold: 700,
    },
    lineHeights: {
      tight: 1.25,
      normal: 1.5,
      relaxed: 1.75,
    },
  },
  spacing: {
    xs: '0.25rem',  // 4px
    sm: '0.5rem',   // 8px
    md: '1rem',     // 16px
    lg: '1.5rem',   // 24px
    xl: '2rem',     // 32px
    '2xl': '3rem',  // 48px
    '3xl': '4rem',  // 64px
  },
  borderRadius: {
    none: '0',
    sm: '0.25rem',  // 4px
    md: '0.5rem',   // 8px
    lg: '0.75rem',  // 12px
    xl: '1rem',     // 16px
    '2xl': '1.5rem', // 24px
    full: '9999px',
  },
  shadows: {
    sm: '0 1px 2px rgba(0, 0, 0, 0.5)',
    md: '0 4px 6px rgba(0, 0, 0, 0.6)',
    lg: '0 10px 15px rgba(0, 0, 0, 0.7)',
    xl: '0 20px 25px rgba(0, 0, 0, 0.8)',
    glow: {
      primary: `0 0 20px ${cyberColors.glow.cyan}, 0 0 40px ${alpha(cyberColors.neon.cyan, 0.3)}`,
      secondary: `0 0 20px ${cyberColors.glow.magenta}, 0 0 40px ${alpha(cyberColors.neon.magenta, 0.3)}`,
      success: `0 0 20px ${cyberColors.glow.green}`,
      error: `0 0 20px ${cyberColors.glow.red}`,
      subtle: `0 0 10px ${alpha(cyberColors.neon.cyan, 0.2)}`,
    },
    neon: {
      cyan: `0 0 5px ${cyberColors.neon.cyan}, 0 0 20px ${cyberColors.glow.cyan}`,
      magenta: `0 0 5px ${cyberColors.neon.magenta}, 0 0 20px ${cyberColors.glow.magenta}`,
      green: `0 0 5px ${cyberColors.neon.green}, 0 0 20px ${cyberColors.glow.green}`,
      red: `0 0 5px ${cyberColors.neon.red}, 0 0 20px ${cyberColors.glow.red}`,
    },
  },
  transitions: {
    fast: '150ms ease',
    normal: '200ms ease',
    slow: '300ms ease',
    glow: '300ms ease-in-out',
  },
  breakpoints: {
    xs: 0,
    sm: 600,
    md: 900,
    lg: 1200,
    xl: 1536,
  },
  zIndex: {
    drawer: 1200,
    modal: 1300,
    snackbar: 1400,
    tooltip: 1500,
  },
};

// =============================================================================
// Glassmorphism Styles
// =============================================================================

export const glassmorphism = {
  // Standard glass panel
  panel: {
    background: alpha(cyberColors.dark.slate, 0.8),
    backdropFilter: 'blur(12px)',
    WebkitBackdropFilter: 'blur(12px)',
    border: `1px solid ${alpha(cyberColors.neon.cyan, 0.15)}`,
    boxShadow: `0 8px 32px rgba(0, 0, 0, 0.4), inset 0 1px 0 ${alpha(cyberColors.neon.cyan, 0.1)}`,
  },
  // Elevated glass card
  card: {
    background: alpha(cyberColors.dark.slate, 0.7),
    backdropFilter: 'blur(16px)',
    WebkitBackdropFilter: 'blur(16px)',
    border: `1px solid ${alpha(cyberColors.neon.cyan, 0.2)}`,
    boxShadow: `0 8px 32px rgba(0, 0, 0, 0.5), inset 0 1px 0 ${alpha(cyberColors.neon.cyan, 0.1)}`,
  },
  // Interactive glass element
  interactive: {
    background: alpha(cyberColors.dark.graphite, 0.6),
    backdropFilter: 'blur(8px)',
    WebkitBackdropFilter: 'blur(8px)',
    border: `1px solid ${alpha(cyberColors.neon.cyan, 0.1)}`,
    transition: 'all 0.3s ease',
    '&:hover': {
      background: alpha(cyberColors.dark.graphite, 0.8),
      border: `1px solid ${alpha(cyberColors.neon.cyan, 0.3)}`,
      boxShadow: `0 0 20px ${alpha(cyberColors.neon.cyan, 0.2)}`,
    },
  },
  // Frosted overlay
  overlay: {
    background: alpha(cyberColors.dark.charcoal, 0.9),
    backdropFilter: 'blur(20px)',
    WebkitBackdropFilter: 'blur(20px)',
  },
};

// =============================================================================
// Cyber Effects
// =============================================================================

export const cyberEffects = {
  // Glowing text effect
  glowText: (color: string = cyberColors.neon.cyan) => ({
    color: color,
    textShadow: `0 0 10px ${color}, 0 0 20px ${alpha(color, 0.5)}, 0 0 30px ${alpha(color, 0.3)}`,
  }),
  // Pulsing border animation
  pulsingBorder: {
    animation: 'pulsingBorder 2s ease-in-out infinite',
    '@keyframes pulsingBorder': {
      '0%, 100%': {
        borderColor: alpha(cyberColors.neon.cyan, 0.3),
        boxShadow: `0 0 5px ${alpha(cyberColors.neon.cyan, 0.2)}`,
      },
      '50%': {
        borderColor: alpha(cyberColors.neon.cyan, 0.6),
        boxShadow: `0 0 20px ${alpha(cyberColors.neon.cyan, 0.4)}`,
      },
    },
  },
  // Scanline effect
  scanlines: {
    position: 'relative' as const,
    '&::after': {
      content: '""',
      position: 'absolute',
      top: 0,
      left: 0,
      right: 0,
      bottom: 0,
      background: `repeating-linear-gradient(
        0deg,
        transparent,
        transparent 2px,
        ${alpha(cyberColors.dark.void, 0.03)} 2px,
        ${alpha(cyberColors.dark.void, 0.03)} 4px
      )`,
      pointerEvents: 'none',
    },
  },
  // Grid pattern background
  gridPattern: {
    backgroundImage: `
      linear-gradient(${alpha(cyberColors.neon.cyan, 0.03)} 1px, transparent 1px),
      linear-gradient(90deg, ${alpha(cyberColors.neon.cyan, 0.03)} 1px, transparent 1px)
    `,
    backgroundSize: '20px 20px',
  },
  // HUD-style corner brackets
  hudBrackets: {
    position: 'relative' as const,
    '&::before, &::after': {
      content: '""',
      position: 'absolute',
      width: '20px',
      height: '20px',
      border: `2px solid ${cyberColors.neon.cyan}`,
    },
    '&::before': {
      top: 0,
      left: 0,
      borderRight: 'none',
      borderBottom: 'none',
    },
    '&::after': {
      bottom: 0,
      right: 0,
      borderLeft: 'none',
      borderTop: 'none',
    },
  },
};

// =============================================================================
// Material-UI Theme Configuration
// =============================================================================

const themeOptions: ThemeOptions = {
  palette: {
    mode: 'dark',
    primary: designTokens.colors.primary,
    secondary: designTokens.colors.secondary,
    success: designTokens.colors.success,
    warning: designTokens.colors.warning,
    error: designTokens.colors.error,
    info: designTokens.colors.info,
    background: {
      default: designTokens.colors.background.default,
      paper: designTokens.colors.background.paper,
    },
    text: {
      primary: designTokens.colors.text.primary,
      secondary: designTokens.colors.text.secondary,
      disabled: designTokens.colors.text.disabled,
    },
    divider: designTokens.colors.border.main,
  },
  typography: {
    fontFamily: designTokens.typography.fontFamily.primary,
    h1: {
      fontFamily: designTokens.typography.fontFamily.display,
      fontSize: designTokens.typography.fontSizes['4xl'],
      fontWeight: designTokens.typography.fontWeights.bold,
      lineHeight: designTokens.typography.lineHeights.tight,
      letterSpacing: '0.02em',
    },
    h2: {
      fontFamily: designTokens.typography.fontFamily.display,
      fontSize: designTokens.typography.fontSizes['3xl'],
      fontWeight: designTokens.typography.fontWeights.bold,
      lineHeight: designTokens.typography.lineHeights.tight,
      letterSpacing: '0.01em',
    },
    h3: {
      fontFamily: designTokens.typography.fontFamily.display,
      fontSize: designTokens.typography.fontSizes['2xl'],
      fontWeight: designTokens.typography.fontWeights.semibold,
      lineHeight: designTokens.typography.lineHeights.tight,
    },
    h4: {
      fontSize: designTokens.typography.fontSizes.xl,
      fontWeight: designTokens.typography.fontWeights.semibold,
      lineHeight: designTokens.typography.lineHeights.normal,
    },
    h5: {
      fontSize: designTokens.typography.fontSizes.lg,
      fontWeight: designTokens.typography.fontWeights.medium,
      lineHeight: designTokens.typography.lineHeights.normal,
    },
    h6: {
      fontSize: designTokens.typography.fontSizes.md,
      fontWeight: designTokens.typography.fontWeights.medium,
      lineHeight: designTokens.typography.lineHeights.normal,
    },
    body1: {
      fontSize: designTokens.typography.fontSizes.md,
      lineHeight: designTokens.typography.lineHeights.relaxed,
    },
    body2: {
      fontSize: designTokens.typography.fontSizes.sm,
      lineHeight: designTokens.typography.lineHeights.relaxed,
    },
    caption: {
      fontSize: designTokens.typography.fontSizes.xs,
      lineHeight: designTokens.typography.lineHeights.normal,
    },
    button: {
      textTransform: 'none',
      fontWeight: designTokens.typography.fontWeights.medium,
      letterSpacing: '0.02em',
    },
    overline: {
      fontFamily: designTokens.typography.fontFamily.mono,
      fontSize: designTokens.typography.fontSizes.xs,
      letterSpacing: '0.1em',
      textTransform: 'uppercase',
    },
  },
  shape: {
    borderRadius: 8,
  },
  shadows: [
    'none',
    designTokens.shadows.sm,
    designTokens.shadows.sm,
    designTokens.shadows.md,
    designTokens.shadows.md,
    designTokens.shadows.md,
    designTokens.shadows.lg,
    designTokens.shadows.lg,
    designTokens.shadows.lg,
    designTokens.shadows.lg,
    designTokens.shadows.xl,
    designTokens.shadows.xl,
    designTokens.shadows.xl,
    designTokens.shadows.xl,
    designTokens.shadows.xl,
    designTokens.shadows.xl,
    designTokens.shadows.xl,
    designTokens.shadows.xl,
    designTokens.shadows.xl,
    designTokens.shadows.xl,
    designTokens.shadows.xl,
    designTokens.shadows.xl,
    designTokens.shadows.xl,
    designTokens.shadows.xl,
    designTokens.shadows.xl,
  ],
  components: {
    MuiCssBaseline: {
      styleOverrides: {
        '@import': [
          'url("https://fonts.googleapis.com/css2?family=Orbitron:wght@400;500;600;700&display=swap")',
          'url("https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600&display=swap")',
        ],
        body: {
          background: designTokens.colors.gradients.surface,
          minHeight: '100vh',
          // Subtle grid pattern
          backgroundImage: `
            radial-gradient(ellipse at top, ${cyberColors.dark.graphite} 0%, ${cyberColors.dark.charcoal} 100%),
            linear-gradient(${alpha(cyberColors.neon.cyan, 0.02)} 1px, transparent 1px),
            linear-gradient(90deg, ${alpha(cyberColors.neon.cyan, 0.02)} 1px, transparent 1px)
          `,
          backgroundSize: '100% 100%, 40px 40px, 40px 40px',
        },
        '*': {
          scrollbarWidth: 'thin',
          scrollbarColor: `${cyberColors.neon.cyan} ${cyberColors.dark.slate}`,
        },
        '*::-webkit-scrollbar': {
          width: '8px',
          height: '8px',
        },
        '*::-webkit-scrollbar-track': {
          background: cyberColors.dark.slate,
        },
        '*::-webkit-scrollbar-thumb': {
          background: alpha(cyberColors.neon.cyan, 0.5),
          borderRadius: '4px',
          '&:hover': {
            background: cyberColors.neon.cyan,
          },
        },
        '::selection': {
          background: alpha(cyberColors.neon.cyan, 0.3),
          color: cyberColors.text.primary,
        },
      },
    },
    MuiButton: {
      styleOverrides: {
        root: {
          borderRadius: designTokens.borderRadius.md,
          padding: '10px 20px',
          transition: 'all 0.3s ease',
          fontWeight: 600,
          '&:hover': {
            transform: 'translateY(-2px)',
          },
        },
        contained: {
          boxShadow: `0 0 10px ${alpha(cyberColors.neon.cyan, 0.3)}`,
          '&:hover': {
            boxShadow: `0 0 20px ${alpha(cyberColors.neon.cyan, 0.5)}, 0 0 40px ${alpha(cyberColors.neon.cyan, 0.3)}`,
          },
        },
        containedPrimary: {
          background: designTokens.colors.gradients.primary,
          color: '#000000',
          '&:hover': {
            background: designTokens.colors.gradients.primary,
            filter: 'brightness(1.2)',
          },
        },
        outlined: {
          borderWidth: '2px',
          '&:hover': {
            borderWidth: '2px',
            boxShadow: `0 0 15px ${alpha(cyberColors.neon.cyan, 0.4)}`,
          },
        },
        outlinedPrimary: {
          borderColor: cyberColors.neon.cyan,
          color: cyberColors.neon.cyan,
          '&:hover': {
            borderColor: cyberColors.neon.cyan,
            backgroundColor: alpha(cyberColors.neon.cyan, 0.1),
          },
        },
      },
    },
    MuiCard: {
      styleOverrides: {
        root: {
          ...glassmorphism.card,
          borderRadius: designTokens.borderRadius.lg,
          transition: 'all 0.3s ease',
          '&:hover': {
            borderColor: alpha(cyberColors.neon.cyan, 0.4),
            boxShadow: `0 8px 32px rgba(0, 0, 0, 0.5), 0 0 20px ${alpha(cyberColors.neon.cyan, 0.2)}`,
          },
        },
      },
    },
    MuiPaper: {
      styleOverrides: {
        root: {
          backgroundImage: 'none',
        },
        elevation1: glassmorphism.panel,
        elevation2: glassmorphism.card,
      },
    },
    MuiTextField: {
      styleOverrides: {
        root: {
          '& .MuiOutlinedInput-root': {
            borderRadius: designTokens.borderRadius.md,
            background: alpha(cyberColors.dark.midnight, 0.5),
            transition: 'all 0.3s ease',
            '& fieldset': {
              borderColor: alpha(cyberColors.neon.cyan, 0.2),
              borderWidth: '2px',
            },
            '&:hover fieldset': {
              borderColor: alpha(cyberColors.neon.cyan, 0.4),
            },
            '&.Mui-focused fieldset': {
              borderColor: cyberColors.neon.cyan,
              boxShadow: `0 0 10px ${alpha(cyberColors.neon.cyan, 0.3)}`,
            },
          },
          '& .MuiInputLabel-root': {
            color: cyberColors.text.secondary,
            '&.Mui-focused': {
              color: cyberColors.neon.cyan,
            },
          },
        },
      },
    },
    MuiChip: {
      styleOverrides: {
        root: {
          borderRadius: designTokens.borderRadius.md,
          fontWeight: 500,
          backdropFilter: 'blur(4px)',
        },
        filled: {
          background: alpha(cyberColors.neon.cyan, 0.2),
          '&:hover': {
            background: alpha(cyberColors.neon.cyan, 0.3),
          },
        },
        outlined: {
          borderColor: alpha(cyberColors.neon.cyan, 0.5),
        },
      },
    },
    MuiTooltip: {
      styleOverrides: {
        tooltip: {
          ...glassmorphism.panel,
          borderRadius: designTokens.borderRadius.md,
          fontSize: designTokens.typography.fontSizes.sm,
          padding: '8px 12px',
        },
        arrow: {
          color: alpha(cyberColors.dark.slate, 0.9),
        },
      },
    },
    MuiDialog: {
      styleOverrides: {
        paper: {
          ...glassmorphism.card,
          borderRadius: designTokens.borderRadius.xl,
        },
      },
    },
    MuiDrawer: {
      styleOverrides: {
        paper: {
          ...glassmorphism.panel,
          borderRight: `1px solid ${alpha(cyberColors.neon.cyan, 0.2)}`,
        },
      },
    },
    MuiAppBar: {
      styleOverrides: {
        root: {
          ...glassmorphism.panel,
          boxShadow: `0 4px 20px rgba(0, 0, 0, 0.3), 0 0 40px ${alpha(cyberColors.neon.cyan, 0.1)}`,
        },
      },
    },
    MuiTableCell: {
      styleOverrides: {
        root: {
          borderColor: alpha(cyberColors.neon.cyan, 0.1),
        },
        head: {
          fontWeight: designTokens.typography.fontWeights.semibold,
          background: alpha(cyberColors.dark.steel, 0.8),
          fontFamily: designTokens.typography.fontFamily.mono,
          textTransform: 'uppercase',
          fontSize: designTokens.typography.fontSizes.xs,
          letterSpacing: '0.05em',
        },
      },
    },
    MuiTableRow: {
      styleOverrides: {
        root: {
          transition: 'all 0.2s ease',
          '&:hover': {
            backgroundColor: alpha(cyberColors.neon.cyan, 0.05),
          },
        },
      },
    },
    MuiTabs: {
      styleOverrides: {
        indicator: {
          backgroundColor: cyberColors.neon.cyan,
          height: 3,
          boxShadow: `0 0 10px ${cyberColors.neon.cyan}`,
        },
      },
    },
    MuiTab: {
      styleOverrides: {
        root: {
          fontWeight: 500,
          textTransform: 'none',
          '&.Mui-selected': {
            color: cyberColors.neon.cyan,
          },
        },
      },
    },
    MuiLinearProgress: {
      styleOverrides: {
        root: {
          borderRadius: designTokens.borderRadius.full,
          backgroundColor: alpha(cyberColors.neon.cyan, 0.1),
        },
        bar: {
          borderRadius: designTokens.borderRadius.full,
          background: designTokens.colors.gradients.primary,
        },
      },
    },
    MuiCircularProgress: {
      styleOverrides: {
        root: {
          color: cyberColors.neon.cyan,
        },
      },
    },
    MuiBadge: {
      styleOverrides: {
        badge: {
          fontWeight: 600,
        },
        colorPrimary: {
          background: designTokens.colors.gradients.primary,
          boxShadow: `0 0 10px ${alpha(cyberColors.neon.cyan, 0.5)}`,
        },
        colorError: {
          background: cyberColors.neon.red,
          boxShadow: `0 0 10px ${alpha(cyberColors.neon.red, 0.5)}`,
        },
      },
    },
    MuiAlert: {
      styleOverrides: {
        root: {
          borderRadius: designTokens.borderRadius.md,
          backdropFilter: 'blur(8px)',
        },
        standardError: {
          backgroundColor: alpha(cyberColors.neon.red, 0.15),
          border: `1px solid ${alpha(cyberColors.neon.red, 0.3)}`,
        },
        standardWarning: {
          backgroundColor: alpha(cyberColors.neon.orange, 0.15),
          border: `1px solid ${alpha(cyberColors.neon.orange, 0.3)}`,
        },
        standardInfo: {
          backgroundColor: alpha(cyberColors.neon.cyan, 0.15),
          border: `1px solid ${alpha(cyberColors.neon.cyan, 0.3)}`,
        },
        standardSuccess: {
          backgroundColor: alpha(cyberColors.neon.green, 0.15),
          border: `1px solid ${alpha(cyberColors.neon.green, 0.3)}`,
        },
      },
    },
    MuiSwitch: {
      styleOverrides: {
        switchBase: {
          '&.Mui-checked': {
            color: cyberColors.neon.cyan,
            '& + .MuiSwitch-track': {
              backgroundColor: alpha(cyberColors.neon.cyan, 0.5),
            },
          },
        },
        track: {
          backgroundColor: alpha(cyberColors.text.muted, 0.3),
        },
      },
    },
    MuiSlider: {
      styleOverrides: {
        root: {
          color: cyberColors.neon.cyan,
        },
        thumb: {
          boxShadow: `0 0 10px ${alpha(cyberColors.neon.cyan, 0.5)}`,
          '&:hover': {
            boxShadow: `0 0 20px ${cyberColors.neon.cyan}`,
          },
        },
        track: {
          background: designTokens.colors.gradients.primary,
        },
      },
    },
  },
};

export const theme = createTheme(themeOptions);

// =============================================================================
// CSS Variable Generator (for non-MUI components)
// =============================================================================

export const getCSSVariables = (): Record<string, string> => ({
  // Colors
  '--color-primary': designTokens.colors.primary.main,
  '--color-primary-light': designTokens.colors.primary.light,
  '--color-primary-dark': designTokens.colors.primary.dark,
  '--color-secondary': designTokens.colors.secondary.main,
  '--color-success': designTokens.colors.success.main,
  '--color-warning': designTokens.colors.warning.main,
  '--color-error': designTokens.colors.error.main,
  '--color-info': designTokens.colors.info.main,
  '--color-bg-default': designTokens.colors.background.default,
  '--color-bg-paper': designTokens.colors.background.paper,
  '--color-bg-elevated': designTokens.colors.background.elevated,
  '--color-text-primary': designTokens.colors.text.primary,
  '--color-text-secondary': designTokens.colors.text.secondary,
  '--color-border': designTokens.colors.border.main,
  // Cyber colors
  '--cyber-cyan': cyberColors.neon.cyan,
  '--cyber-magenta': cyberColors.neon.magenta,
  '--cyber-green': cyberColors.neon.green,
  '--cyber-red': cyberColors.neon.red,
  '--cyber-orange': cyberColors.neon.orange,
  // Typography
  '--font-family': designTokens.typography.fontFamily.primary,
  '--font-family-mono': designTokens.typography.fontFamily.mono,
  '--font-family-display': designTokens.typography.fontFamily.display,
  // Spacing
  '--radius-sm': designTokens.borderRadius.sm,
  '--radius-md': designTokens.borderRadius.md,
  '--radius-lg': designTokens.borderRadius.lg,
  // Shadows
  '--shadow-sm': designTokens.shadows.sm,
  '--shadow-md': designTokens.shadows.md,
  '--shadow-lg': designTokens.shadows.lg,
  '--shadow-glow': designTokens.shadows.glow.primary,
  // Transitions
  '--transition-fast': designTokens.transitions.fast,
  '--transition-normal': designTokens.transitions.normal,
});

// =============================================================================
// Helper Functions
// =============================================================================

/**
 * Get risk color based on severity level
 */
export const getRiskColor = (level: 'critical' | 'high' | 'medium' | 'low'): string => {
  return designTokens.colors.risk[level];
};

/**
 * Get glow shadow for a specific color
 */
export const getGlowShadow = (color: string, intensity: 'subtle' | 'medium' | 'strong' = 'medium'): string => {
  const intensities = {
    subtle: `0 0 10px ${alpha(color, 0.3)}`,
    medium: `0 0 20px ${alpha(color, 0.5)}, 0 0 40px ${alpha(color, 0.3)}`,
    strong: `0 0 30px ${color}, 0 0 60px ${alpha(color, 0.5)}, 0 0 90px ${alpha(color, 0.3)}`,
  };
  return intensities[intensity];
};

export default theme;
