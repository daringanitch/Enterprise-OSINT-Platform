/**
 * OSINT Platform Design System
 *
 * Centralized theme configuration with CSS variables,
 * color palette, typography, and spacing system.
 */

import { createTheme, ThemeOptions } from '@mui/material/styles';

// =============================================================================
// Design Tokens (CSS Variables compatible)
// =============================================================================

export const designTokens = {
  colors: {
    // Primary palette
    primary: {
      main: '#3b82f6',
      light: '#60a5fa',
      dark: '#2563eb',
      contrastText: '#ffffff',
    },
    // Secondary palette
    secondary: {
      main: '#8b5cf6',
      light: '#a78bfa',
      dark: '#7c3aed',
      contrastText: '#ffffff',
    },
    // Status colors
    success: {
      main: '#10b981',
      light: '#34d399',
      dark: '#059669',
      contrastText: '#ffffff',
    },
    warning: {
      main: '#f59e0b',
      light: '#fbbf24',
      dark: '#d97706',
      contrastText: '#000000',
    },
    error: {
      main: '#ef4444',
      light: '#f87171',
      dark: '#dc2626',
      contrastText: '#ffffff',
    },
    info: {
      main: '#06b6d4',
      light: '#22d3ee',
      dark: '#0891b2',
      contrastText: '#ffffff',
    },
    // Risk levels
    risk: {
      critical: '#dc2626',
      high: '#f97316',
      medium: '#eab308',
      low: '#22c55e',
    },
    // Dark theme backgrounds
    background: {
      default: '#0a0a0a',
      paper: '#111827',
      elevated: '#1f2937',
      surface: '#374151',
    },
    // Text colors
    text: {
      primary: '#f9fafb',
      secondary: '#9ca3af',
      disabled: '#6b7280',
      hint: '#4b5563',
    },
    // Border colors
    border: {
      light: '#374151',
      main: '#4b5563',
      dark: '#1f2937',
    },
    // Gradients
    gradients: {
      primary: 'linear-gradient(135deg, #3b82f6, #8b5cf6)',
      success: 'linear-gradient(135deg, #10b981, #3b82f6)',
      danger: 'linear-gradient(135deg, #ef4444, #f97316)',
      surface: 'radial-gradient(ellipse at top, #1f2937 0%, #0a0a0a 100%)',
    },
  },
  typography: {
    fontFamily: {
      primary: '"Inter", "Segoe UI", -apple-system, BlinkMacSystemFont, sans-serif',
      mono: '"JetBrains Mono", "Fira Code", "Consolas", monospace',
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
    full: '9999px',
  },
  shadows: {
    sm: '0 1px 2px rgba(0, 0, 0, 0.3)',
    md: '0 4px 6px rgba(0, 0, 0, 0.4)',
    lg: '0 10px 15px rgba(0, 0, 0, 0.5)',
    xl: '0 20px 25px rgba(0, 0, 0, 0.6)',
    glow: {
      primary: '0 0 20px rgba(59, 130, 246, 0.4)',
      success: '0 0 20px rgba(16, 185, 129, 0.4)',
      error: '0 0 20px rgba(239, 68, 68, 0.4)',
    },
  },
  transitions: {
    fast: '150ms ease',
    normal: '200ms ease',
    slow: '300ms ease',
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
    divider: designTokens.colors.border.light,
  },
  typography: {
    fontFamily: designTokens.typography.fontFamily.primary,
    h1: {
      fontSize: designTokens.typography.fontSizes['4xl'],
      fontWeight: designTokens.typography.fontWeights.bold,
      lineHeight: designTokens.typography.lineHeights.tight,
    },
    h2: {
      fontSize: designTokens.typography.fontSizes['3xl'],
      fontWeight: designTokens.typography.fontWeights.bold,
      lineHeight: designTokens.typography.lineHeights.tight,
    },
    h3: {
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
        body: {
          background: designTokens.colors.gradients.surface,
          minHeight: '100vh',
        },
        '*': {
          scrollbarWidth: 'thin',
          scrollbarColor: `${designTokens.colors.border.main} ${designTokens.colors.background.paper}`,
        },
        '*::-webkit-scrollbar': {
          width: '8px',
          height: '8px',
        },
        '*::-webkit-scrollbar-track': {
          background: designTokens.colors.background.paper,
        },
        '*::-webkit-scrollbar-thumb': {
          background: designTokens.colors.border.main,
          borderRadius: '4px',
        },
        '*::-webkit-scrollbar-thumb:hover': {
          background: designTokens.colors.border.light,
        },
      },
    },
    MuiButton: {
      styleOverrides: {
        root: {
          borderRadius: designTokens.borderRadius.md,
          padding: '8px 16px',
          transition: designTokens.transitions.normal,
          '&:hover': {
            transform: 'translateY(-1px)',
          },
        },
        contained: {
          boxShadow: designTokens.shadows.md,
          '&:hover': {
            boxShadow: designTokens.shadows.lg,
          },
        },
        containedPrimary: {
          background: designTokens.colors.gradients.primary,
          '&:hover': {
            background: designTokens.colors.gradients.primary,
            filter: 'brightness(1.1)',
          },
        },
      },
    },
    MuiCard: {
      styleOverrides: {
        root: {
          background: designTokens.colors.background.paper,
          borderRadius: designTokens.borderRadius.lg,
          border: `1px solid ${designTokens.colors.border.dark}`,
          transition: designTokens.transitions.normal,
          '&:hover': {
            borderColor: designTokens.colors.border.light,
            boxShadow: designTokens.shadows.lg,
          },
        },
      },
    },
    MuiTextField: {
      styleOverrides: {
        root: {
          '& .MuiOutlinedInput-root': {
            borderRadius: designTokens.borderRadius.md,
            '&:hover .MuiOutlinedInput-notchedOutline': {
              borderColor: designTokens.colors.primary.main,
            },
          },
        },
      },
    },
    MuiChip: {
      styleOverrides: {
        root: {
          borderRadius: designTokens.borderRadius.md,
        },
      },
    },
    MuiTooltip: {
      styleOverrides: {
        tooltip: {
          background: designTokens.colors.background.elevated,
          border: `1px solid ${designTokens.colors.border.light}`,
          borderRadius: designTokens.borderRadius.md,
          fontSize: designTokens.typography.fontSizes.sm,
        },
      },
    },
    MuiDialog: {
      styleOverrides: {
        paper: {
          background: designTokens.colors.background.paper,
          borderRadius: designTokens.borderRadius.xl,
          border: `1px solid ${designTokens.colors.border.dark}`,
        },
      },
    },
    MuiDrawer: {
      styleOverrides: {
        paper: {
          background: designTokens.colors.background.paper,
          borderRight: `1px solid ${designTokens.colors.border.dark}`,
        },
      },
    },
    MuiAppBar: {
      styleOverrides: {
        root: {
          background: designTokens.colors.background.paper,
          borderBottom: `1px solid ${designTokens.colors.border.dark}`,
          boxShadow: 'none',
        },
      },
    },
    MuiTableCell: {
      styleOverrides: {
        root: {
          borderColor: designTokens.colors.border.dark,
        },
        head: {
          fontWeight: designTokens.typography.fontWeights.semibold,
          background: designTokens.colors.background.elevated,
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
  '--font-family': designTokens.typography.fontFamily.primary,
  '--font-family-mono': designTokens.typography.fontFamily.mono,
  '--radius-sm': designTokens.borderRadius.sm,
  '--radius-md': designTokens.borderRadius.md,
  '--radius-lg': designTokens.borderRadius.lg,
  '--shadow-sm': designTokens.shadows.sm,
  '--shadow-md': designTokens.shadows.md,
  '--shadow-lg': designTokens.shadows.lg,
  '--transition-fast': designTokens.transitions.fast,
  '--transition-normal': designTokens.transitions.normal,
});

export default theme;
