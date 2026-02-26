/**
 * OSINT Platform Design System — Dark Intelligence
 *
 * Professional dark theme tuned for analysts who spend long hours
 * in the platform. GitHub-dark-inspired backgrounds, muted cyan
 * accent, semantic threat colours, and monospace data rendering.
 *
 * Palette
 * -------
 * Shell:      #0D1117   Cards:    #1C2128   Sidebar:   #161B22
 * Hover:      #21262D   Border:   #30363D   Focus:     #1E3A4C
 * Accent:     #22D3EE   (cyan — readable, not eye-searing)
 * HIGH:       #EF4444   MED:      #F59E0B   LOW:       #22C55E
 * Text/1:     #E2E8F0   Text/2:   #8B949E   Disabled:  #484F58
 */

import { createTheme, ThemeOptions, alpha } from '@mui/material/styles';

// =============================================================================
// Core Colour Tokens
// =============================================================================

export const cyberColors = {
  // Primary accent — muted cyan (replaces #00ffff neon)
  neon: {
    cyan:          '#22D3EE',
    magenta:       '#A78BFA',   // soft violet — secondary only
    electricBlue:  '#38BDF8',
    green:         '#22C55E',
    orange:        '#F59E0B',
    red:           '#EF4444',
    yellow:        '#EAB308',
    purple:        '#8B5CF6',
  },
  // Shell backgrounds — GitHub dark scale
  dark: {
    void:       '#010409',
    deepSpace:  '#0D1117',   // app shell / page bg
    charcoal:   '#0D1117',   // alias kept for back-compat
    midnight:   '#161B22',   // sidebar
    slate:      '#1C2128',   // cards / paper
    graphite:   '#21262D',   // hover / elevated surfaces
    steel:      '#2D333B',   // table headers / input bg
    ash:        '#444C56',   // muted elements
  },
  // Text
  text: {
    primary:   '#E2E8F0',
    secondary: '#8B949E',
    muted:     '#484F58',
    accent:    '#22D3EE',
    glowing:   '#22D3EE',
  },
  // Ambient glow — subtle, not retina-burning
  glow: {
    cyan:    'rgba(34, 211, 238, 0.25)',
    magenta: 'rgba(167, 139, 250, 0.25)',
    blue:    'rgba(56, 189, 248, 0.25)',
    green:   'rgba(34, 197, 94, 0.25)',
    red:     'rgba(239, 68, 68, 0.25)',
  },
  // Borders
  border: {
    subtle:  '#21262D',
    default: '#30363D',
    strong:  '#444C56',
    glow:    'rgba(34, 211, 238, 0.35)',
  },
};

// =============================================================================
// Design Tokens
// =============================================================================

export const designTokens = {
  colors: {
    primary: {
      main:          cyberColors.neon.cyan,
      light:         '#67E8F9',
      dark:          '#0E7490',
      contrastText:  '#0D1117',
    },
    secondary: {
      main:          cyberColors.neon.magenta,
      light:         '#C4B5FD',
      dark:          '#7C3AED',
      contrastText:  '#0D1117',
    },
    success: {
      main:          cyberColors.neon.green,
      light:         '#86EFAC',
      dark:          '#15803D',
      contrastText:  '#0D1117',
    },
    warning: {
      main:          cyberColors.neon.orange,
      light:         '#FCD34D',
      dark:          '#B45309',
      contrastText:  '#0D1117',
    },
    error: {
      main:          cyberColors.neon.red,
      light:         '#FCA5A5',
      dark:          '#B91C1C',
      contrastText:  '#ffffff',
    },
    info: {
      main:          cyberColors.neon.electricBlue,
      light:         '#7DD3FC',
      dark:          '#0369A1',
      contrastText:  '#0D1117',
    },
    // Threat severity — semantic, unambiguous
    risk: {
      critical:  '#DC2626',   // deep red — reserved for critical-only
      high:      cyberColors.neon.red,
      medium:    cyberColors.neon.orange,
      low:       cyberColors.neon.green,
      none:      '#6B7280',
    },
    background: {
      default:   cyberColors.dark.deepSpace,   // #0D1117
      paper:     cyberColors.dark.slate,       // #1C2128
      elevated:  cyberColors.dark.graphite,    // #21262D
      surface:   cyberColors.dark.steel,       // #2D333B
    },
    text: {
      primary:   cyberColors.text.primary,
      secondary: cyberColors.text.secondary,
      disabled:  cyberColors.text.muted,
      hint:      '#484F58',
    },
    border: {
      light: cyberColors.border.subtle,
      main:  cyberColors.border.default,
      dark:  cyberColors.border.strong,
      glow:  cyberColors.border.glow,
    },
    gradients: {
      // Subtle directional gradient for primary actions
      primary:    `linear-gradient(135deg, ${cyberColors.neon.cyan}, ${cyberColors.neon.electricBlue})`,
      success:    `linear-gradient(135deg, ${cyberColors.neon.green}, #38BDF8)`,
      danger:     `linear-gradient(135deg, ${cyberColors.neon.red}, ${cyberColors.neon.orange})`,
      // Page background — very subtle depth, no radial flash
      surface:    `linear-gradient(180deg, #161B22 0%, #0D1117 100%)`,
      // Kept for back-compat — now maps to primary
      cyber:      `linear-gradient(90deg, ${cyberColors.neon.cyan}, ${cyberColors.neon.electricBlue})`,
      neonBorder: `linear-gradient(90deg, ${cyberColors.neon.cyan}, ${cyberColors.neon.electricBlue})`,
    },
    cyber: cyberColors,
  },
  typography: {
    fontFamily: {
      // Inter for all UI text — professional, highly legible
      primary: '"Inter", "Segoe UI", -apple-system, BlinkMacSystemFont, sans-serif',
      // JetBrains Mono for any data value: IPs, domains, hashes, IOCs
      mono:    '"JetBrains Mono", "Fira Code", "Consolas", monospace',
      // Keep display alias pointing to Inter (drop Orbitron — too sci-fi)
      display: '"Inter", "Segoe UI", sans-serif',
    },
    fontSizes: {
      xs:   '0.75rem',
      sm:   '0.875rem',
      md:   '1rem',
      lg:   '1.125rem',
      xl:   '1.25rem',
      '2xl':'1.5rem',
      '3xl':'1.875rem',
      '4xl':'2.25rem',
      '5xl':'3rem',
    },
    fontWeights: {
      normal:   400,
      medium:   500,
      semibold: 600,
      bold:     700,
    },
    lineHeights: {
      tight:   1.25,
      normal:  1.5,
      relaxed: 1.75,
    },
  },
  spacing: {
    xs:   '0.25rem',
    sm:   '0.5rem',
    md:   '1rem',
    lg:   '1.5rem',
    xl:   '2rem',
    '2xl':'3rem',
    '3xl':'4rem',
  },
  borderRadius: {
    none: '0',
    sm:   '0.25rem',
    md:   '0.375rem',   // slightly tighter than before — more enterprise
    lg:   '0.5rem',
    xl:   '0.75rem',
    '2xl':'1rem',
    full: '9999px',
  },
  shadows: {
    sm:  '0 1px 2px rgba(1, 4, 9, 0.6)',
    md:  '0 4px 8px rgba(1, 4, 9, 0.7)',
    lg:  '0 8px 16px rgba(1, 4, 9, 0.8)',
    xl:  '0 16px 32px rgba(1, 4, 9, 0.9)',
    // Glow shadows — subtle, not cinematic
    glow: {
      primary:   `0 0 12px rgba(34, 211, 238, 0.2)`,
      secondary: `0 0 12px rgba(167, 139, 250, 0.2)`,
      success:   `0 0 12px rgba(34, 197, 94, 0.2)`,
      error:     `0 0 12px rgba(239, 68, 68, 0.2)`,
      subtle:    `0 0 8px rgba(34, 211, 238, 0.12)`,
    },
    neon: {
      cyan:    `0 0 6px rgba(34, 211, 238, 0.4)`,
      magenta: `0 0 6px rgba(167, 139, 250, 0.4)`,
      green:   `0 0 6px rgba(34, 197, 94, 0.4)`,
      red:     `0 0 6px rgba(239, 68, 68, 0.4)`,
    },
  },
  transitions: {
    fast:   '120ms ease',
    normal: '180ms ease',
    slow:   '280ms ease',
    glow:   '240ms ease-in-out',
  },
  breakpoints: {
    xs: 0,
    sm: 600,
    md: 900,
    lg: 1200,
    xl: 1536,
  },
  zIndex: {
    drawer:    1200,
    modal:     1300,
    snackbar:  1400,
    tooltip:   1500,
  },
};

// =============================================================================
// Panel / Card Styles  (glassmorphism dialled back to subtle depth)
// =============================================================================

export const glassmorphism = {
  panel: {
    background:             cyberColors.dark.slate,
    backdropFilter:         'blur(4px)',
    WebkitBackdropFilter:   'blur(4px)',
    border:                 `1px solid ${cyberColors.border.default}`,
    boxShadow:              `0 4px 16px rgba(1, 4, 9, 0.5)`,
  },
  card: {
    background:             cyberColors.dark.slate,
    backdropFilter:         'blur(4px)',
    WebkitBackdropFilter:   'blur(4px)',
    border:                 `1px solid ${cyberColors.border.default}`,
    boxShadow:              `0 2px 8px rgba(1, 4, 9, 0.6)`,
  },
  interactive: {
    background:             cyberColors.dark.graphite,
    backdropFilter:         'blur(4px)',
    WebkitBackdropFilter:   'blur(4px)',
    border:                 `1px solid ${cyberColors.border.subtle}`,
    transition:             'all 0.18s ease',
    '&:hover': {
      background:           cyberColors.dark.graphite,
      border:               `1px solid ${cyberColors.border.default}`,
      boxShadow:            `0 0 10px rgba(34, 211, 238, 0.1)`,
    },
  },
  overlay: {
    background:             alpha(cyberColors.dark.deepSpace, 0.92),
    backdropFilter:         'blur(12px)',
    WebkitBackdropFilter:   'blur(12px)',
  },
};

// =============================================================================
// Cyber Effects  (kept for API compatibility — toned down)
// =============================================================================

export const cyberEffects = {
  glowText: (color: string = cyberColors.neon.cyan) => ({
    color,
    textShadow: `0 0 8px ${alpha(color, 0.5)}`,
  }),
  // Subtle pulsing used on active watchlist items, critical alerts
  pulsingBorder: {
    animation: 'pulsingBorder 2.5s ease-in-out infinite',
    '@keyframes pulsingBorder': {
      '0%, 100%': {
        borderColor: alpha(cyberColors.neon.cyan, 0.25),
        boxShadow:   `0 0 4px ${alpha(cyberColors.neon.cyan, 0.15)}`,
      },
      '50%': {
        borderColor: alpha(cyberColors.neon.cyan, 0.55),
        boxShadow:   `0 0 10px ${alpha(cyberColors.neon.cyan, 0.25)}`,
      },
    },
  },
  // Very faint scanline — optional texture on hero panels
  scanlines: {
    position: 'relative' as const,
    '&::after': {
      content:  '""',
      position: 'absolute',
      top: 0, left: 0, right: 0, bottom: 0,
      background: `repeating-linear-gradient(
        0deg,
        transparent,
        transparent 3px,
        rgba(1, 4, 9, 0.015) 3px,
        rgba(1, 4, 9, 0.015) 4px
      )`,
      pointerEvents: 'none',
    },
  },
  // Subtle grid — 40px, barely visible
  gridPattern: {
    backgroundImage: `
      linear-gradient(${alpha(cyberColors.neon.cyan, 0.025)} 1px, transparent 1px),
      linear-gradient(90deg, ${alpha(cyberColors.neon.cyan, 0.025)} 1px, transparent 1px)
    `,
    backgroundSize: '40px 40px',
  },
  // HUD corner brackets — kept for entity cards
  hudBrackets: {
    position: 'relative' as const,
    '&::before, &::after': {
      content:  '""',
      position: 'absolute',
      width:    '14px',
      height:   '14px',
      border:   `1px solid ${alpha(cyberColors.neon.cyan, 0.6)}`,
    },
    '&::before': {
      top: 0, left: 0,
      borderRight: 'none',
      borderBottom: 'none',
    },
    '&::after': {
      bottom: 0, right: 0,
      borderLeft: 'none',
      borderTop: 'none',
    },
  },
};

// =============================================================================
// Material-UI Theme
// =============================================================================

const themeOptions: ThemeOptions = {
  palette: {
    mode: 'dark',
    primary:    designTokens.colors.primary,
    secondary:  designTokens.colors.secondary,
    success:    designTokens.colors.success,
    warning:    designTokens.colors.warning,
    error:      designTokens.colors.error,
    info:       designTokens.colors.info,
    background: {
      default: designTokens.colors.background.default,
      paper:   designTokens.colors.background.paper,
    },
    text: {
      primary:   designTokens.colors.text.primary,
      secondary: designTokens.colors.text.secondary,
      disabled:  designTokens.colors.text.disabled,
    },
    divider: designTokens.colors.border.main,
  },
  typography: {
    fontFamily: designTokens.typography.fontFamily.primary,
    // h1–h3: Inter semibold — professional, not sci-fi
    h1: {
      fontFamily:  designTokens.typography.fontFamily.primary,
      fontSize:    designTokens.typography.fontSizes['4xl'],
      fontWeight:  designTokens.typography.fontWeights.bold,
      lineHeight:  designTokens.typography.lineHeights.tight,
      letterSpacing: '-0.01em',
    },
    h2: {
      fontFamily:  designTokens.typography.fontFamily.primary,
      fontSize:    designTokens.typography.fontSizes['3xl'],
      fontWeight:  designTokens.typography.fontWeights.bold,
      lineHeight:  designTokens.typography.lineHeights.tight,
      letterSpacing: '-0.01em',
    },
    h3: {
      fontFamily:  designTokens.typography.fontFamily.primary,
      fontSize:    designTokens.typography.fontSizes['2xl'],
      fontWeight:  designTokens.typography.fontWeights.semibold,
      lineHeight:  designTokens.typography.lineHeights.tight,
    },
    h4: {
      fontSize:   designTokens.typography.fontSizes.xl,
      fontWeight: designTokens.typography.fontWeights.semibold,
      lineHeight: designTokens.typography.lineHeights.normal,
    },
    h5: {
      fontSize:   designTokens.typography.fontSizes.lg,
      fontWeight: designTokens.typography.fontWeights.medium,
      lineHeight: designTokens.typography.lineHeights.normal,
    },
    h6: {
      fontSize:   designTokens.typography.fontSizes.md,
      fontWeight: designTokens.typography.fontWeights.medium,
      lineHeight: designTokens.typography.lineHeights.normal,
    },
    body1: {
      fontSize:   designTokens.typography.fontSizes.md,
      lineHeight: designTokens.typography.lineHeights.relaxed,
    },
    body2: {
      fontSize:   designTokens.typography.fontSizes.sm,
      lineHeight: designTokens.typography.lineHeights.relaxed,
    },
    caption: {
      fontSize:   designTokens.typography.fontSizes.xs,
      lineHeight: designTokens.typography.lineHeights.normal,
      color:      cyberColors.text.secondary,
    },
    button: {
      textTransform: 'none',
      fontWeight:    designTokens.typography.fontWeights.medium,
      letterSpacing: '0.01em',
    },
    // overline used for section labels and table headers
    overline: {
      fontFamily:    designTokens.typography.fontFamily.mono,
      fontSize:      designTokens.typography.fontSizes.xs,
      letterSpacing: '0.08em',
      textTransform: 'uppercase',
      color:         cyberColors.text.secondary,
    },
  },
  shape: {
    borderRadius: 6,
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
          // JetBrains Mono for data rendering — Inter loaded via HTML or system
          'url("https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600&display=swap")',
          'url("https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap")',
        ],
        body: {
          backgroundColor: cyberColors.dark.deepSpace,
          // Very subtle grid — gives depth without distraction
          backgroundImage: `
            linear-gradient(${alpha(cyberColors.neon.cyan, 0.02)} 1px, transparent 1px),
            linear-gradient(90deg, ${alpha(cyberColors.neon.cyan, 0.02)} 1px, transparent 1px)
          `,
          backgroundSize: '40px 40px',
          minHeight: '100vh',
        },
        // Slim, dark scrollbar — matches sidebar
        '*': {
          scrollbarWidth: 'thin',
          scrollbarColor: `${cyberColors.border.strong} ${cyberColors.dark.midnight}`,
        },
        '*::-webkit-scrollbar': {
          width:  '6px',
          height: '6px',
        },
        '*::-webkit-scrollbar-track': {
          background: cyberColors.dark.midnight,
        },
        '*::-webkit-scrollbar-thumb': {
          background:    cyberColors.border.strong,
          borderRadius:  '3px',
          '&:hover': {
            background: alpha(cyberColors.neon.cyan, 0.6),
          },
        },
        // Selection — muted cyan tint
        '::selection': {
          background: alpha(cyberColors.neon.cyan, 0.2),
          color:      cyberColors.text.primary,
        },
        // IOC / data value class — apply monospace to any element with this class
        '.ioc, .entity-value, code, pre': {
          fontFamily:  designTokens.typography.fontFamily.mono,
          fontSize:    '0.85em',
          color:       cyberColors.neon.cyan,
          background:  alpha(cyberColors.dark.steel, 0.6),
          borderRadius:'3px',
          padding:     '1px 4px',
        },
        'pre': {
          padding:      '12px 16px',
          borderRadius: '6px',
          overflowX:    'auto',
          border:       `1px solid ${cyberColors.border.default}`,
        },
      },
    },

    MuiButton: {
      styleOverrides: {
        root: {
          borderRadius: designTokens.borderRadius.md,
          padding:      '8px 18px',
          transition:   'background 0.18s ease, box-shadow 0.18s ease',
          fontWeight:   600,
          // No translateY lift — keeps it grounded and professional
        },
        contained: {
          boxShadow:   'none',
          '&:hover': {
            boxShadow:  `0 0 10px ${alpha(cyberColors.neon.cyan, 0.25)}`,
          },
        },
        containedPrimary: {
          background: designTokens.colors.gradients.primary,
          color:      '#0D1117',
          '&:hover': {
            background: designTokens.colors.gradients.primary,
            filter:     'brightness(1.1)',
          },
        },
        outlined: {
          borderWidth:    '1px',
          borderColor:    cyberColors.border.default,
          '&:hover': {
            borderWidth:  '1px',
            borderColor:  cyberColors.neon.cyan,
            background:   alpha(cyberColors.neon.cyan, 0.06),
          },
        },
        outlinedPrimary: {
          borderColor:  alpha(cyberColors.neon.cyan, 0.5),
          color:        cyberColors.neon.cyan,
          '&:hover': {
            borderColor: cyberColors.neon.cyan,
            background:  alpha(cyberColors.neon.cyan, 0.08),
          },
        },
        text: {
          color: cyberColors.text.secondary,
          '&:hover': {
            color:      cyberColors.text.primary,
            background: alpha(cyberColors.neon.cyan, 0.06),
          },
        },
      },
    },

    MuiCard: {
      styleOverrides: {
        root: {
          ...glassmorphism.card,
          borderRadius: designTokens.borderRadius.lg,
          transition:   'border-color 0.18s ease, box-shadow 0.18s ease',
          '&:hover': {
            borderColor: alpha(cyberColors.neon.cyan, 0.35),
            boxShadow:   `0 4px 16px rgba(1,4,9,0.7), 0 0 10px ${alpha(cyberColors.neon.cyan, 0.1)}`,
          },
        },
      },
    },

    MuiPaper: {
      styleOverrides: {
        root: {
          backgroundImage: 'none',
          backgroundColor: cyberColors.dark.slate,
          border:          `1px solid ${cyberColors.border.default}`,
        },
        elevation0: {
          border: 'none',
        },
        elevation1: glassmorphism.panel,
        elevation2: glassmorphism.card,
      },
    },

    MuiTextField: {
      styleOverrides: {
        root: {
          '& .MuiOutlinedInput-root': {
            borderRadius:  designTokens.borderRadius.md,
            background:    cyberColors.dark.steel,
            transition:    'border-color 0.18s ease, box-shadow 0.18s ease',
            '& fieldset': {
              borderColor:  cyberColors.border.default,
              borderWidth:  '1px',
            },
            '&:hover fieldset': {
              borderColor:  cyberColors.border.strong,
            },
            '&.Mui-focused fieldset': {
              borderColor:  cyberColors.neon.cyan,
              borderWidth:  '1px',
              boxShadow:    `0 0 0 3px ${alpha(cyberColors.neon.cyan, 0.12)}`,
            },
          },
          '& .MuiInputLabel-root': {
            color:  cyberColors.text.secondary,
            '&.Mui-focused': {
              color: cyberColors.neon.cyan,
            },
          },
          '& .MuiInputBase-input': {
            color: cyberColors.text.primary,
          },
        },
      },
    },

    MuiChip: {
      styleOverrides: {
        root: {
          borderRadius:  designTokens.borderRadius.md,
          fontWeight:    500,
          fontSize:      designTokens.typography.fontSizes.xs,
          height:        '24px',
        },
        filled: {
          background:  alpha(cyberColors.dark.steel, 0.8),
          border:      `1px solid ${cyberColors.border.default}`,
          '&:hover': {
            background: cyberColors.dark.graphite,
          },
        },
        outlined: {
          borderColor: cyberColors.border.default,
          '&:hover': {
            borderColor: cyberColors.border.strong,
          },
        },
        colorPrimary: {
          background:  alpha(cyberColors.neon.cyan, 0.12),
          border:      `1px solid ${alpha(cyberColors.neon.cyan, 0.4)}`,
          color:       cyberColors.neon.cyan,
        },
        colorError: {
          background:  alpha(cyberColors.neon.red, 0.12),
          border:      `1px solid ${alpha(cyberColors.neon.red, 0.4)}`,
          color:       cyberColors.neon.red,
        },
        colorWarning: {
          background:  alpha(cyberColors.neon.orange, 0.12),
          border:      `1px solid ${alpha(cyberColors.neon.orange, 0.4)}`,
          color:       cyberColors.neon.orange,
        },
        colorSuccess: {
          background:  alpha(cyberColors.neon.green, 0.12),
          border:      `1px solid ${alpha(cyberColors.neon.green, 0.4)}`,
          color:       cyberColors.neon.green,
        },
      },
    },

    MuiTooltip: {
      styleOverrides: {
        tooltip: {
          background:   cyberColors.dark.steel,
          border:       `1px solid ${cyberColors.border.default}`,
          borderRadius: designTokens.borderRadius.md,
          fontSize:     designTokens.typography.fontSizes.sm,
          color:        cyberColors.text.primary,
          padding:      '6px 10px',
          boxShadow:    designTokens.shadows.md,
        },
        arrow: {
          color: cyberColors.dark.steel,
        },
      },
    },

    MuiDialog: {
      styleOverrides: {
        paper: {
          background:   cyberColors.dark.slate,
          border:       `1px solid ${cyberColors.border.default}`,
          borderRadius: designTokens.borderRadius.xl,
          boxShadow:    designTokens.shadows.xl,
        },
      },
    },

    MuiDrawer: {
      styleOverrides: {
        paper: {
          background:  cyberColors.dark.midnight,
          borderRight: `1px solid ${cyberColors.border.default}`,
          boxShadow:   'none',
        },
      },
    },

    MuiAppBar: {
      styleOverrides: {
        root: {
          background:  cyberColors.dark.midnight,
          borderBottom:`1px solid ${cyberColors.border.default}`,
          boxShadow:   'none',
          backdropFilter: 'blur(8px)',
        },
      },
    },

    MuiTableCell: {
      styleOverrides: {
        root: {
          borderColor: cyberColors.border.default,
          padding:     '10px 16px',
        },
        head: {
          fontFamily:     designTokens.typography.fontFamily.mono,
          fontWeight:     designTokens.typography.fontWeights.semibold,
          background:     cyberColors.dark.steel,
          color:          cyberColors.text.secondary,
          textTransform:  'uppercase',
          fontSize:       designTokens.typography.fontSizes.xs,
          letterSpacing:  '0.06em',
          borderBottom:   `1px solid ${cyberColors.border.strong}`,
        },
      },
    },

    MuiTableRow: {
      styleOverrides: {
        root: {
          transition: 'background 0.12s ease',
          '&:hover': {
            backgroundColor: alpha(cyberColors.neon.cyan, 0.04),
          },
          '&.Mui-selected': {
            backgroundColor: alpha(cyberColors.neon.cyan, 0.08),
            '&:hover': {
              backgroundColor: alpha(cyberColors.neon.cyan, 0.1),
            },
          },
        },
      },
    },

    MuiTabs: {
      styleOverrides: {
        root: {
          borderBottom: `1px solid ${cyberColors.border.default}`,
        },
        indicator: {
          backgroundColor: cyberColors.neon.cyan,
          height:          2,
          boxShadow:       `0 0 6px ${alpha(cyberColors.neon.cyan, 0.5)}`,
        },
      },
    },

    MuiTab: {
      styleOverrides: {
        root: {
          fontWeight:    500,
          textTransform: 'none',
          color:         cyberColors.text.secondary,
          minHeight:     '44px',
          '&.Mui-selected': {
            color: cyberColors.text.primary,
          },
          '&:hover': {
            color:      cyberColors.text.primary,
            background: alpha(cyberColors.neon.cyan, 0.04),
          },
        },
      },
    },

    MuiLinearProgress: {
      styleOverrides: {
        root: {
          borderRadius:    designTokens.borderRadius.full,
          backgroundColor: alpha(cyberColors.neon.cyan, 0.08),
          height:          4,
        },
        bar: {
          borderRadius: designTokens.borderRadius.full,
          background:   designTokens.colors.gradients.primary,
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
          fontWeight:   600,
          fontSize:     '0.65rem',
          height:       '18px',
          minWidth:     '18px',
          borderRadius: '9px',
        },
        colorPrimary: {
          background: cyberColors.neon.cyan,
          color:      '#0D1117',
        },
        colorError: {
          background: cyberColors.neon.red,
          boxShadow:  `0 0 6px ${alpha(cyberColors.neon.red, 0.5)}`,
        },
      },
    },

    MuiAlert: {
      styleOverrides: {
        root: {
          borderRadius: designTokens.borderRadius.md,
          border:       `1px solid`,
        },
        standardError: {
          backgroundColor: alpha(cyberColors.neon.red, 0.1),
          borderColor:     alpha(cyberColors.neon.red, 0.3),
          color:           '#FCA5A5',
        },
        standardWarning: {
          backgroundColor: alpha(cyberColors.neon.orange, 0.1),
          borderColor:     alpha(cyberColors.neon.orange, 0.3),
          color:           '#FCD34D',
        },
        standardInfo: {
          backgroundColor: alpha(cyberColors.neon.cyan, 0.08),
          borderColor:     alpha(cyberColors.neon.cyan, 0.25),
          color:           '#67E8F9',
        },
        standardSuccess: {
          backgroundColor: alpha(cyberColors.neon.green, 0.1),
          borderColor:     alpha(cyberColors.neon.green, 0.3),
          color:           '#86EFAC',
        },
      },
    },

    MuiSwitch: {
      styleOverrides: {
        switchBase: {
          '&.Mui-checked': {
            color: cyberColors.neon.cyan,
            '& + .MuiSwitch-track': {
              backgroundColor: alpha(cyberColors.neon.cyan, 0.4),
              opacity: 1,
            },
          },
        },
        track: {
          backgroundColor: alpha(cyberColors.border.strong, 0.5),
          opacity: 1,
        },
      },
    },

    MuiSlider: {
      styleOverrides: {
        root: {
          color: cyberColors.neon.cyan,
        },
        thumb: {
          boxShadow: `0 0 0 4px ${alpha(cyberColors.neon.cyan, 0.15)}`,
          '&:hover': {
            boxShadow: `0 0 0 6px ${alpha(cyberColors.neon.cyan, 0.2)}`,
          },
        },
        track: {
          background: designTokens.colors.gradients.primary,
          border:     'none',
        },
        rail: {
          backgroundColor: cyberColors.border.default,
        },
      },
    },

    MuiListItemButton: {
      styleOverrides: {
        root: {
          borderRadius: designTokens.borderRadius.md,
          margin:       '1px 8px',
          padding:      '6px 12px',
          color:        cyberColors.text.secondary,
          '&:hover': {
            background: alpha(cyberColors.neon.cyan, 0.06),
            color:      cyberColors.text.primary,
          },
          '&.Mui-selected': {
            background:  alpha(cyberColors.neon.cyan, 0.1),
            color:       cyberColors.neon.cyan,
            borderLeft:  `2px solid ${cyberColors.neon.cyan}`,
            '&:hover': {
              background: alpha(cyberColors.neon.cyan, 0.12),
            },
          },
        },
      },
    },

    MuiDivider: {
      styleOverrides: {
        root: {
          borderColor: cyberColors.border.default,
        },
      },
    },

    MuiMenu: {
      styleOverrides: {
        paper: {
          background:   cyberColors.dark.slate,
          border:       `1px solid ${cyberColors.border.default}`,
          borderRadius: designTokens.borderRadius.lg,
          boxShadow:    designTokens.shadows.lg,
        },
      },
    },

    MuiMenuItem: {
      styleOverrides: {
        root: {
          fontSize:  designTokens.typography.fontSizes.sm,
          color:     cyberColors.text.secondary,
          '&:hover': {
            background: alpha(cyberColors.neon.cyan, 0.06),
            color:      cyberColors.text.primary,
          },
          '&.Mui-selected': {
            background: alpha(cyberColors.neon.cyan, 0.1),
            color:      cyberColors.neon.cyan,
          },
        },
      },
    },
  },
};

export const theme = createTheme(themeOptions);

// =============================================================================
// CSS Variable Generator
// =============================================================================

export const getCSSVariables = (): Record<string, string> => ({
  '--color-primary':        designTokens.colors.primary.main,
  '--color-primary-light':  designTokens.colors.primary.light,
  '--color-primary-dark':   designTokens.colors.primary.dark,
  '--color-secondary':      designTokens.colors.secondary.main,
  '--color-success':        designTokens.colors.success.main,
  '--color-warning':        designTokens.colors.warning.main,
  '--color-error':          designTokens.colors.error.main,
  '--color-info':           designTokens.colors.info.main,
  '--color-bg-default':     designTokens.colors.background.default,
  '--color-bg-paper':       designTokens.colors.background.paper,
  '--color-bg-elevated':    designTokens.colors.background.elevated,
  '--color-text-primary':   designTokens.colors.text.primary,
  '--color-text-secondary': designTokens.colors.text.secondary,
  '--color-border':         designTokens.colors.border.main,
  // Threat severity
  '--threat-critical':      designTokens.colors.risk.critical,
  '--threat-high':          designTokens.colors.risk.high,
  '--threat-medium':        designTokens.colors.risk.medium,
  '--threat-low':           designTokens.colors.risk.low,
  '--threat-none':          designTokens.colors.risk.none,
  // Cyber accent aliases (back-compat)
  '--cyber-cyan':           cyberColors.neon.cyan,
  '--cyber-magenta':        cyberColors.neon.magenta,
  '--cyber-green':          cyberColors.neon.green,
  '--cyber-red':            cyberColors.neon.red,
  '--cyber-orange':         cyberColors.neon.orange,
  // Typography
  '--font-family':          designTokens.typography.fontFamily.primary,
  '--font-family-mono':     designTokens.typography.fontFamily.mono,
  '--font-family-display':  designTokens.typography.fontFamily.display,
  // Radius
  '--radius-sm':   designTokens.borderRadius.sm,
  '--radius-md':   designTokens.borderRadius.md,
  '--radius-lg':   designTokens.borderRadius.lg,
  // Shadows
  '--shadow-sm':   designTokens.shadows.sm,
  '--shadow-md':   designTokens.shadows.md,
  '--shadow-lg':   designTokens.shadows.lg,
  '--shadow-glow': designTokens.shadows.glow.primary,
  // Transitions
  '--transition-fast':   designTokens.transitions.fast,
  '--transition-normal': designTokens.transitions.normal,
});

// =============================================================================
// Helper Functions
// =============================================================================

export const getRiskColor = (level: 'critical' | 'high' | 'medium' | 'low'): string =>
  designTokens.colors.risk[level];

export const getGlowShadow = (
  color: string,
  intensity: 'subtle' | 'medium' | 'strong' = 'medium'
): string => {
  const intensities = {
    subtle: `0 0 6px ${alpha(color, 0.2)}`,
    medium: `0 0 12px ${alpha(color, 0.35)}, 0 0 24px ${alpha(color, 0.2)}`,
    strong: `0 0 20px ${alpha(color, 0.5)}, 0 0 40px ${alpha(color, 0.3)}`,
  };
  return intensities[intensity];
};

export default theme;
