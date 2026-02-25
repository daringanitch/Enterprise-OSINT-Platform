/**
 * Card Component
 *
 * Reusable card container with header, content, and footer sections.
 * Supports different variants and interactive states including glassmorphism.
 */

import React from 'react';
import {
  Card as MuiCard,
  CardContent,
  CardHeader,
  CardActions,
  Typography,
  Box,
  Skeleton,
  styled,
  alpha,
} from '@mui/material';
import { motion } from 'framer-motion';
import { designTokens, glassmorphism, cyberColors } from '../../utils/theme';
import { cardVariants, glassCardVariants } from '../../utils/animations';

export type CardVariant = 'default' | 'elevated' | 'outlined' | 'gradient' | 'glass' | 'cyber';

export interface CardProps {
  /** Card title */
  title?: string;
  /** Subtitle or description */
  subtitle?: string;
  /** Header action element (e.g., icon button) */
  headerAction?: React.ReactNode;
  /** Main card content */
  children: React.ReactNode;
  /** Footer content or actions */
  footer?: React.ReactNode;
  /** Visual variant */
  variant?: CardVariant;
  /** Makes card clickable with hover effects */
  interactive?: boolean;
  /** Click handler for interactive cards */
  onClick?: () => void;
  /** Loading state shows skeleton */
  loading?: boolean;
  /** Custom padding */
  padding?: 'none' | 'sm' | 'md' | 'lg';
  /** Test ID for testing */
  testId?: string;
  /** Additional CSS class */
  className?: string;
  /** Enable framer-motion animations */
  animated?: boolean;
  /** Custom glow color for cyber/glass variants */
  glowColor?: string;
  /** Animation delay (for staggered lists) */
  animationDelay?: number;
}

const paddingValues = {
  none: 0,
  sm: '12px',
  md: '16px',
  lg: '24px',
};

const variantStyles = {
  default: {
    background: designTokens.colors.background.paper,
    border: `1px solid ${designTokens.colors.border.dark}`,
  },
  elevated: {
    background: designTokens.colors.background.elevated,
    border: 'none',
    boxShadow: designTokens.shadows.lg,
  },
  outlined: {
    background: 'transparent',
    border: `1px solid ${designTokens.colors.border.main}`,
  },
  gradient: {
    background: designTokens.colors.gradients.surface,
    border: `1px solid ${designTokens.colors.border.dark}`,
  },
  glass: {
    ...glassmorphism.card,
  },
  cyber: {
    ...glassmorphism.card,
    border: `1px solid ${alpha(cyberColors.neon.cyan, 0.3)}`,
    position: 'relative' as const,
    overflow: 'hidden',
    '&::before': {
      content: '""',
      position: 'absolute',
      top: 0,
      left: 0,
      right: 0,
      height: '2px',
      background: designTokens.colors.gradients.primary,
    },
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
      zIndex: 1,
    },
  },
};

const StyledCard = styled(MuiCard, {
  shouldForwardProp: (prop) =>
    !['cardVariant', 'interactive', 'cardPadding', 'glowColor'].includes(prop as string),
})<{
  cardVariant: CardVariant;
  interactive?: boolean;
  cardPadding: string | number;
  glowColor?: string;
}>(({ cardVariant, interactive, glowColor }) => ({
  borderRadius: designTokens.borderRadius.lg,
  transition: 'all 0.3s ease',
  ...variantStyles[cardVariant],
  ...(interactive && {
    cursor: 'pointer',
    '&:hover': {
      borderColor: cardVariant === 'cyber' || cardVariant === 'glass'
        ? alpha(cyberColors.neon.cyan, 0.5)
        : designTokens.colors.border.light,
      boxShadow: cardVariant === 'cyber' || cardVariant === 'glass'
        ? `0 8px 32px rgba(0, 0, 0, 0.5), 0 0 20px ${alpha(glowColor || cyberColors.neon.cyan, 0.3)}`
        : designTokens.shadows.lg,
      transform: 'translateY(-4px)',
    },
    '&:focus-visible': {
      outline: `2px solid ${designTokens.colors.primary.main}`,
      outlineOffset: '2px',
    },
  }),
  ...(cardVariant === 'cyber' && {
    '&:hover::before': {
      animation: 'gradientShift 2s linear infinite',
    },
    '@keyframes gradientShift': {
      '0%': { backgroundPosition: '0% 50%' },
      '100%': { backgroundPosition: '200% 50%' },
    },
  }),
}));

// Motion-enabled card wrapper
const MotionCard = motion(StyledCard);

const StyledCardHeader = styled(CardHeader)({
  padding: '16px 16px 8px',
  '& .MuiCardHeader-title': {
    fontSize: designTokens.typography.fontSizes.lg,
    fontWeight: designTokens.typography.fontWeights.semibold,
    color: designTokens.colors.text.primary,
    fontFamily: designTokens.typography.fontFamily.display,
    letterSpacing: '0.02em',
  },
  '& .MuiCardHeader-subheader': {
    fontSize: designTokens.typography.fontSizes.sm,
    color: designTokens.colors.text.secondary,
    fontFamily: designTokens.typography.fontFamily.mono,
  },
});

const StyledCardContent = styled(CardContent, {
  shouldForwardProp: (prop) => prop !== 'cardPadding',
})<{ cardPadding: string | number }>(({ cardPadding }) => ({
  padding: cardPadding,
  '&:last-child': {
    paddingBottom: cardPadding,
  },
}));

const StyledCardActions = styled(CardActions)({
  padding: '8px 16px 16px',
  borderTop: `1px solid ${designTokens.colors.border.dark}`,
  marginTop: '8px',
});

export const Card: React.FC<CardProps> = ({
  title,
  subtitle,
  headerAction,
  children,
  footer,
  variant = 'default',
  interactive = false,
  onClick,
  loading = false,
  padding = 'md',
  testId,
  className,
  animated = false,
  glowColor,
  animationDelay = 0,
}) => {
  const cardPadding = paddingValues[padding];
  const isGlassVariant = variant === 'glass' || variant === 'cyber';

  // Animation variants based on card type
  const variants = isGlassVariant ? glassCardVariants : cardVariants;

  if (loading) {
    return (
      <StyledCard
        cardVariant={variant}
        interactive={false}
        cardPadding={cardPadding}
        glowColor={glowColor}
        data-testid={testId}
        className={className}
      >
        {(title || subtitle) && (
          <StyledCardHeader
            title={<Skeleton width="60%" height={24} />}
            subheader={subtitle && <Skeleton width="40%" height={16} />}
          />
        )}
        <StyledCardContent cardPadding={cardPadding}>
          <Skeleton variant="rectangular" height={100} />
        </StyledCardContent>
      </StyledCard>
    );
  }

  const cardContent = (
    <>
      {(title || subtitle || headerAction) && (
        <StyledCardHeader
          title={title}
          subheader={subtitle}
          action={headerAction}
        />
      )}
      <StyledCardContent cardPadding={cardPadding}>{children}</StyledCardContent>
      {footer && <StyledCardActions>{footer}</StyledCardActions>}
    </>
  );

  // Use motion wrapper if animated
  if (animated) {
    return (
      <MotionCard
        cardVariant={variant}
        interactive={interactive}
        cardPadding={cardPadding}
        glowColor={glowColor}
        onClick={interactive ? onClick : undefined}
        tabIndex={interactive ? 0 : undefined}
        onKeyDown={
          interactive
            ? (e: React.KeyboardEvent) => {
                if (e.key === 'Enter' || e.key === ' ') {
                  e.preventDefault();
                  onClick?.();
                }
              }
            : undefined
        }
        role={interactive ? 'button' : undefined}
        data-testid={testId}
        className={className}
        initial="initial"
        animate="enter"
        exit="exit"
        whileHover={interactive ? 'hover' : undefined}
        whileTap={interactive ? 'tap' : undefined}
        variants={variants}
        transition={{ delay: animationDelay }}
      >
        {cardContent}
      </MotionCard>
    );
  }

  return (
    <StyledCard
      cardVariant={variant}
      interactive={interactive}
      cardPadding={cardPadding}
      glowColor={glowColor}
      onClick={interactive ? onClick : undefined}
      tabIndex={interactive ? 0 : undefined}
      onKeyDown={
        interactive
          ? (e) => {
              if (e.key === 'Enter' || e.key === ' ') {
                e.preventDefault();
                onClick?.();
              }
            }
          : undefined
      }
      role={interactive ? 'button' : undefined}
      data-testid={testId}
      className={className}
    >
      {cardContent}
    </StyledCard>
  );
};

// =============================================================================
// Card Subcomponents
// =============================================================================

export interface CardStatProps {
  label: string;
  value: string | number;
  trend?: 'up' | 'down' | 'neutral';
  trendValue?: string;
  icon?: React.ReactNode;
}

const StatContainer = styled(Box)({
  display: 'flex',
  alignItems: 'center',
  gap: '12px',
});

const StatContent = styled(Box)({
  flex: 1,
});

const StatLabel = styled(Typography)({
  fontSize: designTokens.typography.fontSizes.sm,
  color: designTokens.colors.text.secondary,
  marginBottom: '4px',
});

const StatValue = styled(Typography)({
  fontSize: designTokens.typography.fontSizes['2xl'],
  fontWeight: designTokens.typography.fontWeights.bold,
  color: cyberColors.text.primary,
  fontFamily: designTokens.typography.fontFamily.mono,
});

const StatTrend = styled(Typography, {
  shouldForwardProp: (prop) => prop !== 'trend',
})<{ trend: 'up' | 'down' | 'neutral' }>(({ trend }) => ({
  fontSize: designTokens.typography.fontSizes.sm,
  fontWeight: designTokens.typography.fontWeights.medium,
  color:
    trend === 'up'
      ? cyberColors.neon.green
      : trend === 'down'
      ? cyberColors.neon.red
      : designTokens.colors.text.secondary,
  textShadow: trend === 'up'
    ? `0 0 10px ${alpha(cyberColors.neon.green, 0.5)}`
    : trend === 'down'
    ? `0 0 10px ${alpha(cyberColors.neon.red, 0.5)}`
    : 'none',
}));

const StatIconContainer = styled(Box)({
  width: 48,
  height: 48,
  borderRadius: designTokens.borderRadius.md,
  background: alpha(cyberColors.neon.cyan, 0.1),
  border: `1px solid ${alpha(cyberColors.neon.cyan, 0.2)}`,
  display: 'flex',
  alignItems: 'center',
  justifyContent: 'center',
  color: cyberColors.neon.cyan,
  boxShadow: `0 0 10px ${alpha(cyberColors.neon.cyan, 0.2)}`,
});

export const CardStat: React.FC<CardStatProps> = ({
  label,
  value,
  trend,
  trendValue,
  icon,
}) => {
  return (
    <StatContainer>
      {icon && <StatIconContainer>{icon}</StatIconContainer>}
      <StatContent>
        <StatLabel variant="body2">{label}</StatLabel>
        <StatValue variant="h4">{value}</StatValue>
        {trend && trendValue && (
          <StatTrend trend={trend}>
            {trend === 'up' ? '↑' : trend === 'down' ? '↓' : '→'} {trendValue}
          </StatTrend>
        )}
      </StatContent>
    </StatContainer>
  );
};

export default Card;
