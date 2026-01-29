/**
 * Card Component
 *
 * Reusable card container with header, content, and footer sections.
 * Supports different variants and interactive states.
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
} from '@mui/material';
import { designTokens } from '../../utils/theme';

export type CardVariant = 'default' | 'elevated' | 'outlined' | 'gradient';

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
};

const StyledCard = styled(MuiCard, {
  shouldForwardProp: (prop) =>
    !['cardVariant', 'interactive', 'cardPadding'].includes(prop as string),
})<{
  cardVariant: CardVariant;
  interactive?: boolean;
  cardPadding: string | number;
}>(({ cardVariant, interactive }) => ({
  borderRadius: designTokens.borderRadius.lg,
  transition: designTokens.transitions.normal,
  ...variantStyles[cardVariant],
  ...(interactive && {
    cursor: 'pointer',
    '&:hover': {
      borderColor: designTokens.colors.border.light,
      boxShadow: designTokens.shadows.lg,
      transform: 'translateY(-2px)',
    },
    '&:focus-visible': {
      outline: `2px solid ${designTokens.colors.primary.main}`,
      outlineOffset: '2px',
    },
  }),
}));

const StyledCardHeader = styled(CardHeader)({
  padding: '16px 16px 8px',
  '& .MuiCardHeader-title': {
    fontSize: designTokens.typography.fontSizes.lg,
    fontWeight: designTokens.typography.fontWeights.semibold,
    color: designTokens.colors.text.primary,
  },
  '& .MuiCardHeader-subheader': {
    fontSize: designTokens.typography.fontSizes.sm,
    color: designTokens.colors.text.secondary,
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
}) => {
  const cardPadding = paddingValues[padding];

  if (loading) {
    return (
      <StyledCard
        cardVariant={variant}
        interactive={false}
        cardPadding={cardPadding}
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

  return (
    <StyledCard
      cardVariant={variant}
      interactive={interactive}
      cardPadding={cardPadding}
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
      {(title || subtitle || headerAction) && (
        <StyledCardHeader
          title={title}
          subheader={subtitle}
          action={headerAction}
        />
      )}
      <StyledCardContent cardPadding={cardPadding}>{children}</StyledCardContent>
      {footer && <StyledCardActions>{footer}</StyledCardActions>}
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
  color: designTokens.colors.text.primary,
});

const StatTrend = styled(Typography, {
  shouldForwardProp: (prop) => prop !== 'trend',
})<{ trend: 'up' | 'down' | 'neutral' }>(({ trend }) => ({
  fontSize: designTokens.typography.fontSizes.sm,
  color:
    trend === 'up'
      ? designTokens.colors.success.main
      : trend === 'down'
      ? designTokens.colors.error.main
      : designTokens.colors.text.secondary,
}));

const StatIconContainer = styled(Box)({
  width: 48,
  height: 48,
  borderRadius: designTokens.borderRadius.md,
  background: designTokens.colors.background.elevated,
  display: 'flex',
  alignItems: 'center',
  justifyContent: 'center',
  color: designTokens.colors.primary.main,
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
