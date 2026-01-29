/**
 * StatusIndicator Component
 *
 * Visual indicator for status states with support for
 * different variants, sizes, and accessibility labels.
 */

import React from 'react';
import { Box, Typography, Chip, styled, keyframes } from '@mui/material';
import { designTokens } from '../../utils/theme';

export type StatusVariant = 'success' | 'warning' | 'error' | 'info' | 'neutral' | 'pending';

export interface StatusIndicatorProps {
  /** Status variant determines color */
  variant: StatusVariant;
  /** Optional label text */
  label?: string;
  /** Size of the indicator */
  size?: 'sm' | 'md' | 'lg';
  /** Show pulse animation for active states */
  pulse?: boolean;
  /** Display as badge/chip */
  asBadge?: boolean;
  /** Accessible label for screen readers */
  ariaLabel?: string;
  /** Test ID for testing */
  testId?: string;
}

const pulseAnimation = keyframes`
  0% {
    transform: scale(1);
    opacity: 1;
  }
  50% {
    transform: scale(1.5);
    opacity: 0.5;
  }
  100% {
    transform: scale(1);
    opacity: 1;
  }
`;

const variantColors = {
  success: {
    main: designTokens.colors.success.main,
    light: designTokens.colors.success.light,
    background: `${designTokens.colors.success.main}20`,
  },
  warning: {
    main: designTokens.colors.warning.main,
    light: designTokens.colors.warning.light,
    background: `${designTokens.colors.warning.main}20`,
  },
  error: {
    main: designTokens.colors.error.main,
    light: designTokens.colors.error.light,
    background: `${designTokens.colors.error.main}20`,
  },
  info: {
    main: designTokens.colors.info.main,
    light: designTokens.colors.info.light,
    background: `${designTokens.colors.info.main}20`,
  },
  neutral: {
    main: designTokens.colors.text.secondary,
    light: designTokens.colors.text.disabled,
    background: `${designTokens.colors.text.secondary}20`,
  },
  pending: {
    main: designTokens.colors.secondary.main,
    light: designTokens.colors.secondary.light,
    background: `${designTokens.colors.secondary.main}20`,
  },
};

const sizeValues = {
  sm: { dot: 8, fontSize: '0.75rem', padding: '2px 8px' },
  md: { dot: 10, fontSize: '0.8125rem', padding: '4px 10px' },
  lg: { dot: 12, fontSize: '0.875rem', padding: '6px 12px' },
};

const Container = styled(Box)({
  display: 'inline-flex',
  alignItems: 'center',
  gap: '8px',
});

const StatusDot = styled(Box, {
  shouldForwardProp: (prop) =>
    !['statusVariant', 'statusSize', 'pulse'].includes(prop as string),
})<{
  statusVariant: StatusVariant;
  statusSize: 'sm' | 'md' | 'lg';
  pulse?: boolean;
}>(({ statusVariant, statusSize, pulse }) => ({
  width: sizeValues[statusSize].dot,
  height: sizeValues[statusSize].dot,
  borderRadius: '50%',
  backgroundColor: variantColors[statusVariant].main,
  flexShrink: 0,
  ...(pulse && {
    animation: `${pulseAnimation} 2s ease-in-out infinite`,
  }),
}));

const StatusLabel = styled(Typography, {
  shouldForwardProp: (prop) => !['statusSize'].includes(prop as string),
})<{
  statusSize: 'sm' | 'md' | 'lg';
}>(({ statusSize }) => ({
  fontSize: sizeValues[statusSize].fontSize,
  color: designTokens.colors.text.primary,
  fontWeight: designTokens.typography.fontWeights.medium,
}));

const StatusChip = styled(Chip, {
  shouldForwardProp: (prop) =>
    !['statusVariant', 'statusSize'].includes(prop as string),
})<{
  statusVariant: StatusVariant;
  statusSize: 'sm' | 'md' | 'lg';
}>(({ statusVariant, statusSize }) => ({
  backgroundColor: variantColors[statusVariant].background,
  color: variantColors[statusVariant].main,
  borderRadius: designTokens.borderRadius.md,
  fontSize: sizeValues[statusSize].fontSize,
  fontWeight: designTokens.typography.fontWeights.medium,
  height: 'auto',
  '& .MuiChip-label': {
    padding: sizeValues[statusSize].padding,
  },
}));

export const StatusIndicator: React.FC<StatusIndicatorProps> = ({
  variant,
  label,
  size = 'md',
  pulse = false,
  asBadge = false,
  ariaLabel,
  testId,
}) => {
  const accessibleLabel = ariaLabel || `Status: ${label || variant}`;

  if (asBadge && label) {
    return (
      <StatusChip
        statusVariant={variant}
        statusSize={size}
        label={label}
        size="small"
        aria-label={accessibleLabel}
        data-testid={testId}
      />
    );
  }

  return (
    <Container
      role="status"
      aria-label={accessibleLabel}
      data-testid={testId}
    >
      <StatusDot
        statusVariant={variant}
        statusSize={size}
        pulse={pulse}
        aria-hidden="true"
      />
      {label && (
        <StatusLabel statusSize={size}>{label}</StatusLabel>
      )}
    </Container>
  );
};

// =============================================================================
// Risk Level Indicator
// =============================================================================

export interface RiskLevelIndicatorProps {
  level: 'critical' | 'high' | 'medium' | 'low';
  score?: number;
  showScore?: boolean;
  size?: 'sm' | 'md' | 'lg';
  testId?: string;
}

const riskVariantMap: Record<string, StatusVariant> = {
  critical: 'error',
  high: 'warning',
  medium: 'info',
  low: 'success',
};

const riskLabels: Record<string, string> = {
  critical: 'Critical',
  high: 'High',
  medium: 'Medium',
  low: 'Low',
};

export const RiskLevelIndicator: React.FC<RiskLevelIndicatorProps> = ({
  level,
  score,
  showScore = true,
  size = 'md',
  testId,
}) => {
  const variant = riskVariantMap[level];
  const label = showScore && score !== undefined
    ? `${riskLabels[level]} (${score})`
    : riskLabels[level];

  return (
    <StatusIndicator
      variant={variant}
      label={label}
      size={size}
      asBadge
      ariaLabel={`Risk level: ${label}`}
      testId={testId}
    />
  );
};

// =============================================================================
// Investigation Status Indicator
// =============================================================================

export interface InvestigationStatusIndicatorProps {
  status: string;
  progress?: number;
  size?: 'sm' | 'md' | 'lg';
  testId?: string;
}

const statusVariantMap: Record<string, StatusVariant> = {
  pending: 'neutral',
  queued: 'pending',
  planning: 'info',
  profiling: 'info',
  collecting: 'info',
  analyzing: 'info',
  assessing_risk: 'info',
  verifying: 'info',
  generating_report: 'info',
  completed: 'success',
  failed: 'error',
  cancelled: 'warning',
};

const statusLabels: Record<string, string> = {
  pending: 'Pending',
  queued: 'Queued',
  planning: 'Planning',
  profiling: 'Profiling',
  collecting: 'Collecting',
  analyzing: 'Analyzing',
  assessing_risk: 'Assessing Risk',
  verifying: 'Verifying',
  generating_report: 'Generating Report',
  completed: 'Completed',
  failed: 'Failed',
  cancelled: 'Cancelled',
};

export const InvestigationStatusIndicator: React.FC<
  InvestigationStatusIndicatorProps
> = ({ status, progress, size = 'md', testId }) => {
  const variant = statusVariantMap[status] || 'neutral';
  const label = statusLabels[status] || status;
  const isActive = [
    'planning',
    'profiling',
    'collecting',
    'analyzing',
    'assessing_risk',
    'verifying',
    'generating_report',
  ].includes(status);

  return (
    <StatusIndicator
      variant={variant}
      label={progress !== undefined ? `${label} (${progress}%)` : label}
      size={size}
      pulse={isActive}
      asBadge
      ariaLabel={`Investigation status: ${label}${
        progress !== undefined ? `, ${progress}% complete` : ''
      }`}
      testId={testId}
    />
  );
};

export default StatusIndicator;
