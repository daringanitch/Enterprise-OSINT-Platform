/**
 * Loading Components
 *
 * Various loading indicators including spinners, skeletons,
 * and full-page loading states.
 */

import React from 'react';
import {
  CircularProgress,
  LinearProgress,
  Skeleton,
  Box,
  Typography,
  styled,
  keyframes,
} from '@mui/material';
import { designTokens } from '../../utils/theme';

// =============================================================================
// Spinner
// =============================================================================

export interface SpinnerProps {
  /** Spinner size */
  size?: 'sm' | 'md' | 'lg';
  /** Color variant */
  color?: 'primary' | 'secondary' | 'inherit';
  /** Accessible label */
  label?: string;
  /** Test ID for testing */
  testId?: string;
}

const sizeMap = {
  sm: 20,
  md: 32,
  lg: 48,
};

const StyledCircularProgress = styled(CircularProgress)({
  color: designTokens.colors.primary.main,
});

export const Spinner: React.FC<SpinnerProps> = ({
  size = 'md',
  color = 'primary',
  label = 'Loading',
  testId,
}) => {
  return (
    <StyledCircularProgress
      size={sizeMap[size]}
      color={color}
      aria-label={label}
      data-testid={testId}
    />
  );
};

// =============================================================================
// Progress Bar
// =============================================================================

export interface ProgressBarProps {
  /** Current progress value (0-100) */
  value?: number;
  /** Show as indeterminate (no value) */
  indeterminate?: boolean;
  /** Color variant */
  color?: 'primary' | 'secondary' | 'success' | 'warning' | 'error';
  /** Show percentage label */
  showLabel?: boolean;
  /** Custom label */
  label?: string;
  /** Height of the bar */
  height?: number;
  /** Test ID for testing */
  testId?: string;
}

const ProgressContainer = styled(Box)({
  width: '100%',
});

const ProgressLabel = styled(Box)({
  display: 'flex',
  justifyContent: 'space-between',
  alignItems: 'center',
  marginBottom: '8px',
});

const ProgressText = styled(Typography)({
  fontSize: designTokens.typography.fontSizes.sm,
  color: designTokens.colors.text.secondary,
});

const ProgressValue = styled(Typography)({
  fontSize: designTokens.typography.fontSizes.sm,
  fontWeight: designTokens.typography.fontWeights.medium,
  color: designTokens.colors.text.primary,
});

const StyledLinearProgress = styled(LinearProgress, {
  shouldForwardProp: (prop) => prop !== 'customHeight',
})<{ customHeight: number }>(({ customHeight }) => ({
  height: customHeight,
  borderRadius: customHeight / 2,
  backgroundColor: designTokens.colors.background.elevated,
  '& .MuiLinearProgress-bar': {
    borderRadius: customHeight / 2,
  },
}));

export const ProgressBar: React.FC<ProgressBarProps> = ({
  value,
  indeterminate = false,
  color = 'primary',
  showLabel = false,
  label,
  height = 8,
  testId,
}) => {
  return (
    <ProgressContainer data-testid={testId}>
      {(showLabel || label) && (
        <ProgressLabel>
          <ProgressText>{label || 'Progress'}</ProgressText>
          {!indeterminate && value !== undefined && (
            <ProgressValue>{Math.round(value)}%</ProgressValue>
          )}
        </ProgressLabel>
      )}
      <StyledLinearProgress
        variant={indeterminate ? 'indeterminate' : 'determinate'}
        value={value}
        color={color}
        customHeight={height}
        aria-label={label || 'Progress'}
        aria-valuenow={value}
        aria-valuemin={0}
        aria-valuemax={100}
      />
    </ProgressContainer>
  );
};

// =============================================================================
// Loading Overlay
// =============================================================================

export interface LoadingOverlayProps {
  /** Whether to show the overlay */
  loading: boolean;
  /** Loading message */
  message?: string;
  /** Make overlay translucent */
  translucent?: boolean;
  /** Test ID for testing */
  testId?: string;
  /** Children to overlay */
  children?: React.ReactNode;
}

const OverlayContainer = styled(Box)({
  position: 'relative',
  width: '100%',
  height: '100%',
});

const Overlay = styled(Box, {
  shouldForwardProp: (prop) => prop !== 'translucent',
})<{ translucent: boolean }>(({ translucent }) => ({
  position: 'absolute',
  top: 0,
  left: 0,
  right: 0,
  bottom: 0,
  display: 'flex',
  flexDirection: 'column',
  alignItems: 'center',
  justifyContent: 'center',
  backgroundColor: translucent
    ? 'rgba(10, 10, 10, 0.8)'
    : designTokens.colors.background.default,
  backdropFilter: translucent ? 'blur(4px)' : 'none',
  zIndex: 10,
  borderRadius: designTokens.borderRadius.lg,
}));

const LoadingMessage = styled(Typography)({
  marginTop: '16px',
  fontSize: designTokens.typography.fontSizes.sm,
  color: designTokens.colors.text.secondary,
});

export const LoadingOverlay: React.FC<LoadingOverlayProps> = ({
  loading,
  message,
  translucent = true,
  testId,
  children,
}) => {
  return (
    <OverlayContainer>
      {children}
      {loading && (
        <Overlay translucent={translucent} data-testid={testId}>
          <Spinner size="lg" />
          {message && <LoadingMessage>{message}</LoadingMessage>}
        </Overlay>
      )}
    </OverlayContainer>
  );
};

// =============================================================================
// Full Page Loading
// =============================================================================

export interface FullPageLoadingProps {
  /** Loading message */
  message?: string;
  /** Show logo */
  showLogo?: boolean;
  /** Test ID for testing */
  testId?: string;
}

const pulseAnimation = keyframes`
  0%, 100% {
    opacity: 1;
  }
  50% {
    opacity: 0.5;
  }
`;

const FullPageContainer = styled(Box)({
  position: 'fixed',
  top: 0,
  left: 0,
  right: 0,
  bottom: 0,
  display: 'flex',
  flexDirection: 'column',
  alignItems: 'center',
  justifyContent: 'center',
  background: designTokens.colors.gradients.surface,
  zIndex: 9999,
});

const Logo = styled(Box)({
  marginBottom: '32px',
  animation: `${pulseAnimation} 2s ease-in-out infinite`,
});

const LogoText = styled(Typography)({
  fontSize: designTokens.typography.fontSizes['3xl'],
  fontWeight: designTokens.typography.fontWeights.bold,
  background: designTokens.colors.gradients.primary,
  WebkitBackgroundClip: 'text',
  WebkitTextFillColor: 'transparent',
  backgroundClip: 'text',
});

const FullPageMessage = styled(Typography)({
  marginTop: '24px',
  fontSize: designTokens.typography.fontSizes.md,
  color: designTokens.colors.text.secondary,
});

export const FullPageLoading: React.FC<FullPageLoadingProps> = ({
  message = 'Loading...',
  showLogo = true,
  testId,
}) => {
  return (
    <FullPageContainer data-testid={testId} role="status" aria-live="polite">
      {showLogo && (
        <Logo>
          <LogoText>OSINT Platform</LogoText>
        </Logo>
      )}
      <Spinner size="lg" />
      <FullPageMessage>{message}</FullPageMessage>
    </FullPageContainer>
  );
};

// =============================================================================
// Skeleton Loaders
// =============================================================================

export interface SkeletonCardProps {
  /** Show header skeleton */
  showHeader?: boolean;
  /** Number of content lines */
  lines?: number;
  /** Show footer skeleton */
  showFooter?: boolean;
  /** Test ID for testing */
  testId?: string;
}

const SkeletonContainer = styled(Box)({
  padding: '16px',
  backgroundColor: designTokens.colors.background.paper,
  borderRadius: designTokens.borderRadius.lg,
  border: `1px solid ${designTokens.colors.border.dark}`,
});

const StyledSkeleton = styled(Skeleton)({
  backgroundColor: designTokens.colors.background.elevated,
  '&::after': {
    background: `linear-gradient(90deg, transparent, ${designTokens.colors.background.surface}, transparent)`,
  },
});

export const SkeletonCard: React.FC<SkeletonCardProps> = ({
  showHeader = true,
  lines = 3,
  showFooter = false,
  testId,
}) => {
  return (
    <SkeletonContainer data-testid={testId}>
      {showHeader && (
        <Box sx={{ mb: 2 }}>
          <StyledSkeleton variant="text" width="60%" height={24} />
          <StyledSkeleton variant="text" width="40%" height={16} />
        </Box>
      )}
      {Array.from({ length: lines }).map((_, index) => (
        <StyledSkeleton
          key={index}
          variant="text"
          width={index === lines - 1 ? '80%' : '100%'}
          height={20}
          sx={{ mb: 1 }}
        />
      ))}
      {showFooter && (
        <Box sx={{ mt: 2, display: 'flex', gap: 1 }}>
          <StyledSkeleton variant="rounded" width={80} height={32} />
          <StyledSkeleton variant="rounded" width={80} height={32} />
        </Box>
      )}
    </SkeletonContainer>
  );
};

export interface SkeletonTableProps {
  /** Number of rows */
  rows?: number;
  /** Number of columns */
  columns?: number;
  /** Test ID for testing */
  testId?: string;
}

const TableContainer = styled(Box)({
  backgroundColor: designTokens.colors.background.paper,
  borderRadius: designTokens.borderRadius.lg,
  border: `1px solid ${designTokens.colors.border.dark}`,
  overflow: 'hidden',
});

const TableHeader = styled(Box)({
  display: 'flex',
  gap: '16px',
  padding: '12px 16px',
  backgroundColor: designTokens.colors.background.elevated,
  borderBottom: `1px solid ${designTokens.colors.border.dark}`,
});

const TableRow = styled(Box)({
  display: 'flex',
  gap: '16px',
  padding: '12px 16px',
  borderBottom: `1px solid ${designTokens.colors.border.dark}`,
  '&:last-child': {
    borderBottom: 'none',
  },
});

export const SkeletonTable: React.FC<SkeletonTableProps> = ({
  rows = 5,
  columns = 4,
  testId,
}) => {
  return (
    <TableContainer data-testid={testId}>
      <TableHeader>
        {Array.from({ length: columns }).map((_, index) => (
          <StyledSkeleton
            key={index}
            variant="text"
            width={`${100 / columns}%`}
            height={20}
          />
        ))}
      </TableHeader>
      {Array.from({ length: rows }).map((_, rowIndex) => (
        <TableRow key={rowIndex}>
          {Array.from({ length: columns }).map((_, colIndex) => (
            <StyledSkeleton
              key={colIndex}
              variant="text"
              width={`${100 / columns}%`}
              height={18}
            />
          ))}
        </TableRow>
      ))}
    </TableContainer>
  );
};

export default Spinner;
