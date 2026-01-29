/**
 * Button Component
 *
 * Reusable button with multiple variants, sizes, and states.
 * Supports icons, loading states, and full accessibility.
 */

import React from 'react';
import {
  Button as MuiButton,
  ButtonProps as MuiButtonProps,
  CircularProgress,
  styled,
} from '@mui/material';
import { designTokens } from '../../utils/theme';

export type ButtonVariant = 'primary' | 'secondary' | 'success' | 'warning' | 'danger' | 'ghost';
export type ButtonSize = 'sm' | 'md' | 'lg';

export interface ButtonProps extends Omit<MuiButtonProps, 'variant' | 'size'> {
  /** Visual style variant */
  variant?: ButtonVariant;
  /** Button size */
  size?: ButtonSize;
  /** Shows loading spinner and disables button */
  loading?: boolean;
  /** Icon to display before text */
  startIcon?: React.ReactNode;
  /** Icon to display after text */
  endIcon?: React.ReactNode;
  /** Makes button full width */
  fullWidth?: boolean;
  /** Test ID for testing */
  testId?: string;
}

const sizeStyles = {
  sm: {
    padding: '6px 12px',
    fontSize: '0.8125rem',
    minHeight: '32px',
  },
  md: {
    padding: '8px 16px',
    fontSize: '0.875rem',
    minHeight: '40px',
  },
  lg: {
    padding: '12px 24px',
    fontSize: '1rem',
    minHeight: '48px',
  },
};

const variantStyles = {
  primary: {
    background: designTokens.colors.gradients.primary,
    color: '#ffffff',
    '&:hover': {
      background: designTokens.colors.gradients.primary,
      filter: 'brightness(1.1)',
    },
    '&:disabled': {
      background: designTokens.colors.background.surface,
      color: designTokens.colors.text.disabled,
    },
  },
  secondary: {
    background: designTokens.colors.secondary.main,
    color: '#ffffff',
    '&:hover': {
      background: designTokens.colors.secondary.light,
    },
    '&:disabled': {
      background: designTokens.colors.background.surface,
      color: designTokens.colors.text.disabled,
    },
  },
  success: {
    background: designTokens.colors.success.main,
    color: '#ffffff',
    '&:hover': {
      background: designTokens.colors.success.light,
    },
    '&:disabled': {
      background: designTokens.colors.background.surface,
      color: designTokens.colors.text.disabled,
    },
  },
  warning: {
    background: designTokens.colors.warning.main,
    color: '#000000',
    '&:hover': {
      background: designTokens.colors.warning.light,
    },
    '&:disabled': {
      background: designTokens.colors.background.surface,
      color: designTokens.colors.text.disabled,
    },
  },
  danger: {
    background: designTokens.colors.error.main,
    color: '#ffffff',
    '&:hover': {
      background: designTokens.colors.error.light,
    },
    '&:disabled': {
      background: designTokens.colors.background.surface,
      color: designTokens.colors.text.disabled,
    },
  },
  ghost: {
    background: 'transparent',
    color: designTokens.colors.text.primary,
    border: `1px solid ${designTokens.colors.border.main}`,
    '&:hover': {
      background: designTokens.colors.background.elevated,
      borderColor: designTokens.colors.border.light,
    },
    '&:disabled': {
      color: designTokens.colors.text.disabled,
      borderColor: designTokens.colors.border.dark,
    },
  },
};

const StyledButton = styled(MuiButton, {
  shouldForwardProp: (prop) =>
    !['buttonVariant', 'buttonSize', 'loading'].includes(prop as string),
})<{
  buttonVariant: ButtonVariant;
  buttonSize: ButtonSize;
  loading?: boolean;
}>(({ buttonVariant, buttonSize, loading }) => ({
  borderRadius: designTokens.borderRadius.md,
  fontWeight: designTokens.typography.fontWeights.medium,
  textTransform: 'none',
  transition: designTokens.transitions.normal,
  position: 'relative',
  ...sizeStyles[buttonSize],
  ...variantStyles[buttonVariant],
  ...(loading && {
    color: 'transparent',
    pointerEvents: 'none',
  }),
  '&:focus-visible': {
    outline: `2px solid ${designTokens.colors.primary.main}`,
    outlineOffset: '2px',
  },
}));

const LoadingSpinner = styled(CircularProgress)({
  position: 'absolute',
  top: '50%',
  left: '50%',
  marginTop: '-10px',
  marginLeft: '-10px',
});

export const Button: React.FC<ButtonProps> = ({
  variant = 'primary',
  size = 'md',
  loading = false,
  startIcon,
  endIcon,
  children,
  disabled,
  fullWidth,
  testId,
  ...props
}) => {
  return (
    <StyledButton
      buttonVariant={variant}
      buttonSize={size}
      loading={loading}
      disabled={disabled || loading}
      startIcon={!loading ? startIcon : undefined}
      endIcon={!loading ? endIcon : undefined}
      fullWidth={fullWidth}
      data-testid={testId}
      aria-busy={loading}
      {...props}
    >
      {children}
      {loading && <LoadingSpinner size={20} color="inherit" />}
    </StyledButton>
  );
};

export default Button;
