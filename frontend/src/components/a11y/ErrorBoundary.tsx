/**
 * Error Boundary Component
 *
 * Catches JavaScript errors in child components and displays
 * a fallback UI instead of crashing the whole application.
 */

import React, { Component, ErrorInfo, ReactNode } from 'react';
import { Box, Typography, Button, styled } from '@mui/material';
import ErrorOutlineIcon from '@mui/icons-material/ErrorOutline';
import RefreshIcon from '@mui/icons-material/Refresh';
import { designTokens } from '../../utils/theme';

export interface ErrorBoundaryProps {
  /** Child components to render */
  children: ReactNode;
  /** Custom fallback UI */
  fallback?: ReactNode;
  /** Called when error is caught */
  onError?: (error: Error, errorInfo: ErrorInfo) => void;
  /** Show detailed error in development */
  showDetails?: boolean;
  /** Custom error message */
  errorMessage?: string;
  /** Test ID for testing */
  testId?: string;
}

export interface ErrorBoundaryState {
  hasError: boolean;
  error: Error | null;
  errorInfo: ErrorInfo | null;
}

const ErrorContainer = styled(Box)({
  display: 'flex',
  flexDirection: 'column',
  alignItems: 'center',
  justifyContent: 'center',
  padding: '48px 24px',
  minHeight: '300px',
  backgroundColor: designTokens.colors.background.paper,
  borderRadius: designTokens.borderRadius.lg,
  border: `1px solid ${designTokens.colors.border.dark}`,
  textAlign: 'center',
});

const ErrorIcon = styled(ErrorOutlineIcon)({
  fontSize: '64px',
  color: designTokens.colors.error.main,
  marginBottom: '24px',
});

const ErrorTitle = styled(Typography)({
  fontSize: designTokens.typography.fontSizes['2xl'],
  fontWeight: designTokens.typography.fontWeights.bold,
  color: designTokens.colors.text.primary,
  marginBottom: '12px',
});

const ErrorMessage = styled(Typography)({
  fontSize: designTokens.typography.fontSizes.md,
  color: designTokens.colors.text.secondary,
  marginBottom: '24px',
  maxWidth: '500px',
});

const ErrorDetails = styled(Box)({
  width: '100%',
  maxWidth: '600px',
  marginTop: '24px',
  padding: '16px',
  backgroundColor: designTokens.colors.background.elevated,
  borderRadius: designTokens.borderRadius.md,
  textAlign: 'left',
  overflow: 'auto',
  maxHeight: '200px',
});

const ErrorStack = styled('pre')({
  margin: 0,
  fontSize: designTokens.typography.fontSizes.xs,
  fontFamily: designTokens.typography.fontFamily.mono,
  color: designTokens.colors.error.light,
  whiteSpace: 'pre-wrap',
  wordBreak: 'break-word',
});

const RetryButton = styled(Button)({
  backgroundColor: designTokens.colors.primary.main,
  color: '#ffffff',
  '&:hover': {
    backgroundColor: designTokens.colors.primary.light,
  },
});

export class ErrorBoundary extends Component<ErrorBoundaryProps, ErrorBoundaryState> {
  constructor(props: ErrorBoundaryProps) {
    super(props);
    this.state = {
      hasError: false,
      error: null,
      errorInfo: null,
    };
  }

  static getDerivedStateFromError(error: Error): Partial<ErrorBoundaryState> {
    return { hasError: true, error };
  }

  componentDidCatch(error: Error, errorInfo: ErrorInfo) {
    this.setState({ errorInfo });

    // Log error to console in development
    if (process.env.NODE_ENV === 'development') {
      console.error('ErrorBoundary caught an error:', error, errorInfo);
    }

    // Call custom error handler
    this.props.onError?.(error, errorInfo);
  }

  handleRetry = () => {
    this.setState({
      hasError: false,
      error: null,
      errorInfo: null,
    });
  };

  render() {
    const { hasError, error, errorInfo } = this.state;
    const {
      children,
      fallback,
      showDetails = process.env.NODE_ENV === 'development',
      errorMessage = 'Something went wrong. Please try again or contact support if the problem persists.',
      testId,
    } = this.props;

    if (hasError) {
      // Use custom fallback if provided
      if (fallback) {
        return fallback;
      }

      // Default error UI
      return (
        <ErrorContainer role="alert" data-testid={testId}>
          <ErrorIcon aria-hidden="true" />
          <ErrorTitle>Oops! An error occurred</ErrorTitle>
          <ErrorMessage>{errorMessage}</ErrorMessage>
          <RetryButton
            onClick={this.handleRetry}
            startIcon={<RefreshIcon />}
            data-testid={testId ? `${testId}-retry` : undefined}
          >
            Try Again
          </RetryButton>
          {showDetails && error && (
            <ErrorDetails>
              <Typography
                variant="subtitle2"
                sx={{
                  color: designTokens.colors.text.primary,
                  marginBottom: '8px',
                  fontWeight: 'bold',
                }}
              >
                Error Details:
              </Typography>
              <ErrorStack>
                {error.toString()}
                {errorInfo?.componentStack && (
                  <>
                    {'\n\nComponent Stack:'}
                    {errorInfo.componentStack}
                  </>
                )}
              </ErrorStack>
            </ErrorDetails>
          )}
        </ErrorContainer>
      );
    }

    return children;
  }
}

/**
 * withErrorBoundary HOC
 */
export function withErrorBoundary<P extends object>(
  WrappedComponent: React.ComponentType<P>,
  errorBoundaryProps?: Omit<ErrorBoundaryProps, 'children'>
) {
  const WithErrorBoundary: React.FC<P> = (props) => (
    <ErrorBoundary {...errorBoundaryProps}>
      <WrappedComponent {...props} />
    </ErrorBoundary>
  );

  WithErrorBoundary.displayName = `withErrorBoundary(${
    WrappedComponent.displayName || WrappedComponent.name || 'Component'
  })`;

  return WithErrorBoundary;
}

export default ErrorBoundary;
