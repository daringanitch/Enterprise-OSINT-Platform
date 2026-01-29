/**
 * Toast/Notification Components
 *
 * Provides toast notifications for user feedback with
 * different severity levels and auto-dismiss functionality.
 */

import React, { createContext, useContext, useState, useCallback } from 'react';
import { Snackbar, Alert, AlertTitle, styled, Slide } from '@mui/material';
import { TransitionProps } from '@mui/material/transitions';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import ErrorIcon from '@mui/icons-material/Error';
import WarningIcon from '@mui/icons-material/Warning';
import InfoIcon from '@mui/icons-material/Info';
import { designTokens } from '../../utils/theme';

// =============================================================================
// Types
// =============================================================================

export type ToastSeverity = 'success' | 'error' | 'warning' | 'info';

export interface ToastMessage {
  id: string;
  severity: ToastSeverity;
  title?: string;
  message: string;
  duration?: number;
  action?: React.ReactNode;
}

export interface ToastContextValue {
  showToast: (toast: Omit<ToastMessage, 'id'>) => void;
  showSuccess: (message: string, title?: string) => void;
  showError: (message: string, title?: string) => void;
  showWarning: (message: string, title?: string) => void;
  showInfo: (message: string, title?: string) => void;
  hideToast: (id: string) => void;
}

// =============================================================================
// Styled Components
// =============================================================================

const StyledAlert = styled(Alert, {
  shouldForwardProp: (prop) => prop !== 'toastSeverity',
})<{ toastSeverity: ToastSeverity }>(({ toastSeverity }) => {
  const severityColors = {
    success: designTokens.colors.success,
    error: designTokens.colors.error,
    warning: designTokens.colors.warning,
    info: designTokens.colors.info,
  };

  const colors = severityColors[toastSeverity];

  return {
    backgroundColor: designTokens.colors.background.elevated,
    border: `1px solid ${colors.main}`,
    borderRadius: designTokens.borderRadius.lg,
    boxShadow: designTokens.shadows.lg,
    color: designTokens.colors.text.primary,
    minWidth: '320px',
    maxWidth: '480px',
    '& .MuiAlert-icon': {
      color: colors.main,
    },
    '& .MuiAlertTitle-root': {
      fontWeight: designTokens.typography.fontWeights.semibold,
      color: designTokens.colors.text.primary,
    },
    '& .MuiAlert-message': {
      color: designTokens.colors.text.secondary,
    },
    '& .MuiAlert-action': {
      paddingTop: 0,
      '& .MuiIconButton-root': {
        color: designTokens.colors.text.secondary,
        '&:hover': {
          color: designTokens.colors.text.primary,
          backgroundColor: designTokens.colors.background.surface,
        },
      },
    },
  };
});

// =============================================================================
// Transition
// =============================================================================

function SlideTransition(props: TransitionProps & { children: React.ReactElement }) {
  return <Slide {...props} direction="left" />;
}

// =============================================================================
// Toast Context
// =============================================================================

const ToastContext = createContext<ToastContextValue | undefined>(undefined);

export const useToast = (): ToastContextValue => {
  const context = useContext(ToastContext);
  if (!context) {
    throw new Error('useToast must be used within a ToastProvider');
  }
  return context;
};

// =============================================================================
// Toast Provider
// =============================================================================

export interface ToastProviderProps {
  children: React.ReactNode;
  /** Maximum number of toasts to show at once */
  maxToasts?: number;
  /** Default duration in milliseconds */
  defaultDuration?: number;
  /** Position of toasts */
  position?: {
    vertical: 'top' | 'bottom';
    horizontal: 'left' | 'center' | 'right';
  };
}

export const ToastProvider: React.FC<ToastProviderProps> = ({
  children,
  maxToasts = 3,
  defaultDuration = 5000,
  position = { vertical: 'top', horizontal: 'right' },
}) => {
  const [toasts, setToasts] = useState<ToastMessage[]>([]);

  const generateId = () => `toast-${Date.now()}-${Math.random().toString(36).slice(2)}`;

  const hideToast = useCallback((id: string) => {
    setToasts((prev) => prev.filter((toast) => toast.id !== id));
  }, []);

  const showToast = useCallback(
    (toast: Omit<ToastMessage, 'id'>) => {
      const id = generateId();
      const newToast: ToastMessage = {
        ...toast,
        id,
        duration: toast.duration ?? defaultDuration,
      };

      setToasts((prev) => {
        const updated = [...prev, newToast];
        // Limit number of toasts
        if (updated.length > maxToasts) {
          return updated.slice(-maxToasts);
        }
        return updated;
      });

      // Auto-dismiss
      if (newToast.duration && newToast.duration > 0) {
        setTimeout(() => {
          hideToast(id);
        }, newToast.duration);
      }
    },
    [defaultDuration, maxToasts, hideToast]
  );

  const showSuccess = useCallback(
    (message: string, title?: string) => {
      showToast({ severity: 'success', message, title });
    },
    [showToast]
  );

  const showError = useCallback(
    (message: string, title?: string) => {
      showToast({ severity: 'error', message, title, duration: 8000 });
    },
    [showToast]
  );

  const showWarning = useCallback(
    (message: string, title?: string) => {
      showToast({ severity: 'warning', message, title });
    },
    [showToast]
  );

  const showInfo = useCallback(
    (message: string, title?: string) => {
      showToast({ severity: 'info', message, title });
    },
    [showToast]
  );

  const contextValue: ToastContextValue = {
    showToast,
    showSuccess,
    showError,
    showWarning,
    showInfo,
    hideToast,
  };

  const iconMap = {
    success: <CheckCircleIcon />,
    error: <ErrorIcon />,
    warning: <WarningIcon />,
    info: <InfoIcon />,
  };

  return (
    <ToastContext.Provider value={contextValue}>
      {children}
      {toasts.map((toast, index) => (
        <Snackbar
          key={toast.id}
          open={true}
          anchorOrigin={position}
          TransitionComponent={SlideTransition}
          sx={{
            marginTop: `${index * 80}px`,
          }}
        >
          <StyledAlert
            toastSeverity={toast.severity}
            severity={toast.severity}
            icon={iconMap[toast.severity]}
            onClose={() => hideToast(toast.id)}
            action={toast.action}
            data-testid={`toast-${toast.severity}`}
          >
            {toast.title && <AlertTitle>{toast.title}</AlertTitle>}
            {toast.message}
          </StyledAlert>
        </Snackbar>
      ))}
    </ToastContext.Provider>
  );
};

// =============================================================================
// Standalone Toast Component (for non-context usage)
// =============================================================================

export interface ToastProps {
  /** Whether toast is visible */
  open: boolean;
  /** Close handler */
  onClose: () => void;
  /** Severity level */
  severity: ToastSeverity;
  /** Toast title */
  title?: string;
  /** Toast message */
  message: string;
  /** Auto-hide duration (0 to disable) */
  duration?: number;
  /** Action element */
  action?: React.ReactNode;
  /** Test ID for testing */
  testId?: string;
}

export const Toast: React.FC<ToastProps> = ({
  open,
  onClose,
  severity,
  title,
  message,
  duration = 5000,
  action,
  testId,
}) => {
  const iconMap = {
    success: <CheckCircleIcon />,
    error: <ErrorIcon />,
    warning: <WarningIcon />,
    info: <InfoIcon />,
  };

  return (
    <Snackbar
      open={open}
      autoHideDuration={duration > 0 ? duration : undefined}
      onClose={onClose}
      anchorOrigin={{ vertical: 'top', horizontal: 'right' }}
      TransitionComponent={SlideTransition}
    >
      <StyledAlert
        toastSeverity={severity}
        severity={severity}
        icon={iconMap[severity]}
        onClose={onClose}
        action={action}
        data-testid={testId}
      >
        {title && <AlertTitle>{title}</AlertTitle>}
        {message}
      </StyledAlert>
    </Snackbar>
  );
};

export default Toast;
