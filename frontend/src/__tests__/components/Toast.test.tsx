/**
 * Toast Component Tests
 */

import React from 'react';
import { render, screen, fireEvent, act, waitFor } from '@testing-library/react';
import { ThemeProvider } from '@mui/material/styles';
import { theme } from '../../utils/theme';
import { Toast, ToastProvider, useToast } from '../../components/common/Toast';

const renderWithTheme = (component: React.ReactElement) => {
  return render(<ThemeProvider theme={theme}>{component}</ThemeProvider>);
};

describe('Toast Component (Standalone)', () => {
  const defaultProps = {
    open: true,
    onClose: jest.fn(),
    severity: 'success' as const,
    message: 'Operation successful',
  };

  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe('Rendering', () => {
    it('renders when open', () => {
      renderWithTheme(<Toast {...defaultProps} testId="test-toast" />);
      expect(screen.getByTestId('test-toast')).toBeInTheDocument();
    });

    it('shows message', () => {
      renderWithTheme(<Toast {...defaultProps} />);
      expect(screen.getByText('Operation successful')).toBeInTheDocument();
    });

    it('shows title when provided', () => {
      renderWithTheme(<Toast {...defaultProps} title="Success!" />);
      expect(screen.getByText('Success!')).toBeInTheDocument();
      expect(screen.getByText('Operation successful')).toBeInTheDocument();
    });

    it('does not render when closed', () => {
      renderWithTheme(<Toast {...defaultProps} open={false} testId="closed-toast" />);
      expect(screen.queryByTestId('closed-toast')).not.toBeInTheDocument();
    });
  });

  describe('Severity Variants', () => {
    const severities = ['success', 'error', 'warning', 'info'] as const;

    severities.forEach((severity) => {
      it(`renders ${severity} severity`, () => {
        renderWithTheme(
          <Toast {...defaultProps} severity={severity} testId={`${severity}-toast`} />
        );
        expect(screen.getByTestId(`${severity}-toast`)).toBeInTheDocument();
      });
    });
  });

  describe('Close Functionality', () => {
    it('calls onClose when close button is clicked', () => {
      const onClose = jest.fn();
      renderWithTheme(<Toast {...defaultProps} onClose={onClose} />);
      const closeButton = screen.getByRole('button', { name: /close/i });
      fireEvent.click(closeButton);
      expect(onClose).toHaveBeenCalled();
    });
  });

  describe('Action', () => {
    it('renders action element', () => {
      renderWithTheme(
        <Toast {...defaultProps} action={<button>Undo</button>} />
      );
      expect(screen.getByRole('button', { name: /undo/i })).toBeInTheDocument();
    });
  });
});

describe('ToastProvider and useToast', () => {
  // Test component that uses the useToast hook
  const TestComponent: React.FC<{ action?: string }> = ({ action }) => {
    const toast = useToast();

    const handleAction = () => {
      switch (action) {
        case 'success':
          toast.showSuccess('Success message', 'Success');
          break;
        case 'error':
          toast.showError('Error message', 'Error');
          break;
        case 'warning':
          toast.showWarning('Warning message', 'Warning');
          break;
        case 'info':
          toast.showInfo('Info message', 'Info');
          break;
        case 'custom':
          toast.showToast({
            severity: 'success',
            message: 'Custom toast',
            title: 'Custom',
            duration: 1000,
          });
          break;
        default:
          break;
      }
    };

    return (
      <button onClick={handleAction} data-testid="trigger-button">
        Trigger Toast
      </button>
    );
  };

  const renderWithProvider = (
    component: React.ReactElement,
    providerProps?: Partial<React.ComponentProps<typeof ToastProvider>>
  ) => {
    return render(
      <ThemeProvider theme={theme}>
        <ToastProvider {...providerProps}>{component}</ToastProvider>
      </ThemeProvider>
    );
  };

  beforeEach(() => {
    jest.useFakeTimers();
  });

  afterEach(() => {
    jest.useRealTimers();
  });

  describe('Context', () => {
    it('throws error when useToast is used outside provider', () => {
      const consoleError = jest.spyOn(console, 'error').mockImplementation(() => {});

      expect(() => {
        renderWithTheme(<TestComponent />);
      }).toThrow('useToast must be used within a ToastProvider');

      consoleError.mockRestore();
    });

    it('provides toast functions through context', () => {
      renderWithProvider(<TestComponent action="success" />);
      expect(screen.getByTestId('trigger-button')).toBeInTheDocument();
    });
  });

  describe('showSuccess', () => {
    it('shows success toast', () => {
      renderWithProvider(<TestComponent action="success" />);

      act(() => {
        fireEvent.click(screen.getByTestId('trigger-button'));
      });

      expect(screen.getByText('Success message')).toBeInTheDocument();
      expect(screen.getByText('Success')).toBeInTheDocument();
    });
  });

  describe('showError', () => {
    it('shows error toast', () => {
      renderWithProvider(<TestComponent action="error" />);

      act(() => {
        fireEvent.click(screen.getByTestId('trigger-button'));
      });

      expect(screen.getByText('Error message')).toBeInTheDocument();
      expect(screen.getByText('Error')).toBeInTheDocument();
    });
  });

  describe('showWarning', () => {
    it('shows warning toast', () => {
      renderWithProvider(<TestComponent action="warning" />);

      act(() => {
        fireEvent.click(screen.getByTestId('trigger-button'));
      });

      expect(screen.getByText('Warning message')).toBeInTheDocument();
      expect(screen.getByText('Warning')).toBeInTheDocument();
    });
  });

  describe('showInfo', () => {
    it('shows info toast', () => {
      renderWithProvider(<TestComponent action="info" />);

      act(() => {
        fireEvent.click(screen.getByTestId('trigger-button'));
      });

      expect(screen.getByText('Info message')).toBeInTheDocument();
      expect(screen.getByText('Info')).toBeInTheDocument();
    });
  });

  describe('Auto-dismiss', () => {
    it('auto-dismisses toast after duration', async () => {
      renderWithProvider(<TestComponent action="custom" />, { defaultDuration: 1000 });

      act(() => {
        fireEvent.click(screen.getByTestId('trigger-button'));
      });

      expect(screen.getByText('Custom toast')).toBeInTheDocument();

      act(() => {
        jest.advanceTimersByTime(1100);
      });

      await waitFor(() => {
        expect(screen.queryByText('Custom toast')).not.toBeInTheDocument();
      });
    });
  });

  describe('Max Toasts', () => {
    const MultiToastComponent: React.FC = () => {
      const toast = useToast();

      const handleClick = () => {
        toast.showSuccess('Toast 1');
        toast.showSuccess('Toast 2');
        toast.showSuccess('Toast 3');
        toast.showSuccess('Toast 4');
      };

      return (
        <button onClick={handleClick} data-testid="multi-trigger">
          Trigger Multiple
        </button>
      );
    };

    it('limits number of visible toasts', () => {
      renderWithProvider(<MultiToastComponent />, { maxToasts: 3 });

      act(() => {
        fireEvent.click(screen.getByTestId('multi-trigger'));
      });

      // Should only show the last 3 toasts due to maxToasts limit
      expect(screen.queryByText('Toast 1')).not.toBeInTheDocument();
      expect(screen.getByText('Toast 2')).toBeInTheDocument();
      expect(screen.getByText('Toast 3')).toBeInTheDocument();
      expect(screen.getByText('Toast 4')).toBeInTheDocument();
    });
  });

  describe('hideToast', () => {
    const HideToastComponent: React.FC = () => {
      const toast = useToast();

      const handleShow = () => {
        // Test via close button — ID not needed here
        toast.showSuccess('Dismissible toast');
      };

      return (
        <>
          <button onClick={handleShow} data-testid="show-button">
            Show
          </button>
        </>
      );
    };

    it('dismisses toast when close button is clicked', async () => {
      renderWithProvider(<HideToastComponent />);

      act(() => {
        fireEvent.click(screen.getByTestId('show-button'));
      });

      expect(screen.getByText('Dismissible toast')).toBeInTheDocument();

      const closeButton = screen.getByRole('button', { name: /close/i });
      act(() => {
        fireEvent.click(closeButton);
      });

      await waitFor(() => {
        expect(screen.queryByText('Dismissible toast')).not.toBeInTheDocument();
      });
    });
  });

  describe('Position', () => {
    it('accepts custom position', () => {
      renderWithProvider(<TestComponent action="success" />, {
        position: { vertical: 'bottom', horizontal: 'left' },
      });

      act(() => {
        fireEvent.click(screen.getByTestId('trigger-button'));
      });

      expect(screen.getByText('Success message')).toBeInTheDocument();
    });
  });
});
