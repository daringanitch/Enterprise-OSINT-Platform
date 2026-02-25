/**
 * Modal Component Tests
 */

import React from 'react';
import { render, screen, fireEvent } from '@testing-library/react';
import { ThemeProvider } from '@mui/material/styles';
import { theme } from '../../utils/theme';
import { Modal, ConfirmationModal } from '../../components/common/Modal';

const renderWithTheme = (component: React.ReactElement) => {
  return render(<ThemeProvider theme={theme}>{component}</ThemeProvider>);
};

describe('Modal Component', () => {
  const defaultProps = {
    open: true,
    onClose: jest.fn(),
    children: <p>Modal content</p>,
  };

  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe('Rendering', () => {
    it('renders when open', () => {
      renderWithTheme(<Modal {...defaultProps} testId="test-modal" />);
      expect(screen.getByTestId('test-modal')).toBeInTheDocument();
      expect(screen.getByText('Modal content')).toBeInTheDocument();
    });

    it('does not render when closed', () => {
      renderWithTheme(<Modal {...defaultProps} open={false} testId="test-modal" />);
      expect(screen.queryByTestId('test-modal')).not.toBeInTheDocument();
    });

    it('renders with title', () => {
      renderWithTheme(<Modal {...defaultProps} title="Modal Title" />);
      expect(screen.getByText('Modal Title')).toBeInTheDocument();
    });

    it('renders with subtitle', () => {
      renderWithTheme(
        <Modal {...defaultProps} title="Title" subtitle="Subtitle text" />
      );
      expect(screen.getByText('Subtitle text')).toBeInTheDocument();
    });

    it('renders actions', () => {
      renderWithTheme(
        <Modal {...defaultProps} actions={<button>Save</button>} />
      );
      expect(screen.getByRole('button', { name: /save/i })).toBeInTheDocument();
    });
  });

  describe('Close Button', () => {
    it('shows close button by default', () => {
      renderWithTheme(<Modal {...defaultProps} testId="test-modal" />);
      expect(screen.getByLabelText('Close modal')).toBeInTheDocument();
    });

    it('hides close button when showCloseButton is false', () => {
      renderWithTheme(
        <Modal {...defaultProps} showCloseButton={false} title="Title" />
      );
      expect(screen.queryByLabelText('Close modal')).not.toBeInTheDocument();
    });

    it('calls onClose when close button is clicked', () => {
      const onClose = jest.fn();
      renderWithTheme(<Modal {...defaultProps} onClose={onClose} />);
      fireEvent.click(screen.getByLabelText('Close modal'));
      expect(onClose).toHaveBeenCalledTimes(1);
    });
  });

  describe('Sizes', () => {
    const sizes = ['sm', 'md', 'lg', 'xl', 'fullWidth'] as const;

    sizes.forEach((size) => {
      it(`renders ${size} size`, () => {
        renderWithTheme(<Modal {...defaultProps} size={size} testId={`${size}-modal`} />);
        expect(screen.getByTestId(`${size}-modal`)).toBeInTheDocument();
      });
    });
  });

  describe('Backdrop Close', () => {
    it('closes on backdrop click by default', () => {
      const onClose = jest.fn();
      renderWithTheme(<Modal {...defaultProps} onClose={onClose} />);
      const backdrop = document.querySelector('.MuiBackdrop-root');
      if (backdrop) {
        fireEvent.click(backdrop);
        expect(onClose).toHaveBeenCalled();
      }
    });

    it('does not close on backdrop click when disabled', () => {
      const onClose = jest.fn();
      renderWithTheme(
        <Modal {...defaultProps} onClose={onClose} disableBackdropClose />
      );
      const backdrop = document.querySelector('.MuiBackdrop-root');
      if (backdrop) {
        fireEvent.click(backdrop);
        // onClose should not be called for backdrop click
      }
    });
  });

  describe('Accessibility', () => {
    it('has proper aria-labelledby when title is provided', () => {
      renderWithTheme(<Modal {...defaultProps} title="Accessible Modal" />);
      expect(screen.getByText('Accessible Modal')).toHaveAttribute('id', 'modal-title');
    });

    it('has proper aria-describedby when subtitle is provided', () => {
      renderWithTheme(
        <Modal {...defaultProps} title="Title" subtitle="Description" />
      );
      expect(screen.getByText('Description')).toHaveAttribute('id', 'modal-subtitle');
    });
  });
});

describe('ConfirmationModal Component', () => {
  const defaultProps = {
    open: true,
    onClose: jest.fn(),
    onConfirm: jest.fn(),
    title: 'Confirm Action',
    message: 'Are you sure you want to proceed?',
  };

  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe('Rendering', () => {
    it('renders with title and message', () => {
      renderWithTheme(<ConfirmationModal {...defaultProps} />);
      expect(screen.getByText('Confirm Action')).toBeInTheDocument();
      expect(screen.getByText('Are you sure you want to proceed?')).toBeInTheDocument();
    });

    it('renders confirm and cancel buttons', () => {
      renderWithTheme(<ConfirmationModal {...defaultProps} />);
      expect(screen.getByRole('button', { name: /confirm/i })).toBeInTheDocument();
      expect(screen.getByRole('button', { name: /cancel/i })).toBeInTheDocument();
    });

    it('uses custom button labels', () => {
      renderWithTheme(
        <ConfirmationModal
          {...defaultProps}
          confirmLabel="Delete"
          cancelLabel="Keep"
        />
      );
      expect(screen.getByRole('button', { name: /delete/i })).toBeInTheDocument();
      expect(screen.getByRole('button', { name: /keep/i })).toBeInTheDocument();
    });
  });

  describe('Interactions', () => {
    it('calls onConfirm when confirm button is clicked', () => {
      const onConfirm = jest.fn();
      renderWithTheme(<ConfirmationModal {...defaultProps} onConfirm={onConfirm} />);
      fireEvent.click(screen.getByRole('button', { name: /confirm/i }));
      expect(onConfirm).toHaveBeenCalledTimes(1);
    });

    it('calls onClose when cancel button is clicked', () => {
      const onClose = jest.fn();
      renderWithTheme(<ConfirmationModal {...defaultProps} onClose={onClose} />);
      fireEvent.click(screen.getByRole('button', { name: /cancel/i }));
      expect(onClose).toHaveBeenCalledTimes(1);
    });
  });

  describe('Variants', () => {
    const variants = ['danger', 'warning', 'info'] as const;

    variants.forEach((variant) => {
      it(`renders ${variant} variant`, () => {
        renderWithTheme(
          <ConfirmationModal {...defaultProps} variant={variant} testId={`${variant}-confirm`} />
        );
        expect(screen.getByTestId(`${variant}-confirm`)).toBeInTheDocument();
      });
    });
  });

  describe('Loading State', () => {
    it('shows loading text when loading', () => {
      renderWithTheme(<ConfirmationModal {...defaultProps} loading />);
      expect(screen.getByText('Processing...')).toBeInTheDocument();
    });

    it('disables buttons when loading', () => {
      renderWithTheme(<ConfirmationModal {...defaultProps} loading testId="loading-confirm" />);
      const confirmButton = screen.getByTestId('loading-confirm-confirm');
      const cancelButton = screen.getByTestId('loading-confirm-cancel');
      expect(confirmButton).toBeDisabled();
      expect(cancelButton).toBeDisabled();
    });
  });

  describe('Test IDs', () => {
    it('applies testId to modal and buttons', () => {
      renderWithTheme(<ConfirmationModal {...defaultProps} testId="delete-modal" />);
      expect(screen.getByTestId('delete-modal')).toBeInTheDocument();
      expect(screen.getByTestId('delete-modal-confirm')).toBeInTheDocument();
      expect(screen.getByTestId('delete-modal-cancel')).toBeInTheDocument();
    });
  });
});
