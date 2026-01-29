/**
 * Modal Component
 *
 * Accessible modal dialog with customizable header, content, and actions.
 * Supports different sizes and handles keyboard navigation.
 */

import React, { useEffect, useCallback } from 'react';
import {
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  IconButton,
  Typography,
  Box,
  styled,
  Slide,
} from '@mui/material';
import { TransitionProps } from '@mui/material/transitions';
import CloseIcon from '@mui/icons-material/Close';
import { designTokens } from '../../utils/theme';

export type ModalSize = 'sm' | 'md' | 'lg' | 'xl' | 'fullWidth';

export interface ModalProps {
  /** Controls modal visibility */
  open: boolean;
  /** Called when modal should close */
  onClose: () => void;
  /** Modal title */
  title?: string;
  /** Subtitle or description */
  subtitle?: string;
  /** Main modal content */
  children: React.ReactNode;
  /** Footer actions (typically buttons) */
  actions?: React.ReactNode;
  /** Modal size variant */
  size?: ModalSize;
  /** Show close button in header */
  showCloseButton?: boolean;
  /** Disable closing on backdrop click */
  disableBackdropClose?: boolean;
  /** Disable closing on escape key */
  disableEscapeClose?: boolean;
  /** Test ID for testing */
  testId?: string;
}

const sizeMap: Record<ModalSize, 'xs' | 'sm' | 'md' | 'lg' | 'xl'> = {
  sm: 'xs',
  md: 'sm',
  lg: 'md',
  xl: 'lg',
  fullWidth: 'xl',
};

const Transition = React.forwardRef(function Transition(
  props: TransitionProps & { children: React.ReactElement },
  ref: React.Ref<unknown>
) {
  return <Slide direction="up" ref={ref} {...props} />;
});

const StyledDialog = styled(Dialog)(({ theme }) => ({
  '& .MuiDialog-paper': {
    background: designTokens.colors.background.paper,
    borderRadius: designTokens.borderRadius.xl,
    border: `1px solid ${designTokens.colors.border.dark}`,
    boxShadow: designTokens.shadows.xl,
    maxHeight: '90vh',
  },
  '& .MuiBackdrop-root': {
    backgroundColor: 'rgba(0, 0, 0, 0.7)',
    backdropFilter: 'blur(4px)',
  },
}));

const StyledDialogTitle = styled(DialogTitle)({
  display: 'flex',
  alignItems: 'flex-start',
  justifyContent: 'space-between',
  padding: '20px 24px 12px',
  borderBottom: `1px solid ${designTokens.colors.border.dark}`,
});

const TitleContent = styled(Box)({
  flex: 1,
});

const Title = styled(Typography)({
  fontSize: designTokens.typography.fontSizes.xl,
  fontWeight: designTokens.typography.fontWeights.semibold,
  color: designTokens.colors.text.primary,
  marginBottom: '4px',
});

const Subtitle = styled(Typography)({
  fontSize: designTokens.typography.fontSizes.sm,
  color: designTokens.colors.text.secondary,
});

const CloseButton = styled(IconButton)({
  color: designTokens.colors.text.secondary,
  marginLeft: '12px',
  marginTop: '-4px',
  marginRight: '-8px',
  '&:hover': {
    color: designTokens.colors.text.primary,
    background: designTokens.colors.background.elevated,
  },
});

const StyledDialogContent = styled(DialogContent)({
  padding: '24px',
  color: designTokens.colors.text.primary,
  '&:first-of-type': {
    paddingTop: '24px',
  },
});

const StyledDialogActions = styled(DialogActions)({
  padding: '16px 24px 20px',
  borderTop: `1px solid ${designTokens.colors.border.dark}`,
  gap: '12px',
  '& > :not(:first-of-type)': {
    marginLeft: 0,
  },
});

export const Modal: React.FC<ModalProps> = ({
  open,
  onClose,
  title,
  subtitle,
  children,
  actions,
  size = 'md',
  showCloseButton = true,
  disableBackdropClose = false,
  disableEscapeClose = false,
  testId,
}) => {
  const handleClose = useCallback(
    (event: object, reason: 'backdropClick' | 'escapeKeyDown') => {
      if (reason === 'backdropClick' && disableBackdropClose) {
        return;
      }
      if (reason === 'escapeKeyDown' && disableEscapeClose) {
        return;
      }
      onClose();
    },
    [onClose, disableBackdropClose, disableEscapeClose]
  );

  // Handle escape key when disableEscapeClose is true
  useEffect(() => {
    if (!open || !disableEscapeClose) return;

    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        e.preventDefault();
      }
    };

    document.addEventListener('keydown', handleKeyDown);
    return () => document.removeEventListener('keydown', handleKeyDown);
  }, [open, disableEscapeClose]);

  return (
    <StyledDialog
      open={open}
      onClose={handleClose}
      maxWidth={sizeMap[size]}
      fullWidth={size === 'fullWidth'}
      TransitionComponent={Transition}
      aria-labelledby={title ? 'modal-title' : undefined}
      aria-describedby={subtitle ? 'modal-subtitle' : undefined}
      data-testid={testId}
    >
      {(title || showCloseButton) && (
        <StyledDialogTitle>
          <TitleContent>
            {title && <Title id="modal-title">{title}</Title>}
            {subtitle && <Subtitle id="modal-subtitle">{subtitle}</Subtitle>}
          </TitleContent>
          {showCloseButton && (
            <CloseButton
              onClick={onClose}
              aria-label="Close modal"
              data-testid={testId ? `${testId}-close-button` : undefined}
            >
              <CloseIcon />
            </CloseButton>
          )}
        </StyledDialogTitle>
      )}

      <StyledDialogContent>{children}</StyledDialogContent>

      {actions && <StyledDialogActions>{actions}</StyledDialogActions>}
    </StyledDialog>
  );
};

// =============================================================================
// Confirmation Modal
// =============================================================================

export interface ConfirmationModalProps {
  open: boolean;
  onClose: () => void;
  onConfirm: () => void;
  title: string;
  message: string;
  confirmLabel?: string;
  cancelLabel?: string;
  variant?: 'danger' | 'warning' | 'info';
  loading?: boolean;
  testId?: string;
}

const variantColors = {
  danger: designTokens.colors.error.main,
  warning: designTokens.colors.warning.main,
  info: designTokens.colors.info.main,
};

const ConfirmButton = styled('button', {
  shouldForwardProp: (prop) => prop !== 'colorVariant' && prop !== 'isLoading',
})<{ colorVariant: 'danger' | 'warning' | 'info'; isLoading?: boolean }>(
  ({ colorVariant, isLoading }) => ({
    padding: '8px 20px',
    borderRadius: designTokens.borderRadius.md,
    border: 'none',
    background: variantColors[colorVariant],
    color: colorVariant === 'warning' ? '#000000' : '#ffffff',
    fontSize: designTokens.typography.fontSizes.sm,
    fontWeight: designTokens.typography.fontWeights.medium,
    cursor: isLoading ? 'not-allowed' : 'pointer',
    opacity: isLoading ? 0.7 : 1,
    transition: designTokens.transitions.normal,
    '&:hover:not(:disabled)': {
      filter: 'brightness(1.1)',
    },
    '&:focus-visible': {
      outline: `2px solid ${variantColors[colorVariant]}`,
      outlineOffset: '2px',
    },
  })
);

const CancelButton = styled('button')({
  padding: '8px 20px',
  borderRadius: designTokens.borderRadius.md,
  border: `1px solid ${designTokens.colors.border.main}`,
  background: 'transparent',
  color: designTokens.colors.text.primary,
  fontSize: designTokens.typography.fontSizes.sm,
  fontWeight: designTokens.typography.fontWeights.medium,
  cursor: 'pointer',
  transition: designTokens.transitions.normal,
  '&:hover': {
    background: designTokens.colors.background.elevated,
    borderColor: designTokens.colors.border.light,
  },
  '&:focus-visible': {
    outline: `2px solid ${designTokens.colors.primary.main}`,
    outlineOffset: '2px',
  },
});

export const ConfirmationModal: React.FC<ConfirmationModalProps> = ({
  open,
  onClose,
  onConfirm,
  title,
  message,
  confirmLabel = 'Confirm',
  cancelLabel = 'Cancel',
  variant = 'danger',
  loading = false,
  testId,
}) => {
  return (
    <Modal
      open={open}
      onClose={onClose}
      title={title}
      size="sm"
      disableBackdropClose={loading}
      disableEscapeClose={loading}
      testId={testId}
      actions={
        <>
          <CancelButton
            onClick={onClose}
            disabled={loading}
            data-testid={testId ? `${testId}-cancel` : undefined}
          >
            {cancelLabel}
          </CancelButton>
          <ConfirmButton
            colorVariant={variant}
            onClick={onConfirm}
            isLoading={loading}
            disabled={loading}
            data-testid={testId ? `${testId}-confirm` : undefined}
          >
            {loading ? 'Processing...' : confirmLabel}
          </ConfirmButton>
        </>
      }
    >
      <Typography
        sx={{
          color: designTokens.colors.text.secondary,
          fontSize: designTokens.typography.fontSizes.md,
        }}
      >
        {message}
      </Typography>
    </Modal>
  );
};

export default Modal;
