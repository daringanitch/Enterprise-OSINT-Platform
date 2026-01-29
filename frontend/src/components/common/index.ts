/**
 * Common Components Barrel Export
 *
 * Re-exports all common components for convenient imports:
 * import { Button, Card, Modal } from '@/components/common';
 */

// Button
export { Button } from './Button';
export type { ButtonProps, ButtonVariant, ButtonSize } from './Button';

// Card
export { Card, CardStat } from './Card';
export type { CardProps, CardVariant, CardStatProps } from './Card';

// StatusIndicator
export {
  StatusIndicator,
  RiskLevelIndicator,
  InvestigationStatusIndicator,
} from './StatusIndicator';
export type {
  StatusIndicatorProps,
  StatusVariant,
  RiskLevelIndicatorProps,
  InvestigationStatusIndicatorProps,
} from './StatusIndicator';

// Modal
export { Modal, ConfirmationModal } from './Modal';
export type { ModalProps, ModalSize, ConfirmationModalProps } from './Modal';

// FormField
export {
  TextInput,
  SelectInput,
  CheckboxInput,
  SwitchInput,
  Textarea,
} from './FormField';
export type {
  TextInputProps,
  SelectInputProps,
  SelectOption,
  CheckboxInputProps,
  SwitchInputProps,
  TextareaProps,
} from './FormField';

// Loading
export {
  Spinner,
  ProgressBar,
  LoadingOverlay,
  FullPageLoading,
  SkeletonCard,
  SkeletonTable,
} from './Loading';
export type {
  SpinnerProps,
  ProgressBarProps,
  LoadingOverlayProps,
  FullPageLoadingProps,
  SkeletonCardProps,
  SkeletonTableProps,
} from './Loading';

// Toast
export { Toast, ToastProvider, useToast } from './Toast';
export type {
  ToastProps,
  ToastProviderProps,
  ToastSeverity,
  ToastMessage,
  ToastContextValue,
} from './Toast';
