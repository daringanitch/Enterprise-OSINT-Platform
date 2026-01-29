/**
 * FormField Components
 *
 * Reusable form inputs with consistent styling, validation,
 * and accessibility support.
 */

import React from 'react';
import {
  TextField,
  Select,
  MenuItem,
  FormControl,
  InputLabel,
  FormHelperText,
  InputAdornment,
  Checkbox,
  FormControlLabel,
  Switch,
  styled,
  TextFieldProps,
} from '@mui/material';
import { designTokens } from '../../utils/theme';

// =============================================================================
// Text Input
// =============================================================================

export interface TextInputProps extends Omit<TextFieldProps, 'variant'> {
  /** Field label */
  label: string;
  /** Helper text or error message */
  helperText?: string;
  /** Error state */
  error?: boolean;
  /** Icon at the start of input */
  startIcon?: React.ReactNode;
  /** Icon at the end of input */
  endIcon?: React.ReactNode;
  /** Test ID for testing */
  testId?: string;
}

const StyledTextField = styled(TextField)({
  '& .MuiOutlinedInput-root': {
    borderRadius: designTokens.borderRadius.md,
    backgroundColor: designTokens.colors.background.elevated,
    transition: designTokens.transitions.normal,
    '& fieldset': {
      borderColor: designTokens.colors.border.main,
    },
    '&:hover fieldset': {
      borderColor: designTokens.colors.border.light,
    },
    '&.Mui-focused fieldset': {
      borderColor: designTokens.colors.primary.main,
      borderWidth: '2px',
    },
    '&.Mui-error fieldset': {
      borderColor: designTokens.colors.error.main,
    },
  },
  '& .MuiInputLabel-root': {
    color: designTokens.colors.text.secondary,
    '&.Mui-focused': {
      color: designTokens.colors.primary.main,
    },
    '&.Mui-error': {
      color: designTokens.colors.error.main,
    },
  },
  '& .MuiOutlinedInput-input': {
    color: designTokens.colors.text.primary,
    '&::placeholder': {
      color: designTokens.colors.text.hint,
      opacity: 1,
    },
  },
  '& .MuiFormHelperText-root': {
    color: designTokens.colors.text.secondary,
    marginLeft: '4px',
    '&.Mui-error': {
      color: designTokens.colors.error.main,
    },
  },
});

export const TextInput: React.FC<TextInputProps> = ({
  label,
  helperText,
  error,
  startIcon,
  endIcon,
  testId,
  ...props
}) => {
  return (
    <StyledTextField
      label={label}
      helperText={helperText}
      error={error}
      variant="outlined"
      fullWidth
      InputProps={{
        startAdornment: startIcon ? (
          <InputAdornment position="start">{startIcon}</InputAdornment>
        ) : undefined,
        endAdornment: endIcon ? (
          <InputAdornment position="end">{endIcon}</InputAdornment>
        ) : undefined,
      }}
      inputProps={{
        'data-testid': testId,
      }}
      {...props}
    />
  );
};

// =============================================================================
// Select Input
// =============================================================================

export interface SelectOption {
  value: string;
  label: string;
  disabled?: boolean;
}

export interface SelectInputProps {
  /** Field label */
  label: string;
  /** Current value */
  value: string;
  /** Change handler */
  onChange: (value: string) => void;
  /** Available options */
  options: SelectOption[];
  /** Helper text or error message */
  helperText?: string;
  /** Error state */
  error?: boolean;
  /** Disabled state */
  disabled?: boolean;
  /** Required field */
  required?: boolean;
  /** Placeholder text */
  placeholder?: string;
  /** Full width */
  fullWidth?: boolean;
  /** Test ID for testing */
  testId?: string;
}

const StyledFormControl = styled(FormControl)({
  '& .MuiOutlinedInput-root': {
    borderRadius: designTokens.borderRadius.md,
    backgroundColor: designTokens.colors.background.elevated,
    '& fieldset': {
      borderColor: designTokens.colors.border.main,
    },
    '&:hover fieldset': {
      borderColor: designTokens.colors.border.light,
    },
    '&.Mui-focused fieldset': {
      borderColor: designTokens.colors.primary.main,
      borderWidth: '2px',
    },
    '&.Mui-error fieldset': {
      borderColor: designTokens.colors.error.main,
    },
  },
  '& .MuiInputLabel-root': {
    color: designTokens.colors.text.secondary,
    '&.Mui-focused': {
      color: designTokens.colors.primary.main,
    },
    '&.Mui-error': {
      color: designTokens.colors.error.main,
    },
  },
  '& .MuiSelect-select': {
    color: designTokens.colors.text.primary,
  },
  '& .MuiFormHelperText-root': {
    color: designTokens.colors.text.secondary,
    marginLeft: '4px',
    '&.Mui-error': {
      color: designTokens.colors.error.main,
    },
  },
});

const StyledMenuItem = styled(MenuItem)({
  color: designTokens.colors.text.primary,
  '&:hover': {
    backgroundColor: designTokens.colors.background.elevated,
  },
  '&.Mui-selected': {
    backgroundColor: `${designTokens.colors.primary.main}20`,
    '&:hover': {
      backgroundColor: `${designTokens.colors.primary.main}30`,
    },
  },
  '&.Mui-disabled': {
    color: designTokens.colors.text.disabled,
  },
});

export const SelectInput: React.FC<SelectInputProps> = ({
  label,
  value,
  onChange,
  options,
  helperText,
  error,
  disabled,
  required,
  placeholder,
  fullWidth = true,
  testId,
}) => {
  const labelId = `${label.toLowerCase().replace(/\s+/g, '-')}-label`;

  return (
    <StyledFormControl
      fullWidth={fullWidth}
      error={error}
      disabled={disabled}
      required={required}
    >
      <InputLabel id={labelId}>{label}</InputLabel>
      <Select
        labelId={labelId}
        value={value}
        onChange={(e) => onChange(e.target.value as string)}
        label={label}
        displayEmpty={!!placeholder}
        data-testid={testId}
        MenuProps={{
          PaperProps: {
            sx: {
              backgroundColor: designTokens.colors.background.paper,
              border: `1px solid ${designTokens.colors.border.dark}`,
              borderRadius: designTokens.borderRadius.md,
            },
          },
        }}
      >
        {placeholder && (
          <StyledMenuItem value="" disabled>
            <em style={{ color: designTokens.colors.text.hint }}>{placeholder}</em>
          </StyledMenuItem>
        )}
        {options.map((option) => (
          <StyledMenuItem
            key={option.value}
            value={option.value}
            disabled={option.disabled}
          >
            {option.label}
          </StyledMenuItem>
        ))}
      </Select>
      {helperText && <FormHelperText>{helperText}</FormHelperText>}
    </StyledFormControl>
  );
};

// =============================================================================
// Checkbox Input
// =============================================================================

export interface CheckboxInputProps {
  /** Field label */
  label: string;
  /** Checked state */
  checked: boolean;
  /** Change handler */
  onChange: (checked: boolean) => void;
  /** Disabled state */
  disabled?: boolean;
  /** Indeterminate state */
  indeterminate?: boolean;
  /** Helper text */
  helperText?: string;
  /** Test ID for testing */
  testId?: string;
}

const StyledCheckbox = styled(Checkbox)({
  color: designTokens.colors.border.main,
  '&.Mui-checked': {
    color: designTokens.colors.primary.main,
  },
  '&.MuiCheckbox-indeterminate': {
    color: designTokens.colors.primary.main,
  },
  '&.Mui-disabled': {
    color: designTokens.colors.text.disabled,
  },
});

const CheckboxLabel = styled(FormControlLabel)({
  '& .MuiFormControlLabel-label': {
    color: designTokens.colors.text.primary,
    fontSize: designTokens.typography.fontSizes.sm,
    '&.Mui-disabled': {
      color: designTokens.colors.text.disabled,
    },
  },
});

export const CheckboxInput: React.FC<CheckboxInputProps> = ({
  label,
  checked,
  onChange,
  disabled,
  indeterminate,
  helperText,
  testId,
}) => {
  return (
    <div>
      <CheckboxLabel
        control={
          <StyledCheckbox
            checked={checked}
            onChange={(e) => onChange(e.target.checked)}
            disabled={disabled}
            indeterminate={indeterminate}
            data-testid={testId}
          />
        }
        label={label}
      />
      {helperText && (
        <FormHelperText
          sx={{
            color: designTokens.colors.text.secondary,
            marginLeft: '32px',
            marginTop: '-4px',
          }}
        >
          {helperText}
        </FormHelperText>
      )}
    </div>
  );
};

// =============================================================================
// Switch Input
// =============================================================================

export interface SwitchInputProps {
  /** Field label */
  label: string;
  /** Checked state */
  checked: boolean;
  /** Change handler */
  onChange: (checked: boolean) => void;
  /** Disabled state */
  disabled?: boolean;
  /** Label placement */
  labelPlacement?: 'start' | 'end' | 'top' | 'bottom';
  /** Helper text */
  helperText?: string;
  /** Test ID for testing */
  testId?: string;
}

const StyledSwitch = styled(Switch)({
  '& .MuiSwitch-switchBase': {
    color: designTokens.colors.border.main,
    '&.Mui-checked': {
      color: designTokens.colors.primary.main,
      '& + .MuiSwitch-track': {
        backgroundColor: designTokens.colors.primary.main,
        opacity: 0.5,
      },
    },
    '&.Mui-disabled': {
      color: designTokens.colors.text.disabled,
      '& + .MuiSwitch-track': {
        opacity: 0.3,
      },
    },
  },
  '& .MuiSwitch-track': {
    backgroundColor: designTokens.colors.border.main,
    opacity: 1,
  },
});

const SwitchLabel = styled(FormControlLabel)({
  '& .MuiFormControlLabel-label': {
    color: designTokens.colors.text.primary,
    fontSize: designTokens.typography.fontSizes.sm,
    '&.Mui-disabled': {
      color: designTokens.colors.text.disabled,
    },
  },
});

export const SwitchInput: React.FC<SwitchInputProps> = ({
  label,
  checked,
  onChange,
  disabled,
  labelPlacement = 'end',
  helperText,
  testId,
}) => {
  return (
    <div>
      <SwitchLabel
        control={
          <StyledSwitch
            checked={checked}
            onChange={(e) => onChange(e.target.checked)}
            disabled={disabled}
            data-testid={testId}
          />
        }
        label={label}
        labelPlacement={labelPlacement}
      />
      {helperText && (
        <FormHelperText
          sx={{
            color: designTokens.colors.text.secondary,
            marginLeft: labelPlacement === 'end' ? '48px' : '0',
            marginTop: '-4px',
          }}
        >
          {helperText}
        </FormHelperText>
      )}
    </div>
  );
};

// =============================================================================
// Textarea Input
// =============================================================================

export interface TextareaProps extends Omit<TextFieldProps, 'variant' | 'multiline' | 'rows'> {
  /** Field label */
  label: string;
  /** Number of rows */
  rows?: number;
  /** Minimum rows (for auto-resize) */
  minRows?: number;
  /** Maximum rows (for auto-resize) */
  maxRows?: number;
  /** Helper text or error message */
  helperText?: string;
  /** Error state */
  error?: boolean;
  /** Test ID for testing */
  testId?: string;
}

export const Textarea: React.FC<TextareaProps> = ({
  label,
  rows,
  minRows = 3,
  maxRows = 10,
  helperText,
  error,
  testId,
  ...props
}) => {
  return (
    <StyledTextField
      label={label}
      helperText={helperText}
      error={error}
      variant="outlined"
      fullWidth
      multiline
      rows={rows}
      minRows={!rows ? minRows : undefined}
      maxRows={!rows ? maxRows : undefined}
      inputProps={{
        'data-testid': testId,
      }}
      {...props}
    />
  );
};

export default TextInput;
