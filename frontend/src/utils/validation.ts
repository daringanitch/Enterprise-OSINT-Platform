/**
 * Form Validation Utilities
 *
 * Provides validation functions and hooks for form inputs
 * with accessibility-friendly error messaging.
 */

export interface ValidationResult {
  isValid: boolean;
  message?: string;
}

export type Validator<T = string> = (value: T) => ValidationResult;

// =============================================================================
// Basic Validators
// =============================================================================

/**
 * Required field validator
 */
export const required = (message = 'This field is required'): Validator => {
  return (value) => ({
    isValid: value !== undefined && value !== null && value.toString().trim() !== '',
    message: value ? undefined : message,
  });
};

/**
 * Minimum length validator
 */
export const minLength = (min: number, message?: string): Validator => {
  return (value) => {
    const isValid = value.length >= min;
    return {
      isValid,
      message: isValid ? undefined : message || `Must be at least ${min} characters`,
    };
  };
};

/**
 * Maximum length validator
 */
export const maxLength = (max: number, message?: string): Validator => {
  return (value) => {
    const isValid = value.length <= max;
    return {
      isValid,
      message: isValid ? undefined : message || `Must be no more than ${max} characters`,
    };
  };
};

/**
 * Pattern validator (regex)
 */
export const pattern = (regex: RegExp, message: string): Validator => {
  return (value) => {
    const isValid = regex.test(value);
    return {
      isValid,
      message: isValid ? undefined : message,
    };
  };
};

/**
 * Email validator
 */
export const email = (message = 'Please enter a valid email address'): Validator => {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return pattern(emailRegex, message);
};

/**
 * URL validator
 */
export const url = (message = 'Please enter a valid URL'): Validator => {
  return (value) => {
    try {
      new URL(value);
      return { isValid: true };
    } catch {
      return { isValid: false, message };
    }
  };
};

/**
 * Numeric validator
 */
export const numeric = (message = 'Please enter a number'): Validator => {
  return (value) => {
    const isValid = !isNaN(Number(value)) && value.trim() !== '';
    return {
      isValid,
      message: isValid ? undefined : message,
    };
  };
};

/**
 * Integer validator
 */
export const integer = (message = 'Please enter a whole number'): Validator => {
  return (value) => {
    const isValid = Number.isInteger(Number(value)) && value.trim() !== '';
    return {
      isValid,
      message: isValid ? undefined : message,
    };
  };
};

/**
 * Minimum value validator
 */
export const min = (minValue: number, message?: string): Validator => {
  return (value) => {
    const num = Number(value);
    const isValid = !isNaN(num) && num >= minValue;
    return {
      isValid,
      message: isValid ? undefined : message || `Must be at least ${minValue}`,
    };
  };
};

/**
 * Maximum value validator
 */
export const max = (maxValue: number, message?: string): Validator => {
  return (value) => {
    const num = Number(value);
    const isValid = !isNaN(num) && num <= maxValue;
    return {
      isValid,
      message: isValid ? undefined : message || `Must be no more than ${maxValue}`,
    };
  };
};

/**
 * Custom validator
 */
export const custom = <T = string>(
  predicate: (value: T) => boolean,
  message: string
): Validator<T> => {
  return (value) => ({
    isValid: predicate(value),
    message: predicate(value) ? undefined : message,
  });
};

// =============================================================================
// Domain-Specific Validators
// =============================================================================

/**
 * Domain name validator
 */
export const domain = (message = 'Please enter a valid domain name'): Validator => {
  const domainRegex = /^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/;
  return pattern(domainRegex, message);
};

/**
 * IP address validator (IPv4)
 */
export const ipv4 = (message = 'Please enter a valid IPv4 address'): Validator => {
  const ipv4Regex =
    /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
  return pattern(ipv4Regex, message);
};

/**
 * IP address validator (IPv6)
 */
export const ipv6 = (message = 'Please enter a valid IPv6 address'): Validator => {
  const ipv6Regex =
    /^(?:(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,7}:|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|::)$/;
  return pattern(ipv6Regex, message);
};

/**
 * Hash validator (MD5, SHA1, SHA256, SHA512)
 */
export const hash = (type: 'md5' | 'sha1' | 'sha256' | 'sha512', message?: string): Validator => {
  const lengths: Record<string, number> = {
    md5: 32,
    sha1: 40,
    sha256: 64,
    sha512: 128,
  };
  const len = lengths[type];
  const regex = new RegExp(`^[a-fA-F0-9]{${len}}$`);
  return pattern(regex, message || `Please enter a valid ${type.toUpperCase()} hash`);
};

// =============================================================================
// Validator Composition
// =============================================================================

/**
 * Combine multiple validators (all must pass)
 */
export const compose = <T = string>(...validators: Validator<T>[]): Validator<T> => {
  return (value) => {
    for (const validator of validators) {
      const result = validator(value);
      if (!result.isValid) {
        return result;
      }
    }
    return { isValid: true };
  };
};

/**
 * Apply validators only if value is not empty
 */
export const optional = <T = string>(validator: Validator<T>): Validator<T> => {
  return (value) => {
    if (value === undefined || value === null || value.toString().trim() === '') {
      return { isValid: true };
    }
    return validator(value);
  };
};

// =============================================================================
// Form Validation Helper
// =============================================================================

export interface FieldValidation<T = string> {
  value: T;
  validators: Validator<T>[];
}

export interface FormValidationResult {
  isValid: boolean;
  errors: Record<string, string>;
}

/**
 * Validate multiple form fields
 */
export function validateForm<T extends Record<string, FieldValidation<any>>>(
  fields: T
): FormValidationResult {
  const errors: Record<string, string> = {};
  let isValid = true;

  for (const [fieldName, field] of Object.entries(fields)) {
    const composedValidator = compose(...field.validators);
    const result = composedValidator(field.value);

    if (!result.isValid && result.message) {
      errors[fieldName] = result.message;
      isValid = false;
    }
  }

  return { isValid, errors };
}

/**
 * Format validation error for screen readers
 */
export function formatErrorForScreenReader(fieldLabel: string, error: string): string {
  return `${fieldLabel}: ${error}`;
}

/**
 * Get ARIA describedby IDs for a field
 */
export function getAriaDescribedBy(
  fieldId: string,
  hasError: boolean,
  hasHint: boolean
): string | undefined {
  const ids: string[] = [];

  if (hasError) {
    ids.push(`${fieldId}-error`);
  }
  if (hasHint) {
    ids.push(`${fieldId}-hint`);
  }

  return ids.length > 0 ? ids.join(' ') : undefined;
}

export default {
  required,
  minLength,
  maxLength,
  pattern,
  email,
  url,
  numeric,
  integer,
  min,
  max,
  custom,
  domain,
  ipv4,
  ipv6,
  hash,
  compose,
  optional,
  validateForm,
};
