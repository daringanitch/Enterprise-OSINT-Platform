/**
 * Validation Utilities Tests
 */

import {
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
  hash,
  compose,
  optional,
  validateForm,
} from '../../utils/validation';

describe('Validation Utilities', () => {
  describe('required', () => {
    const validator = required();

    it('fails for empty string', () => {
      expect(validator('').isValid).toBe(false);
    });

    it('fails for whitespace only', () => {
      expect(validator('   ').isValid).toBe(false);
    });

    it('passes for non-empty string', () => {
      expect(validator('hello').isValid).toBe(true);
    });

    it('uses custom message', () => {
      const customValidator = required('Field is required');
      const result = customValidator('');
      expect(result.message).toBe('Field is required');
    });
  });

  describe('minLength', () => {
    const validator = minLength(3);

    it('fails for short strings', () => {
      expect(validator('ab').isValid).toBe(false);
    });

    it('passes for strings at minimum', () => {
      expect(validator('abc').isValid).toBe(true);
    });

    it('passes for longer strings', () => {
      expect(validator('abcdef').isValid).toBe(true);
    });

    it('includes length in message', () => {
      const result = validator('ab');
      expect(result.message).toContain('3');
    });
  });

  describe('maxLength', () => {
    const validator = maxLength(5);

    it('passes for short strings', () => {
      expect(validator('abc').isValid).toBe(true);
    });

    it('passes for strings at maximum', () => {
      expect(validator('abcde').isValid).toBe(true);
    });

    it('fails for longer strings', () => {
      expect(validator('abcdefgh').isValid).toBe(false);
    });
  });

  describe('pattern', () => {
    const validator = pattern(/^[A-Z]+$/, 'Must be uppercase letters');

    it('passes for matching pattern', () => {
      expect(validator('HELLO').isValid).toBe(true);
    });

    it('fails for non-matching pattern', () => {
      expect(validator('hello').isValid).toBe(false);
    });

    it('uses provided message', () => {
      const result = validator('hello');
      expect(result.message).toBe('Must be uppercase letters');
    });
  });

  describe('email', () => {
    const validator = email();

    it('passes for valid email', () => {
      expect(validator('test@example.com').isValid).toBe(true);
    });

    it('passes for email with subdomain', () => {
      expect(validator('user@mail.example.org').isValid).toBe(true);
    });

    it('fails for invalid email - no @', () => {
      expect(validator('testexample.com').isValid).toBe(false);
    });

    it('fails for invalid email - no domain', () => {
      expect(validator('test@').isValid).toBe(false);
    });

    it('fails for invalid email - no local part', () => {
      expect(validator('@example.com').isValid).toBe(false);
    });
  });

  describe('url', () => {
    const validator = url();

    it('passes for valid http URL', () => {
      expect(validator('http://example.com').isValid).toBe(true);
    });

    it('passes for valid https URL', () => {
      expect(validator('https://example.com/path').isValid).toBe(true);
    });

    it('passes for URL with query string', () => {
      expect(validator('https://example.com?foo=bar').isValid).toBe(true);
    });

    it('fails for invalid URL', () => {
      expect(validator('not-a-url').isValid).toBe(false);
    });
  });

  describe('numeric', () => {
    const validator = numeric();

    it('passes for integers', () => {
      expect(validator('123').isValid).toBe(true);
    });

    it('passes for decimals', () => {
      expect(validator('123.45').isValid).toBe(true);
    });

    it('passes for negative numbers', () => {
      expect(validator('-123').isValid).toBe(true);
    });

    it('fails for non-numeric', () => {
      expect(validator('abc').isValid).toBe(false);
    });

    it('fails for empty string', () => {
      expect(validator('').isValid).toBe(false);
    });
  });

  describe('integer', () => {
    const validator = integer();

    it('passes for integers', () => {
      expect(validator('123').isValid).toBe(true);
    });

    it('fails for decimals', () => {
      expect(validator('123.45').isValid).toBe(false);
    });
  });

  describe('min', () => {
    const validator = min(10);

    it('passes for values above minimum', () => {
      expect(validator('15').isValid).toBe(true);
    });

    it('passes for value at minimum', () => {
      expect(validator('10').isValid).toBe(true);
    });

    it('fails for values below minimum', () => {
      expect(validator('5').isValid).toBe(false);
    });
  });

  describe('max', () => {
    const validator = max(100);

    it('passes for values below maximum', () => {
      expect(validator('50').isValid).toBe(true);
    });

    it('passes for value at maximum', () => {
      expect(validator('100').isValid).toBe(true);
    });

    it('fails for values above maximum', () => {
      expect(validator('150').isValid).toBe(false);
    });
  });

  describe('custom', () => {
    it('uses custom predicate', () => {
      const validator = custom((value: string) => value.startsWith('test'), 'Must start with test');

      expect(validator('testing').isValid).toBe(true);
      expect(validator('hello').isValid).toBe(false);
    });
  });

  describe('domain', () => {
    const validator = domain();

    it('passes for valid domain', () => {
      expect(validator('example.com').isValid).toBe(true);
    });

    it('passes for subdomain', () => {
      expect(validator('sub.example.com').isValid).toBe(true);
    });

    it('fails for invalid domain', () => {
      expect(validator('not a domain').isValid).toBe(false);
    });
  });

  describe('ipv4', () => {
    const validator = ipv4();

    it('passes for valid IPv4', () => {
      expect(validator('192.168.1.1').isValid).toBe(true);
    });

    it('passes for 0.0.0.0', () => {
      expect(validator('0.0.0.0').isValid).toBe(true);
    });

    it('passes for 255.255.255.255', () => {
      expect(validator('255.255.255.255').isValid).toBe(true);
    });

    it('fails for invalid octets', () => {
      expect(validator('256.1.1.1').isValid).toBe(false);
    });

    it('fails for too few octets', () => {
      expect(validator('192.168.1').isValid).toBe(false);
    });
  });

  describe('hash', () => {
    it('validates MD5 hash', () => {
      const validator = hash('md5');
      expect(validator('d41d8cd98f00b204e9800998ecf8427e').isValid).toBe(true);
      expect(validator('invalid').isValid).toBe(false);
    });

    it('validates SHA1 hash', () => {
      const validator = hash('sha1');
      expect(validator('da39a3ee5e6b4b0d3255bfef95601890afd80709').isValid).toBe(true);
    });

    it('validates SHA256 hash', () => {
      const validator = hash('sha256');
      const validHash = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
      expect(validator(validHash).isValid).toBe(true);
    });
  });

  describe('compose', () => {
    it('combines multiple validators', () => {
      const validator = compose(required(), minLength(3), maxLength(10));

      expect(validator('').isValid).toBe(false); // fails required
      expect(validator('ab').isValid).toBe(false); // fails minLength
      expect(validator('abcdefghijk').isValid).toBe(false); // fails maxLength
      expect(validator('hello').isValid).toBe(true); // passes all
    });

    it('returns first error message', () => {
      const validator = compose(
        required('Required'),
        minLength(3, 'Too short')
      );

      expect(validator('').message).toBe('Required');
      expect(validator('ab').message).toBe('Too short');
    });
  });

  describe('optional', () => {
    it('passes for empty values', () => {
      const validator = optional(email());

      expect(validator('').isValid).toBe(true);
      expect(validator('   ').isValid).toBe(true);
    });

    it('validates non-empty values', () => {
      const validator = optional(email());

      expect(validator('invalid').isValid).toBe(false);
      expect(validator('test@example.com').isValid).toBe(true);
    });
  });

  describe('validateForm', () => {
    it('validates multiple fields', () => {
      const result = validateForm({
        email: {
          value: 'test@example.com',
          validators: [required(), email()],
        },
        password: {
          value: '12345',
          validators: [required(), minLength(6)],
        },
      });

      expect(result.isValid).toBe(false);
      expect(result.errors.email).toBeUndefined();
      expect(result.errors.password).toBeDefined();
    });

    it('returns all errors', () => {
      const result = validateForm({
        email: {
          value: '',
          validators: [required()],
        },
        name: {
          value: '',
          validators: [required()],
        },
      });

      expect(result.isValid).toBe(false);
      expect(Object.keys(result.errors)).toHaveLength(2);
    });

    it('returns empty errors for valid form', () => {
      const result = validateForm({
        email: {
          value: 'test@example.com',
          validators: [required(), email()],
        },
      });

      expect(result.isValid).toBe(true);
      expect(Object.keys(result.errors)).toHaveLength(0);
    });
  });
});
