/**
 * Accessibility Components Tests
 */

import React from 'react';
import { render, screen, fireEvent } from '@testing-library/react';
import { ThemeProvider } from '@mui/material/styles';
import { theme } from '../../utils/theme';
import {
  SkipLinks,
  VisuallyHidden,
  ErrorBoundary,
  FocusRing,
} from '../../components/a11y';

const renderWithTheme = (component: React.ReactElement) => {
  return render(<ThemeProvider theme={theme}>{component}</ThemeProvider>);
};

// =============================================================================
// SkipLinks Tests
// =============================================================================

describe('SkipLinks Component', () => {
  describe('Rendering', () => {
    it('renders skip links', () => {
      renderWithTheme(<SkipLinks testId="skip-links" />);
      expect(screen.getByTestId('skip-links')).toBeInTheDocument();
    });

    it('renders default links', () => {
      renderWithTheme(<SkipLinks />);
      expect(screen.getByText('Skip to main content')).toBeInTheDocument();
      expect(screen.getByText('Skip to navigation')).toBeInTheDocument();
    });

    it('renders custom links', () => {
      const customLinks = [
        { targetId: 'search', label: 'Skip to search' },
        { targetId: 'footer', label: 'Skip to footer' },
      ];
      renderWithTheme(<SkipLinks links={customLinks} />);
      expect(screen.getByText('Skip to search')).toBeInTheDocument();
      expect(screen.getByText('Skip to footer')).toBeInTheDocument();
    });
  });

  describe('Accessibility', () => {
    it('has navigation role', () => {
      renderWithTheme(<SkipLinks testId="skip-links" />);
      expect(screen.getByRole('navigation', { name: /skip links/i })).toBeInTheDocument();
    });

    it('has correct href attributes', () => {
      renderWithTheme(<SkipLinks />);
      const link = screen.getByText('Skip to main content');
      expect(link).toHaveAttribute('href', '#main-content');
    });
  });

  describe('Click Behavior', () => {
    it('focuses target element on click', () => {
      // Create target element
      const targetElement = document.createElement('div');
      targetElement.id = 'main-content';
      document.body.appendChild(targetElement);

      renderWithTheme(<SkipLinks />);

      fireEvent.click(screen.getByText('Skip to main content'));

      // Element should be focusable
      expect(targetElement).toHaveAttribute('tabindex', '-1');

      // Cleanup
      document.body.removeChild(targetElement);
    });
  });
});

// =============================================================================
// VisuallyHidden Tests
// =============================================================================

describe('VisuallyHidden Component', () => {
  describe('Rendering', () => {
    it('renders children', () => {
      renderWithTheme(<VisuallyHidden>Hidden text</VisuallyHidden>);
      expect(screen.getByText('Hidden text')).toBeInTheDocument();
    });

    it('renders with testId', () => {
      renderWithTheme(<VisuallyHidden testId="hidden">Text</VisuallyHidden>);
      expect(screen.getByTestId('hidden')).toBeInTheDocument();
    });

    it('renders as span by default', () => {
      renderWithTheme(<VisuallyHidden testId="hidden">Text</VisuallyHidden>);
      expect(screen.getByTestId('hidden').tagName).toBe('SPAN');
    });

    it('renders as custom element', () => {
      renderWithTheme(
        <VisuallyHidden as="div" testId="hidden">
          Text
        </VisuallyHidden>
      );
      expect(screen.getByTestId('hidden').tagName).toBe('DIV');
    });
  });

  describe('Accessibility', () => {
    it('is accessible to screen readers', () => {
      renderWithTheme(<VisuallyHidden>Screen reader text</VisuallyHidden>);
      // Text should be in the document (for screen readers)
      expect(screen.getByText('Screen reader text')).toBeInTheDocument();
    });
  });

  describe('Focusable Mode', () => {
    it('can be focusable', () => {
      renderWithTheme(
        <VisuallyHidden focusable testId="focusable">
          Focusable content
        </VisuallyHidden>
      );
      expect(screen.getByTestId('focusable')).toBeInTheDocument();
    });
  });
});

// =============================================================================
// ErrorBoundary Tests
// =============================================================================

describe('ErrorBoundary Component', () => {
  // Suppress console.error for these tests
  const originalError = console.error;
  beforeAll(() => {
    console.error = jest.fn();
  });
  afterAll(() => {
    console.error = originalError;
  });

  const ThrowError: React.FC<{ shouldThrow?: boolean }> = ({ shouldThrow }) => {
    if (shouldThrow) {
      throw new Error('Test error');
    }
    return <div>No error</div>;
  };

  describe('Normal Operation', () => {
    it('renders children when no error', () => {
      renderWithTheme(
        <ErrorBoundary>
          <div>Child content</div>
        </ErrorBoundary>
      );
      expect(screen.getByText('Child content')).toBeInTheDocument();
    });
  });

  describe('Error Handling', () => {
    it('renders error UI when error occurs', () => {
      renderWithTheme(
        <ErrorBoundary testId="error-boundary">
          <ThrowError shouldThrow />
        </ErrorBoundary>
      );
      expect(screen.getByText(/an error occurred/i)).toBeInTheDocument();
    });

    it('shows retry button', () => {
      renderWithTheme(
        <ErrorBoundary testId="error-boundary">
          <ThrowError shouldThrow />
        </ErrorBoundary>
      );
      expect(screen.getByRole('button', { name: /try again/i })).toBeInTheDocument();
    });

    it('has alert role', () => {
      renderWithTheme(
        <ErrorBoundary testId="error-boundary">
          <ThrowError shouldThrow />
        </ErrorBoundary>
      );
      expect(screen.getByRole('alert')).toBeInTheDocument();
    });

    it('calls onError callback', () => {
      const onError = jest.fn();
      renderWithTheme(
        <ErrorBoundary onError={onError}>
          <ThrowError shouldThrow />
        </ErrorBoundary>
      );
      expect(onError).toHaveBeenCalled();
    });

    it('uses custom error message', () => {
      renderWithTheme(
        <ErrorBoundary errorMessage="Custom error message">
          <ThrowError shouldThrow />
        </ErrorBoundary>
      );
      expect(screen.getByText('Custom error message')).toBeInTheDocument();
    });

    it('renders custom fallback', () => {
      renderWithTheme(
        <ErrorBoundary fallback={<div>Custom fallback</div>}>
          <ThrowError shouldThrow />
        </ErrorBoundary>
      );
      expect(screen.getByText('Custom fallback')).toBeInTheDocument();
    });
  });

  describe('Recovery', () => {
    it('recovers when retry is clicked', () => {
      let shouldThrow = true;

      const TestComponent: React.FC = () => {
        if (shouldThrow) {
          throw new Error('Test error');
        }
        return <div>Recovered</div>;
      };

      const { rerender } = renderWithTheme(
        <ErrorBoundary testId="error-boundary">
          <TestComponent />
        </ErrorBoundary>
      );

      // Error should be shown
      expect(screen.getByRole('alert')).toBeInTheDocument();

      // Fix the error
      shouldThrow = false;

      // Click retry
      fireEvent.click(screen.getByTestId('error-boundary-retry'));

      // Force re-render
      rerender(
        <ThemeProvider theme={theme}>
          <ErrorBoundary testId="error-boundary">
            <TestComponent />
          </ErrorBoundary>
        </ThemeProvider>
      );

      // Should show recovered content
      expect(screen.getByText('Recovered')).toBeInTheDocument();
    });
  });
});

// =============================================================================
// FocusRing Tests
// =============================================================================

describe('FocusRing Component', () => {
  describe('Rendering', () => {
    it('renders children', () => {
      renderWithTheme(
        <FocusRing>
          <button>Focus me</button>
        </FocusRing>
      );
      expect(screen.getByRole('button', { name: /focus me/i })).toBeInTheDocument();
    });
  });

  describe('Props', () => {
    it('accepts custom color', () => {
      renderWithTheme(
        <FocusRing color="#ff0000">
          <button>Button</button>
        </FocusRing>
      );
      expect(screen.getByRole('button')).toBeInTheDocument();
    });

    it('accepts custom offset', () => {
      renderWithTheme(
        <FocusRing offset={4}>
          <button>Button</button>
        </FocusRing>
      );
      expect(screen.getByRole('button')).toBeInTheDocument();
    });

    it('accepts custom width', () => {
      renderWithTheme(
        <FocusRing width={3}>
          <button>Button</button>
        </FocusRing>
      );
      expect(screen.getByRole('button')).toBeInTheDocument();
    });

    it('accepts alwaysShow prop', () => {
      renderWithTheme(
        <FocusRing alwaysShow>
          <button>Button</button>
        </FocusRing>
      );
      expect(screen.getByRole('button')).toBeInTheDocument();
    });
  });
});
