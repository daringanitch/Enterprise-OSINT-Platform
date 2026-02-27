/**
 * Button Component Tests
 */

import React from 'react';
import { render, screen, fireEvent, within } from '@testing-library/react';
import { ThemeProvider } from '@mui/material/styles';
import { theme } from '../../utils/theme';
import { Button } from '../../components/common/Button';

const renderWithTheme = (component: React.ReactElement) => {
  return render(<ThemeProvider theme={theme}>{component}</ThemeProvider>);
};

describe('Button Component', () => {
  describe('Rendering', () => {
    it('renders button with text', () => {
      renderWithTheme(<Button>Click me</Button>);
      expect(screen.getByRole('button', { name: /click me/i })).toBeInTheDocument();
    });

    it('renders with testId', () => {
      renderWithTheme(<Button testId="test-button">Test</Button>);
      expect(screen.getByTestId('test-button')).toBeInTheDocument();
    });
  });

  describe('Variants', () => {
    const variants = ['primary', 'secondary', 'success', 'warning', 'danger', 'ghost'] as const;

    variants.forEach((variant) => {
      it(`renders ${variant} variant`, () => {
        renderWithTheme(
          <Button variant={variant} testId={`${variant}-btn`}>
            {variant}
          </Button>
        );
        expect(screen.getByTestId(`${variant}-btn`)).toBeInTheDocument();
      });
    });
  });

  describe('Sizes', () => {
    const sizes = ['sm', 'md', 'lg'] as const;

    sizes.forEach((size) => {
      it(`renders ${size} size`, () => {
        renderWithTheme(
          <Button size={size} testId={`${size}-btn`}>
            {size}
          </Button>
        );
        expect(screen.getByTestId(`${size}-btn`)).toBeInTheDocument();
      });
    });
  });

  describe('States', () => {
    it('handles disabled state', () => {
      renderWithTheme(<Button disabled>Disabled</Button>);
      expect(screen.getByRole('button')).toBeDisabled();
    });

    it('handles loading state', () => {
      renderWithTheme(<Button loading>Loading</Button>);
      const button = screen.getByRole('button');
      expect(button).toBeDisabled();
      expect(button).toHaveAttribute('aria-busy', 'true');
    });

    it('shows spinner when loading', () => {
      renderWithTheme(<Button loading testId="loading-btn">Loading</Button>);
      const button = screen.getByTestId('loading-btn');
      expect(within(button).getByRole('progressbar')).toBeInTheDocument();
    });
  });

  describe('Interactions', () => {
    it('calls onClick handler when clicked', () => {
      const handleClick = jest.fn();
      renderWithTheme(<Button onClick={handleClick}>Click</Button>);
      fireEvent.click(screen.getByRole('button'));
      expect(handleClick).toHaveBeenCalledTimes(1);
    });

    it('does not call onClick when disabled', () => {
      const handleClick = jest.fn();
      renderWithTheme(
        <Button onClick={handleClick} disabled>
          Click
        </Button>
      );
      fireEvent.click(screen.getByRole('button'));
      expect(handleClick).not.toHaveBeenCalled();
    });

    it('does not call onClick when loading', () => {
      const handleClick = jest.fn();
      renderWithTheme(
        <Button onClick={handleClick} loading>
          Click
        </Button>
      );
      fireEvent.click(screen.getByRole('button'));
      expect(handleClick).not.toHaveBeenCalled();
    });
  });

  describe('Icons', () => {
    it('renders with start icon', () => {
      renderWithTheme(
        <Button startIcon={<span data-testid="start-icon">→</span>}>
          With Icon
        </Button>
      );
      expect(screen.getByTestId('start-icon')).toBeInTheDocument();
    });

    it('renders with end icon', () => {
      renderWithTheme(
        <Button endIcon={<span data-testid="end-icon">←</span>}>
          With Icon
        </Button>
      );
      expect(screen.getByTestId('end-icon')).toBeInTheDocument();
    });

    it('hides icons when loading', () => {
      renderWithTheme(
        <Button
          loading
          startIcon={<span data-testid="start-icon">→</span>}
          endIcon={<span data-testid="end-icon">←</span>}
        >
          Loading
        </Button>
      );
      expect(screen.queryByTestId('start-icon')).not.toBeInTheDocument();
      expect(screen.queryByTestId('end-icon')).not.toBeInTheDocument();
    });
  });

  describe('Full Width', () => {
    it('renders full width when specified', () => {
      renderWithTheme(<Button fullWidth testId="full-btn">Full Width</Button>);
      const button = screen.getByTestId('full-btn');
      expect(button).toHaveClass('MuiButton-fullWidth');
    });
  });
});
