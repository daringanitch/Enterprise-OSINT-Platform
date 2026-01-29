/**
 * Loading Component Tests
 */

import React from 'react';
import { render, screen } from '@testing-library/react';
import { ThemeProvider } from '@mui/material/styles';
import { theme } from '../../utils/theme';
import {
  Spinner,
  ProgressBar,
  LoadingOverlay,
  FullPageLoading,
  SkeletonCard,
  SkeletonTable,
} from '../../components/common/Loading';

const renderWithTheme = (component: React.ReactElement) => {
  return render(<ThemeProvider theme={theme}>{component}</ThemeProvider>);
};

describe('Spinner Component', () => {
  describe('Rendering', () => {
    it('renders spinner', () => {
      renderWithTheme(<Spinner testId="test-spinner" />);
      expect(screen.getByTestId('test-spinner')).toBeInTheDocument();
    });

    it('has accessible label', () => {
      renderWithTheme(<Spinner label="Loading data" />);
      expect(screen.getByLabelText('Loading data')).toBeInTheDocument();
    });

    it('uses default label when not provided', () => {
      renderWithTheme(<Spinner />);
      expect(screen.getByLabelText('Loading')).toBeInTheDocument();
    });
  });

  describe('Sizes', () => {
    const sizes = ['sm', 'md', 'lg'] as const;

    sizes.forEach((size) => {
      it(`renders ${size} size`, () => {
        renderWithTheme(<Spinner size={size} testId={`${size}-spinner`} />);
        expect(screen.getByTestId(`${size}-spinner`)).toBeInTheDocument();
      });
    });
  });

  describe('Colors', () => {
    const colors = ['primary', 'secondary', 'inherit'] as const;

    colors.forEach((color) => {
      it(`renders ${color} color`, () => {
        renderWithTheme(<Spinner color={color} testId={`${color}-spinner`} />);
        expect(screen.getByTestId(`${color}-spinner`)).toBeInTheDocument();
      });
    });
  });
});

describe('ProgressBar Component', () => {
  describe('Rendering', () => {
    it('renders progress bar', () => {
      renderWithTheme(<ProgressBar value={50} testId="test-progress" />);
      expect(screen.getByTestId('test-progress')).toBeInTheDocument();
    });

    it('renders indeterminate progress', () => {
      renderWithTheme(<ProgressBar indeterminate testId="indeterminate-progress" />);
      expect(screen.getByTestId('indeterminate-progress')).toBeInTheDocument();
    });
  });

  describe('Values', () => {
    it('shows 0% progress', () => {
      renderWithTheme(<ProgressBar value={0} showLabel />);
      expect(screen.getByText('0%')).toBeInTheDocument();
    });

    it('shows 50% progress', () => {
      renderWithTheme(<ProgressBar value={50} showLabel />);
      expect(screen.getByText('50%')).toBeInTheDocument();
    });

    it('shows 100% progress', () => {
      renderWithTheme(<ProgressBar value={100} showLabel />);
      expect(screen.getByText('100%')).toBeInTheDocument();
    });

    it('rounds decimal values', () => {
      renderWithTheme(<ProgressBar value={33.7} showLabel />);
      expect(screen.getByText('34%')).toBeInTheDocument();
    });
  });

  describe('Labels', () => {
    it('shows label when showLabel is true', () => {
      renderWithTheme(<ProgressBar value={50} showLabel />);
      expect(screen.getByText('Progress')).toBeInTheDocument();
      expect(screen.getByText('50%')).toBeInTheDocument();
    });

    it('shows custom label', () => {
      renderWithTheme(<ProgressBar value={75} label="Uploading" />);
      expect(screen.getByText('Uploading')).toBeInTheDocument();
    });

    it('hides percentage for indeterminate', () => {
      renderWithTheme(<ProgressBar indeterminate showLabel label="Loading" />);
      expect(screen.getByText('Loading')).toBeInTheDocument();
      expect(screen.queryByText('%')).not.toBeInTheDocument();
    });
  });

  describe('Colors', () => {
    const colors = ['primary', 'secondary', 'success', 'warning', 'error'] as const;

    colors.forEach((color) => {
      it(`renders ${color} color`, () => {
        renderWithTheme(<ProgressBar value={50} color={color} testId={`${color}-progress`} />);
        expect(screen.getByTestId(`${color}-progress`)).toBeInTheDocument();
      });
    });
  });

  describe('Accessibility', () => {
    it('has progressbar role', () => {
      renderWithTheme(<ProgressBar value={50} />);
      expect(screen.getByRole('progressbar')).toBeInTheDocument();
    });

    it('has aria-valuenow', () => {
      renderWithTheme(<ProgressBar value={50} />);
      expect(screen.getByRole('progressbar')).toHaveAttribute('aria-valuenow', '50');
    });

    it('has aria-valuemin and aria-valuemax', () => {
      renderWithTheme(<ProgressBar value={50} />);
      const progressbar = screen.getByRole('progressbar');
      expect(progressbar).toHaveAttribute('aria-valuemin', '0');
      expect(progressbar).toHaveAttribute('aria-valuemax', '100');
    });
  });
});

describe('LoadingOverlay Component', () => {
  describe('Rendering', () => {
    it('renders children', () => {
      renderWithTheme(
        <LoadingOverlay loading={false}>
          <p>Content</p>
        </LoadingOverlay>
      );
      expect(screen.getByText('Content')).toBeInTheDocument();
    });

    it('shows overlay when loading', () => {
      renderWithTheme(
        <LoadingOverlay loading testId="loading-overlay">
          <p>Content</p>
        </LoadingOverlay>
      );
      expect(screen.getByTestId('loading-overlay')).toBeInTheDocument();
    });

    it('hides overlay when not loading', () => {
      renderWithTheme(
        <LoadingOverlay loading={false} testId="loading-overlay">
          <p>Content</p>
        </LoadingOverlay>
      );
      expect(screen.queryByTestId('loading-overlay')).not.toBeInTheDocument();
    });

    it('shows message when loading', () => {
      renderWithTheme(
        <LoadingOverlay loading message="Please wait...">
          <p>Content</p>
        </LoadingOverlay>
      );
      expect(screen.getByText('Please wait...')).toBeInTheDocument();
    });
  });

  describe('Translucent Mode', () => {
    it('renders translucent by default', () => {
      renderWithTheme(
        <LoadingOverlay loading testId="translucent-overlay">
          <p>Content</p>
        </LoadingOverlay>
      );
      expect(screen.getByTestId('translucent-overlay')).toBeInTheDocument();
    });

    it('renders opaque when translucent is false', () => {
      renderWithTheme(
        <LoadingOverlay loading translucent={false} testId="opaque-overlay">
          <p>Content</p>
        </LoadingOverlay>
      );
      expect(screen.getByTestId('opaque-overlay')).toBeInTheDocument();
    });
  });
});

describe('FullPageLoading Component', () => {
  describe('Rendering', () => {
    it('renders full page loading', () => {
      renderWithTheme(<FullPageLoading testId="full-page-loading" />);
      expect(screen.getByTestId('full-page-loading')).toBeInTheDocument();
    });

    it('shows default message', () => {
      renderWithTheme(<FullPageLoading />);
      expect(screen.getByText('Loading...')).toBeInTheDocument();
    });

    it('shows custom message', () => {
      renderWithTheme(<FullPageLoading message="Initializing application..." />);
      expect(screen.getByText('Initializing application...')).toBeInTheDocument();
    });

    it('shows logo by default', () => {
      renderWithTheme(<FullPageLoading />);
      expect(screen.getByText('OSINT Platform')).toBeInTheDocument();
    });

    it('hides logo when showLogo is false', () => {
      renderWithTheme(<FullPageLoading showLogo={false} />);
      expect(screen.queryByText('OSINT Platform')).not.toBeInTheDocument();
    });
  });

  describe('Accessibility', () => {
    it('has status role', () => {
      renderWithTheme(<FullPageLoading />);
      expect(screen.getByRole('status')).toBeInTheDocument();
    });

    it('has aria-live attribute', () => {
      renderWithTheme(<FullPageLoading />);
      expect(screen.getByRole('status')).toHaveAttribute('aria-live', 'polite');
    });
  });
});

describe('SkeletonCard Component', () => {
  describe('Rendering', () => {
    it('renders skeleton card', () => {
      renderWithTheme(<SkeletonCard testId="skeleton-card" />);
      expect(screen.getByTestId('skeleton-card')).toBeInTheDocument();
    });

    it('shows header skeleton by default', () => {
      renderWithTheme(<SkeletonCard testId="skeleton-card" />);
      // Header skeleton should be present
      expect(screen.getByTestId('skeleton-card')).toBeInTheDocument();
    });

    it('hides header when showHeader is false', () => {
      renderWithTheme(<SkeletonCard showHeader={false} testId="no-header-skeleton" />);
      expect(screen.getByTestId('no-header-skeleton')).toBeInTheDocument();
    });

    it('shows footer when showFooter is true', () => {
      renderWithTheme(<SkeletonCard showFooter testId="footer-skeleton" />);
      expect(screen.getByTestId('footer-skeleton')).toBeInTheDocument();
    });
  });

  describe('Lines', () => {
    it('renders default 3 lines', () => {
      renderWithTheme(<SkeletonCard testId="default-lines" />);
      expect(screen.getByTestId('default-lines')).toBeInTheDocument();
    });

    it('renders custom number of lines', () => {
      renderWithTheme(<SkeletonCard lines={5} testId="custom-lines" />);
      expect(screen.getByTestId('custom-lines')).toBeInTheDocument();
    });
  });
});

describe('SkeletonTable Component', () => {
  describe('Rendering', () => {
    it('renders skeleton table', () => {
      renderWithTheme(<SkeletonTable testId="skeleton-table" />);
      expect(screen.getByTestId('skeleton-table')).toBeInTheDocument();
    });

    it('renders default 5 rows', () => {
      renderWithTheme(<SkeletonTable testId="default-rows" />);
      expect(screen.getByTestId('default-rows')).toBeInTheDocument();
    });

    it('renders custom number of rows', () => {
      renderWithTheme(<SkeletonTable rows={10} testId="custom-rows" />);
      expect(screen.getByTestId('custom-rows')).toBeInTheDocument();
    });

    it('renders default 4 columns', () => {
      renderWithTheme(<SkeletonTable testId="default-cols" />);
      expect(screen.getByTestId('default-cols')).toBeInTheDocument();
    });

    it('renders custom number of columns', () => {
      renderWithTheme(<SkeletonTable columns={6} testId="custom-cols" />);
      expect(screen.getByTestId('custom-cols')).toBeInTheDocument();
    });
  });
});
