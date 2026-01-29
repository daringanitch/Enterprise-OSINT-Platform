/**
 * Card Component Tests
 */

import React from 'react';
import { render, screen, fireEvent } from '@testing-library/react';
import { ThemeProvider } from '@mui/material/styles';
import { theme } from '../../utils/theme';
import { Card, CardStat } from '../../components/common/Card';

const renderWithTheme = (component: React.ReactElement) => {
  return render(<ThemeProvider theme={theme}>{component}</ThemeProvider>);
};

describe('Card Component', () => {
  describe('Rendering', () => {
    it('renders card with children', () => {
      renderWithTheme(
        <Card>
          <p>Card content</p>
        </Card>
      );
      expect(screen.getByText('Card content')).toBeInTheDocument();
    });

    it('renders with testId', () => {
      renderWithTheme(
        <Card testId="test-card">
          <p>Content</p>
        </Card>
      );
      expect(screen.getByTestId('test-card')).toBeInTheDocument();
    });

    it('renders with title', () => {
      renderWithTheme(
        <Card title="Card Title">
          <p>Content</p>
        </Card>
      );
      expect(screen.getByText('Card Title')).toBeInTheDocument();
    });

    it('renders with subtitle', () => {
      renderWithTheme(
        <Card title="Title" subtitle="Subtitle">
          <p>Content</p>
        </Card>
      );
      expect(screen.getByText('Subtitle')).toBeInTheDocument();
    });

    it('renders header action', () => {
      renderWithTheme(
        <Card title="Title" headerAction={<button>Action</button>}>
          <p>Content</p>
        </Card>
      );
      expect(screen.getByRole('button', { name: /action/i })).toBeInTheDocument();
    });

    it('renders footer', () => {
      renderWithTheme(
        <Card footer={<button>Footer Action</button>}>
          <p>Content</p>
        </Card>
      );
      expect(screen.getByRole('button', { name: /footer action/i })).toBeInTheDocument();
    });
  });

  describe('Variants', () => {
    const variants = ['default', 'elevated', 'outlined', 'gradient'] as const;

    variants.forEach((variant) => {
      it(`renders ${variant} variant`, () => {
        renderWithTheme(
          <Card variant={variant} testId={`${variant}-card`}>
            <p>{variant}</p>
          </Card>
        );
        expect(screen.getByTestId(`${variant}-card`)).toBeInTheDocument();
      });
    });
  });

  describe('Interactive State', () => {
    it('handles click when interactive', () => {
      const handleClick = jest.fn();
      renderWithTheme(
        <Card interactive onClick={handleClick} testId="interactive-card">
          <p>Click me</p>
        </Card>
      );
      fireEvent.click(screen.getByTestId('interactive-card'));
      expect(handleClick).toHaveBeenCalledTimes(1);
    });

    it('has button role when interactive', () => {
      renderWithTheme(
        <Card interactive testId="interactive-card">
          <p>Content</p>
        </Card>
      );
      expect(screen.getByTestId('interactive-card')).toHaveAttribute('role', 'button');
    });

    it('is focusable when interactive', () => {
      renderWithTheme(
        <Card interactive testId="interactive-card">
          <p>Content</p>
        </Card>
      );
      expect(screen.getByTestId('interactive-card')).toHaveAttribute('tabIndex', '0');
    });

    it('handles keyboard Enter when interactive', () => {
      const handleClick = jest.fn();
      renderWithTheme(
        <Card interactive onClick={handleClick} testId="interactive-card">
          <p>Content</p>
        </Card>
      );
      fireEvent.keyDown(screen.getByTestId('interactive-card'), { key: 'Enter' });
      expect(handleClick).toHaveBeenCalledTimes(1);
    });

    it('handles keyboard Space when interactive', () => {
      const handleClick = jest.fn();
      renderWithTheme(
        <Card interactive onClick={handleClick} testId="interactive-card">
          <p>Content</p>
        </Card>
      );
      fireEvent.keyDown(screen.getByTestId('interactive-card'), { key: ' ' });
      expect(handleClick).toHaveBeenCalledTimes(1);
    });

    it('does not have button role when not interactive', () => {
      renderWithTheme(
        <Card testId="static-card">
          <p>Content</p>
        </Card>
      );
      expect(screen.getByTestId('static-card')).not.toHaveAttribute('role', 'button');
    });
  });

  describe('Loading State', () => {
    it('shows skeleton when loading', () => {
      renderWithTheme(
        <Card loading title="Title" subtitle="Subtitle" testId="loading-card">
          <p>Content</p>
        </Card>
      );
      expect(screen.getByTestId('loading-card')).toBeInTheDocument();
      // Skeleton elements should be rendered
      expect(screen.queryByText('Content')).not.toBeInTheDocument();
    });
  });

  describe('Padding', () => {
    const paddings = ['none', 'sm', 'md', 'lg'] as const;

    paddings.forEach((padding) => {
      it(`renders with ${padding} padding`, () => {
        renderWithTheme(
          <Card padding={padding} testId={`${padding}-padding-card`}>
            <p>Content</p>
          </Card>
        );
        expect(screen.getByTestId(`${padding}-padding-card`)).toBeInTheDocument();
      });
    });
  });

  describe('Custom className', () => {
    it('applies custom className', () => {
      renderWithTheme(
        <Card className="custom-class" testId="custom-card">
          <p>Content</p>
        </Card>
      );
      expect(screen.getByTestId('custom-card')).toHaveClass('custom-class');
    });
  });
});

describe('CardStat Component', () => {
  it('renders label and value', () => {
    renderWithTheme(<CardStat label="Total Users" value={1234} />);
    expect(screen.getByText('Total Users')).toBeInTheDocument();
    expect(screen.getByText('1234')).toBeInTheDocument();
  });

  it('renders string value', () => {
    renderWithTheme(<CardStat label="Status" value="Active" />);
    expect(screen.getByText('Active')).toBeInTheDocument();
  });

  it('renders with icon', () => {
    renderWithTheme(
      <CardStat
        label="Users"
        value={100}
        icon={<span data-testid="stat-icon">👤</span>}
      />
    );
    expect(screen.getByTestId('stat-icon')).toBeInTheDocument();
  });

  describe('Trends', () => {
    it('renders up trend', () => {
      renderWithTheme(
        <CardStat label="Revenue" value="$10k" trend="up" trendValue="+15%" />
      );
      expect(screen.getByText(/↑/)).toBeInTheDocument();
      expect(screen.getByText(/\+15%/)).toBeInTheDocument();
    });

    it('renders down trend', () => {
      renderWithTheme(
        <CardStat label="Costs" value="$5k" trend="down" trendValue="-10%" />
      );
      expect(screen.getByText(/↓/)).toBeInTheDocument();
      expect(screen.getByText(/-10%/)).toBeInTheDocument();
    });

    it('renders neutral trend', () => {
      renderWithTheme(
        <CardStat label="Users" value={100} trend="neutral" trendValue="0%" />
      );
      expect(screen.getByText(/→/)).toBeInTheDocument();
      expect(screen.getByText(/0%/)).toBeInTheDocument();
    });

    it('does not render trend without trendValue', () => {
      renderWithTheme(<CardStat label="Users" value={100} trend="up" />);
      expect(screen.queryByText(/↑/)).not.toBeInTheDocument();
    });
  });
});
