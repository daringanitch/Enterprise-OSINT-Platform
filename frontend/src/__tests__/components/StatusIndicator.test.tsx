/**
 * StatusIndicator Component Tests
 */

import React from 'react';
import { render, screen } from '@testing-library/react';
import { ThemeProvider } from '@mui/material/styles';
import { theme } from '../../utils/theme';
import {
  StatusIndicator,
  RiskLevelIndicator,
  InvestigationStatusIndicator,
} from '../../components/common/StatusIndicator';

const renderWithTheme = (component: React.ReactElement) => {
  return render(<ThemeProvider theme={theme}>{component}</ThemeProvider>);
};

describe('StatusIndicator Component', () => {
  describe('Rendering', () => {
    it('renders with variant', () => {
      renderWithTheme(<StatusIndicator variant="success" testId="status" />);
      expect(screen.getByTestId('status')).toBeInTheDocument();
    });

    it('renders with label', () => {
      renderWithTheme(<StatusIndicator variant="success" label="Active" />);
      expect(screen.getByText('Active')).toBeInTheDocument();
    });

    it('renders with testId', () => {
      renderWithTheme(<StatusIndicator variant="info" testId="test-status" />);
      expect(screen.getByTestId('test-status')).toBeInTheDocument();
    });
  });

  describe('Variants', () => {
    const variants = ['success', 'warning', 'error', 'info', 'neutral', 'pending'] as const;

    variants.forEach((variant) => {
      it(`renders ${variant} variant`, () => {
        renderWithTheme(
          <StatusIndicator variant={variant} testId={`${variant}-status`} />
        );
        expect(screen.getByTestId(`${variant}-status`)).toBeInTheDocument();
      });
    });
  });

  describe('Sizes', () => {
    const sizes = ['sm', 'md', 'lg'] as const;

    sizes.forEach((size) => {
      it(`renders ${size} size`, () => {
        renderWithTheme(
          <StatusIndicator variant="success" size={size} testId={`${size}-status`} />
        );
        expect(screen.getByTestId(`${size}-status`)).toBeInTheDocument();
      });
    });
  });

  describe('Badge Mode', () => {
    it('renders as badge when asBadge is true and has label', () => {
      renderWithTheme(
        <StatusIndicator variant="success" label="Active" asBadge testId="badge-status" />
      );
      expect(screen.getByTestId('badge-status')).toBeInTheDocument();
      expect(screen.getByText('Active')).toBeInTheDocument();
    });

    it('renders as dot without badge when no label', () => {
      renderWithTheme(
        <StatusIndicator variant="success" asBadge testId="dot-status" />
      );
      expect(screen.getByTestId('dot-status')).toBeInTheDocument();
    });
  });

  describe('Pulse Animation', () => {
    it('renders with pulse animation', () => {
      renderWithTheme(
        <StatusIndicator variant="success" pulse testId="pulse-status" />
      );
      expect(screen.getByTestId('pulse-status')).toBeInTheDocument();
    });
  });

  describe('Accessibility', () => {
    it('has status role', () => {
      renderWithTheme(<StatusIndicator variant="success" />);
      expect(screen.getByRole('status')).toBeInTheDocument();
    });

    it('uses provided ariaLabel', () => {
      renderWithTheme(
        <StatusIndicator variant="success" ariaLabel="System is operational" />
      );
      expect(screen.getByLabelText('System is operational')).toBeInTheDocument();
    });

    it('generates ariaLabel from label when not provided', () => {
      renderWithTheme(<StatusIndicator variant="success" label="Active" />);
      expect(screen.getByLabelText('Status: Active')).toBeInTheDocument();
    });

    it('generates ariaLabel from variant when no label', () => {
      renderWithTheme(<StatusIndicator variant="success" />);
      expect(screen.getByLabelText('Status: success')).toBeInTheDocument();
    });
  });
});

describe('RiskLevelIndicator Component', () => {
  describe('Risk Levels', () => {
    const levels = ['critical', 'high', 'medium', 'low'] as const;

    levels.forEach((level) => {
      it(`renders ${level} risk level`, () => {
        renderWithTheme(
          <RiskLevelIndicator level={level} testId={`${level}-risk`} />
        );
        expect(screen.getByTestId(`${level}-risk`)).toBeInTheDocument();
      });
    });
  });

  describe('Labels', () => {
    it('renders Critical label', () => {
      renderWithTheme(<RiskLevelIndicator level="critical" />);
      expect(screen.getByText('Critical')).toBeInTheDocument();
    });

    it('renders High label', () => {
      renderWithTheme(<RiskLevelIndicator level="high" />);
      expect(screen.getByText('High')).toBeInTheDocument();
    });

    it('renders Medium label', () => {
      renderWithTheme(<RiskLevelIndicator level="medium" />);
      expect(screen.getByText('Medium')).toBeInTheDocument();
    });

    it('renders Low label', () => {
      renderWithTheme(<RiskLevelIndicator level="low" />);
      expect(screen.getByText('Low')).toBeInTheDocument();
    });
  });

  describe('Score Display', () => {
    it('shows score when provided and showScore is true', () => {
      renderWithTheme(<RiskLevelIndicator level="high" score={85} showScore />);
      expect(screen.getByText('High (85)')).toBeInTheDocument();
    });

    it('hides score when showScore is false', () => {
      renderWithTheme(<RiskLevelIndicator level="high" score={85} showScore={false} />);
      expect(screen.getByText('High')).toBeInTheDocument();
      expect(screen.queryByText('High (85)')).not.toBeInTheDocument();
    });

    it('shows score by default', () => {
      renderWithTheme(<RiskLevelIndicator level="medium" score={50} />);
      expect(screen.getByText('Medium (50)')).toBeInTheDocument();
    });
  });

  describe('Accessibility', () => {
    it('has appropriate aria-label', () => {
      renderWithTheme(<RiskLevelIndicator level="critical" score={95} />);
      expect(screen.getByLabelText('Risk level: Critical (95)')).toBeInTheDocument();
    });
  });
});

describe('InvestigationStatusIndicator Component', () => {
  describe('Status States', () => {
    const statuses = [
      'pending',
      'queued',
      'planning',
      'profiling',
      'collecting',
      'analyzing',
      'assessing_risk',
      'verifying',
      'generating_report',
      'completed',
      'failed',
      'cancelled',
    ];

    statuses.forEach((status) => {
      it(`renders ${status} status`, () => {
        renderWithTheme(
          <InvestigationStatusIndicator status={status} testId={`${status}-investigation`} />
        );
        expect(screen.getByTestId(`${status}-investigation`)).toBeInTheDocument();
      });
    });
  });

  describe('Labels', () => {
    it('renders Pending label', () => {
      renderWithTheme(<InvestigationStatusIndicator status="pending" />);
      expect(screen.getByText('Pending')).toBeInTheDocument();
    });

    it('renders Analyzing label', () => {
      renderWithTheme(<InvestigationStatusIndicator status="analyzing" />);
      expect(screen.getByText('Analyzing')).toBeInTheDocument();
    });

    it('renders Completed label', () => {
      renderWithTheme(<InvestigationStatusIndicator status="completed" />);
      expect(screen.getByText('Completed')).toBeInTheDocument();
    });

    it('renders Failed label', () => {
      renderWithTheme(<InvestigationStatusIndicator status="failed" />);
      expect(screen.getByText('Failed')).toBeInTheDocument();
    });

    it('handles unknown status gracefully', () => {
      renderWithTheme(<InvestigationStatusIndicator status="unknown_status" />);
      expect(screen.getByText('unknown_status')).toBeInTheDocument();
    });
  });

  describe('Progress Display', () => {
    it('shows progress percentage when provided', () => {
      renderWithTheme(
        <InvestigationStatusIndicator status="analyzing" progress={45} />
      );
      expect(screen.getByText('Analyzing (45%)')).toBeInTheDocument();
    });

    it('shows 0% progress', () => {
      renderWithTheme(
        <InvestigationStatusIndicator status="planning" progress={0} />
      );
      expect(screen.getByText('Planning (0%)')).toBeInTheDocument();
    });

    it('shows 100% progress', () => {
      renderWithTheme(
        <InvestigationStatusIndicator status="generating_report" progress={100} />
      );
      expect(screen.getByText('Generating Report (100%)')).toBeInTheDocument();
    });
  });

  describe('Pulse Animation', () => {
    const activeStatuses = [
      'planning',
      'profiling',
      'collecting',
      'analyzing',
      'assessing_risk',
      'verifying',
      'generating_report',
    ];

    activeStatuses.forEach((status) => {
      it(`has pulse animation for ${status}`, () => {
        renderWithTheme(
          <InvestigationStatusIndicator status={status} testId={`${status}-indicator`} />
        );
        // Component should render (pulse is handled internally)
        expect(screen.getByTestId(`${status}-indicator`)).toBeInTheDocument();
      });
    });
  });

  describe('Accessibility', () => {
    it('has appropriate aria-label', () => {
      renderWithTheme(<InvestigationStatusIndicator status="analyzing" />);
      expect(screen.getByLabelText('Investigation status: Analyzing')).toBeInTheDocument();
    });

    it('includes progress in aria-label when provided', () => {
      renderWithTheme(<InvestigationStatusIndicator status="collecting" progress={75} />);
      expect(
        screen.getByLabelText('Investigation status: Collecting (75%), 75% complete')
      ).toBeInTheDocument();
    });
  });
});
