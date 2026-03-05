/**
 * Tests for src/components/common/FreshnessIndicator.tsx
 */

import React from 'react';
import { render, screen } from '@testing-library/react';
import { FreshnessIndicator } from '../../components/common/FreshnessIndicator';

// Fixed "now" so tier calculations are deterministic
const NOW = new Date('2026-03-05T12:00:00Z');

function daysAgoISO(days: number): string {
  return new Date(NOW.getTime() - days * 86400_000).toISOString();
}

beforeEach(() => {
  jest.useFakeTimers();
  jest.setSystemTime(NOW);
});
afterEach(() => jest.useRealTimers());

// ─── Renders without crashing ─────────────────────────────────────────────────

describe('FreshnessIndicator — renders without crashing', () => {
  it('renders with null lastSeen', () => {
    expect(() => render(<FreshnessIndicator lastSeen={null} />)).not.toThrow();
  });
  it('renders with undefined lastSeen', () => {
    expect(() => render(<FreshnessIndicator lastSeen={undefined} />)).not.toThrow();
  });
  it('renders with a valid ISO string', () => {
    expect(() => render(<FreshnessIndicator lastSeen={daysAgoISO(3)} />)).not.toThrow();
  });
  it('renders with a Date object', () => {
    expect(() => render(<FreshnessIndicator lastSeen={new Date(daysAgoISO(5))} />)).not.toThrow();
  });
  it('renders with an invalid date string', () => {
    expect(() => render(<FreshnessIndicator lastSeen="not-a-date" />)).not.toThrow();
  });
});

// ─── Full size — label text ───────────────────────────────────────────────────

describe('FreshnessIndicator — full size labels', () => {
  it('shows "Today" for same-day intel', () => {
    render(<FreshnessIndicator lastSeen={daysAgoISO(0)} size="full" />);
    expect(screen.getByText('Today')).toBeInTheDocument();
  });

  it('shows "1 day ago" for 1-day-old intel', () => {
    render(<FreshnessIndicator lastSeen={daysAgoISO(1)} size="full" />);
    expect(screen.getByText('1 day ago')).toBeInTheDocument();
  });

  it('shows "1 week ago" for 7-day-old intel', () => {
    render(<FreshnessIndicator lastSeen={daysAgoISO(7)} size="full" />);
    expect(screen.getByText('1 week ago')).toBeInTheDocument();
  });

  it('shows "Never seen" for null input', () => {
    render(<FreshnessIndicator lastSeen={null} size="full" />);
    expect(screen.getByText('Never seen')).toBeInTheDocument();
  });

  it('shows "1 month ago" for 30-day-old intel', () => {
    render(<FreshnessIndicator lastSeen={daysAgoISO(30)} size="full" />);
    expect(screen.getByText('1 month ago')).toBeInTheDocument();
  });
});

// ─── Compact size ─────────────────────────────────────────────────────────────

describe('FreshnessIndicator — compact size', () => {
  it('renders in compact mode without throwing', () => {
    expect(() =>
      render(<FreshnessIndicator lastSeen={daysAgoISO(5)} size="compact" />)
    ).not.toThrow();
  });

  it('does not render the chip label text in compact mode', () => {
    render(<FreshnessIndicator lastSeen={daysAgoISO(5)} size="compact" />);
    // Compact mode should not show the textual label in the DOM
    expect(screen.queryByText('5 days ago')).not.toBeInTheDocument();
  });

  it('renders compact mode for stale data without throwing', () => {
    expect(() =>
      render(<FreshnessIndicator lastSeen={daysAgoISO(120)} size="compact" />)
    ).not.toThrow();
  });
});

// ─── Default size prop ────────────────────────────────────────────────────────

describe('FreshnessIndicator — default size', () => {
  it('defaults to full size when size prop is omitted', () => {
    render(<FreshnessIndicator lastSeen={daysAgoISO(2)} />);
    // The label should appear (full-size only)
    expect(screen.getByText('2 days ago')).toBeInTheDocument();
  });
});

// ─── className prop ───────────────────────────────────────────────────────────

describe('FreshnessIndicator — className prop', () => {
  it('passes className to the root element', () => {
    const { container } = render(
      <FreshnessIndicator lastSeen={daysAgoISO(3)} className="test-class" />
    );
    // className forwarding requires direct DOM inspection — no Testing Library equivalent
    // eslint-disable-next-line testing-library/no-container, testing-library/no-node-access
    expect(container.querySelector('.test-class')).toBeInTheDocument();
  });
});
