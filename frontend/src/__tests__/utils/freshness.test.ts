/**
 * Tests for src/utils/freshness.ts
 *
 * All time-based assertions use a fixed "now" to ensure deterministic results.
 */

import {
  calculateFreshness,
  isActionable,
  freshnessComparator,
  FreshnessTier,
} from '../../utils/freshness';

// Fixed reference point: 2026-03-05T12:00:00Z
const NOW = new Date('2026-03-05T12:00:00Z');

/** Returns an ISO string that is `daysAgo` days before NOW */
function daysBeforeNow(daysAgo: number): string {
  const d = new Date(NOW.getTime() - daysAgo * 24 * 60 * 60 * 1000);
  return d.toISOString();
}

// Freeze time for all tests in this suite
beforeEach(() => {
  jest.useFakeTimers();
  jest.setSystemTime(NOW);
});

afterEach(() => {
  jest.useRealTimers();
});

// ─────────────────────────────────────────────────────────────────────────────
// calculateFreshness — null / undefined / invalid inputs
// ─────────────────────────────────────────────────────────────────────────────
describe('calculateFreshness — null / undefined / invalid', () => {
  it('returns expired tier for null', () => {
    const r = calculateFreshness(null);
    expect(r.tier).toBe('expired');
    expect(r.daysAgo).toBe(Infinity);
    expect(r.label).toBe('Never seen');
    expect(r.warningMessage).toBeTruthy();
  });

  it('returns expired tier for undefined', () => {
    const r = calculateFreshness(undefined);
    expect(r.tier).toBe('expired');
    expect(r.daysAgo).toBe(Infinity);
  });

  it('returns expired tier for an invalid date string', () => {
    const r = calculateFreshness('not-a-date');
    expect(r.tier).toBe('expired');
    expect(r.daysAgo).toBe(Infinity);
    expect(r.label).toBe('Unknown');
    expect(r.warningMessage).toContain('could not be parsed');
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// calculateFreshness — tier boundaries
// ─────────────────────────────────────────────────────────────────────────────
describe('calculateFreshness — tier boundaries', () => {
  const cases: Array<{ daysAgo: number; expectedTier: FreshnessTier }> = [
    { daysAgo: 0, expectedTier: 'fresh' },
    { daysAgo: 1, expectedTier: 'fresh' },
    { daysAgo: 6, expectedTier: 'fresh' },
    { daysAgo: 7, expectedTier: 'recent' },   // first day of "recent"
    { daysAgo: 29, expectedTier: 'recent' },
    { daysAgo: 30, expectedTier: 'aging' },   // first day of "aging"
    { daysAgo: 89, expectedTier: 'aging' },
    { daysAgo: 90, expectedTier: 'stale' },   // first day of "stale"
    { daysAgo: 179, expectedTier: 'stale' },
    { daysAgo: 180, expectedTier: 'expired' },// first day of "expired"
    { daysAgo: 365, expectedTier: 'expired' },
  ];

  test.each(cases)('$daysAgo days ago → tier $expectedTier', ({ daysAgo, expectedTier }) => {
    const r = calculateFreshness(daysBeforeNow(daysAgo));
    expect(r.tier).toBe(expectedTier);
    expect(r.daysAgo).toBe(daysAgo);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// calculateFreshness — color mapping
// ─────────────────────────────────────────────────────────────────────────────
describe('calculateFreshness — colors', () => {
  it('returns green for fresh', () => {
    expect(calculateFreshness(daysBeforeNow(2)).color).toBe('#22C55E');
  });
  it('returns cyan for recent', () => {
    expect(calculateFreshness(daysBeforeNow(15)).color).toBe('#22D3EE');
  });
  it('returns amber for aging', () => {
    expect(calculateFreshness(daysBeforeNow(60)).color).toBe('#F59E0B');
  });
  it('returns red for stale', () => {
    expect(calculateFreshness(daysBeforeNow(120)).color).toBe('#EF4444');
  });
  it('returns grey for expired', () => {
    expect(calculateFreshness(daysBeforeNow(200)).color).toBe('#484F58');
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// calculateFreshness — warning messages
// ─────────────────────────────────────────────────────────────────────────────
describe('calculateFreshness — warning messages', () => {
  it('has no warning for fresh', () => {
    expect(calculateFreshness(daysBeforeNow(3)).warningMessage).toBeUndefined();
  });
  it('has no warning for recent', () => {
    expect(calculateFreshness(daysBeforeNow(15)).warningMessage).toBeUndefined();
  });
  it('has no warning for aging', () => {
    expect(calculateFreshness(daysBeforeNow(60)).warningMessage).toBeUndefined();
  });
  it('has a warning for stale', () => {
    expect(calculateFreshness(daysBeforeNow(120)).warningMessage).toContain('90 days');
  });
  it('has a warning for expired', () => {
    expect(calculateFreshness(daysBeforeNow(200)).warningMessage).toContain('180 days');
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// calculateFreshness — label formatting
// ─────────────────────────────────────────────────────────────────────────────
describe('calculateFreshness — label formatting', () => {
  it('returns "Today" for 0 days ago', () => {
    expect(calculateFreshness(daysBeforeNow(0)).label).toBe('Today');
  });
  it('returns "1 day ago" for 1 day ago', () => {
    expect(calculateFreshness(daysBeforeNow(1)).label).toBe('1 day ago');
  });
  it('returns "3 days ago" for 3 days ago', () => {
    expect(calculateFreshness(daysBeforeNow(3)).label).toBe('3 days ago');
  });
  it('returns "1 week ago" for 7 days ago', () => {
    expect(calculateFreshness(daysBeforeNow(7)).label).toBe('1 week ago');
  });
  it('returns "2 weeks ago" for 14 days ago', () => {
    expect(calculateFreshness(daysBeforeNow(14)).label).toBe('2 weeks ago');
  });
  it('returns "1 month ago" for 30 days ago', () => {
    expect(calculateFreshness(daysBeforeNow(30)).label).toBe('1 month ago');
  });
  it('returns "2 months ago" for 60 days ago', () => {
    expect(calculateFreshness(daysBeforeNow(60)).label).toBe('2 months ago');
  });
  it('returns "1 year ago" for 365 days ago', () => {
    expect(calculateFreshness(daysBeforeNow(365)).label).toBe('1 year ago');
  });
  it('returns "2 years ago" for 730 days ago', () => {
    expect(calculateFreshness(daysBeforeNow(730)).label).toBe('2 years ago');
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// calculateFreshness — accepts Date objects
// ─────────────────────────────────────────────────────────────────────────────
describe('calculateFreshness — Date object input', () => {
  it('accepts a Date object and returns the same result as an ISO string', () => {
    const iso = daysBeforeNow(5);
    const dateObj = new Date(iso);
    const fromIso = calculateFreshness(iso);
    const fromDate = calculateFreshness(dateObj);
    expect(fromDate.tier).toBe(fromIso.tier);
    expect(fromDate.daysAgo).toBe(fromIso.daysAgo);
    expect(fromDate.color).toBe(fromIso.color);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// isActionable
// ─────────────────────────────────────────────────────────────────────────────
describe('isActionable', () => {
  it('returns true for fresh intel', () => {
    expect(isActionable(daysBeforeNow(3))).toBe(true);
  });
  it('returns true for recent intel', () => {
    expect(isActionable(daysBeforeNow(15))).toBe(true);
  });
  it('returns false for aging intel', () => {
    expect(isActionable(daysBeforeNow(60))).toBe(false);
  });
  it('returns false for stale intel', () => {
    expect(isActionable(daysBeforeNow(120))).toBe(false);
  });
  it('returns false for expired intel', () => {
    expect(isActionable(daysBeforeNow(200))).toBe(false);
  });
  it('returns false for null (never seen)', () => {
    expect(isActionable(null)).toBe(false);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// freshnessComparator
// ─────────────────────────────────────────────────────────────────────────────
describe('freshnessComparator', () => {
  it('sorts most-recent first (ascending daysAgo)', () => {
    const items = [
      { id: 'c', last_seen: daysBeforeNow(120) },
      { id: 'a', last_seen: daysBeforeNow(2) },
      { id: 'b', last_seen: daysBeforeNow(30) },
    ];
    const sorted = [...items].sort(freshnessComparator);
    expect(sorted.map((i) => i.id)).toEqual(['a', 'b', 'c']);
  });

  it('places null last_seen at the end (Infinity daysAgo)', () => {
    const items = [
      { id: 'null', last_seen: null },
      { id: 'fresh', last_seen: daysBeforeNow(1) },
    ];
    const sorted = [...items].sort(freshnessComparator);
    expect(sorted[0].id).toBe('fresh');
    expect(sorted[1].id).toBe('null');
  });

  it('returns 0 for equally-aged items', () => {
    const ts = daysBeforeNow(10);
    const a = { last_seen: ts };
    const b = { last_seen: ts };
    expect(freshnessComparator(a, b)).toBe(0);
  });
});
