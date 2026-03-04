/**
 * Indicator Freshness / Decay Utility
 *
 * Calculates the "freshness" of a piece of threat intelligence based on its
 * last_seen timestamp. Intelligence has a shelf life — IPs change ownership,
 * domains expire, threat actors rotate infrastructure. This utility provides
 * a consistent visual signal across the platform.
 *
 * Tiers:
 *  fresh   < 7 days     → green  (#22C55E)
 *  recent  7–30 days    → cyan   (#22D3EE)
 *  aging   30–90 days   → amber  (#F59E0B)
 *  stale   90–180 days  → red    (#EF4444)
 *  expired > 180 days   → grey   (#484F58) + warning
 *  never   null/undefined → grey  (#484F58) + warning
 */

export type FreshnessTier = 'fresh' | 'recent' | 'aging' | 'stale' | 'expired';

export interface FreshnessResult {
  tier: FreshnessTier;
  /** Days since last seen (Infinity if never seen) */
  daysAgo: number;
  /** Human-readable label: "3 days ago", "47 days ago", "Never seen" */
  label: string;
  /** Hex color from cyber palette */
  color: string;
  /** Present for stale/expired tiers — explains the risk */
  warningMessage?: string;
}

// Tier thresholds in days
const THRESHOLDS = {
  fresh: 7,
  recent: 30,
  aging: 90,
  stale: 180,
} as const;

// Cyber palette colors aligned with theme.ts
const TIER_COLORS: Record<FreshnessTier, string> = {
  fresh: '#22C55E',
  recent: '#22D3EE',
  aging: '#F59E0B',
  stale: '#EF4444',
  expired: '#484F58',
};

// Warning messages explaining the risk for stale/expired intel
const WARNING_MESSAGES: Partial<Record<FreshnessTier, string>> = {
  stale: 'Intelligence is over 90 days old — infrastructure may have changed',
  expired: 'Intelligence is over 180 days old — IP ownership, domain registration, or infrastructure may have significantly changed. Recommend re-enriching before acting on this data.',
};

/**
 * Calculates the freshness of a piece of intelligence.
 *
 * @param lastSeen - ISO 8601 string, Date object, or null/undefined for "never seen"
 * @returns FreshnessResult with tier, label, color, and optional warning
 */
export function calculateFreshness(
  lastSeen: string | Date | null | undefined
): FreshnessResult {
  if (!lastSeen) {
    return {
      tier: 'expired',
      daysAgo: Infinity,
      label: 'Never seen',
      color: TIER_COLORS.expired,
      warningMessage: 'No last-seen timestamp available for this indicator.',
    };
  }

  const lastSeenDate = lastSeen instanceof Date ? lastSeen : new Date(lastSeen);

  // Guard against invalid dates
  if (isNaN(lastSeenDate.getTime())) {
    return {
      tier: 'expired',
      daysAgo: Infinity,
      label: 'Unknown',
      color: TIER_COLORS.expired,
      warningMessage: 'Last-seen timestamp could not be parsed.',
    };
  }

  const now = new Date();
  const msAgo = now.getTime() - lastSeenDate.getTime();
  const daysAgo = Math.floor(msAgo / (1000 * 60 * 60 * 24));

  let tier: FreshnessTier;
  if (daysAgo < THRESHOLDS.fresh) {
    tier = 'fresh';
  } else if (daysAgo < THRESHOLDS.recent) {
    tier = 'recent';
  } else if (daysAgo < THRESHOLDS.aging) {
    tier = 'aging';
  } else if (daysAgo < THRESHOLDS.stale) {
    tier = 'stale';
  } else {
    tier = 'expired';
  }

  const label = formatDaysAgo(daysAgo);

  return {
    tier,
    daysAgo,
    label,
    color: TIER_COLORS[tier],
    warningMessage: WARNING_MESSAGES[tier],
  };
}

/**
 * Formats a days count into a human-readable string.
 */
function formatDaysAgo(daysAgo: number): string {
  if (daysAgo === 0) return 'Today';
  if (daysAgo === 1) return '1 day ago';
  if (daysAgo < 7) return `${daysAgo} days ago`;
  if (daysAgo < 14) return '1 week ago';
  if (daysAgo < 30) return `${Math.floor(daysAgo / 7)} weeks ago`;
  if (daysAgo < 60) return '1 month ago';
  if (daysAgo < 365) return `${Math.floor(daysAgo / 30)} months ago`;
  const years = Math.floor(daysAgo / 365);
  return years === 1 ? '1 year ago' : `${years} years ago`;
}

/**
 * Returns true if the intelligence is considered actionable (fresh or recent).
 * Use to filter out stale IOCs from active threat feeds.
 */
export function isActionable(lastSeen: string | Date | null | undefined): boolean {
  const result = calculateFreshness(lastSeen);
  return result.tier === 'fresh' || result.tier === 'recent';
}

/**
 * Returns a sort comparator that sorts entities by freshness (most recent first).
 */
export function freshnessComparator<T extends { last_seen?: string | null }>(
  a: T,
  b: T
): number {
  const aFresh = calculateFreshness(a.last_seen);
  const bFresh = calculateFreshness(b.last_seen);
  return aFresh.daysAgo - bFresh.daysAgo;
}
