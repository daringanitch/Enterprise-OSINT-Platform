/**
 * FreshnessIndicator
 *
 * Visual badge showing how recently a piece of intelligence was observed.
 * Uses the freshness utility to determine tier/color and renders as either:
 *   - 'compact': colored dot + tooltip only (for tight spaces like table cells)
 *   - 'full': colored chip with clock icon + text (for cards and detail panels)
 *
 * Usage:
 *   <FreshnessIndicator lastSeen={entity.last_seen} />
 *   <FreshnessIndicator lastSeen={indicator.first_seen} size="compact" />
 */

import React from 'react';
import { Chip, Tooltip, Box, styled } from '@mui/material';
import AccessTimeIcon from '@mui/icons-material/AccessTime';
import WarningAmberIcon from '@mui/icons-material/WarningAmber';
import { calculateFreshness, FreshnessTier } from '../../utils/freshness';

// ─── Types ────────────────────────────────────────────────────────────────────

export interface FreshnessIndicatorProps {
  /** ISO 8601 string, Date, or null/undefined */
  lastSeen: string | Date | null | undefined;
  /** 'compact' shows only an icon with tooltip; 'full' shows icon + label */
  size?: 'compact' | 'full';
  /** Optional className for layout control */
  className?: string;
}

// ─── Styled Components ────────────────────────────────────────────────────────

const FreshnessChip = styled(Chip)<{ tier: FreshnessTier; chipcolor: string }>(
  ({ chipcolor }) => ({
    height: 22,
    fontSize: '0.7rem',
    fontWeight: 600,
    letterSpacing: '0.03em',
    backgroundColor: `${chipcolor}18`,
    color: chipcolor,
    border: `1px solid ${chipcolor}40`,
    '& .MuiChip-icon': {
      color: `${chipcolor} !important`,
      fontSize: '0.85rem',
    },
  })
);

const CompactDot = styled(Box)<{ dotColor: string }>(({ dotColor }) => ({
  display: 'inline-flex',
  alignItems: 'center',
  gap: 4,
  cursor: 'default',
  '& .dot': {
    width: 8,
    height: 8,
    borderRadius: '50%',
    backgroundColor: dotColor,
    flexShrink: 0,
  },
}));

// ─── Component ────────────────────────────────────────────────────────────────

export const FreshnessIndicator: React.FC<FreshnessIndicatorProps> = ({
  lastSeen,
  size = 'full',
  className,
}) => {
  const freshness = calculateFreshness(lastSeen);
  const isWarning = freshness.tier === 'stale' || freshness.tier === 'expired';

  const tooltipContent = (
    <Box>
      <Box sx={{ fontWeight: 600, mb: 0.5 }}>
        {freshness.tier === 'expired' && freshness.daysAgo === Infinity
          ? 'Never observed'
          : freshness.label}
      </Box>
      {freshness.warningMessage && (
        <Box sx={{ fontSize: '0.75rem', opacity: 0.85, maxWidth: 220 }}>
          {freshness.warningMessage}
        </Box>
      )}
    </Box>
  );

  if (size === 'compact') {
    return (
      <Tooltip title={tooltipContent} arrow placement="top">
        <CompactDot dotColor={freshness.color} className={className}>
          <span className="dot" />
          {isWarning && (
            <WarningAmberIcon
              sx={{ fontSize: '0.85rem', color: freshness.color, opacity: 0.9 }}
            />
          )}
        </CompactDot>
      </Tooltip>
    );
  }

  // Full size
  const icon = isWarning ? (
    <WarningAmberIcon />
  ) : (
    <AccessTimeIcon />
  );

  const label =
    freshness.daysAgo === Infinity ? 'Never seen' : freshness.label;

  return (
    <Tooltip title={freshness.warningMessage || ''} arrow placement="top" disableHoverListener={!freshness.warningMessage}>
      <FreshnessChip
        icon={icon}
        label={label}
        size="small"
        tier={freshness.tier}
        chipcolor={freshness.color}
        className={className}
      />
    </Tooltip>
  );
};

export default FreshnessIndicator;
