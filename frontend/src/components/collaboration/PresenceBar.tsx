/**
 * PresenceBar
 *
 * Shows who else is currently viewing the same investigation.
 * Renders avatar circles with the analyst's initials and their assigned color,
 * plus a live connection indicator dot.
 *
 * Usage:
 *   <PresenceBar analysts={analysts} connected={connected} />
 */

import React from 'react';
import {
  Box,
  Tooltip,
  Typography,
  styled,
  Chip,
} from '@mui/material';
import WifiIcon from '@mui/icons-material/Wifi';
import WifiOffIcon from '@mui/icons-material/WifiOff';
import { cyberColors, designTokens } from '../../utils/theme';
import { AnalystPresence } from '../../hooks/useCollaboration';

// ─── Styled ───────────────────────────────────────────────────────────────────

const Bar = styled(Box)({
  display: 'flex',
  alignItems: 'center',
  gap: 8,
});

const AvatarStack = styled(Box)({
  display: 'flex',
  alignItems: 'center',
  '& > *:not(:first-of-type)': {
    marginLeft: -8,
  },
});

const Avatar = styled(Box)<{ bgcolor: string; size?: number }>(({ bgcolor, size = 32 }) => ({
  width: size,
  height: size,
  borderRadius: '50%',
  backgroundColor: `${bgcolor}20`,
  border: `2px solid ${bgcolor}`,
  display: 'flex',
  alignItems: 'center',
  justifyContent: 'center',
  fontSize: size > 28 ? '0.72rem' : '0.62rem',
  fontWeight: 700,
  fontFamily: designTokens.typography.fontFamily.mono,
  color: bgcolor,
  flexShrink: 0,
  zIndex: 1,
  boxShadow: `0 0 0 1px ${cyberColors.dark.charcoal}`,
  transition: 'transform 0.15s ease',
  '&:hover': { transform: 'scale(1.15)', zIndex: 10 },
}));

const ConnectionBadge = styled(Chip)<{ isconnected: string }>(({ isconnected }) => ({
  height: 22,
  fontSize: '0.65rem',
  fontWeight: 700,
  borderRadius: 11,
  backgroundColor: isconnected === 'true'
    ? `${cyberColors.neon.green}15`
    : `${cyberColors.neon.red}15`,
  color: isconnected === 'true' ? cyberColors.neon.green : cyberColors.neon.red,
  border: `1px solid ${isconnected === 'true' ? cyberColors.neon.green : cyberColors.neon.red}35`,
  '& .MuiChip-icon': {
    color: 'inherit !important',
    fontSize: '0.75rem',
  },
}));

// ─── Types ────────────────────────────────────────────────────────────────────

export interface PresenceBarProps {
  analysts: AnalystPresence[];
  connected: boolean;
  /** Max avatars to show before "+N more" overflow */
  maxVisible?: number;
  /** Show/hide connection status badge */
  showConnectionStatus?: boolean;
  className?: string;
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

function initials(name: string): string {
  return name
    .split(/\s+/)
    .slice(0, 2)
    .map((n) => n[0]?.toUpperCase() || '')
    .join('');
}

function timeAgo(isoDate: string): string {
  const secs = Math.floor((Date.now() - new Date(isoDate).getTime()) / 1000);
  if (secs < 60) return 'just now';
  if (secs < 3600) return `${Math.floor(secs / 60)}m ago`;
  return `${Math.floor(secs / 3600)}h ago`;
}

// ─── Component ────────────────────────────────────────────────────────────────

export const PresenceBar: React.FC<PresenceBarProps> = ({
  analysts,
  connected,
  maxVisible = 5,
  showConnectionStatus = true,
  className,
}) => {
  const visible = analysts.slice(0, maxVisible);
  const overflow = analysts.length - maxVisible;

  return (
    <Bar className={className}>
      {/* Connection status */}
      {showConnectionStatus && (
        <ConnectionBadge
          isconnected={connected.toString()}
          icon={connected ? <WifiIcon /> : <WifiOffIcon />}
          label={connected ? 'Live' : 'Offline'}
          size="small"
        />
      )}

      {/* Analyst avatars */}
      {analysts.length > 0 && (
        <AvatarStack>
          {visible.map((a) => (
            <Tooltip
              key={a.analyst_id}
              title={
                <Box>
                  <Typography sx={{ fontSize: '0.8rem', fontWeight: 600 }}>{a.analyst_name}</Typography>
                  <Typography sx={{ fontSize: '0.7rem', color: cyberColors.text.muted }}>
                    Active {timeAgo(a.last_seen)}
                  </Typography>
                </Box>
              }
              arrow
              placement="bottom"
            >
              <Avatar bgcolor={a.color}>
                {initials(a.analyst_name)}
              </Avatar>
            </Tooltip>
          ))}
          {overflow > 0 && (
            <Tooltip
              title={`${overflow} more analyst${overflow > 1 ? 's' : ''} viewing`}
              arrow
              placement="bottom"
            >
              <Avatar bgcolor={cyberColors.text.muted}>
                +{overflow}
              </Avatar>
            </Tooltip>
          )}
        </AvatarStack>
      )}

      {/* "X analysts viewing" label */}
      {analysts.length > 0 && (
        <Typography sx={{ fontSize: '0.72rem', color: cyberColors.text.muted, whiteSpace: 'nowrap' }}>
          {analysts.length === 1
            ? `${analysts[0].analyst_name} is also viewing`
            : `${analysts.length} analysts viewing`}
        </Typography>
      )}
    </Bar>
  );
};

export default PresenceBar;
