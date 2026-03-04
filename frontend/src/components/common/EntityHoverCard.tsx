/**
 * EntityHoverCard
 *
 * A rich Popover that shows aggregated threat intelligence for an entity
 * (IP, domain, email, hash). Fetches from GET /api/entities/lookup on mount.
 *
 * Used by EntityChip — not intended for direct placement in pages.
 *
 * Usage:
 *   <EntityHoverCard
 *     value="1.2.3.4"
 *     type="ip_address"
 *     anchorEl={anchorRef.current}   // null to hide
 *     onClose={() => setOpen(false)}
 *   />
 */

import React, { useEffect, useState, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Popover,
  Box,
  Typography,
  Chip,
  LinearProgress,
  Skeleton,
  Divider,
  styled,
} from '@mui/material';
import OpenInNewIcon from '@mui/icons-material/OpenInNew';
import ErrorOutlineIcon from '@mui/icons-material/ErrorOutline';
import { cyberColors, designTokens, glassmorphism } from '../../utils/theme';
import { FreshnessIndicator } from './FreshnessIndicator';

// ─── Types ────────────────────────────────────────────────────────────────────

interface EntityLookupResult {
  found: boolean;
  value?: string;
  type?: string;
  confidence?: number;
  first_seen?: string | null;
  last_seen?: string | null;
  days_since_seen?: number | null;
  sources?: string[];
  tags?: string[];
  investigations?: Array<{
    id: string;
    target: string;
    status: string;
    risk_level?: string | null;
  }>;
  investigation_count?: number;
}

export interface EntityHoverCardProps {
  value: string;
  type?: string;
  /** DOM element to anchor the popover to. Pass null to hide. */
  anchorEl: Element | null;
  onClose: () => void;
}

// ─── Styled components ────────────────────────────────────────────────────────

const CardBox = styled(Box)({
  ...glassmorphism.card,
  padding: 16,
  minWidth: 280,
  maxWidth: 340,
  borderRadius: designTokens.borderRadius.md,
});

const Section = styled(Box)({
  marginBottom: 10,
});

const Label = styled(Typography)({
  fontSize: '0.65rem',
  fontWeight: 700,
  textTransform: 'uppercase',
  letterSpacing: '0.08em',
  color: cyberColors.text.muted,
  marginBottom: 4,
});

const InvRow = styled(Box)({
  display: 'flex',
  alignItems: 'center',
  justifyContent: 'space-between',
  padding: '4px 8px',
  borderRadius: 4,
  cursor: 'pointer',
  '&:hover': {
    backgroundColor: `${cyberColors.neon.cyan}10`,
  },
});

const RISK_COLORS: Record<string, string> = {
  critical: '#EF4444',
  high: '#F59E0B',
  medium: '#22D3EE',
  low: '#22C55E',
};

// ─── API fetch ────────────────────────────────────────────────────────────────

const API_BASE = process.env.REACT_APP_API_URL || 'http://localhost:5001';

async function fetchEntityLookup(value: string, type?: string): Promise<EntityLookupResult> {
  const token = localStorage.getItem('auth_token');
  const params = new URLSearchParams({ value });
  if (type) params.set('type', type);

  const res = await fetch(`${API_BASE}/api/entities/lookup?${params.toString()}`, {
    headers: {
      'Authorization': token ? `Bearer ${token}` : '',
      'Content-Type': 'application/json',
    },
  });

  if (!res.ok) {
    throw new Error(`HTTP ${res.status}`);
  }
  return res.json();
}

// ─── Component ────────────────────────────────────────────────────────────────

export const EntityHoverCard: React.FC<EntityHoverCardProps> = ({
  value,
  type,
  anchorEl,
  onClose,
}) => {
  const navigate = useNavigate();
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<EntityLookupResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  const open = Boolean(anchorEl);

  const fetchData = useCallback(async () => {
    if (!value) return;
    setLoading(true);
    setError(null);
    try {
      const data = await fetchEntityLookup(value, type);
      setResult(data);
    } catch (err) {
      setError('Could not load entity data');
      setResult({ found: false });
    } finally {
      setLoading(false);
    }
  }, [value, type]);

  useEffect(() => {
    if (open && !result) {
      fetchData();
    }
    // Reset when the value changes
    if (!open) {
      setResult(null);
      setError(null);
    }
  }, [open, value]); // eslint-disable-line react-hooks/exhaustive-deps

  return (
    <Popover
      open={open}
      anchorEl={anchorEl}
      onClose={onClose}
      anchorOrigin={{ vertical: 'center', horizontal: 'right' }}
      transformOrigin={{ vertical: 'center', horizontal: 'left' }}
      disableRestoreFocus
      sx={{
        pointerEvents: 'none',
        '& .MuiPopover-paper': {
          background: 'transparent',
          boxShadow: 'none',
          overflow: 'visible',
          pointerEvents: 'auto',
        },
      }}
      PaperProps={{ onMouseLeave: onClose }}
    >
      <CardBox>
        {/* Header */}
        <Section>
          <Typography
            sx={{
              fontFamily: designTokens.typography.fontFamily.mono,
              fontSize: '0.85rem',
              fontWeight: 700,
              color: cyberColors.neon.cyan,
              mb: 0.5,
              overflow: 'hidden',
              textOverflow: 'ellipsis',
              whiteSpace: 'nowrap',
            }}
            title={value}
          >
            {value}
          </Typography>
          {type && (
            <Chip
              label={type.replace(/_/g, ' ')}
              size="small"
              sx={{
                height: 18,
                fontSize: '0.62rem',
                fontWeight: 600,
                textTransform: 'uppercase',
                backgroundColor: `${cyberColors.neon.cyan}15`,
                color: cyberColors.neon.cyan,
                border: `1px solid ${cyberColors.neon.cyan}30`,
                '& .MuiChip-label': { px: '5px' },
              }}
            />
          )}
        </Section>

        <Divider sx={{ borderColor: `${cyberColors.dark.steel}80`, mb: 1.5 }} />

        {/* Loading skeleton */}
        {loading && (
          <Box>
            <Skeleton variant="text" width="60%" height={16} sx={{ bgcolor: `${cyberColors.dark.steel}60`, mb: 1 }} />
            <Skeleton variant="text" width="80%" height={16} sx={{ bgcolor: `${cyberColors.dark.steel}60`, mb: 1 }} />
            <Skeleton variant="rectangular" width="100%" height={32} sx={{ bgcolor: `${cyberColors.dark.steel}60`, borderRadius: 1 }} />
          </Box>
        )}

        {/* Error state */}
        {!loading && error && (
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, color: cyberColors.text.muted }}>
            <ErrorOutlineIcon sx={{ fontSize: '1rem' }} />
            <Typography sx={{ fontSize: '0.78rem' }}>Unable to load entity data</Typography>
          </Box>
        )}

        {/* Not found */}
        {!loading && result && !result.found && !error && (
          <Typography sx={{ fontSize: '0.78rem', color: cyberColors.text.muted, fontStyle: 'italic' }}>
            No threat intelligence found for this entity.
          </Typography>
        )}

        {/* Found — entity details */}
        {!loading && result?.found && (
          <>
            {/* Confidence */}
            {result.confidence !== undefined && (
              <Section>
                <Label>Confidence</Label>
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                  <LinearProgress
                    variant="determinate"
                    value={(result.confidence || 0) * 100}
                    sx={{
                      flex: 1,
                      height: 4,
                      borderRadius: 2,
                      backgroundColor: `${cyberColors.neon.cyan}20`,
                      '& .MuiLinearProgress-bar': {
                        background: `linear-gradient(90deg, ${cyberColors.neon.cyan}, ${cyberColors.neon.green})`,
                        borderRadius: 2,
                      },
                    }}
                  />
                  <Typography sx={{ fontSize: '0.72rem', color: cyberColors.text.secondary, minWidth: 28 }}>
                    {Math.round((result.confidence || 0) * 100)}%
                  </Typography>
                </Box>
              </Section>
            )}

            {/* Last seen / freshness */}
            {(result.first_seen || result.last_seen) && (
              <Section>
                <Label>Observed</Label>
                <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <Typography sx={{ fontSize: '0.72rem', color: cyberColors.text.secondary }}>
                    {result.first_seen
                      ? `First: ${new Date(result.first_seen).toLocaleDateString()}`
                      : 'First seen unknown'}
                  </Typography>
                  <FreshnessIndicator lastSeen={result.last_seen} size="compact" />
                </Box>
              </Section>
            )}

            {/* Tags */}
            {result.tags && result.tags.length > 0 && (
              <Section>
                <Label>Tags</Label>
                <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.5 }}>
                  {result.tags.slice(0, 5).map((tag) => (
                    <Chip
                      key={tag}
                      label={tag}
                      size="small"
                      sx={{
                        height: 18,
                        fontSize: '0.62rem',
                        backgroundColor: `${cyberColors.neon.red}15`,
                        color: cyberColors.neon.red,
                        border: `1px solid ${cyberColors.neon.red}30`,
                        '& .MuiChip-label': { px: '5px' },
                      }}
                    />
                  ))}
                  {result.tags.length > 5 && (
                    <Typography sx={{ fontSize: '0.62rem', color: cyberColors.text.muted, alignSelf: 'center' }}>
                      +{result.tags.length - 5} more
                    </Typography>
                  )}
                </Box>
              </Section>
            )}

            {/* Sources */}
            {result.sources && result.sources.length > 0 && (
              <Section>
                <Label>Sources ({result.sources.length})</Label>
                <Typography sx={{ fontSize: '0.72rem', color: cyberColors.text.secondary }}>
                  {result.sources.slice(0, 3).join(', ')}
                  {result.sources.length > 3 ? ` +${result.sources.length - 3} more` : ''}
                </Typography>
              </Section>
            )}

            {/* Linked investigations */}
            {result.investigations && result.investigations.length > 0 && (
              <Section sx={{ mb: 0 }}>
                <Label>
                  In {result.investigation_count} Investigation
                  {(result.investigation_count || 0) !== 1 ? 's' : ''}
                </Label>
                {result.investigations.slice(0, 3).map((inv) => {
                  const riskColor = RISK_COLORS[inv.risk_level || ''] || cyberColors.text.muted;
                  return (
                    <InvRow
                      key={inv.id}
                      onClick={(e) => {
                        e.stopPropagation();
                        onClose();
                        navigate(`/investigations/${inv.id}`);
                      }}
                    >
                      <Typography
                        sx={{
                          fontFamily: designTokens.typography.fontFamily.mono,
                          fontSize: '0.72rem',
                          color: cyberColors.neon.cyan,
                          overflow: 'hidden',
                          textOverflow: 'ellipsis',
                          whiteSpace: 'nowrap',
                          flex: 1,
                          mr: 1,
                        }}
                      >
                        {inv.target}
                      </Typography>
                      <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
                        {inv.risk_level && (
                          <Chip
                            label={inv.risk_level.toUpperCase()}
                            size="small"
                            sx={{
                              height: 16,
                              fontSize: '0.58rem',
                              fontWeight: 700,
                              bgcolor: `${riskColor}18`,
                              color: riskColor,
                              border: `1px solid ${riskColor}35`,
                              '& .MuiChip-label': { px: '4px' },
                            }}
                          />
                        )}
                        <OpenInNewIcon sx={{ fontSize: '0.75rem', color: cyberColors.text.muted }} />
                      </Box>
                    </InvRow>
                  );
                })}
                {(result.investigation_count || 0) > 3 && (
                  <Typography sx={{ fontSize: '0.68rem', color: cyberColors.text.muted, mt: 0.5, pl: 1 }}>
                    +{(result.investigation_count || 0) - 3} more investigations
                  </Typography>
                )}
              </Section>
            )}
          </>
        )}
      </CardBox>
    </Popover>
  );
};

export default EntityHoverCard;
