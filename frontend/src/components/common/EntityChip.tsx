/**
 * EntityChip
 *
 * Renders an entity value (IP, domain, email, hash, URL) as an inline
 * monospace chip with a type icon. Hovering the chip opens an EntityHoverCard
 * with aggregated threat intelligence for that entity.
 *
 * Usage:
 *   <EntityChip value="1.2.3.4" type="ip_address" />
 *   <EntityChip value="evil.com" />   // type auto-detected
 *   <EntityChip value="a@b.com" type="email" clickable={false} />
 */

import React, { useRef, useState, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import { Chip, styled, Tooltip } from '@mui/material';
import RouterIcon from '@mui/icons-material/Router';
import LanguageIcon from '@mui/icons-material/Language';
import EmailIcon from '@mui/icons-material/Email';
import FingerprintIcon from '@mui/icons-material/Fingerprint';
import LinkIcon from '@mui/icons-material/Link';
import DevicesIcon from '@mui/icons-material/Devices';
import HelpOutlineIcon from '@mui/icons-material/HelpOutline';
import { cyberColors, designTokens } from '../../utils/theme';
import { EntityType } from '../../types';
import { EntityHoverCard } from './EntityHoverCard';

// ─── Types ────────────────────────────────────────────────────────────────────

export interface EntityChipProps {
  value: string;
  /** Entity type — auto-detected from value if not provided */
  type?: EntityType | string;
  /** Whether clicking navigates to the entity's first matching investigation */
  clickable?: boolean;
  /** Optional className */
  className?: string;
}

// ─── Type icon map ────────────────────────────────────────────────────────────

const TYPE_ICONS: Record<string, React.ReactElement> = {
  ip_address: <RouterIcon sx={{ fontSize: '0.8rem' }} />,
  domain:     <LanguageIcon sx={{ fontSize: '0.8rem' }} />,
  email:      <EmailIcon sx={{ fontSize: '0.8rem' }} />,
  hash:       <FingerprintIcon sx={{ fontSize: '0.8rem' }} />,
  url:        <LinkIcon sx={{ fontSize: '0.8rem' }} />,
  technology: <DevicesIcon sx={{ fontSize: '0.8rem' }} />,
};

const getTypeIcon = (type: string | undefined): React.ReactElement =>
  TYPE_ICONS[type || ''] ?? <HelpOutlineIcon sx={{ fontSize: '0.8rem' }} />;

const TYPE_COLORS: Record<string, string> = {
  ip_address: '#38BDF8',
  domain:     '#22D3EE',
  email:      '#A78BFA',
  hash:       '#F59E0B',
  url:        '#22C55E',
  technology: '#8B5CF6',
};

const getTypeColor = (type: string | undefined): string =>
  TYPE_COLORS[type || ''] ?? cyberColors.text.secondary;

// ─── Auto type detection ──────────────────────────────────────────────────────

function detectType(value: string): string {
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(value)) return 'ip_address';
  if (/^[0-9a-fA-F:]+$/.test(value) && value.includes(':')) return 'ip_address';
  if (/@/.test(value) && /\.[a-z]{2,}$/.test(value.split('@')[1] || '')) return 'email';
  if (/^[0-9a-fA-F]{32}$/.test(value)) return 'hash';
  if (/^[0-9a-fA-F]{40}$/.test(value)) return 'hash';
  if (/^[0-9a-fA-F]{64}$/.test(value)) return 'hash';
  if (/^https?:\/\//.test(value)) return 'url';
  if (/\.[a-z]{2,}/.test(value)) return 'domain';
  return 'unknown';
}

// ─── Styled chip ──────────────────────────────────────────────────────────────

const StyledEntityChip = styled(Chip)<{ chipcolor: string; isclickable?: string }>(
  ({ chipcolor, isclickable }) => ({
    height: 22,
    fontFamily: designTokens.typography.fontFamily.mono,
    fontSize: '0.72rem',
    fontWeight: 600,
    backgroundColor: `${chipcolor}15`,
    color: chipcolor,
    border: `1px solid ${chipcolor}35`,
    cursor: isclickable === 'true' ? 'pointer' : 'default',
    maxWidth: 220,
    '& .MuiChip-label': {
      overflow: 'hidden',
      textOverflow: 'ellipsis',
      padding: '0 6px 0 2px',
    },
    '& .MuiChip-icon': {
      color: `${chipcolor} !important`,
      marginLeft: 4,
    },
    '&:hover': {
      backgroundColor: `${chipcolor}22`,
      borderColor: `${chipcolor}60`,
    },
  })
);

// ─── Component ────────────────────────────────────────────────────────────────

export const EntityChip: React.FC<EntityChipProps> = ({
  value,
  type: typeProp,
  clickable = true,
  className,
}) => {
  const navigate = useNavigate();
  const anchorRef = useRef<HTMLDivElement>(null);
  const [hoverOpen, setHoverOpen] = useState(false);
  const hoverTimer = useRef<ReturnType<typeof setTimeout> | null>(null);

  const resolvedType = typeProp || detectType(value);
  const color = getTypeColor(resolvedType);
  const icon = getTypeIcon(resolvedType);

  const handleMouseEnter = useCallback(() => {
    hoverTimer.current = setTimeout(() => setHoverOpen(true), 400);
  }, []);

  const handleMouseLeave = useCallback(() => {
    if (hoverTimer.current) {
      clearTimeout(hoverTimer.current);
      hoverTimer.current = null;
    }
    setHoverOpen(false);
  }, []);

  const handleClick = useCallback((e: React.MouseEvent) => {
    if (!clickable) return;
    e.stopPropagation();
    // EntityHoverCard will expose the investigation ID — for now navigate
    // to the investigations list filtered by this target
    navigate(`/investigations?q=${encodeURIComponent(value)}`);
  }, [clickable, navigate, value]);

  return (
    <>
      <StyledEntityChip
        ref={anchorRef as React.Ref<HTMLDivElement>}
        icon={icon}
        label={value}
        size="small"
        chipcolor={color}
        isclickable={clickable ? 'true' : 'false'}
        onClick={handleClick}
        onMouseEnter={handleMouseEnter}
        onMouseLeave={handleMouseLeave}
        className={className}
        title={`${resolvedType}: ${value}`}
      />
      <EntityHoverCard
        value={value}
        type={resolvedType}
        anchorEl={hoverOpen ? anchorRef.current : null}
        onClose={() => setHoverOpen(false)}
      />
    </>
  );
};

export default EntityChip;
