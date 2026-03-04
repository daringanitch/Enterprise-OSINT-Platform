/**
 * CommandPalette — ⌘K
 *
 * Keyboard-first navigation and action launcher for the OSINT Platform.
 *
 * Capabilities:
 *  - Navigate to any page instantly
 *  - Jump to recent / all investigations
 *  - IOC auto-detection: paste an IP / domain / email / hash to trigger enrichment
 *  - Admin actions: new investigation, generate report, clear cache
 *  - Fuzzy search across all items (case-insensitive substring match)
 *  - Full keyboard nav: ↑↓ to move, Enter to execute, Esc to close
 *
 * Open with:  ⌘K  (Mac) /  Ctrl+K  (Windows/Linux)
 *             or  useCommandPalette().open()
 */

import React, {
  useState,
  useEffect,
  useRef,
  useCallback,
  useMemo,
} from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Dialog,
  Box,
  InputBase,
  Typography,
  Divider,
  styled,
  Chip,
} from '@mui/material';
import SearchIcon from '@mui/icons-material/Search';
import DashboardIcon from '@mui/icons-material/Dashboard';
import FolderOpenIcon from '@mui/icons-material/FolderOpen';
import AddCircleOutlineIcon from '@mui/icons-material/AddCircleOutline';
import AssessmentIcon from '@mui/icons-material/Assessment';
import SecurityIcon from '@mui/icons-material/Security';
import BugReportIcon from '@mui/icons-material/BugReport';
import AccountTreeIcon from '@mui/icons-material/AccountTree';
import PolicyIcon from '@mui/icons-material/Policy';
import GroupIcon from '@mui/icons-material/Group';
import TuneIcon from '@mui/icons-material/Tune';
import MonitorIcon from '@mui/icons-material/Monitor';
import FlashOnIcon from '@mui/icons-material/FlashOn';
import RouterIcon from '@mui/icons-material/Router';
import LanguageIcon from '@mui/icons-material/Language';
import AlternateEmailIcon from '@mui/icons-material/AlternateEmail';
import FingerprintIcon from '@mui/icons-material/Fingerprint';
import KeyboardReturnIcon from '@mui/icons-material/KeyboardReturn';
import { cyberColors, designTokens } from '../../utils/theme';

// ─── IOC detection ────────────────────────────────────────────────────────────

const IOC_PATTERNS: { pattern: RegExp; type: string; icon: React.ElementType; label: string }[] = [
  {
    pattern: /^(\d{1,3}\.){3}\d{1,3}(\/\d{1,2})?$/,
    type: 'ip_address',
    icon: RouterIcon,
    label: 'IP Address',
  },
  {
    pattern: /^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$/,
    type: 'domain',
    icon: LanguageIcon,
    label: 'Domain',
  },
  {
    pattern: /^[^\s@]+@[^\s@]+\.[^\s@]+$/,
    type: 'email',
    icon: AlternateEmailIcon,
    label: 'Email',
  },
  {
    pattern: /^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$/,
    type: 'hash',
    icon: FingerprintIcon,
    label: 'Hash (MD5/SHA1/SHA256)',
  },
  {
    pattern: /^https?:\/\/.+/,
    type: 'url',
    icon: LanguageIcon,
    label: 'URL',
  },
];

function detectIOC(query: string): { type: string; icon: React.ElementType; label: string } | null {
  const trimmed = query.trim();
  for (const { pattern, type, icon, label } of IOC_PATTERNS) {
    if (pattern.test(trimmed)) return { type, icon, label };
  }
  return null;
}

// ─── Static command registry ──────────────────────────────────────────────────

interface CommandItem {
  id: string;
  type: 'nav' | 'action' | 'investigation' | 'ioc';
  icon: React.ElementType;
  label: string;
  description?: string;
  shortcut?: string;
  group: string;
  action: () => void;
  keywords?: string[];
}

// ─── Styled components ────────────────────────────────────────────────────────

const PaletteDialog = styled(Dialog)({
  '& .MuiDialog-paper': {
    backgroundColor: 'transparent',
    boxShadow: 'none',
    overflow: 'visible',
    margin: '15vh auto 0',
    width: '100%',
    maxWidth: 640,
    verticalAlign: 'top',
  },
  '& .MuiBackdrop-root': {
    backgroundColor: 'rgba(0,0,0,0.75)',
    backdropFilter: 'blur(4px)',
  },
});

const PaletteContainer = styled(Box)({
  backgroundColor: '#0D1117',
  border: `1px solid ${cyberColors.dark.steel}`,
  borderRadius: 12,
  overflow: 'hidden',
  boxShadow: `0 24px 80px rgba(0,0,0,0.6), 0 0 0 1px ${cyberColors.neon.cyan}15, inset 0 1px 0 rgba(255,255,255,0.04)`,
});

const SearchRow = styled(Box)({
  display: 'flex',
  alignItems: 'center',
  gap: 12,
  padding: '14px 18px',
  borderBottom: `1px solid ${cyberColors.dark.steel}`,
});

const StyledInput = styled(InputBase)({
  flex: 1,
  '& input': {
    fontFamily: designTokens.typography.fontFamily.mono,
    fontSize: '1rem',
    color: cyberColors.text.primary,
    padding: 0,
    '&::placeholder': {
      color: cyberColors.text.muted,
      opacity: 1,
    },
  },
});

const ResultsList = styled(Box)({
  maxHeight: 420,
  overflowY: 'auto',
  scrollbarWidth: 'thin',
  scrollbarColor: `${cyberColors.dark.steel} transparent`,
  '&::-webkit-scrollbar': { width: 4 },
  '&::-webkit-scrollbar-thumb': { backgroundColor: cyberColors.dark.steel, borderRadius: 2 },
});

const GroupLabel = styled(Typography)({
  fontSize: '0.65rem',
  fontWeight: 700,
  letterSpacing: '0.1em',
  textTransform: 'uppercase',
  color: cyberColors.text.muted,
  padding: '10px 18px 4px',
});

const ResultItem = styled(Box, {
  shouldForwardProp: (p) => p !== 'active',
})<{ active?: boolean }>(({ active }) => ({
  display: 'flex',
  alignItems: 'center',
  gap: 12,
  padding: '10px 18px',
  cursor: 'pointer',
  backgroundColor: active ? `${cyberColors.neon.cyan}10` : 'transparent',
  borderLeft: `2px solid ${active ? cyberColors.neon.cyan : 'transparent'}`,
  transition: 'all 0.1s ease',
  '&:hover': {
    backgroundColor: `${cyberColors.neon.cyan}08`,
    borderLeftColor: `${cyberColors.neon.cyan}60`,
  },
}));

const IconBox = styled(Box)<{ ioctype?: string }>(({ ioctype }) => ({
  display: 'flex',
  alignItems: 'center',
  justifyContent: 'center',
  width: 32,
  height: 32,
  borderRadius: 8,
  flexShrink: 0,
  backgroundColor: ioctype
    ? `${cyberColors.neon.orange}15`
    : `${cyberColors.neon.cyan}12`,
  color: ioctype ? cyberColors.neon.orange : cyberColors.neon.cyan,
}));

const ShortcutBadge = styled(Box)({
  display: 'flex',
  alignItems: 'center',
  gap: 4,
  marginLeft: 'auto',
  flexShrink: 0,
});

const KbdChip = styled('kbd')({
  display: 'inline-flex',
  alignItems: 'center',
  padding: '2px 6px',
  fontSize: '0.65rem',
  fontFamily: designTokens.typography.fontFamily.mono,
  color: cyberColors.text.muted,
  backgroundColor: `${cyberColors.dark.steel}30`,
  border: `1px solid ${cyberColors.dark.steel}`,
  borderRadius: 4,
  minWidth: 20,
  justifyContent: 'center',
});

const Footer = styled(Box)({
  display: 'flex',
  alignItems: 'center',
  gap: 16,
  padding: '8px 18px',
  borderTop: `1px solid ${cyberColors.dark.steel}`,
  backgroundColor: `${cyberColors.dark.steel}08`,
});

const FooterHint = styled(Typography)({
  fontSize: '0.65rem',
  color: cyberColors.text.muted,
  display: 'flex',
  alignItems: 'center',
  gap: 4,
});

// ─── Main component ───────────────────────────────────────────────────────────

export interface CommandPaletteProps {
  open: boolean;
  onClose: () => void;
  initialQuery?: string;
  /** Recent investigation stubs (id + target + status) */
  recentInvestigations?: Array<{ id: string; target: string; status: string }>;
}

export const CommandPalette: React.FC<CommandPaletteProps> = ({
  open,
  onClose,
  initialQuery = '',
  recentInvestigations = [],
}) => {
  const navigate = useNavigate();
  const [query, setQuery] = useState(initialQuery);
  const [activeIndex, setActiveIndex] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);
  const listRef = useRef<HTMLDivElement>(null);

  // Sync initial query
  useEffect(() => {
    if (open) {
      setQuery(initialQuery);
      setActiveIndex(0);
      setTimeout(() => inputRef.current?.focus(), 50);
    }
  }, [open, initialQuery]);

  const go = useCallback(
    (path: string) => {
      navigate(path);
      onClose();
    },
    [navigate, onClose],
  );

  // ── Static commands ────────────────────────────────────────────────────────
  const staticCommands: CommandItem[] = useMemo(
    () => [
      // Navigation
      {
        id: 'nav-dashboard',
        type: 'nav',
        icon: DashboardIcon,
        label: 'Dashboard',
        description: 'Overview and metrics',
        group: 'Navigate',
        shortcut: 'G D',
        action: () => go('/dashboard'),
        keywords: ['home', 'overview', 'metrics'],
      },
      {
        id: 'nav-investigations',
        type: 'nav',
        icon: FolderOpenIcon,
        label: 'All Investigations',
        group: 'Navigate',
        shortcut: 'G I',
        action: () => go('/investigations'),
        keywords: ['cases', 'targets'],
      },
      {
        id: 'nav-active',
        type: 'nav',
        icon: FlashOnIcon,
        label: 'Active Investigations',
        group: 'Navigate',
        action: () => go('/investigations/active'),
        keywords: ['running', 'live'],
      },
      {
        id: 'nav-reports',
        type: 'nav',
        icon: AssessmentIcon,
        label: 'Reports',
        group: 'Navigate',
        action: () => go('/reports'),
        keywords: ['export', 'pdf'],
      },
      {
        id: 'nav-threat-intel',
        type: 'nav',
        icon: SecurityIcon,
        label: 'Threat Intelligence',
        group: 'Navigate',
        action: () => go('/threat-intelligence'),
        keywords: ['ioc', 'feed', 'threat'],
      },
      {
        id: 'nav-compliance',
        type: 'nav',
        icon: PolicyIcon,
        label: 'Compliance',
        group: 'Navigate',
        action: () => go('/compliance'),
        keywords: ['audit', 'framework', 'gdpr', 'sox'],
      },
      {
        id: 'nav-team',
        type: 'nav',
        icon: GroupIcon,
        label: 'Team',
        group: 'Navigate',
        action: () => go('/team'),
        keywords: ['analysts', 'users', 'roles'],
      },
      {
        id: 'nav-monitoring',
        type: 'nav',
        icon: MonitorIcon,
        label: 'Monitoring',
        group: 'Navigate',
        action: () => go('/monitoring'),
        keywords: ['health', 'status', 'alerts'],
      },
      {
        id: 'nav-data-sources',
        type: 'nav',
        icon: TuneIcon,
        label: 'Data Sources',
        group: 'Navigate',
        action: () => go('/data-sources'),
        keywords: ['mcp', 'integrations', 'connectors'],
      },
      {
        id: 'nav-settings',
        type: 'nav',
        icon: TuneIcon,
        label: 'Settings',
        group: 'Navigate',
        action: () => go('/settings'),
        keywords: ['config', 'preferences'],
      },
      // Actions
      {
        id: 'action-new-investigation',
        type: 'action',
        icon: AddCircleOutlineIcon,
        label: 'New Investigation',
        description: 'Start a new OSINT investigation',
        shortcut: 'N',
        group: 'Actions',
        action: () => go('/investigations/new'),
        keywords: ['create', 'add', 'start', 'new'],
      },
      {
        id: 'action-graph',
        type: 'action',
        icon: AccountTreeIcon,
        label: 'Open Graph Intelligence',
        description: 'Launch the entity relationship graph',
        group: 'Actions',
        action: () => go('/investigations'),
        keywords: ['graph', 'neo4j', 'entities', 'relationships'],
      },
      {
        id: 'action-credential-intel',
        type: 'action',
        icon: BugReportIcon,
        label: 'Credential Intelligence',
        description: 'Search for leaked credentials',
        group: 'Actions',
        action: () => go('/credential-intelligence'),
        keywords: ['credential', 'breach', 'leak', 'password'],
      },
    ],
    [go],
  );

  // ── Recent investigations ──────────────────────────────────────────────────
  const recentCommands: CommandItem[] = useMemo(
    () =>
      recentInvestigations.slice(0, 5).map((inv) => ({
        id: `inv-${inv.id}`,
        type: 'investigation' as const,
        icon: FolderOpenIcon,
        label: inv.target,
        description: `Investigation · ${inv.status}`,
        group: 'Recent Investigations',
        action: () => go(`/investigations/${inv.id}`),
        keywords: [inv.target, inv.status],
      })),
    [recentInvestigations, go],
  );

  // ── IOC detection ──────────────────────────────────────────────────────────
  const ioc = useMemo(() => detectIOC(query), [query]);

  const iocCommands: CommandItem[] = useMemo(() => {
    if (!ioc) return [];
    const IocIcon = ioc.icon;
    return [
      {
        id: 'ioc-investigate',
        type: 'ioc' as const,
        icon: IocIcon,
        label: `Investigate "${query.trim()}"`,
        description: `Detected: ${ioc.label} — fan-out enrichment across all sources`,
        group: 'IOC Enrichment',
        action: () => {
          go(`/investigations/new?ioc=${encodeURIComponent(query.trim())}&type=${ioc.type}`);
        },
        keywords: [],
      },
      {
        id: 'ioc-search',
        type: 'ioc' as const,
        icon: SearchIcon,
        label: `Search investigations for "${query.trim()}"`,
        description: 'Find any investigation containing this indicator',
        group: 'IOC Enrichment',
        action: () => {
          go(`/investigations?q=${encodeURIComponent(query.trim())}`);
        },
        keywords: [],
      },
    ];
  }, [ioc, query, go]);

  // ── Filtered result set ────────────────────────────────────────────────────
  const results = useMemo(() => {
    const q = query.trim().toLowerCase();

    // If IOC detected, prioritise ioc commands, then others
    if (ioc) {
      return [...iocCommands, ...staticCommands.filter((c) => {
        const text = [c.label, c.description || '', ...(c.keywords || [])].join(' ').toLowerCase();
        return !q || text.includes(q);
      })];
    }

    // No query: show recent investigations + top nav actions
    if (!q) {
      return [
        ...recentCommands,
        ...staticCommands.slice(0, 6),
      ];
    }

    const all = [...staticCommands, ...recentCommands];
    return all.filter((c) => {
      const text = [c.label, c.description || '', ...(c.keywords || [])].join(' ').toLowerCase();
      return text.includes(q);
    });
  }, [query, ioc, iocCommands, staticCommands, recentCommands]);

  // Keep activeIndex in bounds
  useEffect(() => {
    setActiveIndex((prev) => Math.min(prev, Math.max(0, results.length - 1)));
  }, [results]);

  // Scroll active item into view
  useEffect(() => {
    if (!listRef.current) return;
    const active = listRef.current.querySelector('[data-active="true"]');
    active?.scrollIntoView({ block: 'nearest' });
  }, [activeIndex]);

  // ── Keyboard navigation ────────────────────────────────────────────────────
  const handleKeyDown = useCallback(
    (e: React.KeyboardEvent) => {
      if (e.key === 'ArrowDown') {
        e.preventDefault();
        setActiveIndex((i) => (i + 1) % Math.max(1, results.length));
      } else if (e.key === 'ArrowUp') {
        e.preventDefault();
        setActiveIndex((i) => (i - 1 + results.length) % Math.max(1, results.length));
      } else if (e.key === 'Enter') {
        e.preventDefault();
        results[activeIndex]?.action();
      } else if (e.key === 'Escape') {
        onClose();
      }
    },
    [results, activeIndex, onClose],
  );

  // ── Group results by group label ───────────────────────────────────────────
  const grouped = useMemo(() => {
    const groups: Map<string, CommandItem[]> = new Map();
    for (const item of results) {
      if (!groups.has(item.group)) groups.set(item.group, []);
      groups.get(item.group)!.push(item);
    }
    return groups;
  }, [results]);

  // Flat index tracker per-group for activeIndex
  let flatIdx = 0;

  return (
    <PaletteDialog
      open={open}
      onClose={onClose}
      fullWidth
      TransitionProps={{ timeout: 150 }}
    >
      <PaletteContainer>
        {/* Search input */}
        <SearchRow>
          <SearchIcon sx={{ color: cyberColors.neon.cyan, fontSize: '1.1rem', flexShrink: 0 }} />
          <StyledInput
            inputRef={inputRef}
            value={query}
            onChange={(e) => { setQuery(e.target.value); setActiveIndex(0); }}
            onKeyDown={handleKeyDown}
            placeholder="Search pages, investigations, or paste an IOC…"
            fullWidth
            autoFocus
          />
          {query && (
            <KbdChip onClick={() => setQuery('')} style={{ cursor: 'pointer' }}>✕</KbdChip>
          )}
          {ioc && (
            <Chip
              size="small"
              label={ioc.label}
              sx={{
                height: 20,
                fontSize: '0.65rem',
                backgroundColor: `${cyberColors.neon.orange}18`,
                color: cyberColors.neon.orange,
                border: `1px solid ${cyberColors.neon.orange}35`,
                flexShrink: 0,
              }}
            />
          )}
        </SearchRow>

        {/* Results */}
        <ResultsList ref={listRef}>
          {results.length === 0 ? (
            <Box sx={{ p: '24px 18px', textAlign: 'center' }}>
              <Typography sx={{ color: cyberColors.text.muted, fontSize: '0.88rem' }}>
                No results for "{query}"
              </Typography>
              <Typography sx={{ color: cyberColors.text.muted, fontSize: '0.75rem', mt: 0.5 }}>
                Try an IP address, domain, email, or hash to trigger enrichment
              </Typography>
            </Box>
          ) : (
            Array.from(grouped.entries()).map(([group, items]) => (
              <Box key={group}>
                <GroupLabel>{group}</GroupLabel>
                {items.map((item) => {
                  const ItemIcon = item.icon;
                  const myIdx = flatIdx++;
                  const isActive = myIdx === activeIndex;
                  return (
                    <ResultItem
                      key={item.id}
                      active={isActive}
                      data-active={isActive}
                      onClick={() => item.action()}
                      onMouseEnter={() => setActiveIndex(myIdx)}
                    >
                      <IconBox ioctype={item.type === 'ioc' ? 'true' : undefined}>
                        <ItemIcon sx={{ fontSize: '1rem' }} />
                      </IconBox>
                      <Box sx={{ flex: 1, minWidth: 0 }}>
                        <Typography
                          sx={{
                            fontSize: '0.875rem',
                            color: item.type === 'ioc' ? cyberColors.neon.orange : cyberColors.text.primary,
                            fontWeight: item.type === 'ioc' ? 600 : 400,
                            overflow: 'hidden',
                            textOverflow: 'ellipsis',
                            whiteSpace: 'nowrap',
                          }}
                        >
                          {item.label}
                        </Typography>
                        {item.description && (
                          <Typography sx={{ fontSize: '0.72rem', color: cyberColors.text.muted }}>
                            {item.description}
                          </Typography>
                        )}
                      </Box>
                      {item.shortcut && (
                        <ShortcutBadge>
                          {item.shortcut.split(' ').map((k) => (
                            <KbdChip key={k}>{k}</KbdChip>
                          ))}
                        </ShortcutBadge>
                      )}
                      {isActive && !item.shortcut && (
                        <ShortcutBadge sx={{ opacity: 0.5 }}>
                          <KbdChip><KeyboardReturnIcon sx={{ fontSize: '0.65rem' }} /></KbdChip>
                        </ShortcutBadge>
                      )}
                    </ResultItem>
                  );
                })}
                <Divider sx={{ borderColor: `${cyberColors.dark.steel}40`, mx: 0 }} />
              </Box>
            ))
          )}
        </ResultsList>

        {/* Footer hints */}
        <Footer>
          <FooterHint>
            <KbdChip>↑</KbdChip><KbdChip>↓</KbdChip>
            navigate
          </FooterHint>
          <FooterHint>
            <KbdChip>↵</KbdChip>
            open
          </FooterHint>
          <FooterHint>
            <KbdChip>Esc</KbdChip>
            close
          </FooterHint>
          <Box sx={{ flex: 1 }} />
          <FooterHint sx={{ color: `${cyberColors.neon.cyan}60` }}>
            <KbdChip style={{ color: cyberColors.neon.cyan, borderColor: `${cyberColors.neon.cyan}30` }}>
              ⌘K
            </KbdChip>
            toggle
          </FooterHint>
        </Footer>
      </PaletteContainer>
    </PaletteDialog>
  );
};

export default CommandPalette;
