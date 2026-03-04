/**
 * Investigations List Page
 *
 * Supports filtering by URL path:
 * - /investigations - show all
 * - /investigations/active - show only active/in-progress
 * - /investigations/history - show completed/cancelled
 * - /investigations/saved - show all (placeholder for bookmarked investigations)
 *
 * View modes: List (default) | Kanban — toggled by the toolbar buttons.
 * View preference is persisted in localStorage.
 *
 * Search: SearchBar provides live client-side filtering by query text, status,
 * priority, and risk level. Filters can be saved and re-applied via useSavedSearches.
 * On page mount a Toast notification fires if any saved search has new matches
 * since the last visit (compared via a localStorage timestamp).
 */

import React, { useMemo, useState, useEffect, useCallback } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import {
  Box,
  Typography,
  Button,
  Chip,
  ToggleButtonGroup,
  ToggleButton,
  Tooltip,
  Snackbar,
  Alert,
  styled,
} from '@mui/material';
import { motion } from 'framer-motion';
import AddIcon from '@mui/icons-material/Add';
import ViewListIcon from '@mui/icons-material/ViewList';
import ViewKanbanIcon from '@mui/icons-material/ViewKanban';
import NotificationsActiveIcon from '@mui/icons-material/NotificationsActive';
import { cyberColors, designTokens, glassmorphism } from '../utils/theme';
import { pageVariants } from '../utils/animations';
import { Card } from '../components/common/Card';
import { FreshnessIndicator } from '../components/common/FreshnessIndicator';
import { KanbanBoard } from '../components/investigations/KanbanBoard';
import { SearchBar } from '../components/investigations/SearchBar';
import { useSavedSearches, SearchParams } from '../hooks/useSavedSearches';

// ─── Constants ────────────────────────────────────────────────────────────────

const VIEW_MODE_KEY = 'osint_investigations_view_mode';
const LAST_CHECK_KEY = 'osint_searches_last_check';

// ─── Styled components ────────────────────────────────────────────────────────

const PageContainer = styled(motion.div)({
  padding: 24,
});

const Header = styled(Box)({
  display: 'flex',
  justifyContent: 'space-between',
  alignItems: 'center',
  marginBottom: 16,
});

const HeaderLeft = styled(Box)({
  display: 'flex',
  alignItems: 'center',
  gap: 16,
});

const Title = styled(Typography)({
  fontFamily: designTokens.typography.fontFamily.display,
  fontSize: '1.75rem',
  fontWeight: 700,
  color: cyberColors.text.primary,
});

const NewButton = styled(Button)({
  backgroundColor: cyberColors.neon.cyan,
  color: cyberColors.dark.void,
  fontWeight: 600,
  '&:hover': {
    backgroundColor: cyberColors.neon.electricBlue,
    boxShadow: `0 0 20px ${cyberColors.neon.cyan}60`,
  },
});

const ViewToggle = styled(ToggleButtonGroup)({
  '& .MuiToggleButton-root': {
    border: `1px solid ${cyberColors.dark.steel}`,
    color: cyberColors.text.secondary,
    padding: '6px 10px',
    '&.Mui-selected': {
      backgroundColor: `${cyberColors.neon.cyan}15`,
      color: cyberColors.neon.cyan,
      borderColor: `${cyberColors.neon.cyan}50`,
    },
    '&:hover': {
      backgroundColor: `${cyberColors.neon.cyan}08`,
    },
  },
});

const InvestigationCard = styled(motion.div)({
  ...glassmorphism.card,
  padding: 20,
  borderRadius: designTokens.borderRadius.md,
  marginBottom: 16,
  cursor: 'pointer',
  transition: 'all 0.2s ease',
  '&:hover': {
    borderColor: cyberColors.neon.cyan,
    boxShadow: `0 0 20px ${cyberColors.neon.cyan}20`,
  },
});

const StatusChip = styled(Chip)<{ status: string }>(({ status }) => {
  const colors: Record<string, string> = {
    active: cyberColors.neon.green,
    pending: cyberColors.neon.orange,
    completed: cyberColors.neon.cyan,
    failed: cyberColors.neon.red,
    // Extended statuses
    queued: '#A78BFA',
    planning: '#38BDF8',
    profiling: '#38BDF8',
    collecting: '#22D3EE',
    analyzing: '#F59E0B',
    assessing_risk: '#F59E0B',
    verifying: '#F59E0B',
    generating_report: '#22C55E',
    cancelled: '#484F58',
  };
  const color = colors[status] || cyberColors.text.secondary;
  return {
    backgroundColor: `${color}20`,
    color: color,
    fontWeight: 600,
    fontSize: '0.75rem',
  };
});

// ─── Mock data ────────────────────────────────────────────────────────────────
// In a real integration this comes from the API; replaced by live data in Sprint 2.

const allInvestigations = [
  {
    id: '1',
    target: 'suspicious-domain.com',
    type: 'domain',
    status: 'collecting',
    priority: 'high',
    risk_level: 'high',
    created_at: new Date(Date.now() - 2 * 24 * 60 * 60 * 1000).toISOString(),
    updated_at: new Date(Date.now() - 1 * 60 * 60 * 1000).toISOString(),
    findings_count: 24,
    progress: 60,
  },
  {
    id: '2',
    target: '192.168.1.100',
    type: 'ip_address',
    status: 'completed',
    priority: 'normal',
    risk_level: 'medium',
    created_at: new Date(Date.now() - 5 * 24 * 60 * 60 * 1000).toISOString(),
    updated_at: new Date(Date.now() - 4 * 24 * 60 * 60 * 1000).toISOString(),
    findings_count: 18,
    progress: 100,
  },
  {
    id: '3',
    target: 'threat-actor@example.com',
    type: 'email',
    status: 'pending',
    priority: 'urgent',
    risk_level: 'critical',
    created_at: new Date(Date.now() - 1 * 24 * 60 * 60 * 1000).toISOString(),
    updated_at: new Date(Date.now() - 30 * 60 * 1000).toISOString(),
    findings_count: 0,
    progress: 0,
  },
  {
    id: '4',
    target: 'malware-c2.net',
    type: 'domain',
    status: 'analyzing',
    priority: 'critical',
    risk_level: 'critical',
    created_at: new Date(Date.now() - 3 * 24 * 60 * 60 * 1000).toISOString(),
    updated_at: new Date(Date.now() - 2 * 60 * 60 * 1000).toISOString(),
    findings_count: 42,
    progress: 75,
  },
  {
    id: '5',
    target: 'compromised-host.org',
    type: 'domain',
    status: 'completed',
    priority: 'high',
    risk_level: 'high',
    created_at: new Date(Date.now() - 120 * 24 * 60 * 60 * 1000).toISOString(),
    updated_at: new Date(Date.now() - 115 * 24 * 60 * 60 * 1000).toISOString(),
    findings_count: 31,
    progress: 100,
  },
  {
    id: '6',
    target: 'phishing-kit-domain.xyz',
    type: 'domain',
    status: 'queued',
    priority: 'high',
    risk_level: 'high',
    created_at: new Date(Date.now() - 2 * 60 * 60 * 1000).toISOString(),
    updated_at: new Date(Date.now() - 2 * 60 * 60 * 1000).toISOString(),
    findings_count: 0,
    progress: 0,
  },
  {
    id: '7',
    target: '10.0.0.55',
    type: 'ip_address',
    status: 'generating_report',
    priority: 'normal',
    risk_level: 'medium',
    created_at: new Date(Date.now() - 4 * 24 * 60 * 60 * 1000).toISOString(),
    updated_at: new Date(Date.now() - 20 * 60 * 1000).toISOString(),
    findings_count: 15,
    progress: 95,
  },
];

// ─── Client-side search filter ────────────────────────────────────────────────

function applySearchParams(
  investigations: typeof allInvestigations,
  params: SearchParams,
): typeof allInvestigations {
  return investigations.filter((inv) => {
    if (params.q) {
      const q = params.q.toLowerCase();
      const hit = inv.target.toLowerCase().includes(q) || (inv.type || '').toLowerCase().includes(q);
      if (!hit) return false;
    }
    if (params.status && inv.status !== params.status) return false;
    if (params.priority && inv.priority !== params.priority) return false;
    if (params.risk_level && inv.risk_level !== params.risk_level) return false;
    return true;
  });
}

// ─── Page component ───────────────────────────────────────────────────────────

const InvestigationsPage: React.FC = () => {
  const navigate = useNavigate();
  const location = useLocation();

  // ── View mode — persisted in localStorage ──────────────────────────────────
  const [viewMode, setViewMode] = useState<'list' | 'kanban'>(() => {
    try {
      const stored = localStorage.getItem(VIEW_MODE_KEY);
      return (stored === 'kanban' ? 'kanban' : 'list') as 'list' | 'kanban';
    } catch {
      return 'list';
    }
  });

  const handleViewModeChange = (_: React.MouseEvent, newMode: 'list' | 'kanban' | null) => {
    if (!newMode) return;
    setViewMode(newMode);
    try {
      localStorage.setItem(VIEW_MODE_KEY, newMode);
    } catch {
      // ignore localStorage errors
    }
  };

  // ── Search params ──────────────────────────────────────────────────────────
  const [searchParams, setSearchParams] = useState<SearchParams>({});

  // ── Saved searches hook ────────────────────────────────────────────────────
  const {
    savedSearches,
    saveSearch,
    deleteSearch,
    loading: saveLoading,
  } = useSavedSearches();

  const handleSaveSearch = useCallback(
    async (name: string, description: string, params: SearchParams) => {
      await saveSearch(name, description, params);
    },
    [saveSearch],
  );

  const handleSelectSavedSearch = useCallback((params: SearchParams) => {
    setSearchParams(params);
  }, []);

  // ── Saved-search alert: check on mount for new matches ─────────────────────
  const [alertMessage, setAlertMessage] = useState<string | null>(null);

  useEffect(() => {
    if (savedSearches.length === 0) return;

    let lastCheck: number;
    try {
      lastCheck = parseInt(localStorage.getItem(LAST_CHECK_KEY) || '0', 10);
    } catch {
      lastCheck = 0;
    }

    // Count investigations created after the last check that match any saved search
    let totalNewMatches = 0;
    let matchingSearchNames: string[] = [];

    for (const ss of savedSearches) {
      const matches = applySearchParams(allInvestigations, ss.query_params).filter((inv) => {
        const createdMs = new Date(inv.created_at).getTime();
        return lastCheck === 0 ? false : createdMs > lastCheck;
      });
      if (matches.length > 0) {
        totalNewMatches += matches.length;
        matchingSearchNames.push(ss.name);
      }
    }

    if (totalNewMatches > 0) {
      const namesStr = matchingSearchNames.slice(0, 2).map((n) => `"${n}"`).join(', ');
      const extra = matchingSearchNames.length > 2 ? ` +${matchingSearchNames.length - 2} more` : '';
      setAlertMessage(
        `${totalNewMatches} new investigation${totalNewMatches !== 1 ? 's' : ''} match ${namesStr}${extra}`,
      );
    }

    // Update last-check timestamp
    try {
      localStorage.setItem(LAST_CHECK_KEY, Date.now().toString());
    } catch {
      // ignore
    }
  }, [savedSearches]);

  // ── Path-based filter ──────────────────────────────────────────────────────
  const getFilter = (): string => {
    const pathSegments = location.pathname.split('/');
    return pathSegments[2] || 'all';
  };

  const filter = getFilter();

  // ── Apply path filter first, then search params ────────────────────────────
  const pathFiltered = useMemo(() => {
    switch (filter) {
      case 'active':
        return allInvestigations.filter((inv) =>
          ['active', 'pending', 'queued', 'planning', 'profiling', 'collecting',
           'analyzing', 'assessing_risk', 'verifying', 'generating_report'].includes(inv.status),
        );
      case 'history':
        return allInvestigations.filter((inv) =>
          ['completed', 'failed', 'cancelled'].includes(inv.status),
        );
      case 'saved':
        return allInvestigations;
      case 'all':
      default:
        return allInvestigations;
    }
  }, [filter]);

  const filteredInvestigations = useMemo(
    () => applySearchParams(pathFiltered, searchParams),
    [pathFiltered, searchParams],
  );

  // ── Title ──────────────────────────────────────────────────────────────────
  const getTitle = (): string => {
    switch (filter) {
      case 'active':   return 'Active Investigations';
      case 'history':  return 'Investigation History';
      case 'saved':    return 'Saved Investigations';
      default:         return 'Investigations';
    }
  };

  return (
    <PageContainer
      variants={pageVariants}
      initial="initial"
      animate="enter"
      exit="exit"
    >
      {/* Saved-search alert Toast */}
      <Snackbar
        open={Boolean(alertMessage)}
        autoHideDuration={8000}
        onClose={() => setAlertMessage(null)}
        anchorOrigin={{ vertical: 'top', horizontal: 'right' }}
      >
        <Alert
          severity="info"
          icon={<NotificationsActiveIcon />}
          onClose={() => setAlertMessage(null)}
          sx={{
            backgroundColor: `${cyberColors.neon.purple}18`,
            color: cyberColors.text.primary,
            border: `1px solid ${cyberColors.neon.purple}50`,
            borderRadius: 2,
            '& .MuiAlert-icon': { color: cyberColors.neon.purple },
          }}
        >
          <Typography sx={{ fontSize: '0.85rem', fontWeight: 600 }}>
            Saved Search Alert
          </Typography>
          <Typography sx={{ fontSize: '0.78rem', color: cyberColors.text.secondary, mt: 0.25 }}>
            {alertMessage}
          </Typography>
        </Alert>
      </Snackbar>

      <Header>
        <HeaderLeft>
          <Title>{getTitle()}</Title>
          <Tooltip title={viewMode === 'list' ? 'Switch to kanban view' : 'Switch to list view'}>
            <ViewToggle
              value={viewMode}
              exclusive
              onChange={handleViewModeChange}
              size="small"
            >
              <ToggleButton value="list" aria-label="list view">
                <ViewListIcon fontSize="small" />
              </ToggleButton>
              <ToggleButton value="kanban" aria-label="kanban view">
                <ViewKanbanIcon fontSize="small" />
              </ToggleButton>
            </ViewToggle>
          </Tooltip>
        </HeaderLeft>

        <NewButton
          variant="contained"
          startIcon={<AddIcon />}
          onClick={() => navigate('/investigations/new')}
        >
          New Investigation
        </NewButton>
      </Header>

      {/* Search / filter bar */}
      <SearchBar
        params={searchParams}
        onChange={setSearchParams}
        savedSearches={savedSearches}
        onSaveSearch={handleSaveSearch}
        onDeleteSearch={deleteSearch}
        onSelectSavedSearch={handleSelectSavedSearch}
        saving={saveLoading}
      />

      {/* Kanban view */}
      {viewMode === 'kanban' && (
        <KanbanBoard investigations={filteredInvestigations} />
      )}

      {/* List view */}
      {viewMode === 'list' && (
        <>
          {filteredInvestigations.map((inv, index) => (
            <InvestigationCard
              key={inv.id}
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: index * 0.07 }}
              onClick={() => navigate(`/investigations/${inv.id}`)}
            >
              <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                <Box sx={{ flex: 1, minWidth: 0, mr: 2 }}>
                  <Typography
                    sx={{
                      fontFamily: designTokens.typography.fontFamily.mono,
                      color: cyberColors.neon.cyan,
                      fontSize: '1.05rem',
                      fontWeight: 600,
                      mb: 0.75,
                      overflow: 'hidden',
                      textOverflow: 'ellipsis',
                      whiteSpace: 'nowrap',
                    }}
                    title={inv.target}
                  >
                    {inv.target}
                  </Typography>
                  <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5 }}>
                    <Typography variant="body2" sx={{ color: cyberColors.text.secondary, fontSize: '0.78rem' }}>
                      {inv.findings_count} finding{inv.findings_count !== 1 ? 's' : ''}
                    </Typography>
                    <FreshnessIndicator
                      lastSeen={inv.updated_at || inv.created_at}
                      size="full"
                    />
                  </Box>
                </Box>
                <StatusChip
                  label={(inv.status || 'unknown').replace(/_/g, ' ').toUpperCase()}
                  status={inv.status}
                  size="small"
                />
              </Box>
            </InvestigationCard>
          ))}

          {filteredInvestigations.length === 0 && (
            <Card variant="glass">
              <Typography color="text.secondary" textAlign="center">
                {Object.keys(searchParams).some((k) => searchParams[k as keyof SearchParams])
                  ? 'No investigations match your current filters. Try clearing some filters.'
                  : `No ${filter !== 'all' ? filter : ''} investigations yet. Create one to get started.`}
              </Typography>
            </Card>
          )}
        </>
      )}
    </PageContainer>
  );
};

export default InvestigationsPage;
