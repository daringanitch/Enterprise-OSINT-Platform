/**
 * KanbanBoard — Investigation Kanban View
 *
 * Groups investigations into 5 operational columns giving team leads an
 * at-a-glance operational picture. All 12 InvestigationStatus values are
 * mapped to one of the 5 columns below.
 *
 * Column mapping:
 *   New       → pending, queued
 *   Active    → planning, profiling, collecting
 *   Analysis  → analyzing, assessing_risk, verifying
 *   Reporting → generating_report
 *   Closed    → completed, failed, cancelled
 */

import React from 'react';
import { useNavigate } from 'react-router-dom';
import { Box, Typography, LinearProgress, Chip, styled } from '@mui/material';
import { motion, AnimatePresence } from 'framer-motion';
import AssignmentIcon from '@mui/icons-material/Assignment';
import { cyberColors, designTokens, glassmorphism } from '../../utils/theme';
import { FreshnessIndicator } from '../common/FreshnessIndicator';
import { InvestigationStatus, Priority, RiskLevel } from '../../types';

// ─── Types ────────────────────────────────────────────────────────────────────

interface KanbanInvestigation {
  id: string;
  target: string;
  status: string;
  priority?: string;
  risk_level?: string;
  findings_count?: number;
  progress?: number;
  created_at?: string;
  updated_at?: string;
  investigator?: string;
}

export interface KanbanBoardProps {
  investigations: KanbanInvestigation[];
}

// ─── Column configuration ────────────────────────────────────────────────────

type KanbanColumnKey = 'new' | 'active' | 'analysis' | 'reporting' | 'closed';

interface ColumnConfig {
  key: KanbanColumnKey;
  label: string;
  color: string;
  statuses: string[];
}

const COLUMNS: ColumnConfig[] = [
  {
    key: 'new',
    label: 'New',
    color: '#8B5CF6',
    statuses: ['pending', 'queued'],
  },
  {
    key: 'active',
    label: 'Active',
    color: '#22D3EE',
    statuses: ['planning', 'profiling', 'collecting'],
  },
  {
    key: 'analysis',
    label: 'Analysis',
    color: '#F59E0B',
    statuses: ['analyzing', 'assessing_risk', 'verifying'],
  },
  {
    key: 'reporting',
    label: 'Reporting',
    color: '#22C55E',
    statuses: ['generating_report'],
  },
  {
    key: 'closed',
    label: 'Closed',
    color: '#484F58',
    statuses: ['completed', 'failed', 'cancelled'],
  },
];

// ─── Risk level colors ────────────────────────────────────────────────────────

const RISK_COLORS: Record<string, string> = {
  critical: '#EF4444',
  high: '#F59E0B',
  medium: '#22D3EE',
  low: '#22C55E',
};

const PRIORITY_COLORS: Record<string, string> = {
  critical: '#EF4444',
  urgent: '#F59E0B',
  high: '#A78BFA',
  normal: '#22D3EE',
  low: '#484F58',
};

// ─── Styled Components ────────────────────────────────────────────────────────

const BoardContainer = styled(Box)({
  display: 'flex',
  gap: 16,
  overflowX: 'auto',
  paddingBottom: 16,
  minHeight: 400,
  // Custom scrollbar
  '&::-webkit-scrollbar': { height: 6 },
  '&::-webkit-scrollbar-track': { background: cyberColors.dark.void },
  '&::-webkit-scrollbar-thumb': {
    background: cyberColors.dark.steel,
    borderRadius: 3,
  },
});

const Column = styled(Box)({
  minWidth: 260,
  flex: '0 0 260px',
  display: 'flex',
  flexDirection: 'column',
  gap: 0,
});

const ColumnHeader = styled(Box)<{ accentColor: string }>(({ accentColor }) => ({
  display: 'flex',
  alignItems: 'center',
  justifyContent: 'space-between',
  padding: '10px 14px',
  borderRadius: `${designTokens.borderRadius.md}px ${designTokens.borderRadius.md}px 0 0`,
  backgroundColor: `${accentColor}12`,
  borderBottom: `2px solid ${accentColor}50`,
  border: `1px solid ${accentColor}30`,
  borderBottomWidth: 2,
}));

const ColumnCount = styled(Chip)<{ accentColor: string }>(({ accentColor }) => ({
  height: 20,
  fontSize: '0.7rem',
  fontWeight: 700,
  backgroundColor: `${accentColor}25`,
  color: accentColor,
  border: `1px solid ${accentColor}40`,
  '& .MuiChip-label': { padding: '0 6px' },
}));

const CardStack = styled(Box)({
  flex: 1,
  padding: '8px 0',
  display: 'flex',
  flexDirection: 'column',
  gap: 8,
  minHeight: 120,
});

const KanbanCard = styled(motion.div)({
  ...glassmorphism.card,
  padding: 14,
  borderRadius: designTokens.borderRadius.md,
  cursor: 'pointer',
  transition: 'all 0.15s ease',
  '&:hover': {
    borderColor: cyberColors.neon.cyan,
    boxShadow: `0 0 16px ${cyberColors.neon.cyan}20`,
    transform: 'translateY(-1px)',
  },
});

const EmptyColumn = styled(Box)<{ accentColor: string }>(({ accentColor }) => ({
  flex: 1,
  minHeight: 80,
  border: `1px dashed ${accentColor}25`,
  borderRadius: designTokens.borderRadius.md,
  display: 'flex',
  alignItems: 'center',
  justifyContent: 'center',
  color: cyberColors.text.muted,
  fontSize: '0.75rem',
  padding: '12px 8px',
  textAlign: 'center',
}));

// ─── Sub-components ───────────────────────────────────────────────────────────

interface KanbanCardItemProps {
  investigation: KanbanInvestigation;
  onClick: () => void;
}

const KanbanCardItem: React.FC<KanbanCardItemProps> = ({ investigation, onClick }) => {
  const riskColor = RISK_COLORS[investigation.risk_level || ''] || cyberColors.text.muted;
  const priorityColor = PRIORITY_COLORS[investigation.priority || ''] || cyberColors.text.muted;
  const isInProgress =
    investigation.progress !== undefined &&
    investigation.progress > 0 &&
    investigation.progress < 100;

  return (
    <KanbanCard
      layout
      initial={{ opacity: 0, scale: 0.95 }}
      animate={{ opacity: 1, scale: 1 }}
      exit={{ opacity: 0, scale: 0.9 }}
      transition={{ duration: 0.15 }}
      onClick={onClick}
    >
      {/* Target */}
      <Typography
        sx={{
          fontFamily: designTokens.typography.fontFamily.mono,
          color: cyberColors.neon.cyan,
          fontSize: '0.85rem',
          fontWeight: 600,
          mb: 0.75,
          overflow: 'hidden',
          textOverflow: 'ellipsis',
          whiteSpace: 'nowrap',
        }}
        title={investigation.target}
      >
        {investigation.target}
      </Typography>

      {/* Badges row */}
      <Box sx={{ display: 'flex', gap: 0.5, flexWrap: 'wrap', mb: 1 }}>
        {investigation.risk_level && (
          <Chip
            label={investigation.risk_level.toUpperCase()}
            size="small"
            sx={{
              height: 18,
              fontSize: '0.62rem',
              fontWeight: 700,
              bgcolor: `${riskColor}18`,
              color: riskColor,
              border: `1px solid ${riskColor}40`,
              '& .MuiChip-label': { px: '5px' },
            }}
          />
        )}
        {investigation.priority && investigation.priority !== 'normal' && (
          <Chip
            label={investigation.priority.toUpperCase()}
            size="small"
            sx={{
              height: 18,
              fontSize: '0.62rem',
              fontWeight: 700,
              bgcolor: `${priorityColor}18`,
              color: priorityColor,
              border: `1px solid ${priorityColor}40`,
              '& .MuiChip-label': { px: '5px' },
            }}
          />
        )}
      </Box>

      {/* Progress bar (in-progress items only) */}
      {isInProgress && (
        <Box sx={{ mb: 1 }}>
          <LinearProgress
            variant="determinate"
            value={investigation.progress || 0}
            sx={{
              height: 3,
              borderRadius: 2,
              backgroundColor: `${cyberColors.neon.cyan}20`,
              '& .MuiLinearProgress-bar': {
                background: `linear-gradient(90deg, ${cyberColors.neon.cyan}, ${cyberColors.neon.electricBlue})`,
                borderRadius: 2,
              },
            }}
          />
          <Typography sx={{ fontSize: '0.65rem', color: cyberColors.text.muted, mt: 0.25 }}>
            {investigation.progress}% complete
          </Typography>
        </Box>
      )}

      {/* Footer row */}
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <Typography sx={{ fontSize: '0.68rem', color: cyberColors.text.muted }}>
          {investigation.findings_count !== undefined
            ? `${investigation.findings_count} finding${investigation.findings_count !== 1 ? 's' : ''}`
            : 'No findings yet'}
        </Typography>
        <FreshnessIndicator
          lastSeen={investigation.updated_at || investigation.created_at}
          size="compact"
        />
      </Box>
    </KanbanCard>
  );
};

// ─── Main Component ───────────────────────────────────────────────────────────

export const KanbanBoard: React.FC<KanbanBoardProps> = ({ investigations }) => {
  const navigate = useNavigate();

  return (
    <BoardContainer>
      {COLUMNS.map((col) => {
        const cards = investigations.filter((inv) =>
          col.statuses.includes(inv.status)
        );

        return (
          <Column key={col.key}>
            <ColumnHeader accentColor={col.color}>
              <Typography
                sx={{
                  fontFamily: designTokens.typography.fontFamily.display,
                  fontWeight: 700,
                  fontSize: '0.8rem',
                  color: col.color,
                  letterSpacing: '0.06em',
                  textTransform: 'uppercase',
                }}
              >
                {col.label}
              </Typography>
              <ColumnCount
                label={String(cards.length)}
                size="small"
                accentColor={col.color}
              />
            </ColumnHeader>

            <CardStack>
              <AnimatePresence mode="popLayout">
                {cards.length === 0 ? (
                  <EmptyColumn accentColor={col.color}>
                    <Box sx={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 0.5 }}>
                      <AssignmentIcon sx={{ fontSize: '1.2rem', opacity: 0.4 }} />
                      <span>No investigations</span>
                    </Box>
                  </EmptyColumn>
                ) : (
                  cards.map((inv) => (
                    <KanbanCardItem
                      key={inv.id}
                      investigation={inv}
                      onClick={() => navigate(`/investigations/${inv.id}`)}
                    />
                  ))
                )}
              </AnimatePresence>
            </CardStack>
          </Column>
        );
      })}
    </BoardContainer>
  );
};

export default KanbanBoard;
