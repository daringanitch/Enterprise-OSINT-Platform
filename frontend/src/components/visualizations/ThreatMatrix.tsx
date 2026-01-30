/**
 * ThreatMatrix Component
 *
 * MITRE ATT&CK style threat matrix for displaying tactics and techniques.
 */

import React, { useMemo, useState } from 'react';
import {
  Box,
  Typography,
  Paper,
  useTheme,
  Tooltip,
  Chip,
  Collapse,
  IconButton,
} from '@mui/material';
import ExpandMoreIcon from '@mui/icons-material/ExpandMore';
import ExpandLessIcon from '@mui/icons-material/ExpandLess';

export interface Technique {
  id: string;
  name: string;
  description?: string;
  severity?: 'low' | 'medium' | 'high' | 'critical';
  detected?: boolean;
  count?: number;
  subtechniques?: Technique[];
}

export interface Tactic {
  id: string;
  name: string;
  description?: string;
  techniques: Technique[];
}

export interface ThreatMatrixProps {
  /** Matrix tactics with their techniques */
  tactics: Tactic[];
  /** Chart title */
  title?: string;
  /** Show technique counts */
  showCounts?: boolean;
  /** Show only detected techniques */
  showDetectedOnly?: boolean;
  /** Technique click handler */
  onTechniqueClick?: (technique: Technique, tactic: Tactic) => void;
  /** Compact mode */
  compact?: boolean;
  /** Maximum techniques to show per tactic (before "more" button) */
  maxTechniquesPerTactic?: number;
  /** Test ID for testing */
  testId?: string;
}

const severityColors: Record<string, string> = {
  low: '#4caf50',
  medium: '#ff9800',
  high: '#f44336',
  critical: '#9c27b0',
};

export const ThreatMatrix: React.FC<ThreatMatrixProps> = ({
  tactics,
  title,
  showCounts = true,
  showDetectedOnly = false,
  onTechniqueClick,
  compact = false,
  maxTechniquesPerTactic = 10,
  testId,
}) => {
  const theme = useTheme();
  const [expandedTactics, setExpandedTactics] = useState<Set<string>>(new Set());

  const filteredTactics = useMemo(() => {
    if (!showDetectedOnly) return tactics;

    return tactics
      .map((tactic) => ({
        ...tactic,
        techniques: tactic.techniques.filter((t) => t.detected),
      }))
      .filter((tactic) => tactic.techniques.length > 0);
  }, [tactics, showDetectedOnly]);

  const toggleTacticExpansion = (tacticId: string) => {
    setExpandedTactics((prev) => {
      const next = new Set(prev);
      if (next.has(tacticId)) {
        next.delete(tacticId);
      } else {
        next.add(tacticId);
      }
      return next;
    });
  };

  const totalDetected = useMemo(() => {
    return tactics.reduce(
      (sum, tactic) =>
        sum + tactic.techniques.filter((t) => t.detected).length,
      0
    );
  }, [tactics]);

  const totalTechniques = useMemo(() => {
    return tactics.reduce((sum, tactic) => sum + tactic.techniques.length, 0);
  }, [tactics]);

  if (filteredTactics.length === 0) {
    return (
      <Box data-testid={testId} sx={{ textAlign: 'center', py: 4 }}>
        <Typography color="text.secondary">No techniques to display</Typography>
      </Box>
    );
  }

  return (
    <Box data-testid={testId}>
      {title && (
        <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 2 }}>
          <Typography variant="h6">{title}</Typography>
          <Box sx={{ display: 'flex', gap: 1 }}>
            <Chip
              label={`${totalDetected} / ${totalTechniques} detected`}
              size="small"
              color="primary"
              variant="outlined"
            />
          </Box>
        </Box>
      )}

      <Box
        sx={{
          display: 'flex',
          gap: 1,
          overflowX: 'auto',
          pb: 2,
        }}
      >
        {filteredTactics.map((tactic) => {
          const isExpanded = expandedTactics.has(tactic.id);
          const detectedCount = tactic.techniques.filter((t) => t.detected).length;
          const displayedTechniques = isExpanded
            ? tactic.techniques
            : tactic.techniques.slice(0, maxTechniquesPerTactic);
          const hasMore = tactic.techniques.length > maxTechniquesPerTactic;

          return (
            <Paper
              key={tactic.id}
              elevation={1}
              sx={{
                minWidth: compact ? 150 : 200,
                maxWidth: compact ? 180 : 250,
                flexShrink: 0,
                display: 'flex',
                flexDirection: 'column',
              }}
            >
              {/* Tactic header */}
              <Tooltip title={tactic.description || ''} placement="top">
                <Box
                  sx={{
                    p: 1.5,
                    bgcolor: 'primary.main',
                    color: 'primary.contrastText',
                    borderTopLeftRadius: theme.shape.borderRadius,
                    borderTopRightRadius: theme.shape.borderRadius,
                  }}
                >
                  <Typography
                    variant="subtitle2"
                    fontWeight="bold"
                    sx={{ fontSize: compact ? '0.75rem' : '0.875rem' }}
                  >
                    {tactic.name}
                  </Typography>
                  {showCounts && (
                    <Typography variant="caption" sx={{ opacity: 0.8 }}>
                      {detectedCount} / {tactic.techniques.length}
                    </Typography>
                  )}
                </Box>
              </Tooltip>

              {/* Techniques list */}
              <Box
                sx={{
                  p: 1,
                  flex: 1,
                  display: 'flex',
                  flexDirection: 'column',
                  gap: 0.5,
                  bgcolor: theme.palette.mode === 'dark' ? 'grey.900' : 'grey.50',
                }}
              >
                {displayedTechniques.map((technique) => (
                  <TechniqueItem
                    key={technique.id}
                    technique={technique}
                    tactic={tactic}
                    compact={compact}
                    onTechniqueClick={onTechniqueClick}
                    showCounts={showCounts}
                  />
                ))}

                {hasMore && (
                  <Box sx={{ textAlign: 'center', mt: 0.5 }}>
                    <IconButton
                      size="small"
                      onClick={() => toggleTacticExpansion(tactic.id)}
                      sx={{ fontSize: '0.75rem' }}
                    >
                      {isExpanded ? <ExpandLessIcon /> : <ExpandMoreIcon />}
                    </IconButton>
                    {!isExpanded && (
                      <Typography variant="caption" color="text.secondary">
                        +{tactic.techniques.length - maxTechniquesPerTactic} more
                      </Typography>
                    )}
                  </Box>
                )}
              </Box>
            </Paper>
          );
        })}
      </Box>

      {/* Legend */}
      <Box sx={{ display: 'flex', gap: 2, mt: 2, flexWrap: 'wrap' }}>
        <Typography variant="caption" color="text.secondary">
          Severity:
        </Typography>
        {Object.entries(severityColors).map(([severity, color]) => (
          <Box key={severity} sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
            <Box
              sx={{
                width: 12,
                height: 12,
                borderRadius: 0.5,
                bgcolor: color,
              }}
            />
            <Typography variant="caption" sx={{ textTransform: 'capitalize' }}>
              {severity}
            </Typography>
          </Box>
        ))}
      </Box>
    </Box>
  );
};

interface TechniqueItemProps {
  technique: Technique;
  tactic: Tactic;
  compact: boolean;
  showCounts: boolean;
  onTechniqueClick?: (technique: Technique, tactic: Tactic) => void;
}

const TechniqueItem: React.FC<TechniqueItemProps> = ({
  technique,
  tactic,
  compact,
  showCounts,
  onTechniqueClick,
}) => {
  const theme = useTheme();
  const [expanded, setExpanded] = useState(false);

  const severityColor = technique.severity
    ? severityColors[technique.severity]
    : theme.palette.grey[400];

  const hasSubtechniques = technique.subtechniques && technique.subtechniques.length > 0;

  return (
    <>
      <Tooltip title={technique.description || ''} placement="right">
        <Paper
          elevation={0}
          onClick={() => {
            if (hasSubtechniques) {
              setExpanded(!expanded);
            }
            onTechniqueClick?.(technique, tactic);
          }}
          sx={{
            p: 1,
            display: 'flex',
            alignItems: 'center',
            gap: 1,
            cursor: 'pointer',
            bgcolor: technique.detected
              ? theme.palette.mode === 'dark'
                ? 'rgba(255,255,255,0.05)'
                : 'rgba(0,0,0,0.02)'
              : 'transparent',
            border: 1,
            borderColor: technique.detected ? severityColor : 'transparent',
            borderLeft: 3,
            borderLeftColor: severityColor,
            '&:hover': {
              bgcolor: theme.palette.action.hover,
            },
            opacity: technique.detected ? 1 : 0.6,
          }}
        >
          <Box sx={{ flex: 1, minWidth: 0 }}>
            <Typography
              variant="caption"
              noWrap
              sx={{
                display: 'block',
                fontWeight: technique.detected ? 'bold' : 'normal',
                fontSize: compact ? '0.65rem' : '0.75rem',
              }}
            >
              {technique.id}
            </Typography>
            <Typography
              variant="caption"
              color="text.secondary"
              noWrap
              sx={{
                display: 'block',
                fontSize: compact ? '0.6rem' : '0.7rem',
              }}
            >
              {technique.name}
            </Typography>
          </Box>

          {showCounts && technique.count !== undefined && technique.count > 0 && (
            <Chip
              label={technique.count}
              size="small"
              sx={{
                height: 18,
                fontSize: '0.65rem',
                bgcolor: severityColor,
                color: 'white',
              }}
            />
          )}

          {hasSubtechniques && (
            <IconButton size="small" sx={{ p: 0 }}>
              {expanded ? (
                <ExpandLessIcon sx={{ fontSize: 14 }} />
              ) : (
                <ExpandMoreIcon sx={{ fontSize: 14 }} />
              )}
            </IconButton>
          )}
        </Paper>
      </Tooltip>

      {/* Subtechniques */}
      {hasSubtechniques && (
        <Collapse in={expanded}>
          <Box sx={{ pl: 2, display: 'flex', flexDirection: 'column', gap: 0.25 }}>
            {technique.subtechniques!.map((sub) => (
              <TechniqueItem
                key={sub.id}
                technique={sub}
                tactic={tactic}
                compact={compact}
                showCounts={showCounts}
                onTechniqueClick={onTechniqueClick}
              />
            ))}
          </Box>
        </Collapse>
      )}
    </>
  );
};

export default ThreatMatrix;
