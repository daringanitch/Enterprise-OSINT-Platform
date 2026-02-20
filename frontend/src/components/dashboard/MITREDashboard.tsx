/**
 * MITREDashboard Component
 *
 * Enhanced MITRE ATT&CK visualization with kill chain flow,
 * technique heat maps, and coverage analysis.
 *
 * Features:
 * - 14 tactic columns with technique cards
 * - Heat intensity based on detection count
 * - Kill chain flow lines (SVG overlay)
 * - Technique drill-down modal
 * - Coverage percentage per-tactic
 */

import React, { useState, useMemo } from 'react';
import {
  Box,
  Typography,
  Paper,
  Chip,
  Tooltip,
  IconButton,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Button,
  LinearProgress,
  Grid,
  alpha,
  styled,
  Divider,
} from '@mui/material';
import { motion, AnimatePresence } from 'framer-motion';
import SecurityIcon from '@mui/icons-material/Security';
import ExpandMoreIcon from '@mui/icons-material/ExpandMore';
import ExpandLessIcon from '@mui/icons-material/ExpandLess';
import CloseIcon from '@mui/icons-material/Close';
import ArrowForwardIcon from '@mui/icons-material/ArrowForward';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import WarningIcon from '@mui/icons-material/Warning';
import ShieldIcon from '@mui/icons-material/Shield';
import { cyberColors, designTokens, glassmorphism } from '../../utils/theme';
import { staggerContainer, staggerItem } from '../../utils/animations';

// =============================================================================
// Types
// =============================================================================

export interface MITRETechnique {
  id: string;
  name: string;
  description?: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  detected: boolean;
  count: number;
  subtechniques?: MITRETechnique[];
  evidence?: string[];
  mitigations?: string[];
  dataSourcesUsed?: string[];
  firstSeen?: string;
  lastSeen?: string;
}

export interface MITRETactic {
  id: string;
  name: string;
  shortName: string;
  description?: string;
  order: number; // For kill chain ordering
  techniques: MITRETechnique[];
}

export interface MITREDashboardProps {
  /** MITRE tactics with techniques */
  tactics: MITRETactic[];
  /** Title */
  title?: string;
  /** Show kill chain flow lines */
  showKillChain?: boolean;
  /** Loading state */
  loading?: boolean;
  /** Technique click handler */
  onTechniqueClick?: (technique: MITRETechnique, tactic: MITRETactic) => void;
  /** Test ID */
  testId?: string;
}

// =============================================================================
// Constants - MITRE ATT&CK Tactics (in kill chain order)
// =============================================================================

const TACTIC_ORDER = [
  'reconnaissance',
  'resource-development',
  'initial-access',
  'execution',
  'persistence',
  'privilege-escalation',
  'defense-evasion',
  'credential-access',
  'discovery',
  'lateral-movement',
  'collection',
  'command-and-control',
  'exfiltration',
  'impact',
];

const severityColors = {
  critical: cyberColors.neon.magenta,
  high: cyberColors.neon.red,
  medium: cyberColors.neon.orange,
  low: cyberColors.neon.yellow,
};

// =============================================================================
// Styled Components
// =============================================================================

const DashboardContainer = styled(Paper)(({ theme }) => ({
  ...glassmorphism.card,
  borderRadius: designTokens.borderRadius.lg,
  overflow: 'hidden',
}));

const HeaderSection = styled(Box)(({ theme }) => ({
  padding: '16px 20px',
  borderBottom: `1px solid ${alpha(cyberColors.neon.cyan, 0.1)}`,
  display: 'flex',
  alignItems: 'center',
  justifyContent: 'space-between',
  background: `linear-gradient(90deg, ${alpha(cyberColors.neon.red, 0.05)} 0%, transparent 50%, ${alpha(cyberColors.neon.cyan, 0.05)} 100%)`,
}));

const TacticColumn = styled(motion.div)(({ theme }) => ({
  minWidth: 180,
  maxWidth: 220,
  flex: '0 0 auto',
}));

const TacticHeader = styled(Box)<{ coverage: number }>(({ coverage }) => ({
  padding: '12px 8px',
  textAlign: 'center',
  borderBottom: `2px solid ${
    coverage > 0.6 ? cyberColors.neon.green :
    coverage > 0.3 ? cyberColors.neon.orange :
    cyberColors.neon.red
  }`,
  background: alpha(cyberColors.dark.steel, 0.5),
  position: 'relative',
  '&::after': {
    content: '""',
    position: 'absolute',
    bottom: 0,
    left: 0,
    width: `${coverage * 100}%`,
    height: '2px',
    background: cyberColors.neon.cyan,
    boxShadow: `0 0 10px ${cyberColors.neon.cyan}`,
  },
}));

const TechniqueCard = styled(motion.div)<{ severity: string; detected: boolean }>(
  ({ severity, detected }) => ({
    ...glassmorphism.interactive,
    borderRadius: designTokens.borderRadius.sm,
    padding: 8,
    marginBottom: 4,
    cursor: 'pointer',
    borderLeft: `3px solid ${severityColors[severity as keyof typeof severityColors] || cyberColors.text.muted}`,
    opacity: detected ? 1 : 0.5,
    background: detected
      ? alpha(severityColors[severity as keyof typeof severityColors] || cyberColors.text.muted, 0.1)
      : 'transparent',
  })
);

const KillChainArrow = styled(motion.div)(({ theme }) => ({
  display: 'flex',
  alignItems: 'center',
  justifyContent: 'center',
  padding: '0 4px',
  color: cyberColors.neon.cyan,
  opacity: 0.5,
}));

const CoverageBar = styled(Box)(({ theme }) => ({
  height: 4,
  borderRadius: 2,
  background: alpha(cyberColors.dark.ash, 0.5),
  overflow: 'hidden',
  marginTop: 4,
}));

const CoverageFill = styled(motion.div)<{ percentage: number }>(({ percentage }) => ({
  height: '100%',
  borderRadius: 2,
  background:
    percentage > 60 ? cyberColors.neon.green :
    percentage > 30 ? cyberColors.neon.orange :
    cyberColors.neon.red,
  boxShadow: `0 0 8px ${
    percentage > 60 ? cyberColors.neon.green :
    percentage > 30 ? cyberColors.neon.orange :
    cyberColors.neon.red
  }`,
}));

const StatsChip = styled(Chip)(({ theme }) => ({
  height: 24,
  fontSize: '0.7rem',
  fontWeight: 600,
  fontFamily: designTokens.typography.fontFamily.mono,
}));

// =============================================================================
// Component
// =============================================================================

export const MITREDashboard: React.FC<MITREDashboardProps> = ({
  tactics,
  title = 'MITRE ATT&CK Coverage',
  showKillChain = true,
  loading = false,
  onTechniqueClick,
  testId,
}) => {
  const [selectedTechnique, setSelectedTechnique] = useState<{
    technique: MITRETechnique;
    tactic: MITRETactic;
  } | null>(null);
  const [expandedTactics, setExpandedTactics] = useState<Set<string>>(new Set());

  // Sort tactics by kill chain order
  const sortedTactics = useMemo(() => {
    return [...tactics].sort((a, b) => {
      const orderA = TACTIC_ORDER.indexOf(a.id) !== -1 ? TACTIC_ORDER.indexOf(a.id) : 999;
      const orderB = TACTIC_ORDER.indexOf(b.id) !== -1 ? TACTIC_ORDER.indexOf(b.id) : 999;
      return orderA - orderB;
    });
  }, [tactics]);

  // Calculate stats
  const stats = useMemo(() => {
    let totalTechniques = 0;
    let detectedTechniques = 0;
    let criticalCount = 0;
    let highCount = 0;

    tactics.forEach((tactic) => {
      tactic.techniques.forEach((tech) => {
        totalTechniques++;
        if (tech.detected) {
          detectedTechniques++;
          if (tech.severity === 'critical') criticalCount++;
          if (tech.severity === 'high') highCount++;
        }
      });
    });

    return {
      total: totalTechniques,
      detected: detectedTechniques,
      coverage: totalTechniques > 0 ? (detectedTechniques / totalTechniques) * 100 : 0,
      critical: criticalCount,
      high: highCount,
    };
  }, [tactics]);

  const getTacticCoverage = (tactic: MITRETactic): number => {
    const detected = tactic.techniques.filter((t) => t.detected).length;
    return tactic.techniques.length > 0 ? detected / tactic.techniques.length : 0;
  };

  const handleTechniqueClick = (technique: MITRETechnique, tactic: MITRETactic) => {
    setSelectedTechnique({ technique, tactic });
    onTechniqueClick?.(technique, tactic);
  };

  const toggleTacticExpand = (tacticId: string) => {
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

  if (loading) {
    return (
      <DashboardContainer data-testid={testId}>
        <HeaderSection>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
            <SecurityIcon sx={{ color: cyberColors.neon.cyan }} />
            <Typography variant="h6">{title}</Typography>
          </Box>
        </HeaderSection>
        <Box sx={{ p: 4, textAlign: 'center' }}>
          <LinearProgress
            sx={{
              bgcolor: alpha(cyberColors.neon.cyan, 0.1),
              '& .MuiLinearProgress-bar': {
                background: designTokens.colors.gradients.primary,
              },
            }}
          />
          <Typography variant="body2" sx={{ mt: 2, color: cyberColors.text.secondary }}>
            Loading MITRE ATT&CK data...
          </Typography>
        </Box>
      </DashboardContainer>
    );
  }

  return (
    <DashboardContainer data-testid={testId}>
      {/* Header */}
      <HeaderSection>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
          <SecurityIcon sx={{ color: cyberColors.neon.cyan }} />
          <Box>
            <Typography
              variant="h6"
              sx={{
                fontFamily: designTokens.typography.fontFamily.display,
                color: cyberColors.text.primary,
                fontSize: '1rem',
              }}
            >
              {title}
            </Typography>
            <Typography variant="caption" sx={{ color: cyberColors.text.secondary }}>
              Kill Chain Analysis | {sortedTactics.length} Tactics
            </Typography>
          </Box>
        </Box>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
          <StatsChip
            label={`Coverage: ${stats.coverage.toFixed(0)}%`}
            sx={{
              bgcolor: alpha(
                stats.coverage > 60 ? cyberColors.neon.green :
                stats.coverage > 30 ? cyberColors.neon.orange :
                cyberColors.neon.red, 0.2
              ),
              color:
                stats.coverage > 60 ? cyberColors.neon.green :
                stats.coverage > 30 ? cyberColors.neon.orange :
                cyberColors.neon.red,
            }}
          />
          {stats.critical > 0 && (
            <StatsChip
              label={`${stats.critical} CRITICAL`}
              sx={{
                bgcolor: alpha(cyberColors.neon.magenta, 0.2),
                color: cyberColors.neon.magenta,
              }}
            />
          )}
          {stats.high > 0 && (
            <StatsChip
              label={`${stats.high} HIGH`}
              sx={{
                bgcolor: alpha(cyberColors.neon.red, 0.2),
                color: cyberColors.neon.red,
              }}
            />
          )}
        </Box>
      </HeaderSection>

      {/* Kill Chain Matrix */}
      <Box
        sx={{
          display: 'flex',
          overflowX: 'auto',
          p: 2,
          pb: 3,
          position: 'relative',
        }}
      >
        <motion.div
          variants={staggerContainer}
          initial="initial"
          animate="enter"
          style={{ display: 'flex', gap: 4 }}
        >
          {sortedTactics.map((tactic, tacticIndex) => {
            const coverage = getTacticCoverage(tactic);
            const isExpanded = expandedTactics.has(tactic.id);
            const visibleTechniques = isExpanded
              ? tactic.techniques
              : tactic.techniques.filter((t) => t.detected).slice(0, 6);
            const hasMore = tactic.techniques.length > 6;

            return (
              <React.Fragment key={tactic.id}>
                <TacticColumn
                  variants={staggerItem}
                >
                  {/* Tactic Header */}
                  <TacticHeader coverage={coverage}>
                    <Typography
                      variant="caption"
                      sx={{
                        display: 'block',
                        fontWeight: 700,
                        color: cyberColors.text.primary,
                        fontSize: '0.7rem',
                        textTransform: 'uppercase',
                        letterSpacing: '0.05em',
                        mb: 0.5,
                      }}
                    >
                      {tactic.shortName || tactic.name}
                    </Typography>
                    <Box sx={{ display: 'flex', justifyContent: 'center', gap: 0.5 }}>
                      <Chip
                        size="small"
                        label={`${tactic.techniques.filter((t) => t.detected).length}/${tactic.techniques.length}`}
                        sx={{
                          height: 18,
                          fontSize: '0.6rem',
                          bgcolor: alpha(cyberColors.neon.cyan, 0.2),
                          color: cyberColors.neon.cyan,
                        }}
                      />
                    </Box>
                    <CoverageBar>
                      <CoverageFill
                        percentage={coverage * 100}
                        initial={{ width: 0 }}
                        animate={{ width: `${coverage * 100}%` }}
                        transition={{ duration: 0.5, delay: tacticIndex * 0.1 }}
                      />
                    </CoverageBar>
                  </TacticHeader>

                  {/* Techniques */}
                  <Box sx={{ p: 1 }}>
                    <AnimatePresence>
                      {visibleTechniques.map((technique, techIndex) => (
                        <TechniqueCard
                          key={technique.id}
                          severity={technique.severity}
                          detected={technique.detected}
                          onClick={() => handleTechniqueClick(technique, tactic)}
                          initial={{ opacity: 0, y: 10 }}
                          animate={{ opacity: 1, y: 0 }}
                          exit={{ opacity: 0, y: -10 }}
                          transition={{ delay: techIndex * 0.02 }}
                          whileHover={{ scale: 1.02, x: 2 }}
                          whileTap={{ scale: 0.98 }}
                        >
                          <Typography
                            variant="caption"
                            sx={{
                              display: 'block',
                              fontWeight: 600,
                              color: technique.detected
                                ? severityColors[technique.severity]
                                : cyberColors.text.muted,
                              fontSize: '0.65rem',
                              fontFamily: designTokens.typography.fontFamily.mono,
                            }}
                          >
                            {technique.id}
                          </Typography>
                          <Typography
                            variant="caption"
                            sx={{
                              display: 'block',
                              color: cyberColors.text.secondary,
                              fontSize: '0.6rem',
                              overflow: 'hidden',
                              textOverflow: 'ellipsis',
                              whiteSpace: 'nowrap',
                            }}
                          >
                            {technique.name}
                          </Typography>
                          {technique.detected && technique.count > 0 && (
                            <Chip
                              label={technique.count}
                              size="small"
                              sx={{
                                height: 14,
                                fontSize: '0.55rem',
                                mt: 0.5,
                                bgcolor: alpha(severityColors[technique.severity], 0.2),
                                color: severityColors[technique.severity],
                              }}
                            />
                          )}
                        </TechniqueCard>
                      ))}
                    </AnimatePresence>

                    {/* Show More Button */}
                    {hasMore && (
                      <Box sx={{ textAlign: 'center', mt: 1 }}>
                        <IconButton
                          size="small"
                          onClick={() => toggleTacticExpand(tactic.id)}
                          sx={{ color: cyberColors.neon.cyan }}
                        >
                          {isExpanded ? (
                            <ExpandLessIcon fontSize="small" />
                          ) : (
                            <ExpandMoreIcon fontSize="small" />
                          )}
                        </IconButton>
                        {!isExpanded && (
                          <Typography
                            variant="caption"
                            sx={{ color: cyberColors.text.muted, display: 'block' }}
                          >
                            +{tactic.techniques.length - 6}
                          </Typography>
                        )}
                      </Box>
                    )}
                  </Box>
                </TacticColumn>

                {/* Kill Chain Arrow */}
                {showKillChain && tacticIndex < sortedTactics.length - 1 && (
                  <KillChainArrow
                    initial={{ opacity: 0 }}
                    animate={{ opacity: 0.5 }}
                    transition={{ delay: tacticIndex * 0.1 }}
                  >
                    <ArrowForwardIcon fontSize="small" />
                  </KillChainArrow>
                )}
              </React.Fragment>
            );
          })}
        </motion.div>
      </Box>

      {/* Legend */}
      <Box
        sx={{
          p: 2,
          pt: 1,
          borderTop: `1px solid ${alpha(cyberColors.neon.cyan, 0.1)}`,
          display: 'flex',
          flexWrap: 'wrap',
          gap: 2,
          alignItems: 'center',
        }}
      >
        <Typography variant="caption" sx={{ color: cyberColors.text.muted }}>
          Severity:
        </Typography>
        {Object.entries(severityColors).map(([severity, color]) => (
          <Box key={severity} sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
            <Box
              sx={{
                width: 10,
                height: 10,
                borderRadius: 1,
                bgcolor: color,
                boxShadow: `0 0 6px ${color}`,
              }}
            />
            <Typography
              variant="caption"
              sx={{ color: cyberColors.text.secondary, textTransform: 'capitalize' }}
            >
              {severity}
            </Typography>
          </Box>
        ))}
      </Box>

      {/* Technique Detail Modal */}
      <Dialog
        open={!!selectedTechnique}
        onClose={() => setSelectedTechnique(null)}
        maxWidth="sm"
        fullWidth
        PaperProps={{
          sx: {
            ...glassmorphism.card,
            borderRadius: designTokens.borderRadius.lg,
          },
        }}
      >
        {selectedTechnique && (
          <>
            <DialogTitle
              sx={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                borderBottom: `1px solid ${alpha(cyberColors.neon.cyan, 0.1)}`,
              }}
            >
              <Box>
                <Typography
                  variant="h6"
                  sx={{
                    color: severityColors[selectedTechnique.technique.severity],
                    fontFamily: designTokens.typography.fontFamily.display,
                  }}
                >
                  {selectedTechnique.technique.id}
                </Typography>
                <Typography variant="body2" sx={{ color: cyberColors.text.secondary }}>
                  {selectedTechnique.technique.name}
                </Typography>
              </Box>
              <IconButton onClick={() => setSelectedTechnique(null)}>
                <CloseIcon />
              </IconButton>
            </DialogTitle>
            <DialogContent sx={{ pt: 2 }}>
              {/* Status */}
              <Box sx={{ display: 'flex', gap: 1, mb: 2 }}>
                <Chip
                  icon={
                    selectedTechnique.technique.detected ? (
                      <WarningIcon fontSize="small" />
                    ) : (
                      <CheckCircleIcon fontSize="small" />
                    )
                  }
                  label={selectedTechnique.technique.detected ? 'DETECTED' : 'NOT DETECTED'}
                  sx={{
                    bgcolor: selectedTechnique.technique.detected
                      ? alpha(cyberColors.neon.red, 0.2)
                      : alpha(cyberColors.neon.green, 0.2),
                    color: selectedTechnique.technique.detected
                      ? cyberColors.neon.red
                      : cyberColors.neon.green,
                  }}
                />
                <Chip
                  label={selectedTechnique.technique.severity.toUpperCase()}
                  sx={{
                    bgcolor: alpha(severityColors[selectedTechnique.technique.severity], 0.2),
                    color: severityColors[selectedTechnique.technique.severity],
                  }}
                />
                <Chip
                  label={selectedTechnique.tactic.name}
                  sx={{
                    bgcolor: alpha(cyberColors.neon.cyan, 0.2),
                    color: cyberColors.neon.cyan,
                  }}
                />
              </Box>

              {/* Description */}
              {selectedTechnique.technique.description && (
                <Box sx={{ mb: 2 }}>
                  <Typography
                    variant="caption"
                    sx={{ color: cyberColors.neon.cyan, display: 'block', mb: 0.5 }}
                  >
                    Description
                  </Typography>
                  <Typography variant="body2" sx={{ color: cyberColors.text.secondary }}>
                    {selectedTechnique.technique.description}
                  </Typography>
                </Box>
              )}

              {/* Evidence */}
              {selectedTechnique.technique.evidence && selectedTechnique.technique.evidence.length > 0 && (
                <Box sx={{ mb: 2 }}>
                  <Typography
                    variant="caption"
                    sx={{ color: cyberColors.neon.orange, display: 'block', mb: 0.5 }}
                  >
                    Evidence ({selectedTechnique.technique.evidence.length})
                  </Typography>
                  <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.5 }}>
                    {selectedTechnique.technique.evidence.slice(0, 5).map((ev, i) => (
                      <Chip
                        key={i}
                        label={ev}
                        size="small"
                        sx={{
                          bgcolor: alpha(cyberColors.neon.orange, 0.15),
                          fontSize: '0.7rem',
                        }}
                      />
                    ))}
                  </Box>
                </Box>
              )}

              {/* Mitigations */}
              {selectedTechnique.technique.mitigations && selectedTechnique.technique.mitigations.length > 0 && (
                <Box sx={{ mb: 2 }}>
                  <Typography
                    variant="caption"
                    sx={{ color: cyberColors.neon.green, display: 'block', mb: 0.5 }}
                  >
                    <ShieldIcon sx={{ fontSize: 14, mr: 0.5, verticalAlign: 'middle' }} />
                    Mitigations
                  </Typography>
                  {selectedTechnique.technique.mitigations.map((mit, i) => (
                    <Typography
                      key={i}
                      variant="body2"
                      sx={{
                        color: cyberColors.text.secondary,
                        fontSize: '0.8rem',
                        pl: 2,
                        borderLeft: `2px solid ${cyberColors.neon.green}`,
                        mb: 1,
                      }}
                    >
                      {mit}
                    </Typography>
                  ))}
                </Box>
              )}

              {/* Timestamps */}
              {(selectedTechnique.technique.firstSeen || selectedTechnique.technique.lastSeen) && (
                <Box sx={{ display: 'flex', gap: 2 }}>
                  {selectedTechnique.technique.firstSeen && (
                    <Typography
                      variant="caption"
                      sx={{ color: cyberColors.text.muted, fontFamily: designTokens.typography.fontFamily.mono }}
                    >
                      First: {new Date(selectedTechnique.technique.firstSeen).toLocaleDateString()}
                    </Typography>
                  )}
                  {selectedTechnique.technique.lastSeen && (
                    <Typography
                      variant="caption"
                      sx={{ color: cyberColors.text.muted, fontFamily: designTokens.typography.fontFamily.mono }}
                    >
                      Last: {new Date(selectedTechnique.technique.lastSeen).toLocaleDateString()}
                    </Typography>
                  )}
                </Box>
              )}
            </DialogContent>
            <DialogActions sx={{ borderTop: `1px solid ${alpha(cyberColors.neon.cyan, 0.1)}` }}>
              <Button onClick={() => setSelectedTechnique(null)}>Close</Button>
            </DialogActions>
          </>
        )}
      </Dialog>
    </DashboardContainer>
  );
};

export default MITREDashboard;
