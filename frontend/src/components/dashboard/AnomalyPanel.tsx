/**
 * AnomalyPanel Component
 *
 * Dashboard panel for displaying anomaly detection results from the
 * Graph Intelligence engine. Shows suspicious entities ranked by severity.
 *
 * Features:
 * - Ranked suspicious entity cards
 * - Anomaly type indicators (degree, bridge, hub, star pattern)
 * - Z-score visualization
 * - One-click investigation drill-down
 */

import React, { useState } from 'react';
import {
  Box,
  Typography,
  IconButton,
  Tooltip,
  Chip,
  LinearProgress,
  Collapse,
  alpha,
  styled,
} from '@mui/material';
import { motion, AnimatePresence } from 'framer-motion';
import WarningAmberIcon from '@mui/icons-material/WarningAmber';
import ErrorOutlineIcon from '@mui/icons-material/ErrorOutline';
import HubIcon from '@mui/icons-material/Hub';
import DeviceHubIcon from '@mui/icons-material/DeviceHub';
import StarIcon from '@mui/icons-material/Star';
import ExpandMoreIcon from '@mui/icons-material/ExpandMore';
import ExpandLessIcon from '@mui/icons-material/ExpandLess';
import RefreshIcon from '@mui/icons-material/Refresh';
import { cyberColors, designTokens, glassmorphism } from '../../utils/theme';
import { staggerContainer, staggerItem } from '../../utils/animations';

// =============================================================================
// Types
// =============================================================================

export type AnomalyType =
  | 'degree'         // Unusually high/low connections
  | 'bridge'         // Critical connection between communities
  | 'hub'            // Authority/hub pattern anomaly
  | 'star'           // Star pattern (one-to-many relationships)
  | 'clustering'     // Unusual clustering coefficient
  | 'attribute'      // Attribute-based anomaly
  | 'behavioral'     // Behavioral pattern anomaly
  | 'temporal';      // Time-based anomaly

export interface AnomalyEntity {
  id: string;
  label: string;
  entityType: string;
  anomalyTypes: AnomalyType[];
  severity: 'critical' | 'high' | 'medium' | 'low';
  zScore: number;
  description: string;
  properties?: Record<string, any>;
  detectedAt?: string;
  confidence: number;
}

export interface AnomalyPanelProps {
  /** List of anomalous entities */
  anomalies: AnomalyEntity[];
  /** Title of the panel */
  title?: string;
  /** Loading state */
  loading?: boolean;
  /** Error message */
  error?: string | null;
  /** Maximum entities to show before "show more" */
  maxVisible?: number;
  /** Entity click handler */
  onEntityClick?: (entity: AnomalyEntity) => void;
  /** Refresh handler */
  onRefresh?: () => void;
  /** Test ID for testing */
  testId?: string;
}

// =============================================================================
// Anomaly Type Configuration
// =============================================================================

const anomalyTypeConfig: Record<AnomalyType, { icon: React.ReactElement; label: string; color: string }> = {
  degree: {
    icon: <DeviceHubIcon fontSize="small" />,
    label: 'Degree Anomaly',
    color: cyberColors.neon.orange,
  },
  bridge: {
    icon: <HubIcon fontSize="small" />,
    label: 'Bridge Node',
    color: cyberColors.neon.electricBlue,
  },
  hub: {
    icon: <HubIcon fontSize="small" />,
    label: 'Hub/Authority',
    color: cyberColors.neon.purple,
  },
  star: {
    icon: <StarIcon fontSize="small" />,
    label: 'Star Pattern',
    color: cyberColors.neon.yellow,
  },
  clustering: {
    icon: <DeviceHubIcon fontSize="small" />,
    label: 'Clustering',
    color: cyberColors.neon.green,
  },
  attribute: {
    icon: <ErrorOutlineIcon fontSize="small" />,
    label: 'Attribute',
    color: cyberColors.neon.cyan,
  },
  behavioral: {
    icon: <WarningAmberIcon fontSize="small" />,
    label: 'Behavioral',
    color: cyberColors.neon.magenta,
  },
  temporal: {
    icon: <WarningAmberIcon fontSize="small" />,
    label: 'Temporal',
    color: cyberColors.neon.red,
  },
};

const severityConfig = {
  critical: { color: cyberColors.neon.magenta, label: 'CRITICAL', priority: 4 },
  high: { color: cyberColors.neon.red, label: 'HIGH', priority: 3 },
  medium: { color: cyberColors.neon.orange, label: 'MEDIUM', priority: 2 },
  low: { color: cyberColors.neon.yellow, label: 'LOW', priority: 1 },
};

// =============================================================================
// Styled Components
// =============================================================================

const PanelContainer = styled(Box)(({ theme }) => ({
  ...glassmorphism.card,
  borderRadius: designTokens.borderRadius.lg,
  overflow: 'hidden',
}));

const PanelHeader = styled(Box)(({ theme }) => ({
  display: 'flex',
  alignItems: 'center',
  justifyContent: 'space-between',
  padding: '16px 20px',
  borderBottom: `1px solid ${alpha(cyberColors.neon.cyan, 0.1)}`,
  background: `linear-gradient(90deg, ${alpha(cyberColors.neon.red, 0.1)} 0%, transparent 100%)`,
}));

const AnomalyCard = styled(motion.div)(({ theme }) => ({
  ...glassmorphism.interactive,
  borderRadius: designTokens.borderRadius.md,
  padding: 16,
  marginBottom: 8,
  cursor: 'pointer',
  position: 'relative',
  overflow: 'hidden',
  '&::before': {
    content: '""',
    position: 'absolute',
    left: 0,
    top: 0,
    bottom: 0,
    width: 3,
    background: 'var(--severity-color)',
  },
}));

const ZScoreBar = styled(Box)(({ theme }) => ({
  height: 4,
  borderRadius: 2,
  background: alpha(cyberColors.dark.ash, 0.5),
  overflow: 'hidden',
  marginTop: 8,
}));

const ZScoreFill = styled(motion.div)<{ severity: string }>(({ severity }) => ({
  height: '100%',
  borderRadius: 2,
  background: severityConfig[severity as keyof typeof severityConfig]?.color || cyberColors.neon.orange,
  boxShadow: `0 0 10px ${severityConfig[severity as keyof typeof severityConfig]?.color || cyberColors.neon.orange}`,
}));

const TypeBadge = styled(Chip)(({ theme }) => ({
  height: 24,
  fontSize: '0.65rem',
  fontWeight: 600,
  letterSpacing: '0.03em',
  '& .MuiChip-icon': {
    marginLeft: 6,
  },
}));

const SeverityBadge = styled(Chip)<{ severity: string }>(({ severity }) => ({
  height: 20,
  fontSize: '0.6rem',
  fontWeight: 700,
  letterSpacing: '0.05em',
  background: alpha(severityConfig[severity as keyof typeof severityConfig]?.color || cyberColors.neon.orange, 0.2),
  color: severityConfig[severity as keyof typeof severityConfig]?.color || cyberColors.neon.orange,
  border: `1px solid ${alpha(severityConfig[severity as keyof typeof severityConfig]?.color || cyberColors.neon.orange, 0.5)}`,
  animation: severity === 'critical' ? 'pulse 2s infinite' : 'none',
  '@keyframes pulse': {
    '0%, 100%': {
      boxShadow: `0 0 5px ${alpha(cyberColors.neon.magenta, 0.3)}`,
    },
    '50%': {
      boxShadow: `0 0 15px ${alpha(cyberColors.neon.magenta, 0.6)}`,
    },
  },
}));

const CountBadge = styled(Box)(({ theme }) => ({
  display: 'flex',
  alignItems: 'center',
  justifyContent: 'center',
  minWidth: 28,
  height: 28,
  borderRadius: designTokens.borderRadius.sm,
  background: alpha(cyberColors.neon.red, 0.2),
  border: `1px solid ${alpha(cyberColors.neon.red, 0.4)}`,
  color: cyberColors.neon.red,
  fontWeight: 700,
  fontSize: '0.85rem',
  fontFamily: designTokens.typography.fontFamily.mono,
}));

// =============================================================================
// Component
// =============================================================================

export const AnomalyPanel: React.FC<AnomalyPanelProps> = ({
  anomalies,
  title = 'Anomaly Detection',
  loading = false,
  error = null,
  maxVisible = 5,
  onEntityClick,
  onRefresh,
  testId,
}) => {
  const [expanded, setExpanded] = useState(false);
  const [expandedCards, setExpandedCards] = useState<Set<string>>(new Set());

  // Sort anomalies by severity priority
  const sortedAnomalies = [...anomalies].sort((a, b) => {
    const priorityA = severityConfig[a.severity]?.priority || 0;
    const priorityB = severityConfig[b.severity]?.priority || 0;
    return priorityB - priorityA;
  });

  const visibleAnomalies = expanded
    ? sortedAnomalies
    : sortedAnomalies.slice(0, maxVisible);

  const hasMore = sortedAnomalies.length > maxVisible;

  const toggleCardExpanded = (id: string) => {
    setExpandedCards((prev) => {
      const next = new Set(prev);
      if (next.has(id)) {
        next.delete(id);
      } else {
        next.add(id);
      }
      return next;
    });
  };

  // Calculate summary stats
  const criticalCount = anomalies.filter((a) => a.severity === 'critical').length;
  const highCount = anomalies.filter((a) => a.severity === 'high').length;

  return (
    <PanelContainer data-testid={testId}>
      {/* Header */}
      <PanelHeader>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
          <WarningAmberIcon sx={{ color: cyberColors.neon.red }} />
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
            <Typography
              variant="caption"
              sx={{ color: cyberColors.text.secondary }}
            >
              {anomalies.length} suspicious entities detected
            </Typography>
          </Box>
        </Box>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
          {criticalCount > 0 && (
            <CountBadge sx={{ background: alpha(cyberColors.neon.magenta, 0.2) }}>
              {criticalCount}
            </CountBadge>
          )}
          {highCount > 0 && (
            <CountBadge>
              {highCount}
            </CountBadge>
          )}
          {onRefresh && (
            <Tooltip title="Refresh Analysis">
              <IconButton
                size="small"
                onClick={onRefresh}
                disabled={loading}
                sx={{ color: cyberColors.neon.cyan }}
              >
                <RefreshIcon fontSize="small" />
              </IconButton>
            </Tooltip>
          )}
        </Box>
      </PanelHeader>

      {/* Loading State */}
      {loading && (
        <Box sx={{ p: 2 }}>
          <LinearProgress
            sx={{
              bgcolor: alpha(cyberColors.neon.cyan, 0.1),
              '& .MuiLinearProgress-bar': {
                background: designTokens.colors.gradients.primary,
              },
            }}
          />
          <Typography
            variant="caption"
            sx={{ color: cyberColors.text.secondary, mt: 1, display: 'block' }}
          >
            Running anomaly detection algorithms...
          </Typography>
        </Box>
      )}

      {/* Error State */}
      {error && (
        <Box sx={{ p: 2, textAlign: 'center' }}>
          <ErrorOutlineIcon sx={{ color: cyberColors.neon.red, mb: 1 }} />
          <Typography variant="body2" sx={{ color: cyberColors.neon.red }}>
            {error}
          </Typography>
        </Box>
      )}

      {/* Anomaly List */}
      {!loading && !error && (
        <Box sx={{ p: 2 }}>
          {anomalies.length === 0 ? (
            <Box sx={{ textAlign: 'center', py: 4 }}>
              <Typography variant="body2" sx={{ color: cyberColors.text.secondary }}>
                No anomalies detected
              </Typography>
            </Box>
          ) : (
            <motion.div
              variants={staggerContainer}
              initial="initial"
              animate="enter"
            >
              <AnimatePresence>
                {visibleAnomalies.map((anomaly, index) => (
                  <AnomalyCard
                    key={anomaly.id}
                    variants={staggerItem}
                    style={{
                      '--severity-color': severityConfig[anomaly.severity]?.color,
                    } as React.CSSProperties}
                    onClick={() => onEntityClick?.(anomaly)}
                    whileHover={{ scale: 1.01, x: 4 }}
                    whileTap={{ scale: 0.99 }}
                  >
                    {/* Card Header */}
                    <Box sx={{ display: 'flex', justifyContent: 'space-between', mb: 1 }}>
                      <Box sx={{ flex: 1, minWidth: 0 }}>
                        <Typography
                          variant="subtitle2"
                          sx={{
                            color: cyberColors.text.primary,
                            fontWeight: 600,
                            overflow: 'hidden',
                            textOverflow: 'ellipsis',
                            whiteSpace: 'nowrap',
                          }}
                        >
                          {anomaly.label}
                        </Typography>
                        <Typography
                          variant="caption"
                          sx={{
                            color: cyberColors.text.secondary,
                            fontFamily: designTokens.typography.fontFamily.mono,
                          }}
                        >
                          {anomaly.entityType}
                        </Typography>
                      </Box>
                      <Box sx={{ display: 'flex', alignItems: 'flex-start', gap: 1 }}>
                        <SeverityBadge
                          severity={anomaly.severity}
                          label={severityConfig[anomaly.severity]?.label}
                          size="small"
                        />
                        <IconButton
                          size="small"
                          onClick={(e) => {
                            e.stopPropagation();
                            toggleCardExpanded(anomaly.id);
                          }}
                        >
                          {expandedCards.has(anomaly.id) ? (
                            <ExpandLessIcon fontSize="small" />
                          ) : (
                            <ExpandMoreIcon fontSize="small" />
                          )}
                        </IconButton>
                      </Box>
                    </Box>

                    {/* Anomaly Types */}
                    <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.5, mb: 1 }}>
                      {anomaly.anomalyTypes.map((type) => {
                        const config = anomalyTypeConfig[type];
                        return (
                          <TypeBadge
                            key={type}
                            icon={config.icon}
                            label={config.label}
                            size="small"
                            sx={{
                              bgcolor: alpha(config.color, 0.15),
                              color: config.color,
                              border: `1px solid ${alpha(config.color, 0.3)}`,
                            }}
                          />
                        );
                      })}
                    </Box>

                    {/* Z-Score Bar */}
                    <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                      <Typography
                        variant="caption"
                        sx={{
                          color: cyberColors.text.secondary,
                          fontFamily: designTokens.typography.fontFamily.mono,
                          minWidth: 60,
                        }}
                      >
                        Z: {anomaly.zScore.toFixed(2)}
                      </Typography>
                      <ZScoreBar sx={{ flex: 1 }}>
                        <ZScoreFill
                          severity={anomaly.severity}
                          initial={{ width: 0 }}
                          animate={{ width: `${Math.min(anomaly.zScore * 20, 100)}%` }}
                          transition={{ duration: 0.5, delay: index * 0.1 }}
                        />
                      </ZScoreBar>
                      <Typography
                        variant="caption"
                        sx={{
                          color: cyberColors.text.secondary,
                          fontFamily: designTokens.typography.fontFamily.mono,
                          minWidth: 40,
                        }}
                      >
                        {(anomaly.confidence * 100).toFixed(0)}%
                      </Typography>
                    </Box>

                    {/* Expanded Details */}
                    <Collapse in={expandedCards.has(anomaly.id)}>
                      <Box sx={{ mt: 2, pt: 2, borderTop: `1px solid ${alpha(cyberColors.neon.cyan, 0.1)}` }}>
                        <Typography
                          variant="body2"
                          sx={{ color: cyberColors.text.secondary, mb: 1 }}
                        >
                          {anomaly.description}
                        </Typography>
                        {anomaly.properties && (
                          <Box sx={{ mt: 1 }}>
                            {Object.entries(anomaly.properties).slice(0, 4).map(([key, value]) => (
                              <Typography
                                key={key}
                                variant="caption"
                                sx={{
                                  display: 'block',
                                  fontFamily: designTokens.typography.fontFamily.mono,
                                  color: cyberColors.text.muted,
                                }}
                              >
                                <span style={{ color: cyberColors.neon.cyan }}>{key}:</span>{' '}
                                {String(value).substring(0, 50)}
                              </Typography>
                            ))}
                          </Box>
                        )}
                        {anomaly.detectedAt && (
                          <Typography
                            variant="caption"
                            sx={{
                              color: cyberColors.text.muted,
                              fontFamily: designTokens.typography.fontFamily.mono,
                              mt: 1,
                              display: 'block',
                            }}
                          >
                            Detected: {new Date(anomaly.detectedAt).toLocaleString()}
                          </Typography>
                        )}
                      </Box>
                    </Collapse>
                  </AnomalyCard>
                ))}
              </AnimatePresence>

              {/* Show More Button */}
              {hasMore && (
                <Box sx={{ textAlign: 'center', mt: 2 }}>
                  <Chip
                    label={expanded ? 'Show Less' : `Show ${sortedAnomalies.length - maxVisible} More`}
                    onClick={() => setExpanded(!expanded)}
                    icon={expanded ? <ExpandLessIcon /> : <ExpandMoreIcon />}
                    sx={{
                      bgcolor: alpha(cyberColors.neon.cyan, 0.1),
                      color: cyberColors.neon.cyan,
                      border: `1px solid ${alpha(cyberColors.neon.cyan, 0.3)}`,
                      cursor: 'pointer',
                      '&:hover': {
                        bgcolor: alpha(cyberColors.neon.cyan, 0.2),
                      },
                    }}
                  />
                </Box>
              )}
            </motion.div>
          )}
        </Box>
      )}
    </PanelContainer>
  );
};

export default AnomalyPanel;
