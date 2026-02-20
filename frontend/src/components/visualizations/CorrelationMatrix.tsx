/**
 * CorrelationMatrix Component
 *
 * Multi-source corroboration heatmap showing agreement strength
 * between different intelligence sources.
 *
 * Features:
 * - Source vs source agreement heatmap
 * - Entity type breakdown
 * - Confidence indicators per entity
 * - Corroboration count display
 */

import React, { useState, useMemo } from 'react';
import {
  Box,
  Typography,
  Tooltip,
  Chip,
  IconButton,
  alpha,
  styled,
} from '@mui/material';
import { motion } from 'framer-motion';
import GridViewIcon from '@mui/icons-material/GridView';
import InfoOutlinedIcon from '@mui/icons-material/InfoOutlined';
import { cyberColors, designTokens, glassmorphism } from '../../utils/theme';

// =============================================================================
// Types
// =============================================================================

export interface CorrelatedEntity {
  id: string;
  value: string; // The actual entity value (e.g., IP address, domain)
  type: 'ip' | 'domain' | 'email' | 'hash' | 'url' | 'other';
  sources: string[]; // Which sources reported this entity
  confidence: number; // 0-1 aggregated confidence
  firstSeen?: string;
}

export interface SourceCorrelation {
  source1: string;
  source2: string;
  agreementCount: number; // Number of entities both sources agree on
  agreementStrength: number; // 0-1 normalized agreement
}

export interface CorrelationMatrixProps {
  /** List of correlated entities */
  entities: CorrelatedEntity[];
  /** Source names */
  sources: string[];
  /** Pre-computed correlations (optional, will compute if not provided) */
  correlations?: SourceCorrelation[];
  /** Title */
  title?: string;
  /** Show entity list */
  showEntityList?: boolean;
  /** Max entities to display */
  maxEntities?: number;
  /** Entity click handler */
  onEntityClick?: (entity: CorrelatedEntity) => void;
  /** Test ID */
  testId?: string;
}

// =============================================================================
// Helper Functions
// =============================================================================

const getHeatColor = (value: number): string => {
  if (value >= 0.8) return cyberColors.neon.green;
  if (value >= 0.6) return cyberColors.neon.cyan;
  if (value >= 0.4) return cyberColors.neon.yellow;
  if (value >= 0.2) return cyberColors.neon.orange;
  return cyberColors.neon.red;
};

const entityTypeColors: Record<string, string> = {
  ip: cyberColors.neon.cyan,
  domain: cyberColors.neon.electricBlue,
  email: cyberColors.neon.orange,
  hash: cyberColors.neon.purple,
  url: cyberColors.neon.green,
  other: cyberColors.text.muted,
};

// =============================================================================
// Styled Components
// =============================================================================

const MatrixContainer = styled(Box)(({ theme }) => ({
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
}));

const HeatmapGrid = styled(Box)(({ theme }) => ({
  display: 'grid',
  gap: 2,
  padding: 16,
}));

const HeatmapCell = styled(motion.div)<{ intensity: number }>(({ intensity }) => ({
  aspectRatio: '1',
  borderRadius: designTokens.borderRadius.sm,
  display: 'flex',
  alignItems: 'center',
  justifyContent: 'center',
  cursor: 'pointer',
  background: alpha(getHeatColor(intensity), 0.2),
  border: `1px solid ${alpha(getHeatColor(intensity), 0.4)}`,
  transition: 'all 0.2s ease',
  '&:hover': {
    background: alpha(getHeatColor(intensity), 0.4),
    transform: 'scale(1.05)',
    boxShadow: `0 0 15px ${alpha(getHeatColor(intensity), 0.5)}`,
  },
}));

const SourceLabel = styled(Typography)(({ theme }) => ({
  fontSize: '0.65rem',
  fontFamily: designTokens.typography.fontFamily.mono,
  color: cyberColors.text.secondary,
  overflow: 'hidden',
  textOverflow: 'ellipsis',
  whiteSpace: 'nowrap',
}));

const EntityCard = styled(motion.div)(({ theme }) => ({
  ...glassmorphism.interactive,
  borderRadius: designTokens.borderRadius.sm,
  padding: 10,
  marginBottom: 4,
  cursor: 'pointer',
}));

const ConfidenceBar = styled(Box)(({ theme }) => ({
  height: 4,
  borderRadius: 2,
  background: alpha(cyberColors.dark.ash, 0.5),
  overflow: 'hidden',
  flex: 1,
}));

// =============================================================================
// Component
// =============================================================================

export const CorrelationMatrix: React.FC<CorrelationMatrixProps> = ({
  entities,
  sources,
  correlations: providedCorrelations,
  title = 'Source Correlation Matrix',
  showEntityList = true,
  maxEntities = 10,
  onEntityClick,
  testId,
}) => {
  const [selectedCell, setSelectedCell] = useState<{ s1: string; s2: string } | null>(null);

  // Compute correlations if not provided
  const correlations = useMemo(() => {
    if (providedCorrelations) return providedCorrelations;

    const computed: SourceCorrelation[] = [];
    for (let i = 0; i < sources.length; i++) {
      for (let j = i; j < sources.length; j++) {
        const s1 = sources[i];
        const s2 = sources[j];

        const agreementCount = entities.filter(
          (e) => e.sources.includes(s1) && e.sources.includes(s2)
        ).length;

        const totalUnion = entities.filter(
          (e) => e.sources.includes(s1) || e.sources.includes(s2)
        ).length;

        computed.push({
          source1: s1,
          source2: s2,
          agreementCount,
          agreementStrength: totalUnion > 0 ? agreementCount / totalUnion : 0,
        });
      }
    }
    return computed;
  }, [entities, sources, providedCorrelations]);

  // Create correlation matrix lookup
  const correlationMap = useMemo(() => {
    const map = new Map<string, SourceCorrelation>();
    correlations.forEach((c) => {
      map.set(`${c.source1}-${c.source2}`, c);
      map.set(`${c.source2}-${c.source1}`, c);
    });
    return map;
  }, [correlations]);

  // Get correlation for a cell
  const getCorrelation = (s1: string, s2: string): SourceCorrelation | undefined => {
    return correlationMap.get(`${s1}-${s2}`);
  };

  // Entities corroborated by selected sources
  const selectedEntities = useMemo(() => {
    if (!selectedCell) return [];
    return entities
      .filter(
        (e) =>
          e.sources.includes(selectedCell.s1) && e.sources.includes(selectedCell.s2)
      )
      .sort((a, b) => b.confidence - a.confidence);
  }, [selectedCell, entities]);

  // Entity type breakdown
  const typeBreakdown = useMemo(() => {
    const counts: Record<string, number> = {};
    entities.forEach((e) => {
      counts[e.type] = (counts[e.type] || 0) + 1;
    });
    return counts;
  }, [entities]);

  // Top corroborated entities (by source count)
  const topCorroborated = useMemo(() => {
    return [...entities]
      .sort((a, b) => b.sources.length - a.sources.length)
      .slice(0, maxEntities);
  }, [entities, maxEntities]);

  return (
    <MatrixContainer data-testid={testId}>
      {/* Header */}
      <HeaderSection>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
          <GridViewIcon sx={{ color: cyberColors.neon.cyan }} />
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
              {sources.length} sources | {entities.length} entities correlated
            </Typography>
          </Box>
        </Box>
        <Box sx={{ display: 'flex', gap: 1 }}>
          {Object.entries(typeBreakdown).map(([type, count]) => (
            <Chip
              key={type}
              label={`${type}: ${count}`}
              size="small"
              sx={{
                height: 20,
                fontSize: '0.6rem',
                bgcolor: alpha(entityTypeColors[type] || cyberColors.text.muted, 0.2),
                color: entityTypeColors[type] || cyberColors.text.muted,
              }}
            />
          ))}
        </Box>
      </HeaderSection>

      <Box sx={{ display: 'flex' }}>
        {/* Heatmap */}
        <Box sx={{ flex: 1, p: 2 }}>
          <Box
            sx={{
              display: 'grid',
              gridTemplateColumns: `40px repeat(${sources.length}, 1fr)`,
              gap: '2px',
            }}
          >
            {/* Top-left empty cell */}
            <Box />

            {/* Column headers */}
            {sources.map((source) => (
              <Box
                key={`col-${source}`}
                sx={{
                  textAlign: 'center',
                  transform: 'rotate(-45deg)',
                  transformOrigin: 'center',
                  height: 60,
                  display: 'flex',
                  alignItems: 'flex-end',
                  justifyContent: 'center',
                }}
              >
                <SourceLabel>{source}</SourceLabel>
              </Box>
            ))}

            {/* Rows */}
            {sources.map((rowSource) => (
              <React.Fragment key={`row-${rowSource}`}>
                {/* Row header */}
                <Box
                  sx={{
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'flex-end',
                    pr: 1,
                  }}
                >
                  <SourceLabel>{rowSource}</SourceLabel>
                </Box>

                {/* Cells */}
                {sources.map((colSource) => {
                  const correlation = getCorrelation(rowSource, colSource);
                  const intensity = correlation?.agreementStrength || 0;
                  const isSelected =
                    selectedCell?.s1 === rowSource && selectedCell?.s2 === colSource;
                  const isDiagonal = rowSource === colSource;

                  return (
                    <Tooltip
                      key={`${rowSource}-${colSource}`}
                      title={
                        isDiagonal
                          ? `${rowSource} self`
                          : `${rowSource} + ${colSource}: ${correlation?.agreementCount || 0} entities (${(intensity * 100).toFixed(0)}%)`
                      }
                    >
                      <HeatmapCell
                        intensity={isDiagonal ? 1 : intensity}
                        onClick={() =>
                          !isDiagonal &&
                          setSelectedCell(
                            isSelected ? null : { s1: rowSource, s2: colSource }
                          )
                        }
                        initial={{ opacity: 0, scale: 0.8 }}
                        animate={{ opacity: 1, scale: 1 }}
                        transition={{ delay: Math.random() * 0.3 }}
                        style={{
                          border: isSelected
                            ? `2px solid ${cyberColors.neon.cyan}`
                            : undefined,
                          boxShadow: isSelected
                            ? `0 0 15px ${cyberColors.neon.cyan}`
                            : undefined,
                        }}
                      >
                        <Typography
                          variant="caption"
                          sx={{
                            fontSize: '0.6rem',
                            fontFamily: designTokens.typography.fontFamily.mono,
                            color: getHeatColor(isDiagonal ? 1 : intensity),
                          }}
                        >
                          {isDiagonal ? '-' : correlation?.agreementCount || 0}
                        </Typography>
                      </HeatmapCell>
                    </Tooltip>
                  );
                })}
              </React.Fragment>
            ))}
          </Box>

          {/* Legend */}
          <Box sx={{ mt: 2, display: 'flex', alignItems: 'center', gap: 1 }}>
            <Typography variant="caption" sx={{ color: cyberColors.text.muted }}>
              Agreement:
            </Typography>
            {[0, 0.25, 0.5, 0.75, 1].map((val) => (
              <Box
                key={val}
                sx={{
                  width: 20,
                  height: 20,
                  borderRadius: 2,
                  bgcolor: alpha(getHeatColor(val), 0.4),
                  border: `1px solid ${alpha(getHeatColor(val), 0.6)}`,
                }}
              />
            ))}
            <Typography variant="caption" sx={{ color: cyberColors.text.muted, ml: 1 }}>
              Low → High
            </Typography>
          </Box>
        </Box>

        {/* Entity List */}
        {showEntityList && (
          <Box
            sx={{
              width: 280,
              borderLeft: `1px solid ${alpha(cyberColors.neon.cyan, 0.1)}`,
              p: 2,
              maxHeight: 400,
              overflowY: 'auto',
            }}
          >
            <Typography
              variant="caption"
              sx={{
                color: cyberColors.neon.cyan,
                fontWeight: 600,
                letterSpacing: '0.05em',
                display: 'block',
                mb: 1,
              }}
            >
              {selectedCell
                ? `COMMON ENTITIES (${selectedEntities.length})`
                : `TOP CORROBORATED (${topCorroborated.length})`}
            </Typography>

            {(selectedCell ? selectedEntities : topCorroborated).slice(0, maxEntities).map((entity) => (
              <EntityCard
                key={entity.id}
                onClick={() => onEntityClick?.(entity)}
                whileHover={{ x: 4 }}
              >
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 0.5 }}>
                  <Chip
                    label={entity.type.toUpperCase()}
                    size="small"
                    sx={{
                      height: 16,
                      fontSize: '0.5rem',
                      bgcolor: alpha(entityTypeColors[entity.type], 0.2),
                      color: entityTypeColors[entity.type],
                    }}
                  />
                  <Chip
                    label={`${entity.sources.length} sources`}
                    size="small"
                    sx={{
                      height: 16,
                      fontSize: '0.5rem',
                      bgcolor: alpha(cyberColors.neon.green, 0.2),
                      color: cyberColors.neon.green,
                    }}
                  />
                </Box>
                <Typography
                  variant="caption"
                  sx={{
                    display: 'block',
                    fontFamily: designTokens.typography.fontFamily.mono,
                    color: cyberColors.text.primary,
                    overflow: 'hidden',
                    textOverflow: 'ellipsis',
                    whiteSpace: 'nowrap',
                    fontSize: '0.7rem',
                  }}
                >
                  {entity.value}
                </Typography>
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mt: 0.5 }}>
                  <ConfidenceBar>
                    <motion.div
                      initial={{ width: 0 }}
                      animate={{ width: `${entity.confidence * 100}%` }}
                      style={{
                        height: '100%',
                        borderRadius: 2,
                        background: getHeatColor(entity.confidence),
                      }}
                    />
                  </ConfidenceBar>
                  <Typography
                    variant="caption"
                    sx={{
                      fontSize: '0.55rem',
                      color: cyberColors.text.muted,
                      fontFamily: designTokens.typography.fontFamily.mono,
                    }}
                  >
                    {(entity.confidence * 100).toFixed(0)}%
                  </Typography>
                </Box>
              </EntityCard>
            ))}

            {((selectedCell ? selectedEntities : topCorroborated).length === 0) && (
              <Typography
                variant="caption"
                sx={{ color: cyberColors.text.muted, textAlign: 'center', display: 'block' }}
              >
                No entities found
              </Typography>
            )}
          </Box>
        )}
      </Box>
    </MatrixContainer>
  );
};

export default CorrelationMatrix;
