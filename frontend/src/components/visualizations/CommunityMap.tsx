/**
 * CommunityMap Component
 *
 * Visualizes entity clusters from community detection algorithms.
 * Shows color-coded communities with size indicators and inter-community edges.
 *
 * Features:
 * - Color-coded communities (Louvain algorithm results)
 * - Community size indicators
 * - Inter-community edges
 * - Cohesion metrics display
 * - Expandable community details
 */

import React, { useState, useMemo, useCallback } from 'react';
import {
  Box,
  Typography,
  Paper,
  Chip,
  Tooltip,
  IconButton,
  Collapse,
  LinearProgress,
  alpha,
  styled,
} from '@mui/material';
import { motion, AnimatePresence } from 'framer-motion';
import GroupWorkIcon from '@mui/icons-material/GroupWork';
import ExpandMoreIcon from '@mui/icons-material/ExpandMore';
import ExpandLessIcon from '@mui/icons-material/ExpandLess';
import ZoomInIcon from '@mui/icons-material/ZoomIn';
import ZoomOutIcon from '@mui/icons-material/ZoomOut';
import CenterFocusStrongIcon from '@mui/icons-material/CenterFocusStrong';
import { cyberColors, designTokens, glassmorphism } from '../../utils/theme';
import { staggerContainer, staggerItem } from '../../utils/animations';

// =============================================================================
// Types
// =============================================================================

export interface CommunityEntity {
  id: string;
  label: string;
  type: string;
  communityId: number;
  centralityScore?: number;
}

export interface Community {
  id: number;
  name?: string;
  entities: CommunityEntity[];
  cohesion: number; // 0-1 measure of internal connectivity
  density: number; // 0-1 measure of edge density
  avgClusteringCoefficient?: number;
  bridgeNodes?: string[]; // Nodes connecting to other communities
}

export interface InterCommunityEdge {
  source: number;
  target: number;
  weight: number; // Number of cross-community connections
}

export interface CommunityMapProps {
  /** Detected communities */
  communities: Community[];
  /** Inter-community connections */
  interCommunityEdges: InterCommunityEdge[];
  /** Title */
  title?: string;
  /** Width */
  width?: number | string;
  /** Height */
  height?: number;
  /** Loading state */
  loading?: boolean;
  /** Community click handler */
  onCommunityClick?: (community: Community) => void;
  /** Entity click handler */
  onEntityClick?: (entity: CommunityEntity) => void;
  /** Test ID */
  testId?: string;
}

// =============================================================================
// Color Palette for Communities
// =============================================================================

const communityColors = [
  cyberColors.neon.cyan,
  cyberColors.neon.magenta,
  cyberColors.neon.green,
  cyberColors.neon.orange,
  cyberColors.neon.purple,
  cyberColors.neon.electricBlue,
  cyberColors.neon.yellow,
  '#ff6b6b',
  '#4ecdc4',
  '#95e1d3',
  '#ffeaa7',
  '#dfe6e9',
];

const getCommunityColor = (id: number): string => {
  return communityColors[id % communityColors.length];
};

// =============================================================================
// Styled Components
// =============================================================================

const MapContainer = styled(Paper)(({ theme }) => ({
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

const ControlPanel = styled(Box)(({ theme }) => ({
  position: 'absolute',
  top: 12,
  right: 12,
  display: 'flex',
  flexDirection: 'column',
  gap: 4,
  ...glassmorphism.panel,
  borderRadius: designTokens.borderRadius.md,
  padding: 8,
  zIndex: 10,
}));

const CommunityBubble = styled(motion.g)(({ theme }) => ({
  cursor: 'pointer',
}));

const CommunityCard = styled(motion.div)(({ theme }) => ({
  ...glassmorphism.interactive,
  borderRadius: designTokens.borderRadius.md,
  padding: 12,
  marginBottom: 8,
  cursor: 'pointer',
}));

const MetricBar = styled(Box)(({ theme }) => ({
  height: 4,
  borderRadius: 2,
  background: alpha(cyberColors.dark.ash, 0.5),
  overflow: 'hidden',
  flex: 1,
}));

const MetricFill = styled(motion.div)<{ color: string }>(({ color }) => ({
  height: '100%',
  borderRadius: 2,
  background: color,
  boxShadow: `0 0 8px ${color}`,
}));

// =============================================================================
// Component
// =============================================================================

export const CommunityMap: React.FC<CommunityMapProps> = ({
  communities,
  interCommunityEdges,
  title = 'Community Detection',
  width = '100%',
  height = 500,
  loading = false,
  onCommunityClick,
  onEntityClick,
  testId,
}) => {
  const [zoom, setZoom] = useState(1);
  const [pan, setPan] = useState({ x: 0, y: 0 });
  const [selectedCommunity, setSelectedCommunity] = useState<Community | null>(null);
  const [expandedCommunities, setExpandedCommunities] = useState<Set<number>>(new Set());
  const [viewMode, setViewMode] = useState<'bubble' | 'list'>('bubble');

  // Calculate community positions in a circular layout
  const communityPositions = useMemo(() => {
    const centerX = 300;
    const centerY = height / 2 - 40;
    const baseRadius = Math.min(200, height / 3);

    return communities.map((community, index) => {
      const angle = (2 * Math.PI * index) / communities.length - Math.PI / 2;
      const entityCount = community.entities.length;
      const bubbleRadius = 30 + Math.sqrt(entityCount) * 8;

      return {
        ...community,
        x: centerX + baseRadius * Math.cos(angle),
        y: centerY + baseRadius * Math.sin(angle),
        radius: bubbleRadius,
        color: getCommunityColor(community.id),
      };
    });
  }, [communities, height]);

  // Summary stats
  const totalEntities = communities.reduce((sum, c) => sum + c.entities.length, 0);
  const avgCohesion = communities.length > 0
    ? communities.reduce((sum, c) => sum + c.cohesion, 0) / communities.length
    : 0;

  const handleCommunityClick = useCallback(
    (community: Community) => {
      setSelectedCommunity(community.id === selectedCommunity?.id ? null : community);
      onCommunityClick?.(community);
    },
    [selectedCommunity, onCommunityClick]
  );

  const toggleExpanded = (communityId: number) => {
    setExpandedCommunities((prev) => {
      const next = new Set(prev);
      if (next.has(communityId)) {
        next.delete(communityId);
      } else {
        next.add(communityId);
      }
      return next;
    });
  };

  const handleZoomIn = () => setZoom((z) => Math.min(z + 0.2, 2));
  const handleZoomOut = () => setZoom((z) => Math.max(z - 0.2, 0.5));
  const handleReset = () => {
    setZoom(1);
    setPan({ x: 0, y: 0 });
  };

  if (loading) {
    return (
      <MapContainer data-testid={testId} sx={{ width, height }}>
        <Box
          sx={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            height: '100%',
            flexDirection: 'column',
            gap: 2,
          }}
        >
          <Typography color="text.secondary">Running community detection...</Typography>
          <LinearProgress
            sx={{
              width: 200,
              bgcolor: alpha(cyberColors.neon.cyan, 0.1),
              '& .MuiLinearProgress-bar': {
                background: designTokens.colors.gradients.primary,
              },
            }}
          />
        </Box>
      </MapContainer>
    );
  }

  return (
    <MapContainer data-testid={testId} sx={{ width }}>
      {/* Header */}
      <HeaderSection>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
          <GroupWorkIcon sx={{ color: cyberColors.neon.cyan }} />
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
              {communities.length} communities | {totalEntities} entities
            </Typography>
          </Box>
        </Box>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
          <Chip
            label={`Avg Cohesion: ${(avgCohesion * 100).toFixed(0)}%`}
            size="small"
            sx={{
              bgcolor: alpha(cyberColors.neon.cyan, 0.15),
              color: cyberColors.neon.cyan,
              fontFamily: designTokens.typography.fontFamily.mono,
              fontSize: '0.7rem',
            }}
          />
        </Box>
      </HeaderSection>

      {/* Bubble Map View */}
      <Box sx={{ position: 'relative', height: height - 80 }}>
        {/* Controls */}
        <ControlPanel>
          <Tooltip title="Zoom In">
            <IconButton size="small" onClick={handleZoomIn}>
              <ZoomInIcon fontSize="small" />
            </IconButton>
          </Tooltip>
          <Tooltip title="Zoom Out">
            <IconButton size="small" onClick={handleZoomOut}>
              <ZoomOutIcon fontSize="small" />
            </IconButton>
          </Tooltip>
          <Tooltip title="Reset View">
            <IconButton size="small" onClick={handleReset}>
              <CenterFocusStrongIcon fontSize="small" />
            </IconButton>
          </Tooltip>
        </ControlPanel>

        <svg width="100%" height={height - 80} style={{ overflow: 'visible' }}>
          <defs>
            <filter id="communityGlow" x="-50%" y="-50%" width="200%" height="200%">
              <feGaussianBlur stdDeviation="4" result="coloredBlur" />
              <feMerge>
                <feMergeNode in="coloredBlur" />
                <feMergeNode in="SourceGraphic" />
              </feMerge>
            </filter>
          </defs>

          <g transform={`translate(${pan.x}, ${pan.y}) scale(${zoom})`}>
            {/* Inter-community edges */}
            {interCommunityEdges.map((edge, index) => {
              const source = communityPositions.find((c) => c.id === edge.source);
              const target = communityPositions.find((c) => c.id === edge.target);
              if (!source || !target) return null;

              const strokeWidth = Math.max(1, Math.min(edge.weight / 2, 5));
              return (
                <motion.line
                  key={`edge-${index}`}
                  x1={source.x}
                  y1={source.y}
                  x2={target.x}
                  y2={target.y}
                  stroke={alpha(cyberColors.text.muted, 0.3)}
                  strokeWidth={strokeWidth}
                  strokeDasharray="4 4"
                  initial={{ pathLength: 0 }}
                  animate={{ pathLength: 1 }}
                  transition={{ duration: 1, delay: index * 0.1 }}
                />
              );
            })}

            {/* Community bubbles */}
            {communityPositions.map((community, index) => {
              const isSelected = selectedCommunity?.id === community.id;
              return (
                <CommunityBubble
                  key={community.id}
                  onClick={() => handleCommunityClick(community)}
                  initial={{ scale: 0, opacity: 0 }}
                  animate={{ scale: 1, opacity: 1 }}
                  transition={{ delay: index * 0.1, type: 'spring', stiffness: 200 }}
                >
                  {/* Glow ring when selected */}
                  {isSelected && (
                    <motion.circle
                      cx={community.x}
                      cy={community.y}
                      r={community.radius + 10}
                      fill="none"
                      stroke={community.color}
                      strokeWidth={2}
                      strokeDasharray="6 3"
                      filter="url(#communityGlow)"
                      animate={{ rotate: 360 }}
                      transition={{ duration: 20, repeat: Infinity, ease: 'linear' }}
                      style={{ transformOrigin: `${community.x}px ${community.y}px` }}
                    />
                  )}

                  {/* Outer glow */}
                  <circle
                    cx={community.x}
                    cy={community.y}
                    r={community.radius + 4}
                    fill={alpha(community.color, 0.15)}
                    filter="url(#communityGlow)"
                  />

                  {/* Main bubble */}
                  <motion.circle
                    cx={community.x}
                    cy={community.y}
                    r={community.radius}
                    fill={alpha(cyberColors.dark.midnight, 0.8)}
                    stroke={community.color}
                    strokeWidth={2}
                    whileHover={{ scale: 1.05 }}
                    whileTap={{ scale: 0.95 }}
                  />

                  {/* Cohesion ring (inner) */}
                  <circle
                    cx={community.x}
                    cy={community.y}
                    r={community.radius * 0.7}
                    fill="none"
                    stroke={community.color}
                    strokeWidth={3}
                    strokeDasharray={`${community.cohesion * 220} 220`}
                    transform={`rotate(-90 ${community.x} ${community.y})`}
                    opacity={0.5}
                  />

                  {/* Entity count */}
                  <text
                    x={community.x}
                    y={community.y}
                    textAnchor="middle"
                    dominantBaseline="middle"
                    fill={community.color}
                    fontSize={community.radius > 40 ? 16 : 12}
                    fontWeight="bold"
                    fontFamily={designTokens.typography.fontFamily.mono}
                  >
                    {community.entities.length}
                  </text>

                  {/* Community label */}
                  {community.radius > 35 && (
                    <text
                      x={community.x}
                      y={community.y + community.radius + 16}
                      textAnchor="middle"
                      fill={cyberColors.text.secondary}
                      fontSize={10}
                      fontFamily={designTokens.typography.fontFamily.mono}
                    >
                      {community.name || `Community ${community.id + 1}`}
                    </text>
                  )}
                </CommunityBubble>
              );
            })}
          </g>
        </svg>

        {/* Selected Community Details */}
        <AnimatePresence>
          {selectedCommunity && (
            <motion.div
              initial={{ opacity: 0, x: 20 }}
              animate={{ opacity: 1, x: 0 }}
              exit={{ opacity: 0, x: 20 }}
              style={{
                position: 'absolute',
                bottom: 12,
                right: 12,
                maxWidth: 280,
                ...glassmorphism.card,
                borderRadius: designTokens.borderRadius.md,
                padding: 16,
                zIndex: 10,
              }}
            >
              <Typography
                variant="subtitle2"
                sx={{
                  color: getCommunityColor(selectedCommunity.id),
                  fontFamily: designTokens.typography.fontFamily.display,
                  mb: 1,
                }}
              >
                {selectedCommunity.name || `Community ${selectedCommunity.id + 1}`}
              </Typography>

              <Box sx={{ display: 'flex', gap: 1, mb: 2 }}>
                <Chip
                  label={`${selectedCommunity.entities.length} entities`}
                  size="small"
                  sx={{
                    bgcolor: alpha(getCommunityColor(selectedCommunity.id), 0.2),
                    color: getCommunityColor(selectedCommunity.id),
                    fontSize: '0.7rem',
                  }}
                />
              </Box>

              {/* Metrics */}
              <Box sx={{ mb: 2 }}>
                <Box sx={{ display: 'flex', alignItems: 'center', mb: 1 }}>
                  <Typography
                    variant="caption"
                    sx={{ color: cyberColors.text.secondary, minWidth: 70 }}
                  >
                    Cohesion
                  </Typography>
                  <MetricBar>
                    <MetricFill
                      color={getCommunityColor(selectedCommunity.id)}
                      initial={{ width: 0 }}
                      animate={{ width: `${selectedCommunity.cohesion * 100}%` }}
                    />
                  </MetricBar>
                  <Typography
                    variant="caption"
                    sx={{
                      color: cyberColors.text.secondary,
                      ml: 1,
                      fontFamily: designTokens.typography.fontFamily.mono,
                      minWidth: 35,
                    }}
                  >
                    {(selectedCommunity.cohesion * 100).toFixed(0)}%
                  </Typography>
                </Box>

                <Box sx={{ display: 'flex', alignItems: 'center' }}>
                  <Typography
                    variant="caption"
                    sx={{ color: cyberColors.text.secondary, minWidth: 70 }}
                  >
                    Density
                  </Typography>
                  <MetricBar>
                    <MetricFill
                      color={cyberColors.neon.cyan}
                      initial={{ width: 0 }}
                      animate={{ width: `${selectedCommunity.density * 100}%` }}
                    />
                  </MetricBar>
                  <Typography
                    variant="caption"
                    sx={{
                      color: cyberColors.text.secondary,
                      ml: 1,
                      fontFamily: designTokens.typography.fontFamily.mono,
                      minWidth: 35,
                    }}
                  >
                    {(selectedCommunity.density * 100).toFixed(0)}%
                  </Typography>
                </Box>
              </Box>

              {/* Entity Preview */}
              <Typography
                variant="caption"
                sx={{ color: cyberColors.text.muted, display: 'block', mb: 1 }}
              >
                Top Entities:
              </Typography>
              <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.5 }}>
                {selectedCommunity.entities.slice(0, 5).map((entity) => (
                  <Chip
                    key={entity.id}
                    label={entity.label.substring(0, 15)}
                    size="small"
                    onClick={() => onEntityClick?.(entity)}
                    sx={{
                      height: 20,
                      fontSize: '0.6rem',
                      bgcolor: alpha(cyberColors.neon.cyan, 0.1),
                      cursor: 'pointer',
                      '&:hover': {
                        bgcolor: alpha(cyberColors.neon.cyan, 0.2),
                      },
                    }}
                  />
                ))}
                {selectedCommunity.entities.length > 5 && (
                  <Chip
                    label={`+${selectedCommunity.entities.length - 5} more`}
                    size="small"
                    sx={{
                      height: 20,
                      fontSize: '0.6rem',
                      bgcolor: alpha(cyberColors.text.muted, 0.2),
                    }}
                  />
                )}
              </Box>

              {/* Bridge nodes */}
              {selectedCommunity.bridgeNodes && selectedCommunity.bridgeNodes.length > 0 && (
                <Box sx={{ mt: 2 }}>
                  <Typography
                    variant="caption"
                    sx={{ color: cyberColors.neon.orange, display: 'block', mb: 0.5 }}
                  >
                    Bridge Nodes ({selectedCommunity.bridgeNodes.length}):
                  </Typography>
                  <Typography
                    variant="caption"
                    sx={{
                      color: cyberColors.text.secondary,
                      fontFamily: designTokens.typography.fontFamily.mono,
                    }}
                  >
                    {selectedCommunity.bridgeNodes.slice(0, 3).join(', ')}
                    {selectedCommunity.bridgeNodes.length > 3 && '...'}
                  </Typography>
                </Box>
              )}
            </motion.div>
          )}
        </AnimatePresence>
      </Box>

      {/* Legend */}
      <Box
        sx={{
          p: 2,
          pt: 1,
          borderTop: `1px solid ${alpha(cyberColors.neon.cyan, 0.1)}`,
          display: 'flex',
          flexWrap: 'wrap',
          gap: 1,
        }}
      >
        {communities.slice(0, 8).map((community) => (
          <Chip
            key={community.id}
            label={community.name || `C${community.id + 1}`}
            size="small"
            onClick={() => handleCommunityClick(community)}
            sx={{
              bgcolor: alpha(getCommunityColor(community.id), 0.15),
              color: getCommunityColor(community.id),
              border: `1px solid ${alpha(getCommunityColor(community.id), 0.3)}`,
              fontSize: '0.7rem',
              cursor: 'pointer',
              '&:hover': {
                bgcolor: alpha(getCommunityColor(community.id), 0.25),
              },
            }}
          />
        ))}
        {communities.length > 8 && (
          <Chip
            label={`+${communities.length - 8} more`}
            size="small"
            sx={{
              bgcolor: alpha(cyberColors.text.muted, 0.2),
              fontSize: '0.7rem',
            }}
          />
        )}
      </Box>
    </MapContainer>
  );
};

export default CommunityMap;
