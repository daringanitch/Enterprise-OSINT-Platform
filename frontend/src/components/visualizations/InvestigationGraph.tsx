/**
 * InvestigationGraph Component
 *
 * Advanced force-directed graph for visualizing investigation entities,
 * relationships, and graph intelligence analysis results.
 *
 * Features:
 * - Centrality-based node sizing (PageRank scores)
 * - Animated edge weights
 * - Entity type clustering with expandable groups
 * - Attack path highlighting
 * - Blast radius mode with ripple animation
 * - Integration with Graph Intelligence API
 */

import React, {
  useEffect,
  useRef,
  useState,
  useCallback,
  useMemo,
} from 'react';
import {
  Box,
  Typography,
  Paper,
  IconButton,
  Tooltip,
  Chip,
  Slider,
  FormControlLabel,
  Switch,
  Menu,
  MenuItem,
  Divider,
  Button,
  alpha,
  styled,
  CircularProgress,
} from '@mui/material';
import { motion, AnimatePresence } from 'framer-motion';
import ZoomInIcon from '@mui/icons-material/ZoomIn';
import ZoomOutIcon from '@mui/icons-material/ZoomOut';
import CenterFocusStrongIcon from '@mui/icons-material/CenterFocusStrong';
import FilterListIcon from '@mui/icons-material/FilterList';
import RouteIcon from '@mui/icons-material/Route';
import BubbleChartIcon from '@mui/icons-material/BubbleChart';
import WarningAmberIcon from '@mui/icons-material/WarningAmber';
import AccountTreeIcon from '@mui/icons-material/AccountTree';
import { cyberColors, designTokens, glassmorphism } from '../../utils/theme';
import { nodeVariants, edgeVariants, rippleVariants } from '../../utils/animations';

// =============================================================================
// Types
// =============================================================================

export interface GraphEntity {
  id: string;
  label: string;
  type: EntityType;
  properties?: Record<string, any>;
  centralityScore?: number;
  isAnomaly?: boolean;
  riskLevel?: 'critical' | 'high' | 'medium' | 'low';
  community?: number;
}

export interface GraphRelationship {
  id: string;
  source: string;
  target: string;
  type: string;
  weight?: number;
  confidence?: number;
  properties?: Record<string, any>;
}

export interface PathResult {
  nodes: string[];
  edges: string[];
  totalWeight: number;
}

export interface BlastRadiusResult {
  affectedNodes: string[];
  impactLevels: Record<string, number>; // node id -> impact level (0-1)
  totalImpact: number;
}

export type EntityType =
  | 'ip_address'
  | 'domain'
  | 'email'
  | 'hash'
  | 'url'
  | 'person'
  | 'organization'
  | 'certificate'
  | 'vulnerability'
  | 'malware'
  | 'threat_actor'
  | 'infrastructure'
  | 'default';

export type VisualizationMode = 'default' | 'centrality' | 'communities' | 'anomalies' | 'blast_radius' | 'path';

export interface InvestigationGraphProps {
  /** Graph entities (nodes) */
  entities: GraphEntity[];
  /** Graph relationships (edges) */
  relationships: GraphRelationship[];
  /** Graph title */
  title?: string;
  /** Width of the graph */
  width?: number | string;
  /** Height of the graph */
  height?: number;
  /** Currently highlighted path */
  highlightedPath?: PathResult | null;
  /** Blast radius analysis results */
  blastRadius?: BlastRadiusResult | null;
  /** Selected entity for blast radius */
  blastRadiusSource?: string | null;
  /** Loading state */
  loading?: boolean;
  /** Visualization mode */
  mode?: VisualizationMode;
  /** Node click handler */
  onNodeClick?: (entity: GraphEntity) => void;
  /** Node double-click handler (for path finding) */
  onNodeDoubleClick?: (entity: GraphEntity) => void;
  /** Find path handler */
  onFindPath?: (sourceId: string, targetId: string) => void;
  /** Blast radius handler */
  onBlastRadius?: (sourceId: string) => void;
  /** Test ID for testing */
  testId?: string;
}

// =============================================================================
// Entity Type Colors and Icons
// =============================================================================

const entityTypeConfig: Record<EntityType, { color: string; icon: string }> = {
  ip_address: { color: cyberColors.neon.cyan, icon: 'IP' },
  domain: { color: cyberColors.neon.electricBlue, icon: 'DN' },
  email: { color: cyberColors.neon.orange, icon: 'EM' },
  hash: { color: cyberColors.neon.purple, icon: 'HS' },
  url: { color: cyberColors.neon.green, icon: 'URL' },
  person: { color: '#ff6b6b', icon: 'PR' },
  organization: { color: '#4ecdc4', icon: 'ORG' },
  certificate: { color: '#95e1d3', icon: 'CRT' },
  vulnerability: { color: cyberColors.neon.red, icon: 'VUL' },
  malware: { color: cyberColors.neon.magenta, icon: 'MAL' },
  threat_actor: { color: '#ff4757', icon: 'TA' },
  infrastructure: { color: '#5352ed', icon: 'INF' },
  default: { color: cyberColors.text.muted, icon: '?' },
};

// =============================================================================
// Styled Components
// =============================================================================

const GraphContainer = styled(Paper)(({ theme }) => ({
  ...glassmorphism.card,
  position: 'relative',
  overflow: 'hidden',
  borderRadius: designTokens.borderRadius.lg,
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

const ModeSelector = styled(Box)(({ theme }) => ({
  position: 'absolute',
  top: 12,
  left: 12,
  display: 'flex',
  gap: 4,
  ...glassmorphism.panel,
  borderRadius: designTokens.borderRadius.md,
  padding: 4,
  zIndex: 10,
}));

const Legend = styled(Box)(({ theme }) => ({
  position: 'absolute',
  bottom: 12,
  left: 12,
  display: 'flex',
  flexWrap: 'wrap',
  gap: 4,
  maxWidth: '60%',
  ...glassmorphism.panel,
  borderRadius: designTokens.borderRadius.md,
  padding: 8,
  zIndex: 10,
}));

const NodeDetailsPanel = styled(motion.div)(({ theme }) => ({
  position: 'absolute',
  bottom: 12,
  right: 12,
  maxWidth: 300,
  ...glassmorphism.card,
  borderRadius: designTokens.borderRadius.md,
  padding: 16,
  zIndex: 10,
}));

const ModeButton = styled(IconButton, {
  shouldForwardProp: (prop) => prop !== 'active',
})<{ active?: boolean }>(({ active }) => ({
  color: active ? cyberColors.neon.cyan : cyberColors.text.secondary,
  background: active ? alpha(cyberColors.neon.cyan, 0.15) : 'transparent',
  border: `1px solid ${active ? cyberColors.neon.cyan : 'transparent'}`,
  '&:hover': {
    background: alpha(cyberColors.neon.cyan, 0.1),
  },
}));

// =============================================================================
// Internal Types for Simulation
// =============================================================================

interface SimulationNode extends GraphEntity {
  x: number;
  y: number;
  vx: number;
  vy: number;
  fx?: number;
  fy?: number;
  radius: number;
}

// =============================================================================
// Component
// =============================================================================

export const InvestigationGraph: React.FC<InvestigationGraphProps> = ({
  entities,
  relationships,
  title,
  width = '100%',
  height = 600,
  highlightedPath,
  blastRadius,
  blastRadiusSource,
  loading = false,
  mode = 'default',
  onNodeClick,
  onNodeDoubleClick,
  onFindPath,
  onBlastRadius,
  testId,
}) => {
  const svgRef = useRef<SVGSVGElement>(null);
  const [zoom, setZoom] = useState(1);
  const [pan, setPan] = useState({ x: 0, y: 0 });
  const [selectedNode, setSelectedNode] = useState<GraphEntity | null>(null);
  const [pathSource, setPathSource] = useState<string | null>(null);
  const [simulationNodes, setSimulationNodes] = useState<SimulationNode[]>([]);
  const [isDragging, setIsDragging] = useState(false);
  const [draggedNode, setDraggedNode] = useState<string | null>(null);
  const [internalMode, setInternalMode] = useState<VisualizationMode>(mode);
  const [showLabels, setShowLabels] = useState(true);
  const [anchorEl, setAnchorEl] = useState<null | HTMLElement>(null);

  // Sync external mode changes
  useEffect(() => {
    setInternalMode(mode);
  }, [mode]);

  // Calculate node radius based on centrality and mode
  const getNodeRadius = useCallback(
    (entity: GraphEntity): number => {
      const baseRadius = 20;
      if (internalMode === 'centrality' && entity.centralityScore !== undefined) {
        return baseRadius + entity.centralityScore * 30;
      }
      if (internalMode === 'blast_radius' && blastRadius) {
        const impact = blastRadius.impactLevels[entity.id];
        if (impact !== undefined) {
          return baseRadius + impact * 25;
        }
      }
      return baseRadius;
    },
    [internalMode, blastRadius]
  );

  // Get node color based on mode and state
  const getNodeColor = useCallback(
    (entity: GraphEntity): string => {
      if (internalMode === 'anomalies' && entity.isAnomaly) {
        return cyberColors.neon.red;
      }
      if (internalMode === 'communities' && entity.community !== undefined) {
        const communityColors = [
          cyberColors.neon.cyan,
          cyberColors.neon.magenta,
          cyberColors.neon.green,
          cyberColors.neon.orange,
          cyberColors.neon.purple,
          cyberColors.neon.electricBlue,
        ];
        return communityColors[entity.community % communityColors.length];
      }
      if (internalMode === 'blast_radius' && blastRadius) {
        if (entity.id === blastRadiusSource) {
          return cyberColors.neon.red;
        }
        const impact = blastRadius.impactLevels[entity.id];
        if (impact !== undefined) {
          // Gradient from orange to red based on impact
          if (impact > 0.7) return cyberColors.neon.red;
          if (impact > 0.4) return cyberColors.neon.orange;
          return cyberColors.neon.yellow;
        }
      }
      if (highlightedPath?.nodes.includes(entity.id)) {
        return cyberColors.neon.cyan;
      }
      return entityTypeConfig[entity.type]?.color || entityTypeConfig.default.color;
    },
    [internalMode, blastRadius, blastRadiusSource, highlightedPath]
  );

  // Check if edge is highlighted
  const isEdgeHighlighted = useCallback(
    (rel: GraphRelationship): boolean => {
      if (highlightedPath?.edges.includes(rel.id)) {
        return true;
      }
      if (blastRadius?.affectedNodes.includes(rel.source) && blastRadius?.affectedNodes.includes(rel.target)) {
        return true;
      }
      return false;
    },
    [highlightedPath, blastRadius]
  );

  // Initialize and run force simulation
  useEffect(() => {
    if (entities.length === 0) return;

    const centerX = 400;
    const centerY = height / 2;

    // Initialize nodes with positions
    const initialNodes: SimulationNode[] = entities.map((entity, i) => {
      const angle = (2 * Math.PI * i) / entities.length;
      const radius = 150 + Math.random() * 100;
      return {
        ...entity,
        x: centerX + radius * Math.cos(angle),
        y: centerY + radius * Math.sin(angle),
        vx: 0,
        vy: 0,
        radius: getNodeRadius(entity),
      };
    });

    const nodeMap = new Map(initialNodes.map((n) => [n.id, n]));

    // Run force simulation
    for (let iteration = 0; iteration < 150; iteration++) {
      // Repulsion between nodes
      for (let i = 0; i < initialNodes.length; i++) {
        for (let j = i + 1; j < initialNodes.length; j++) {
          const nodeA = initialNodes[i];
          const nodeB = initialNodes[j];
          const dx = nodeB.x - nodeA.x;
          const dy = nodeB.y - nodeA.y;
          const distance = Math.sqrt(dx * dx + dy * dy) || 1;
          const minDist = nodeA.radius + nodeB.radius + 40;

          if (distance < minDist * 3) {
            const force = 2000 / (distance * distance);
            const fx = (dx / distance) * force;
            const fy = (dy / distance) * force;

            nodeA.vx -= fx;
            nodeA.vy -= fy;
            nodeB.vx += fx;
            nodeB.vy += fy;
          }
        }
      }

      // Attraction along edges
      relationships.forEach((rel) => {
        const source = nodeMap.get(rel.source);
        const target = nodeMap.get(rel.target);
        if (!source || !target) return;

        const dx = target.x - source.x;
        const dy = target.y - source.y;
        const distance = Math.sqrt(dx * dx + dy * dy) || 1;
        const idealDist = 120;
        const force = (distance - idealDist) * 0.02 * (rel.weight || 1);

        const fx = (dx / distance) * force;
        const fy = (dy / distance) * force;

        source.vx += fx;
        source.vy += fy;
        target.vx -= fx;
        target.vy -= fy;
      });

      // Center gravity
      initialNodes.forEach((node) => {
        node.vx += (centerX - node.x) * 0.002;
        node.vy += (centerY - node.y) * 0.002;
      });

      // Apply velocities with damping
      initialNodes.forEach((node) => {
        if (node.fx === undefined) {
          node.x += node.vx * 0.5;
          node.y += node.vy * 0.5;
        }
        node.vx *= 0.85;
        node.vy *= 0.85;
      });
    }

    setSimulationNodes([...initialNodes]);
  }, [entities, relationships, height, getNodeRadius]);

  // Handlers
  const handleZoomIn = () => setZoom((z) => Math.min(z + 0.2, 3));
  const handleZoomOut = () => setZoom((z) => Math.max(z - 0.2, 0.3));
  const handleReset = () => {
    setZoom(1);
    setPan({ x: 0, y: 0 });
  };

  const handleNodeClick = useCallback(
    (entity: GraphEntity, event: React.MouseEvent) => {
      event.stopPropagation();

      if (internalMode === 'path' && pathSource) {
        // Complete path finding
        if (pathSource !== entity.id) {
          onFindPath?.(pathSource, entity.id);
        }
        setPathSource(null);
      } else if (internalMode === 'blast_radius') {
        onBlastRadius?.(entity.id);
      } else {
        setSelectedNode(entity.id === selectedNode?.id ? null : entity);
        onNodeClick?.(entity);
      }
    },
    [internalMode, pathSource, selectedNode, onNodeClick, onFindPath, onBlastRadius]
  );

  const handleNodeDoubleClick = useCallback(
    (entity: GraphEntity) => {
      if (internalMode === 'path') {
        setPathSource(entity.id);
      } else {
        onNodeDoubleClick?.(entity);
      }
    },
    [internalMode, onNodeDoubleClick]
  );

  const handleBackgroundClick = () => {
    setSelectedNode(null);
    setPathSource(null);
  };

  const nodeMap = useMemo(
    () => new Map(simulationNodes.map((n) => [n.id, n])),
    [simulationNodes]
  );

  // Entity types present in the graph
  const presentTypes = useMemo(
    () => Array.from(new Set(entities.map((e) => e.type))),
    [entities]
  );

  if (loading) {
    return (
      <GraphContainer data-testid={testId} sx={{ width, height }}>
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
          <CircularProgress sx={{ color: cyberColors.neon.cyan }} />
          <Typography color="text.secondary">Loading graph data...</Typography>
        </Box>
      </GraphContainer>
    );
  }

  if (entities.length === 0) {
    return (
      <GraphContainer data-testid={testId} sx={{ width, height }}>
        <Box
          sx={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            height: '100%',
          }}
        >
          <Typography color="text.secondary">No entities to display</Typography>
        </Box>
      </GraphContainer>
    );
  }

  return (
    <GraphContainer data-testid={testId} sx={{ width }}>
      {title && (
        <Typography
          variant="h6"
          sx={{
            p: 2,
            pb: 1,
            fontFamily: designTokens.typography.fontFamily.display,
            color: cyberColors.neon.cyan,
            textShadow: `0 0 10px ${alpha(cyberColors.neon.cyan, 0.5)}`,
          }}
        >
          {title}
        </Typography>
      )}

      {/* Mode Selector */}
      <ModeSelector>
        <Tooltip title="Default View">
          <ModeButton
            size="small"
            active={internalMode === 'default'}
            onClick={() => setInternalMode('default')}
          >
            <BubbleChartIcon fontSize="small" />
          </ModeButton>
        </Tooltip>
        <Tooltip title="Centrality Analysis">
          <ModeButton
            size="small"
            active={internalMode === 'centrality'}
            onClick={() => setInternalMode('centrality')}
          >
            <AccountTreeIcon fontSize="small" />
          </ModeButton>
        </Tooltip>
        <Tooltip title="Path Finding (double-click to select nodes)">
          <ModeButton
            size="small"
            active={internalMode === 'path'}
            onClick={() => setInternalMode('path')}
          >
            <RouteIcon fontSize="small" />
          </ModeButton>
        </Tooltip>
        <Tooltip title="Blast Radius Analysis">
          <ModeButton
            size="small"
            active={internalMode === 'blast_radius'}
            onClick={() => setInternalMode('blast_radius')}
          >
            <WarningAmberIcon fontSize="small" />
          </ModeButton>
        </Tooltip>
      </ModeSelector>

      {/* Control Panel */}
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
        <Divider sx={{ my: 0.5 }} />
        <Tooltip title="Toggle Labels">
          <IconButton
            size="small"
            onClick={() => setShowLabels(!showLabels)}
            sx={{ color: showLabels ? cyberColors.neon.cyan : undefined }}
          >
            <FilterListIcon fontSize="small" />
          </IconButton>
        </Tooltip>
      </ControlPanel>

      {/* SVG Graph */}
      <svg
        ref={svgRef}
        width="100%"
        height={height}
        style={{ cursor: isDragging ? 'grabbing' : 'grab' }}
        onClick={handleBackgroundClick}
      >
        {/* Definitions for effects */}
        <defs>
          {/* Glow filter */}
          <filter id="glow" x="-50%" y="-50%" width="200%" height="200%">
            <feGaussianBlur stdDeviation="4" result="coloredBlur" />
            <feMerge>
              <feMergeNode in="coloredBlur" />
              <feMergeNode in="SourceGraphic" />
            </feMerge>
          </filter>
          {/* Animated gradient for edges */}
          <linearGradient id="edgeGradient" x1="0%" y1="0%" x2="100%" y2="0%">
            <stop offset="0%" stopColor={cyberColors.neon.cyan}>
              <animate
                attributeName="stop-color"
                values={`${cyberColors.neon.cyan};${cyberColors.neon.magenta};${cyberColors.neon.cyan}`}
                dur="3s"
                repeatCount="indefinite"
              />
            </stop>
            <stop offset="100%" stopColor={cyberColors.neon.magenta}>
              <animate
                attributeName="stop-color"
                values={`${cyberColors.neon.magenta};${cyberColors.neon.cyan};${cyberColors.neon.magenta}`}
                dur="3s"
                repeatCount="indefinite"
              />
            </stop>
          </linearGradient>
        </defs>

        <g transform={`translate(${pan.x}, ${pan.y}) scale(${zoom})`}>
          {/* Edges */}
          {relationships.map((rel) => {
            const source = nodeMap.get(rel.source);
            const target = nodeMap.get(rel.target);
            if (!source || !target) return null;

            const isHighlighted = isEdgeHighlighted(rel);
            const strokeWidth = isHighlighted ? 3 : (rel.weight || 1);
            const strokeColor = isHighlighted
              ? 'url(#edgeGradient)'
              : alpha(cyberColors.text.muted, 0.3);

            return (
              <motion.line
                key={rel.id}
                x1={source.x}
                y1={source.y}
                x2={target.x}
                y2={target.y}
                stroke={strokeColor}
                strokeWidth={strokeWidth}
                strokeOpacity={isHighlighted ? 1 : 0.5}
                filter={isHighlighted ? 'url(#glow)' : undefined}
                initial={{ pathLength: 0, opacity: 0 }}
                animate={{ pathLength: 1, opacity: 1 }}
                transition={{ duration: 0.5, delay: Math.random() * 0.3 }}
              />
            );
          })}

          {/* Blast radius ripples */}
          <AnimatePresence>
            {internalMode === 'blast_radius' && blastRadiusSource && (
              <motion.circle
                cx={nodeMap.get(blastRadiusSource)?.x || 0}
                cy={nodeMap.get(blastRadiusSource)?.y || 0}
                r={20}
                fill="none"
                stroke={cyberColors.neon.red}
                strokeWidth={2}
                variants={rippleVariants}
                initial="initial"
                animate="animate"
                key="ripple"
              />
            )}
          </AnimatePresence>

          {/* Nodes */}
          {simulationNodes.map((node, index) => {
            const nodeColor = getNodeColor(node);
            const isSelected = selectedNode?.id === node.id;
            const isPathSource = pathSource === node.id;
            const config = entityTypeConfig[node.type] || entityTypeConfig.default;

            return (
              <motion.g
                key={node.id}
                initial={{ scale: 0, opacity: 0 }}
                animate={{ scale: 1, opacity: 1 }}
                transition={{ delay: index * 0.02, type: 'spring', stiffness: 300 }}
                style={{ cursor: 'pointer' }}
                onClick={(e) => handleNodeClick(node, e as any)}
                onDoubleClick={() => handleNodeDoubleClick(node)}
              >
                {/* Selection/path source ring */}
                {(isSelected || isPathSource) && (
                  <motion.circle
                    cx={node.x}
                    cy={node.y}
                    r={node.radius + 8}
                    fill="none"
                    stroke={isPathSource ? cyberColors.neon.magenta : cyberColors.neon.cyan}
                    strokeWidth={2}
                    strokeDasharray="4 4"
                    filter="url(#glow)"
                    animate={{ rotate: 360 }}
                    transition={{ duration: 10, repeat: Infinity, ease: 'linear' }}
                    style={{ transformOrigin: `${node.x}px ${node.y}px` }}
                  />
                )}

                {/* Node glow */}
                <circle
                  cx={node.x}
                  cy={node.y}
                  r={node.radius + 4}
                  fill={alpha(nodeColor, 0.2)}
                  filter="url(#glow)"
                />

                {/* Node circle */}
                <motion.circle
                  cx={node.x}
                  cy={node.y}
                  r={node.radius}
                  fill={alpha(cyberColors.dark.midnight, 0.9)}
                  stroke={nodeColor}
                  strokeWidth={2}
                  whileHover={{ scale: 1.1 }}
                  whileTap={{ scale: 0.95 }}
                />

                {/* Node icon */}
                <text
                  x={node.x}
                  y={node.y + 4}
                  fill={nodeColor}
                  fontSize={10}
                  fontWeight="bold"
                  textAnchor="middle"
                  fontFamily={designTokens.typography.fontFamily.mono}
                  style={{ pointerEvents: 'none' }}
                >
                  {config.icon}
                </text>

                {/* Label */}
                {showLabels && (
                  <text
                    x={node.x}
                    y={node.y + node.radius + 16}
                    fill={cyberColors.text.primary}
                    fontSize={11}
                    textAnchor="middle"
                    fontFamily={designTokens.typography.fontFamily.mono}
                    style={{ pointerEvents: 'none' }}
                  >
                    {node.label.length > 20
                      ? `${node.label.substring(0, 20)}...`
                      : node.label}
                  </text>
                )}

                {/* Anomaly indicator */}
                {node.isAnomaly && (
                  <circle
                    cx={node.x + node.radius - 4}
                    cy={node.y - node.radius + 4}
                    r={6}
                    fill={cyberColors.neon.red}
                    filter="url(#glow)"
                  />
                )}

                {/* Risk level indicator */}
                {node.riskLevel && (
                  <circle
                    cx={node.x - node.radius + 4}
                    cy={node.y - node.radius + 4}
                    r={5}
                    fill={
                      node.riskLevel === 'critical'
                        ? cyberColors.neon.magenta
                        : node.riskLevel === 'high'
                        ? cyberColors.neon.red
                        : node.riskLevel === 'medium'
                        ? cyberColors.neon.orange
                        : cyberColors.neon.green
                    }
                  />
                )}
              </motion.g>
            );
          })}
        </g>
      </svg>

      {/* Legend */}
      <Legend>
        {presentTypes.map((type) => {
          const config = entityTypeConfig[type] || entityTypeConfig.default;
          return (
            <Chip
              key={type}
              label={type.replace('_', ' ')}
              size="small"
              sx={{
                bgcolor: alpha(config.color, 0.2),
                color: config.color,
                borderColor: config.color,
                border: '1px solid',
                fontSize: '0.7rem',
                height: 24,
                '& .MuiChip-label': {
                  textTransform: 'uppercase',
                  letterSpacing: '0.05em',
                },
              }}
            />
          );
        })}
      </Legend>

      {/* Mode-specific instructions */}
      {internalMode === 'path' && (
        <Box
          sx={{
            position: 'absolute',
            top: '50%',
            left: '50%',
            transform: 'translate(-50%, -50%)',
            ...glassmorphism.panel,
            p: 2,
            borderRadius: designTokens.borderRadius.md,
            textAlign: 'center',
            display: pathSource ? 'none' : 'block',
          }}
        >
          <Typography variant="body2" color="text.secondary">
            Double-click a node to set it as the path source
          </Typography>
        </Box>
      )}

      {pathSource && (
        <Box
          sx={{
            position: 'absolute',
            top: 60,
            left: 12,
            ...glassmorphism.panel,
            p: 1,
            borderRadius: designTokens.borderRadius.sm,
          }}
        >
          <Typography variant="caption" sx={{ color: cyberColors.neon.magenta }}>
            Click another node to find path
          </Typography>
        </Box>
      )}

      {/* Selected Node Details */}
      <AnimatePresence>
        {selectedNode && (
          <NodeDetailsPanel
            initial={{ opacity: 0, x: 20 }}
            animate={{ opacity: 1, x: 0 }}
            exit={{ opacity: 0, x: 20 }}
          >
            <Typography
              variant="subtitle2"
              sx={{
                color: getNodeColor(selectedNode),
                fontFamily: designTokens.typography.fontFamily.display,
                mb: 1,
              }}
            >
              {selectedNode.label}
            </Typography>
            <Box sx={{ display: 'flex', gap: 1, mb: 1 }}>
              <Chip
                label={selectedNode.type.replace('_', ' ')}
                size="small"
                sx={{
                  bgcolor: alpha(getNodeColor(selectedNode), 0.2),
                  color: getNodeColor(selectedNode),
                  fontSize: '0.7rem',
                }}
              />
              {selectedNode.riskLevel && (
                <Chip
                  label={selectedNode.riskLevel}
                  size="small"
                  sx={{
                    bgcolor: alpha(
                      selectedNode.riskLevel === 'critical'
                        ? cyberColors.neon.magenta
                        : selectedNode.riskLevel === 'high'
                        ? cyberColors.neon.red
                        : selectedNode.riskLevel === 'medium'
                        ? cyberColors.neon.orange
                        : cyberColors.neon.green,
                      0.2
                    ),
                    fontSize: '0.7rem',
                  }}
                />
              )}
            </Box>
            {selectedNode.centralityScore !== undefined && (
              <Typography
                variant="caption"
                sx={{ display: 'block', color: cyberColors.text.secondary }}
              >
                Centrality: {(selectedNode.centralityScore * 100).toFixed(1)}%
              </Typography>
            )}
            {selectedNode.properties && (
              <Box sx={{ mt: 1 }}>
                {Object.entries(selectedNode.properties)
                  .slice(0, 4)
                  .map(([key, value]) => (
                    <Typography
                      key={key}
                      variant="caption"
                      sx={{
                        display: 'block',
                        fontFamily: designTokens.typography.fontFamily.mono,
                        color: cyberColors.text.secondary,
                      }}
                    >
                      <span style={{ color: cyberColors.neon.cyan }}>{key}:</span>{' '}
                      {String(value).substring(0, 30)}
                    </Typography>
                  ))}
              </Box>
            )}
            <Box sx={{ mt: 2, display: 'flex', gap: 1 }}>
              <Button
                size="small"
                variant="outlined"
                onClick={() => onBlastRadius?.(selectedNode.id)}
                sx={{
                  fontSize: '0.7rem',
                  borderColor: cyberColors.neon.red,
                  color: cyberColors.neon.red,
                }}
              >
                Blast Radius
              </Button>
            </Box>
          </NodeDetailsPanel>
        )}
      </AnimatePresence>
    </GraphContainer>
  );
};

export default InvestigationGraph;
