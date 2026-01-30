/**
 * NetworkGraph Component
 *
 * Force-directed graph for visualizing entity relationships and connections.
 */

import React, { useEffect, useRef, useMemo, useState, useCallback } from 'react';
import { Box, Typography, useTheme, Paper, Chip, IconButton, Tooltip } from '@mui/material';
import ZoomInIcon from '@mui/icons-material/ZoomIn';
import ZoomOutIcon from '@mui/icons-material/ZoomOut';
import CenterFocusStrongIcon from '@mui/icons-material/CenterFocusStrong';

export interface GraphNode {
  id: string;
  label: string;
  type: string;
  size?: number;
  color?: string;
  data?: Record<string, any>;
}

export interface GraphEdge {
  source: string;
  target: string;
  label?: string;
  weight?: number;
  color?: string;
  style?: 'solid' | 'dashed' | 'dotted';
}

export interface NetworkGraphProps {
  /** Graph nodes */
  nodes: GraphNode[];
  /** Graph edges */
  edges: GraphEdge[];
  /** Chart title */
  title?: string;
  /** Width of the graph */
  width?: number | string;
  /** Height of the graph */
  height?: number;
  /** Show node labels */
  showLabels?: boolean;
  /** Show edge labels */
  showEdgeLabels?: boolean;
  /** Enable zoom controls */
  zoomable?: boolean;
  /** Enable node dragging */
  draggable?: boolean;
  /** Node click handler */
  onNodeClick?: (node: GraphNode) => void;
  /** Color mapping by node type */
  typeColors?: Record<string, string>;
  /** Test ID for testing */
  testId?: string;
}

const defaultTypeColors: Record<string, string> = {
  domain: '#1976d2',
  ip: '#2e7d32',
  email: '#ed6c02',
  hash: '#9c27b0',
  organization: '#0288d1',
  person: '#d32f2f',
  default: '#757575',
};

interface SimulationNode extends GraphNode {
  x: number;
  y: number;
  vx: number;
  vy: number;
  fx?: number;
  fy?: number;
}

export const NetworkGraph: React.FC<NetworkGraphProps> = ({
  nodes,
  edges,
  title,
  width = '100%',
  height = 400,
  showLabels = true,
  showEdgeLabels = false,
  zoomable = true,
  draggable = true,
  onNodeClick,
  typeColors = defaultTypeColors,
  testId,
}) => {
  const theme = useTheme();
  const svgRef = useRef<SVGSVGElement>(null);
  const [zoom, setZoom] = useState(1);
  const [pan, setPan] = useState({ x: 0, y: 0 });
  const [selectedNode, setSelectedNode] = useState<GraphNode | null>(null);
  const [simulationNodes, setSimulationNodes] = useState<SimulationNode[]>([]);
  const [dragging, setDragging] = useState<string | null>(null);

  // Initialize simulation
  useEffect(() => {
    if (nodes.length === 0) return;

    const centerX = 400;
    const centerY = height / 2;

    // Initialize nodes with random positions around center
    const initialNodes: SimulationNode[] = nodes.map((node, i) => ({
      ...node,
      x: centerX + (Math.random() - 0.5) * 200,
      y: centerY + (Math.random() - 0.5) * 200,
      vx: 0,
      vy: 0,
    }));

    // Simple force simulation
    const simulate = () => {
      const nodeMap = new Map(initialNodes.map((n) => [n.id, n]));

      // Apply forces
      for (let iteration = 0; iteration < 100; iteration++) {
        // Repulsion between nodes
        for (let i = 0; i < initialNodes.length; i++) {
          for (let j = i + 1; j < initialNodes.length; j++) {
            const nodeA = initialNodes[i];
            const nodeB = initialNodes[j];
            const dx = nodeB.x - nodeA.x;
            const dy = nodeB.y - nodeA.y;
            const distance = Math.sqrt(dx * dx + dy * dy) || 1;
            const force = 1000 / (distance * distance);

            const fx = (dx / distance) * force;
            const fy = (dy / distance) * force;

            nodeA.vx -= fx;
            nodeA.vy -= fy;
            nodeB.vx += fx;
            nodeB.vy += fy;
          }
        }

        // Attraction along edges
        edges.forEach((edge) => {
          const source = nodeMap.get(edge.source);
          const target = nodeMap.get(edge.target);
          if (!source || !target) return;

          const dx = target.x - source.x;
          const dy = target.y - source.y;
          const distance = Math.sqrt(dx * dx + dy * dy) || 1;
          const force = distance * 0.01;

          const fx = (dx / distance) * force;
          const fy = (dy / distance) * force;

          source.vx += fx;
          source.vy += fy;
          target.vx -= fx;
          target.vy -= fy;
        });

        // Center gravity
        initialNodes.forEach((node) => {
          node.vx += (centerX - node.x) * 0.001;
          node.vy += (centerY - node.y) * 0.001;
        });

        // Apply velocities with damping
        initialNodes.forEach((node) => {
          if (node.fx === undefined) {
            node.x += node.vx * 0.5;
            node.y += node.vy * 0.5;
          }
          node.vx *= 0.9;
          node.vy *= 0.9;
        });
      }

      setSimulationNodes([...initialNodes]);
    };

    simulate();
  }, [nodes, edges, height]);

  const getNodeColor = useCallback(
    (node: GraphNode) => {
      if (node.color) return node.color;
      return typeColors[node.type] || typeColors.default;
    },
    [typeColors]
  );

  const getNodeRadius = useCallback((node: GraphNode) => {
    return node.size || 20;
  }, []);

  const handleNodeClick = useCallback(
    (node: GraphNode) => {
      setSelectedNode(node.id === selectedNode?.id ? null : node);
      onNodeClick?.(node);
    },
    [selectedNode, onNodeClick]
  );

  const handleZoomIn = () => setZoom((z) => Math.min(z + 0.2, 3));
  const handleZoomOut = () => setZoom((z) => Math.max(z - 0.2, 0.5));
  const handleReset = () => {
    setZoom(1);
    setPan({ x: 0, y: 0 });
  };

  const nodeMap = useMemo(
    () => new Map(simulationNodes.map((n) => [n.id, n])),
    [simulationNodes]
  );

  const edgeStrokeStyle = (style?: string) => {
    switch (style) {
      case 'dashed':
        return '5,5';
      case 'dotted':
        return '2,2';
      default:
        return undefined;
    }
  };

  if (nodes.length === 0) {
    return (
      <Box data-testid={testId} sx={{ textAlign: 'center', py: 4 }}>
        <Typography color="text.secondary">No data to display</Typography>
      </Box>
    );
  }

  return (
    <Box data-testid={testId} sx={{ width }}>
      {title && (
        <Typography variant="h6" gutterBottom>
          {title}
        </Typography>
      )}
      <Paper
        elevation={1}
        sx={{
          position: 'relative',
          overflow: 'hidden',
          bgcolor: theme.palette.mode === 'dark' ? 'grey.900' : 'grey.50',
        }}
      >
        {zoomable && (
          <Box
            sx={{
              position: 'absolute',
              top: 8,
              right: 8,
              zIndex: 10,
              display: 'flex',
              flexDirection: 'column',
              gap: 0.5,
              bgcolor: 'background.paper',
              borderRadius: 1,
              p: 0.5,
            }}
          >
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
          </Box>
        )}

        <svg
          ref={svgRef}
          width="100%"
          height={height}
          style={{ cursor: draggable ? 'grab' : 'default' }}
        >
          <g
            transform={`translate(${pan.x}, ${pan.y}) scale(${zoom})`}
            style={{ transformOrigin: 'center' }}
          >
            {/* Edges */}
            {edges.map((edge, index) => {
              const source = nodeMap.get(edge.source);
              const target = nodeMap.get(edge.target);
              if (!source || !target) return null;

              const midX = (source.x + target.x) / 2;
              const midY = (source.y + target.y) / 2;

              return (
                <g key={`edge-${index}`}>
                  <line
                    x1={source.x}
                    y1={source.y}
                    x2={target.x}
                    y2={target.y}
                    stroke={edge.color || theme.palette.divider}
                    strokeWidth={edge.weight || 1}
                    strokeDasharray={edgeStrokeStyle(edge.style)}
                    opacity={0.6}
                  />
                  {showEdgeLabels && edge.label && (
                    <text
                      x={midX}
                      y={midY}
                      fill={theme.palette.text.secondary}
                      fontSize={10}
                      textAnchor="middle"
                      dominantBaseline="middle"
                      style={{
                        pointerEvents: 'none',
                        userSelect: 'none',
                      }}
                    >
                      {edge.label}
                    </text>
                  )}
                </g>
              );
            })}

            {/* Nodes */}
            {simulationNodes.map((node) => {
              const radius = getNodeRadius(node);
              const isSelected = selectedNode?.id === node.id;

              return (
                <g
                  key={node.id}
                  transform={`translate(${node.x}, ${node.y})`}
                  style={{ cursor: 'pointer' }}
                  onClick={() => handleNodeClick(node)}
                >
                  {/* Selection ring */}
                  {isSelected && (
                    <circle
                      r={radius + 5}
                      fill="none"
                      stroke={theme.palette.primary.main}
                      strokeWidth={2}
                    />
                  )}
                  {/* Node circle */}
                  <circle
                    r={radius}
                    fill={getNodeColor(node)}
                    stroke={theme.palette.background.paper}
                    strokeWidth={2}
                  />
                  {/* Node label */}
                  {showLabels && (
                    <text
                      y={radius + 14}
                      fill={theme.palette.text.primary}
                      fontSize={11}
                      textAnchor="middle"
                      style={{
                        pointerEvents: 'none',
                        userSelect: 'none',
                        fontWeight: isSelected ? 'bold' : 'normal',
                      }}
                    >
                      {node.label.length > 15
                        ? `${node.label.slice(0, 15)}...`
                        : node.label}
                    </text>
                  )}
                  {/* Node type badge */}
                  <text
                    y={3}
                    fill="white"
                    fontSize={9}
                    textAnchor="middle"
                    dominantBaseline="middle"
                    fontWeight="bold"
                    style={{
                      pointerEvents: 'none',
                      userSelect: 'none',
                      textTransform: 'uppercase',
                    }}
                  >
                    {node.type.slice(0, 2)}
                  </text>
                </g>
              );
            })}
          </g>
        </svg>

        {/* Legend */}
        <Box
          sx={{
            position: 'absolute',
            bottom: 8,
            left: 8,
            display: 'flex',
            flexWrap: 'wrap',
            gap: 0.5,
          }}
        >
          {Array.from(new Set(nodes.map((n) => n.type))).map((type) => (
            <Chip
              key={type}
              label={type}
              size="small"
              sx={{
                bgcolor: typeColors[type] || typeColors.default,
                color: 'white',
                fontSize: '0.7rem',
                height: 20,
              }}
            />
          ))}
        </Box>

        {/* Selected node details */}
        {selectedNode && (
          <Paper
            elevation={3}
            sx={{
              position: 'absolute',
              top: 8,
              left: 8,
              p: 1.5,
              maxWidth: 250,
            }}
          >
            <Typography variant="subtitle2" fontWeight="bold">
              {selectedNode.label}
            </Typography>
            <Typography variant="caption" color="text.secondary">
              Type: {selectedNode.type}
            </Typography>
            {selectedNode.data && (
              <Box sx={{ mt: 1 }}>
                {Object.entries(selectedNode.data).slice(0, 3).map(([key, value]) => (
                  <Typography key={key} variant="caption" display="block">
                    <strong>{key}:</strong> {String(value)}
                  </Typography>
                ))}
              </Box>
            )}
          </Paper>
        )}
      </Paper>
    </Box>
  );
};

export default NetworkGraph;
