/**
 * GraphIntelligence Page
 *
 * Dedicated page for graph analysis with full-screen visualization,
 * algorithm selection, and results panel.
 */

import React, { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import {
  Box,
  Typography,
  Grid,
  Button,
  IconButton,
  Tooltip,
  Tabs,
  Tab,
  Chip,
  CircularProgress,
  Alert,
  alpha,
  styled,
} from '@mui/material';
import { motion, AnimatePresence } from 'framer-motion';
import ArrowBackIcon from '@mui/icons-material/ArrowBack';
import RefreshIcon from '@mui/icons-material/Refresh';
import FullscreenIcon from '@mui/icons-material/Fullscreen';
import DownloadIcon from '@mui/icons-material/Download';
import HubIcon from '@mui/icons-material/Hub';
import GroupWorkIcon from '@mui/icons-material/GroupWork';
import WarningAmberIcon from '@mui/icons-material/WarningAmber';
import RouteIcon from '@mui/icons-material/Route';
import { cyberColors, designTokens, glassmorphism } from '../utils/theme';
import { pageVariants } from '../utils/animations';

// Components
import { InvestigationGraph } from '../components/visualizations/InvestigationGraph';
import { AnomalyPanel } from '../components/dashboard/AnomalyPanel';
import { CommunityMap } from '../components/visualizations/CommunityMap';
import { Card } from '../components/common/Card';

// Hooks
import { useGraphIntelligence } from '../hooks/useGraphIntelligence';

// =============================================================================
// Styled Components
// =============================================================================

const PageContainer = styled(motion.div)(({ theme }) => ({
  minHeight: '100vh',
  padding: 24,
}));

const HeaderSection = styled(Box)(({ theme }) => ({
  display: 'flex',
  alignItems: 'center',
  justifyContent: 'space-between',
  marginBottom: 24,
}));

const TabPanel = styled(Box)(({ theme }) => ({
  marginTop: 16,
}));

const StatCard = styled(Box)(({ theme }) => ({
  ...glassmorphism.panel,
  borderRadius: designTokens.borderRadius.md,
  padding: 16,
  textAlign: 'center',
}));

// =============================================================================
// Component
// =============================================================================

interface TabPanelProps {
  children?: React.ReactNode;
  index: number;
  value: number;
}

function CustomTabPanel(props: TabPanelProps) {
  const { children, value, index, ...other } = props;

  return (
    <div
      role="tabpanel"
      hidden={value !== index}
      id={`graph-tabpanel-${index}`}
      aria-labelledby={`graph-tab-${index}`}
      {...other}
    >
      {value === index && <Box sx={{ pt: 2 }}>{children}</Box>}
    </div>
  );
}

export const GraphIntelligence: React.FC = () => {
  const { id: investigationId } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const [activeTab, setActiveTab] = useState(0);
  const [graphMode, setGraphMode] = useState<'default' | 'centrality' | 'communities' | 'anomalies' | 'path'>('default');
  const [isFullscreen, setIsFullscreen] = useState(false);

  const {
    graphData,
    analysis,
    anomalies,
    communities,
    selectedPath,
    blastRadiusResult,
    isLoading,
    isSyncing,
    isAnalyzing,
    isFindingPath,
    error,
    syncGraph,
    runFullAnalysis,
    fetchAnomalies,
    fetchCommunities,
    findPath,
    calculateBlastRadius,
    clearPath,
    clearBlastRadius,
  } = useGraphIntelligence({
    investigationId: investigationId || '',
    autoSync: true,
  });

  // Handle tab change
  const handleTabChange = (event: React.SyntheticEvent, newValue: number) => {
    setActiveTab(newValue);
    // Update graph mode based on tab
    const modes = ['default', 'centrality', 'communities', 'anomalies', 'path'] as const;
    setGraphMode(modes[newValue] || 'default');
  };

  // Handle path finding
  const handleFindPath = (sourceId: string, targetId: string) => {
    findPath(sourceId, targetId);
  };

  // Handle blast radius
  const handleBlastRadius = (entityId: string) => {
    calculateBlastRadius(entityId);
  };

  // Stats from analysis
  const stats = {
    entities: graphData?.entities.length || 0,
    relationships: graphData?.relationships.length || 0,
    communities: analysis?.communities?.length || 0,
    anomalies: analysis?.anomalies?.length || 0,
  };

  if (!investigationId) {
    return (
      <PageContainer>
        <Alert severity="error">No investigation ID provided</Alert>
      </PageContainer>
    );
  }

  return (
    <PageContainer
      variants={pageVariants}
      initial="initial"
      animate="enter"
      exit="exit"
    >
      {/* Header */}
      <HeaderSection>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
          <IconButton onClick={() => navigate(-1)} sx={{ color: cyberColors.neon.cyan }}>
            <ArrowBackIcon />
          </IconButton>
          <Box>
            <Typography
              variant="h4"
              sx={{
                fontFamily: designTokens.typography.fontFamily.display,
                color: cyberColors.text.primary,
              }}
            >
              Graph Intelligence
            </Typography>
            <Typography variant="body2" sx={{ color: cyberColors.text.secondary }}>
              Investigation: {investigationId}
            </Typography>
          </Box>
        </Box>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
          <Tooltip title="Refresh Graph">
            <IconButton
              onClick={() => syncGraph()}
              disabled={isSyncing}
              sx={{ color: cyberColors.neon.cyan }}
            >
              {isSyncing ? <CircularProgress size={20} /> : <RefreshIcon />}
            </IconButton>
          </Tooltip>
          <Tooltip title="Run Full Analysis">
            <Button
              variant="outlined"
              onClick={() => runFullAnalysis()}
              disabled={isAnalyzing}
              startIcon={isAnalyzing ? <CircularProgress size={16} /> : <HubIcon />}
              sx={{
                borderColor: cyberColors.neon.cyan,
                color: cyberColors.neon.cyan,
              }}
            >
              Analyze
            </Button>
          </Tooltip>
          <Tooltip title="Toggle Fullscreen">
            <IconButton
              onClick={() => setIsFullscreen(!isFullscreen)}
              sx={{ color: cyberColors.text.secondary }}
            >
              <FullscreenIcon />
            </IconButton>
          </Tooltip>
        </Box>
      </HeaderSection>

      {/* Stats Row */}
      <Grid container spacing={2} sx={{ mb: 3 }}>
        <Grid item xs={6} sm={3}>
          <StatCard>
            <Typography
              variant="h4"
              sx={{
                fontFamily: designTokens.typography.fontFamily.mono,
                color: cyberColors.neon.cyan,
              }}
            >
              {stats.entities}
            </Typography>
            <Typography variant="caption" sx={{ color: cyberColors.text.secondary }}>
              Entities
            </Typography>
          </StatCard>
        </Grid>
        <Grid item xs={6} sm={3}>
          <StatCard>
            <Typography
              variant="h4"
              sx={{
                fontFamily: designTokens.typography.fontFamily.mono,
                color: cyberColors.neon.magenta,
              }}
            >
              {stats.relationships}
            </Typography>
            <Typography variant="caption" sx={{ color: cyberColors.text.secondary }}>
              Relationships
            </Typography>
          </StatCard>
        </Grid>
        <Grid item xs={6} sm={3}>
          <StatCard>
            <Typography
              variant="h4"
              sx={{
                fontFamily: designTokens.typography.fontFamily.mono,
                color: cyberColors.neon.green,
              }}
            >
              {stats.communities}
            </Typography>
            <Typography variant="caption" sx={{ color: cyberColors.text.secondary }}>
              Communities
            </Typography>
          </StatCard>
        </Grid>
        <Grid item xs={6} sm={3}>
          <StatCard>
            <Typography
              variant="h4"
              sx={{
                fontFamily: designTokens.typography.fontFamily.mono,
                color: cyberColors.neon.red,
              }}
            >
              {stats.anomalies}
            </Typography>
            <Typography variant="caption" sx={{ color: cyberColors.text.secondary }}>
              Anomalies
            </Typography>
          </StatCard>
        </Grid>
      </Grid>

      {/* Error State */}
      {error && (
        <Alert severity="error" sx={{ mb: 2 }}>
          {String(error)}
        </Alert>
      )}

      {/* Main Content */}
      <Grid container spacing={3}>
        {/* Graph Visualization */}
        <Grid item xs={12} lg={isFullscreen ? 12 : 8}>
          <Card variant="cyber" padding="none">
            <Tabs
              value={activeTab}
              onChange={handleTabChange}
              sx={{
                borderBottom: `1px solid ${alpha(cyberColors.neon.cyan, 0.2)}`,
                px: 2,
              }}
            >
              <Tab
                icon={<HubIcon sx={{ fontSize: 18 }} />}
                iconPosition="start"
                label="Graph"
                sx={{ minHeight: 48 }}
              />
              <Tab
                icon={<HubIcon sx={{ fontSize: 18 }} />}
                iconPosition="start"
                label="Centrality"
                sx={{ minHeight: 48 }}
              />
              <Tab
                icon={<GroupWorkIcon sx={{ fontSize: 18 }} />}
                iconPosition="start"
                label="Communities"
                sx={{ minHeight: 48 }}
              />
              <Tab
                icon={<WarningAmberIcon sx={{ fontSize: 18 }} />}
                iconPosition="start"
                label="Anomalies"
                sx={{ minHeight: 48 }}
              />
              <Tab
                icon={<RouteIcon sx={{ fontSize: 18 }} />}
                iconPosition="start"
                label="Paths"
                sx={{ minHeight: 48 }}
              />
            </Tabs>

            <Box sx={{ p: 2 }}>
              {isLoading ? (
                <Box
                  sx={{
                    height: 500,
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    flexDirection: 'column',
                    gap: 2,
                  }}
                >
                  <CircularProgress sx={{ color: cyberColors.neon.cyan }} />
                  <Typography color="text.secondary">Loading graph data...</Typography>
                </Box>
              ) : graphData ? (
                <InvestigationGraph
                  entities={graphData.entities.map((e: any) => ({
                    ...e,
                    centralityScore: analysis?.centrality?.find((c: any) => c.entityId === e.id)?.pageRank,
                    community: analysis?.communities?.findIndex((c: any) =>
                      c.entities.some((ce: any) => ce.id === e.id)
                    ),
                    isAnomaly: analysis?.anomalies?.some((a: any) => a.id === e.id),
                  }))}
                  relationships={graphData.relationships}
                  height={isFullscreen ? 700 : 500}
                  mode={graphMode}
                  highlightedPath={selectedPath}
                  blastRadius={blastRadiusResult}
                  onFindPath={handleFindPath}
                  onBlastRadius={handleBlastRadius}
                  loading={isFindingPath}
                />
              ) : (
                <Box
                  sx={{
                    height: 500,
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                  }}
                >
                  <Typography color="text.secondary">
                    No graph data available. Click Refresh to sync.
                  </Typography>
                </Box>
              )}
            </Box>
          </Card>
        </Grid>

        {/* Side Panel */}
        {!isFullscreen && (
          <Grid item xs={12} lg={4}>
            <AnimatePresence mode="wait">
              {/* Anomalies Panel */}
              {activeTab === 3 && (
                <motion.div
                  key="anomalies"
                  initial={{ opacity: 0, x: 20 }}
                  animate={{ opacity: 1, x: 0 }}
                  exit={{ opacity: 0, x: -20 }}
                >
                  <AnomalyPanel
                    anomalies={
                      analysis?.anomalies?.map((a: any) => ({
                        id: a.id,
                        label: a.label,
                        entityType: a.entityType,
                        anomalyTypes: a.anomalyTypes || ['degree'],
                        severity: a.severity,
                        zScore: a.zScore || 2.5,
                        description: a.description || 'Anomalous behavior detected',
                        confidence: a.confidence || 0.8,
                      })) || []
                    }
                    onRefresh={fetchAnomalies}
                  />
                </motion.div>
              )}

              {/* Communities Panel */}
              {activeTab === 2 && (
                <motion.div
                  key="communities"
                  initial={{ opacity: 0, x: 20 }}
                  animate={{ opacity: 1, x: 0 }}
                  exit={{ opacity: 0, x: -20 }}
                >
                  <CommunityMap
                    communities={
                      analysis?.communities?.map((c: any, i: number) => ({
                        id: i,
                        name: c.name || `Community ${i + 1}`,
                        entities: c.entities,
                        cohesion: c.cohesion || 0.7,
                        density: c.density || 0.5,
                      })) || []
                    }
                    interCommunityEdges={[]}
                    height={400}
                  />
                </motion.div>
              )}

              {/* Path Finding Results */}
              {activeTab === 4 && selectedPath && (
                <motion.div
                  key="paths"
                  initial={{ opacity: 0, x: 20 }}
                  animate={{ opacity: 1, x: 0 }}
                  exit={{ opacity: 0, x: -20 }}
                >
                  <Card variant="glass" title="Path Found">
                    <Typography variant="body2" sx={{ mb: 2 }}>
                      Path length: {selectedPath.nodes.length} nodes
                    </Typography>
                    <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 1 }}>
                      {selectedPath.path?.map((node: any, i: number) => (
                        <React.Fragment key={node.id}>
                          <Chip
                            label={node.label}
                            size="small"
                            sx={{
                              bgcolor: alpha(cyberColors.neon.cyan, 0.2),
                              color: cyberColors.neon.cyan,
                            }}
                          />
                          {i < (selectedPath.path?.length || 0) - 1 && (
                            <Typography sx={{ color: cyberColors.text.muted }}>→</Typography>
                          )}
                        </React.Fragment>
                      ))}
                    </Box>
                    <Button
                      size="small"
                      onClick={clearPath}
                      sx={{ mt: 2, color: cyberColors.neon.cyan }}
                    >
                      Clear Path
                    </Button>
                  </Card>
                </motion.div>
              )}

              {/* Default - Analysis Summary */}
              {(activeTab === 0 || activeTab === 1) && (
                <motion.div
                  key="summary"
                  initial={{ opacity: 0, x: 20 }}
                  animate={{ opacity: 1, x: 0 }}
                  exit={{ opacity: 0, x: -20 }}
                >
                  <Card variant="glass" title="Analysis Summary">
                    {analysis ? (
                      <Box>
                        <Typography variant="body2" sx={{ mb: 2 }}>
                          The graph analysis has identified{' '}
                          <strong style={{ color: cyberColors.neon.green }}>
                            {analysis.communities?.length || 0}
                          </strong>{' '}
                          distinct communities and{' '}
                          <strong style={{ color: cyberColors.neon.red }}>
                            {analysis.anomalies?.length || 0}
                          </strong>{' '}
                          anomalous entities.
                        </Typography>
                        {analysis.centrality && (
                          <Box>
                            <Typography
                              variant="caption"
                              sx={{ color: cyberColors.neon.cyan, display: 'block', mb: 1 }}
                            >
                              Top Central Entities:
                            </Typography>
                            {analysis.centrality.slice(0, 5).map((c: any) => (
                              <Box
                                key={c.entityId}
                                sx={{
                                  display: 'flex',
                                  justifyContent: 'space-between',
                                  mb: 0.5,
                                }}
                              >
                                <Typography
                                  variant="caption"
                                  sx={{ fontFamily: designTokens.typography.fontFamily.mono }}
                                >
                                  {c.entityId}
                                </Typography>
                                <Typography
                                  variant="caption"
                                  sx={{ color: cyberColors.neon.cyan }}
                                >
                                  {(c.pageRank * 100).toFixed(1)}%
                                </Typography>
                              </Box>
                            ))}
                          </Box>
                        )}
                      </Box>
                    ) : (
                      <Typography variant="body2" color="text.secondary">
                        Run analysis to see results
                      </Typography>
                    )}
                  </Card>
                </motion.div>
              )}
            </AnimatePresence>
          </Grid>
        )}
      </Grid>
    </PageContainer>
  );
};

export default GraphIntelligence;
