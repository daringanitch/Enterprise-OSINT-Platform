/**
 * ThreatAnalysis Page
 *
 * Combined threat intelligence view with MITRE ATT&CK matrix,
 * Risk Command Center, and Timeline.
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
  CircularProgress,
  Alert,
  Divider,
  alpha,
  styled,
} from '@mui/material';
import { motion } from 'framer-motion';
import ArrowBackIcon from '@mui/icons-material/ArrowBack';
import RefreshIcon from '@mui/icons-material/Refresh';
import SecurityIcon from '@mui/icons-material/Security';
import ShieldIcon from '@mui/icons-material/Shield';
import TimelineIcon from '@mui/icons-material/Timeline';
import AssessmentIcon from '@mui/icons-material/Assessment';
import DownloadIcon from '@mui/icons-material/Download';
import { cyberColors, designTokens, glassmorphism } from '../utils/theme';
import { pageVariants } from '../utils/animations';

// Components
import { MITREDashboard } from '../components/dashboard/MITREDashboard';
import { RiskCommandCenter } from '../components/dashboard/RiskCommandCenter';
import { InvestigationTimeline } from '../components/visualizations/InvestigationTimeline';
import { ExecutiveSummary } from '../components/dashboard/ExecutiveSummary';
import { Card } from '../components/common/Card';

// Hooks
import { useAdvancedAnalysis } from '../hooks/useAdvancedAnalysis';

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

const SectionTitle = styled(Typography)(({ theme }) => ({
  fontFamily: designTokens.typography.fontFamily.display,
  color: cyberColors.text.primary,
  display: 'flex',
  alignItems: 'center',
  gap: 8,
  marginBottom: 16,
  fontSize: '1.1rem',
}));

// =============================================================================
// Component
// =============================================================================

export const ThreatAnalysis: React.FC = () => {
  const { id: investigationId } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const [activeSection, setActiveSection] = useState<'summary' | 'mitre' | 'risk' | 'timeline'>('summary');

  const {
    advancedAnalysis,
    mitre,
    risk,
    correlation,
    timeline,
    summary,
    isLoading,
    isMITRELoading,
    isTimelineLoading,
    isSummaryLoading,
    error,
    fetchAdvancedAnalysis,
    fetchTimeline,
    fetchSummary,
    refreshAll,
  } = useAdvancedAnalysis({
    investigationId: investigationId || '',
    autoFetch: true,
  });

  // Handle section change
  const handleSectionChange = (section: typeof activeSection) => {
    setActiveSection(section);
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
              Threat Analysis
            </Typography>
            <Typography variant="body2" sx={{ color: cyberColors.text.secondary }}>
              Investigation: {investigationId}
            </Typography>
          </Box>
        </Box>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
          <Tooltip title="Refresh All">
            <IconButton
              onClick={() => refreshAll()}
              disabled={isLoading}
              sx={{ color: cyberColors.neon.cyan }}
            >
              {isLoading ? <CircularProgress size={20} /> : <RefreshIcon />}
            </IconButton>
          </Tooltip>
          <Tooltip title="Export Report">
            <Button
              variant="outlined"
              startIcon={<DownloadIcon />}
              sx={{
                borderColor: cyberColors.neon.cyan,
                color: cyberColors.neon.cyan,
              }}
            >
              Export
            </Button>
          </Tooltip>
        </Box>
      </HeaderSection>

      {/* Navigation Tabs */}
      <Box
        sx={{
          ...glassmorphism.panel,
          borderRadius: designTokens.borderRadius.md,
          mb: 3,
          p: 0.5,
          display: 'flex',
          gap: 0.5,
        }}
      >
        {[
          { key: 'summary', label: 'Summary', icon: <AssessmentIcon /> },
          { key: 'mitre', label: 'MITRE ATT&CK', icon: <SecurityIcon /> },
          { key: 'risk', label: 'Risk Center', icon: <ShieldIcon /> },
          { key: 'timeline', label: 'Timeline', icon: <TimelineIcon /> },
        ].map(({ key, label, icon }) => (
          <Button
            key={key}
            onClick={() => handleSectionChange(key as typeof activeSection)}
            startIcon={icon}
            sx={{
              flex: 1,
              py: 1,
              borderRadius: designTokens.borderRadius.sm,
              bgcolor: activeSection === key ? alpha(cyberColors.neon.cyan, 0.15) : 'transparent',
              color: activeSection === key ? cyberColors.neon.cyan : cyberColors.text.secondary,
              border: activeSection === key ? `1px solid ${cyberColors.neon.cyan}` : '1px solid transparent',
              '&:hover': {
                bgcolor: alpha(cyberColors.neon.cyan, 0.1),
              },
            }}
          >
            {label}
          </Button>
        ))}
      </Box>

      {/* Error State */}
      {error && (
        <Alert severity="error" sx={{ mb: 2 }}>
          {String(error)}
        </Alert>
      )}

      {/* Content Sections */}
      {activeSection === 'summary' && (
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          exit={{ opacity: 0 }}
        >
          <Grid container spacing={3}>
            <Grid item xs={12} lg={6}>
              {isSummaryLoading ? (
                <Box sx={{ display: 'flex', justifyContent: 'center', p: 4 }}>
                  <CircularProgress sx={{ color: cyberColors.neon.cyan }} />
                </Box>
              ) : summary ? (
                <ExecutiveSummary
                  title={summary.title || investigationId || ''}
                  status={summary.status || 'in_progress'}
                  threatLevel={summary.threatLevel || 'medium'}
                  riskTrajectory={summary.riskTrajectory || 'stable'}
                  findings={summary.findings || []}
                  recommendations={summary.recommendations || []}
                  confidenceScore={summary.confidenceScore || 75}
                  summary={summary.summary}
                  entitiesAnalyzed={summary.entitiesAnalyzed}
                  dataSourcesUsed={summary.dataSourcesUsed}
                  investigationDuration={summary.investigationDuration}
                />
              ) : (
                <Card variant="glass">
                  <Typography color="text.secondary">
                    No summary data available. Run analysis to generate.
                  </Typography>
                </Card>
              )}
            </Grid>
            <Grid item xs={12} lg={6}>
              {/* Quick Stats */}
              <Card variant="cyber" title="Quick Stats">
                <Grid container spacing={2}>
                  <Grid item xs={6}>
                    <Box sx={{ textAlign: 'center', p: 2 }}>
                      <Typography
                        variant="h3"
                        sx={{
                          fontFamily: designTokens.typography.fontFamily.mono,
                          color: cyberColors.neon.cyan,
                        }}
                      >
                        {mitre?.detectedTechniques || 0}
                      </Typography>
                      <Typography variant="caption" sx={{ color: cyberColors.text.secondary }}>
                        MITRE Techniques
                      </Typography>
                    </Box>
                  </Grid>
                  <Grid item xs={6}>
                    <Box sx={{ textAlign: 'center', p: 2 }}>
                      <Typography
                        variant="h3"
                        sx={{
                          fontFamily: designTokens.typography.fontFamily.mono,
                          color: cyberColors.neon.magenta,
                        }}
                      >
                        {mitre?.criticalCount || 0}
                      </Typography>
                      <Typography variant="caption" sx={{ color: cyberColors.text.secondary }}>
                        Critical Findings
                      </Typography>
                    </Box>
                  </Grid>
                  <Grid item xs={6}>
                    <Box sx={{ textAlign: 'center', p: 2 }}>
                      <Typography
                        variant="h3"
                        sx={{
                          fontFamily: designTokens.typography.fontFamily.mono,
                          color: cyberColors.neon.green,
                        }}
                      >
                        {correlation?.entities?.length || 0}
                      </Typography>
                      <Typography variant="caption" sx={{ color: cyberColors.text.secondary }}>
                        Correlated Entities
                      </Typography>
                    </Box>
                  </Grid>
                  <Grid item xs={6}>
                    <Box sx={{ textAlign: 'center', p: 2 }}>
                      <Typography
                        variant="h3"
                        sx={{
                          fontFamily: designTokens.typography.fontFamily.mono,
                          color: cyberColors.neon.orange,
                        }}
                      >
                        {timeline?.totalEvents || 0}
                      </Typography>
                      <Typography variant="caption" sx={{ color: cyberColors.text.secondary }}>
                        Timeline Events
                      </Typography>
                    </Box>
                  </Grid>
                </Grid>
              </Card>
            </Grid>
          </Grid>
        </motion.div>
      )}

      {activeSection === 'mitre' && (
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          exit={{ opacity: 0 }}
        >
          {isMITRELoading ? (
            <Box sx={{ display: 'flex', justifyContent: 'center', p: 4 }}>
              <CircularProgress sx={{ color: cyberColors.neon.cyan }} />
            </Box>
          ) : mitre?.tactics ? (
            <MITREDashboard
              tactics={mitre.tactics}
              title="MITRE ATT&CK Coverage Analysis"
              showKillChain
            />
          ) : (
            <Card variant="glass">
              <Typography color="text.secondary">
                No MITRE data available. Run analysis to generate.
              </Typography>
            </Card>
          )}
        </motion.div>
      )}

      {activeSection === 'risk' && (
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          exit={{ opacity: 0 }}
        >
          {risk ? (
            <RiskCommandCenter
              overallScore={risk.overallScore}
              overallTrend={risk.overallTrend}
              categories={risk.categories}
              riskFactors={risk.riskFactors}
              recommendations={risk.recommendations}
              title="Risk Command Center"
            />
          ) : (
            <Card variant="glass">
              <Typography color="text.secondary">
                No risk data available. Run analysis to generate.
              </Typography>
            </Card>
          )}
        </motion.div>
      )}

      {activeSection === 'timeline' && (
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          exit={{ opacity: 0 }}
        >
          {isTimelineLoading ? (
            <Box sx={{ display: 'flex', justifyContent: 'center', p: 4 }}>
              <CircularProgress sx={{ color: cyberColors.neon.cyan }} />
            </Box>
          ) : timeline?.events ? (
            <InvestigationTimeline
              events={timeline.events}
              title="Investigation Timeline"
              height={600}
            />
          ) : (
            <Card variant="glass">
              <Typography color="text.secondary">
                No timeline data available. Run analysis to generate.
              </Typography>
            </Card>
          )}
        </motion.div>
      )}
    </PageContainer>
  );
};

export default ThreatAnalysis;
