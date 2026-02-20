/**
 * Reports Page
 */

import React, { useEffect, useState } from 'react';
import { Box, Typography, Chip, IconButton, Tooltip, CircularProgress, Alert, styled, alpha } from '@mui/material';
import { motion } from 'framer-motion';
import DownloadIcon from '@mui/icons-material/Download';
import VisibilityIcon from '@mui/icons-material/Visibility';
import RefreshIcon from '@mui/icons-material/Refresh';
import AssessmentIcon from '@mui/icons-material/Assessment';
import SecurityIcon from '@mui/icons-material/Security';
import SummarizeIcon from '@mui/icons-material/Summarize';
import BugReportIcon from '@mui/icons-material/BugReport';
import { cyberColors, designTokens, glassmorphism } from '../utils/theme';
import { pageVariants } from '../utils/animations';
import api from '../utils/api';

interface Report {
  id: string;
  investigation_id: string;
  target: string;
  title?: string;
  type: string;
  investigator: string;
  generated_at: string;
  expires_at: string;
  status?: string;
  pages?: number;
  findings_count?: number;
  risk_level?: string;
  content?: {
    executive_summary?: string;
    key_findings?: string[];
    risk_assessment?: {
      overall_score?: number;
      category?: string;
    };
  };
}

const PageContainer = styled(motion.div)({
  padding: 24,
});

const Header = styled(Box)({
  display: 'flex',
  justifyContent: 'space-between',
  alignItems: 'center',
  marginBottom: 24,
});

const Title = styled(Typography)({
  fontFamily: designTokens.typography.fontFamily.display,
  fontSize: '1.75rem',
  fontWeight: 700,
  color: cyberColors.text.primary,
});

const StatsRow = styled(Box)({
  display: 'flex',
  gap: 16,
  marginBottom: 24,
});

const StatCard = styled(motion.div)({
  ...glassmorphism.card,
  padding: 16,
  borderRadius: designTokens.borderRadius.md,
  flex: 1,
  textAlign: 'center',
});

const ReportCard = styled(motion.div)({
  ...glassmorphism.card,
  padding: 20,
  borderRadius: designTokens.borderRadius.md,
  marginBottom: 16,
  cursor: 'pointer',
  transition: 'all 0.2s ease',
  '&:hover': {
    borderColor: cyberColors.neon.cyan,
    boxShadow: `0 0 20px ${cyberColors.neon.cyan}20`,
  },
});

const TypeIcon = styled(Box)<{ color: string }>(({ color }) => ({
  width: 48,
  height: 48,
  borderRadius: designTokens.borderRadius.sm,
  display: 'flex',
  alignItems: 'center',
  justifyContent: 'center',
  backgroundColor: alpha(color, 0.15),
  color: color,
  marginRight: 16,
  '& svg': {
    fontSize: 24,
  },
}));

const StatusChip = styled(Chip)<{ status: string }>(({ status }) => {
  const colors: Record<string, string> = {
    completed: cyberColors.neon.green,
    generating: cyberColors.neon.orange,
    failed: cyberColors.neon.red,
  };
  const color = colors[status] || cyberColors.neon.green;
  return {
    backgroundColor: alpha(color, 0.15),
    color: color,
    fontWeight: 600,
    fontSize: '0.7rem',
  };
});

const EmptyState = styled(Box)({
  ...glassmorphism.card,
  padding: 48,
  borderRadius: designTokens.borderRadius.lg,
  textAlign: 'center',
});

// Report type configuration
const reportTypeConfig: Record<string, { icon: React.ReactElement; color: string; label: string }> = {
  threat_assessment: {
    icon: <SecurityIcon />,
    color: cyberColors.neon.magenta,
    label: 'Threat Assessment',
  },
  executive_summary: {
    icon: <SummarizeIcon />,
    color: cyberColors.neon.cyan,
    label: 'Executive Summary',
  },
  technical_analysis: {
    icon: <BugReportIcon />,
    color: cyberColors.neon.orange,
    label: 'Technical Analysis',
  },
  risk_assessment: {
    icon: <AssessmentIcon />,
    color: cyberColors.neon.green,
    label: 'Risk Assessment',
  },
  comprehensive: {
    icon: <AssessmentIcon />,
    color: cyberColors.neon.cyan,
    label: 'Comprehensive',
  },
};

const ReportsPage: React.FC = () => {
  const [reports, setReports] = useState<Report[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchReports = async () => {
    setLoading(true);
    setError(null);
    try {
      const response = await api.get('/reports');
      setReports(response.data || []);
    } catch (err: any) {
      console.error('Failed to fetch reports:', err);
      setError(err.response?.data?.error || 'Failed to load reports');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchReports();
  }, []);

  const totalReports = reports.length;
  const totalFindings = reports.reduce((sum, r) => sum + (r.findings_count || 0), 0);
  const criticalReports = reports.filter((r) => r.risk_level === 'critical').length;

  const formatDate = (dateStr: string) => {
    try {
      const date = new Date(dateStr);
      return date.toLocaleString();
    } catch {
      return dateStr;
    }
  };

  const getReportTitle = (report: Report) => {
    if (report.title) return report.title;
    const typeConfig = reportTypeConfig[report.type] || reportTypeConfig.comprehensive;
    return `${typeConfig.label}: ${report.target}`;
  };

  if (loading) {
    return (
      <PageContainer
        variants={pageVariants}
        initial="initial"
        animate="enter"
        exit="exit"
      >
        <Box sx={{ display: 'flex', justifyContent: 'center', alignItems: 'center', minHeight: 400 }}>
          <CircularProgress sx={{ color: cyberColors.neon.cyan }} />
        </Box>
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
      <Header>
        <Title>Intelligence Reports</Title>
        <Tooltip title="Refresh">
          <IconButton onClick={fetchReports} sx={{ color: cyberColors.neon.cyan }}>
            <RefreshIcon />
          </IconButton>
        </Tooltip>
      </Header>

      {error && (
        <Alert severity="error" sx={{ mb: 3 }}>
          {error}
        </Alert>
      )}

      {/* Stats Row */}
      <StatsRow>
        <StatCard
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0 }}
        >
          <Typography
            variant="h3"
            sx={{
              fontFamily: designTokens.typography.fontFamily.mono,
              color: cyberColors.neon.cyan,
              fontWeight: 700,
            }}
          >
            {totalReports}
          </Typography>
          <Typography variant="caption" sx={{ color: cyberColors.text.secondary }}>
            Total Reports
          </Typography>
        </StatCard>
        <StatCard
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.1 }}
        >
          <Typography
            variant="h3"
            sx={{
              fontFamily: designTokens.typography.fontFamily.mono,
              color: cyberColors.neon.green,
              fontWeight: 700,
            }}
          >
            {totalFindings}
          </Typography>
          <Typography variant="caption" sx={{ color: cyberColors.text.secondary }}>
            Total Findings
          </Typography>
        </StatCard>
        <StatCard
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.2 }}
        >
          <Typography
            variant="h3"
            sx={{
              fontFamily: designTokens.typography.fontFamily.mono,
              color: cyberColors.neon.magenta,
              fontWeight: 700,
            }}
          >
            {criticalReports}
          </Typography>
          <Typography variant="caption" sx={{ color: cyberColors.text.secondary }}>
            Critical Reports
          </Typography>
        </StatCard>
      </StatsRow>

      {/* Reports List */}
      {reports.length === 0 ? (
        <EmptyState>
          <Typography
            variant="h6"
            sx={{ color: cyberColors.text.secondary, mb: 1 }}
          >
            No Reports Available
          </Typography>
          <Typography variant="body2" sx={{ color: cyberColors.text.muted }}>
            Generate a report from a completed investigation to see it here.
          </Typography>
        </EmptyState>
      ) : (
        reports.map((report, index) => {
          const typeConfig = reportTypeConfig[report.type] || reportTypeConfig.comprehensive;
          const riskLevel = report.risk_level || report.content?.risk_assessment?.category?.toLowerCase().replace(' risk', '') || 'medium';

          return (
            <ReportCard
              key={report.id}
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.3 + index * 0.1 }}
            >
              <Box sx={{ display: 'flex', alignItems: 'flex-start' }}>
                <TypeIcon color={typeConfig.color}>{typeConfig.icon}</TypeIcon>
                <Box sx={{ flex: 1 }}>
                  <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 0.5 }}>
                    <Typography
                      sx={{
                        fontFamily: designTokens.typography.fontFamily.display,
                        color: cyberColors.text.primary,
                        fontSize: '1.1rem',
                        fontWeight: 600,
                      }}
                    >
                      {getReportTitle(report)}
                    </Typography>
                    <StatusChip
                      label={(report.status || 'completed').toUpperCase()}
                      status={report.status || 'completed'}
                      size="small"
                    />
                  </Box>
                  <Typography variant="body2" sx={{ color: cyberColors.text.secondary, mb: 1 }}>
                    Investigation: {report.target} | By: {report.investigator}
                  </Typography>
                  <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, flexWrap: 'wrap' }}>
                    <Typography
                      variant="caption"
                      sx={{
                        color: cyberColors.text.muted,
                        fontFamily: designTokens.typography.fontFamily.mono,
                      }}
                    >
                      {formatDate(report.generated_at)}
                    </Typography>
                    {report.pages && (
                      <Chip
                        label={`${report.pages} pages`}
                        size="small"
                        sx={{
                          bgcolor: alpha(cyberColors.neon.cyan, 0.1),
                          color: cyberColors.neon.cyan,
                          fontSize: '0.7rem',
                        }}
                      />
                    )}
                    {report.findings_count && (
                      <Chip
                        label={`${report.findings_count} findings`}
                        size="small"
                        sx={{
                          bgcolor: alpha(cyberColors.neon.green, 0.1),
                          color: cyberColors.neon.green,
                          fontSize: '0.7rem',
                        }}
                      />
                    )}
                    <Chip
                      label={riskLevel.toUpperCase()}
                      size="small"
                      sx={{
                        bgcolor: alpha(
                          riskLevel === 'critical'
                            ? cyberColors.neon.magenta
                            : riskLevel === 'high'
                            ? cyberColors.neon.red
                            : riskLevel === 'low'
                            ? cyberColors.neon.green
                            : cyberColors.neon.orange,
                          0.15
                        ),
                        color:
                          riskLevel === 'critical'
                            ? cyberColors.neon.magenta
                            : riskLevel === 'high'
                            ? cyberColors.neon.red
                            : riskLevel === 'low'
                            ? cyberColors.neon.green
                            : cyberColors.neon.orange,
                        fontSize: '0.7rem',
                        fontWeight: 600,
                      }}
                    />
                  </Box>
                </Box>
                <Box sx={{ display: 'flex', gap: 1 }}>
                  <Tooltip title="View Report">
                    <IconButton
                      size="small"
                      sx={{
                        color: cyberColors.neon.cyan,
                        '&:hover': { bgcolor: alpha(cyberColors.neon.cyan, 0.1) },
                      }}
                    >
                      <VisibilityIcon fontSize="small" />
                    </IconButton>
                  </Tooltip>
                  <Tooltip title="Download PDF">
                    <IconButton
                      size="small"
                      sx={{
                        color: cyberColors.neon.green,
                        '&:hover': { bgcolor: alpha(cyberColors.neon.green, 0.1) },
                      }}
                    >
                      <DownloadIcon fontSize="small" />
                    </IconButton>
                  </Tooltip>
                </Box>
              </Box>
            </ReportCard>
          );
        })
      )}
    </PageContainer>
  );
};

export default ReportsPage;
