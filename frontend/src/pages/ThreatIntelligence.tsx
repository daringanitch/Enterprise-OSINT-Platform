/**
 * Threat Intelligence Overview Page
 *
 * Displays threat intelligence feeds, IOC tracking, and actor profiles.
 */

import React, { useState } from 'react';
import {
  Box,
  Typography,
  Tabs,
  Tab,
  Card,
  Grid,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Chip,
  Alert,
  AlertTitle,
  styled,
  alpha,
} from '@mui/material';
import {
  Security as SecurityIcon,
  TrendingUp as TrendingUpIcon,
  People as PeopleIcon,
  Warning as WarningIcon,
} from '@mui/icons-material';
import { motion } from 'framer-motion';
import { cyberColors, designTokens, glassmorphism } from '../utils/theme';
import { pageVariants } from '../utils/animations';

const PageContainer = styled(motion.div)({
  padding: '24px',
  minHeight: '100vh',
  background: cyberColors.dark.void,
});

const PageTitle = styled(Typography)({
  fontFamily: designTokens.typography.fontFamily.display,
  fontSize: '1.75rem',
  fontWeight: 700,
  color: cyberColors.text.primary,
  marginBottom: 8,
});

const PageSubtitle = styled(Typography)({
  color: cyberColors.text.secondary,
  marginBottom: 24,
  fontSize: '0.95rem',
});

const SummaryCard = styled(Card)(({ theme }) => ({
  ...glassmorphism.card,
  padding: 20,
  borderRadius: designTokens.borderRadius.lg,
  display: 'flex',
  flexDirection: 'column',
  justifyContent: 'center',
  minHeight: 140,
  transition: 'all 0.2s ease',
  '&:hover': {
    borderColor: cyberColors.neon.cyan,
    boxShadow: `0 0 20px ${alpha(cyberColors.neon.cyan, 0.2)}`,
  },
}));

const StatValue = styled(Typography)({
  fontFamily: designTokens.typography.fontFamily.display,
  fontSize: '2.5rem',
  fontWeight: 700,
  color: cyberColors.neon.cyan,
  lineHeight: 1,
  marginBottom: 8,
});

const StatLabel = styled(Typography)({
  color: cyberColors.text.secondary,
  fontSize: '0.85rem',
  fontWeight: 600,
  textTransform: 'uppercase',
  letterSpacing: '0.05em',
});

const IconBox = styled(Box)({
  width: 40,
  height: 40,
  borderRadius: '50%',
  display: 'flex',
  alignItems: 'center',
  justifyContent: 'center',
  marginBottom: 12,
});

const TabPanel = styled(Box)({
  paddingTop: 24,
});

const EmptyState = styled(Box)({
  ...glassmorphism.card,
  padding: 40,
  borderRadius: designTokens.borderRadius.lg,
  textAlign: 'center',
  display: 'flex',
  flexDirection: 'column',
  alignItems: 'center',
  gap: 16,
});

interface TabPanelProps {
  children?: React.ReactNode;
  index: number;
  value: number;
}

function CustomTabPanel(props: TabPanelProps) {
  const { children, value, index, ...other } = props;

  return (
    <TabPanel
      role="tabpanel"
      hidden={value !== index}
      id={`threat-tabpanel-${index}`}
      aria-labelledby={`threat-tab-${index}`}
      {...other}
    >
      {value === index && children}
    </TabPanel>
  );
}

const ThreatIntelligencePage: React.FC = () => {
  const [tabValue, setTabValue] = useState(0);

  const handleTabChange = (_event: React.SyntheticEvent, newValue: number) => {
    setTabValue(newValue);
  };

  return (
    <PageContainer
      variants={pageVariants}
      initial="initial"
      animate="enter"
      exit="exit"
    >
      <PageTitle>Threat Intelligence</PageTitle>
      <PageSubtitle>Real-time threat feeds, indicators of compromise, and threat actor profiles</PageSubtitle>

      {/* Alert Banner */}
      <Alert
        severity="info"
        sx={{
          mb: 3,
          backgroundColor: alpha(cyberColors.neon.electricBlue, 0.1),
          border: `1px solid ${alpha(cyberColors.neon.electricBlue, 0.3)}`,
          borderRadius: designTokens.borderRadius.lg,
        }}
        icon={<TrendingUpIcon sx={{ color: cyberColors.neon.electricBlue }} />}
      >
        <AlertTitle sx={{ color: cyberColors.neon.electricBlue, fontWeight: 700 }}>
          Connect Intelligence Sources
        </AlertTitle>
        Connect VirusTotal, AlienVault OTX, or ThreatFox via Settings to populate real-time threat feeds and
        automatically extract IOCs from investigation results.
      </Alert>

      {/* Summary Cards - Overview Tab */}
      {tabValue === 0 && (
        <Grid container spacing={2} sx={{ mb: 3 }}>
          {[
            {
              label: 'Active Threats',
              value: '--',
              icon: <WarningIcon sx={{ color: cyberColors.neon.red }} />,
              iconBg: alpha(cyberColors.neon.red, 0.15),
            },
            {
              label: 'IOCs Tracked',
              value: '--',
              icon: <SecurityIcon sx={{ color: cyberColors.neon.orange }} />,
              iconBg: alpha(cyberColors.neon.orange, 0.15),
            },
            {
              label: 'Threat Actors',
              value: '--',
              icon: <PeopleIcon sx={{ color: cyberColors.neon.magenta }} />,
              iconBg: alpha(cyberColors.neon.magenta, 0.15),
            },
            {
              label: 'Intelligence Reports',
              value: '--',
              icon: <TrendingUpIcon sx={{ color: cyberColors.neon.cyan }} />,
              iconBg: alpha(cyberColors.neon.cyan, 0.15),
            },
          ].map((stat, index) => (
            <Grid item xs={12} sm={6} md={3} key={index}>
              <motion.div
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: index * 0.1 }}
              >
                <SummaryCard>
                  <IconBox sx={{ backgroundColor: stat.iconBg }}>
                    {stat.icon}
                  </IconBox>
                  <StatValue>{stat.value}</StatValue>
                  <StatLabel>{stat.label}</StatLabel>
                </SummaryCard>
              </motion.div>
            </Grid>
          ))}
        </Grid>
      )}

      {/* Tabs */}
      <Box
        sx={{
          ...glassmorphism.card,
          borderRadius: designTokens.borderRadius.lg,
          padding: 0,
          overflow: 'hidden',
        }}
      >
        <Tabs
          value={tabValue}
          onChange={handleTabChange}
          aria-label="threat intelligence tabs"
          sx={{
            borderBottom: `1px solid ${alpha(cyberColors.neon.cyan, 0.2)}`,
            '& .MuiTab-root': {
              color: cyberColors.text.secondary,
              textTransform: 'none',
              fontSize: '0.95rem',
              fontWeight: 500,
            },
            '& .Mui-selected': {
              color: cyberColors.neon.cyan,
            },
            '& .MuiTabs-indicator': {
              backgroundColor: cyberColors.neon.cyan,
            },
          }}
        >
          <Tab label="Overview" id="threat-tab-0" aria-controls="threat-tabpanel-0" />
          <Tab label="IOC Feed" id="threat-tab-1" aria-controls="threat-tabpanel-1" />
          <Tab label="Actor Profiles" id="threat-tab-2" aria-controls="threat-tabpanel-2" />
        </Tabs>

        <Box sx={{ p: 3 }}>
          {/* Overview Tab */}
          <CustomTabPanel value={tabValue} index={0}>
            <Typography color="text.secondary" sx={{ fontSize: '0.95rem' }}>
              Summary statistics are populated as you run investigations. Intelligence sources are connected via
              Settings.
            </Typography>
          </CustomTabPanel>

          {/* IOC Feed Tab */}
          <CustomTabPanel value={tabValue} index={1}>
            <EmptyState>
              <SecurityIcon sx={{ fontSize: 48, color: cyberColors.neon.cyan, opacity: 0.5 }} />
              <Typography variant="h6" sx={{ color: cyberColors.text.primary }}>
                No IOCs loaded yet
              </Typography>
              <Typography
                variant="body2"
                sx={{ color: cyberColors.text.secondary, maxWidth: 400 }}
              >
                IOCs (Indicators of Compromise) are automatically extracted and populated from investigation results.
                Run an investigation to see IOCs appear here.
              </Typography>
            </EmptyState>
          </CustomTabPanel>

          {/* Actor Profiles Tab */}
          <CustomTabPanel value={tabValue} index={2}>
            <EmptyState>
              <PeopleIcon sx={{ fontSize: 48, color: cyberColors.neon.magenta, opacity: 0.5 }} />
              <Typography variant="h6" sx={{ color: cyberColors.text.primary }}>
                No threat actor profiles yet
              </Typography>
              <Typography
                variant="body2"
                sx={{ color: cyberColors.text.secondary, maxWidth: 400 }}
              >
                Threat actor profiles are extracted and aggregated from your investigations. As you investigate
                threats, actor information will be collected and displayed here.
              </Typography>
            </EmptyState>
          </CustomTabPanel>
        </Box>
      </Box>
    </PageContainer>
  );
};

export default ThreatIntelligencePage;
