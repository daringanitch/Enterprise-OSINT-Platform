/**
 * Investigation Detail Page
 */

import React from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import {
  Box,
  Typography,
  Button,
  Grid,
  Chip,
  IconButton,
  Tooltip,
  styled,
} from '@mui/material';
import { motion } from 'framer-motion';
import ArrowBackIcon from '@mui/icons-material/ArrowBack';
import AccountTreeIcon from '@mui/icons-material/AccountTree';
import SecurityIcon from '@mui/icons-material/Security';
import DownloadIcon from '@mui/icons-material/Download';
import { cyberColors, designTokens, glassmorphism } from '../utils/theme';
import { pageVariants } from '../utils/animations';
import { Card } from '../components/common/Card';
import { RiskGauge } from '../components/visualizations/RiskGauge';

const PageContainer = styled(motion.div)({
  padding: 24,
});

const Header = styled(Box)({
  display: 'flex',
  alignItems: 'center',
  gap: 16,
  marginBottom: 24,
});

const Title = styled(Typography)({
  fontFamily: designTokens.typography.fontFamily.display,
  fontSize: '1.75rem',
  fontWeight: 700,
  color: cyberColors.text.primary,
});

const TargetText = styled(Typography)({
  fontFamily: designTokens.typography.fontFamily.mono,
  color: cyberColors.neon.cyan,
  fontSize: '1.25rem',
});

const ActionButton = styled(Button)({
  fontWeight: 600,
  '&.MuiButton-outlined': {
    borderColor: cyberColors.neon.cyan,
    color: cyberColors.neon.cyan,
    '&:hover': {
      backgroundColor: `${cyberColors.neon.cyan}10`,
    },
  },
});

const StatBox = styled(Box)({
  textAlign: 'center',
  padding: 16,
});

const StatValue = styled(Typography)({
  fontFamily: designTokens.typography.fontFamily.mono,
  fontSize: '2rem',
  fontWeight: 700,
  color: cyberColors.neon.cyan,
});

const StatLabel = styled(Typography)({
  color: cyberColors.text.secondary,
  fontSize: '0.875rem',
});

const InvestigationDetailPage: React.FC = () => {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();

  // Mock data
  const investigation = {
    id,
    target: 'suspicious-domain.com',
    status: 'active',
    created: '2024-01-15',
    riskScore: 72,
    findings: 24,
    entities: 156,
    relationships: 89,
  };

  return (
    <PageContainer
      variants={pageVariants}
      initial="initial"
      animate="enter"
      exit="exit"
    >
      <Header>
        <IconButton onClick={() => navigate('/investigations')} sx={{ color: cyberColors.neon.cyan }}>
          <ArrowBackIcon />
        </IconButton>
        <Box sx={{ flex: 1 }}>
          <Title>Investigation Details</Title>
          <TargetText>{investigation.target}</TargetText>
        </Box>
        <Box sx={{ display: 'flex', gap: 1 }}>
          <Tooltip title="View Graph Intelligence">
            <ActionButton
              variant="outlined"
              startIcon={<AccountTreeIcon />}
              onClick={() => navigate(`/investigations/${id}/graph`)}
            >
              Graph
            </ActionButton>
          </Tooltip>
          <Tooltip title="View Threat Analysis">
            <ActionButton
              variant="outlined"
              startIcon={<SecurityIcon />}
              onClick={() => navigate(`/investigations/${id}/threats`)}
            >
              Threats
            </ActionButton>
          </Tooltip>
          <Tooltip title="Export Report">
            <ActionButton variant="outlined" startIcon={<DownloadIcon />}>
              Export
            </ActionButton>
          </Tooltip>
        </Box>
      </Header>

      <Grid container spacing={3}>
        <Grid item xs={12} md={4}>
          <Card variant="cyber" title="Risk Score">
            <Box sx={{ display: 'flex', justifyContent: 'center', py: 2 }}>
              <RiskGauge value={investigation.riskScore} size={180} />
            </Box>
          </Card>
        </Grid>

        <Grid item xs={12} md={8}>
          <Card variant="cyber" title="Investigation Stats">
            <Grid container>
              <Grid item xs={3}>
                <StatBox>
                  <StatValue>{investigation.findings}</StatValue>
                  <StatLabel>Findings</StatLabel>
                </StatBox>
              </Grid>
              <Grid item xs={3}>
                <StatBox>
                  <StatValue>{investigation.entities}</StatValue>
                  <StatLabel>Entities</StatLabel>
                </StatBox>
              </Grid>
              <Grid item xs={3}>
                <StatBox>
                  <StatValue>{investigation.relationships}</StatValue>
                  <StatLabel>Relationships</StatLabel>
                </StatBox>
              </Grid>
              <Grid item xs={3}>
                <StatBox>
                  <Chip
                    label={investigation.status.toUpperCase()}
                    sx={{
                      backgroundColor: `${cyberColors.neon.green}20`,
                      color: cyberColors.neon.green,
                      fontWeight: 600,
                    }}
                  />
                  <StatLabel sx={{ mt: 1 }}>Status</StatLabel>
                </StatBox>
              </Grid>
            </Grid>
          </Card>
        </Grid>

        <Grid item xs={12}>
          <Card variant="cyber" title="Recent Findings">
            <Typography color="text.secondary">
              Investigation findings will be displayed here...
            </Typography>
          </Card>
        </Grid>
      </Grid>
    </PageContainer>
  );
};

export default InvestigationDetailPage;
