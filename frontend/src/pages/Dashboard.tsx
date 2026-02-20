/**
 * Dashboard Page
 */

import React from 'react';
import { Box, Typography, Grid, styled } from '@mui/material';
import { motion } from 'framer-motion';
import SecurityIcon from '@mui/icons-material/Security';
import AssessmentIcon from '@mui/icons-material/Assessment';
import SearchIcon from '@mui/icons-material/Search';
import TrendingUpIcon from '@mui/icons-material/TrendingUp';
import { cyberColors, designTokens, glassmorphism } from '../utils/theme';
import { pageVariants, cardVariants } from '../utils/animations';
import { Card } from '../components/common/Card';

const PageContainer = styled(motion.div)({
  padding: 24,
});

const WelcomeSection = styled(Box)({
  marginBottom: 32,
});

const Title = styled(Typography)({
  fontFamily: designTokens.typography.fontFamily.display,
  fontSize: '2rem',
  fontWeight: 700,
  color: cyberColors.text.primary,
  marginBottom: 8,
});

const Subtitle = styled(Typography)({
  color: cyberColors.text.secondary,
  fontSize: '1rem',
});

const StatCard = styled(motion.div)({
  ...glassmorphism.card,
  padding: 24,
  borderRadius: designTokens.borderRadius.lg,
  display: 'flex',
  alignItems: 'center',
  gap: 16,
});

const StatIcon = styled(Box)<{ color: string }>(({ color }) => ({
  width: 56,
  height: 56,
  borderRadius: designTokens.borderRadius.md,
  display: 'flex',
  alignItems: 'center',
  justifyContent: 'center',
  backgroundColor: `${color}20`,
  color: color,
  '& svg': {
    fontSize: 28,
  },
}));

const StatValue = styled(Typography)({
  fontFamily: designTokens.typography.fontFamily.mono,
  fontSize: '2rem',
  fontWeight: 700,
  color: cyberColors.text.primary,
  lineHeight: 1,
});

const StatLabel = styled(Typography)({
  color: cyberColors.text.secondary,
  fontSize: '0.875rem',
  marginTop: 4,
});

const stats = [
  { icon: <SearchIcon />, value: '12', label: 'Active Investigations', color: cyberColors.neon.cyan },
  { icon: <SecurityIcon />, value: '847', label: 'Threats Analyzed', color: cyberColors.neon.magenta },
  { icon: <AssessmentIcon />, value: '98%', label: 'Detection Rate', color: cyberColors.neon.green },
  { icon: <TrendingUpIcon />, value: '24', label: 'Reports Generated', color: cyberColors.neon.orange },
];

const DashboardPage: React.FC = () => {
  return (
    <PageContainer
      variants={pageVariants}
      initial="initial"
      animate="enter"
      exit="exit"
    >
      <WelcomeSection>
        <Title>Intelligence Dashboard</Title>
        <Subtitle>Real-time threat monitoring and investigation management</Subtitle>
      </WelcomeSection>

      <Grid container spacing={3}>
        {stats.map((stat, index) => (
          <Grid item xs={12} sm={6} lg={3} key={stat.label}>
            <StatCard
              variants={cardVariants}
              initial="initial"
              animate="animate"
              whileHover="hover"
              custom={index}
            >
              <StatIcon color={stat.color}>{stat.icon}</StatIcon>
              <Box>
                <StatValue>{stat.value}</StatValue>
                <StatLabel>{stat.label}</StatLabel>
              </Box>
            </StatCard>
          </Grid>
        ))}
      </Grid>

      <Box sx={{ mt: 4 }}>
        <Grid container spacing={3}>
          <Grid item xs={12} lg={8}>
            <Card variant="cyber" title="Recent Activity">
              <Typography color="text.secondary">
                Activity feed will display here...
              </Typography>
            </Card>
          </Grid>
          <Grid item xs={12} lg={4}>
            <Card variant="cyber" title="Quick Actions">
              <Typography color="text.secondary">
                Quick action buttons will display here...
              </Typography>
            </Card>
          </Grid>
        </Grid>
      </Box>
    </PageContainer>
  );
};

export default DashboardPage;
