/**
 * Team Management Page
 *
 * Simple placeholder page for team management features coming in future releases.
 */

import React from 'react';
import {
  Box,
  Typography,
  Card,
  Grid,
  Alert,
  AlertTitle,
  styled,
  alpha,
} from '@mui/material';
import {
  People as PeopleIcon,
  Security as SecurityIcon,
  Assignment as AssignmentIcon,
  History as HistoryIcon,
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

const Banner = styled(Alert)({
  backgroundColor: alpha(cyberColors.neon.orange, 0.1),
  border: `1px solid ${alpha(cyberColors.neon.orange, 0.3)}`,
  borderRadius: designTokens.borderRadius.lg,
  marginBottom: 32,
});

const FeatureCard = styled(motion.div)({
  ...glassmorphism.card,
  padding: 24,
  borderRadius: designTokens.borderRadius.lg,
  display: 'flex',
  flexDirection: 'column',
  alignItems: 'center',
  textAlign: 'center',
  transition: 'all 0.2s ease',
  '&:hover': {
    borderColor: cyberColors.neon.cyan,
    boxShadow: `0 0 20px ${alpha(cyberColors.neon.cyan, 0.15)}`,
  },
});

const FeatureIcon = styled(Box)({
  width: 56,
  height: 56,
  borderRadius: '50%',
  display: 'flex',
  alignItems: 'center',
  justifyContent: 'center',
  marginBottom: 16,
  backgroundColor: alpha(cyberColors.neon.cyan, 0.15),
  color: cyberColors.neon.cyan,
  fontSize: 28,
});

const FeatureTitle = styled(Typography)({
  fontFamily: designTokens.typography.fontFamily.display,
  fontSize: '1.1rem',
  fontWeight: 700,
  color: cyberColors.text.primary,
  marginBottom: 8,
});

const FeatureDescription = styled(Typography)({
  color: cyberColors.text.secondary,
  fontSize: '0.9rem',
  lineHeight: 1.6,
});

interface Feature {
  id: string;
  title: string;
  description: string;
  icon: React.ReactNode;
}

const features: Feature[] = [
  {
    id: 'rbac',
    title: 'Role-Based Access Control',
    description: 'Define roles and permissions for team members with granular access controls',
    icon: <SecurityIcon />,
  },
  {
    id: 'assignments',
    title: 'Investigation Assignments',
    description: 'Assign investigations to team members and track progress across investigations',
    icon: <AssignmentIcon />,
  },
  {
    id: 'audit',
    title: 'Audit Trail',
    description: 'Complete audit logs of all team actions and investigation modifications',
    icon: <HistoryIcon />,
  },
];

const TeamPage: React.FC = () => {
  return (
    <PageContainer
      variants={pageVariants}
      initial="initial"
      animate="enter"
      exit="exit"
    >
      <PageTitle>Team Management</PageTitle>
      <PageSubtitle>Manage team members, roles, and investigation assignments</PageSubtitle>

      {/* Coming Soon Banner */}
      <Banner
        severity="warning"
        icon={<AlertTitle />}
      >
        <AlertTitle sx={{ color: cyberColors.neon.orange, fontWeight: 700, mb: 0.5 }}>
          Upcoming Feature
        </AlertTitle>
        <Typography sx={{ color: cyberColors.text.secondary, fontSize: '0.9rem' }}>
          Team management features are coming in a future release. Stay tuned for role-based access control,
          investigation assignments, and detailed audit trails.
        </Typography>
      </Banner>

      {/* Feature Preview Cards */}
      <Box sx={{ mb: 4 }}>
        <Typography
          sx={{
            fontFamily: designTokens.typography.fontFamily.display,
            fontSize: '1rem',
            fontWeight: 600,
            color: cyberColors.text.primary,
            marginBottom: 2,
            textTransform: 'uppercase',
            letterSpacing: '0.05em',
            display: 'flex',
            alignItems: 'center',
            gap: 1,
          }}
        >
          <PeopleIcon sx={{ fontSize: 20 }} />
          Coming Features
        </Typography>

        <Grid container spacing={2}>
          {features.map((feature, index) => (
            <Grid item xs={12} sm={6} md={4} key={feature.id}>
              <motion.div
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: index * 0.1 }}
              >
                <FeatureCard>
                  <FeatureIcon>{feature.icon}</FeatureIcon>
                  <FeatureTitle>{feature.title}</FeatureTitle>
                  <FeatureDescription>{feature.description}</FeatureDescription>
                </FeatureCard>
              </motion.div>
            </Grid>
          ))}
        </Grid>
      </Box>
    </PageContainer>
  );
};

export default TeamPage;
