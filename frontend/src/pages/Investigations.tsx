/**
 * Investigations List Page
 */

import React from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Box,
  Typography,
  Button,
  Chip,
  styled,
} from '@mui/material';
import { motion } from 'framer-motion';
import AddIcon from '@mui/icons-material/Add';
import { cyberColors, designTokens, glassmorphism } from '../utils/theme';
import { pageVariants } from '../utils/animations';
import { Card } from '../components/common/Card';

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

const NewButton = styled(Button)({
  backgroundColor: cyberColors.neon.cyan,
  color: cyberColors.dark.void,
  fontWeight: 600,
  '&:hover': {
    backgroundColor: cyberColors.neon.electricBlue,
    boxShadow: `0 0 20px ${cyberColors.neon.cyan}60`,
  },
});

const InvestigationCard = styled(motion.div)({
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

const StatusChip = styled(Chip)<{ status: string }>(({ status }) => {
  const colors: Record<string, string> = {
    active: cyberColors.neon.green,
    pending: cyberColors.neon.orange,
    completed: cyberColors.neon.cyan,
    failed: cyberColors.neon.red,
  };
  const color = colors[status] || cyberColors.text.secondary;
  return {
    backgroundColor: `${color}20`,
    color: color,
    fontWeight: 600,
    fontSize: '0.75rem',
  };
});

// Mock data
const investigations = [
  { id: '1', target: 'suspicious-domain.com', status: 'active', created: '2024-01-15', findings: 24 },
  { id: '2', target: '192.168.1.100', status: 'completed', created: '2024-01-14', findings: 18 },
  { id: '3', target: 'threat-actor@example.com', status: 'pending', created: '2024-01-13', findings: 0 },
];

const InvestigationsPage: React.FC = () => {
  const navigate = useNavigate();

  return (
    <PageContainer
      variants={pageVariants}
      initial="initial"
      animate="enter"
      exit="exit"
    >
      <Header>
        <Title>Investigations</Title>
        <NewButton
          variant="contained"
          startIcon={<AddIcon />}
          onClick={() => navigate('/investigations/new')}
        >
          New Investigation
        </NewButton>
      </Header>

      {investigations.map((inv, index) => (
        <InvestigationCard
          key={inv.id}
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: index * 0.1 }}
          onClick={() => navigate(`/investigations/${inv.id}`)}
        >
          <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
            <Box>
              <Typography
                sx={{
                  fontFamily: designTokens.typography.fontFamily.mono,
                  color: cyberColors.neon.cyan,
                  fontSize: '1.1rem',
                  fontWeight: 600,
                  mb: 1,
                }}
              >
                {inv.target}
              </Typography>
              <Typography variant="body2" sx={{ color: cyberColors.text.secondary }}>
                Created: {inv.created} | Findings: {inv.findings}
              </Typography>
            </Box>
            <StatusChip label={inv.status.toUpperCase()} status={inv.status} size="small" />
          </Box>
        </InvestigationCard>
      ))}

      {investigations.length === 0 && (
        <Card variant="glass">
          <Typography color="text.secondary" textAlign="center">
            No investigations yet. Create one to get started.
          </Typography>
        </Card>
      )}
    </PageContainer>
  );
};

export default InvestigationsPage;
