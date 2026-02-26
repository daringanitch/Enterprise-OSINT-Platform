/**
 * Compliance Framework Dashboard Page
 *
 * Displays compliance frameworks and assessment history.
 */

import React, { useState } from 'react';
import {
  Box,
  Typography,
  Button,
  Card,
  Grid,
  Alert,
  AlertTitle,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  styled,
  alpha,
  CircularProgress,
} from '@mui/material';
import {
  VerifiedUser as VerifiedUserIcon,
  Check as CheckIcon,
  Info as InfoIcon,
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

const FrameworkCard = styled(motion.div)({
  ...glassmorphism.card,
  padding: 24,
  borderRadius: designTokens.borderRadius.lg,
  cursor: 'pointer',
  transition: 'all 0.2s ease',
  '&:hover': {
    borderColor: cyberColors.neon.cyan,
    boxShadow: `0 0 20px ${alpha(cyberColors.neon.cyan, 0.2)}`,
  },
});

const FrameworkIcon = styled(Box)({
  width: 48,
  height: 48,
  borderRadius: '50%',
  display: 'flex',
  alignItems: 'center',
  justifyContent: 'center',
  marginBottom: 16,
  backgroundColor: alpha(cyberColors.neon.cyan, 0.15),
  color: cyberColors.neon.cyan,
});

const FrameworkTitle = styled(Typography)({
  fontFamily: designTokens.typography.fontFamily.display,
  fontSize: '1.25rem',
  fontWeight: 700,
  color: cyberColors.text.primary,
  marginBottom: 8,
});

const FrameworkDescription = styled(Typography)({
  color: cyberColors.text.secondary,
  fontSize: '0.9rem',
  lineHeight: 1.6,
  marginBottom: 16,
});

const SectionTitle = styled(Typography)({
  fontFamily: designTokens.typography.fontFamily.display,
  fontSize: '1rem',
  fontWeight: 600,
  color: cyberColors.text.primary,
  marginTop: 32,
  marginBottom: 16,
  textTransform: 'uppercase',
  letterSpacing: '0.05em',
  display: 'flex',
  alignItems: 'center',
  gap: 1,
});

const EmptyStateBox = styled(Box)({
  ...glassmorphism.card,
  padding: 40,
  borderRadius: designTokens.borderRadius.lg,
  textAlign: 'center',
  display: 'flex',
  flexDirection: 'column',
  alignItems: 'center',
  gap: 16,
});

interface Framework {
  id: string;
  name: string;
  description: string;
  icon: React.ReactNode;
}

const frameworks: Framework[] = [
  {
    id: 'gdpr',
    name: 'GDPR',
    description: 'General Data Protection Regulation - EU data protection and privacy regulation',
    icon: <VerifiedUserIcon />,
  },
  {
    id: 'ccpa',
    name: 'CCPA',
    description: 'California Consumer Privacy Act - California data privacy rights legislation',
    icon: <VerifiedUserIcon />,
  },
  {
    id: 'hipaa',
    name: 'HIPAA',
    description: 'Health Insurance Portability and Accountability Act - Healthcare data protection',
    icon: <VerifiedUserIcon />,
  },
  {
    id: 'sox',
    name: 'SOX',
    description: 'Sarbanes-Oxley Act - Financial reporting and corporate governance',
    icon: <VerifiedUserIcon />,
  },
];

const CompliancePage: React.FC = () => {
  const [selectedFramework, setSelectedFramework] = useState<Framework | null>(null);
  const [isRunningAssessment, setIsRunningAssessment] = useState(false);

  const handleFrameworkClick = (framework: Framework) => {
    setSelectedFramework(framework);
  };

  const handleCloseDialog = () => {
    setSelectedFramework(null);
  };

  const handleRunAssessment = async () => {
    setIsRunningAssessment(true);
    // Simulate assessment API call
    setTimeout(() => {
      setIsRunningAssessment(false);
      alert(`Assessment for ${selectedFramework?.name} initiated. Check back soon for results.`);
      handleCloseDialog();
    }, 2000);
  };

  return (
    <PageContainer
      variants={pageVariants}
      initial="initial"
      animate="enter"
      exit="exit"
    >
      <PageTitle>Compliance Dashboard</PageTitle>
      <PageSubtitle>Track compliance with industry frameworks and regulatory standards</PageSubtitle>

      {/* Frameworks Section */}
      <Box sx={{ mb: 4 }}>
        <SectionTitle>
          <CheckIcon sx={{ fontSize: 20 }} />
          Supported Frameworks
        </SectionTitle>
        <Grid container spacing={2}>
          {frameworks.map((framework, index) => (
            <Grid item xs={12} sm={6} md={3} key={framework.id}>
              <motion.div
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: index * 0.1 }}
              >
                <FrameworkCard onClick={() => handleFrameworkClick(framework)}>
                  <FrameworkIcon>{framework.icon}</FrameworkIcon>
                  <FrameworkTitle>{framework.name}</FrameworkTitle>
                  <FrameworkDescription>{framework.description}</FrameworkDescription>
                  <Button
                    variant="outlined"
                    size="small"
                    fullWidth
                    onClick={(e) => {
                      e.stopPropagation();
                      handleFrameworkClick(framework);
                    }}
                    sx={{
                      borderColor: cyberColors.neon.cyan,
                      color: cyberColors.neon.cyan,
                      '&:hover': {
                        backgroundColor: alpha(cyberColors.neon.cyan, 0.1),
                        borderColor: cyberColors.neon.cyan,
                      },
                    }}
                  >
                    View Details
                  </Button>
                </FrameworkCard>
              </motion.div>
            </Grid>
          ))}
        </Grid>
      </Box>

      {/* Assessment History Section */}
      <Box>
        <SectionTitle>
          <InfoIcon sx={{ fontSize: 20 }} />
          Assessment History
        </SectionTitle>
        <EmptyStateBox>
          <VerifiedUserIcon sx={{ fontSize: 48, color: cyberColors.neon.cyan, opacity: 0.5 }} />
          <Typography variant="h6" sx={{ color: cyberColors.text.primary }}>
            No assessments yet
          </Typography>
          <Typography
            variant="body2"
            sx={{ color: cyberColors.text.secondary, maxWidth: 400 }}
          >
            Run a compliance assessment by selecting a framework above. Assessment results will appear here.
          </Typography>
        </EmptyStateBox>
      </Box>

      {/* Framework Details Dialog */}
      <Dialog
        open={selectedFramework !== null}
        onClose={handleCloseDialog}
        maxWidth="sm"
        fullWidth
        PaperProps={{
          sx: {
            ...glassmorphism.card,
            borderRadius: designTokens.borderRadius.lg,
          },
        }}
      >
        <DialogTitle
          sx={{
            fontFamily: designTokens.typography.fontFamily.display,
            fontSize: '1.25rem',
            fontWeight: 700,
            color: cyberColors.neon.cyan,
          }}
        >
          {selectedFramework?.name}
        </DialogTitle>
        <DialogContent sx={{ pt: 2 }}>
          <Typography color="text.secondary" sx={{ mb: 2 }}>
            {selectedFramework?.description}
          </Typography>
          <Alert
            severity="info"
            sx={{
              backgroundColor: alpha(cyberColors.neon.electricBlue, 0.1),
              border: `1px solid ${alpha(cyberColors.neon.electricBlue, 0.3)}`,
              borderRadius: designTokens.borderRadius.md,
            }}
          >
            <AlertTitle sx={{ color: cyberColors.neon.electricBlue }}>
              Assessment Ready
            </AlertTitle>
            Run an automated compliance assessment to evaluate your organization's adherence to this framework.
          </Alert>
        </DialogContent>
        <DialogActions sx={{ gap: 1, p: 2 }}>
          <Button onClick={handleCloseDialog} sx={{ color: cyberColors.text.secondary }}>
            Cancel
          </Button>
          <Button
            onClick={handleRunAssessment}
            disabled={isRunningAssessment}
            variant="contained"
            sx={{
              backgroundColor: cyberColors.neon.cyan,
              color: cyberColors.dark.void,
              '&:hover': {
                backgroundColor: cyberColors.neon.electricBlue,
              },
              '&:disabled': {
                backgroundColor: alpha(cyberColors.neon.cyan, 0.5),
              },
            }}
          >
            {isRunningAssessment ? (
              <>
                <CircularProgress size={16} sx={{ mr: 1, color: 'inherit' }} />
                Running...
              </>
            ) : (
              'Run Assessment'
            )}
          </Button>
        </DialogActions>
      </Dialog>
    </PageContainer>
  );
};

export default CompliancePage;
