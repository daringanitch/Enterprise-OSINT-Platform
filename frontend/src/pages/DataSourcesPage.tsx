/**
 * Data Sources Overview Page
 *
 * Displays available intelligence data sources and categories.
 */

import React from 'react';
import {
  Box,
  Typography,
  Button,
  Card,
  Grid,
  Chip,
  styled,
  alpha,
} from '@mui/material';
import {
  Settings as SettingsIcon,
  NetworkCheck as NetworkIcon,
  Security as SecurityIcon,
  PersonSearch as SocialIcon,
  SmartToy as AiIcon,
  Lock as BreachIcon,
  TrendingUp as AnalyticsIcon,
} from '@mui/icons-material';
import { useNavigate } from 'react-router-dom';
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
  marginBottom: 12,
  fontSize: '0.95rem',
});

const IntroText = styled(Typography)({
  color: cyberColors.text.secondary,
  marginBottom: 32,
  fontSize: '0.9rem',
  lineHeight: 1.6,
  maxWidth: 600,
});

const CategoryCard = styled(motion.div)({
  ...glassmorphism.card,
  padding: 24,
  borderRadius: designTokens.borderRadius.lg,
  transition: 'all 0.2s ease',
  '&:hover': {
    borderColor: cyberColors.neon.cyan,
    boxShadow: `0 0 20px ${alpha(cyberColors.neon.cyan, 0.2)}`,
  },
});

const CategoryHeader = styled(Box)({
  display: 'flex',
  alignItems: 'center',
  gap: 12,
  marginBottom: 16,
});

const CategoryIcon = styled(Box)({
  width: 48,
  height: 48,
  borderRadius: '50%',
  display: 'flex',
  alignItems: 'center',
  justifyContent: 'center',
  backgroundColor: alpha(cyberColors.neon.cyan, 0.15),
  color: cyberColors.neon.cyan,
  fontSize: 24,
});

const CategoryTitle = styled(Typography)({
  fontFamily: designTokens.typography.fontFamily.display,
  fontSize: '1.1rem',
  fontWeight: 700,
  color: cyberColors.text.primary,
});

const SourceList = styled(Box)({
  display: 'flex',
  flexDirection: 'column',
  gap: 8,
  marginBottom: 16,
});

const SourceItem = styled(Typography)({
  color: cyberColors.text.secondary,
  fontSize: '0.9rem',
  display: 'flex',
  alignItems: 'center',
  gap: 8,
  '&::before': {
    content: '"•"',
    color: cyberColors.neon.cyan,
    fontWeight: 'bold',
  },
});

interface DataSourceCategory {
  id: string;
  title: string;
  icon: React.ReactNode;
  sources: string[];
  tiers: string[];
}

const categories: DataSourceCategory[] = [
  {
    id: 'network',
    title: 'Network Intelligence',
    icon: <NetworkIcon />,
    sources: ['DNS Lookups', 'WHOIS', 'Certificate Transparency', 'Geolocation'],
    tiers: ['Free'],
  },
  {
    id: 'threat',
    title: 'Threat Intelligence',
    icon: <SecurityIcon />,
    sources: ['VirusTotal', 'Shodan', 'AbuseIPDB', 'AlienVault OTX', 'ThreatFox'],
    tiers: ['Free', 'API Key Required'],
  },
  {
    id: 'breach',
    title: 'Breach Data',
    icon: <BreachIcon />,
    sources: ['Have I Been Pwned', 'Dehashed', 'Hudson Rock'],
    tiers: ['Free', 'API Key Required'],
  },
  {
    id: 'social',
    title: 'Social Intelligence',
    icon: <SocialIcon />,
    sources: ['Social Media Monitoring', 'Leaked Credentials', 'Forum Intelligence'],
    tiers: ['API Key Required'],
  },
  {
    id: 'financial',
    title: 'Financial Intelligence',
    icon: <AnalyticsIcon />,
    sources: ['SEC Filings', 'Corporate Records', 'Financial Data'],
    tiers: ['Free', 'API Key Required'],
  },
  {
    id: 'ai',
    title: 'AI Analysis',
    icon: <AiIcon />,
    sources: ['OpenAI Analysis', 'Threat Profiling', 'Executive Summaries'],
    tiers: ['API Key Required'],
  },
];

const DataSourcesPage: React.FC = () => {
  const navigate = useNavigate();

  return (
    <PageContainer
      variants={pageVariants}
      initial="initial"
      animate="enter"
      exit="exit"
    >
      <PageTitle>Data Sources</PageTitle>
      <PageSubtitle>Available intelligence sources and data categories</PageSubtitle>
      <IntroText>
        Manage and monitor intelligence data sources. Configure API keys in Settings to unlock premium features
        and real-time data feeds.
      </IntroText>

      {/* Data Source Categories */}
      <Grid container spacing={2} sx={{ mb: 4 }}>
        {categories.map((category, index) => (
          <Grid item xs={12} sm={6} md={4} key={category.id}>
            <motion.div
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: index * 0.1 }}
            >
              <CategoryCard>
                <CategoryHeader>
                  <CategoryIcon>{category.icon}</CategoryIcon>
                  <CategoryTitle>{category.title}</CategoryTitle>
                </CategoryHeader>

                <SourceList>
                  {category.sources.map((source, idx) => (
                    <SourceItem key={idx}>{source}</SourceItem>
                  ))}
                </SourceList>

                <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap', mb: 16 }}>
                  {category.tiers.map((tier, idx) => (
                    <Chip
                      key={idx}
                      label={tier}
                      size="small"
                      variant="outlined"
                      sx={{
                        borderColor: tier === 'Free' ? cyberColors.neon.green : cyberColors.neon.orange,
                        color: tier === 'Free' ? cyberColors.neon.green : cyberColors.neon.orange,
                        fontSize: '0.75rem',
                        height: 24,
                      }}
                    />
                  ))}
                </Box>
              </CategoryCard>
            </motion.div>
          </Grid>
        ))}
      </Grid>

      {/* Configure Button */}
      <Box sx={{ display: 'flex', justifyContent: 'center', mt: 4 }}>
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.5 }}
        >
          <Button
            variant="contained"
            size="large"
            startIcon={<SettingsIcon />}
            onClick={() => navigate('/settings')}
            sx={{
              backgroundColor: cyberColors.neon.cyan,
              color: cyberColors.dark.void,
              fontWeight: 600,
              padding: '12px 28px',
              '&:hover': {
                backgroundColor: cyberColors.neon.electricBlue,
                boxShadow: `0 0 30px ${alpha(cyberColors.neon.cyan, 0.4)}`,
              },
            }}
          >
            Configure Sources in Settings
          </Button>
        </motion.div>
      </Box>
    </PageContainer>
  );
};

export default DataSourcesPage;
