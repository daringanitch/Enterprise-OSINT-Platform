/**
 * Settings Page
 */

import React from 'react';
import { Box, Typography, Switch, FormControlLabel, Divider, styled } from '@mui/material';
import { motion } from 'framer-motion';
import { cyberColors, designTokens, glassmorphism } from '../utils/theme';
import { pageVariants } from '../utils/animations';

const PageContainer = styled(motion.div)({
  padding: 24,
  maxWidth: 800,
  margin: '0 auto',
});

const Title = styled(Typography)({
  fontFamily: designTokens.typography.fontFamily.display,
  fontSize: '1.75rem',
  fontWeight: 700,
  color: cyberColors.text.primary,
  marginBottom: 24,
});

const SettingsCard = styled(Box)({
  ...glassmorphism.card,
  padding: 24,
  borderRadius: designTokens.borderRadius.lg,
  marginBottom: 24,
});

const SectionTitle = styled(Typography)({
  fontFamily: designTokens.typography.fontFamily.display,
  fontSize: '1.1rem',
  fontWeight: 600,
  color: cyberColors.neon.cyan,
  marginBottom: 16,
});

const SettingRow = styled(Box)({
  display: 'flex',
  justifyContent: 'space-between',
  alignItems: 'center',
  padding: '12px 0',
});

const SettingLabel = styled(Typography)({
  color: cyberColors.text.primary,
});

const SettingDescription = styled(Typography)({
  color: cyberColors.text.secondary,
  fontSize: '0.875rem',
});

const StyledSwitch = styled(Switch)({
  '& .MuiSwitch-switchBase.Mui-checked': {
    color: cyberColors.neon.cyan,
  },
  '& .MuiSwitch-switchBase.Mui-checked + .MuiSwitch-track': {
    backgroundColor: cyberColors.neon.cyan,
  },
});

const SettingsPage: React.FC = () => {
  return (
    <PageContainer
      variants={pageVariants}
      initial="initial"
      animate="enter"
      exit="exit"
    >
      <Title>Settings</Title>

      <SettingsCard>
        <SectionTitle>Notifications</SectionTitle>
        <SettingRow>
          <Box>
            <SettingLabel>Email Notifications</SettingLabel>
            <SettingDescription>Receive email alerts for investigation updates</SettingDescription>
          </Box>
          <StyledSwitch defaultChecked />
        </SettingRow>
        <Divider sx={{ borderColor: cyberColors.border.subtle }} />
        <SettingRow>
          <Box>
            <SettingLabel>Threat Alerts</SettingLabel>
            <SettingDescription>Real-time alerts for critical threats</SettingDescription>
          </Box>
          <StyledSwitch defaultChecked />
        </SettingRow>
      </SettingsCard>

      <SettingsCard>
        <SectionTitle>Display</SectionTitle>
        <SettingRow>
          <Box>
            <SettingLabel>Dark Mode</SettingLabel>
            <SettingDescription>Use dark theme (cyberpunk aesthetic)</SettingDescription>
          </Box>
          <StyledSwitch defaultChecked disabled />
        </SettingRow>
        <Divider sx={{ borderColor: cyberColors.border.subtle }} />
        <SettingRow>
          <Box>
            <SettingLabel>Reduced Motion</SettingLabel>
            <SettingDescription>Minimize animations for accessibility</SettingDescription>
          </Box>
          <StyledSwitch />
        </SettingRow>
      </SettingsCard>

      <SettingsCard>
        <SectionTitle>Data & Privacy</SectionTitle>
        <SettingRow>
          <Box>
            <SettingLabel>Auto-Archive</SettingLabel>
            <SettingDescription>Automatically archive completed investigations</SettingDescription>
          </Box>
          <StyledSwitch defaultChecked />
        </SettingRow>
        <Divider sx={{ borderColor: cyberColors.border.subtle }} />
        <SettingRow>
          <Box>
            <SettingLabel>Data Retention</SettingLabel>
            <SettingDescription>Keep investigation data for 90 days</SettingDescription>
          </Box>
          <StyledSwitch defaultChecked />
        </SettingRow>
      </SettingsCard>
    </PageContainer>
  );
};

export default SettingsPage;
