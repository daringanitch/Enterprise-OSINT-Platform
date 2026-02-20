/**
 * New Investigation Page
 */

import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Box,
  Typography,
  TextField,
  Button,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  styled,
} from '@mui/material';
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

const FormCard = styled(Box)({
  ...glassmorphism.card,
  padding: 32,
  borderRadius: designTokens.borderRadius.lg,
});

const StyledTextField = styled(TextField)({
  marginBottom: 24,
  '& .MuiOutlinedInput-root': {
    color: cyberColors.text.primary,
    backgroundColor: cyberColors.dark.slate,
    '& fieldset': {
      borderColor: cyberColors.border.subtle,
    },
    '&:hover fieldset': {
      borderColor: cyberColors.neon.cyan,
    },
    '&.Mui-focused fieldset': {
      borderColor: cyberColors.neon.cyan,
    },
  },
  '& .MuiInputLabel-root': {
    color: cyberColors.text.secondary,
    '&.Mui-focused': {
      color: cyberColors.neon.cyan,
    },
  },
});

const StyledSelect = styled(FormControl)({
  marginBottom: 24,
  '& .MuiOutlinedInput-root': {
    color: cyberColors.text.primary,
    backgroundColor: cyberColors.dark.slate,
    '& fieldset': {
      borderColor: cyberColors.border.subtle,
    },
    '&:hover fieldset': {
      borderColor: cyberColors.neon.cyan,
    },
    '&.Mui-focused fieldset': {
      borderColor: cyberColors.neon.cyan,
    },
  },
  '& .MuiInputLabel-root': {
    color: cyberColors.text.secondary,
    '&.Mui-focused': {
      color: cyberColors.neon.cyan,
    },
  },
});

const SubmitButton = styled(Button)({
  marginTop: 16,
  padding: '12px 32px',
  fontFamily: designTokens.typography.fontFamily.display,
  fontWeight: 600,
  backgroundColor: cyberColors.neon.cyan,
  color: cyberColors.dark.void,
  '&:hover': {
    backgroundColor: cyberColors.neon.electricBlue,
    boxShadow: `0 0 20px ${cyberColors.neon.cyan}60`,
  },
});

const NewInvestigationPage: React.FC = () => {
  const navigate = useNavigate();
  const [target, setTarget] = useState('');
  const [targetType, setTargetType] = useState('domain');
  const [description, setDescription] = useState('');

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    // API call would go here
    navigate('/investigations');
  };

  return (
    <PageContainer
      variants={pageVariants}
      initial="initial"
      animate="enter"
      exit="exit"
    >
      <Title>New Investigation</Title>

      <FormCard>
        <form onSubmit={handleSubmit}>
          <StyledTextField
            fullWidth
            label="Target"
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            placeholder="e.g., domain.com, 192.168.1.1, email@example.com"
            required
          />

          <StyledSelect fullWidth>
            <InputLabel>Target Type</InputLabel>
            <Select
              value={targetType}
              label="Target Type"
              onChange={(e) => setTargetType(e.target.value)}
            >
              <MenuItem value="domain">Domain</MenuItem>
              <MenuItem value="ip">IP Address</MenuItem>
              <MenuItem value="email">Email</MenuItem>
              <MenuItem value="organization">Organization</MenuItem>
              <MenuItem value="person">Person</MenuItem>
            </Select>
          </StyledSelect>

          <StyledTextField
            fullWidth
            label="Description"
            value={description}
            onChange={(e) => setDescription(e.target.value)}
            multiline
            rows={4}
            placeholder="Describe the investigation objectives..."
          />

          <Box sx={{ display: 'flex', gap: 2, justifyContent: 'flex-end' }}>
            <Button
              variant="outlined"
              onClick={() => navigate('/investigations')}
              sx={{
                borderColor: cyberColors.border.subtle,
                color: cyberColors.text.secondary,
              }}
            >
              Cancel
            </Button>
            <SubmitButton type="submit" variant="contained">
              Start Investigation
            </SubmitButton>
          </Box>
        </form>
      </FormCard>
    </PageContainer>
  );
};

export default NewInvestigationPage;
