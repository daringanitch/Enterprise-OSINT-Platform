/**
 * Main Layout Component
 *
 * Wraps authenticated pages with header, sidebar, and main content area.
 */

import React, { useState } from 'react';
import { Outlet, useLocation, useNavigate } from 'react-router-dom';
import { Box, styled } from '@mui/material';
import { Header } from './layout/Header';
import { Sidebar } from './layout/Sidebar';
import { cyberColors } from '../utils/theme';

const SIDEBAR_WIDTH = 280;

const LayoutRoot = styled(Box)({
  display: 'flex',
  minHeight: '100vh',
  backgroundColor: cyberColors.dark.charcoal,
});

const MainContent = styled(Box)<{ sidebarOpen: boolean }>(({ sidebarOpen }) => ({
  flexGrow: 1,
  display: 'flex',
  flexDirection: 'column',
  minHeight: '100vh',
  marginLeft: sidebarOpen ? SIDEBAR_WIDTH : 64,
  transition: 'margin-left 0.3s ease',
}));

const ContentArea = styled(Box)(({ theme }) => ({
  flexGrow: 1,
  padding: theme.spacing(3),
  marginTop: 64, // Header height
  backgroundColor: cyberColors.dark.charcoal,
  overflowY: 'auto',
}));

const Layout: React.FC = () => {
  const [sidebarOpen, setSidebarOpen] = useState(true);
  const location = useLocation();
  const navigate = useNavigate();

  const handleNavigate = (path: string) => {
    navigate(path);
  };

  const handleToggleSidebar = () => {
    setSidebarOpen(!sidebarOpen);
  };

  return (
    <LayoutRoot>
      <Header onMenuClick={handleToggleSidebar} />
      <Sidebar
        open={sidebarOpen}
        activePath={location.pathname}
        onNavigate={handleNavigate}
        width={SIDEBAR_WIDTH}
      />
      <MainContent sidebarOpen={sidebarOpen}>
        <ContentArea>
          <Outlet />
        </ContentArea>
      </MainContent>
    </LayoutRoot>
  );
};

export default Layout;
