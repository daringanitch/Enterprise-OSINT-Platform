/**
 * Main Layout Component
 *
 * Wraps authenticated pages with header, sidebar, and main content area.
 * Also hosts the global Command Palette (⌘K) and its context provider,
 * so it is available on every authenticated page.
 */

import React, { useState, createContext } from 'react';
import { Outlet, useLocation, useNavigate } from 'react-router-dom';
import { Box, styled } from '@mui/material';
import { Header } from './layout/Header';
import { Sidebar } from './layout/Sidebar';
import { cyberColors } from '../utils/theme';
import { CommandPalette } from './common/CommandPalette';
import {
  CommandPaletteContext,
  useCommandPaletteState,
} from '../hooks/useCommandPalette';

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

// Mock recent investigations — replace with real API data in Sprint 2
const RECENT_INVESTIGATIONS = [
  { id: '4', target: 'malware-c2.net', status: 'analyzing' },
  { id: '1', target: 'suspicious-domain.com', status: 'collecting' },
  { id: '3', target: 'threat-actor@example.com', status: 'pending' },
  { id: '7', target: '10.0.0.55', status: 'generating_report' },
];

const Layout: React.FC = () => {
  const [sidebarOpen, setSidebarOpen] = useState(true);
  const location = useLocation();
  const navigate = useNavigate();

  // Command Palette state — owns global ⌘K context
  const cmdPalette = useCommandPaletteState();

  const handleNavigate = (path: string) => {
    navigate(path);
  };

  const handleToggleSidebar = () => {
    setSidebarOpen(!sidebarOpen);
  };

  return (
    <CommandPaletteContext.Provider value={cmdPalette}>
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

        {/* Global Command Palette — always mounted, toggled by ⌘K */}
        <CommandPalette
          open={cmdPalette.isOpen}
          onClose={cmdPalette.close}
          initialQuery={cmdPalette.initialQuery}
          recentInvestigations={RECENT_INVESTIGATIONS}
        />
      </LayoutRoot>
    </CommandPaletteContext.Provider>
  );
};

export default Layout;
