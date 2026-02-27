/**
 * Layout Component
 *
 * Main application layout with header, sidebar, and content area.
 */

import React, { useState } from 'react';
import { Box, styled } from '@mui/material';
import { Header, HeaderProps } from './Header';
import { Sidebar, SidebarProps } from './Sidebar';
import { designTokens } from '../../utils/theme';

export interface LayoutProps {
  /** Main content */
  children: React.ReactNode;
  /** Header props */
  headerProps?: Partial<HeaderProps>;
  /** Sidebar props */
  sidebarProps?: Partial<SidebarProps>;
  /** Initial sidebar open state */
  defaultSidebarOpen?: boolean;
  /** Hide sidebar completely */
  hideSidebar?: boolean;
  /** Hide header completely */
  hideHeader?: boolean;
  /** Current user info */
  user?: {
    name: string;
    role: string;
  };
  /** Notification count */
  notificationCount?: number;
  /** Called when navigation occurs */
  onNavigate?: (path: string) => void;
  /** Called when logout is clicked */
  onLogout?: () => void;
  /** Called when search is submitted */
  onSearch?: (query: string) => void;
  /** Test ID for testing */
  testId?: string;
}

const HEADER_HEIGHT = 64;
const SIDEBAR_WIDTH = 260;
const SIDEBAR_COLLAPSED_WIDTH = 64;

const LayoutRoot = styled(Box)({
  display: 'flex',
  minHeight: '100vh',
  background: designTokens.colors.gradients.surface,
});

const MainContent = styled(Box, {
  shouldForwardProp: (prop) =>
    !['sidebarOpen', 'hideSidebar', 'hideHeader', 'sidebarWidth'].includes(prop as string),
})<{
  sidebarOpen: boolean;
  hideSidebar: boolean;
  hideHeader: boolean;
  sidebarWidth: number;
}>(({ sidebarOpen, hideSidebar, hideHeader, sidebarWidth }) => ({
  flexGrow: 1,
  display: 'flex',
  flexDirection: 'column',
  marginTop: hideHeader ? 0 : HEADER_HEIGHT,
  marginLeft: hideSidebar ? 0 : sidebarOpen ? sidebarWidth : 0,
  transition: designTokens.transitions.normal,
  minHeight: hideHeader ? '100vh' : `calc(100vh - ${HEADER_HEIGHT}px)`,
}));

const ContentArea = styled(Box)({
  flex: 1,
  padding: '24px',
  overflow: 'auto',
});


export const Layout: React.FC<LayoutProps> = ({
  children,
  headerProps,
  sidebarProps,
  defaultSidebarOpen = true,
  hideSidebar = false,
  hideHeader = false,
  user,
  notificationCount = 0,
  onNavigate,
  onLogout,
  onSearch,
  testId,
}) => {
  const [sidebarOpen, setSidebarOpen] = useState(defaultSidebarOpen);
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);

  const handleMenuClick = () => {
    if (sidebarOpen && !sidebarCollapsed) {
      setSidebarCollapsed(true);
    } else if (sidebarOpen && sidebarCollapsed) {
      setSidebarOpen(false);
      setSidebarCollapsed(false);
    } else {
      setSidebarOpen(true);
      setSidebarCollapsed(false);
    }
  };

  const sidebarWidth = sidebarCollapsed ? SIDEBAR_COLLAPSED_WIDTH : SIDEBAR_WIDTH;

  return (
    <LayoutRoot data-testid={testId}>
      {!hideHeader && (
        <Header
          onMenuClick={handleMenuClick}
          userName={user?.name}
          userRole={user?.role}
          notificationCount={notificationCount}
          onSearch={onSearch}
          onLogout={onLogout}
          testId={testId ? `${testId}-header` : undefined}
          {...headerProps}
        />
      )}

      {!hideSidebar && (
        <Sidebar
          open={sidebarOpen}
          collapsed={sidebarCollapsed}
          onNavigate={onNavigate}
          width={SIDEBAR_WIDTH}
          collapsedWidth={SIDEBAR_COLLAPSED_WIDTH}
          testId={testId ? `${testId}-sidebar` : undefined}
          {...sidebarProps}
        />
      )}

      <MainContent
        sidebarOpen={sidebarOpen}
        hideSidebar={hideSidebar}
        hideHeader={hideHeader}
        sidebarWidth={sidebarWidth}
        component="main"
        data-testid={testId ? `${testId}-content` : undefined}
      >
        <ContentArea>{children}</ContentArea>
      </MainContent>
    </LayoutRoot>
  );
};

// =============================================================================
// Page Wrapper Component
// =============================================================================

export interface PageWrapperProps {
  /** Page title */
  title?: string;
  /** Page subtitle/description */
  subtitle?: string;
  /** Action buttons for the page header */
  actions?: React.ReactNode;
  /** Page content */
  children: React.ReactNode;
  /** Maximum content width */
  maxWidth?: number | string;
  /** Test ID for testing */
  testId?: string;
}

const PageContainer = styled(Box, {
  shouldForwardProp: (prop) => prop !== 'maxContentWidth',
})<{ maxContentWidth?: number | string }>(({ maxContentWidth }) => ({
  width: '100%',
  maxWidth: maxContentWidth || '100%',
  margin: '0 auto',
}));

const PageHeader = styled(Box)({
  display: 'flex',
  alignItems: 'flex-start',
  justifyContent: 'space-between',
  marginBottom: '24px',
  flexWrap: 'wrap',
  gap: '16px',
});

const PageTitleSection = styled(Box)({
  flex: 1,
});

const PageTitleText = styled('h1')({
  fontSize: designTokens.typography.fontSizes['2xl'],
  fontWeight: designTokens.typography.fontWeights.bold,
  color: designTokens.colors.text.primary,
  margin: 0,
  marginBottom: '4px',
});

const PageSubtitle = styled('p')({
  fontSize: designTokens.typography.fontSizes.sm,
  color: designTokens.colors.text.secondary,
  margin: 0,
});

const PageActions = styled(Box)({
  display: 'flex',
  alignItems: 'center',
  gap: '12px',
});

export const PageWrapper: React.FC<PageWrapperProps> = ({
  title,
  subtitle,
  actions,
  children,
  maxWidth,
  testId,
}) => {
  return (
    <PageContainer maxContentWidth={maxWidth} data-testid={testId}>
      {(title || actions) && (
        <PageHeader>
          {title && (
            <PageTitleSection>
              <PageTitleText>{title}</PageTitleText>
              {subtitle && <PageSubtitle>{subtitle}</PageSubtitle>}
            </PageTitleSection>
          )}
          {actions && <PageActions>{actions}</PageActions>}
        </PageHeader>
      )}
      {children}
    </PageContainer>
  );
};

export default Layout;
