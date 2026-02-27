/**
 * Sidebar Component
 *
 * Navigation sidebar with collapsible sections and icons.
 */

import React, { useState } from 'react';
import {
  Drawer,
  List,
  ListItemButton,
  ListItemIcon,
  ListItemText,
  Collapse,
  Box,
  Typography,
  Divider,
  styled,
  Tooltip,
} from '@mui/material';
import DashboardIcon from '@mui/icons-material/Dashboard';
import SearchIcon from '@mui/icons-material/Search';
import AssessmentIcon from '@mui/icons-material/Assessment';
import SecurityIcon from '@mui/icons-material/Security';
import SettingsIcon from '@mui/icons-material/Settings';
import ExpandLess from '@mui/icons-material/ExpandLess';
import ExpandMore from '@mui/icons-material/ExpandMore';
import FolderIcon from '@mui/icons-material/Folder';
import HistoryIcon from '@mui/icons-material/History';
import BookmarkIcon from '@mui/icons-material/Bookmark';
import PeopleIcon from '@mui/icons-material/People';
import StorageIcon from '@mui/icons-material/Storage';
import VerifiedUserIcon from '@mui/icons-material/VerifiedUser';
import ManageSearchIcon from '@mui/icons-material/ManageSearch';
import MonitorHeartIcon from '@mui/icons-material/MonitorHeart';
import { designTokens } from '../../utils/theme';

export interface NavItem {
  id: string;
  label: string;
  icon: React.ReactNode;
  path?: string;
  children?: NavItem[];
  badge?: number;
}

export interface SidebarProps {
  /** Whether sidebar is open */
  open: boolean;
  /** Called when a nav item is clicked */
  onNavigate?: (path: string) => void;
  /** Currently active path */
  activePath?: string;
  /** Sidebar width when open */
  width?: number;
  /** Collapsed width */
  collapsedWidth?: number;
  /** Whether sidebar is in collapsed mode */
  collapsed?: boolean;
  /** Test ID for testing */
  testId?: string;
}

const defaultNavItems: NavItem[] = [
  {
    id: 'dashboard',
    label: 'Dashboard',
    icon: <DashboardIcon />,
    path: '/dashboard',
  },
  {
    id: 'investigations',
    label: 'Investigations',
    icon: <SearchIcon />,
    children: [
      { id: 'active', label: 'Active', icon: <FolderIcon />, path: '/investigations/active' },
      { id: 'history', label: 'History', icon: <HistoryIcon />, path: '/investigations/history' },
      { id: 'saved', label: 'Saved', icon: <BookmarkIcon />, path: '/investigations/saved' },
    ],
  },
  {
    id: 'reports',
    label: 'Reports',
    icon: <AssessmentIcon />,
    path: '/reports',
  },
  {
    id: 'threat-intel',
    label: 'Threat Intelligence',
    icon: <SecurityIcon />,
    path: '/threat-intelligence',
  },
  {
    id: 'compliance',
    label: 'Compliance',
    icon: <VerifiedUserIcon />,
    path: '/compliance',
  },
  {
    id: 'team',
    label: 'Team',
    icon: <PeopleIcon />,
    path: '/team',
  },
  {
    id: 'data-sources',
    label: 'Data Sources',
    icon: <StorageIcon />,
    path: '/data-sources',
  },
  {
    id: 'monitoring',
    label: 'Monitoring',
    icon: <MonitorHeartIcon />,
    path: '/monitoring',
  },
  {
    id: 'credentials',
    label: 'Credentials',
    icon: <ManageSearchIcon />,
    path: '/credentials',
  },
  {
    id: 'settings',
    label: 'Settings',
    icon: <SettingsIcon />,
    path: '/settings',
  },
];

const StyledDrawer = styled(Drawer, {
  shouldForwardProp: (prop) => !['drawerWidth', 'isCollapsed'].includes(prop as string),
})<{ drawerWidth: number; isCollapsed: boolean }>(({ drawerWidth, isCollapsed }) => ({
  width: isCollapsed ? 64 : drawerWidth,
  flexShrink: 0,
  whiteSpace: 'nowrap',
  '& .MuiDrawer-paper': {
    width: isCollapsed ? 64 : drawerWidth,
    boxSizing: 'border-box',
    backgroundColor: designTokens.colors.background.paper,
    borderRight: `1px solid ${designTokens.colors.border.dark}`,
    transition: designTokens.transitions.normal,
    overflowX: 'hidden',
    marginTop: '64px',
    height: 'calc(100% - 64px)',
  },
}));

const NavSection = styled(Box)({
  padding: '8px 0',
});

const SectionTitle = styled(Typography)({
  fontSize: designTokens.typography.fontSizes.xs,
  fontWeight: designTokens.typography.fontWeights.semibold,
  color: designTokens.colors.text.hint,
  textTransform: 'uppercase',
  letterSpacing: '0.5px',
  padding: '16px 16px 8px',
});

const StyledListItemButton = styled(ListItemButton, {
  shouldForwardProp: (prop) => prop !== 'isActive' && prop !== 'isNested',
})<{ isActive?: boolean; isNested?: boolean }>(({ isActive, isNested }) => ({
  borderRadius: designTokens.borderRadius.md,
  margin: isNested ? '2px 8px 2px 16px' : '2px 8px',
  padding: isNested ? '8px 12px' : '10px 12px',
  transition: designTokens.transitions.normal,
  backgroundColor: isActive ? `${designTokens.colors.primary.main}20` : 'transparent',
  borderLeft: isActive ? `3px solid ${designTokens.colors.primary.main}` : '3px solid transparent',
  '&:hover': {
    backgroundColor: isActive
      ? `${designTokens.colors.primary.main}30`
      : designTokens.colors.background.elevated,
  },
  '& .MuiListItemIcon-root': {
    color: isActive ? designTokens.colors.primary.main : designTokens.colors.text.secondary,
    minWidth: '40px',
  },
  '& .MuiListItemText-primary': {
    color: isActive ? designTokens.colors.primary.main : designTokens.colors.text.primary,
    fontWeight: isActive
      ? designTokens.typography.fontWeights.medium
      : designTokens.typography.fontWeights.normal,
    fontSize: designTokens.typography.fontSizes.sm,
  },
}));

const Badge = styled(Box)({
  backgroundColor: designTokens.colors.error.main,
  color: '#ffffff',
  fontSize: '11px',
  fontWeight: designTokens.typography.fontWeights.bold,
  padding: '2px 6px',
  borderRadius: designTokens.borderRadius.full,
  minWidth: '20px',
  textAlign: 'center',
});

export const Sidebar: React.FC<SidebarProps> = ({
  open,
  onNavigate,
  activePath = '/dashboard',
  width = 260,
  collapsedWidth = 64,
  collapsed = false,
  testId,
}) => {
  const [expandedItems, setExpandedItems] = useState<Record<string, boolean>>({
    investigations: true,
  });

  const handleToggle = (id: string) => {
    setExpandedItems((prev) => ({
      ...prev,
      [id]: !prev[id],
    }));
  };

  const handleNavigate = (path: string) => {
    if (onNavigate) {
      onNavigate(path);
    }
  };

  const isActive = (path?: string) => {
    if (!path) return false;
    return activePath === path || activePath.startsWith(path + '/');
  };

  const renderNavItem = (item: NavItem, isNested = false) => {
    const hasChildren = item.children && item.children.length > 0;
    const itemIsActive = isActive(item.path);
    const isExpanded = expandedItems[item.id];

    const button = (
      <StyledListItemButton
        isActive={itemIsActive}
        isNested={isNested}
        onClick={() => {
          if (hasChildren) {
            handleToggle(item.id);
          } else if (item.path) {
            handleNavigate(item.path);
          }
        }}
        data-testid={testId ? `${testId}-nav-${item.id}` : undefined}
      >
        <ListItemIcon>{item.icon}</ListItemIcon>
        {!collapsed && (
          <>
            <ListItemText primary={item.label} />
            {item.badge !== undefined && item.badge > 0 && (
              <Badge>{item.badge > 99 ? '99+' : item.badge}</Badge>
            )}
            {hasChildren && (isExpanded ? <ExpandLess /> : <ExpandMore />)}
          </>
        )}
      </StyledListItemButton>
    );

    return (
      <React.Fragment key={item.id}>
        {collapsed ? (
          <Tooltip title={item.label} placement="right">
            {button}
          </Tooltip>
        ) : (
          button
        )}
        {hasChildren && !collapsed && (
          <Collapse in={isExpanded} timeout="auto" unmountOnExit>
            <List component="div" disablePadding>
              {item.children!.map((child) => renderNavItem(child, true))}
            </List>
          </Collapse>
        )}
      </React.Fragment>
    );
  };

  return (
    <StyledDrawer
      variant="persistent"
      anchor="left"
      open={open}
      drawerWidth={width}
      isCollapsed={collapsed}
      data-testid={testId}
    >
      <NavSection>
        {!collapsed && <SectionTitle>Main</SectionTitle>}
        <List>
          {defaultNavItems.slice(0, 5).map((item) => renderNavItem(item))}
        </List>
      </NavSection>

      <Divider sx={{ borderColor: designTokens.colors.border.dark }} />

      <NavSection>
        {!collapsed && <SectionTitle>Administration</SectionTitle>}
        <List>
          {defaultNavItems.slice(5).map((item) => renderNavItem(item))}
        </List>
      </NavSection>
    </StyledDrawer>
  );
};

export default Sidebar;
