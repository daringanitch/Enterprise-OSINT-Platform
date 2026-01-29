/**
 * Header Component
 *
 * Application header with navigation, search, and user menu.
 */

import React, { useState } from 'react';
import {
  AppBar,
  Toolbar,
  Typography,
  IconButton,
  Box,
  InputBase,
  Badge,
  Menu,
  MenuItem,
  Avatar,
  Divider,
  ListItemIcon,
  ListItemText,
  styled,
  Tooltip,
} from '@mui/material';
import MenuIcon from '@mui/icons-material/Menu';
import SearchIcon from '@mui/icons-material/Search';
import NotificationsIcon from '@mui/icons-material/Notifications';
import SettingsIcon from '@mui/icons-material/Settings';
import AccountCircleIcon from '@mui/icons-material/AccountCircle';
import LogoutIcon from '@mui/icons-material/Logout';
import HelpOutlineIcon from '@mui/icons-material/HelpOutline';
import { designTokens } from '../../utils/theme';

export interface HeaderProps {
  /** Toggle sidebar visibility */
  onMenuClick?: () => void;
  /** Current user name */
  userName?: string;
  /** Current user role */
  userRole?: string;
  /** Number of unread notifications */
  notificationCount?: number;
  /** Called when search is submitted */
  onSearch?: (query: string) => void;
  /** Called when settings is clicked */
  onSettingsClick?: () => void;
  /** Called when logout is clicked */
  onLogout?: () => void;
  /** Called when profile is clicked */
  onProfileClick?: () => void;
  /** Test ID for testing */
  testId?: string;
}

const StyledAppBar = styled(AppBar)({
  background: designTokens.colors.background.paper,
  borderBottom: `1px solid ${designTokens.colors.border.dark}`,
  boxShadow: 'none',
  zIndex: 1201,
});

const Logo = styled(Typography)({
  fontWeight: designTokens.typography.fontWeights.bold,
  fontSize: designTokens.typography.fontSizes.xl,
  background: designTokens.colors.gradients.primary,
  WebkitBackgroundClip: 'text',
  WebkitTextFillColor: 'transparent',
  backgroundClip: 'text',
  marginRight: '24px',
  userSelect: 'none',
});

const SearchContainer = styled(Box)({
  display: 'flex',
  alignItems: 'center',
  backgroundColor: designTokens.colors.background.elevated,
  borderRadius: designTokens.borderRadius.md,
  padding: '4px 12px',
  flex: 1,
  maxWidth: '400px',
  border: `1px solid ${designTokens.colors.border.dark}`,
  transition: designTokens.transitions.normal,
  '&:focus-within': {
    borderColor: designTokens.colors.primary.main,
    boxShadow: `0 0 0 2px ${designTokens.colors.primary.main}30`,
  },
});

const SearchInput = styled(InputBase)({
  flex: 1,
  color: designTokens.colors.text.primary,
  fontSize: designTokens.typography.fontSizes.sm,
  '& .MuiInputBase-input': {
    padding: '6px 8px',
    '&::placeholder': {
      color: designTokens.colors.text.hint,
      opacity: 1,
    },
  },
});

const IconButtonStyled = styled(IconButton)({
  color: designTokens.colors.text.secondary,
  '&:hover': {
    color: designTokens.colors.text.primary,
    backgroundColor: designTokens.colors.background.elevated,
  },
});

const UserAvatar = styled(Avatar)({
  width: 36,
  height: 36,
  backgroundColor: designTokens.colors.primary.main,
  cursor: 'pointer',
  transition: designTokens.transitions.normal,
  '&:hover': {
    boxShadow: designTokens.shadows.glow.primary,
  },
});

const StyledMenu = styled(Menu)({
  '& .MuiPaper-root': {
    backgroundColor: designTokens.colors.background.paper,
    border: `1px solid ${designTokens.colors.border.dark}`,
    borderRadius: designTokens.borderRadius.lg,
    minWidth: '200px',
    marginTop: '8px',
  },
});

const UserInfo = styled(Box)({
  padding: '12px 16px',
});

const UserName = styled(Typography)({
  fontWeight: designTokens.typography.fontWeights.medium,
  color: designTokens.colors.text.primary,
  fontSize: designTokens.typography.fontSizes.sm,
});

const UserRole = styled(Typography)({
  color: designTokens.colors.text.secondary,
  fontSize: designTokens.typography.fontSizes.xs,
  textTransform: 'capitalize',
});

const StyledMenuItem = styled(MenuItem)({
  padding: '10px 16px',
  '&:hover': {
    backgroundColor: designTokens.colors.background.elevated,
  },
  '& .MuiListItemIcon-root': {
    color: designTokens.colors.text.secondary,
    minWidth: '36px',
  },
  '& .MuiListItemText-primary': {
    color: designTokens.colors.text.primary,
    fontSize: designTokens.typography.fontSizes.sm,
  },
});

export const Header: React.FC<HeaderProps> = ({
  onMenuClick,
  userName = 'User',
  userRole = 'analyst',
  notificationCount = 0,
  onSearch,
  onSettingsClick,
  onLogout,
  onProfileClick,
  testId,
}) => {
  const [anchorEl, setAnchorEl] = useState<null | HTMLElement>(null);
  const [searchQuery, setSearchQuery] = useState('');

  const handleUserMenuOpen = (event: React.MouseEvent<HTMLElement>) => {
    setAnchorEl(event.currentTarget);
  };

  const handleUserMenuClose = () => {
    setAnchorEl(null);
  };

  const handleSearchSubmit = (event: React.FormEvent) => {
    event.preventDefault();
    if (onSearch && searchQuery.trim()) {
      onSearch(searchQuery.trim());
    }
  };

  const handleSearchKeyDown = (event: React.KeyboardEvent) => {
    if (event.key === 'Enter') {
      event.preventDefault();
      if (onSearch && searchQuery.trim()) {
        onSearch(searchQuery.trim());
      }
    }
  };

  const getInitials = (name: string) => {
    return name
      .split(' ')
      .map((part) => part[0])
      .join('')
      .toUpperCase()
      .slice(0, 2);
  };

  return (
    <StyledAppBar position="fixed" data-testid={testId}>
      <Toolbar>
        {onMenuClick && (
          <IconButtonStyled
            edge="start"
            onClick={onMenuClick}
            aria-label="Toggle sidebar"
            data-testid={testId ? `${testId}-menu-button` : undefined}
          >
            <MenuIcon />
          </IconButtonStyled>
        )}

        <Logo variant="h6">OSINT Platform</Logo>

        <SearchContainer component="form" onSubmit={handleSearchSubmit}>
          <SearchIcon sx={{ color: designTokens.colors.text.hint }} />
          <SearchInput
            placeholder="Search investigations, targets, findings..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            onKeyDown={handleSearchKeyDown}
            inputProps={{
              'aria-label': 'Search',
              'data-testid': testId ? `${testId}-search-input` : undefined,
            }}
          />
        </SearchContainer>

        <Box sx={{ flexGrow: 1 }} />

        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
          <Tooltip title="Help">
            <IconButtonStyled aria-label="Help">
              <HelpOutlineIcon />
            </IconButtonStyled>
          </Tooltip>

          <Tooltip title="Notifications">
            <IconButtonStyled
              aria-label={`${notificationCount} notifications`}
              data-testid={testId ? `${testId}-notifications` : undefined}
            >
              <Badge badgeContent={notificationCount} color="error">
                <NotificationsIcon />
              </Badge>
            </IconButtonStyled>
          </Tooltip>

          <Tooltip title="Settings">
            <IconButtonStyled
              onClick={onSettingsClick}
              aria-label="Settings"
              data-testid={testId ? `${testId}-settings` : undefined}
            >
              <SettingsIcon />
            </IconButtonStyled>
          </Tooltip>

          <UserAvatar
            onClick={handleUserMenuOpen}
            aria-label="User menu"
            aria-controls="user-menu"
            aria-haspopup="true"
            data-testid={testId ? `${testId}-user-avatar` : undefined}
          >
            {getInitials(userName)}
          </UserAvatar>
        </Box>

        <StyledMenu
          id="user-menu"
          anchorEl={anchorEl}
          open={Boolean(anchorEl)}
          onClose={handleUserMenuClose}
          anchorOrigin={{
            vertical: 'bottom',
            horizontal: 'right',
          }}
          transformOrigin={{
            vertical: 'top',
            horizontal: 'right',
          }}
        >
          <UserInfo>
            <UserName>{userName}</UserName>
            <UserRole>{userRole}</UserRole>
          </UserInfo>
          <Divider sx={{ borderColor: designTokens.colors.border.dark }} />
          <StyledMenuItem
            onClick={() => {
              handleUserMenuClose();
              onProfileClick?.();
            }}
            data-testid={testId ? `${testId}-profile-menu-item` : undefined}
          >
            <ListItemIcon>
              <AccountCircleIcon fontSize="small" />
            </ListItemIcon>
            <ListItemText primary="Profile" />
          </StyledMenuItem>
          <StyledMenuItem
            onClick={() => {
              handleUserMenuClose();
              onSettingsClick?.();
            }}
          >
            <ListItemIcon>
              <SettingsIcon fontSize="small" />
            </ListItemIcon>
            <ListItemText primary="Settings" />
          </StyledMenuItem>
          <Divider sx={{ borderColor: designTokens.colors.border.dark }} />
          <StyledMenuItem
            onClick={() => {
              handleUserMenuClose();
              onLogout?.();
            }}
            data-testid={testId ? `${testId}-logout-menu-item` : undefined}
          >
            <ListItemIcon>
              <LogoutIcon fontSize="small" />
            </ListItemIcon>
            <ListItemText primary="Logout" />
          </StyledMenuItem>
        </StyledMenu>
      </Toolbar>
    </StyledAppBar>
  );
};

export default Header;
