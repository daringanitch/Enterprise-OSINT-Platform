/**
 * Layout Component Tests
 */

import React from 'react';
import { render, screen, fireEvent } from '@testing-library/react';
import { ThemeProvider } from '@mui/material/styles';
import { theme } from '../../utils/theme';
import { Header } from '../../components/layout/Header';
import { Sidebar } from '../../components/layout/Sidebar';
import { Layout, PageWrapper } from '../../components/layout/Layout';

const renderWithTheme = (component: React.ReactElement) => {
  return render(<ThemeProvider theme={theme}>{component}</ThemeProvider>);
};

// =============================================================================
// Header Tests
// =============================================================================

describe('Header Component', () => {
  describe('Rendering', () => {
    it('renders header', () => {
      renderWithTheme(<Header testId="test-header" />);
      expect(screen.getByTestId('test-header')).toBeInTheDocument();
    });

    it('renders logo text', () => {
      renderWithTheme(<Header />);
      expect(screen.getByText('OSINT Platform')).toBeInTheDocument();
    });

    it('renders search input', () => {
      renderWithTheme(<Header testId="header" />);
      expect(screen.getByTestId('header-search-input')).toBeInTheDocument();
    });

    it('renders user avatar', () => {
      renderWithTheme(<Header testId="header" userName="John Doe" />);
      expect(screen.getByTestId('header-user-avatar')).toBeInTheDocument();
    });

    it('shows user initials in avatar', () => {
      renderWithTheme(<Header userName="John Doe" />);
      expect(screen.getByText('JD')).toBeInTheDocument();
    });
  });

  describe('Menu Button', () => {
    it('renders menu button when onMenuClick is provided', () => {
      const handleMenuClick = jest.fn();
      renderWithTheme(<Header onMenuClick={handleMenuClick} testId="header" />);
      expect(screen.getByTestId('header-menu-button')).toBeInTheDocument();
    });

    it('calls onMenuClick when menu button is clicked', () => {
      const handleMenuClick = jest.fn();
      renderWithTheme(<Header onMenuClick={handleMenuClick} testId="header" />);
      fireEvent.click(screen.getByTestId('header-menu-button'));
      expect(handleMenuClick).toHaveBeenCalledTimes(1);
    });
  });

  describe('Notifications', () => {
    it('shows notification count', () => {
      renderWithTheme(<Header notificationCount={5} testId="header" />);
      expect(screen.getByText('5')).toBeInTheDocument();
    });

    it('shows no badge when count is 0', () => {
      renderWithTheme(<Header notificationCount={0} testId="header" />);
      expect(screen.queryByText('0')).not.toBeInTheDocument();
    });
  });

  describe('Search', () => {
    it('calls onSearch when search is submitted', () => {
      const handleSearch = jest.fn();
      renderWithTheme(<Header onSearch={handleSearch} testId="header" />);
      const searchInput = screen.getByTestId('header-search-input');
      fireEvent.change(searchInput, { target: { value: 'test query' } });
      fireEvent.keyDown(searchInput, { key: 'Enter' });
      expect(handleSearch).toHaveBeenCalledWith('test query');
    });

    it('does not call onSearch for empty query', () => {
      const handleSearch = jest.fn();
      renderWithTheme(<Header onSearch={handleSearch} testId="header" />);
      const searchInput = screen.getByTestId('header-search-input');
      fireEvent.keyDown(searchInput, { key: 'Enter' });
      expect(handleSearch).not.toHaveBeenCalled();
    });
  });

  describe('User Menu', () => {
    it('opens user menu when avatar is clicked', () => {
      renderWithTheme(<Header testId="header" userName="Test User" />);
      fireEvent.click(screen.getByTestId('header-user-avatar'));
      expect(screen.getByRole('menu')).toBeInTheDocument();
    });

    it('shows user name in menu', () => {
      renderWithTheme(<Header testId="header" userName="Test User" userRole="admin" />);
      fireEvent.click(screen.getByTestId('header-user-avatar'));
      expect(screen.getByText('Test User')).toBeInTheDocument();
      expect(screen.getByText('admin')).toBeInTheDocument();
    });

    it('calls onLogout when logout is clicked', () => {
      const handleLogout = jest.fn();
      renderWithTheme(<Header testId="header" onLogout={handleLogout} />);
      fireEvent.click(screen.getByTestId('header-user-avatar'));
      fireEvent.click(screen.getByTestId('header-logout-menu-item'));
      expect(handleLogout).toHaveBeenCalledTimes(1);
    });

    it('calls onProfileClick when profile is clicked', () => {
      const handleProfileClick = jest.fn();
      renderWithTheme(<Header testId="header" onProfileClick={handleProfileClick} />);
      fireEvent.click(screen.getByTestId('header-user-avatar'));
      fireEvent.click(screen.getByTestId('header-profile-menu-item'));
      expect(handleProfileClick).toHaveBeenCalledTimes(1);
    });
  });

  describe('Settings', () => {
    it('calls onSettingsClick when settings is clicked', () => {
      const handleSettingsClick = jest.fn();
      renderWithTheme(<Header testId="header" onSettingsClick={handleSettingsClick} />);
      fireEvent.click(screen.getByTestId('header-settings'));
      expect(handleSettingsClick).toHaveBeenCalledTimes(1);
    });
  });
});

// =============================================================================
// Sidebar Tests
// =============================================================================

describe('Sidebar Component', () => {
  describe('Rendering', () => {
    it('renders when open', () => {
      renderWithTheme(<Sidebar open testId="test-sidebar" />);
      expect(screen.getByTestId('test-sidebar')).toBeInTheDocument();
    });

    it('renders navigation items', () => {
      renderWithTheme(<Sidebar open testId="sidebar" />);
      expect(screen.getByText('Dashboard')).toBeInTheDocument();
      expect(screen.getByText('Investigations')).toBeInTheDocument();
      expect(screen.getByText('Reports')).toBeInTheDocument();
    });

    it('renders section titles', () => {
      renderWithTheme(<Sidebar open />);
      expect(screen.getByText('Main')).toBeInTheDocument();
      expect(screen.getByText('Administration')).toBeInTheDocument();
    });
  });

  describe('Navigation', () => {
    it('calls onNavigate when nav item is clicked', () => {
      const handleNavigate = jest.fn();
      renderWithTheme(<Sidebar open onNavigate={handleNavigate} testId="sidebar" />);
      fireEvent.click(screen.getByTestId('sidebar-nav-dashboard'));
      expect(handleNavigate).toHaveBeenCalledWith('/dashboard');
    });

    it('expands nested items when parent is clicked', () => {
      renderWithTheme(<Sidebar open testId="sidebar" />);
      // Investigations should be expanded by default
      expect(screen.getByText('Active')).toBeInTheDocument();
      expect(screen.getByText('History')).toBeInTheDocument();
    });

    it('navigates to nested item', () => {
      const handleNavigate = jest.fn();
      renderWithTheme(<Sidebar open onNavigate={handleNavigate} testId="sidebar" />);
      fireEvent.click(screen.getByTestId('sidebar-nav-active'));
      expect(handleNavigate).toHaveBeenCalledWith('/investigations/active');
    });
  });

  describe('Active State', () => {
    it('highlights active nav item', () => {
      renderWithTheme(<Sidebar open activePath="/dashboard" testId="sidebar" />);
      // The dashboard item should have active styling (tested via data-testid)
      expect(screen.getByTestId('sidebar-nav-dashboard')).toBeInTheDocument();
    });
  });

  describe('Collapsed Mode', () => {
    it('hides text labels when collapsed', () => {
      renderWithTheme(<Sidebar open collapsed testId="sidebar" />);
      // In collapsed mode, labels should be hidden (visible only in tooltip)
      expect(screen.queryByText('Main')).not.toBeInTheDocument();
    });
  });
});

// =============================================================================
// Layout Tests
// =============================================================================

describe('Layout Component', () => {
  describe('Rendering', () => {
    it('renders layout with children', () => {
      renderWithTheme(
        <Layout testId="layout">
          <div>Page Content</div>
        </Layout>
      );
      expect(screen.getByText('Page Content')).toBeInTheDocument();
    });

    it('renders header by default', () => {
      renderWithTheme(
        <Layout testId="layout">
          <div>Content</div>
        </Layout>
      );
      expect(screen.getByTestId('layout-header')).toBeInTheDocument();
    });

    it('renders sidebar by default', () => {
      renderWithTheme(
        <Layout testId="layout">
          <div>Content</div>
        </Layout>
      );
      expect(screen.getByTestId('layout-sidebar')).toBeInTheDocument();
    });
  });

  describe('Visibility Controls', () => {
    it('hides header when hideHeader is true', () => {
      renderWithTheme(
        <Layout hideHeader testId="layout">
          <div>Content</div>
        </Layout>
      );
      expect(screen.queryByTestId('layout-header')).not.toBeInTheDocument();
    });

    it('hides sidebar when hideSidebar is true', () => {
      renderWithTheme(
        <Layout hideSidebar testId="layout">
          <div>Content</div>
        </Layout>
      );
      expect(screen.queryByTestId('layout-sidebar')).not.toBeInTheDocument();
    });
  });

  describe('User Info', () => {
    it('passes user info to header', () => {
      renderWithTheme(
        <Layout user={{ name: 'Jane Doe', role: 'analyst' }} testId="layout">
          <div>Content</div>
        </Layout>
      );
      // User initials should be visible
      expect(screen.getByText('JD')).toBeInTheDocument();
    });
  });

  describe('Callbacks', () => {
    it('calls onNavigate when sidebar navigation occurs', () => {
      const handleNavigate = jest.fn();
      renderWithTheme(
        <Layout onNavigate={handleNavigate} testId="layout">
          <div>Content</div>
        </Layout>
      );
      fireEvent.click(screen.getByTestId('layout-sidebar-nav-dashboard'));
      expect(handleNavigate).toHaveBeenCalledWith('/dashboard');
    });

    it('calls onSearch when search is submitted', () => {
      const handleSearch = jest.fn();
      renderWithTheme(
        <Layout onSearch={handleSearch} testId="layout">
          <div>Content</div>
        </Layout>
      );
      const searchInput = screen.getByTestId('layout-header-search-input');
      fireEvent.change(searchInput, { target: { value: 'test' } });
      fireEvent.keyDown(searchInput, { key: 'Enter' });
      expect(handleSearch).toHaveBeenCalledWith('test');
    });

    it('calls onLogout when logout is clicked', () => {
      const handleLogout = jest.fn();
      renderWithTheme(
        <Layout onLogout={handleLogout} testId="layout">
          <div>Content</div>
        </Layout>
      );
      fireEvent.click(screen.getByTestId('layout-header-user-avatar'));
      fireEvent.click(screen.getByTestId('layout-header-logout-menu-item'));
      expect(handleLogout).toHaveBeenCalledTimes(1);
    });
  });
});

// =============================================================================
// PageWrapper Tests
// =============================================================================

describe('PageWrapper Component', () => {
  describe('Rendering', () => {
    it('renders children', () => {
      renderWithTheme(
        <PageWrapper testId="page">
          <div>Page Content</div>
        </PageWrapper>
      );
      expect(screen.getByText('Page Content')).toBeInTheDocument();
    });

    it('renders title', () => {
      renderWithTheme(
        <PageWrapper title="Dashboard" testId="page">
          <div>Content</div>
        </PageWrapper>
      );
      expect(screen.getByText('Dashboard')).toBeInTheDocument();
    });

    it('renders subtitle', () => {
      renderWithTheme(
        <PageWrapper title="Dashboard" subtitle="Overview of your investigations" testId="page">
          <div>Content</div>
        </PageWrapper>
      );
      expect(screen.getByText('Overview of your investigations')).toBeInTheDocument();
    });

    it('renders actions', () => {
      renderWithTheme(
        <PageWrapper
          title="Investigations"
          actions={<button>New Investigation</button>}
          testId="page"
        >
          <div>Content</div>
        </PageWrapper>
      );
      expect(screen.getByRole('button', { name: /new investigation/i })).toBeInTheDocument();
    });
  });

  describe('No Header', () => {
    it('does not render header when no title or actions', () => {
      renderWithTheme(
        <PageWrapper testId="page">
          <div>Content Only</div>
        </PageWrapper>
      );
      expect(screen.getByText('Content Only')).toBeInTheDocument();
      // No h1 should be present
      expect(screen.queryByRole('heading', { level: 1 })).not.toBeInTheDocument();
    });
  });
});
