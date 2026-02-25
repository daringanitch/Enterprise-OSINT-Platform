import React from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import { ThemeProvider, CssBaseline } from '@mui/material';
import { LocalizationProvider } from '@mui/x-date-pickers';
import { AdapterDateFns } from '@mui/x-date-pickers/AdapterDateFns';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { Provider } from 'react-redux';
import { SnackbarProvider } from 'notistack';

import { store } from './store';
import { theme } from './utils/theme';
import { useAuth } from './hooks/useAuth';

// Pages
import LoginPage from './pages/Login';
import DashboardPage from './pages/Dashboard';
import InvestigationsPage from './pages/Investigations';
import NewInvestigationPage from './pages/NewInvestigation';
import InvestigationDetailPage from './pages/InvestigationDetail';
import ReportsPage from './pages/Reports';
import SettingsPage from './pages/Settings';
import GraphIntelligencePage from './pages/GraphIntelligence';
import ThreatAnalysisPage from './pages/ThreatAnalysis';
import AnalyticWorkbenchPage from './pages/AnalyticWorkbench';
import MonitoringPage from './pages/Monitoring';

// Components
import Layout from './components/Layout';
import PrivateRoute from './components/PrivateRoute';
import LoadingScreen from './components/LoadingScreen';

// Create Query Client
const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      retry: 1,
      refetchOnWindowFocus: false,
      staleTime: 5 * 60 * 1000, // 5 minutes
    },
  },
});

function App() {
  const { isLoading } = useAuth();

  if (isLoading) {
    return <LoadingScreen />;
  }

  return (
    <Provider store={store}>
      <QueryClientProvider client={queryClient}>
        <ThemeProvider theme={theme}>
          <LocalizationProvider dateAdapter={AdapterDateFns}>
            <SnackbarProvider 
              maxSnack={3}
              anchorOrigin={{
                vertical: 'bottom',
                horizontal: 'right',
              }}
            >
              <CssBaseline />
              <Router>
                <Routes>
                  {/* Public Routes */}
                  <Route path="/login" element={<LoginPage />} />
                  
                  {/* Private Routes */}
                  <Route
                    path="/"
                    element={
                      <PrivateRoute>
                        <Layout />
                      </PrivateRoute>
                    }
                  >
                    <Route index element={<Navigate to="/dashboard" replace />} />
                    <Route path="dashboard" element={<DashboardPage />} />
                    <Route path="investigations">
                      <Route index element={<InvestigationsPage />} />
                      <Route path="new" element={<NewInvestigationPage />} />
                      <Route path=":id" element={<InvestigationDetailPage />} />
                      <Route path=":id/graph" element={<GraphIntelligencePage />} />
                      <Route path=":id/threats" element={<ThreatAnalysisPage />} />
                      <Route path=":id/workbench" element={<AnalyticWorkbenchPage />} />
                    </Route>
                    <Route path="reports" element={<ReportsPage />} />
                    <Route path="monitoring" element={<MonitoringPage />} />
                    <Route path="settings" element={<SettingsPage />} />
                  </Route>
                  
                  {/* 404 */}
                  <Route path="*" element={<Navigate to="/" replace />} />
                </Routes>
              </Router>
            </SnackbarProvider>
          </LocalizationProvider>
        </ThemeProvider>
      </QueryClientProvider>
    </Provider>
  );
}

export default App;