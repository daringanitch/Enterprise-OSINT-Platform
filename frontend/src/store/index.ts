/**
 * Redux Store Configuration
 */

import { configureStore, createSlice, PayloadAction } from '@reduxjs/toolkit';

// Investigation slice
interface Investigation {
  id: string;
  target: string;
  status: string;
  created_at: string;
}

interface InvestigationState {
  items: Investigation[];
  current: Investigation | null;
  loading: boolean;
  error: string | null;
}

const initialInvestigationState: InvestigationState = {
  items: [],
  current: null,
  loading: false,
  error: null,
};

const investigationSlice = createSlice({
  name: 'investigations',
  initialState: initialInvestigationState,
  reducers: {
    setInvestigations: (state, action: PayloadAction<Investigation[]>) => {
      state.items = action.payload;
      state.loading = false;
    },
    setCurrentInvestigation: (state, action: PayloadAction<Investigation | null>) => {
      state.current = action.payload;
    },
    setLoading: (state, action: PayloadAction<boolean>) => {
      state.loading = action.payload;
    },
    setError: (state, action: PayloadAction<string | null>) => {
      state.error = action.payload;
      state.loading = false;
    },
  },
});

// UI slice
interface UIState {
  sidebarOpen: boolean;
  theme: 'dark' | 'light';
}

const initialUIState: UIState = {
  sidebarOpen: true,
  theme: 'dark',
};

const uiSlice = createSlice({
  name: 'ui',
  initialState: initialUIState,
  reducers: {
    toggleSidebar: (state) => {
      state.sidebarOpen = !state.sidebarOpen;
    },
    setSidebarOpen: (state, action: PayloadAction<boolean>) => {
      state.sidebarOpen = action.payload;
    },
    setTheme: (state, action: PayloadAction<'dark' | 'light'>) => {
      state.theme = action.payload;
    },
  },
});

export const { setInvestigations, setCurrentInvestigation, setLoading, setError } = investigationSlice.actions;
export const { toggleSidebar, setSidebarOpen, setTheme } = uiSlice.actions;

export const store = configureStore({
  reducer: {
    investigations: investigationSlice.reducer,
    ui: uiSlice.reducer,
  },
});

export type RootState = ReturnType<typeof store.getState>;
export type AppDispatch = typeof store.dispatch;
