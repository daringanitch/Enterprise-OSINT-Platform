/**
 * useSavedSearches
 *
 * React hook that wraps the saved-search API endpoints:
 *   GET    /api/searches           → list all saved searches
 *   POST   /api/searches           → create a saved search
 *   DELETE /api/searches/<id>      → delete a saved search
 *   GET    /api/searches/<id>/matches → run a saved search, returns matched investigations
 *
 * Also exposes `runSearch(params)` which calls the ad-hoc search endpoint:
 *   GET /api/investigations/search  (with filter query params)
 *
 * Usage:
 *   const { savedSearches, saveSearch, deleteSearch, runSearch, loading } = useSavedSearches();
 */

import { useState, useEffect, useCallback, useRef } from 'react';

const API_BASE = process.env.REACT_APP_API_URL || 'http://localhost:5001';

// ─── Types ────────────────────────────────────────────────────────────────────

export interface SavedSearch {
  id: string;
  name: string;
  description: string;
  query_params: SearchParams;
  created_at: string;
  last_run_at: string | null;
  match_count: number;
}

export interface SearchParams {
  q?: string;
  status?: string;
  type?: string;
  priority?: string;
  risk_level?: string;
  from_date?: string;
  to_date?: string;
}

export interface SearchResult {
  results: Investigation[];
  total: number;
}

export interface Investigation {
  id: string;
  target: string;
  status: string;
  priority?: string;
  risk_level?: string | null;
  created_at: string;
  updated_at?: string;
  findings_count?: number;
  progress?: number;
  type?: string;
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

function authHeaders(): HeadersInit {
  const token = localStorage.getItem('auth_token');
  return {
    'Content-Type': 'application/json',
    ...(token ? { Authorization: `Bearer ${token}` } : {}),
  };
}

async function apiFetch<T>(url: string, init?: RequestInit): Promise<T> {
  const res = await fetch(url, { ...init, headers: { ...authHeaders(), ...(init?.headers || {}) } });
  if (!res.ok) {
    let message = `HTTP ${res.status}`;
    try {
      const body = await res.json();
      message = body.message || body.error || message;
    } catch {
      // ignore parse error
    }
    throw new Error(message);
  }
  return res.json() as Promise<T>;
}

// ─── Hook ─────────────────────────────────────────────────────────────────────

interface UseSavedSearchesReturn {
  /** All saved searches from the server */
  savedSearches: SavedSearch[];
  /** True while any network request is in flight */
  loading: boolean;
  /** Last error message, or null */
  error: string | null;
  /** Fetch / refresh the saved searches list */
  fetchSavedSearches: () => Promise<void>;
  /** Persist the current filter params as a named saved search */
  saveSearch: (name: string, description: string, params: SearchParams) => Promise<SavedSearch>;
  /** Remove a saved search by ID */
  deleteSearch: (id: string) => Promise<void>;
  /** Run an ad-hoc search (hits GET /api/investigations/search) */
  runSearch: (params: SearchParams) => Promise<SearchResult>;
  /** Run a saved search by ID and return its matches */
  runSavedSearch: (id: string) => Promise<SearchResult>;
}

export function useSavedSearches(): UseSavedSearchesReturn {
  const [savedSearches, setSavedSearches] = useState<SavedSearch[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Ref to track component mount state and avoid state updates after unmount
  const mountedRef = useRef(true);
  useEffect(() => {
    mountedRef.current = true;
    return () => { mountedRef.current = false; };
  }, []);

  const fetchSavedSearches = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await apiFetch<SavedSearch[]>(`${API_BASE}/api/searches`);
      if (mountedRef.current) setSavedSearches(data);
    } catch (err) {
      if (mountedRef.current) setError(err instanceof Error ? err.message : 'Failed to load saved searches');
    } finally {
      if (mountedRef.current) setLoading(false);
    }
  }, []);

  // Load on mount
  useEffect(() => {
    fetchSavedSearches();
  }, [fetchSavedSearches]);

  const saveSearch = useCallback(async (
    name: string,
    description: string,
    params: SearchParams,
  ): Promise<SavedSearch> => {
    setLoading(true);
    setError(null);
    try {
      const data = await apiFetch<SavedSearch>(`${API_BASE}/api/searches`, {
        method: 'POST',
        body: JSON.stringify({ name, description, query_params: params }),
      });
      if (mountedRef.current) {
        setSavedSearches((prev) => [...prev, data]);
      }
      return data;
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Failed to save search';
      if (mountedRef.current) setError(message);
      throw err;
    } finally {
      if (mountedRef.current) setLoading(false);
    }
  }, []);

  const deleteSearch = useCallback(async (id: string): Promise<void> => {
    setLoading(true);
    setError(null);
    try {
      await apiFetch<void>(`${API_BASE}/api/searches/${id}`, { method: 'DELETE' });
      if (mountedRef.current) {
        setSavedSearches((prev) => prev.filter((s) => s.id !== id));
      }
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Failed to delete search';
      if (mountedRef.current) setError(message);
      throw err;
    } finally {
      if (mountedRef.current) setLoading(false);
    }
  }, []);

  const runSearch = useCallback(async (params: SearchParams): Promise<SearchResult> => {
    const url = new URL(`${API_BASE}/api/investigations/search`);
    if (params.q) url.searchParams.set('q', params.q);
    if (params.status) url.searchParams.set('status', params.status);
    if (params.type) url.searchParams.set('type', params.type);
    if (params.priority) url.searchParams.set('priority', params.priority);
    if (params.risk_level) url.searchParams.set('risk_level', params.risk_level);
    if (params.from_date) url.searchParams.set('from_date', params.from_date);
    if (params.to_date) url.searchParams.set('to_date', params.to_date);

    return apiFetch<SearchResult>(url.toString());
  }, []);

  const runSavedSearch = useCallback(async (id: string): Promise<SearchResult> => {
    return apiFetch<SearchResult>(`${API_BASE}/api/searches/${id}/matches`);
  }, []);

  return {
    savedSearches,
    loading,
    error,
    fetchSavedSearches,
    saveSearch,
    deleteSearch,
    runSearch,
    runSavedSearch,
  };
}

export default useSavedSearches;
