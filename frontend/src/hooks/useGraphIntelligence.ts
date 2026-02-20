/**
 * useGraphIntelligence Hook
 *
 * React hook for interacting with the Graph Intelligence API endpoints.
 * Provides centrality analysis, path finding, community detection,
 * anomaly detection, and blast radius analysis.
 */

import { useState, useCallback } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import api from '../utils/api';

// =============================================================================
// Types
// =============================================================================

export interface GraphEntity {
  id: string;
  label: string;
  type: string;
  properties?: Record<string, any>;
  centralityScore?: number;
  isAnomaly?: boolean;
  riskLevel?: 'critical' | 'high' | 'medium' | 'low';
  community?: number;
}

export interface GraphRelationship {
  id: string;
  source: string;
  target: string;
  type: string;
  weight?: number;
  confidence?: number;
  properties?: Record<string, any>;
}

export interface GraphData {
  entities: GraphEntity[];
  relationships: GraphRelationship[];
}

export interface CentralityResult {
  entityId: string;
  pageRank: number;
  betweenness: number;
  closeness: number;
  eigenvector?: number;
}

export interface PathResult {
  nodes: string[];
  edges: string[];
  totalWeight: number;
  path: GraphEntity[];
}

export interface CommunityResult {
  id: number;
  name?: string;
  entities: GraphEntity[];
  cohesion: number;
  density: number;
}

export interface AnomalyResult {
  id: string;
  label: string;
  entityType: string;
  anomalyTypes: string[];
  severity: 'critical' | 'high' | 'medium' | 'low';
  zScore: number;
  description: string;
  confidence: number;
}

export interface BlastRadiusResult {
  sourceEntity: string;
  affectedNodes: string[];
  impactLevels: Record<string, number>;
  totalImpact: number;
  hops: number;
}

export interface GraphAnalysisResult {
  centrality: CentralityResult[];
  communities: CommunityResult[];
  anomalies: AnomalyResult[];
  paths?: PathResult[];
}

// =============================================================================
// API Client
// =============================================================================

const graphApi = {
  // Sync investigation to graph
  syncToGraph: async (investigationId: string): Promise<GraphData> => {
    const response = await api.post(
      `/investigations/${investigationId}/graph/sync`
    );
    return response.data;
  },

  // Run full graph analysis
  analyzeGraph: async (investigationId: string): Promise<GraphAnalysisResult> => {
    const response = await api.post(
      `/investigations/${investigationId}/graph/analyze`
    );
    return response.data;
  },

  // Get centrality metrics
  getCentrality: async (investigationId: string): Promise<CentralityResult[]> => {
    const response = await api.post(`/graph/centrality`, {
      investigation_id: investigationId,
    });
    return response.data.results;
  },

  // Find shortest path between entities
  findPath: async (
    investigationId: string,
    sourceId: string,
    targetId: string
  ): Promise<PathResult> => {
    const response = await api.post(
      `/investigations/${investigationId}/graph/paths`,
      {
        source_id: sourceId,
        target_id: targetId,
      }
    );
    return response.data;
  },

  // Detect communities
  detectCommunities: async (investigationId: string): Promise<CommunityResult[]> => {
    const response = await api.post(`/graph/communities`, {
      investigation_id: investigationId,
    });
    return response.data.communities;
  },

  // Detect anomalies
  detectAnomalies: async (investigationId: string): Promise<AnomalyResult[]> => {
    const response = await api.post(`/graph/anomalies`, {
      investigation_id: investigationId,
    });
    return response.data.anomalies;
  },

  // Calculate blast radius
  blastRadius: async (
    investigationId: string,
    entityId: string,
    maxHops?: number
  ): Promise<BlastRadiusResult> => {
    const response = await api.post(
      `/investigations/${investigationId}/graph/blast-radius`,
      {
        entity_id: entityId,
        max_hops: maxHops || 3,
      }
    );
    return response.data;
  },

  // Get graph status
  getStatus: async (): Promise<{ connected: boolean; mode: string }> => {
    const response = await api.get(`/graph/status`);
    return response.data;
  },
};

// =============================================================================
// Hook
// =============================================================================

export interface UseGraphIntelligenceOptions {
  investigationId: string;
  autoSync?: boolean;
}

export function useGraphIntelligence({ investigationId, autoSync = false }: UseGraphIntelligenceOptions) {
  const queryClient = useQueryClient();
  const [selectedPath, setSelectedPath] = useState<PathResult | null>(null);
  const [blastRadiusResult, setBlastRadiusResult] = useState<BlastRadiusResult | null>(null);

  // Query: Graph status
  const statusQuery = useQuery({
    queryKey: ['graph', 'status'],
    queryFn: graphApi.getStatus,
    staleTime: 60000, // 1 minute
  });

  // Query: Graph data (sync'd)
  const graphDataQuery = useQuery({
    queryKey: ['graph', 'data', investigationId],
    queryFn: () => graphApi.syncToGraph(investigationId),
    enabled: !!investigationId && autoSync,
    staleTime: 30000,
  });

  // Query: Full analysis
  const analysisQuery = useQuery({
    queryKey: ['graph', 'analysis', investigationId],
    queryFn: () => graphApi.analyzeGraph(investigationId),
    enabled: !!investigationId && autoSync,
    staleTime: 60000,
  });

  // Query: Centrality
  const centralityQuery = useQuery({
    queryKey: ['graph', 'centrality', investigationId],
    queryFn: () => graphApi.getCentrality(investigationId),
    enabled: false, // Manual trigger
  });

  // Query: Communities
  const communitiesQuery = useQuery({
    queryKey: ['graph', 'communities', investigationId],
    queryFn: () => graphApi.detectCommunities(investigationId),
    enabled: false, // Manual trigger
  });

  // Query: Anomalies
  const anomaliesQuery = useQuery({
    queryKey: ['graph', 'anomalies', investigationId],
    queryFn: () => graphApi.detectAnomalies(investigationId),
    enabled: false, // Manual trigger
  });

  // Mutation: Sync to graph
  const syncMutation = useMutation({
    mutationFn: () => graphApi.syncToGraph(investigationId),
    onSuccess: (data) => {
      queryClient.setQueryData(['graph', 'data', investigationId], data);
    },
  });

  // Mutation: Find path
  const findPathMutation = useMutation({
    mutationFn: ({ sourceId, targetId }: { sourceId: string; targetId: string }) =>
      graphApi.findPath(investigationId, sourceId, targetId),
    onSuccess: (data) => {
      setSelectedPath(data);
    },
  });

  // Mutation: Blast radius
  const blastRadiusMutation = useMutation({
    mutationFn: ({ entityId, maxHops }: { entityId: string; maxHops?: number }) =>
      graphApi.blastRadius(investigationId, entityId, maxHops),
    onSuccess: (data) => {
      setBlastRadiusResult(data);
    },
  });

  // Actions
  const syncGraph = useCallback(() => {
    return syncMutation.mutateAsync();
  }, [syncMutation]);

  const runFullAnalysis = useCallback(() => {
    return queryClient.fetchQuery({
      queryKey: ['graph', 'analysis', investigationId],
      queryFn: () => graphApi.analyzeGraph(investigationId),
    });
  }, [queryClient, investigationId]);

  const fetchCentrality = useCallback(() => {
    return centralityQuery.refetch();
  }, [centralityQuery]);

  const fetchCommunities = useCallback(() => {
    return communitiesQuery.refetch();
  }, [communitiesQuery]);

  const fetchAnomalies = useCallback(() => {
    return anomaliesQuery.refetch();
  }, [anomaliesQuery]);

  const findPath = useCallback(
    (sourceId: string, targetId: string) => {
      return findPathMutation.mutateAsync({ sourceId, targetId });
    },
    [findPathMutation]
  );

  const calculateBlastRadius = useCallback(
    (entityId: string, maxHops?: number) => {
      return blastRadiusMutation.mutateAsync({ entityId, maxHops });
    },
    [blastRadiusMutation]
  );

  const clearPath = useCallback(() => {
    setSelectedPath(null);
  }, []);

  const clearBlastRadius = useCallback(() => {
    setBlastRadiusResult(null);
  }, []);

  return {
    // Status
    isConnected: statusQuery.data?.connected ?? false,
    graphMode: statusQuery.data?.mode ?? 'unknown',

    // Data
    graphData: graphDataQuery.data,
    analysis: analysisQuery.data,
    centrality: centralityQuery.data,
    communities: communitiesQuery.data,
    anomalies: anomaliesQuery.data,
    selectedPath,
    blastRadiusResult,

    // Loading states
    isLoading: graphDataQuery.isLoading || analysisQuery.isLoading,
    isSyncing: syncMutation.isPending,
    isAnalyzing: analysisQuery.isFetching,
    isFindingPath: findPathMutation.isPending,
    isCalculatingBlastRadius: blastRadiusMutation.isPending,

    // Error states
    error: graphDataQuery.error || analysisQuery.error,

    // Actions
    syncGraph,
    runFullAnalysis,
    fetchCentrality,
    fetchCommunities,
    fetchAnomalies,
    findPath,
    calculateBlastRadius,
    clearPath,
    clearBlastRadius,
  };
}

export default useGraphIntelligence;
