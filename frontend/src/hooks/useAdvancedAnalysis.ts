/**
 * useAdvancedAnalysis Hook
 *
 * React hook for interacting with advanced analysis API endpoints.
 * Provides MITRE ATT&CK mapping, risk assessment, correlation analysis,
 * and timeline reconstruction.
 */

import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import api from '../utils/api';
import type { TimelineEvent as ComponentTimelineEvent } from '../components/visualizations/InvestigationTimeline';

// =============================================================================
// Types
// =============================================================================

// MITRE ATT&CK Types
export interface MITRETechnique {
  id: string;
  name: string;
  description?: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  detected: boolean;
  count: number;
  subtechniques?: MITRETechnique[];
  evidence?: string[];
  mitigations?: string[];
  dataSourcesUsed?: string[];
  firstSeen?: string;
  lastSeen?: string;
}

export interface MITRETactic {
  id: string;
  name: string;
  shortName: string;
  description?: string;
  order: number;
  techniques: MITRETechnique[];
}

export interface MITREAnalysisResult {
  tactics: MITRETactic[];
  coverage: number;
  totalTechniques: number;
  detectedTechniques: number;
  criticalCount: number;
  highCount: number;
}

// Risk Assessment Types
export type RiskCategory =
  | 'infrastructure'
  | 'threat'
  | 'credential'
  | 'reputation'
  | 'compliance'
  | 'data_exposure';

export interface CategoryRisk {
  category: RiskCategory;
  score: number;
  trend: 'up' | 'down' | 'stable';
  trendPercentage: number;
  history: number[];
  topFactors: string[];
}

export interface RiskFactor {
  id: string;
  title: string;
  description: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  category: RiskCategory;
  impact: number;
}

export interface Recommendation {
  id: string;
  title: string;
  description: string;
  priority: 'immediate' | 'high' | 'medium' | 'low';
  effort: 'low' | 'medium' | 'high';
  category: RiskCategory;
}

export interface RiskAssessmentResult {
  overallScore: number;
  overallTrend: 'up' | 'down' | 'stable';
  categories: CategoryRisk[];
  riskFactors: RiskFactor[];
  recommendations: Recommendation[];
}

// Correlation Types
export interface CorrelatedEntity {
  id: string;
  value: string;
  type: 'ip' | 'domain' | 'email' | 'hash' | 'url' | 'other';
  sources: string[];
  confidence: number;
  firstSeen?: string;
}

export interface CorrelationResult {
  entities: CorrelatedEntity[];
  sources: string[];
  totalCorrelations: number;
  highConfidenceCount: number;
}

// Timeline Types - re-export from component for compatibility
export type TimelineEvent = ComponentTimelineEvent;

export interface TimelineResult {
  events: TimelineEvent[];
  startDate: string;
  endDate: string;
  totalEvents: number;
}

// Executive Summary Types
export interface KeyFinding {
  id: string;
  text: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  category?: string;
}

export interface RecommendedAction {
  id: string;
  text: string;
  priority: 'immediate' | 'high' | 'medium' | 'low';
  completed?: boolean;
}

export interface ExecutiveSummaryResult {
  title: string;
  status: 'completed' | 'in_progress' | 'pending';
  threatLevel: 'critical' | 'high' | 'medium' | 'low' | 'none';
  riskTrajectory: 'increasing' | 'decreasing' | 'stable';
  findings: KeyFinding[];
  recommendations: RecommendedAction[];
  confidenceScore: number;
  summary: string;
  entitiesAnalyzed: number;
  dataSourcesUsed: number;
  investigationDuration: string;
}

// =============================================================================
// API Client
// =============================================================================

const analysisApi = {
  // Get MITRE ATT&CK mapping
  getMITREMapping: async (investigationId: string): Promise<MITREAnalysisResult> => {
    const response = await api.get(
      `/investigations/${investigationId}/analysis/advanced`
    );
    return response.data.mitre;
  },

  // Get full advanced analysis
  getAdvancedAnalysis: async (investigationId: string): Promise<{
    mitre: MITREAnalysisResult;
    risk: RiskAssessmentResult;
  }> => {
    const response = await api.get(
      `/investigations/${investigationId}/analysis/advanced`
    );
    return response.data;
  },

  // Get risk assessment
  getRiskAssessment: async (target: string): Promise<RiskAssessmentResult> => {
    const response = await api.post(`/risk/assess`, { target });
    return response.data;
  },

  // Get risk trends
  getRiskTrends: async (target: string): Promise<CategoryRisk[]> => {
    const response = await api.get(`/risk/trends/${encodeURIComponent(target)}`);
    return response.data.categories;
  },

  // Get entity correlation
  getCorrelation: async (investigationId: string): Promise<CorrelationResult> => {
    const response = await api.get(
      `/investigations/${investigationId}/correlation`
    );
    return response.data;
  },

  // Get timeline
  getTimeline: async (investigationId: string): Promise<TimelineResult> => {
    const response = await api.get(
      `/investigations/${investigationId}/timeline`
    );
    return response.data;
  },

  // Generate executive summary
  getExecutiveSummary: async (investigationId: string): Promise<ExecutiveSummaryResult> => {
    const response = await api.get(
      `/investigations/${investigationId}/summary`
    );
    return response.data;
  },
};

// =============================================================================
// Hook
// =============================================================================

export interface UseAdvancedAnalysisOptions {
  investigationId: string;
  autoFetch?: boolean;
}

export function useAdvancedAnalysis({ investigationId, autoFetch = false }: UseAdvancedAnalysisOptions) {
  const queryClient = useQueryClient();

  // Query: Full advanced analysis
  const advancedAnalysisQuery = useQuery({
    queryKey: ['analysis', 'advanced', investigationId],
    queryFn: () => analysisApi.getAdvancedAnalysis(investigationId),
    enabled: !!investigationId && autoFetch,
    staleTime: 60000,
  });

  // Query: MITRE mapping only
  const mitreQuery = useQuery({
    queryKey: ['analysis', 'mitre', investigationId],
    queryFn: () => analysisApi.getMITREMapping(investigationId),
    enabled: false,
  });

  // Query: Correlation
  const correlationQuery = useQuery({
    queryKey: ['analysis', 'correlation', investigationId],
    queryFn: () => analysisApi.getCorrelation(investigationId),
    enabled: !!investigationId && autoFetch,
    staleTime: 30000,
  });

  // Query: Timeline
  const timelineQuery = useQuery({
    queryKey: ['analysis', 'timeline', investigationId],
    queryFn: () => analysisApi.getTimeline(investigationId),
    enabled: !!investigationId && autoFetch,
    staleTime: 30000,
  });

  // Query: Executive summary
  const summaryQuery = useQuery({
    queryKey: ['analysis', 'summary', investigationId],
    queryFn: () => analysisApi.getExecutiveSummary(investigationId),
    enabled: !!investigationId && autoFetch,
    staleTime: 60000,
  });

  // Mutation: Risk assessment
  const riskAssessmentMutation = useMutation({
    mutationFn: (target: string) => analysisApi.getRiskAssessment(target),
  });

  // Actions
  const fetchAdvancedAnalysis = () => {
    return advancedAnalysisQuery.refetch();
  };

  const fetchMITRE = () => {
    return mitreQuery.refetch();
  };

  const fetchCorrelation = () => {
    return correlationQuery.refetch();
  };

  const fetchTimeline = () => {
    return timelineQuery.refetch();
  };

  const fetchSummary = () => {
    return summaryQuery.refetch();
  };

  const assessRisk = (target: string) => {
    return riskAssessmentMutation.mutateAsync(target);
  };

  const refreshAll = async () => {
    await Promise.all([
      advancedAnalysisQuery.refetch(),
      correlationQuery.refetch(),
      timelineQuery.refetch(),
      summaryQuery.refetch(),
    ]);
  };

  return {
    // Data
    advancedAnalysis: advancedAnalysisQuery.data,
    mitre: advancedAnalysisQuery.data?.mitre || mitreQuery.data,
    risk: advancedAnalysisQuery.data?.risk,
    correlation: correlationQuery.data,
    timeline: timelineQuery.data,
    summary: summaryQuery.data,

    // Loading states
    isLoading:
      advancedAnalysisQuery.isLoading ||
      correlationQuery.isLoading ||
      timelineQuery.isLoading,
    isMITRELoading: mitreQuery.isFetching,
    isCorrelationLoading: correlationQuery.isFetching,
    isTimelineLoading: timelineQuery.isFetching,
    isSummaryLoading: summaryQuery.isFetching,
    isAssessingRisk: riskAssessmentMutation.isPending,

    // Error states
    error:
      advancedAnalysisQuery.error ||
      correlationQuery.error ||
      timelineQuery.error ||
      summaryQuery.error,

    // Actions
    fetchAdvancedAnalysis,
    fetchMITRE,
    fetchCorrelation,
    fetchTimeline,
    fetchSummary,
    assessRisk,
    refreshAll,
  };
}

export default useAdvancedAnalysis;
