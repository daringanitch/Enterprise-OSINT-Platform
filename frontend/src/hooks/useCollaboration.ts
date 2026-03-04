/**
 * useCollaboration
 *
 * Socket.IO-based real-time collaboration hook.
 * Connects to the backend when an analyst opens an investigation,
 * tracks presence (who else is viewing), and provides annotation helpers.
 *
 * Usage:
 *   const { analysts, annotations, addAnnotation, connected } =
 *     useCollaboration({ investigationId: '123', analyst });
 */

import { useState, useEffect, useCallback, useRef } from 'react';
import { io, Socket } from 'socket.io-client';

const SOCKET_URL = process.env.REACT_APP_API_URL || 'http://localhost:5001';

// ─── Types ────────────────────────────────────────────────────────────────────

export interface AnalystPresence {
  analyst_id: string;
  analyst_name: string;
  color: string;
  joined_at: string;
  last_seen: string;
}

export interface Annotation {
  id: string;
  investigation_id: string;
  analyst_id: string;
  analyst_name: string;
  color: string;
  text: string;
  entity?: { value: string; type: string } | null;
  created_at: string;
  reactions: Record<string, string[]>;
}

export interface CursorPosition {
  analyst_id: string;
  analyst_name: string;
  color: string;
  x: number;
  y: number;
}

export interface CollaborationOptions {
  investigationId: string | null | undefined;
  analyst: {
    analyst_id: string;
    analyst_name: string;
    color?: string;
  };
  /** Called when a remote analyst updates the investigation */
  onInvestigationUpdated?: (changes: Record<string, unknown>, updatedBy: string) => void;
}

interface UseCollaborationReturn {
  connected: boolean;
  analysts: AnalystPresence[];
  annotations: Annotation[];
  cursors: Map<string, CursorPosition>;
  addAnnotation: (text: string, entity?: { value: string; type: string }) => Promise<Annotation | null>;
  deleteAnnotation: (annotationId: string) => Promise<void>;
  broadcastCursor: (x: number, y: number) => void;
  broadcastUpdate: (changes: Record<string, unknown>) => void;
}

// ─── Analyst color pool ───────────────────────────────────────────────────────

const COLORS = [
  '#22D3EE', '#8B5CF6', '#F59E0B', '#22C55E',
  '#EF4444', '#F97316', '#EC4899', '#06B6D4',
];

function pickColor(id: string): string {
  let hash = 0;
  for (const ch of id) hash = (hash * 31 + ch.charCodeAt(0)) >>> 0;
  return COLORS[hash % COLORS.length];
}

// ─── Hook ─────────────────────────────────────────────────────────────────────

export function useCollaboration({
  investigationId,
  analyst,
  onInvestigationUpdated,
}: CollaborationOptions): UseCollaborationReturn {
  const [connected, setConnected] = useState(false);
  const [analysts, setAnalysts] = useState<AnalystPresence[]>([]);
  const [annotations, setAnnotations] = useState<Annotation[]>([]);
  const [cursors, setCursors] = useState<Map<string, CursorPosition>>(new Map());

  const socketRef = useRef<Socket | null>(null);
  const color = analyst.color || pickColor(analyst.analyst_id);

  // ── Load existing annotations via REST on mount ────────────────────────────
  useEffect(() => {
    if (!investigationId) return;
    const token = localStorage.getItem('auth_token');
    fetch(`${SOCKET_URL}/api/investigations/${investigationId}/annotations`, {
      headers: token ? { Authorization: `Bearer ${token}` } : {},
    })
      .then((r) => r.ok ? r.json() : [])
      .then((data: Annotation[]) => setAnnotations(data))
      .catch(() => {});
  }, [investigationId]);

  // ── Socket lifecycle ───────────────────────────────────────────────────────
  useEffect(() => {
    if (!investigationId) return;

    const socket = io(SOCKET_URL, {
      transports: ['websocket', 'polling'],
      reconnection: true,
      reconnectionDelay: 1000,
      reconnectionAttempts: 5,
    });
    socketRef.current = socket;

    socket.on('connect', () => {
      setConnected(true);
      socket.emit('join_investigation', {
        investigation_id: investigationId,
        analyst_id: analyst.analyst_id,
        analyst_name: analyst.analyst_name,
        color,
      });
    });

    socket.on('disconnect', () => setConnected(false));

    socket.on('presence_update', (data: { investigation_id: string; analysts: AnalystPresence[] }) => {
      if (data.investigation_id === investigationId) {
        setAnalysts(data.analysts.filter((a) => a.analyst_id !== analyst.analyst_id));
      }
    });

    socket.on('analyst_joined', (entry: AnalystPresence) => {
      if (entry.analyst_id !== analyst.analyst_id) {
        setAnalysts((prev) => {
          if (prev.some((a) => a.analyst_id === entry.analyst_id)) return prev;
          return [...prev, entry];
        });
      }
    });

    socket.on('analyst_left', (data: { analyst_id: string }) => {
      setAnalysts((prev) => prev.filter((a) => a.analyst_id !== data.analyst_id));
      setCursors((prev) => {
        const next = new Map(prev);
        next.delete(data.analyst_id);
        return next;
      });
    });

    socket.on('new_annotation', (annotation: Annotation) => {
      setAnnotations((prev) => {
        if (prev.some((a) => a.id === annotation.id)) return prev;
        return [annotation, ...prev];
      });
    });

    socket.on('annotation_deleted', (data: { annotation_id: string }) => {
      setAnnotations((prev) => prev.filter((a) => a.id !== data.annotation_id));
    });

    socket.on('cursor_update', (data: { analyst_id: string; analyst_name: string; color: string; x: number; y: number }) => {
      setCursors((prev) => new Map(prev).set(data.analyst_id, data));
    });

    socket.on('investigation_updated', (data: { changes: Record<string, unknown>; updated_by: string }) => {
      onInvestigationUpdated?.(data.changes, data.updated_by);
    });

    // Heartbeat every 20 s
    const heartbeatInterval = setInterval(() => {
      if (socket.connected) {
        socket.emit('heartbeat', {
          investigation_id: investigationId,
          analyst_id: analyst.analyst_id,
        });
      }
    }, 20_000);

    return () => {
      clearInterval(heartbeatInterval);
      if (socket.connected) {
        socket.emit('leave_investigation', {
          investigation_id: investigationId,
          analyst_id: analyst.analyst_id,
        });
      }
      socket.disconnect();
      socketRef.current = null;
      setConnected(false);
      setAnalysts([]);
    };
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [investigationId, analyst.analyst_id]);

  // ── Actions ────────────────────────────────────────────────────────────────

  const addAnnotation = useCallback(
    async (text: string, entity?: { value: string; type: string }): Promise<Annotation | null> => {
      if (!investigationId) return null;
      const token = localStorage.getItem('auth_token');
      try {
        const res = await fetch(
          `${SOCKET_URL}/api/investigations/${investigationId}/annotations`,
          {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
              ...(token ? { Authorization: `Bearer ${token}` } : {}),
            },
            body: JSON.stringify({
              analyst_id: analyst.analyst_id,
              analyst_name: analyst.analyst_name,
              color,
              text,
              entity: entity || null,
            }),
          },
        );
        if (!res.ok) return null;
        const ann: Annotation = await res.json();
        // Optimistic add (server also emits via socket)
        setAnnotations((prev) => {
          if (prev.some((a) => a.id === ann.id)) return prev;
          return [ann, ...prev];
        });
        return ann;
      } catch {
        return null;
      }
    },
    [investigationId, analyst, color],
  );

  const deleteAnnotation = useCallback(
    async (annotationId: string): Promise<void> => {
      if (!investigationId) return;
      const token = localStorage.getItem('auth_token');
      try {
        await fetch(
          `${SOCKET_URL}/api/investigations/${investigationId}/annotations/${annotationId}`,
          {
            method: 'DELETE',
            headers: token ? { Authorization: `Bearer ${token}` } : {},
          },
        );
        setAnnotations((prev) => prev.filter((a) => a.id !== annotationId));
      } catch {
        // ignore
      }
    },
    [investigationId],
  );

  const broadcastCursor = useCallback(
    (x: number, y: number) => {
      socketRef.current?.emit('cursor_move', {
        investigation_id: investigationId,
        analyst_id: analyst.analyst_id,
        analyst_name: analyst.analyst_name,
        color,
        x,
        y,
      });
    },
    [investigationId, analyst, color],
  );

  const broadcastUpdate = useCallback(
    (changes: Record<string, unknown>) => {
      socketRef.current?.emit('update_investigation', {
        investigation_id: investigationId,
        analyst_id: analyst.analyst_id,
        changes,
      });
    },
    [investigationId, analyst.analyst_id],
  );

  return {
    connected,
    analysts,
    annotations,
    cursors,
    addAnnotation,
    deleteAnnotation,
    broadcastCursor,
    broadcastUpdate,
  };
}

export default useCollaboration;
