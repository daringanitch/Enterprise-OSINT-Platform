"""
Collaboration Blueprint — Real-time multi-analyst presence & annotations.

Uses Flask-SocketIO to provide:
  - Investigation rooms: analysts join/leave per investigation
  - Presence tracking: who is viewing each investigation
  - Live annotations: timestamped comments with analyst attribution
  - Activity feed: heartbeats + status updates broadcast to all room members

Socket.IO events (client → server):
  join_investigation      { investigation_id, analyst_id, analyst_name, color }
  leave_investigation     { investigation_id, analyst_id }
  add_annotation          { investigation_id, analyst_id, analyst_name, text, entity? }
  cursor_move             { investigation_id, analyst_id, x, y }   (graph view)
  update_investigation    { investigation_id, changes }            (optimistic update)

Socket.IO events (server → client):
  presence_update         { investigation_id, analysts: [...] }
  new_annotation          { ...annotation object }
  analyst_joined          { analyst_id, analyst_name, color }
  analyst_left            { analyst_id }
  investigation_updated   { investigation_id, changes, updated_by }
  cursor_update           { analyst_id, x, y }

HTTP REST endpoints (for persistence):
  GET  /api/investigations/<id>/annotations        list annotations
  POST /api/investigations/<id>/annotations        add annotation (also emits)
  DELETE /api/investigations/<id>/annotations/<aid> delete annotation
"""

import uuid
from datetime import datetime, timezone
from flask import Blueprint, request, jsonify
from flask_socketio import join_room, leave_room, emit

# ─── In-memory stores ──────────────────────────────────────────────────────────
# Structure: { investigation_id: { analyst_id: PresenceEntry } }
_presence: dict[str, dict] = {}

# Structure: { investigation_id: [Annotation, ...] }
_annotations: dict[str, list] = {}

bp = Blueprint('collaboration', __name__)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _get_socketio():
    """Lazy import to avoid circular dep — imported after app/socketio init."""
    from app import socketio  # noqa: PLC0415
    return socketio


# ─── HTTP REST endpoints ───────────────────────────────────────────────────────

@bp.route('/api/investigations/<investigation_id>/annotations', methods=['GET'])
def list_annotations(investigation_id: str):
    """Return all annotations for an investigation, newest first."""
    anns = _annotations.get(investigation_id, [])
    return jsonify(sorted(anns, key=lambda a: a['created_at'], reverse=True))


@bp.route('/api/investigations/<investigation_id>/annotations', methods=['POST'])
def create_annotation(investigation_id: str):
    """
    Add an annotation and broadcast it to all analysts in the room.
    Body: { analyst_id, analyst_name, text, entity?, color? }
    """
    body = request.get_json(silent=True) or {}
    analyst_id = body.get('analyst_id', 'unknown')
    analyst_name = body.get('analyst_name', 'Analyst')
    text = body.get('text', '').strip()
    entity = body.get('entity')  # optional: { value, type }
    color = body.get('color', '#22D3EE')

    if not text:
        return jsonify({'error': 'text is required'}), 400

    annotation = {
        'id': str(uuid.uuid4()),
        'investigation_id': investigation_id,
        'analyst_id': analyst_id,
        'analyst_name': analyst_name,
        'color': color,
        'text': text,
        'entity': entity,
        'created_at': _now(),
        'reactions': {},
    }

    _annotations.setdefault(investigation_id, []).append(annotation)

    # Broadcast to room
    try:
        sio = _get_socketio()
        sio.emit('new_annotation', annotation, room=f'investigation_{investigation_id}')
    except Exception:
        pass  # Graceful degradation if SocketIO not initialised

    return jsonify(annotation), 201


@bp.route('/api/investigations/<investigation_id>/annotations/<annotation_id>', methods=['DELETE'])
def delete_annotation(investigation_id: str, annotation_id: str):
    """Delete an annotation by ID."""
    anns = _annotations.get(investigation_id, [])
    before = len(anns)
    _annotations[investigation_id] = [a for a in anns if a['id'] != annotation_id]
    if len(_annotations[investigation_id]) == before:
        return jsonify({'error': 'annotation not found'}), 404

    try:
        sio = _get_socketio()
        sio.emit(
            'annotation_deleted',
            {'investigation_id': investigation_id, 'annotation_id': annotation_id},
            room=f'investigation_{investigation_id}',
        )
    except Exception:
        pass

    return jsonify({'deleted': annotation_id})


@bp.route('/api/investigations/<investigation_id>/presence', methods=['GET'])
def get_presence(investigation_id: str):
    """Return current analyst presence for an investigation."""
    analysts = list(_presence.get(investigation_id, {}).values())
    return jsonify({'investigation_id': investigation_id, 'analysts': analysts})


# ─── Socket.IO event handlers ──────────────────────────────────────────────────
# These are registered by collaboration_sockets.register(socketio) called in app.py.

def register_socket_events(socketio):
    """Register all Socket.IO event handlers onto the given SocketIO instance."""

    @socketio.on('join_investigation')
    def on_join(data):
        inv_id = data.get('investigation_id', '')
        analyst_id = data.get('analyst_id', str(uuid.uuid4()))
        analyst_name = data.get('analyst_name', 'Anonymous Analyst')
        color = data.get('color', _assign_color(analyst_id))

        room = f'investigation_{inv_id}'
        join_room(room)

        entry = {
            'analyst_id': analyst_id,
            'analyst_name': analyst_name,
            'color': color,
            'joined_at': _now(),
            'last_seen': _now(),
        }
        _presence.setdefault(inv_id, {})[analyst_id] = entry

        # Tell newcomer about existing presence
        emit('presence_update', {
            'investigation_id': inv_id,
            'analysts': list(_presence[inv_id].values()),
        })

        # Broadcast join to others
        emit('analyst_joined', entry, room=room, include_self=False)

    @socketio.on('leave_investigation')
    def on_leave(data):
        inv_id = data.get('investigation_id', '')
        analyst_id = data.get('analyst_id', '')
        room = f'investigation_{inv_id}'

        leave_room(room)
        _presence.get(inv_id, {}).pop(analyst_id, None)

        emit('analyst_left', {'analyst_id': analyst_id}, room=room, include_self=False)
        emit('presence_update', {
            'investigation_id': inv_id,
            'analysts': list(_presence.get(inv_id, {}).values()),
        }, room=room)

    @socketio.on('cursor_move')
    def on_cursor(data):
        inv_id = data.get('investigation_id', '')
        analyst_id = data.get('analyst_id', '')
        # Update last-seen
        if inv_id in _presence and analyst_id in _presence[inv_id]:
            _presence[inv_id][analyst_id]['last_seen'] = _now()
        emit('cursor_update', data, room=f'investigation_{inv_id}', include_self=False)

    @socketio.on('update_investigation')
    def on_update(data):
        inv_id = data.get('investigation_id', '')
        changes = data.get('changes', {})
        updated_by = data.get('analyst_id', 'unknown')
        emit(
            'investigation_updated',
            {'investigation_id': inv_id, 'changes': changes, 'updated_by': updated_by},
            room=f'investigation_{inv_id}',
            include_self=False,
        )

    @socketio.on('heartbeat')
    def on_heartbeat(data):
        inv_id = data.get('investigation_id', '')
        analyst_id = data.get('analyst_id', '')
        if inv_id in _presence and analyst_id in _presence[inv_id]:
            _presence[inv_id][analyst_id]['last_seen'] = _now()


# ─── Helpers ───────────────────────────────────────────────────────────────────

_ANALYST_COLORS = [
    '#22D3EE', '#8B5CF6', '#F59E0B', '#22C55E', '#EF4444',
    '#F97316', '#EC4899', '#06B6D4', '#84CC16', '#A78BFA',
]


def _assign_color(analyst_id: str) -> str:
    """Deterministically assign a color to an analyst ID."""
    idx = hash(analyst_id) % len(_ANALYST_COLORS)
    return _ANALYST_COLORS[idx]
