"""
Enrichment Blueprint — Unified "Investigate This" fan-out with SSE streaming.

Provides a single endpoint that fans out to all configured MCP intelligence
servers in parallel and streams structured results back to the UI as
Server-Sent Events (SSE), so the frontend can display a live progress
timeline as each source resolves.

Endpoint:
  GET  /api/enrich?value=<ioc>&type=<ip_address|domain|email|hash|url>
       Accept: text/event-stream

SSE event format:
  event: source_start
  data: {"source": "infrastructure", "label": "Infrastructure / DNS", "icon": "dns"}

  event: source_result
  data: {"source": "infrastructure", "status": "success", "duration_ms": 142,
         "findings": [...], "confidence": 0.87, "risk_score": 6.5}

  event: source_error
  data: {"source": "infrastructure", "status": "error", "error": "timeout"}

  event: summary
  data: {"total_findings": 12, "max_risk": 8.2, "sources_queried": 4,
         "sources_successful": 3, "threat_categories": [...], "duration_ms": 890}

  event: done
  data: {}

Also provides:
  POST /api/enrich            Body: { value, type } — same as GET but for CORS
  GET  /api/enrich/sources    List all configured enrichment sources + health
"""

import json
import time
import uuid
import asyncio
import aiohttp
import threading
import logging
from datetime import datetime, timezone
from flask import Blueprint, request, Response, jsonify, stream_with_context

bp = Blueprint('enrichment', __name__)

logger = logging.getLogger(__name__)

# ─── Source registry ───────────────────────────────────────────────────────────

ENRICHMENT_SOURCES = [
    {
        'id': 'infrastructure',
        'label': 'Infrastructure / DNS',
        'icon': 'dns',
        'url_template': 'http://localhost:8021/analyze',
        'timeout': 10.0,
        'applicable_types': {'ip_address', 'domain', 'url'},
        'description': 'DNS records, WHOIS, certificates, port scan summary',
    },
    {
        'id': 'threat_intel',
        'label': 'Threat Intelligence',
        'icon': 'security',
        'url_template': 'http://localhost:8020/analyze',
        'timeout': 12.0,
        'applicable_types': {'ip_address', 'domain', 'url', 'hash', 'email'},
        'description': 'VirusTotal, Shodan, AbuseIPDB, OTX threat feeds',
    },
    {
        'id': 'social',
        'label': 'Social & OSINT',
        'icon': 'people',
        'url_template': 'http://localhost:8010/analyze',
        'timeout': 8.0,
        'applicable_types': {'email', 'domain'},
        'description': 'Social media presence, breach databases, public profiles',
    },
    {
        'id': 'ai_analysis',
        'label': 'AI Analysis',
        'icon': 'psychology',
        'url_template': 'http://localhost:8050/analyze',
        'timeout': 20.0,
        'applicable_types': {'ip_address', 'domain', 'url', 'hash', 'email'},
        'description': 'GPT-4 powered threat profiling and MITRE mapping',
    },
    {
        'id': 'financial',
        'label': 'Financial / SEC',
        'icon': 'account_balance',
        'url_template': 'http://localhost:8040/analyze',
        'timeout': 10.0,
        'applicable_types': {'domain', 'email'},
        'description': 'SEC filings, corporate registry, beneficial ownership',
    },
]


def _now_ms() -> int:
    return int(time.time() * 1000)


def _sse(event: str, data: dict) -> str:
    return f"event: {event}\ndata: {json.dumps(data)}\n\n"


def _applicable_sources(ioc_type: str) -> list:
    return [s for s in ENRICHMENT_SOURCES if ioc_type in s['applicable_types']]


# ─── Async enrichment worker ──────────────────────────────────────────────────

async def _query_source(source: dict, value: str, ioc_type: str) -> dict:
    """Query a single MCP source and return structured result."""
    start = _now_ms()
    try:
        payload = {
            'target': value,
            'type': ioc_type,
            'options': {'quick': True},
        }
        timeout = aiohttp.ClientTimeout(total=source['timeout'])
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.post(source['url_template'], json=payload) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    return {
                        'source': source['id'],
                        'status': 'success',
                        'duration_ms': _now_ms() - start,
                        'findings': data.get('findings', []),
                        'confidence': data.get('confidence', 0.5),
                        'risk_score': data.get('risk_score', 0.0),
                        'summary': data.get('summary', ''),
                        'raw': data,
                    }
                return {
                    'source': source['id'],
                    'status': 'error',
                    'duration_ms': _now_ms() - start,
                    'error': f'HTTP {resp.status}',
                }
    except asyncio.TimeoutError:
        return {
            'source': source['id'],
            'status': 'timeout',
            'duration_ms': _now_ms() - start,
            'error': f'Timed out after {source["timeout"]}s',
        }
    except Exception as e:
        return {
            'source': source['id'],
            'status': 'error',
            'duration_ms': _now_ms() - start,
            'error': str(e)[:200],
        }


def _run_enrichment_sync(value: str, ioc_type: str, queue: list) -> None:
    """
    Run all applicable source queries concurrently using asyncio,
    putting results into `queue` as they arrive.
    This runs in a thread so Flask's SSE generator can consume it.
    """
    sources = _applicable_sources(ioc_type)

    async def _run():
        tasks = [
            asyncio.create_task(_query_source(src, value, ioc_type))
            for src in sources
        ]
        for coro in asyncio.as_completed(tasks):
            result = await coro
            queue.append(result)
        queue.append(None)  # sentinel

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        loop.run_until_complete(_run())
    finally:
        loop.close()


# ─── SSE generator ─────────────────────────────────────────────────────────────

def _enrichment_stream(value: str, ioc_type: str):
    """
    Generator yielding SSE frames.
    Fans out to all applicable sources, streams results as they arrive.
    """
    if not value or not ioc_type:
        yield _sse('error', {'message': 'value and type are required'})
        yield _sse('done', {})
        return

    sources = _applicable_sources(ioc_type)
    if not sources:
        yield _sse('error', {'message': f'No enrichment sources available for type: {ioc_type}'})
        yield _sse('done', {})
        return

    # Announce which sources will be queried
    for src in sources:
        yield _sse('source_start', {
            'source': src['id'],
            'label': src['label'],
            'icon': src['icon'],
            'description': src['description'],
        })

    # Start async fan-out in a background thread
    result_queue: list = []
    thread = threading.Thread(
        target=_run_enrichment_sync,
        args=(value, ioc_type, result_queue),
        daemon=True,
    )
    thread.start()

    # Stream results as they land in the queue
    seen = 0
    all_results = []
    max_wait = 35.0  # hard ceiling
    start_ts = time.time()

    while time.time() - start_ts < max_wait:
        if seen < len(result_queue):
            item = result_queue[seen]
            seen += 1
            if item is None:
                break  # sentinel — all done
            all_results.append(item)
            event = 'source_result' if item['status'] == 'success' else 'source_error'
            yield _sse(event, item)
        else:
            time.sleep(0.05)

    thread.join(timeout=1.0)

    # Summary
    successful = [r for r in all_results if r['status'] == 'success']
    all_findings = []
    for r in successful:
        all_findings.extend(r.get('findings', []))
    max_risk = max((r.get('risk_score', 0.0) for r in successful), default=0.0)
    threat_categories = list({
        f.get('category') for r in successful for f in r.get('findings', [])
        if f.get('category')
    })

    yield _sse('summary', {
        'value': value,
        'type': ioc_type,
        'total_findings': len(all_findings),
        'max_risk': round(max_risk, 1),
        'sources_queried': len(sources),
        'sources_successful': len(successful),
        'threat_categories': threat_categories,
        'duration_ms': int((time.time() - start_ts) * 1000),
        'timestamp': datetime.now(timezone.utc).isoformat(),
    })

    yield _sse('done', {})


# ─── Routes ───────────────────────────────────────────────────────────────────

@bp.route('/api/enrich', methods=['GET'])
def enrich_get():
    """
    SSE enrichment stream.
    Query params: value=<ioc>, type=<ip_address|domain|email|hash|url>
    """
    value = request.args.get('value', '').strip()
    ioc_type = request.args.get('type', 'domain').strip().lower()

    response = Response(
        stream_with_context(_enrichment_stream(value, ioc_type)),
        content_type='text/event-stream',
    )
    response.headers['Cache-Control'] = 'no-cache'
    response.headers['X-Accel-Buffering'] = 'no'
    response.headers['Connection'] = 'keep-alive'
    return response


@bp.route('/api/enrich', methods=['POST'])
def enrich_post():
    """POST variant for CORS-preflight-free usage."""
    body = request.get_json(silent=True) or {}
    value = body.get('value', request.args.get('value', '')).strip()
    ioc_type = body.get('type', request.args.get('type', 'domain')).strip().lower()

    response = Response(
        stream_with_context(_enrichment_stream(value, ioc_type)),
        content_type='text/event-stream',
    )
    response.headers['Cache-Control'] = 'no-cache'
    response.headers['X-Accel-Buffering'] = 'no'
    response.headers['Connection'] = 'keep-alive'
    return response


@bp.route('/api/enrich/sources', methods=['GET'])
def list_sources():
    """Return all configured enrichment sources and their applicability."""
    return jsonify({
        'sources': ENRICHMENT_SOURCES,
        'total': len(ENRICHMENT_SOURCES),
    })
