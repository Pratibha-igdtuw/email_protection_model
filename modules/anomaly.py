"""
Cross-source anomaly detection. Everything else in the pipeline scores
ONE item (an email, an evidence upload) in isolation; nothing looks
across an analyst's whole history for statistical outliers. Previously
this module only ever looked at Case (analyzed-email) rows -- an
Evidence item (SMS export, chat log, image, document) could never
trigger or appear in an anomaly, even though "identifying patterns and
anomalies" is a source-agnostic requirement, not an email-specific one.

Now works off a common "entity event" shape -- {entity_value, timestamp,
source_type, source_ref} -- built separately for each record type
(_case_domain_events, _case_country_events, _evidence_phone_events) but
scored by the SAME two generic, dependency-free checks:

1. Volume-spike detection -- per entity (sender domain / country / phone
   number), is the most recent day's event count a statistical outlier
   against that entity's OWN historical daily mean (z-score), not a
   fixed global threshold?
2. Unusual-time detection -- does an event arrive in an hour-of-day
   bucket that's rare in its entity's own historical distribution?

Deliberately simple (mean/stdev, not isolation forest) so it runs
instantly on a hackathon-scale dataset (dozens of records, not millions)
and stays explainable: "N standard deviations above its own historical
mean" is a real, checkable number, not a black box.
"""
import json
from collections import defaultdict
from statistics import mean, pstdev

# Hackathon-scale datasets rarely produce a clean textbook 2-3 sigma
# signal, so the bar is set a little lower than the usual "outlier"
# convention -- tune upward once there's more real traffic to test against.
Z_SCORE_THRESHOLD = 1.8
MIN_GROUP_DAYS = 3     # need this many distinct days of history in a group first
MIN_HOUR_HISTORY = 5   # need this many prior events for an entity before an
                        # "unusual hour" flag means anything


# ---------------------------------------------------------------------------
# Per-record-type event extraction. Each returns a flat list of
# {'entity_value', 'timestamp', 'source_type', 'source_ref'} dicts -- the
# only shape the generic scoring functions below need to know about.
# ---------------------------------------------------------------------------

def _case_domain_events(cases):
    return [
        {'entity_value': c.sender_domain, 'timestamp': c.created_at,
         'source_type': 'case', 'source_ref': c.case_ref}
        for c in cases if c.sender_domain and c.created_at
    ]


def _case_country_events(cases):
    return [
        {'entity_value': c.country, 'timestamp': c.created_at,
         'source_type': 'case', 'source_ref': c.case_ref}
        for c in cases if c.country and c.created_at
    ]


def _evidence_phone_events(evidence_items):
    """One event per (evidence item, detected phone number) -- an SMS
    export or chat log can mention several numbers, and each is its own
    pivot for volume/timing purposes, same as correlation_graph.py treats
    them as separate entity nodes."""
    events = []
    for e in evidence_items:
        if not e.uploaded_at:
            continue
        try:
            meta = json.loads(e.metadata_json) if e.metadata_json else {}
        except (ValueError, TypeError):
            meta = {}
        for phone in (meta.get('detected_phone_numbers') or []):
            events.append({'entity_value': phone, 'timestamp': e.uploaded_at,
                            'source_type': 'file', 'source_ref': e.evidence_ref})
    return events


# ---------------------------------------------------------------------------
# Generic scoring -- identical statistics, now parameterized over any
# entity-event list instead of being written directly against Case columns.
# ---------------------------------------------------------------------------

def _volume_anomalies(events, label):
    daily_counts = defaultdict(lambda: defaultdict(int))
    for ev in events:
        daily_counts[ev['entity_value']][ev['timestamp'].date()] += 1

    anomalies = []
    for group, by_day in daily_counts.items():
        days_sorted = sorted(by_day.keys())
        if len(days_sorted) < MIN_GROUP_DAYS:
            continue
        counts = [by_day[d] for d in days_sorted]
        history, latest_count = counts[:-1], counts[-1]
        latest_day = days_sorted[-1]
        if not history:
            continue

        m = mean(history)
        sd = pstdev(history) if len(history) > 1 else 0

        if sd == 0:
            if m > 0 and latest_count > m:
                z = None  # no prior variance to measure against -- flag as a clean break instead
            else:
                continue
        else:
            z = (latest_count - m) / sd
            if z < Z_SCORE_THRESHOLD:
                continue

        anomalies.append({
            'type': f'Volume spike ({label})',
            'group': group,
            'date': latest_day.isoformat(),
            'count': latest_count,
            'historical_mean': round(m, 2),
            'z_score': round(z, 2) if z is not None else None,
            'description': (
                f"{latest_count} item(s) from {group} on {latest_day.isoformat()} vs a "
                f"historical daily average of {round(m, 2)} across {len(history)} prior day(s) — "
                + (f"{round(z, 2)} standard deviations above normal."
                   if z is not None else "no prior variance in this group, a clean break from baseline.")
            ),
        })

    anomalies.sort(key=lambda a: (a['z_score'] is not None, a['z_score'] or 0), reverse=True)
    return anomalies


def _timing_anomalies(events, label, unit_noun):
    by_entity = defaultdict(list)
    for ev in events:
        by_entity[ev['entity_value']].append(ev)

    anomalies = []
    for entity, group_events in by_entity.items():
        if len(group_events) < MIN_HOUR_HISTORY:
            continue
        ordered = sorted(group_events, key=lambda e: e['timestamp'])
        history, latest = ordered[:-1], ordered[-1]

        hour_counts = defaultdict(int)
        for ev in history:
            hour_counts[ev['timestamp'].hour] += 1
        total = len(history)
        latest_hour = latest['timestamp'].hour
        freq = hour_counts.get(latest_hour, 0) / total

        if freq <= 0.1:
            anomalies.append({
                'type': label,
                'group': entity,
                'source_type': latest['source_type'],
                'source_ref': latest['source_ref'],
                'hour': latest_hour,
                'historical_frequency_pct': round(freq * 100, 1),
                'description': (
                    f"{entity} rarely {unit_noun} around {latest_hour:02d}:00 — only "
                    f"{round(freq * 100, 1)}% of its {total} prior item(s) did — but "
                    f"{latest['source_ref']} arrived at {latest_hour:02d}:00."
                ),
            })
    return anomalies


def detect_anomalies(cases, evidence_items=None):
    """cases: Case rows. evidence_items: Evidence rows (optional, defaults
    to none for callers that only have cases). Returns the same shape as
    before (volume_by_domain / volume_by_country / timing) plus a new
    volume_by_phone and phone entries folded into timing -- so an Evidence-
    only pattern (e.g. the same phone number spamming several chat/SMS
    uploads in one day) can trigger an anomaly on its own, with no case
    involved at all."""
    evidence_items = evidence_items or []

    domain_events = _case_domain_events(cases)
    country_events = _case_country_events(cases)
    phone_events = _evidence_phone_events(evidence_items)

    return {
        'volume_by_domain': _volume_anomalies(domain_events, 'domain'),
        'volume_by_country': _volume_anomalies(country_events, 'country'),
        'volume_by_phone': _volume_anomalies(phone_events, 'phone number'),
        'timing': (
            _timing_anomalies(domain_events, 'Unusual sending time', 'sends')
            + _timing_anomalies(phone_events, 'Unusual upload time', 'appears in uploads')
        ),
    }