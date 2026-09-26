"""
Cross-case anomaly detection. Everything else in the pipeline scores
ONE email in isolation; nothing looks across an analyst's whole case
history for statistical outliers. Two independent, dependency-free
checks:

1. Volume-spike detection -- per sender domain / country, is the most
   recent day's case count a statistical outlier against that group's
   OWN historical daily mean (z-score), not a fixed global threshold?
2. Unusual sending-time detection -- does a case arrive in an hour-of-day
   bucket that's rare in its sender domain's own historical distribution?

Deliberately simple (mean/stdev, not isolation forest) so it runs
instantly on a hackathon-scale dataset (dozens of cases, not millions)
and stays explainable: "N standard deviations above its own historical
mean" is a real, checkable number, not a black box.
"""
from collections import defaultdict
from statistics import mean, pstdev

# Hackathon-scale datasets rarely produce a clean textbook 2-3 sigma
# signal, so the bar is set a little lower than the usual "outlier"
# convention -- tune upward once there's more real traffic to test against.
Z_SCORE_THRESHOLD = 1.8
MIN_GROUP_DAYS = 3     # need this many distinct days of history in a group first
MIN_HOUR_HISTORY = 5   # need this many prior cases from a domain before an
                        # "unusual hour" flag means anything


def _group_key(case, by):
    if by == 'domain':
        return case.sender_domain or None
    if by == 'country':
        return case.country or None
    return 'all'


def detect_volume_anomalies(cases, by='domain'):
    """Per-group (sender domain or country) daily case counts; flags the
    most recent day for a group when it's Z_SCORE_THRESHOLD standard
    deviations above that SAME group's own historical daily mean."""
    daily_counts = defaultdict(lambda: defaultdict(int))
    for c in cases:
        if not c.created_at:
            continue
        group = _group_key(c, by)
        if not group:
            continue
        daily_counts[group][c.created_at.date()] += 1

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
            'type': f'Volume spike ({by})',
            'group': group,
            'date': latest_day.isoformat(),
            'count': latest_count,
            'historical_mean': round(m, 2),
            'z_score': round(z, 2) if z is not None else None,
            'description': (
                f"{latest_count} case(s) from {group} on {latest_day.isoformat()} vs a "
                f"historical daily average of {round(m, 2)} across {len(history)} prior day(s) — "
                + (f"{round(z, 2)} standard deviations above normal."
                   if z is not None else "no prior variance in this group, a clean break from baseline.")
            ),
        })

    # Strongest (highest z-score) first; the no-variance "clean break"
    # cases (z_score None) sort after every measured one.
    anomalies.sort(key=lambda a: (a['z_score'] is not None, a['z_score'] or 0), reverse=True)
    return anomalies


def detect_timing_anomalies(cases):
    """Per sender domain, flags the most recent case if its arrival hour
    is rare (<=10%) in that domain's own prior hour-of-day distribution."""
    by_domain = defaultdict(list)
    for c in cases:
        if c.sender_domain and c.created_at:
            by_domain[c.sender_domain].append(c)

    anomalies = []
    for domain, group_cases in by_domain.items():
        if len(group_cases) < MIN_HOUR_HISTORY:
            continue
        ordered = sorted(group_cases, key=lambda c: c.created_at)
        history, latest = ordered[:-1], ordered[-1]

        hour_counts = defaultdict(int)
        for c in history:
            hour_counts[c.created_at.hour] += 1
        total = len(history)
        latest_hour = latest.created_at.hour
        freq = hour_counts.get(latest_hour, 0) / total

        if freq <= 0.1:
            anomalies.append({
                'type': 'Unusual sending time',
                'group': domain,
                'case_ref': latest.case_ref,
                'hour': latest_hour,
                'historical_frequency_pct': round(freq * 100, 1),
                'description': (
                    f"{domain} rarely sends around {latest_hour:02d}:00 — only "
                    f"{round(freq * 100, 1)}% of its {total} prior email(s) did — but case "
                    f"{latest.case_ref} arrived at {latest_hour:02d}:00."
                ),
            })
    return anomalies


def detect_anomalies(cases):
    return {
        'volume_by_domain': detect_volume_anomalies(cases, by='domain'),
        'volume_by_country': detect_volume_anomalies(cases, by='country'),
        'timing': detect_timing_anomalies(cases),
    }