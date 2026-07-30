import streamlit as st
from datetime import datetime, timedelta

# Force these to init before plotly to avoid circular-import races
import numpy as np
import pandas as pd

import plotly.graph_objects as go
from database.database import (
    get_dashboard_stats, get_recent_incidents, get_response_metrics,
    get_threat_timeline
)
from components.attack_map import render_attack_map
from components.sidebar import render_sidebar
from config import (
    APP_NAME, COLORS, SEVERITY_COLORS, STATUS_COLORS, CATEGORY_COLORS,
    SEVERITY_WEIGHTS, DASHBOARD_REFRESH_INTERVAL
)
from components.styles import inject_base_styles, render_page_header, render_topbar, clean_html
from services.geo_service import backfill_unknown_geo

st.set_page_config(
    page_title            = APP_NAME,
    layout                = "wide",
    initial_sidebar_state = "expanded",
)


# HELPERS

_ACTIVE_STATUSES = ("Open", "Investigating", "Active")


def _active_count(stats):
    return sum(stats.get("status_counts", {}).get(s, 0) for s in _ACTIVE_STATUSES)





def _compute_risk_score(stats):
    sev = stats.get("severity_counts", {})
    weights = SEVERITY_WEIGHTS or {}
    numerator = sum(sev.get(k, 0) * weights.get(k, 0) for k in sev)
    total = sum(sev.values())
    if total == 0:
        return 0.0, "no signal"
    max_w = max(weights.values()) if weights else 1
    raw = numerator / (total * max_w) * 10
    score = round(raw, 1)
    if score >= 7:
        label = "elevated"
    elif score >= 4:
        label = "moderate"
    else:
        label = "low"
    return score, label


def _risk_color(score):
    if score >= 7:
        return COLORS["critical"]
    if score >= 4:
        return COLORS["high"]
    if score > 0:
        return COLORS["medium"]
    return COLORS["text_muted"]


# SPARKLINE (inline SVG, no axes)

def _sparkline_svg(trend, color):
    points = [(t["hour"], t["count"]) for t in trend or []]
    if len(points) < 2:
        return ""
    w, h = 84, 28
    pad  = 1.5
    counts = [c for _, c in points]
    cmin, cmax = min(counts), max(counts)
    rng = max(cmax - cmin, 1)
    step = (w - pad * 2) / (len(points) - 1)

    coords = []
    for i, (_, c) in enumerate(points):
        x = pad + i * step
        y = h - pad - ((c - cmin) / rng) * (h - pad * 2)
        coords.append((x, y))

    line_d = " ".join(f"{('M' if i == 0 else 'L')} {x:.1f} {y:.1f}" for i, (x, y) in enumerate(coords))
    area_d = (
        f"M {coords[0][0]:.1f} {h:.1f} "
        + " ".join(f"L {x:.1f} {y:.1f}" for x, y in coords)
        + f" L {coords[-1][0]:.1f} {h:.1f} Z"
    )
    last_x, last_y = coords[-1]
    return (
        f'<svg class="kpi-spark" viewBox="0 0 {w} {h}" preserveAspectRatio="none">'
        f'<path d="{area_d}" fill="{color}" opacity="0.16"></path>'
        f'<path d="{line_d}" stroke="{color}" stroke-width="1.4" fill="none" stroke-linecap="round" stroke-linejoin="round"></path>'
        f'<circle cx="{last_x:.1f}" cy="{last_y:.1f}" r="2" fill="{color}"></circle>'
        f'</svg>'
    )


# KPI STRIP — 4 equal cards

def render_kpi_strip(stats):
    active    = _active_count(stats)
    last_hour = stats.get("threats_last_hour", 0)
    avg_conf  = stats.get("avg_confidence", 0) or 0
    total     = stats.get("total", 0)
    last_24h  = stats.get("threats_last_24h", 0)
    risk_score, risk_label = _compute_risk_score(stats)

    col1, col2, col3, col4 = st.columns(4, gap="small")

    with col1:
        spark = _sparkline_svg(stats.get("hourly_trend", []), COLORS["accent_blue"])
        delta = (
            f'<span style="color:{COLORS["high"]};font-weight:600;">&#8593; {last_hour}</span>'
            if last_hour > 0
            else f'<span style="color:{COLORS["text_muted"]};font-weight:600;">&#8594; 0</span>'
        )
        meta = f'{delta} &nbsp;<span style="color:{COLORS["text_muted"]};">in last hour</span>'
        st.markdown(clean_html(f"""
            <div class="kpi-card">
                {spark}
                <div class="kpi-eyebrow">Active Threats</div>
                <div class="kpi-value">{active}<span class="kpi-suffix">incidents</span></div>
                <div class="kpi-meta">{meta}</div>
            </div>
        """), unsafe_allow_html=True)

    with col2:
        meta = f'{last_24h} in last 24h' if last_24h else 'no incidents'
        st.markdown(clean_html(f"""
            <div class="kpi-card">
                <div class="kpi-eyebrow">Total Incidents</div>
                <div class="kpi-value">{total}<span class="kpi-suffix">total</span></div>
                <div class="kpi-meta">{meta}</div>
            </div>
        """), unsafe_allow_html=True)

    with col3:
        conf_pct = f"{avg_conf * 100:.1f}%" if avg_conf else "—"
        fill_pct = min(avg_conf * 100, 100) if avg_conf else 0
        target   = 90
        conf_color = COLORS["mitigated"] if avg_conf and avg_conf * 100 >= target else COLORS["medium"]
        st.markdown(clean_html(f"""
            <div class="kpi-card">
                <div class="kpi-eyebrow">Detection Confidence</div>
                <div class="kpi-value kpi-value-sm">{conf_pct}</div>
                <div class="gauge">
                    <div class="gauge-fill" style="width:{fill_pct:.1f}%; background:{conf_color};"></div>
                    <div class="gauge-band" style="left:{target}%;"></div>
                </div>
                <div class="gauge-labels">
                    <span>0</span>
                    <span>target 90%</span>
                    <span>100</span>
                </div>
            </div>
        """), unsafe_allow_html=True)

    with col4:
        fill_pct = min(risk_score * 10, 100)
        r_color  = _risk_color(risk_score)
        st.markdown(clean_html(f"""
            <div class="kpi-card">
                <div class="kpi-eyebrow">Risk Score</div>
                <div class="kpi-value kpi-value-sm">{risk_score}<span class="kpi-suffix">/ 10</span></div>
                <div class="gauge">
                    <div class="gauge-fill" style="width:{fill_pct:.1f}%; background:{r_color};"></div>
                    <div class="gauge-band" style="left:40%;"></div>
                    <div class="gauge-band" style="left:70%;"></div>
                </div>
                <div class="gauge-labels">
                    <span>low</span>
                    <span>moderate</span>
                    <span>elevated</span>
                </div>
            </div>
        """), unsafe_allow_html=True)


# 24H THREAT VOLUME — STACKED AREA BY CATEGORY

def render_threat_timeline_chart():
    timeline = get_threat_timeline(hours=24)

    if not timeline:
        st.markdown(clean_html(f"""
            <div class="panel" style="text-align:center; padding:40px 20px;">
                <p class="section-label" style="margin:0;">24h Threat Volume</p>
                <p style="color:{COLORS['text_muted']};font-size:13px;margin-top:12px;">
                    No threat activity in the last 24 hours
                </p>
            </div>
        """), unsafe_allow_html=True)
        return

    by_cat = {}
    for row in timeline:
        cat = row["threat_category"]
        ts  = datetime.strptime(row["bucket"], "%Y-%m-%d %H:%M:%S")
        by_cat.setdefault(cat, {})[ts] = row["count"]

    EPS = timedelta(seconds=25)   # half-width of each spike; keeps spikes ~50s wide and visible
    GAP = timedelta(seconds=20)   # consecutive 60s buckets always get bracket zeros

    fig = go.Figure()
    for category in sorted(by_cat.keys(), key=lambda c: -sum(by_cat[c].values())):
        sorted_pts = sorted(by_cat[category].items())
        xs, ys = [], []
        for i, (ts, cnt) in enumerate(sorted_pts):
            if i == 0 or sorted_pts[i - 1][0] < ts - GAP:
                xs.append(ts - EPS)
                ys.append(0)
            xs.append(ts)
            ys.append(cnt)
            if i == len(sorted_pts) - 1 or sorted_pts[i + 1][0] > ts + GAP:
                xs.append(ts + EPS)
                ys.append(0)

        color = CATEGORY_COLORS.get(category, COLORS["accent_blue"])
        fig.add_trace(go.Scatter(
            x             = xs,
            y             = ys,
            name          = category,
            mode          = "lines",
            stackgroup    = "one",
            line          = dict(width=1.2, color=color, shape="linear"),
            fillcolor     = color,
            opacity       = 0.78,
            hovertemplate = f"<b>{category}</b><br>%{{x}}<br>%{{y}} incidents<extra></extra>",
        ))

    fig.update_layout(
        paper_bgcolor = COLORS["bg_secondary"],
        plot_bgcolor  = COLORS["bg_secondary"],
        uirevision    = "threat-timeline",
        height        = 280,
        title         = dict(
            text    = "24h Threat Volume",
            font    = dict(size=13, color=COLORS["text_secondary"], family="Inter, sans-serif"),
            x       = 0,
            xanchor = "left",
            pad     = dict(l=4, t=2),
        ),
        margin     = dict(l=0, r=0, t=34, b=70),
        hovermode  = "x unified",
        showlegend = True,
        legend     = dict(
            orientation = "h",
            yanchor     = "top",
            y           = -0.22,
            xanchor     = "left",
            x           = 0,
            font        = dict(size=10.5, color=COLORS["text_secondary"], family="Inter, sans-serif"),
            bgcolor     = "rgba(0,0,0,0)",
        ),
        xaxis = dict(
            showgrid   = False,
            showline   = False,
            showspikes = False,
            ticks      = "",
            tickfont   = dict(size=9, color=COLORS["text_muted"], family="JetBrains Mono, monospace"),
            tickformat = "%H:%M",
            dtick      = 60000,
            tickmode   = "linear",
        ),
        yaxis = dict(
            showgrid  = True,
            gridcolor = COLORS.get("border", "#E7EBF0"),
            gridwidth = 1,
            zeroline  = False,
            showline  = False,
            ticks     = "",
            tickfont  = dict(size=10, color=COLORS["text_muted"]),
            rangemode = "tozero",
        ),
    )
    st.plotly_chart(fig, use_container_width=True, key="threat-timeline-chart", config={
        "displayModeBar": False,
        "scrollZoom": False,
    })


# TOP COUNTRIES — horizontal bar list

def render_top_countries(stats):
    entries = stats.get("top_countries") or []
    max_count = max((e.get("count", 0) for e in entries), default=0)

    header = (
        f'<p class="section-label">Top Countries'
        f'<span style="font-weight:500;color:{COLORS["text_muted"]};margin-left:8px;font-size:11px;">'
        f'last 24h</span></p>'
    )

    if not entries:
        st.markdown(clean_html(f"""
            <div class="panel">
                {header}
                <p style="color:{COLORS['text_muted']};font-size:13px;text-align:center;padding:20px 0;">
                    No country data
                </p>
            </div>
        """), unsafe_allow_html=True)
        return

    sev_map = {5: "Critical", 4: "High", 3: "Medium", 2: "Low", 1: "Info"}

    rows = ""
    for entry in entries[:5]:
        country = entry.get("country", "—")
        count   = entry.get("count", 0)
        sw      = entry.get("severity_weight", 1)
        sev     = sev_map.get(sw, "Info")
        color   = SEVERITY_COLORS.get(sev, COLORS["info"])
        width   = (count / max_count * 100) if max_count else 0
        rows += f"""
            <div class="ip-row">
                <span class="ip-sev-dot" style="background:{color};"></span>
                <span class="ip-addr">{country}</span>
                <span class="ip-bar">
                    <span class="ip-bar-fill" style="width:{width:.1f}%; background:{color}; opacity:0.55;"></span>
                </span>
                <span class="ip-count">{count}</span>
            </div>
        """

    st.markdown(clean_html(f"""
        <div class="panel">
            {header}
            <div class="ip-list">{rows}</div>
        </div>
    """), unsafe_allow_html=True)


# SEVERITY BREAKDOWN — single horizontal stacked strip

def render_severity_breakdown(stats):
    sev_counts = stats.get("severity_counts", {}) or {}
    order      = ["Critical", "High", "Medium", "Low", "Info"]
    total      = sum(sev_counts.values())

    if total == 0:
        st.markdown(clean_html(f"""
            <div class="panel">
                <p class="section-label">Severity Breakdown</p>
                <p style="color:{COLORS['text_muted']};font-size:13px;text-align:center;padding:20px 0;">
                    No severity data
                </p>
            </div>
        """), unsafe_allow_html=True)
        return

    segments = ""
    for sev in order:
        count = sev_counts.get(sev, 0)
        if count == 0:
            continue
        pct = (count / total) * 100
        color = SEVERITY_COLORS.get(sev, COLORS["info"])
        segments += f'<span class="sev-seg" style="width:{pct:.2f}%;background:{color};" title="{sev}: {count}"></span>'

    legend = ""
    for sev in order:
        count = sev_counts.get(sev, 0)
        if count == 0:
            continue
        color   = SEVERITY_COLORS.get(sev, COLORS["info"])
        pct_str = f"{(count / total) * 100:.0f}%"
        legend += f"""
            <div class="sev-legend-row">
                <div class="sev-legend-left">
                    <span class="sev-legend-swatch" style="background:{color};"></span>{sev}
                </div>
                <div>
                    <span class="sev-legend-value">{count}</span>
                    <span style="color:{COLORS['text_muted']};font-size:11px;margin-left:5px;">{pct_str}</span>
                </div>
            </div>
        """

    st.markdown(clean_html(f"""
        <div class="panel">
            <p class="section-label">Severity Breakdown</p>
            <div class="sev-strip">{segments}</div>
            <div class="sev-legend">{legend}</div>
        </div>
    """), unsafe_allow_html=True)


# ATTACK PROFILE — polar bar chart by category

def render_category_radar(stats):
    category_counts = {k: v for k, v in (stats.get("category_counts") or {}).items() if k != "Normal"}

    if not category_counts:
        st.markdown(clean_html(f"""
            <div class="panel" style="text-align:center; padding:40px 20px;">
                <p style="color:{COLORS['text_muted']};font-size:13px;margin:0;">No category data</p>
            </div>
        """), unsafe_allow_html=True)
        return

    short_name = {
        "Brute Force":          "Brute Force",
        "SQL Injection":        "SQL Inj.",
        "Port Scan":            "Port Scan",
        "Malware Upload":       "Malware",
        "Privilege Escalation": "Priv. Esc.",
        "Unauthorized Access":  "Unauth.",
    }

    cats   = list(category_counts.keys())
    counts = list(category_counts.values())
    colors = [CATEGORY_COLORS.get(c, COLORS["accent_blue"]) for c in cats]
    labels = [short_name.get(c, c) for c in cats]

    fig = go.Figure()
    fig.add_trace(go.Barpolar(
        r             = counts,
        theta         = labels,
        marker        = dict(
            color = colors,
            line  = dict(color="rgba(255,255,255,0.25)", width=0.8),
        ),
        opacity       = 0.82,
        hovertemplate = "<b>%{theta}</b><br>%{r} incidents<extra></extra>",
    ))

    fig.update_layout(
        polar = dict(
            radialaxis  = dict(
                visible        = True,
                showticklabels = False,
                showgrid       = True,
                gridcolor      = COLORS["border"],
                gridwidth      = 1,
                layer          = "below traces",
            ),
            angularaxis = dict(
                tickfont  = dict(size=9.5, color=COLORS["text_secondary"], family="Inter, sans-serif"),
                gridcolor = COLORS["border"],
                linecolor = COLORS["border"],
            ),
            bgcolor = COLORS["bg_secondary"],
        ),
        paper_bgcolor = COLORS["bg_secondary"],
        uirevision    = "category-radar",
        showlegend    = False,
        height        = 255,
        margin        = dict(l=16, r=16, t=42, b=8),
        title         = dict(
            text    = "Attack Profile",
            font    = dict(size=13, color=COLORS["text_secondary"], family="Inter, sans-serif"),
            x       = 0,
            xanchor = "left",
            pad     = dict(l=4, t=2),
        ),
    )

    st.plotly_chart(fig, use_container_width=True, config={"displayModeBar": False})


# RECENT THREATS TABLE

def _time_part(ts):
    return ts.split(" ")[-1] if ts and " " in ts else ts


def render_threats_table(limit=8, query=""):
    incidents = get_recent_incidents(hours=72, limit=limit)

    if query:
        q = query.lower()
        incidents = [
            inc for inc in incidents
            if q in (inc.get("threat_category") or "").lower()
            or q in (inc.get("source_ip")       or "").lower()
            or q in (inc.get("country")          or "").lower()
            or q in (inc.get("status")           or "").lower()
            or q in (inc.get("severity")         or "").lower()
        ]

    title_suffix = (
        f'<span style="font-size:12px; font-weight:500; color:{COLORS["accent_blue"]};">'
        f'&nbsp;- &ldquo;{query}&rdquo;</span>'
        if query else
        f'<span style="font-size:12px; font-weight:500; color:{COLORS["text_muted"]};">Last 72 hours</span>'
    )

    rows = ""
    if not incidents:
        rows = (f"<tr><td colspan='5' style='text-align:center; color:{COLORS['text_muted']}; "
                f"padding:40px;'>{'No matches found' if query else 'No threats detected'}</td></tr>")
    for inc in incidents:
        severity = inc.get("severity", "Info")
        category = inc.get("threat_category", "Unknown")
        ip       = inc.get("source_ip", "Unknown")
        country  = inc.get("country", "Unknown")
        status   = inc.get("status", "Open")
        ts       = _time_part(inc.get("timestamp", ""))
        sev_c    = SEVERITY_COLORS.get(severity, COLORS["info"])
        sc       = STATUS_COLORS.get(status, {"fg": COLORS["text_secondary"], "bg": COLORS["bg_tertiary"]})
        origin   = country if country not in ("Unknown", "Internal") else "Internal"

        rows += f"""
            <tr>
                <td>
                    <div style="display:flex; align-items:center; gap:9px;">
                        <span class="stat-dot" style="background:{sev_c};"></span>
                        <span style="font-weight:500;">{category}</span>
                    </div>
                </td>
                <td class="mono" style="color:{COLORS['text_secondary']};">{ip}</td>
                <td style="color:{COLORS['text_secondary']};">{origin}</td>
                <td class="mono" style="color:{COLORS['text_muted']};">{ts}</td>
                <td>
                    <span class="pill" style="color:{sc['fg']}; background:{sc['bg']};">
                        <span class="pdot" style="background:{sc['fg']};"></span>{status}
                    </span>
                </td>
            </tr>
        """

    st.markdown(clean_html(f"""
        <div class="panel">
            <p class="panel-title">Recent Threats {title_suffix}
            </p>
            <table class="dt">
                <thead><tr>
                    <th>Threat</th><th>Source IP</th><th>Origin</th><th>Time</th><th>Status</th>
                </tr></thead>
                <tbody>{rows}</tbody>
            </table>
        </div>
    """), unsafe_allow_html=True)


# MAIN

@st.fragment(run_every=DASHBOARD_REFRESH_INTERVAL)
def render_live_content():
    backfill_unknown_geo()
    stats    = get_dashboard_stats()
    response = get_response_metrics()

    render_kpi_strip(stats)

    st.markdown("<div style='margin-top:16px;'></div>", unsafe_allow_html=True)

    row2_l, row2_r = st.columns([2, 1], gap="small")
    with row2_l:
        render_threat_timeline_chart()
    with row2_r:
        render_top_countries(stats)

    st.markdown("<div style='margin-top:16px;'></div>", unsafe_allow_html=True)

    query = st.text_input(
        "threat_search",
        value="",
        placeholder="Search threats by category, IP, country, status...",
        key="threat_search",
        label_visibility="collapsed",
    )

    row3_l, row3_r = st.columns([2, 1], gap="small")
    with row3_l:
        render_threats_table(limit=50, query=query)
    with row3_r:
        render_severity_breakdown(stats)
        st.markdown("<div style='margin-top:12px;'></div>", unsafe_allow_html=True)
        render_category_radar(stats)

    st.markdown("<div style='margin-top:16px;'></div>", unsafe_allow_html=True)

    render_attack_map()


def main():
    inject_base_styles()
    render_sidebar()
    render_topbar(show_search=False)
    render_page_header(
        "Threats",
        "Monitor and manage security threats across your network",
    )
    render_live_content()


if __name__ == "__main__":
    main()
