import os, sys, io
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

import pandas as pd
import numpy as np
import dash
from dash import dcc, html, dash_table, Input, Output, State
import plotly.express as px
from reportlab.lib.pagesizes import A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib import colors

from ingest import load_logs, build_alerts

# ---------- Load logs & build alerts ----------
auth, web, fw = load_logs("data")
ALERTS = build_alerts(auth, web, fw)

def filter_time(df: pd.DataFrame, hours):
    if hours is None:
        return df
    end = df['timestamp'].max()
    start = end - pd.Timedelta(hours=hours)
    return df[(df['timestamp'] >= start) & (df['timestamp'] <= end)]

def kpi_card(title, value):
    return html.Div([
        html.Div(title, className="kpi-title"),
        html.Div(value, className="kpi-value")
    ], style={
        "background":"#0d1117","border":"1px solid #30363d","padding":"14px 16px",
        "borderRadius":"12px","color":"#e6edf3","boxShadow":"0 2px 10px rgba(0,0,0,0.25)"
    })

app = dash.Dash(__name__, title="AegisEye — Threat Visualizer")
server = app.server

app.layout = html.Div(style={"background":"#0b0f14","minHeight":"100vh","padding":"20px"}, children=[

    # Header
    html.Div([
        html.Div("AegisEye — Threat Visualizer", style={"fontSize":"24px","fontWeight":"700","color":"#e6edf3"}),
        html.Div("Business-grade SOC dashboard (demo)", style={"color":"#9da7b3"})
    ], style={"marginBottom":"16px"}),

    # Controls & Downloads
    html.Div([
        html.Label("Time window:", style={"color":"#9da7b3","marginRight":"8px"}),
        dcc.Dropdown(
            id="time-window",
            options=[
                {"label":"Last 1 hour","value":1},
                {"label":"Last 6 hours","value":6},
                {"label":"Last 24 hours","value":24},
                {"label":"All","value":None},
            ],
            value=24, clearable=False, style={"width":"220px","color":"#111","marginRight":"16px"}
        ),
        html.Button("⬇ Download CSV", id="btn-csv", n_clicks=0, style={"marginRight":"8px"}),
        dcc.Download(id="download-csv"),
        html.Button("⬇ Download PDF", id="btn-pdf", n_clicks=0),
        dcc.Download(id="download-pdf"),
    ], style={"marginBottom":"14px","display":"flex","alignItems":"center","gap":"8px"}),

    # KPIs
    html.Div(id="kpi-row", style={"display":"grid","gridTemplateColumns":"repeat(4, 1fr)","gap":"12px"}),

    # Charts row 1: timeline + types
    html.Div(style={"display":"grid","gridTemplateColumns":"2fr 1.4fr","gap":"12px","marginTop":"12px"}, children=[
        dcc.Graph(id="alerts-timeline", config={"displayModeBar":False}, style={"height":"360px","background":"#0b0f14"}),
        dcc.Graph(id="alert-types", config={"displayModeBar":False}, style={"height":"360px","background":"#0b0f14"}),
    ]),

    # Charts row 2: top IPs + heatmap
    html.Div(style={"display":"grid","gridTemplateColumns":"1.4fr 2fr","gap":"12px","marginTop":"12px"}, children=[
        dcc.Graph(id="top-ips", config={"displayModeBar":False}, style={"height":"360px","background":"#0b0f14"}),
        dcc.Graph(id="hour-heatmap", config={"displayModeBar":False}, style={"height":"360px","background":"#0b0f14"}),
    ]),

    # Country map
    html.Div(style={"marginTop":"12px"}, children=[
        dcc.Graph(id="country-map", config={"displayModeBar":False}, style={"height":"420px","background":"#0b0f14"})
    ]),

    # Alerts table
    html.Div([
        html.Div("Latest Alerts (click a row to view details)", style={"color":"#e6edf3","fontWeight":"600","margin":"12px 0 6px"}),
        dash_table.DataTable(
            id="alerts-table",
            style_header={"backgroundColor":"#161b22","color":"#9da7b3","border":"0"},
            style_cell={"backgroundColor":"#0d1117","color":"#e6edf3","border":"0","fontSize":"13px"},
            page_size=10, sort_action="native",
            row_selectable="single",
            columns=[
                {"name":"time","id":"timestamp"},
                {"name":"type","id":"type"},
                {"name":"severity","id":"severity"},
                {"name":"src_ip","id":"src_ip"},
                {"name":"country","id":"country_name"},
                {"name":"user","id":"user"},
                {"name":"context","id":"context"},
            ],
        )
    ], style={"marginTop":"10px"}),

    # Details drawer
    html.Div(id="details-panel", style={
        "position":"fixed","right":"20px","bottom":"20px","width":"520px",
        "maxHeight":"70vh","overflowY":"auto","background":"#0d1117",
        "border":"1px solid #30363d","borderRadius":"12px","padding":"16px",
        "boxShadow":"0 8px 24px rgba(0,0,0,0.45)","display":"none","zIndex":"1000"
    }, children=[
        html.Div([
            html.Div("Alert Details", style={"color":"#e6edf3","fontWeight":"700","fontSize":"16px"}),
            html.Button("✕", id="close-details", n_clicks=0,
                        style={"float":"right","background":"transparent","color":"#9da7b3","border":"0","cursor":"pointer"})
        ], style={"marginBottom":"8px","overflow":"hidden"}),
        html.Div(id="details-content", style={"color":"#e6edf3","fontSize":"13px"})
    ]),
])

# ---------- Main dashboard update ----------
@app.callback(
    Output("kpi-row","children"),
    Output("alerts-timeline","figure"),
    Output("alert-types","figure"),
    Output("top-ips","figure"),
    Output("hour-heatmap","figure"),
    Output("country-map","figure"),
    Output("alerts-table","data"),
    Input("time-window","value")
)
def update_dashboard(hours):
    df = filter_time(ALERTS, hours)

    # KPIs
    total = len(df)
    high = (df['severity']=="High").sum()
    unique_ips = df['src_ip'].replace("", np.nan).dropna().nunique()
    last_type = df.iloc[-1]['type'] if not df.empty else "None"
    kpis = [
        kpi_card("Total Alerts", f"{total}"),
        kpi_card("High Severity", f"{high}"),
        kpi_card("Unique Source IPs", f"{unique_ips}"),
        kpi_card("Last Alert Type", f"{last_type}")
    ]

    # Timeline
    if not df.empty:
        ts = (df.set_index('timestamp').resample('1h').size().rename('alerts').reset_index())
        fig_tl = px.area(ts, x="timestamp", y="alerts", title="Alerts over time")
    else:
        fig_tl = px.area(pd.DataFrame({"timestamp":[],"alerts":[]}), x="timestamp", y="alerts", title="Alerts over time")

    # Types donut
    typ = df['type'].value_counts().reset_index()
    typ.columns = ['type','count']
    fig_types = px.pie(typ, names="type", values="count", hole=0.55, title="Alert types")

    # Top IPs
    if 'src_ip' in df and not df.empty:
        ip = (df[df['src_ip']!=""].groupby('src_ip').size().reset_index(name='alerts')
              .sort_values('alerts', ascending=False).head(15))
    else:
        ip = pd.DataFrame({"src_ip":[],"alerts":[]})
    fig_ips = px.bar(ip, x="alerts", y="src_ip", orientation="h", title="Top source IPs (by alerts)")

    # Heatmap hour × type
    if not df.empty:
        tmp = df.copy()
        tmp['hour'] = tmp['timestamp'].dt.hour
        piv = tmp.pivot_table(index='hour', columns='type', values='severity', aggfunc='count', fill_value=0)
        fig_hm = px.imshow(piv, aspect='auto', title="Alert density by hour × type")
    else:
        fig_hm = px.imshow(np.zeros((1,1)), title="Alert density by hour × type")
 
    # Country map (ISO3)
    if not df.empty and 'country_iso3' in df.columns:
        c = df[df['country_iso3'].notna() & (df['country_iso3']!="")].groupby('country_iso3').size().reset_index(name='alerts')
        fig_map = px.choropleth(c, locations="country_iso3", color="alerts",
                                color_continuous_scale="Reds", title="Alert sources by country (demo GeoIP)")
    else:
        fig_map = px.choropleth(pd.DataFrame({"country_iso3":[],"alerts":[]}), locations="country_iso3", color="alerts", title="Alert sources by country")
    # Styling
    for f in (fig_tl, fig_types, fig_ips, fig_hm, fig_map):
        f.update_layout(margin=dict(l=10,r=10,t=40,b=10),
                        paper_bgcolor="#0b0f14", plot_bgcolor="#0b0f14", font_color="#e6edf3")

    table_data = df.sort_values('timestamp', ascending=False).head(200).to_dict('records')
    return kpis, fig_tl, fig_types, fig_ips, fig_hm, fig_map, table_data

# ---------- CSV export ----------
@app.callback(
    Output("download-csv","data"),
    Input("btn-csv","n_clicks"),
    State("time-window","value"),
    prevent_initial_call=True
)
def download_csv(n, hours):
    df = filter_time(ALERTS, hours)
    return dcc.send_data_frame(df.to_csv, f"aegiseye_alerts_{hours or 'all'}h.csv", index=False)

# ---------- PDF export ----------
@app.callback(
    Output("download-pdf","data"),
    Input("btn-pdf","n_clicks"),
    State("time-window","value"),
    prevent_initial_call=True
)
def download_pdf(n, hours):
    df = filter_time(ALERTS, hours)
    buf = io.BytesIO()
    styles = getSampleStyleSheet()
    doc = SimpleDocTemplate(buf, pagesize=A4, title="AegisEye Report")

    story = [
        Paragraph("<b>AegisEye — Threat Report</b>", styles['Title']),
        Spacer(1, 8),
        Paragraph(f"Time window: {hours or 'All'} hours", styles['Normal']),
        Spacer(1, 10),
    ]

    total = len(df)
    high = int((df['severity'] == "High").sum()) if not df.empty else 0
    unique_ips = int(df['src_ip'].replace("", np.nan).dropna().nunique()) if not df.empty else 0

    kpitable = Table(
        [["Total Alerts", total],
         ["High Severity", high],
         ["Unique Source IPs", unique_ips]],
        colWidths=[200, 200]
    )
    kpitable.setStyle(TableStyle([
        ("BOX", (0,0), (-1,-1), 0.5, colors.black),
        ("INNERGRID", (0,0), (-1,-1), 0.25, colors.gray),
        ("BACKGROUND", (0,0), (-1,0), colors.whitesmoke),
    ]))
    story += [kpitable, Spacer(1, 10)]

    # Top IPs table
    if not df.empty:
        ip = (df[df['src_ip'] != ""]
              .groupby('src_ip')
              .size()
              .reset_index(name='alerts')
              .sort_values('alerts', ascending=False)
              .head(10))
        iprows = [["Source IP", "Alerts"]] + ip.values.tolist()
        iptable = Table(iprows, colWidths=[250, 150])
        iptable.setStyle(TableStyle([
            ("BOX", (0,0), (-1,-1), 0.5, colors.black),
            ("BACKGROUND", (0,0), (-1,0), colors.whitesmoke),
        ]))
        story += [Paragraph("<b>Top Source IPs</b>", styles['Heading3']),
                  Spacer(1, 4), iptable, Spacer(1, 10)]

    # Recent alerts
    recent = df.sort_values('timestamp', ascending=False).head(15)
    if not recent.empty:
        rows = [["Time","Type","Severity","IP","Country","User","Context"]]
        for _, r in recent.iterrows():
            rows.append([
                str(r.get("timestamp","")),
                r.get("type",""),
                r.get("severity",""),
                r.get("src_ip",""),
                r.get("country_name",""),
                r.get("user","") or "",
                r.get("context","")[:80],
            ])
        rtable = Table(rows, colWidths=[80,80,60,80,80,60,160])
        rtable.setStyle(TableStyle([
            ("BOX", (0,0), (-1,-1), 0.5, colors.black),
            ("BACKGROUND", (0,0), (-1,0), colors.whitesmoke),
            ("FONTSIZE", (0,0), (-1,-1), 8),
        ]))
        story += [Paragraph("<b>Recent Alerts</b>", styles['Heading3']),
                  Spacer(1, 4), rtable]

    doc.build(story)
    buf.seek(0)
    return dcc.send_bytes(buf.getvalue(), f"aegiseye_report_{hours or 'all'}h.pdf")



# ---------- Details drawer (row click) ----------
@app.callback(
    Output("details-panel","style"),
    Output("details-content","children"),
    Input("alerts-table","selected_rows"),
    State("alerts-table","data"),
    Input("close-details","n_clicks"),
    prevent_initial_call=True
)
def show_details(selected, data, close_clicks):
    ctx = dash.callback_context
    if not ctx.triggered:
        return dash.no_update, dash.no_update

    trig = ctx.triggered[0]["prop_id"].split(".")[0]
    if trig == "close-details":
        return {"display":"none"}, dash.no_update

    if not selected or not data:
        return {"display":"none"}, dash.no_update

    idx = selected[0]
    row = data[idx]
    src_ip = row.get("src_ip","")
    user = row.get("user","")
    atype = row.get("type","")

    auth_rows = auth[(auth["src_ip"]==src_ip) | (auth["user"]==user)].tail(10) if src_ip or user else pd.DataFrame()
    web_rows  = web[web["src_ip"]==src_ip].tail(10) if src_ip else pd.DataFrame()
    fw_rows   = fw[fw["src_ip"]==src_ip].tail(10) if src_ip else pd.DataFrame()

    def df_table(df, title):
        if df.empty:
            return html.Div([html.Div(title, style={"fontWeight":"600","margin":"6px 0"}), html.Div("No related rows.")])
        cols = [c for c in df.columns if c in ("timestamp","user","src_ip","action","status","path","status_code","dst_ip","dst_port","user_agent")]
        return html.Div([
            html.Div(title, style={"fontWeight":"600","margin":"6px 0"}),
            dash_table.DataTable(
                data=df[cols].astype(str).to_dict("records"),
                columns=[{"name":c,"id":c} for c in cols],
                style_header={"backgroundColor":"#161b22","color":"#9da7b3","border":"0"},
                style_cell={"backgroundColor":"#0d1117","color":"#e6edf3","border":"0","fontSize":"12px"},
                page_size=5
            )
        ])

    content = [
        html.Div(f"Type: {atype} | Severity: {row.get('severity','')} | IP: {src_ip} | User: {user} | {row.get('country_name','')}",
                 style={"marginBottom":"8px","color":"#9da7b3"}),
        df_table(auth_rows, "Related AUTH events"),
        df_table(web_rows,  "Related WEB events"),
        df_table(fw_rows,   "Related FIREWALL events"),
    ]
    return {"display":"block",
            "position":"fixed","right":"20px","bottom":"20px","width":"520px",
            "maxHeight":"70vh","overflowY":"auto","background":"#0d1117",
            "border":"1px solid #30363d","borderRadius":"12px","padding":"16px",
            "boxShadow":"0 8px 24px rgba(0,0,0,0.45)","zIndex":"1000"}, content


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8050, debug=False)
