#!/usr/bin/env python3
"""
Enhanced VirusTotal Scanner Dashboard
Improved with better colors, dropdowns, and visual elements
"""

import os
import time
import pandas as pd
import dash
from dash import dcc, html, dash_table
import dash_bootstrap_components as dbc
from dash.dependencies import Input, Output, State
import plotly.express as px
import plotly.graph_objects as go

# Enhanced color palette for better visibility
COLORS = {
    'primary': '#4361ee',
    'secondary': '#555555',
    'success': '#4cc9f0',
    'info': '#4895ef',
    'warning': '#f9c74f',
    'danger': '#f72585',
    'light': '#e0e1dd',
    'dark': '#1e1e1e',
    'background': '#0b0c10',
    'card_bg': '#1f2833',
    'text': '#ffffff'
}

def create_dashboard(results_list, scan_stats, title="VirusTotal IOC Scanner"):
    """
    Create a Dash dashboard application with improved UI
    """
    
    app = dash.Dash(__name__, 
                   external_stylesheets=[dbc.themes.DARKLY],
                   title=title)
    
    # Process data
    df = pd.DataFrame(results_list)
    
    def get_severity(row):
        if "error" in row and row["error"]:
            return "Error"
        elif "vt_detection_percentage" not in row:
            return "Error"
        elif row["vt_detection_percentage"] > 50:
            return "Critical"
        elif row["vt_detection_percentage"] > 25:
            return "High"
        elif row["vt_detection_percentage"] > 0:
            return "Medium"
        else:
            return "Clean"
            
    df["severity"] = df.apply(get_severity, axis=1)
    df = df.fillna("N/A")
    
    # Count data
    ioc_type_counts = df["ioc_type"].value_counts().reset_index()
    ioc_type_counts.columns = ["IOC Type", "Count"]
    
    severity_counts = df["severity"].value_counts().reset_index()
    severity_counts.columns = ["Severity", "Count"]
    
    # Stats
    total_iocs = scan_stats.get('total_iocs', 0)
    malicious_count = scan_stats.get('malicious_count', 0)
    suspicious_count = scan_stats.get('suspicious_count', 0)
    error_count = scan_stats.get('error_count', 0)
    critical_count = scan_stats.get('critical_count', 0)
    scan_start_time = scan_stats.get('scan_start_time', time.time())
    clean_count = total_iocs - malicious_count - suspicious_count - error_count
    
    # Dashboard layout
    app.layout = html.Div([
        dbc.Container([
            # Header
            dbc.Row([
                dbc.Col([
                    html.H1([
                        html.I(className="fas fa-shield-virus me-2"),
                        "VirusTotal IOC Scanner"
                    ], className="my-4 text-center", style={'color': COLORS['primary']})
                ])
            ]),
            
            # Summary Cards
            dbc.Row([
                dbc.Col([
                    dbc.Card([
                        dbc.CardBody([
                            html.Div([
                                html.I(className="fas fa-search fa-2x me-2", style={'color': COLORS['info']}),
                                html.H4("Total IOCs", className="d-inline")
                            ], className="card-title text-center"),
                            html.H2(f"{total_iocs}", 
                                   className="text-center display-4", style={'color': COLORS['info']})
                        ])
                    ], className="mb-4 shadow", style={'background': COLORS['card_bg']})
                ], width=3),
                
                dbc.Col([
                    dbc.Card([
                        dbc.CardBody([
                            html.Div([
                                html.I(className="fas fa-virus fa-2x me-2", style={'color': COLORS['danger']}),
                                html.H4("Malicious", className="d-inline")
                            ], className="card-title text-center"),
                            html.H2(f"{malicious_count}", 
                                   className="text-center display-4", style={'color': COLORS['danger']})
                        ])
                    ], className="mb-4 shadow", style={'background': COLORS['card_bg']})
                ], width=3),
                
                dbc.Col([
                    dbc.Card([
                        dbc.CardBody([
                            html.Div([
                                html.I(className="fas fa-exclamation-triangle fa-2x me-2", style={'color': COLORS['warning']}),
                                html.H4("Suspicious", className="d-inline")
                            ], className="card-title text-center"),
                            html.H2(f"{suspicious_count}", 
                                   className="text-center display-4", style={'color': COLORS['warning']})
                        ])
                    ], className="mb-4 shadow", style={'background': COLORS['card_bg']})
                ], width=3),
                
                dbc.Col([
                    dbc.Card([
                        dbc.CardBody([
                            html.Div([
                                html.I(className="fas fa-check-circle fa-2x me-2", style={'color': COLORS['success']}),
                                html.H4("Clean", className="d-inline")
                            ], className="card-title text-center"),
                            html.H2(f"{clean_count}", 
                                   className="text-center display-4", style={'color': COLORS['success']})
                        ])
                    ], className="mb-4 shadow", style={'background': COLORS['card_bg']})
                ], width=3)
            ]),
            
            # Charts Row
            dbc.Row([
                # IOC Type Distribution
                dbc.Col([
                    dbc.Card([
                        dbc.CardHeader([
                            html.I(className="fas fa-chart-bar me-2"),
                            "IOC Type Distribution"
                        ], style={'background': COLORS['dark'], 'color': COLORS['light']}),
                        dbc.CardBody([
                            dcc.Graph(
                                id='ioc-type-chart',
                                figure=px.bar(
                                    ioc_type_counts, 
                                    x='IOC Type', 
                                    y='Count',
                                    color='IOC Type',
                                    color_discrete_sequence=px.colors.qualitative.Bold
                                ).update_layout(
                                    template='plotly_dark',
                                    paper_bgcolor='rgba(0,0,0,0)',
                                    plot_bgcolor='rgba(0,0,0,0)',
                                    margin=dict(l=20, r=20, t=30, b=20),
                                    height=350
                                )
                            )
                        ], style={'background': COLORS['card_bg']})
                    ], className="mb-4 shadow")
                ], width=6),
                
                # Severity Distribution
                dbc.Col([
                    dbc.Card([
                        dbc.CardHeader([
                            html.I(className="fas fa-chart-pie me-2"),
                            "Detection Severity"
                        ], style={'background': COLORS['dark'], 'color': COLORS['light']}),
                        dbc.CardBody([
                            dcc.Graph(
                                id='severity-chart',
                                figure=px.pie(
                                    severity_counts, 
                                    names='Severity', 
                                    values='Count',
                                    color='Severity',
                                    color_discrete_map={
                                        'Critical': COLORS['danger'],
                                        'High': COLORS['warning'],
                                        'Medium': COLORS['info'],
                                        'Clean': COLORS['success'],
                                        'Error': COLORS['secondary']
                                    },
                                    hole=0.4
                                ).update_layout(
                                    template='plotly_dark',
                                    paper_bgcolor='rgba(0,0,0,0)',
                                    plot_bgcolor='rgba(0,0,0,0)',
                                    margin=dict(l=20, r=20, t=30, b=20),
                                    height=350,
                                    legend=dict(
                                        orientation="h",
                                        yanchor="bottom",
                                        y=-0.2,
                                        xanchor="center",
                                        x=0.5
                                    )
                                )
                            )
                        ], style={'background': COLORS['card_bg']})
                    ], className="mb-4 shadow")
                ], width=6)
            ]),
            
            # Filters Row
            dbc.Row([
                dbc.Col([
                    dbc.Card([
                        dbc.CardHeader([
                            html.I(className="fas fa-filter me-2"),
                            "Filter Results"
                        ], style={'background': COLORS['dark'], 'color': COLORS['light']}),
                        dbc.CardBody([
                            dbc.Row([
                                dbc.Col([
                                    html.Label([
                                        html.I(className="fas fa-sitemap me-2"),
                                        "IOC Type:"
                                    ]),
                                    dcc.Dropdown(
                                        id='ioc-type-filter',
                                        options=[{'label': 'All Types', 'value': 'all'}] + 
                                                [{'label': t, 'value': t} for t in df['ioc_type'].unique()],
                                        value='all',
                                        clearable=False,
                                        className="mb-3",
                                        style={
                                            'backgroundColor': COLORS['dark'],
                                            'color': 'black',
                                            'border': f'1px solid {COLORS["primary"]}'
                                        }
                                    )
                                ], width=4),
                                
                                dbc.Col([
                                    html.Label([
                                        html.I(className="fas fa-exclamation-circle me-2"),
                                        "Severity:"
                                    ]),
                                    dcc.Dropdown(
                                        id='severity-filter',
                                        options=[{'label': 'All Severities', 'value': 'all'}] + 
                                                [{'label': s, 'value': s} for s in df['severity'].unique()],
                                        value='all',
                                        clearable=False,
                                        className="mb-3",
                                        style={
                                            'backgroundColor': COLORS['dark'],
                                            'color': 'black',
                                            'border': f'1px solid {COLORS["primary"]}'
                                        }
                                    )
                                ], width=4),
                                
                                dbc.Col([
                                    html.Label([
                                        html.I(className="fas fa-search me-2"),
                                        "Search:"
                                    ]),
                                    dbc.Input(
                                        id="search-input",
                                        type="text",
                                        placeholder="Search IOCs...",
                                        className="mb-3",
                                        style={
                                            'backgroundColor': COLORS['dark'],
                                            'color': COLORS['light'],
                                            'border': f'1px solid {COLORS["primary"]}'
                                        }
                                    )
                                ], width=4)
                            ])
                        ], style={'background': COLORS['card_bg']})
                    ], className="mb-4 shadow")
                ])
            ]),
            
            # Results Table
            dbc.Row([
                dbc.Col([
                    dbc.Card([
                        dbc.CardHeader([
                            html.I(className="fas fa-table me-2"),
                            "Scan Results"
                        ], style={'background': COLORS['dark'], 'color': COLORS['light']}),
                        dbc.CardBody([
                            dash_table.DataTable(
                                id='results-table',
                                columns=[
                                    {'name': 'IOC', 'id': 'ioc', 'presentation': 'markdown'},
                                    {'name': 'Type', 'id': 'ioc_type'},
                                    {'name': 'Detections', 'id': 'vt_detection_ratio'},
                                    {'name': 'Detection %', 'id': 'vt_detection_percentage', 'type': 'numeric', 'format': {'specifier': '.1f'}},
                                    {'name': 'Severity', 'id': 'severity'},
                                    {'name': 'Category', 'id': 'category'},
                                    {'name': 'Last Analysis', 'id': 'vt_last_analysis_date'},
                                    {'name': 'VT Link', 'id': 'vt_link', 'presentation': 'markdown'},
                                ],
                                data=df.apply(lambda x: {
                                    **x.to_dict(),
                                    'vt_link': f"[View]({x.get('vt_link')})" if x.get('vt_link') else ""
                                }, axis=1).to_list(),
                                style_cell={
                                    'backgroundColor': COLORS['dark'],
                                    'color': COLORS['light'],
                                    'border': '1px solid #444',
                                    'fontSize': '14px',
                                    'textAlign': 'left',
                                    'whiteSpace': 'normal',
                                    'height': 'auto',
                                    'minWidth': '100px',
                                    'width': 'auto',
                                },
                                style_header={
                                    'backgroundColor': COLORS['primary'],
                                    'color': 'white',
                                    'fontWeight': 'bold',
                                    'border': '1px solid #444',
                                },
                                style_data_conditional=[
                                    {
                                        'if': {'filter_query': '{severity} = "Critical"'},
                                        'backgroundColor': 'rgba(247, 37, 133, 0.2)',
                                        'color': COLORS['danger']
                                    },
                                    {
                                        'if': {'filter_query': '{severity} = "High"'},
                                        'backgroundColor': 'rgba(249, 199, 79, 0.2)',
                                        'color': COLORS['warning']
                                    },
                                    {
                                        'if': {'filter_query': '{severity} = "Medium"'},
                                        'backgroundColor': 'rgba(72, 149, 239, 0.2)',
                                        'color': COLORS['info']
                                    },
                                    {
                                        'if': {'filter_query': '{severity} = "Clean"'},
                                        'backgroundColor': 'rgba(76, 201, 240, 0.2)',
                                        'color': COLORS['success']
                                    },
                                    {
                                        'if': {'filter_query': '{severity} = "Error"'},
                                        'backgroundColor': 'rgba(85, 85, 85, 0.2)',
                                        'color': COLORS['light']
                                    },
                                ],
                                page_size=10,
                                sort_action='native',
                                filter_action='native',
                                sort_mode='multi',
                                style_as_list_view=False,
                                page_action='native'
                            )
                        ], style={'background': COLORS['card_bg']})
                    ], className="mb-4 shadow")
                ])
            ]),
            
            # Critical Findings Section
            dbc.Row([
                dbc.Col([
                    dbc.Card([
                        dbc.CardHeader([
                            html.I(className="fas fa-exclamation-circle me-2", style={'color': COLORS['danger']}),
                            html.H4("Critical Findings", className="d-inline", style={'color': COLORS['danger']}),
                        ], style={'background': COLORS['dark']}),
                        dbc.CardBody([
                            html.P("The following IOCs have high detection rates and require immediate attention", 
                                  className="mb-3"),
                            dash_table.DataTable(
                                id='critical-table',
                                columns=[
                                    {'name': 'IOC', 'id': 'ioc'},
                                    {'name': 'Type', 'id': 'ioc_type'},
                                    {'name': 'Detection %', 'id': 'vt_detection_percentage', 'type': 'numeric', 'format': {'specifier': '.1f'}},
                                    {'name': 'Detection Names', 'id': 'detection_names'},
                                    {'name': 'VT Link', 'id': 'vt_link', 'presentation': 'markdown'},
                                ],
                                data=df[df['vt_detection_percentage'] > 25].apply(lambda x: {
                                    **x.to_dict(),
                                    'vt_link': f"[Investigate]({x.get('vt_link')})" if x.get('vt_link') else ""
                                }, axis=1).to_list(),
                                style_cell={
                                    'backgroundColor': COLORS['dark'],
                                    'color': COLORS['light'],
                                    'border': '1px solid #444',
                                    'whiteSpace': 'normal',
                                    'height': 'auto',
                                },
                                style_header={
                                    'backgroundColor': COLORS['primary'],
                                    'color': 'white',
                                    'fontWeight': 'bold',
                                    'border': '1px solid #444',
                                },
                                page_size=5,
                                style_as_list_view=False,
                            )
                        ], style={'background': COLORS['card_bg']})
                    ], className="mb-4 shadow", 
                      style={'display': 'block' if malicious_count > 0 else 'none'})
                ])
            ]),
            
            # Footer
            dbc.Row([
                dbc.Col([
                    html.Hr(style={'borderColor': COLORS['secondary']}),
                    html.P([
                        html.I(className="fas fa-shield-alt me-2"),
                        "VirusTotal IOC Scanner | Scan completed in ", 
                        html.Span(f"{time.time() - scan_start_time:.1f} seconds", 
                                 style={'color': COLORS['info']}),
                    ], className="text-center mt-3")
                ])
            ])
        ], fluid=True)
    ], style={'backgroundColor': COLORS['background'], 'minHeight': '100vh'})
    
    # Callbacks for interactivity
    @app.callback(
        Output('results-table', 'data'),
        [Input('ioc-type-filter', 'value'),
         Input('severity-filter', 'value'),
         Input('search-input', 'value')]
    )
    def update_table(ioc_type, severity, search_value):
        filtered_df = df.copy()
        
        if ioc_type and ioc_type != 'all':
            filtered_df = filtered_df[filtered_df['ioc_type'] == ioc_type]
            
        if severity and severity != 'all':
            filtered_df = filtered_df[filtered_df['severity'] == severity]
            
        if search_value:
            filtered_df = filtered_df[filtered_df['ioc'].str.contains(search_value, case=False, na=False)]
            
        return filtered_df.apply(lambda x: {
            **x.to_dict(),
            'vt_link': f"[View]({x.get('vt_link')})" if x.get('vt_link') else ""
        }, axis=1).to_list()
        
    return app
