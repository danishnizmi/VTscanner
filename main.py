#!/usr/bin/env python3
"""
Enhanced VirusTotal IOC Scanner with HTML Report Generation

A streamlined tool to scan IOCs against VirusTotal API with a static HTML report,
improved visualizations, optimized for Premium API usage, and enhanced safety measures.
"""

import base64
import csv
import getpass
import json
import logging
import os
import re
import sys
import time
import webbrowser
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any, Union
from urllib.parse import urlparse

# Suppress SSL warnings
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

try:
    import requests
    import pandas as pd
    import plotly.express as px
    import plotly.graph_objects as go
    from tqdm import tqdm
except ImportError:
    print("Installing required packages...")
    import subprocess
    subprocess.check_call([sys.executable, "-m", "pip", "install", "--trusted-host", "pypi.org", 
                           "--trusted-host", "files.pythonhosted.org", "requests", "tqdm", 
                           "plotly", "pandas"])
    import requests
    import pandas as pd
    import plotly.express as px
    import plotly.graph_objects as go
    from tqdm import tqdm

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[logging.FileHandler("vt_scanner.log"), logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger(__name__)

# Console colors
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
BLUE = "\033[94m"
CYAN = "\033[96m"
MAGENTA = "\033[95m"
RESET = "\033[0m"
BOLD = "\033[1m"
BG_RED = "\033[41m"
BG_GREEN = "\033[42m"
BG_YELLOW = "\033[43m"

# Enhanced color palette for HTML reports
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
    'text': '#ffffff',
    'ms_known': '#e63946',
    'ms_unknown': '#6c757d'
}

#######################################
# HTML Report Generation Functions
#######################################

def get_severity_class(severity):
    """Return the CSS class for the given severity level"""
    severity_classes = {
        'Critical': 'severity-Critical',
        'High': 'severity-High',
        'Medium': 'severity-Medium',
        'Clean': 'severity-Clean',
        'Error': 'severity-Error'
    }
    return severity_classes.get(severity, '')

def get_severity_badge(severity):
    """Return HTML for a severity badge"""
    badge_classes = {
        'Critical': 'badge badge-danger',
        'High': 'badge badge-warning',
        'Medium': 'badge badge-info',
        'Clean': 'badge badge-success',
        'Error': 'badge badge-secondary'
    }
    if severity in badge_classes:
        return f"<span class='{badge_classes[severity]}'>{severity}</span>"
    return ""

def get_ms_defender_span(status):
    """Return HTML for MS Defender status"""
    if status == "known":
        return f"""
            <span class="ms-known">
                <i class="fas fa-shield-alt"></i> known
            </span>
            """
    elif status == "unknown":
        return f"""
            <span class="ms-unknown">
                <i class="fas fa-question-circle"></i> unknown
            </span>
            """
    else:
        return f"""
            <span class="ms-N/A">
                <i class="fas fa-question-circle"></i> N/A
            </span>
            """

def generate_html_report(results_list, scan_stats, output_path=None, input_filename="IOCs"):
    """
    Generate a static HTML report from scan results
    
    Args:
        results_list: List of dictionaries containing scan results
        scan_stats: Dictionary with scan statistics
        output_path: Path to save the HTML report (default: automatically generated)
        input_filename: Original filename for the title
    
    Returns:
        Path to the generated HTML report
    """
    if not results_list:
        print("No results to display.")
        return None
    
    # Process data
    df = pd.DataFrame(results_list)
    
    # Convert vt_detection_percentage to numeric, coercing errors to NaN
    if 'vt_detection_percentage' in df.columns:
        df['vt_detection_percentage'] = pd.to_numeric(df['vt_detection_percentage'], errors='coerce')
    
    # Determine severity for each IOC
    def get_severity(row):
        if "error" in row and row["error"]:
            return "Error"
        elif "vt_detection_percentage" not in row or pd.isna(row["vt_detection_percentage"]):
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
    
    # Set missing values and determine MS Defender status
    df = df.fillna("N/A")
    
    def get_ms_defender_status(row):
        # Check if Microsoft appears in detection_names
        if "detection_names" in row and isinstance(row["detection_names"], str):
            if "Microsoft:" in row["detection_names"]:
                return "known"
        return "unknown"
    
    df["ms_defender"] = df.apply(get_ms_defender_status, axis=1)
    
    # Count data
    ioc_type_counts = df["ioc_type"].value_counts().reset_index()
    ioc_type_counts.columns = ["IOC Type", "Count"]
    
    severity_counts = df["severity"].value_counts().reset_index()
    severity_counts.columns = ["Severity", "Count"]
    
    ms_defender_counts = df["ms_defender"].value_counts().reset_index()
    ms_defender_counts.columns = ["Status", "Count"]
    
    # Stats
    total_iocs = scan_stats.get('total_iocs', 0)
    malicious_count = scan_stats.get('malicious_count', 0)
    suspicious_count = scan_stats.get('suspicious_count', 0)
    error_count = scan_stats.get('error_count', 0)
    scan_start_time = scan_stats.get('scan_start_time', time.time())
    clean_count = total_iocs - malicious_count - suspicious_count - error_count
    
    ms_known_count = df[df["ms_defender"] == "known"].shape[0]
    ms_unknown_count = df[df["ms_defender"] == "unknown"].shape[0]
    
    scan_duration = time.time() - scan_start_time
    scan_duration_str = f"{int(scan_duration // 60)}m {int(scan_duration % 60)}s"
    
    # Create output path if not provided
    if not output_path:
        timestamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
        report_filename = f"{Path(input_filename).stem}_vt_report_{timestamp}.html"
        output_path = str(Path.cwd() / report_filename)
    
    # Create charts using plotly
    # 1. IOC Type Distribution
    ioc_type_fig = px.bar(
        ioc_type_counts, 
        x='IOC Type', 
        y='Count',
        color='IOC Type',
        color_discrete_sequence=px.colors.qualitative.Bold,
        text='Count'
    )
    ioc_type_fig.update_layout(
        template='plotly_dark',
        paper_bgcolor='rgba(0,0,0,0)',
        plot_bgcolor='rgba(0,0,0,0)',
        margin=dict(l=20, r=20, t=30, b=20),
        height=350,
        legend=dict(
            orientation="h",
            yanchor="bottom",
            y=-0.25,
            xanchor="center",
            x=0.5
        ),
        xaxis=dict(
            title=dict(text="IOC Type", font=dict(size=14)),
            tickfont=dict(size=12)
        ),
        yaxis=dict(
            title=dict(text="Count", font=dict(size=14)),
            tickfont=dict(size=12)
        )
    )
    ioc_type_fig.update_traces(
        textposition='auto',
        textfont=dict(size=14)
    )
    
    # 2. Severity Distribution
    severity_fig = px.pie(
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
    )
    severity_fig.update_layout(
        template='plotly_dark',
        paper_bgcolor='rgba(0,0,0,0)',
        plot_bgcolor='rgba(0,0,0,0)',
        margin=dict(l=20, r=20, t=30, b=20),
        height=350,
        showlegend=True,
        legend=dict(
            font=dict(size=12),
            orientation="h",
            yanchor="bottom",
            y=-0.25,
            xanchor="center",
            x=0.5
        ),
        annotations=[dict(
            text="Severity",
            font=dict(size=16),
            showarrow=False
        )]
    )
    
    # 3. MS Defender Distribution
    ms_defender_fig = px.pie(
        ms_defender_counts, 
        names='Status', 
        values='Count',
        color='Status',
        color_discrete_map={
            'known': COLORS['ms_known'],
            'unknown': COLORS['ms_unknown'],
            'N/A': COLORS['secondary']
        },
        hole=0.4
    )
    ms_defender_fig.update_layout(
        template='plotly_dark',
        paper_bgcolor='rgba(0,0,0,0)',
        plot_bgcolor='rgba(0,0,0,0)',
        margin=dict(l=20, r=20, t=30, b=20),
        height=350,
        showlegend=True,
        legend=dict(
            font=dict(size=12),
            orientation="h",
            yanchor="bottom",
            y=-0.25,
            xanchor="center",
            x=0.5
        ),
        annotations=[dict(
            text="MS Defender",
            font=dict(size=16),
            showarrow=False
        )]
    )
    
    # Generate HTML for tables
    # 1. Critical Findings Table
    critical_rows = ""
    critical_df = df[df['severity'].isin(['Critical', 'High'])]
    for _, row in critical_df.iterrows():
        critical_rows += f"""
                    <tr>
                        <td>{row['ioc']}</td>
                        <td>{row['ioc_type']}</td>
                        <td>{row.get('vt_detection_percentage', 'N/A')}</td>
                        <td class="{get_severity_class(row['severity'])}">{row['severity']} {get_severity_badge(row['severity'])}</td>
                        <td>{row.get('ms_defender', 'N/A')}</td>
                        <td>{row.get('detection_names', '')}</td>
                        <td><a href='{row.get('vt_link', '')}' target='_blank'>Investigate</a></td>
                    </tr>
                    """
    
    # 2. MS Defender Detections Table
    ms_detection_rows = ""
    ms_detection_df = df[df['ms_defender'] == 'known']
    for _, row in ms_detection_df.iterrows():
        ms_detection_rows += f"""
                    <tr data-ioc-type="{row['ioc_type']}" data-severity="{row['severity']}" data-ms-detection="{row['ms_defender']}">
                        <td>{row['ioc']}</td>
                        <td>{row['ioc_type']}</td>
                        <td>{row.get('vt_detection_percentage', 'N/A')}</td>
                        <td class="{get_severity_class(row['severity'])}">{row['severity']} {get_severity_badge(row['severity'])}</td>
                        <td>{row.get('detection_names', '')}</td>
                        <td><a href='{row.get('vt_link', '')}' target='_blank'>Investigate</a></td>
                    </tr>
                    """
    
    # 3. MS Defender Unknown Table
    ms_unknown_rows = ""
    ms_unknown_df = df[df['ms_defender'] == 'unknown']
    for _, row in ms_unknown_df.iterrows():
        ms_unknown_rows += f"""
                    <tr data-ioc-type="{row['ioc_type']}" data-severity="{row['severity']}" data-ms-detection="{row['ms_defender']}">
                        <td>{row['ioc']}</td>
                        <td>{row['ioc_type']}</td>
                        <td>{row.get('vt_detection_percentage', 'N/A')}</td>
                        <td class="{get_severity_class(row['severity'])}">{row['severity']} {get_severity_badge(row['severity'])}</td>
                        <td>{row.get('detection_names', '')}</td>
                        <td><a href='{row.get('vt_link', '')}' target='_blank'>Investigate</a></td>
                    </tr>
                    """
    
    # 4. All Results Table
    all_results_rows = ""
    for _, row in df.iterrows():
        ms_class = f"bg-ms-known" if row['ms_defender'] == 'known' else ""
        all_results_rows += f"""
            <tr class="{ms_class}" data-ioc-type="{row['ioc_type']}" data-severity="{row['severity']}" data-ms-detection="{row['ms_defender']}">
                <td>{row['ioc']}</td>
                <td>{row['ioc_type']}</td>
                <td>{row.get('vt_detection_ratio', 'N/A')}</td>
                <td>{row.get('vt_detection_percentage', 'N/A')}</td>
                <td class="{get_severity_class(row['severity'])}">{row['severity']} {get_severity_badge(row['severity'])}</td>
                <td>
            {get_ms_defender_span(row['ms_defender'])}
            </td>
                <td>{row.get('category', '')}</td>
                <td>{row.get('vt_last_analysis_date', 'N/A')}</td>
                <td><a href='{row.get('vt_link', '')}' target='_blank'>View</a></td>
            </tr>
            """
    
    # Create filter dropdown options
    ioc_type_options = ""
    for ioc_type in df['ioc_type'].unique():
        ioc_type_options += f'<option value="{ioc_type}">{ioc_type}</option>'
    
    severity_options = ""
    for severity in df['severity'].unique():
        severity_options += f'<option value="{severity}">{severity}</option>'
    
    # Build the HTML report
    html_template = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>VirusTotal Scan Results - """ + Path(input_filename).name + """</title>
        
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/5.15.4/css/all.min.css">
    <script src="https://cdn.plot.ly/plotly-latest.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/jquery/3.6.0/jquery.min.js"></script>
    
        
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background-color: #0b0c10;
            color: #ffffff;
            margin: 0;
            padding: 0;
        }
        .container {
            width: 95%;
            margin: 0 auto;
            padding: 20px;
        }
        .header {
            text-align: center;
            margin-bottom: 30px;
            color: #4361ee;
            padding: 20px 0;
            border-bottom: 1px solid #4361ee;
        }
        .header h1 {
            font-size: 2.5rem;
            margin-bottom: 10px;
        }
        .header p {
            font-size: 1.1rem;
            opacity: 0.8;
        }
        .card {
            background-color: #1f2833;
            border-radius: 8px;
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.4);
            margin-bottom: 25px;
            overflow: hidden;
            transition: all 0.3s ease;
        }
        .card:hover {
            box-shadow: 0 6px 16px rgba(0, 0, 0, 0.6);
            transform: translateY(-2px);
        }
        .card-header {
            background-color: #1f2833;
            color: #e0e1dd;
            padding: 15px 20px;
            font-weight: bold;
            font-size: 1.2rem;
            border-bottom: 2px solid rgba(255, 255, 255, 0.1);
        }
        .card-body {
            padding: 20px;
        }
        .row {
            display: flex;
            flex-wrap: wrap;
            margin: 0 -15px;
            gap: 0;
        }
        .col {
            flex: 1;
            padding: 0 15px;
            min-width: 250px;
            margin-bottom: 20px;
        }
        .stats-card {
            text-align: center;
            padding: 20px 15px;
            height: 100%;
            display: flex;
            flex-direction: column;
            justify-content: center;
            align-items: center;
            transition: transform 0.2s ease;
        }
        .stats-card:hover {
            transform: scale(1.02);
        }
        .stats-card i {
            margin-bottom: 10px;
            opacity: 0.9;
        }
        .stats-card h4 {
            margin-top: 5px;
            margin-bottom: 15px;
            font-size: 1.1rem;
            opacity: 0.9;
        }
        .stats-card h2 {
            font-size: 2.8rem;
            margin: 0;
            font-weight: 600;
        }
        .table-container {
            overflow-x: auto;
            border-radius: 4px;
            box-shadow: 0 2px 8px rgba(0, 0, 0, 0.2) inset;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 10px;
            overflow: hidden;
        }
        th, td {
            padding: 12px 15px;
            text-align: left;
            border: 1px solid #444;
        }
        th {
            background-color: #4361ee;
            color: white;
            font-weight: 600;
            position: sticky;
            top: 0;
            box-shadow: 0 2px 2px rgba(0, 0, 0, 0.1);
        }
        tr:nth-child(even) {
            background-color: rgba(255, 255, 255, 0.05);
        }
        tr:hover {
            background-color: rgba(255, 255, 255, 0.1);
        }
        .chart-container {
            width: 100%;
            margin-top: 15px;
            position: relative;
        }
        .footer {
            text-align: center;
            margin-top: 40px;
            padding: 20px 0;
            border-top: 1px solid #555555;
            color: #e0e1dd;
            font-size: 1.1rem;
        }
        .primary {
            color: #4361ee;
        }
        .success {
            color: #4cc9f0;
        }
        .info {
            color: #4895ef;
        }
        .warning {
            color: #f9c74f;
        }
        .danger {
            color: #f72585;
        }
        .bg-danger {
            background-color: rgba(247, 37, 133, 0.15);
        }
        .bg-warning {
            background-color: rgba(249, 199, 79, 0.15);
        }
        .bg-info {
            background-color: rgba(72, 149, 239, 0.15);
        }
        .bg-success {
            background-color: rgba(76, 201, 240, 0.15);
        }
        .bg-error {
            background-color: rgba(85, 85, 85, 0.15);
        }
        .ms-known {
            color: #e63946;
        }
        .ms-unknown {
            color: #6c757d;
        }
        .bg-ms-known {
            background-color: rgba(230, 57, 70, 0.15);
        }
        .severity-Critical {
            color: #f72585;
            font-weight: bold;
        }
        .severity-High {
            color: #f9c74f;
            font-weight: bold;
        }
        .severity-Medium {
            color: #4895ef;
        }
        .severity-Clean {
            color: #4cc9f0;
        }
        .severity-Error {
            color: #555555;
        }
        a {
            color: #4895ef;
            text-decoration: none;
            transition: color 0.2s;
        }
        a:hover {
            color: #4361ee;
            text-decoration: underline;
        }
        @media print {
            body {
                background-color: white;
                color: black;
            }
            .card {
                box-shadow: none;
                border: 1px solid #ddd;
            }
            .card-header {
                background-color: #f0f0f0;
                color: black;
            }
            .stats-card h2 {
                color: black !important;
            }
        }
        /* Filter controls */
        .filter-container {
            padding: 20px;
            background-color: #1f2833;
            border-radius: 8px;
            margin-bottom: 20px;
            border: 1px solid rgba(255, 255, 255, 0.1);
        }
        .filter-title {
            font-weight: bold;
            margin-bottom: 15px;
            font-size: 1.1rem;
        }
        .filter-row {
            display: flex;
            flex-wrap: wrap;
            gap: 20px;
            margin-bottom: 15px;
            align-items: flex-end;
        }
        .filter-group {
            flex: 1;
            min-width: 200px;
        }
        .filter-group label {
            display: block;
            margin-bottom: 8px;
            font-weight: 500;
            opacity: 0.9;
        }
        .filter-input {
            width: 100%;
            padding: 10px 12px;
            background-color: #1f2833;
            color: #e0e1dd;
            border: 1px solid #4361ee;
            border-radius: 4px;
            font-size: 1rem;
            transition: all 0.2s;
        }
        .filter-input:focus {
            outline: none;
            border-color: #4895ef;
            box-shadow: 0 0 0 2px rgba(67, 97, 238, 0.3);
        }
        .filter-btn {
            background-color: #4361ee;
            color: white;
            border: none;
            padding: 10px 20px;
            border-radius: 4px;
            cursor: pointer;
            font-weight: 600;
            transition: background-color 0.2s;
            display: flex;
            align-items: center;
            gap: 8px;
        }
        .filter-btn:hover {
            background-color: #4895ef;
        }
        /* Custom scrollbar */
        ::-webkit-scrollbar {
            width: 12px;
            height: 12px;
        }
        ::-webkit-scrollbar-track {
            background: #1f2833;
            border-radius: 6px;
        }
        ::-webkit-scrollbar-thumb {
            background: #4361ee;
            border-radius: 6px;
        }
        ::-webkit-scrollbar-thumb:hover {
            background: #4895ef;
        }
        /* Tooltip styling */
        .tooltip {
            position: relative;
            display: inline-block;
            cursor: help;
        }
        .tooltip .tooltiptext {
            visibility: hidden;
            width: 200px;
            background-color: #1f2833;
            color: #e0e1dd;
            text-align: center;
            border-radius: 6px;
            padding: 10px;
            position: absolute;
            z-index: 1;
            bottom: 125%;
            left: 50%;
            margin-left: -100px;
            opacity: 0;
            transition: opacity 0.3s;
            font-size: 0.9rem;
            box-shadow: 0 4px 8px rgba(0, 0, 0, 0.3);
            border: 1px solid #4361ee;
        }
        .tooltip:hover .tooltiptext {
            visibility: visible;
            opacity: 1;
        }
        /* Badge styling */
        .badge {
            display: inline-block;
            padding: 4px 8px;
            font-size: 0.75rem;
            font-weight: 600;
            line-height: 1;
            text-align: center;
            white-space: nowrap;
            vertical-align: baseline;
            border-radius: 10px;
            margin-left: 5px;
        }
        .badge-primary {
            background-color: #4361ee;
            color: white;
        }
        .badge-danger {
            background-color: #f72585;
            color: white;
        }
        .badge-warning {
            background-color: #f9c74f;
            color: black;
        }
        .badge-success {
            background-color: #4cc9f0;
            color: white;
        }
        .badge-info {
            background-color: #4895ef;
            color: white;
        }
        .badge-secondary {
            background-color: #555555;
            color: white;
        }
    </style>
    
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1><i class="fas fa-shield-virus"></i> VirusTotal Scan Results - """ + Path(input_filename).name + """</h1>
                <p>Report generated on """ + datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + """</p>
            </div>
            
            <!-- Summary Stats Cards - First Row -->
            <div class="row">
                <div class="col">
                    <div class="card">
                        <div class="stats-card">
                            <i class="fas fa-search fa-3x" style="color: #4895ef;"></i>
                            <h4>Total IOCs</h4>
                            <h2 style="color: #4895ef;">""" + str(total_iocs) + """</h2>
                        </div>
                    </div>
                </div>
                <div class="col">
                    <div class="card">
                        <div class="stats-card">
                            <i class="fas fa-virus fa-3x" style="color: #f72585;"></i>
                            <h4>Malicious</h4>
                            <h2 style="color: #f72585;">""" + str(malicious_count) + """</h2>
                        </div>
                    </div>
                </div>
                <div class="col">
                    <div class="card">
                        <div class="stats-card">
                            <i class="fas fa-exclamation-triangle fa-3x" style="color: #f9c74f;"></i>
                            <h4>Suspicious</h4>
                            <h2 style="color: #f9c74f;">""" + str(suspicious_count) + """</h2>
                        </div>
                    </div>
                </div>
                <div class="col">
                    <div class="card">
                        <div class="stats-card">
                            <i class="fas fa-check-circle fa-3x" style="color: #4cc9f0;"></i>
                            <h4>Clean</h4>
                            <h2 style="color: #4cc9f0;">""" + str(clean_count) + """</h2>
                        </div>
                    </div>
                </div>
            </div>
            
            <!-- Microsoft Defender Stats Row -->
            <div class="row">
                <div class="col" style="flex: 1;">
                    <div class="card">
                        <div class="stats-card">
                            <i class="fas fa-shield-alt fa-3x" style="color: #e63946;"></i>
                            <h4>MS Defender - Known</h4>
                            <h2 style="color: #e63946;">""" + str(ms_known_count) + """</h2>
                        </div>
                    </div>
                </div>
                <div class="col" style="flex: 1;">
                    <div class="card">
                        <div class="stats-card">
                            <i class="fas fa-question-circle fa-3x" style="color: #6c757d;"></i>
                            <h4>MS Defender - Unknown</h4>
                            <h2 style="color: #6c757d;">""" + str(ms_unknown_count) + """</h2>
                        </div>
                    </div>
                </div>
            </div>
            
            <!-- Charts Row -->
            <div class="row">
                <div class="col">
                    <div class="card">
                        <div class="card-header">
                            <i class="fas fa-chart-bar"></i> IOC Type Distribution
                        </div>
                        <div class="card-body">
                            <div class="chart-container" id="ioc-type-chart">
    """ + ioc_type_fig.to_html(full_html=False, include_plotlyjs=False, default_height='350px') + """
                            </div>
                        </div>
                    </div>
                </div>
                <div class="col">
                    <div class="card">
                        <div class="card-header">
                            <i class="fas fa-chart-pie"></i> Detection Severity
                        </div>
                        <div class="card-body">
                            <div class="chart-container" id="severity-chart">
    """ + severity_fig.to_html(full_html=False, include_plotlyjs=False, default_height='350px') + """
                            </div>
                        </div>
                    </div>
                </div>
                <div class="col">
                    <div class="card">
                        <div class="card-header">
                            <i class="fas fa-shield-alt"></i> Microsoft Defender Detection
                        </div>
                        <div class="card-body">
                            <div class="chart-container" id="ms-detection-chart">
    """ + ms_defender_fig.to_html(full_html=False, include_plotlyjs=False, default_height='350px') + """
                            </div>
                        </div>
                    </div>
                </div>
            </div>
            
            <!-- Filter Section -->
            <div class="card">
                <div class="card-header">
                    <i class="fas fa-filter"></i> Filter Results
                </div>
                <div class="card-body">
                    <div class="filter-container">
                        <div class="filter-row">
                            <div class="filter-group">
                                <label><i class="fas fa-sitemap"></i> IOC Type:</label>
                                <select id="ioc-type-filter" class="filter-input">
                                    <option value="all">All Types</option>
                                    """ + ioc_type_options + """
                                </select>
                            </div>
                            <div class="filter-group">
                                <label><i class="fas fa-exclamation-circle"></i> Severity:</label>
                                <select id="severity-filter" class="filter-input">
                                    <option value="all">All Severities</option>
                                    """ + severity_options + """
                                </select>
                            </div>
                            <div class="filter-group">
                                <label><i class="fas fa-shield-alt"></i> MS Defender:</label>
                                <select id="ms-detection-filter" class="filter-input">
                                    <option value="all">All</option>
                                    <option value="known">Known</option>
                                    <option value="unknown">Unknown</option>
                                </select>
                            </div>
                            <div class="filter-group">
                                <label><i class="fas fa-search"></i> Search:</label>
                                <input type="text" id="search-input" class="filter-input" placeholder="Search IOCs...">
                            </div>
                        </div>
                        <div class="filter-row" style="justify-content: flex-end;">
                            <button id="apply-filters-btn" class="filter-btn">
                                <i class="fas fa-filter"></i> Apply Filters
                            </button>
                            <button id="reset-filters-btn" class="filter-btn" style="background-color: #555555;">
                                <i class="fas fa-sync-alt"></i> Reset
                            </button>
                        </div>
                    </div>
                </div>
            </div>
    
            <!-- Critical Findings Section -->
            <div class="card">
                <div class="card-header" style="color: #f72585;">
                    <i class="fas fa-exclamation-circle"></i> Critical Findings
                    <span class="badge badge-danger">""" + str(len(critical_df)) + """</span>
                </div>
                <div class="card-body">
                    <p>The following IOCs have high detection rates and require immediate attention:</p>
                    <div class="table-container">
                        <table id="critical-table">
                            <thead>
                                <tr>
                                    <th>IOC</th>
                                    <th>Type</th>
                                    <th>Detection %</th>
                                    <th>Severity</th>
                                    <th>MS Defender</th>
                                    <th>Detection Names</th>
                                    <th>VT Link</th>
                                </tr>
                            </thead>
                            <tbody>
                                """ + critical_rows + """
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
        
            <!-- Microsoft Defender Detections Section -->
            <div class="card">
                <div class="card-header" style="color: #e63946;">
                    <i class="fas fa-shield-alt"></i> Microsoft Defender Detections
                    <span class="badge badge-primary">""" + str(ms_known_count) + """</span>
                </div>
                <div class="card-body">
                    <p>The following IOCs have been detected by Microsoft Defender:</p>
                    <div class="table-container">
                        <table id="ms-detection-table">
                            <thead>
                                <tr>
                                    <th>IOC</th>
                                    <th>Type</th>
                                    <th>Detection %</th>
                                    <th>Severity</th>
                                    <th>Detection Names</th>
                                    <th>VT Link</th>
                                </tr>
                            </thead>
                            <tbody>
                                """ + ms_detection_rows + """
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
        
            <!-- Microsoft Unknown Detections Section -->
            <div class="card">
                <div class="card-header" style="color: #6c757d;">
                    <i class="fas fa-question-circle"></i> Microsoft Defender - Unknown IOCs
                    <span class="badge badge-secondary">""" + str(ms_unknown_count) + """</span>
                </div>
                <div class="card-body">
                    <p>The following IOCs were not detected by Microsoft Defender or Microsoft engine wasn't present in the scan:</p>
                    <div class="table-container">
                        <table id="ms-unknown-table">
                            <thead>
                                <tr>
                                    <th>IOC</th>
                                    <th>Type</th>
                                    <th>Detection %</th>
                                    <th>Severity</th>
                                    <th>Detection Names</th>
                                    <th>VT Link</th>
                                </tr>
                            </thead>
                            <tbody>
                                """ + ms_unknown_rows + """
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
        
        <!-- All Results Table -->
        <div class="card">
            <div class="card-header">
                <i class="fas fa-table"></i> All Scan Results
                <span class="badge badge-primary">""" + str(total_iocs) + """</span>
            </div>
            <div class="card-body">
                <div class="table-container">
                    <table id="results-table">
                        <thead>
                            <tr>
                                <th>IOC</th>
                                <th>Type</th>
                                <th>Detections</th>
                                <th>Detection %</th>
                                <th>Severity</th>
                                <th>MS Defender</th>
                                <th>Category</th>
                                <th>Last Analysis</th>
                                <th>VT Link</th>
                            </tr>
                        </thead>
                        <tbody>
                            """ + all_results_rows + """
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
        
        <!-- Footer -->
        <div class="footer">
            <p>
                <i class="fas fa-shield-alt"></i> VirusTotal IOC Scanner | Scan completed in """ + scan_duration_str + """ 
                <span class="tooltip">
                    <i class="fas fa-info-circle"></i>
                    <span class="tooltiptext">Report generated at """ + datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + """</span>
                </span>
            </p>
        </div>
    </div>
    
    <script>
        // Client-side filtering functionality
        document.addEventListener('DOMContentLoaded', function() {
            console.log("DOM fully loaded, initializing filters...");
            
            // Get filter elements
            const iocTypeFilter = document.getElementById('ioc-type-filter');
            const severityFilter = document.getElementById('severity-filter');
            const msDetectionFilter = document.getElementById('ms-detection-filter');
            const searchInput = document.getElementById('search-input');
            const resultsTable = document.getElementById('results-table');
            const criticalTable = document.getElementById('critical-table');
            const msDetectionTable = document.getElementById('ms-detection-table');
            const msUnknownTable = document.getElementById('ms-unknown-table');
            const applyFiltersBtn = document.getElementById('apply-filters-btn');
            const resetFiltersBtn = document.getElementById('reset-filters-btn');
            
            // Log if any elements are missing
            if (!iocTypeFilter) console.log("Warning: ioc-type-filter element not found");
            if (!severityFilter) console.log("Warning: severity-filter element not found");
            if (!msDetectionFilter) console.log("Warning: ms-detection-filter element not found");
            if (!searchInput) console.log("Warning: search-input element not found");
            if (!resultsTable) console.log("Warning: results-table element not found");
            
            // Apply filters when values change
            if (iocTypeFilter) iocTypeFilter.addEventListener('change', applyFilters);
            if (severityFilter) severityFilter.addEventListener('change', applyFilters);
            if (msDetectionFilter) msDetectionFilter.addEventListener('change', applyFilters);
            if (searchInput) searchInput.addEventListener('input', applyFilters);
            if (applyFiltersBtn) applyFiltersBtn.addEventListener('click', applyFilters);
            
            // Reset filters
            if (resetFiltersBtn) {
                resetFiltersBtn.addEventListener('click', function() {
                    if (iocTypeFilter) iocTypeFilter.value = 'all';
                    if (severityFilter) severityFilter.value = 'all';
                    if (msDetectionFilter) msDetectionFilter.value = 'all';
                    if (searchInput) searchInput.value = '';
                    applyFilters();
                });
            }
            
            // Apply filters on page load with a slight delay
            setTimeout(applyFilters, 500);
            
            function applyFilters() {
                console.log("Applying filters...");
                try {
                    // Show loading indicator
                    showFilteringStatus(true);
                    
                    const iocType = iocTypeFilter ? iocTypeFilter.value : 'all';
                    const severity = severityFilter ? severityFilter.value : 'all';
                    const msDetection = msDetectionFilter ? msDetectionFilter.value : 'all';
                    const searchText = searchInput ? searchInput.value.toLowerCase() : '';
                    
                    console.log("Filter values:", { iocType, severity, msDetection, searchText });
                    
                    // Function to filter a table
                    function filterTable(table) {
                        if (!table) return 0;
                        
                        const rows = table.querySelectorAll('tbody tr');
                        let visibleCount = 0;
                        
                        rows.forEach(row => {
                            let showRow = true;
                            
                            const rowIocType = row.getAttribute('data-ioc-type');
                            const rowSeverity = row.getAttribute('data-severity');
                            const rowMsDetection = row.getAttribute('data-ms-detection');
                            
                            // Check IOC type filter
                            if (iocType !== 'all' && rowIocType !== iocType) {
                                showRow = false;
                            }
                            
                            // Check severity filter
                            if (severity !== 'all' && rowSeverity !== severity) {
                                showRow = false;
                            }
                            
                            // Check MS detection filter
                            if (msDetection !== 'all' && rowMsDetection !== msDetection) {
                                showRow = false;
                            }
                            
                            // Check search text
                            if (searchText) {
                                const rowText = row.textContent.toLowerCase();
                                if (!rowText.includes(searchText)) {
                                    showRow = false;
                                }
                            }
                            
                            // Show or hide the row
                            row.style.display = showRow ? '' : 'none';
                            if (showRow) visibleCount++;
                        });
                        
                        return visibleCount;
                    }
                    
                    // Apply filters to all tables
                    const resultsCount = filterTable(resultsTable);
                    const criticalCount = filterTable(criticalTable);
                    const msDetectionCount = filterTable(msDetectionTable);
                    const msUnknownCount = filterTable(msUnknownTable);
                    
                    console.log("Filtered counts:", { 
                        results: resultsCount, 
                        critical: criticalCount, 
                        msDetection: msDetectionCount,
                        msUnknown: msUnknownCount
                    });
                    
                    // Update the filter status
                    setTimeout(() => {
                        showFilteringStatus(false);
                        updateFilterStatus({
                            results: resultsCount,
                            critical: criticalCount,
                            msDetection: msDetectionCount,
                            msUnknown: msUnknownCount
                        });
                    }, 300);
                    
                } catch (err) {
                    console.error("Error applying filters:", err);
                    showFilteringStatus(false);
                }
            }
            
            // Show filtering status
            function showFilteringStatus(isFiltering) {
                const filterBtn = document.getElementById('apply-filters-btn');
                if (filterBtn) {
                    if (isFiltering) {
                        filterBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Filtering...';
                        filterBtn.disabled = true;
                    } else {
                        filterBtn.innerHTML = '<i class="fas fa-filter"></i> Apply Filters';
                        filterBtn.disabled = false;
                    }
                }
            }
            
            // Update filter status in the UI
            function updateFilterStatus(counts) {
                // Update results count in badge
                const resultsBadge = document.querySelector('#results-table')?.closest('.card')?.querySelector('.badge');
                if (resultsBadge) resultsBadge.textContent = counts.results;
                
                // Update critical count
                const criticalBadge = document.querySelector('#critical-table')?.closest('.card')?.querySelector('.badge');
                if (criticalBadge) criticalBadge.textContent = counts.critical;
                
                // Update MS detection count
                const msDetectionBadge = document.querySelector('#ms-detection-table')?.closest('.card')?.querySelector('.badge');
                if (msDetectionBadge) msDetectionBadge.textContent = counts.msDetection;
                
                // Update MS unknown count
                const msUnknownBadge = document.querySelector('#ms-unknown-table')?.closest('.card')?.querySelector('.badge');
                if (msUnknownBadge) msUnknownBadge.textContent = counts.msUnknown;
            }
            
            // Make sure tables have equal column widths
            function alignTableColumns() {
                if (!resultsTable) return;
                
                const tables = [
                    criticalTable,
                    msDetectionTable,
                    msUnknownTable
                ].filter(table => table);  // Filter out null tables
                
                // Get the column widths from the main table
                const mainTableHeaders = Array.from(resultsTable.querySelectorAll('th'));
                const columnWidths = mainTableHeaders.map(th => th.offsetWidth);
                
                // Apply to other tables
                tables.forEach(table => {
                    const headers = Array.from(table.querySelectorAll('th'));
                    headers.forEach((th, index) => {
                        if (index < columnWidths.length) {
                            th.style.width = columnWidths[index] + 'px';
                        }
                    });
                });
            }
            
            // Align table columns after a short delay
            setTimeout(alignTableColumns, 1000);
            
            // Handle window resize for better mobile experience
            window.addEventListener('resize', alignTableColumns);
        });
        
        // Fix Plotly rendering issues
        window.addEventListener('load', function() {
            console.log("Window loaded, checking Plotly charts...");
            
            // Make sure Plotly is available
            if (typeof Plotly === 'undefined') {
                console.error("Plotly library not loaded!");
                
                // Try to reload the script
                var script = document.createElement('script');
                script.src = 'https://cdn.plot.ly/plotly-latest.min.js';
                script.onload = function() {
                    console.log("Plotly loaded dynamically, redrawing charts...");
                    redrawCharts();
                };
                document.head.appendChild(script);
            } else {
                console.log("Plotly library found, redrawing charts...");
                // Force redraw of charts after a delay
                setTimeout(redrawCharts, 500);
            }
            
            function redrawCharts() {
                const charts = ['ioc-type-chart', 'severity-chart', 'ms-detection-chart'];
                charts.forEach(function(id) {
                    const chartDiv = document.getElementById(id);
                    console.log("Processing chart:", id);
                    
                    if (chartDiv) {
                        const plotlyDivs = chartDiv.getElementsByClassName('plotly-graph-div');
                        if (plotlyDivs && plotlyDivs.length > 0) {
                            Array.from(plotlyDivs).forEach(function(plotlyDiv) {
                                try {
                                    console.log("Relayouting chart:", plotlyDiv.id);
                                    Plotly.relayout(plotlyDiv, {
                                        autosize: true,
                                        'paper_bgcolor': 'rgba(0,0,0,0)',
                                        'plot_bgcolor': 'rgba(0,0,0,0)'
                                    }).then(function() {
                                        console.log("Chart relayouted successfully:", plotlyDiv.id);
                                    }).catch(function(err) {
                                        console.error("Error relayouting chart:", err);
                                    });
                                } catch (err) {
                                    console.error("Error processing chart:", err);
                                }
                            });
                        } else {
                            console.warn("No plotly-graph-div found in", id);
                        }
                    } else {
                        console.warn("Chart container not found:", id);
                    }
                });
            }
        });
    </script>
    </body>
    </html>
    """
    
    # Write the HTML report to file
    try:
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html_template)
        print(f"HTML report generated: {output_path}")
        
        # Try to open the report in a browser
        try:
            import webbrowser
            webbrowser.open('file://' + os.path.abspath(output_path))
        except:
            pass
            
    except Exception as e:
        print(f"Error generating HTML report: {str(e)}")
        return None
    
    return output_path

def save_api_key(api_key: str) -> None:
    """Save API key to config file with proper permissions"""
    config_dir = Path.home() / ".vtscanner"
    config_file = config_dir / "config.json"
    config_dir.mkdir(exist_ok=True)
    try:
        with open(config_file, 'w') as f:
            json.dump({"api_key": api_key}, f)
        # Set secure permissions
        os.chmod(config_file, 0o600)
        print(f"{GREEN}API key saved securely.{RESET}")
    except Exception as e:
        print(f"{RED}Error saving API key: {str(e)}{RESET}")


def load_api_key() -> Optional[str]:
    """Load API key from config file"""
    config_file = Path.home() / ".vtscanner" / "config.json"
    if config_file.exists():
        try:
            with open(config_file, 'r') as f:
                return json.load(f).get("api_key")
        except Exception as e:
            print(f"{RED}Error loading API key: {str(e)}{RESET}")
    return None


def sanitize_ioc(ioc: str) -> str:
    """Sanitize IOC to prevent any accidental execution or code injection"""
    if not isinstance(ioc, str):
        return str(ioc)
    
    # Remove any control characters and strip whitespace
    ioc = re.sub(r'[\x00-\x1f\x7f]', '', ioc).strip()
    
    # Escape HTML special characters
    ioc = ioc.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
    ioc = ioc.replace('"', '&quot;').replace("'", '&#x27;')
    
    return ioc


class IOCScanner:
    def __init__(self, api_key: str, max_workers: int = 10, scan_mode: str = 'premium'):
        self.api_key = api_key
        self.max_workers = max_workers
        self.scan_mode = scan_mode
        self.session = requests.Session()
        self.session.headers.update({"x-apikey": api_key, "User-Agent": "IOCScanner/5.0 (Premium)"})
        self.session.verify = False  # Disable SSL verification by default
        self.base_url = "https://www.virustotal.com/api/v3"
        self.total_iocs = 0
        self.malicious_count = 0
        self.suspicious_count = 0
        self.error_count = 0
        self.processed_iocs = set()
        self.last_request_time = 0
        self.scan_start_time = time.time()
        self.ioc_types = {}
        self.total_engines = 0
        self.critical_count = 0
        self.dataframe = None
        self.results_list = []

    def identify_ioc_type(self, ioc: str) -> str:
        """Identify the type of IOC (ip, domain, url, hash, email)"""
        if not isinstance(ioc, str) or not ioc.strip():
            return "unknown"
        
        ioc = ioc.strip().strip('"\'')
        
        # IP address
        if re.match(r"^(\d{1,3}\.){3}\d{1,3}$", ioc):
            try:
                if all(0 <= int(p) <= 255 for p in ioc.split('.')):
                    return "ip"
            except ValueError:
                pass
        
        # Email address
        if re.match(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", ioc):
            return "email"
        
        # Domain
        if re.match(r"^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$", ioc):
            return "domain"
        
        # URL
        if re.match(r"^https?://", ioc) or ioc.startswith("www.") or ("/" in ioc and "." in ioc):
            return "url"
        
        # Hash (MD5, SHA1, SHA256)
        if re.match(r"^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$", ioc):
            return "hash"
        
        return "unknown"

    def print_detection_bar(self, positives: int, total: int) -> None:
        """Print a visual detection bar in the console"""
        if total == 0:
            return
            
        ratio = positives / total
        width = 30  # width of the bar
        filled_width = int(width * ratio)
        
        if ratio > 0.5:
            color = RED
            severity = f"{BG_RED}{BOLD} CRITICAL {RESET}"
        elif ratio > 0.25:
            color = YELLOW
            severity = f"{BG_YELLOW}{BOLD} HIGH {RESET}"
        elif ratio > 0:
            color = BLUE
            severity = f"{BLUE}{BOLD} MEDIUM {RESET}"
        else:
            color = GREEN
            severity = f"{BG_GREEN}{BOLD} CLEAN {RESET}"
            
        bar = f"{color}{'█' * filled_width}{RESET}{'░' * (width - filled_width)}"
        percentage = f"{ratio:.1%}"
        
        print(f"  Detection: {bar} {percentage} {severity}")

    def check_ioc(self, ioc: str, ioc_type: Optional[str] = None) -> Dict:
        """Check an IOC against VirusTotal API with optimization for Premium API"""
        if not isinstance(ioc, str):
            return {"ioc": str(ioc), "ioc_type": "unknown", "error": "Invalid IOC format"}
            
        # Sanitize the IOC to prevent any execution or injection
        original_ioc = ioc
        ioc = sanitize_ioc(ioc.strip().strip("'\""))
        
        if not ioc or ioc in self.processed_iocs:
            return {"ioc": ioc, "ioc_type": "unknown", "error": "Empty or duplicate IOC"}
        
        self.processed_iocs.add(ioc)
        self.total_iocs += 1

        if not ioc_type or ioc_type == "unknown":
            ioc_type = self.identify_ioc_type(ioc)
            
        # Track IOC types distribution
        self.ioc_types[ioc_type] = self.ioc_types.get(ioc_type, 0) + 1
        
        if ioc_type == "unknown":
            self.error_count += 1
            return {"ioc": ioc, "ioc_type": "unknown", "error": "Unknown IOC type", "vt_link": ""}
            
        # Skip email scanning directly as it's not supported by VirusTotal API
        if ioc_type == "email":
            # For emails, we'll handle domain part separately
            domain_part = ioc.split('@')[-1]
            if domain_part:
                print(f"\n{YELLOW}Email detected: {ioc}, checking domain part: {domain_part}{RESET}")
                domain_result = self.check_ioc(domain_part, "domain")
                # Add the email result but mark it properly
                email_result = {
                    "ioc": original_ioc,
                    "ioc_type": "email",
                    "email_domain": domain_part,
                    "vt_link": domain_result.get("vt_link", ""),
                    "vt_positives": domain_result.get("vt_positives", 0),
                    "vt_total": domain_result.get("vt_total", 0),
                    "vt_detection_ratio": domain_result.get("vt_detection_ratio", "0/0"),
                    "vt_detection_percentage": domain_result.get("vt_detection_percentage", 0),
                    "vt_malicious": domain_result.get("vt_malicious", 0),
                    "vt_suspicious": domain_result.get("vt_suspicious", 0),
                    "vt_harmless": domain_result.get("vt_harmless", 0),
                    "vt_undetected": domain_result.get("vt_undetected", 0),
                    "vt_last_analysis_date": domain_result.get("vt_last_analysis_date", ""),
                    "category": f"Email Domain: {domain_result.get('category', '')}",
                    "detection_names": domain_result.get("detection_names", ""),
                    "error": ""
                }
                return email_result
            else:
                self.error_count += 1
                return {"ioc": ioc, "ioc_type": "email", "error": "Invalid email format", "vt_link": ""}

        # Premium API has higher rate limits, but we'll still implement a minimal delay
        # between requests to prevent overwhelming the API
        if self.scan_mode == "premium":
            elapsed = time.time() - self.last_request_time
            if elapsed < 0.5 and self.last_request_time > 0:  # 0.5 seconds between requests
                time.sleep(0.5 - elapsed)
        else:
            # Standard API rate limiting
            elapsed = time.time() - self.last_request_time
            if elapsed < 15 and self.last_request_time > 0:
                time.sleep(15 - elapsed)
                
        self.last_request_time = time.time()

        # Set up the appropriate endpoint and link
        endpoint = ""
        vt_link = ""
        
        if ioc_type == "ip":
            endpoint = f"{self.base_url}/ip_addresses/{ioc}"
            vt_link = f"https://www.virustotal.com/gui/ip-address/{ioc}"
        elif ioc_type == "domain":
            endpoint = f"{self.base_url}/domains/{ioc}"
            vt_link = f"https://www.virustotal.com/gui/domain/{ioc}"
        elif ioc_type == "url":
            if ioc.startswith("www."):
                ioc = "http://" + ioc
            try:
                encoded_url = base64.urlsafe_b64encode(ioc.encode()).decode().strip("=")
                endpoint = f"{self.base_url}/urls/{encoded_url}"
                vt_link = f"https://www.virustotal.com/gui/url/{encoded_url}"
            except Exception as e:
                self.error_count += 1
                return {"ioc": ioc, "ioc_type": ioc_type, "error": f"URL encoding error: {str(e)}", "vt_link": ""}
        elif ioc_type == "hash":
            endpoint = f"{self.base_url}/files/{ioc}"
            vt_link = f"https://www.virustotal.com/gui/file/{ioc}"

        # Make the API request with retries
        max_retries = 3
        for attempt in range(max_retries):
            try:
                response = self.session.get(endpoint, timeout=30)
                
                if response.status_code == 429:
                    print(f"{YELLOW}Rate limited. Waiting 60 seconds...{RESET}")
                    time.sleep(60)
                    continue
                    
                response.raise_for_status()
                result = response.json()

                # Parse the response
                data = result.get("data", {})
                attributes = data.get("attributes", {})
                stats = attributes.get("last_analysis_stats", {})
                
                malicious = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)
                harmless = stats.get("harmless", 0)
                undetected = stats.get("undetected", 0)
                total = sum(stats.values()) or 1  # Avoid division by zero
                
                # Keep track of average engines count for reporting
                if self.total_engines == 0:
                    self.total_engines = total
                else:
                    self.total_engines = (self.total_engines + total) / 2
                
                detection_percentage = ((malicious + suspicious) / total) * 100
                detection_ratio = f"{malicious + suspicious}/{total}"
                
                # Get last analysis date
                last_analysis_date = (
                    datetime.fromtimestamp(attributes["last_analysis_date"]).strftime('%Y-%m-%d %H:%M:%S')
                    if attributes.get("last_analysis_date") else ""
                )
                
                # Get category/type details for domains and IPs
                category = ""
                if ioc_type == "domain" or ioc_type == "ip":
                    category = attributes.get("categories", {}).get("Webroot", "")
                    
                    if not category and attributes.get("category"):
                        category = attributes.get("category")
                
                # Get more details for files
                file_type = ""
                file_size = ""
                if ioc_type == "hash":
                    file_type = attributes.get("type_description", "")
                    file_size = attributes.get("size", 0)
                    
                # Get detection names for malicious/suspicious indicators
                detection_names = []
                if malicious + suspicious > 0 and "last_analysis_results" in attributes:
                    results = attributes["last_analysis_results"]
                    for engine, engine_result in results.items():
                        if engine_result.get("category") in ["malicious", "suspicious"]:
                            detection_name = engine_result.get("result", "")
                            if detection_name:
                                detection_names.append(f"{engine}: {detection_name}")

                if malicious + suspicious > 0:
                    if malicious > 0:
                        self.malicious_count += 1
                    else:
                        self.suspicious_count += 1
                        
                    # Count critical findings
                    if (malicious + suspicious) / total > 0.5:
                        self.critical_count += 1
                
                # Build enhanced result object
                result = {
                    "ioc": original_ioc,  # Use original for display
                    "ioc_type": ioc_type,
                    "vt_positives": malicious + suspicious,
                    "vt_total": total,
                    "vt_detection_ratio": detection_ratio,
                    "vt_detection_percentage": detection_percentage,
                    "vt_malicious": malicious,
                    "vt_suspicious": suspicious,
                    "vt_harmless": harmless,
                    "vt_undetected": undetected,
                    "vt_link": vt_link,
                    "vt_last_analysis_date": last_analysis_date,
                    "category": category,
                    "file_type": file_type,
                    "file_size": file_size,
                    "detection_names": "; ".join(detection_names[:5]),  # Limit to top 5
                    "error": ""
                }
                
                # Print detection information for malicious IOCs
                if malicious + suspicious > 0:
                    if ioc_type == "url" or ioc_type == "domain":
                        # Mask the actual URL/domain in terminal output for safety
                        masked_ioc = original_ioc[:5] + "*****" + original_ioc[-5:] if len(original_ioc) > 10 else original_ioc
                        print(f"\n{BOLD}{masked_ioc}{RESET} ({ioc_type}):")
                    else:
                        print(f"\n{BOLD}{original_ioc}{RESET} ({ioc_type}):")
                    
                    self.print_detection_bar(malicious + suspicious, total)
                
                return result
                
            except requests.exceptions.RequestException as e:
                if attempt < max_retries - 1 and not str(e).startswith("404"):
                    print(f"{YELLOW}Attempt {attempt+1} failed: {str(e)}. Retrying...{RESET}")
                    time.sleep(5)
                else:
                    self.error_count += 1
                    error_message = str(e)
                    if "404" in error_message:
                        error_message = "Not found in VirusTotal database"
                    
                    return {
                        "ioc": original_ioc, 
                        "ioc_type": ioc_type, 
                        "error": f"API error: {error_message}", 
                        "vt_link": vt_link,
                        "vt_positives": 0,
                        "vt_total": 0,
                        "vt_detection_ratio": "0/0",
                        "vt_detection_percentage": 0
                    }

    def process_file(self, file_path: str, output_path: str = None) -> List[Dict]:
        """Process a file containing IOCs with premium API optimizations"""
        file_path = Path(file_path)
        
        # Determine output path for CSV export
        if not output_path:
            # Use the directory of the script file
            script_dir = Path(sys.argv[0]).resolve().parent
            output_name = f"{file_path.stem}_vt_report.csv"
            output_path = script_dir / output_name
        else:
            output_path = Path(output_path)

        # Parse the file containing IOCs
        iocs = []
        try:
            # Try to determine file type by extension
            file_ext = file_path.suffix.lower()
            
            if file_ext in ['.xlsx', '.xls']:
                # Excel file
                try:
                    import pandas as pd
                    df = pd.read_excel(file_path)
                    # Look for columns that might contain IOCs
                    potential_ioc_cols = []
                    for col in df.columns:
                        if any(kw in col.lower() for kw in ['ioc', 'indicator', 'ip', 'domain', 'url', 'hash', 'md5', 'sha', 'email']):
                            potential_ioc_cols.append(col)
                    
                    # If no obvious IOC columns, use all columns
                    if not potential_ioc_cols:
                        potential_ioc_cols = df.columns
                    
                    # Extract IOCs from the dataframe
                    for col in potential_ioc_cols:
                        for value in df[col].dropna():
                            value = str(value).strip()
                            if value and not value.startswith('#'):
                                ioc_type = self.identify_ioc_type(value)
                                iocs.append({"ioc": value, "ioc_type": ioc_type})
                except Exception as e:
                    print(f"{RED}Error reading Excel file: {str(e)}{RESET}")
            else:
                # Treat as text file (CSV, TXT, etc.)
                with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            ioc_type = self.identify_ioc_type(line)
                            iocs.append({"ioc": line, "ioc_type": ioc_type})
        except Exception as e:
            print(f"{RED}Error reading file: {str(e)}{RESET}")
            return []

        if not iocs:
            print(f"{RED}No valid IOCs found in file.{RESET}")
            return []

        print(f"{BLUE}Found {len(iocs)} IOCs to check.{RESET}")
        
        # Count IOCs by type
        ioc_types = {}
        for ioc in iocs:
            ioc_type = ioc.get("ioc_type", "unknown")
            ioc_types[ioc_type] = ioc_types.get(ioc_type, 0) + 1
            
        print(f"\n{BOLD}IOC Types:{RESET}")
        for ioc_type, count in sorted(ioc_types.items()):
            print(f"  {ioc_type}: {count}")

        # Process the IOCs in parallel with a progress bar - use more workers for Premium API
        results = []
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {executor.submit(self.check_ioc, ioc["ioc"], ioc.get("ioc_type")): ioc for ioc in iocs}
            
            with tqdm(total=len(iocs), desc="Checking IOCs") as pbar:
                for future in as_completed(futures):
                    result = future.result()
                    if result:
                        results.append(result)
                    pbar.update(1)
                    pbar.set_description(f"Checking IOCs (Malicious: {self.malicious_count}/{self.total_iocs})")

        self.results_list = results
        
        # Calculate scan duration
        scan_duration = time.time() - self.scan_start_time
        scan_duration_str = f"{int(scan_duration // 60)}m {int(scan_duration % 60)}s"
        
        # Convert to DataFrame for easier processing
        try:
            self.dataframe = pd.DataFrame(results)
            
            # Ensure vt_detection_percentage is numeric
            if 'vt_detection_percentage' in self.dataframe.columns:
                self.dataframe['vt_detection_percentage'] = pd.to_numeric(
                    self.dataframe['vt_detection_percentage'], errors='coerce')
        except Exception as e:
            print(f"{RED}Error creating DataFrame: {str(e)}{RESET}")
        
        # Export results to CSV
        if hasattr(self, 'dataframe') and self.dataframe is not None and not self.dataframe.empty:
            try:
                self.dataframe.to_csv(output_path, index=False)
                print(f"\n{GREEN}Results exported to CSV: {output_path}{RESET}")
            except Exception as e:
                print(f"{RED}Error exporting to CSV: {str(e)}{RESET}")
        
        # Print summary
        clean_count = self.total_iocs - self.malicious_count - self.suspicious_count - self.error_count
        
        print(f"\n{BOLD}Scan Summary:{RESET}")
        print(f"Total IOCs checked: {self.total_iocs}")
        print(f"Malicious IOCs: {self.malicious_count}")
        print(f"Suspicious IOCs: {self.suspicious_count}")
        print(f"Clean IOCs: {clean_count}")
        print(f"Errors: {self.error_count}")
        print(f"Scan duration: {scan_duration_str}")
        
        if self.malicious_count > 0:
            print(f"\n{RED}{BOLD}⚠️ IMPORTANT: {self.critical_count} critical threats detected!{RESET}")
            
        return results
    
    def generate_html_report(self, input_filename: str, output_path: str = None) -> str:
        """Generate an HTML report from the scan results"""
        if not self.results_list:
            print(f"{RED}No results to display.{RESET}")
            return None
        
        # Prepare scan stats dictionary for the report
        scan_stats = {
            'total_iocs': self.total_iocs,
            'malicious_count': self.malicious_count,
            'suspicious_count': self.suspicious_count,
            'error_count': self.error_count,
            'critical_count': self.critical_count,
            'scan_start_time': self.scan_start_time,
            'total_engines': self.total_engines
        }
        
        # Generate HTML report
        report_path = generate_html_report(
            self.results_list, 
            scan_stats, 
            output_path=output_path, 
            input_filename=input_filename
        )
        
        return report_path


class BatchIOCScanner:
    """
    A class for processing IOCs in batch mode for Premium API usage efficiency
    Optimized for higher throughput with the Premium API
    """
    
    def __init__(self, api_key: str, batch_size: int = 100):
        self.api_key = api_key
        self.batch_size = batch_size
        self.session = requests.Session()
        self.session.headers.update({"x-apikey": api_key, "User-Agent": "BatchIOCScanner/1.0 (Premium)"})
        self.session.verify = False
        self.base_url = "https://www.virustotal.com/api/v3"
        
    def batch_process_hashes(self, hashes: List[str]) -> Dict:
        """Process a batch of file hashes using Premium API's batch endpoint"""
        if not hashes:
            return {}
        
        url = f"{self.base_url}/files"
        data = {"data": {"hashes": hashes}}
        
        try:
            response = self.session.post(url, json=data)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            print(f"{RED}Error in batch processing: {str(e)}{RESET}")
            return {}
    
    def batch_process_urls(self, urls: List[str]) -> Dict:
        """Process a batch of URLs using Premium API's batch endpoint"""
        if not urls:
            return {}
        
        # Encode URLs
        encoded_urls = []
        for url in urls:
            try:
                if url.startswith("www."):
                    url = "http://" + url
                encoded_url = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
                encoded_urls.append(encoded_url)
            except Exception as e:
                print(f"{RED}Error encoding URL {url}: {str(e)}{RESET}")
                
        if not encoded_urls:
            return {}
            
        url = f"{self.base_url}/urls/batch"
        data = {"data": {"urls": encoded_urls}}
        
        try:
            response = self.session.post(url, json=data)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            print(f"{RED}Error in batch processing: {str(e)}{RESET}")
            return {}
            
    def batch_process_ips(self, ips: List[str]) -> Dict:
        """Process a batch of IPs using Premium API endpoint"""
        # Note: VT API doesn't have a batch endpoint for IPs, but we can use multiple requests with higher rate limits
        results = {}
        for ip in ips:
            try:
                url = f"{self.base_url}/ip_addresses/{ip}"
                response = self.session.get(url)
                response.raise_for_status()
                results[ip] = response.json()
            except requests.exceptions.RequestException as e:
                print(f"{YELLOW}Error processing IP {ip}: {str(e)}{RESET}")
                results[ip] = {"error": str(e)}
        return results
    
    def batch_process_domains(self, domains: List[str]) -> Dict:
        """Process a batch of domains using Premium API endpoint"""
        # Note: VT API doesn't have a batch endpoint for domains, but we can use multiple requests with higher rate limits
        results = {}
        for domain in domains:
            try:
                url = f"{self.base_url}/domains/{domain}"
                response = self.session.get(url)
                response.raise_for_status()
                results[domain] = response.json()
            except requests.exceptions.RequestException as e:
                print(f"{YELLOW}Error processing domain {domain}: {str(e)}{RESET}")
                results[domain] = {"error": str(e)}
        return results


def main():
    """Main function"""
    print(f"{BOLD}{'=' * 60}{RESET}")
    print(f"{BOLD}Enhanced VirusTotal IOC Scanner (Premium Version){RESET}")
    print(f"{BOLD}{'=' * 60}{RESET}")
    print(f"\n{BLUE}This tool uses the Premium VirusTotal API for high-throughput scanning.{RESET}")
    print(f"{YELLOW}Features static HTML report generation and enhanced visualizations.{RESET}")
    
    # Get API key
    api_key = load_api_key() or os.environ.get("VT_API_KEY")
    if api_key:
        if input(f"\n{BOLD}Use saved API key? (Y/n): {RESET}").lower() == 'n':
            api_key = getpass.getpass(f"{BOLD}Enter your VirusTotal Premium API key: {RESET}")
    else:
        print(f"\n{YELLOW}No saved API key found.{RESET}")
        api_key = getpass.getpass(f"{BOLD}Enter your VirusTotal Premium API key: {RESET}")

    if not api_key:
        print(f"{RED}Error: No API key provided. Exiting.{RESET}")
        sys.exit(1)

    if not load_api_key() and input(f"{BOLD}Save this API key? (Y/n): {RESET}").lower() != 'n':
        save_api_key(api_key)
        print(f"{GREEN}API key saved successfully.{RESET}")

    # Get input file
    input_file = ""
    while not input_file or not os.path.exists(input_file):
        input_file = input(f"\n{BOLD}Enter the path to your IOC file: {RESET}")
        if not input_file:
            print(f"{RED}Please enter a valid file path.{RESET}")
        elif not os.path.exists(input_file):
            print(f"{RED}File not found: {input_file}{RESET}")

    # Get output file for CSV
    csv_output_file = input(f"\n{BOLD}Enter output CSV file path (Enter for default): {RESET}")
    
    # Get output file for HTML report
    html_output_file = input(f"\n{BOLD}Enter output HTML file path (Enter for default): {RESET}")
    
    # Worker configuration
    max_workers = 10  # Default for Premium API
    try:
        worker_input = input(f"\n{BOLD}Enter max number of parallel workers (default: 10): {RESET}")
        if worker_input.strip():
            max_workers = int(worker_input)
            if max_workers < 1:
                max_workers = 1
            elif max_workers > 20:
                print(f"{YELLOW}Large number of workers may lead to unstable performance. Capping at 20.{RESET}")
                max_workers = 20
    except ValueError:
        print(f"{YELLOW}Invalid input. Using default value of 10 workers.{RESET}")
    
    print(f"\n{BLUE}Starting scan with {max_workers} worker{'' if max_workers == 1 else 's'}...{RESET}")
    
    # Initialize scanner and process file
    scanner = IOCScanner(api_key, max_workers=max_workers, scan_mode="premium")
    results = scanner.process_file(input_file, csv_output_file)
    
    # Generate HTML report if there are results
    if results:
        html_path = scanner.generate_html_report(input_file, html_output_file)
        if html_path:
            print(f"\n{GREEN}HTML report generated: {html_path}{RESET}")
    
    print(f"\n{GREEN}Thank you for using the Enhanced VirusTotal IOC Scanner!{RESET}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n{YELLOW}Process interrupted by user. Exiting.{RESET}")
        sys.exit(0)
    except Exception as e:
        print(f"\n{RED}An unexpected error occurred: {str(e)}{RESET}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
