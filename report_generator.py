"""
VirusTotal IOC Scanner HTML Report Generator

This module handles the generation of HTML reports for the VirusTotal IOC Scanner.
It includes functionality for creating interactive visualizations, severity indicators,
copy functionality for IOCs, and a responsive HTML template with filtering capabilities.
"""

import os
import html
import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

try:
    import pandas as pd
    import plotly.express as px
except ImportError:
    print("Missing required packages. Please install with: pip install pandas plotly")
    raise

# Setup logging
logger = logging.getLogger(__name__)

# Color palette for charts and styling
COLORS = {
    'primary': '#4361ee', 'secondary': '#555555', 'success': '#4cc9f0', 
    'info': '#4895ef', 'warning': '#f9c74f', 'danger': '#f72585',
    'light': '#e0e1dd', 'dark': '#1e1e1e', 'background': '#0b0c10',
    'card_bg': '#1f2833', 'text': '#ffffff', 
    'ms_known': '#e63946', 'ms_unknown': '#6c757d'
}

def sanitize_for_html(text):
    """Safely encode a string for HTML output"""
    if not isinstance(text, str):
        text = str(text)
    return html.escape(text)

def get_severity_class(severity: str) -> str:
    """Return the CSS class for the given severity level"""
    severity_classes = {
        'Critical': 'severity-Critical', 'High': 'severity-High',
        'Medium': 'severity-Medium', 'Clean': 'severity-Clean',
        'Error': 'severity-Error'
    }
    return severity_classes.get(severity, '')

def get_severity_badge(severity: str) -> str:
    """Return HTML for a severity badge"""
    badge_classes = {
        'Critical': 'badge badge-danger', 'High': 'badge badge-warning',
        'Medium': 'badge badge-info', 'Clean': 'badge badge-success',
        'Error': 'badge badge-secondary'
    }
    return f"<span class='{badge_classes[severity]}'>{severity}</span>" if severity in badge_classes else ""

def get_ms_defender_span(status: str) -> str:
    """Return HTML for MS Defender status"""
    if status == "known":
        return '<span class="ms-known"><i class="fas fa-shield-alt"></i> known</span>'
    return '<span class="ms-unknown"><i class="fas fa-question-circle"></i> unknown</span>'

def has_microsoft_detection(detection_string: str) -> bool:
    """Check if a detection string contains Microsoft detection information"""
    if not detection_string or not isinstance(detection_string, str):
        return False
    
    microsoft_patterns = [
        'microsoft:', 'microsoft/', 'trojan:win32', 'trojan.win32', 'microsoft ',
        'ms defender', 'msdefender', 'msft', 'defender:', 'defender.', 'windows defender'
    ]
    
    detection_lower = detection_string.lower()
    return any(pattern in detection_lower for pattern in microsoft_patterns)

def generate_html_report(results_list: List[Dict], scan_stats: Dict, output_path: Optional[str] = None, input_filename: str = "IOCs") -> Optional[str]:
    """Generate a static HTML report from scan results"""
    if not results_list:
        logger.warning("No results to display.")
        return None
    
    # Process and sanitize data
    results_list_copy = [{k: sanitize_for_html(v) if isinstance(v, str) else v for k, v in result.items() 
                         if k != 'last_analysis_results'} for result in results_list]
    df = pd.DataFrame(results_list_copy)
    
    # Convert detection percentage to numeric
    if 'vt_detection_percentage' in df.columns:
        df['vt_detection_percentage'] = pd.to_numeric(df['vt_detection_percentage'], errors='coerce').round(1)
    
    # Determine severity based on detection percentage
    def get_severity(row):
        if pd.notna(row.get("error")) and row.get("error"):
            return "Error"
        if "vt_detection_percentage" not in row or pd.isna(row["vt_detection_percentage"]):
            return "Error"
        if row["vt_detection_percentage"] > 50: return "Critical"
        if row["vt_detection_percentage"] > 25: return "High"
        if row["vt_detection_percentage"] > 0: return "Medium"
        return "Clean"
    
    df["severity"] = df.apply(get_severity, axis=1)
    df = df.fillna("N/A")
    
    # Extract Microsoft Defender status
    def get_ms_defender_status(row):
        if 'ms_defender' in row and row['ms_defender'] in ['known', 'unknown']:
            return row['ms_defender']
        if 'detection_names' in row and isinstance(row['detection_names'], str):
            if has_microsoft_detection(row['detection_names']):
                return 'known'
        return 'unknown'
    
    if 'ms_defender' not in df.columns:
        df["ms_defender"] = df.apply(get_ms_defender_status, axis=1)
    
    # Prepare summary data for charts
    ioc_type_counts = df["ioc_type"].value_counts().reset_index()
    ioc_type_counts.columns = ["IOC Type", "Count"]
    
    severity_counts = df["severity"].value_counts().reset_index()
    severity_counts.columns = ["Severity", "Count"]
    
    ms_defender_counts = df["ms_defender"].value_counts().reset_index()
    ms_defender_counts.columns = ["Status", "Count"]
    
    # Extract stats from scan_stats or calculate from data
    total_iocs = scan_stats.get('total_iocs', len(df))
    malicious_count = scan_stats.get('malicious_count', df[df["severity"] == "Critical"].shape[0])
    suspicious_count = scan_stats.get('suspicious_count', df[df["severity"] == "High"].shape[0])
    error_count = scan_stats.get('error_count', df[df["severity"] == "Error"].shape[0])
    clean_count = total_iocs - malicious_count - suspicious_count - error_count
    
    ms_known_count = df[df["ms_defender"] == "known"].shape[0]
    ms_unknown_count = df[df["ms_defender"] == "unknown"].shape[0]
    
    scan_duration = datetime.now().timestamp() - scan_stats.get('scan_start_time', datetime.now().timestamp())
    scan_duration_str = f"{int(scan_duration // 60)}m {int(scan_duration % 60)}s"
    
    # Create output path if not provided
    if not output_path:
        timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        report_filename = f"{Path(input_filename).stem}_vt_report_{timestamp}.html"
        output_path = str(Path.cwd() / report_filename)
    
    # Create charts
    ioc_type_fig = px.bar(
        ioc_type_counts, 
        x='IOC Type', y='Count', color='IOC Type',
        text='Count', color_discrete_sequence=px.colors.qualitative.Bold,
        category_orders={"IOC Type": sorted(df["ioc_type"].unique())}
    )
    ioc_type_fig.update_layout(
        template='plotly_dark',
        paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)',
        margin=dict(l=20, r=20, t=30, b=20), height=350,
        legend=dict(orientation="h", yanchor="bottom", y=-0.25, xanchor="center", x=0.5),
        xaxis=dict(title=dict(text="IOC Type", font=dict(size=14)), tickfont=dict(size=12)),
        yaxis=dict(title=dict(text="Count", font=dict(size=14)), tickfont=dict(size=12))
    )
    ioc_type_fig.update_traces(textposition='auto', textfont=dict(size=14))
    
    # Severity chart
    severity_colors = {
        'Critical': COLORS['danger'], 'High': COLORS['warning'],
        'Medium': COLORS['info'], 'Clean': COLORS['success'],
        'Error': COLORS['secondary']
    }
    
    severity_fig = px.pie(
        severity_counts, names='Severity', values='Count',
        color='Severity', color_discrete_map=severity_colors, hole=0.4
    )
    severity_fig.update_layout(
        template='plotly_dark', paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)',
        margin=dict(l=20, r=20, t=30, b=20), height=350, showlegend=True,
        legend=dict(font=dict(size=12), orientation="h", yanchor="bottom", y=-0.25, xanchor="center", x=0.5),
        annotations=[dict(text="Severity", font=dict(size=16), showarrow=False)]
    )
    
    # MS Defender chart
    ms_defender_fig = px.pie(
        ms_defender_counts, names='Status', values='Count',
        color='Status', color_discrete_map={
            'known': COLORS['ms_known'], 'unknown': COLORS['ms_unknown'], 'N/A': COLORS['secondary']
        }, hole=0.4
    )
    ms_defender_fig.update_layout(
        template='plotly_dark', paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)',
        margin=dict(l=20, r=20, t=30, b=20), height=350, showlegend=True,
        legend=dict(font=dict(size=12), orientation="h", yanchor="bottom", y=-0.25, xanchor="center", x=0.5),
        annotations=[dict(text="MS Defender", font=dict(size=16), showarrow=False)]
    )
    
    # Prepare data for tables
    critical_df = df[df['severity'].isin(['Critical', 'High'])]
    ms_known_df = df[df['ms_defender'] == 'known']
    ms_unknown_df = df[df['ms_defender'] == 'unknown']
    
    # Generate table rows
    def generate_row(row, idx, with_ms_defender=True, with_metadata=False):
        vt_link = row.get('vt_link', '')
        if not isinstance(vt_link, str) or not vt_link.startswith(('http://', 'https://')):
            vt_link = ''
            
        error_display = ""
        if pd.notna(row.get('error')) and row.get('error'):
            error_display = f'<div class="error-msg">{row["error"]}</div>'
            
        basic_cols = f"""
                <td>
                    <div class="ioc-container">
                        <span class="ioc-value">{row['ioc']}</span>
                        <button class="copy-btn" onclick="copyToClipboard('{row['ioc']}')">
                            <i class="fas fa-copy"></i>
                        </button>
                    </div>
                    {error_display}
                </td>
                <td>{row['ioc_type']}</td>
                <td>{row.get('vt_detection_percentage', 'N/A')}</td>
                <td class="{get_severity_class(row['severity'])}">{row['severity']} {get_severity_badge(row['severity'])}</td>
        """
        
        if with_ms_defender:
            basic_cols += f"<td>{get_ms_defender_span(row.get('ms_defender', 'unknown'))}</td>"
            
        basic_cols += f"""
                <td>{row.get('detection_names', '')}</td>
                <td><a href='{vt_link}' target='_blank'>Investigate</a></td>
        """
        
        if with_metadata:
            return f"""
            <tr class="{'bg-ms-known' if row['ms_defender'] == 'known' else ''}" data-ioc-type="{row['ioc_type']}" data-severity="{row['severity']}" data-ms-detection="{row['ms_defender']}" data-ioc-index="{idx}">
                {basic_cols}
                <td>{row.get('vt_detection_ratio', 'N/A')}</td>
                <td>{row.get('category', '')}</td>
                <td>{row.get('vt_last_analysis_date', 'N/A')}</td>
                <td><a href='{vt_link}' target='_blank'>View</a></td>
            </tr>
            """
        
        return f"""
        <tr data-ioc-type="{row['ioc_type']}" data-severity="{row['severity']}" data-ms-detection="{row['ms_defender']}" data-ioc-index="{idx}">
            {basic_cols}
        </tr>
        """
    
    # Generate table HTML
    critical_rows = "".join([generate_row(row, idx) for idx, row in critical_df.iterrows()])
    ms_detection_rows = "".join([generate_row(row, idx, with_ms_defender=False) for idx, row in ms_known_df.iterrows()])
    ms_unknown_rows = "".join([generate_row(row, idx, with_ms_defender=False) for idx, row in ms_unknown_df.iterrows()])
    all_results_rows = "".join([generate_row(row, idx, with_ms_defender=True, with_metadata=True) for idx, row in df.iterrows()])
    
    # Create dropdown options
    ioc_type_options = "".join([f'<option value="{ioc_type}">{ioc_type}</option>' for ioc_type in sorted(df['ioc_type'].unique())])
    severity_options = "".join([f'<option value="{severity}">{severity}</option>' for severity in ['Critical', 'High', 'Medium', 'Clean', 'Error'] if severity in df['severity'].unique()])
    
    # Prepare export data
    export_data = []
    for _, row in df.iterrows():
        export_row = {k: v for k, v in row.items() if k != 'last_analysis_results'}
        export_data.append(export_row)
    
    # Convert to JSON for the CSV export functionality
    csv_export_data = json.dumps(export_data)
    
    # HTML template with all styles directly embedded
    html_template = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>VirusTotal Scan Results - {input_filename}</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/5.15.4/css/all.min.css">
    <script src="https://cdn.plot.ly/plotly-latest.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/jquery/3.6.0/jquery.min.js"></script>
    <style>
        body {{ 
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
            background-color: #0b0c10; 
            color: #ffffff; 
            margin: 0; 
            padding: 0; 
        }}
        .container {{ width: 95%; margin: 0 auto; padding: 20px; }}
        .header {{ text-align: center; margin-bottom: 30px; color: #4361ee; padding: 20px 0; border-bottom: 1px solid #4361ee; }}
        .header h1 {{ font-size: 2.5rem; margin-bottom: 10px; }}
        .header p {{ font-size: 1.1rem; opacity: 0.8; }}
        .card {{ background-color: #1f2833; border-radius: 8px; box-shadow: 0 4px 12px rgba(0, 0, 0, 0.4); margin-bottom: 25px; overflow: hidden; transition: all 0.3s ease; }}
        .card:hover {{ box-shadow: 0 6px 16px rgba(0, 0, 0, 0.6); transform: translateY(-2px); }}
        .card-header {{ background-color: #1f2833; color: #e0e1dd; padding: 15px 20px; font-weight: bold; font-size: 1.2rem; border-bottom: 2px solid rgba(255, 255, 255, 0.1); display: flex; justify-content: space-between; align-items: center; }}
        .card-header .actions {{ display: flex; gap: 10px; }}
        .card-body {{ padding: 20px; }}
        .row {{ display: flex; flex-wrap: wrap; margin: 0 -15px; gap: 0; }}
        .col {{ flex: 1; padding: 0 15px; min-width: 250px; margin-bottom: 20px; }}
        .stats-card {{ text-align: center; padding: 20px 15px; height: 100%; display: flex; flex-direction: column; justify-content: center; align-items: center; transition: transform 0.2s ease; }}
        .stats-card:hover {{ transform: scale(1.02); }}
        .stats-card i {{ margin-bottom: 10px; opacity: 0.9; }}
        .stats-card h4 {{ margin-top: 5px; margin-bottom: 15px; font-size: 1.1rem; opacity: 0.9; }}
        .stats-card h2 {{ font-size: 2.8rem; margin: 0; font-weight: 600; }}
        .table-container {{ overflow-x: auto; border-radius: 4px; box-shadow: 0 2px 8px rgba(0, 0, 0, 0.2) inset; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 10px; overflow: hidden; }}
        th, td {{ padding: 12px 15px; text-align: left; border: 1px solid #444; }}
        th {{ background-color: #4361ee; color: white; font-weight: 600; position: sticky; top: 0; box-shadow: 0 2px 2px rgba(0, 0, 0, 0.1); }}
        tr:nth-child(even) {{ background-color: rgba(255, 255, 255, 0.05); }}
        tr:hover {{ background-color: rgba(255, 255, 255, 0.1); }}
        .chart-container {{ width: 100%; margin-top: 15px; position: relative; }}
        .footer {{ text-align: center; margin-top: 40px; padding: 20px 0; border-top: 1px solid #555555; color: #e0e1dd; font-size: 1.1rem; }}
        .ioc-container {{ display: flex; align-items: center; justify-content: space-between; gap: 5px; }}
        .ioc-value {{ max-width: calc(100% - 30px); overflow: hidden; text-overflow: ellipsis; }}
        .copy-btn {{ background: none; border: none; color: #4361ee; cursor: pointer; padding: 3px 6px; border-radius: 3px; transition: all 0.2s; opacity: 0.6; }}
        .copy-btn:hover {{ opacity: 1; background-color: rgba(67, 97, 238, 0.1); }}
        .copy-btn.copied {{ color: #4cc9f0; }}
        .action-btn {{ background-color: #4361ee; color: white; border: none; padding: 6px 12px; border-radius: 4px; cursor: pointer; font-weight: 600; font-size: 0.85rem; display: flex; align-items: center; gap: 5px; transition: background-color 0.2s; }}
        .action-btn:hover {{ background-color: #4895ef; }}
        .action-btn.secondary {{ background-color: #555555; }}
        .action-btn.secondary:hover {{ background-color: #666666; }}
        .error-msg {{ color: #f72585; font-size: 0.85rem; margin-top: 4px; }}
        .notification {{ position: fixed; top: 20px; right: 20px; padding: 10px 20px; background-color: #4cc9f0; color: white; border-radius: 4px; box-shadow: 0 4px 8px rgba(0, 0, 0, 0.2); z-index: 1000; opacity: 0; transform: translateY(-20px); transition: all 0.3s; }}
        .notification.show {{ opacity: 1; transform: translateY(0); }}
        .primary {{ color: #4361ee; }}
        .success {{ color: #4cc9f0; }}
        .info {{ color: #4895ef; }}
        .warning {{ color: #f9c74f; }}
        .danger {{ color: #f72585; }}
        .bg-danger {{ background-color: rgba(247, 37, 133, 0.15); }}
        .bg-warning {{ background-color: rgba(249, 199, 79, 0.15); }}
        .bg-info {{ background-color: rgba(72, 149, 239, 0.15); }}
        .bg-success {{ background-color: rgba(76, 201, 240, 0.15); }}
        .bg-error {{ background-color: rgba(85, 85, 85, 0.15); }}
        .ms-known {{ color: #e63946; }}
        .ms-unknown {{ color: #6c757d; }}
        .bg-ms-known {{ background-color: rgba(230, 57, 70, 0.15); }}
        .severity-Critical {{ color: #f72585; font-weight: bold; }}
        .severity-High {{ color: #f9c74f; font-weight: bold; }}
        .severity-Medium {{ color: #4895ef; }}
        .severity-Clean {{ color: #4cc9f0; }}
        .severity-Error {{ color: #555555; }}
        a {{ color: #4895ef; text-decoration: none; transition: color 0.2s; }}
        a:hover {{ color: #4361ee; text-decoration: underline; }}
        .filter-container {{ padding: 20px; background-color: #1f2833; border-radius: 8px; margin-bottom: 20px; border: 1px solid rgba(255, 255, 255, 0.1); }}
        .filter-title {{ font-weight: bold; margin-bottom: 15px; font-size: 1.1rem; }}
        .filter-row {{ display: flex; flex-wrap: wrap; gap: 20px; margin-bottom: 15px; align-items: flex-end; }}
        .filter-group {{ flex: 1; min-width: 200px; }}
        .filter-group label {{ display: block; margin-bottom: 8px; font-weight: 500; opacity: 0.9; }}
        .filter-input {{ width: 100%; padding: 10px 12px; background-color: #1f2833; color: #e0e1dd; border: 1px solid #4361ee; border-radius: 4px; font-size: 1rem; transition: all 0.2s; }}
        .filter-input:focus {{ outline: none; border-color: #4895ef; box-shadow: 0 0 0 2px rgba(67, 97, 238, 0.3); }}
        .filter-btn {{ background-color: #4361ee; color: white; border: none; padding: 10px 20px; border-radius: 4px; cursor: pointer; font-weight: 600; transition: background-color 0.2s; display: flex; align-items: center; gap: 8px; }}
        .filter-btn:hover {{ background-color: #4895ef; }}
        .tooltip {{ position: relative; display: inline-block; cursor: help; }}
        .tooltip .tooltiptext {{ visibility: hidden; width: 200px; background-color: #1f2833; color: #e0e1dd; text-align: center; border-radius: 6px; padding: 10px; position: absolute; z-index: 1; bottom: 125%; left: 50%; margin-left: -100px; opacity: 0; transition: opacity 0.3s; font-size: 0.9rem; box-shadow: 0 4px 8px rgba(0, 0, 0, 0.3); border: 1px solid #4361ee; }}
        .tooltip:hover .tooltiptext {{ visibility: visible; opacity: 1; }}
        .badge {{ display: inline-block; padding: 4px 8px; font-size: 0.75rem; font-weight: 600; line-height: 1; text-align: center; white-space: nowrap; vertical-align: baseline; border-radius: 10px; margin-left: 5px; }}
        .badge-primary {{ background-color: #4361ee; color: white; }}
        .badge-danger {{ background-color: #f72585; color: white; }}
        .badge-warning {{ background-color: #f9c74f; color: black; }}
        .badge-success {{ background-color: #4cc9f0; color: white; }}
        .badge-info {{ background-color: #4895ef; color: white; }}
        .badge-secondary {{ background-color: #555555; color: white; }}
        .modal {{ display: none; position: fixed; z-index: 1000; left: 0; top: 0; width: 100%; height: 100%; background-color: rgba(0, 0, 0, 0.7); opacity: 0; transition: opacity 0.3s; }}
        .modal.show {{ display: block; opacity: 1; }}
        .modal-content {{ background-color: #1f2833; margin: 10% auto; padding: 20px; border-radius: 8px; max-width: 500px; box-shadow: 0 5px 15px rgba(0, 0, 0, 0.5); transform: translateY(-20px); transition: transform 0.3s; }}
        .modal.show .modal-content {{ transform: translateY(0); }}
        .modal-header {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 15px; padding-bottom: 10px; border-bottom: 1px solid rgba(255, 255, 255, 0.1); }}
        .modal-title {{ font-size: 1.2rem; font-weight: bold; color: #e0e1dd; }}
        .close-modal {{ background: none; border: none; font-size: 1.5rem; color: #e0e1dd; cursor: pointer; transition: color 0.2s; }}
        .close-modal:hover {{ color: #f72585; }}
        .modal-body {{ margin-bottom: 20px; }}
        .modal-footer {{ display: flex; justify-content: flex-end; gap: 10px; }}
        @media (max-width: 768px) {{
            .container {{ width: 100%; padding: 10px; }}
            .col {{ flex: 100%; padding: 0 10px; }}
            .card-header {{ flex-direction: column; align-items: stretch; }}
            .card-header .actions {{ margin-top: 10px; }}
            .filter-group {{ flex: 100%; }}
        }}
    </style>
</head>
<body>
    <div class="notification" id="notification"></div>
    
    <div class="container">
        <div class="header">
            <h1><i class="fas fa-shield-virus"></i> VirusTotal Scan Results - {input_filename_name}</h1>
            <p>Report generated on {generation_time}</p>
        </div>
        
        <!-- Summary Stats Cards - First Row -->
        <div class="row">
            <div class="col">
                <div class="card">
                    <div class="stats-card">
                        <i class="fas fa-search fa-3x" style="color: #4895ef;"></i>
                        <h4>Total IOCs</h4>
                        <h2 style="color: #4895ef;">{total_iocs}</h2>
                    </div>
                </div>
            </div>
            <div class="col">
                <div class="card">
                    <div class="stats-card">
                        <i class="fas fa-virus fa-3x" style="color: #f72585;"></i>
                        <h4>Malicious</h4>
                        <h2 style="color: #f72585;">{malicious_count}</h2>
                    </div>
                </div>
            </div>
            <div class="col">
                <div class="card">
                    <div class="stats-card">
                        <i class="fas fa-exclamation-triangle fa-3x" style="color: #f9c74f;"></i>
                        <h4>Suspicious</h4>
                        <h2 style="color: #f9c74f;">{suspicious_count}</h2>
                    </div>
                </div>
            </div>
            <div class="col">
                <div class="card">
                    <div class="stats-card">
                        <i class="fas fa-check-circle fa-3x" style="color: #4cc9f0;"></i>
                        <h4>Clean</h4>
                        <h2 style="color: #4cc9f0;">{clean_count}</h2>
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
                        <h2 style="color: #e63946;">{ms_known_count}</h2>
                    </div>
                </div>
            </div>
            <div class="col" style="flex: 1;">
                <div class="card">
                    <div class="stats-card">
                        <i class="fas fa-question-circle fa-3x" style="color: #6c757d;"></i>
                        <h4>MS Defender - Unknown</h4>
                        <h2 style="color: #6c757d;">{ms_unknown_count}</h2>
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
{ioc_type_chart}
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
{severity_chart}
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
{ms_defender_chart}
                        </div>
                    </div>
                </div>
            </div>
        </div>
        
        <!-- Filter Section -->
        <div class="card">
            <div class="card-header">
                <i class="fas fa-filter"></i> Filter Results
                <div class="actions">
                    <button class="action-btn" id="export-csv-btn">
                        <i class="fas fa-file-csv"></i> Export to CSV
                    </button>
                </div>
            </div>
            <div class="card-body">
                <div class="filter-container">
                    <div class="filter-row">
                        <div class="filter-group">
                            <label><i class="fas fa-sitemap"></i> IOC Type:</label>
                            <select id="ioc-type-filter" class="filter-input">
                                <option value="all">All Types</option>
                                {ioc_type_options}
                            </select>
                        </div>
                        <div class="filter-group">
                            <label><i class="fas fa-exclamation-circle"></i> Severity:</label>
                            <select id="severity-filter" class="filter-input">
                                <option value="all">All Severities</option>
                                {severity_options}
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
                <div>
                    <i class="fas fa-exclamation-circle"></i> Critical Findings
                    <span class="badge badge-danger">{critical_count}</span>
                </div>
                <div class="actions">
                    <button class="action-btn" id="copy-critical-btn">
                        <i class="fas fa-copy"></i> Copy All
                    </button>
                </div>
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
                            {critical_rows}
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    
        <!-- Microsoft Defender Detections Section -->
        <div class="card">
            <div class="card-header" style="color: #e63946;">
                <div>
                    <i class="fas fa-shield-alt"></i> Microsoft Defender Detections
                    <span class="badge badge-primary">{ms_known_count}</span>
                </div>
                <div class="actions">
                    <button class="action-btn" id="copy-msknown-btn">
                        <i class="fas fa-copy"></i> Copy All
                    </button>
                </div>
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
                            {ms_detection_rows}
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    
        <!-- Microsoft Unknown Detections Section -->
        <div class="card">
            <div class="card-header" style="color: #6c757d;">
                <div>
                    <i class="fas fa-question-circle"></i> Microsoft Defender - Unknown IOCs
                    <span class="badge badge-secondary">{ms_unknown_count}</span>
                </div>
                <div class="actions">
                    <button class="action-btn" id="copy-msunknown-btn">
                        <i class="fas fa-copy"></i> Copy All
                    </button>
                </div>
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
                            {ms_unknown_rows}
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    
    <!-- All Results Table -->
    <div class="card">
        <div class="card-header">
            <div>
                <i class="fas fa-table"></i> All Scan Results
                <span class="badge badge-primary">{total_iocs}</span>
            </div>
            <div class="actions">
                <button class="action-btn" id="copy-all-btn">
                    <i class="fas fa-copy"></i> Copy All
                </button>
            </div>
        </div>
        <div class="card-body">
            <div class="table-container">
                <table id="results-table">
                    <thead>
                        <tr>
                            <th>IOC</th>
                            <th>Type</th>
                            <th>Detection %</th>
                            <th>Severity</th>
                            <th>MS Defender</th>
                            <th>Detection Names</th>
                            <th>VT Link</th>
                            <th>Detection Ratio</th>
                            <th>Category</th>
                            <th>Last Analysis</th>
                            <th>Details</th>
                        </tr>
                    </thead>
                    <tbody>
                        {all_results_rows}
                    </tbody>
                </table>
            </div>
        </div>
    </div>
    
    <!-- Export Modal -->
    <div class="modal" id="export-modal">
        <div class="modal-content">
            <div class="modal-header">
                <h2 class="modal-title">Export Data</h2>
                <button class="close-modal" id="close-export-modal">&times;</button>
            </div>
            <div class="modal-body">
                <p>Choose your export format:</p>
            </div>
            <div class="modal-footer">
                <button class="action-btn" id="export-csv-confirm">
                    <i class="fas fa-file-csv"></i> CSV
                </button>
                <button class="action-btn secondary" id="cancel-export">
                    Cancel
                </button>
            </div>
        </div>
    </div>
    
    <!-- Footer -->
    <div class="footer">
        <p>
            <i class="fas fa-shield-alt"></i> VirusTotal IOC Scanner | Scan completed in {scan_duration} 
            <span class="tooltip">
                <i class="fas fa-info-circle"></i>
                <span class="tooltiptext">Report generated at {generation_time}</span>
            </span>
        </p>
    </div>
</div>

<script>
    // Store the report data for export
    const reportData = {csv_export_data};
    
    // Function to copy text to clipboard
    function copyToClipboard(text) {
        const textarea = document.createElement('textarea');
        textarea.value = text;
        document.body.appendChild(textarea);
        textarea.select();
        
        try {
            const successful = document.execCommand('copy');
            const message = successful ? 'Copied to clipboard!' : 'Copy failed';
            showNotification(message);
        } catch (err) {
            showNotification('Failed to copy: ' + err);
        }
        
        document.body.removeChild(textarea);
    }
    
    // Function to show notification
    function showNotification(message, type = 'success') {
        const notification = document.getElementById('notification');
        notification.textContent = message;
        notification.className = 'notification show ' + type;
        
        setTimeout(() => {
            notification.className = 'notification';
        }, 3000);
    }
    
    // Client-side filtering functionality
    document.addEventListener('DOMContentLoaded', function() {
        console.log("DOM fully loaded, initializing...");
        
        // Force redraw of Plotly charts to ensure they render properly
        setTimeout(function() {
            if (typeof Plotly !== 'undefined') {
                console.log("Redrawing charts...");
                document.querySelectorAll('.plotly-graph-div').forEach(function(plot) {
                    Plotly.relayout(plot, {{
                        'autosize': true,
                        'paper_bgcolor': 'rgba(0,0,0,0)',
                        'plot_bgcolor': 'rgba(0,0,0,0)'
                    }});
                });
            }
        }, 500);
        
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
        
        // Copy functionality
        const copyAllBtn = document.getElementById('copy-all-btn');
        const copyCriticalBtn = document.getElementById('copy-critical-btn');
        const copyMsKnownBtn = document.getElementById('copy-msknown-btn');
        const copyMsUnknownBtn = document.getElementById('copy-msunknown-btn');
        
        // Export modal elements
        const exportCsvBtn = document.getElementById('export-csv-btn');
        const exportModal = document.getElementById('export-modal');
        const closeExportModal = document.getElementById('close-export-modal');
        const exportCsvConfirm = document.getElementById('export-csv-confirm');
        const cancelExport = document.getElementById('cancel-export');
        
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
        
        // Copy all IOCs from tables
        if (copyAllBtn) {
            copyAllBtn.addEventListener('click', function() {
                copyTableContent(resultsTable);
            });
        }
        
        if (copyCriticalBtn) {
            copyCriticalBtn.addEventListener('click', function() {
                copyTableContent(criticalTable);
            });
        }
        
        if (copyMsKnownBtn) {
            copyMsKnownBtn.addEventListener('click', function() {
                copyTableContent(msDetectionTable);
            });
        }
        
        if (copyMsUnknownBtn) {
            copyMsUnknownBtn.addEventListener('click', function() {
                copyTableContent(msUnknownTable);
            });
        }
        
        // Export functionality
        if (exportCsvBtn) {
            exportCsvBtn.addEventListener('click', function() {
                exportModal.classList.add('show');
            });
        }
        
        if (closeExportModal) {
            closeExportModal.addEventListener('click', function() {
                exportModal.classList.remove('show');
            });
        }
        
        if (cancelExport) {
            cancelExport.addEventListener('click', function() {
                exportModal.classList.remove('show');
            });
        }
        
        if (exportCsvConfirm) {
            exportCsvConfirm.addEventListener('click', function() {
                exportToCsv();
                exportModal.classList.remove('show');
            });
        }
        
        // Function to copy all IOCs from a table
        function copyTableContent(table) {
            if (!table) return;
            
            try {
                const rows = table.querySelectorAll('tbody tr');
                if (rows.length === 0) {
                    showNotification('No IOCs to copy', 'warning');
                    return;
                }
                
                let iocList = []; // Define it here properly
                rows.forEach(row => {
                    // Only copy visible rows (respect filters)
                    if (row.style.display !== 'none') {
                        const iocCell = row.querySelector('.ioc-value');
                        if (iocCell) {
                            iocList.push(iocCell.textContent.trim());
                        }
                    }
                });
                
                if (iocList.length === 0) {
                    showNotification('No visible IOCs to copy', 'warning');
                    return;
                }
                
                const iocText = iocList.join('\\n');
                copyToClipboard(iocText);
                showNotification(`Copied ${{iocList.length}} IOCs to clipboard!`);
            } catch (err) {
                console.error('Error copying table content:', err);
                showNotification('Error copying IOCs', 'danger');
            }
        }
        
        // Function to export data to CSV
        function exportToCsv() {
            try {
                // Prepare CSV content
                let csvContent = '';
                
                // Get headers
                const headers = [];
                for (const key in reportData[0]) {
                    headers.push(key);
                }
                
                csvContent += headers.join(',') + '\\n';
                
                // Add rows
                reportData.forEach(row => {
                    const values = headers.map(header => {
                        const value = row[header];
                        // Escape values containing commas, quotes, or newlines
                        if (typeof value === 'string' && (value.includes(',') || value.includes('"') || value.includes('\\n'))) {
                            return '"' + value.replace(/"/g, '""') + '"';
                        }
                        return value !== undefined ? value : '';
                    });
                    csvContent += values.join(',') + '\\n';
                });
                
                // Create and download file
                const blob = new Blob([csvContent], {{ type: 'text/csv;charset=utf-8;' }});
                const link = document.createElement('a');
                const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
                
                if (navigator.msSaveBlob) {{ // IE 10+
                    navigator.msSaveBlob(blob, `vt_report_${{timestamp}}.csv`);
                }} else {{
                    const url = URL.createObjectURL(blob);
                    link.href = url;
                    link.download = `vt_report_${{timestamp}}.csv`;
                    document.body.appendChild(link);
                    link.click();
                    document.body.removeChild(link);
                    setTimeout(() => URL.revokeObjectURL(url), 100);
                }}
                
                showNotification('CSV file exported successfully!');
            }} catch (err) {{
                console.error('Error exporting CSV:', err);
                showNotification('Error exporting CSV file', 'danger');
            }}
        }}
        
        // Apply filters on page load with a slight delay
        setTimeout(applyFilters, 500);
        
        function applyFilters() {{
            console.log("Applying filters...");
            try {{
                // Show loading indicator
                showFilteringStatus(true);
                
                const iocType = iocTypeFilter ? iocTypeFilter.value : 'all';
                const severity = severityFilter ? severityFilter.value : 'all';
                const msDetection = msDetectionFilter ? msDetectionFilter.value : 'all';
                const searchText = searchInput ? searchInput.value.toLowerCase() : '';
                
                console.log("Filter values:", {{ iocType, severity, msDetection, searchText }});
                
                // Function to filter a table
                function filterTable(table) {{
                    if (!table) return 0;
                    
                    const rows = table.querySelectorAll('tbody tr');
                    let visibleCount = 0;
                    
                    rows.forEach(row => {{
                        let showRow = true;
                        
                        const rowIocType = row.getAttribute('data-ioc-type');
                        const rowSeverity = row.getAttribute('data-severity');
                        const rowMsDetection = row.getAttribute('data-ms-detection');
                        
                        // Check IOC type filter
                        if (iocType !== 'all' && rowIocType !== iocType) {{
                            showRow = false;
                        }}
                        
                        // Check severity filter
                        if (severity !== 'all' && rowSeverity !== severity) {{
                            showRow = false;
                        }}
                        
                        // Check MS detection filter
                        if (msDetection !== 'all' && rowMsDetection !== msDetection) {{
                            showRow = false;
                        }}
                        
                        // Check search text
                        if (searchText) {{
                            const rowText = row.textContent.toLowerCase();
                            if (!rowText.includes(searchText)) {{
                                showRow = false;
                            }}
                        }}
                        
                        // Show or hide the row
                        row.style.display = showRow ? '' : 'none';
                        if (showRow) visibleCount++;
                    }});
                    
                    return visibleCount;
                }}
                
                // Apply filters to all tables
                const resultsCount = filterTable(resultsTable);
                const criticalCount = filterTable(criticalTable);
                const msDetectionCount = filterTable(msDetectionTable);
                const msUnknownCount = filterTable(msUnknownTable);
                
                console.log("Filtered counts:", {{ 
                    results: resultsCount, 
                    critical: criticalCount, 
                    msDetection: msDetectionCount,
                    msUnknown: msUnknownCount
                }});
                
                // Update the filter status
                setTimeout(() => {{
                    showFilteringStatus(false);
                    updateFilterStatus({{
                        results: resultsCount,
                        critical: criticalCount,
                        msDetection: msDetectionCount,
                        msUnknown: msUnknownCount
                    }});
                }}, 300);
                
            }} catch (err) {{
                console.error("Error applying filters:", err);
                showFilteringStatus(false);
                showNotification('Error applying filters', 'danger');
            }}
        }}
        
        // Show filtering status
        function showFilteringStatus(isFiltering) {{
            const filterBtn = document.getElementById('apply-filters-btn');
            if (filterBtn) {{
                if (isFiltering) {{
                    filterBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Filtering...';
                    filterBtn.disabled = true;
                }} else {{
                    filterBtn.innerHTML = '<i class="fas fa-filter"></i> Apply Filters';
                    filterBtn.disabled = false;
                }}
            }}
        }}
        
        // Update filter status in the UI
        function updateFilterStatus(counts) {{
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
        }}
        
        // Make sure tables have equal column widths
        function alignTableColumns() {{
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
            tables.forEach(table => {{
                const headers = Array.from(table.querySelectorAll('th'));
                headers.forEach((th, index) => {{
                    if (index < columnWidths.length) {{
                        th.style.width = columnWidths[index] + 'px';
                    }}
                }});
            }});
        }}
        
        // Align table columns after a short delay
        setTimeout(alignTableColumns, 1000);
        
        // Handle window resize for better mobile experience
        window.addEventListener('resize', alignTableColumns);
        
        // Close modal on click outside
        window.addEventListener('click', function(event) {{
            if (event.target === exportModal) {{
                exportModal.classList.remove('show');
            }}
        }});
    }});
</script>
</body>
</html>
"""
    
    # Replace template placeholders
    input_filename_name = sanitize_for_html(Path(input_filename).name)
    generation_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # Format charts for insertion
    ioc_type_chart = ioc_type_fig.to_html(full_html=False, include_plotlyjs=False, default_height='350px')
    severity_chart = severity_fig.to_html(full_html=False, include_plotlyjs=False, default_height='350px')
    ms_defender_chart = ms_defender_fig.to_html(full_html=False, include_plotlyjs=False, default_height='350px')
    
    # Perform replacements
    formatted_html = html_template.format(
        input_filename=sanitize_for_html(input_filename),
        input_filename_name=input_filename_name,
        generation_time=generation_time,
        total_iocs=total_iocs,
        malicious_count=malicious_count,
        suspicious_count=suspicious_count,
        clean_count=clean_count,
        critical_count=len(critical_df),
        ms_known_count=ms_known_count,
        ms_unknown_count=ms_unknown_count,
        ioc_type_chart=ioc_type_chart,
        severity_chart=severity_chart,
        ms_defender_chart=ms_defender_chart,
        ioc_type_options=ioc_type_options,
        severity_options=severity_options,
        critical_rows=critical_rows,
        ms_detection_rows=ms_detection_rows,
        ms_unknown_rows=ms_unknown_rows,
        all_results_rows=all_results_rows,
        scan_duration=scan_duration_str,
        csv_export_data=csv_export_data
    )
    
    # Write the HTML report to file
    try:
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(formatted_html)
        print(f"HTML report generated: {output_path}")
        
        # Try to open the report in a browser
        try:
            import webbrowser
            webbrowser.open('file://' + os.path.abspath(output_path))
        except:
            pass
            
    except Exception as e:
        logger.error(f"Error generating HTML report: {str(e)}")
        return None
    
    return output_path
