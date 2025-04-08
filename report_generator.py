"""
VirusTotal IOC Scanner HTML Report Generator with Simplified Timeline

This module generates HTML reports for the VirusTotal IOC Scanner with a clean,
simplified timeline visualization showing only the total count.

Author: VT Scanner Team
Version: 1.5.1
"""

import os
import html
import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any

try:
    import pandas as pd
    import numpy as np
    import plotly.express as px
    import plotly.graph_objects as go
    import plotly.io as pio
except ImportError:
    print("Missing required packages. Please install with: pip install pandas plotly")
    raise

# Setup logging
logger = logging.getLogger(__name__)

# Color palette
COLORS = {
    'primary': '#4dabf7',      # Bright blue
    'secondary': '#adb5bd',    # Medium gray
    'success': '#40c057',      # Green
    'info': '#228be6',         # Blue
    'warning': '#fd7e14',      # Orange
    'danger': '#fa5252',       # Red
    'background': '#0f172a',   # Dark navy
    'card_bg': '#1e293b',      # Dark blue
    'text': '#f8f9fa',         # Light gray
    'border': '#334155'        # Border color
}

# Severity colors
SEVERITY_COLORS = {
    'Critical': '#fa5252',
    'High': '#ff922b',
    'Medium': '#339af0',
    'Clean': '#51cf66',
    'Error': '#adb5bd'
}

SEVERITY_BADGES = {
    'Critical': 'badge badge-danger', 
    'High': 'badge badge-warning',
    'Medium': 'badge badge-info', 
    'Clean': 'badge badge-success',
    'Error': 'badge badge-secondary'
}

def sanitize_text(text: Any, for_js: bool = False) -> str:
    """Sanitize text for HTML or JavaScript output"""
    if not isinstance(text, str):
        text = str(text)
    
    if for_js:
        # Escape for JavaScript
        return text.replace('\\', '\\\\').replace("'", "\\'").replace('"', '\\"').replace('\n', '\\n')
    else:
        # Escape for HTML
        return html.escape(text)

def get_severity_badge(severity: str) -> str:
    """Return HTML for a severity badge"""
    if severity not in SEVERITY_BADGES:
        return ""
    return f'<span class="{SEVERITY_BADGES[severity]}">{severity}</span>'

def get_ms_defender_status(status: str) -> str:
    """Return HTML for MS Defender status with icon"""
    if status == "known":
        return '<span class="ms-known"><i class="fas fa-shield-alt"></i> known</span>'
    return '<span class="ms-unknown"><i class="fas fa-question-circle"></i> unknown</span>'

def get_ioc_type_icon(ioc_type: str) -> str:
    """Return appropriate icon for IOC type"""
    icons = {
        "ip": "fa-network-wired",
        "domain": "fa-globe",
        "url": "fa-link",
        "hash": "fa-file-code",
        "email": "fa-envelope"
    }
    return icons.get(ioc_type, "fa-question-circle")

def process_data(results_list: List[Dict]) -> Tuple[pd.DataFrame, Dict, Dict]:
    """Process and sanitize data for report generation"""
    # Process and sanitize data
    results_list_copy = [{k: sanitize_text(v) if isinstance(v, str) else v 
                        for k, v in result.items() if k != 'last_analysis_results'} 
                        for result in results_list]
    
    df = pd.DataFrame(results_list_copy)
    
    # Convert detection percentage to numeric
    if 'vt_detection_percentage' in df.columns:
        df['vt_detection_percentage'] = pd.to_numeric(df['vt_detection_percentage'], errors='coerce').round(1)
    
    # Process date columns for timeline visualization
    date_columns = ['vt_last_analysis_date', 'vt_first_submission_date', 'vt_last_submission_date']
    
    for col in date_columns:
        if col in df.columns:
            try:
                df[f'{col}_dt'] = pd.to_datetime(df[col], errors='coerce')
            except Exception as e:
                logger.warning(f"Could not convert {col} to datetime: {e}")
    
    # Ensure severity is set correctly
    if 'severity' not in df.columns:
        def get_severity(row):
            if pd.notna(row.get("error")) and row.get("error"):
                return "Error"
            if "vt_detection_percentage" not in row or pd.isna(row["vt_detection_percentage"]):
                return "Error"
            if row["vt_detection_percentage"] > 50: 
                return "Critical"
            if row["vt_detection_percentage"] > 25: 
                return "High"
            if row["vt_detection_percentage"] > 0: 
                return "Medium"
            return "Clean"
        
        df["severity"] = df.apply(get_severity, axis=1)
    
    # Fill NaN values
    df = df.fillna("N/A")
    
    # Calculate counts for charts
    severity_counts = df["severity"].value_counts().reset_index()
    severity_counts.columns = ["Severity", "Count"]
    
    ms_defender_counts = df["ms_defender"].value_counts().reset_index()
    ms_defender_counts.columns = ["Status", "Count"]
    
    return df, severity_counts, ms_defender_counts

def create_pie_chart(data_df: pd.DataFrame, name_col: str, value_col: str, 
                    color_map: Dict = None, title: str = "") -> str:
    """Create a pie chart visualization"""
    try:
        if color_map is None:
            color_map = {}
            
        fig = px.pie(
            data_df, names=name_col, values=value_col,
            color=name_col, color_discrete_map=color_map, hole=0.4
        )
        
        fig.update_traces(
            textposition='inside',
            textinfo='percent+label',
            hovertemplate='<b>%{label}</b><br>Count: %{value}<br>Percentage: %{percent}',
            marker=dict(line=dict(color=COLORS['background'], width=1.5))
        )
        
        fig.update_layout(
            template='plotly_dark',
            paper_bgcolor='rgba(0,0,0,0)',
            plot_bgcolor='rgba(0,0,0,0)',
            margin=dict(l=10, r=10, t=30, b=10),
            height=280,
            showlegend=True,
            title=title,
            legend=dict(orientation="h", yanchor="bottom", y=-0.2, xanchor="center", x=0.5),
        )
        
        return pio.to_html(fig, full_html=False, include_plotlyjs=False, 
                         config={'displayModeBar': False, 'responsive': True})
    
    except Exception as e:
        logger.error(f"Error creating pie chart: {e}")
        return f"<div class='alert alert-warning'><i class='fas fa-exclamation-triangle'></i> Error creating chart: {str(e)}</div>"

def create_timeline_chart(df: pd.DataFrame) -> str:
    """Create a simplified timeline visualization showing only total IOC counts over time"""
    try:
        # Check for valid date columns
        date_columns = ['vt_last_analysis_date_dt', 'vt_first_submission_date_dt']
        valid_date_col = None
        
        for col in date_columns:
            if col in df.columns and pd.to_datetime(df[col], errors='coerce').notna().any():
                valid_date_col = col
                break
        
        if not valid_date_col:
            return "<div class='alert alert-warning'><i class='fas fa-exclamation-triangle'></i> Timeline analysis unavailable: No valid date information found</div>"
        
        # Create a copy of the dataframe with only valid dates
        timeline_df = df.copy()
        timeline_df['date'] = pd.to_datetime(timeline_df[valid_date_col], errors='coerce')
        timeline_df = timeline_df[timeline_df['date'].notna()]
        
        if len(timeline_df) == 0:
            return "<div class='alert alert-warning'><i class='fas fa-exclamation-triangle'></i> No valid timeline data available</div>"
        
        # Extract just the date component 
        timeline_df['date'] = timeline_df['date'].dt.date
        
        # Count IOCs by date
        date_counts = timeline_df.groupby('date').size().reset_index(name='count')
        
        # Create the chart with just the total line
        fig = go.Figure()
        
        # Add total line
        fig.add_trace(go.Scatter(
            x=date_counts['date'],
            y=date_counts['count'],
            name='Total',
            mode='lines+markers',
            line=dict(color='white', width=2),
            marker=dict(size=6, color='white', line=dict(width=1, color=COLORS['background'])),
            hovertemplate='<b>%{y}</b> IOCs<br>%{x}<extra></extra>'
        ))
        
        # Update layout
        fig.update_layout(
            template='plotly_dark',
            paper_bgcolor='rgba(0,0,0,0)',
            plot_bgcolor='rgba(0,0,0,0)',
            margin=dict(l=10, r=10, t=30, b=20),
            height=350,
            yaxis_title='Number of IOCs',
            xaxis_title='Date',
            showlegend=False,
            hovermode="x unified"
        )
        
        # Better grid lines
        fig.update_xaxes(
            showgrid=True,
            gridwidth=0.5,
            gridcolor='rgba(255,255,255,0.1)'
        )
        
        fig.update_yaxes(
            showgrid=True,
            gridwidth=0.5,
            gridcolor='rgba(255,255,255,0.1)'
        )
        
        return pio.to_html(
            fig, 
            full_html=False, 
            include_plotlyjs=False,
            config={'displayModeBar': True, 'responsive': True}
        )
    
    except Exception as e:
        logger.error(f"Error creating timeline chart: {e}")
        return f"<div class='alert alert-warning'><i class='fas fa-exclamation-triangle'></i> Could not create timeline chart: {str(e)}</div>"

def generate_table_row(row: pd.Series, idx: int, with_ms_defender: bool = True, 
                      with_metadata: bool = False) -> str:
    """Generate an HTML table row for displaying an IOC"""
    ioc_type_icon = get_ioc_type_icon(row['ioc_type'])
    safe_ioc = sanitize_text(row['ioc'], for_js=True)
    error_display = ""
    
    if pd.notna(row.get('error')) and row.get('error'):
        error_display = f'<div class="error-msg">{row["error"]}</div>'
    
    vt_link = row.get('vt_link', '')
    if not isinstance(vt_link, str) or not vt_link.startswith(('http://', 'https://')):
        vt_link = ''
    
    basic_cols = f"""
        <td>
            <div class="ioc-container">
                <span class="ioc-value">{row['ioc']}</span>
                <button class="copy-btn" onclick="copyToClipboard('{safe_ioc}')">
                    <i class="fas fa-copy"></i>
                </button>
            </div>
            {error_display}
        </td>
        <td><i class="fas {ioc_type_icon}"></i> {row['ioc_type']}</td>
        <td data-sort="{row.get('vt_detection_percentage', 0)}">{row.get('vt_detection_percentage', 'N/A')}%</td>
        <td class="severity-{row['severity']}">{get_severity_badge(row['severity'])}</td>
    """
    
    if with_ms_defender:
        basic_cols += f"<td>{get_ms_defender_status(row.get('ms_defender', 'unknown'))}</td>"
        
    basic_cols += f"""
        <td>{row.get('detection_names', '')}</td>
        <td><a href='{vt_link}' target='_blank' class="action-link"><i class="fas fa-external-link-alt"></i> View</a></td>
    """
    
    if with_metadata:
        category = row.get('category', '') or row.get('category_display', '')
        detection_ratio = row.get('vt_detection_ratio', 'N/A')
        
        # Format the ratio with better styling
        ratio_parts = detection_ratio.split('/') if isinstance(detection_ratio, str) else ['0', '0']
        if len(ratio_parts) == 2:
            ratio_html = f'<span class="detection-ratio"><span class="ratio-positive">{ratio_parts[0]}</span>/<span class="ratio-total">{ratio_parts[1]}</span></span>'
        else:
            ratio_html = detection_ratio
            
        return f"""
        <tr class="{'bg-ms-known' if row['ms_defender'] == 'known' else ''}" data-ioc-type="{row['ioc_type']}" data-severity="{row['severity']}" data-ms-detection="{row['ms_defender']}" data-ioc-index="{idx}">
            {basic_cols}
            <td>{ratio_html}</td>
            <td>{category}</td>
            <td>{row.get('vt_last_analysis_date', 'N/A')}</td>
            <td><a href='{vt_link}' target='_blank' class="action-link"><i class="fas fa-search"></i> Details</a></td>
        </tr>
        """
    
    return f"""
    <tr data-ioc-type="{row['ioc_type']}" data-severity="{row['severity']}" data-ms-detection="{row['ms_defender']}" data-ioc-index="{idx}">
        {basic_cols}
    </tr>
    """

class DateTimeEncoder(json.JSONEncoder):
    """Custom JSON encoder that handles datetime and pandas objects"""
    def default(self, obj):
        if isinstance(obj, (pd.Timestamp, datetime)):
            return obj.isoformat()
        if isinstance(obj, np.integer):
            return int(obj)
        if isinstance(obj, np.floating):
            return float(obj)
        if isinstance(obj, np.ndarray):
            return obj.tolist()
        return super().default(obj)

def generate_html_report(results_list: List[Dict], 
                         scan_stats: Dict, 
                         output_path: Optional[str] = None, 
                         input_filename: str = "IOCs") -> Optional[str]:
    """
    Generate an HTML report from scan results with improved timeline visualization
    
    Args:
        results_list: List of result dictionaries with detection information
        scan_stats: Dictionary with scan statistics
        output_path: Optional path for saving the report
        input_filename: Original input filename for display
        
    Returns:
        Path to the generated HTML report or None if generation failed
    """
    if not results_list:
        logger.warning("No results to display.")
        return None
    
    try:
        # Process data
        df, severity_counts, ms_defender_counts = process_data(results_list)
        
        # Extract stats
        total_iocs = scan_stats.get('total_iocs', len(df))
        malicious_count = scan_stats.get('malicious_count', df[df["severity"] == "Critical"].shape[0])
        suspicious_count = scan_stats.get('suspicious_count', df[df["severity"] == "High"].shape[0])
        error_count = scan_stats.get('error_count', df[df["severity"] == "Error"].shape[0])
        clean_count = total_iocs - malicious_count - suspicious_count - error_count
        
        ms_known_count = scan_stats.get('ms_known_count', df[df["ms_defender"] == "known"].shape[0])
        ms_unknown_count = scan_stats.get('ms_unknown_count', df[df["ms_defender"] == "unknown"].shape[0])
        
        scan_duration = datetime.now().timestamp() - scan_stats.get('scan_start_time', datetime.now().timestamp())
        scan_duration_str = f"{int(scan_duration // 60)}m {int(scan_duration % 60)}s"
        
        # Create output path if not provided
        if not output_path:
            timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
            report_filename = f"{Path(input_filename).stem}_vt_report_{timestamp}.html"
            output_path = str(Path.cwd() / report_filename)
        
        # Create charts
        charts = {}
        
        # Basic distribution charts
        charts['severity_chart'] = create_pie_chart(
            severity_counts, 
            'Severity', 
            'Count', 
            color_map=SEVERITY_COLORS,
            title='Severity Distribution'
        )
        
        charts['ms_defender_chart'] = create_pie_chart(
            ms_defender_counts, 
            'Status', 
            'Count',
            color_map={
                'known': '#e03131', 
                'unknown': '#868e96', 
                'N/A': '#495057'
            },
            title='MS Defender Detection'
        )
        
        # Timeline chart - only showing total
        charts['detection_timeline'] = create_timeline_chart(df)
        
        # Filter dataframes for tables
        critical_df = df[df['severity'].isin(['Critical', 'High'])]
        ms_known_df = df[df['ms_defender'] == 'known']
        ms_unknown_df = df[df['ms_defender'] == 'unknown']
        
        # Generate table rows
        critical_rows = "".join([generate_table_row(row, idx) for idx, row in critical_df.iterrows()])
        ms_detection_rows = "".join([generate_table_row(row, idx, with_ms_defender=False) 
                                     for idx, row in ms_known_df.iterrows()])
        ms_unknown_rows = "".join([generate_table_row(row, idx, with_ms_defender=False) 
                                   for idx, row in ms_unknown_df.iterrows()])
        all_results_rows = "".join([generate_table_row(row, idx, with_ms_defender=True, with_metadata=True) 
                                    for idx, row in df.iterrows()])
        
        # Create dropdown options
        ioc_type_options = "".join([f'<option value="{ioc_type}">{ioc_type}</option>' 
                                   for ioc_type in sorted(df['ioc_type'].unique())])
        severity_options = "".join([f'<option value="{severity}">{severity}</option>' 
                                   for severity in ['Critical', 'High', 'Medium', 'Clean', 'Error'] 
                                   if severity in df['severity'].unique()])
        
        # Prepare export data
        export_data = []
        for _, row in df.iterrows():
            export_row = {}
            for k, v in row.items():
                if k != 'last_analysis_results':
                    if isinstance(v, (pd.Timestamp, datetime)):
                        export_row[k] = v.isoformat()
                    elif isinstance(v, (np.integer, np.int64)):
                        export_row[k] = int(v)
                    elif isinstance(v, (np.floating, np.float64)):
                        export_row[k] = float(v)
                    else:
                        export_row[k] = v
            export_data.append(export_row)
        
        # Convert to JSON for CSV export
        try:
            csv_export_data = json.dumps(export_data, cls=DateTimeEncoder)
        except Exception as e:
            logger.error(f"Error serializing data to JSON: {e}")
            # Create fallback with minimal data
            fallback_data = []
            for item in export_data:
                safe_item = {
                    'ioc': item.get('ioc', ''), 
                    'ioc_type': item.get('ioc_type', ''),
                    'severity': item.get('severity', ''),
                    'ms_defender': item.get('ms_defender', ''),
                    'vt_detection_percentage': item.get('vt_detection_percentage', '')
                }
                fallback_data.append(safe_item)
            csv_export_data = json.dumps(fallback_data)
        
        # Prepare template variables
        input_filename_name = sanitize_text(Path(input_filename).name)
        generation_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Build the HTML template
        html_template = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="generator" content="VTScanner/1.5.1">
    <title>VirusTotal Scan Results - {input_filename_name}</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/5.15.4/css/all.min.css">
    <script src="https://cdn.plot.ly/plotly-latest.min.js"></script>
    <style>
        :root {{
            --color-primary: {COLORS['primary']};
            --color-secondary: {COLORS['secondary']};
            --color-success: {COLORS['success']};
            --color-info: {COLORS['info']};
            --color-warning: {COLORS['warning']};
            --color-danger: {COLORS['danger']};
            --color-bg: {COLORS['background']};
            --color-card: {COLORS['card_bg']};
            --color-text: {COLORS['text']};
            --color-border: {COLORS['border']};
        }}
        
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        
        body {{ 
            font-family: 'Segoe UI', -apple-system, 'Roboto', sans-serif; 
            background-color: var(--color-bg); 
            color: var(--color-text); 
            line-height: 1.5;
        }}
        
        .container {{ width: 95%; max-width: 1400px; margin: 0 auto; padding: 15px; }}
        
        .header {{ 
            text-align: center; 
            margin-bottom: 20px; 
            padding: 20px 0; 
            border-bottom: 1px solid var(--color-border);
            border-radius: 8px;
        }}
        
        .header h1 {{ font-size: 2.2rem; margin-bottom: 10px; color: var(--color-primary); }}
        .header p {{ font-size: 1rem; color: var(--color-secondary); }}
        
        .card {{ 
            background-color: var(--color-card); 
            border-radius: 8px; 
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1); 
            margin-bottom: 20px; 
            overflow: hidden; 
            border: 1px solid var(--color-border);
        }}
        
        .card-header {{ 
            padding: 15px; 
            font-weight: 600; 
            font-size: 1.1rem; 
            border-bottom: 2px solid var(--color-border); 
            display: flex; 
            justify-content: space-between; 
            align-items: center; 
        }}
        
        .card-header i {{ margin-right: 8px; color: var(--color-primary); }}
        .card-header .actions {{ display: flex; gap: 8px; }}
        .card-body {{ padding: 15px; }}
        
        .row {{ display: flex; flex-wrap: wrap; margin: 0 -10px; }}
        .col {{ flex: 1; min-width: 200px; padding: 0 10px; margin-bottom: 15px; }}
        
        .stats-card {{ 
            text-align: center; 
            padding: 20px 10px; 
            display: flex; 
            flex-direction: column; 
            justify-content: center; 
            align-items: center; 
            height: 100%; 
        }}
        
        .stats-card i {{ margin-bottom: 10px; font-size: 2.5rem; }}
        .stats-card h4 {{ font-size: 1rem; color: var(--color-secondary); margin: 5px 0 10px; }}
        .stats-card h2 {{ font-size: 2.2rem; margin: 0; font-weight: 600; }}
        
        .table-container {{ 
            overflow-x: auto; 
            border-radius: 4px; 
            box-shadow: inset 0 2px 4px rgba(0, 0, 0, 0.1); 
            background-color: rgba(0, 0, 0, 0.1);
            border: 1px solid var(--color-border);
        }}
        
        table {{ width: 100%; border-collapse: collapse; margin-top: 10px; }}
        
        th, td {{ 
            padding: 10px 12px; 
            text-align: left; 
            border: 1px solid var(--color-border); 
        }}
        
        th {{ 
            background-color: var(--color-primary); 
            color: white; 
            font-weight: 600; 
            position: sticky; 
            top: 0; 
            z-index: 10;
        }}
        
        tr:nth-child(even) {{ background-color: rgba(255, 255, 255, 0.03); }}
        tr:hover {{ background-color: rgba(255, 255, 255, 0.05); }}
        
        .chart-container {{ width: 100%; position: relative; border-radius: 4px; overflow: hidden; }}
        
        .footer {{ 
            text-align: center; 
            margin-top: 30px; 
            padding: 15px 0; 
            border-top: 1px solid var(--color-border); 
            color: var(--color-secondary); 
            font-size: 1rem; 
        }}
        
        .ioc-container {{ display: flex; align-items: center; justify-content: space-between; gap: 5px; }}
        .ioc-value {{ 
            max-width: calc(100% - 30px); 
            overflow: hidden; 
            text-overflow: ellipsis; 
            font-family: 'Consolas', 'Monaco', monospace;
        }}
        
        .copy-btn {{ 
            background: none; 
            border: none; 
            color: var(--color-primary); 
            cursor: pointer; 
            padding: 3px 6px; 
            border-radius: 3px; 
            opacity: 0.7; 
        }}
        
        .copy-btn:hover {{ opacity: 1; background-color: rgba(77, 171, 247, 0.1); }}
        
        .error-msg {{ color: var(--color-danger); font-size: 0.85rem; margin-top: 4px; }}
        
        .notification {{ 
            position: fixed; 
            top: 20px; 
            right: 20px; 
            padding: 10px 20px; 
            background-color: var(--color-success); 
            color: white; 
            border-radius: 4px; 
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1); 
            z-index: 1000; 
            opacity: 0; 
            transform: translateY(-20px); 
            transition: all 0.3s;
            display: flex;
            align-items: center;
            gap: 8px; 
        }}
        
        .notification i {{ font-size: 1.2rem; }}
        .notification.show {{ opacity: 1; transform: translateY(0); }}
        
        .notification.success {{ background-color: var(--color-success); }}
        .notification.warning {{ background-color: var(--color-warning); }}
        .notification.danger {{ background-color: var(--color-danger); }}
        .notification.info {{ background-color: var(--color-info); }}
        
        .ms-known {{ 
            color: #e03131; 
            font-weight: 500;
            display: flex;
            align-items: center;
            gap: 5px;
        }}
        
        .ms-unknown {{ 
            color: #868e96; 
            display: flex;
            align-items: center;
            gap: 5px;
        }}
        
        .bg-ms-known {{ background-color: rgba(224, 49, 49, 0.1); }}
        
        .severity-Critical {{ color: {SEVERITY_COLORS['Critical']}; font-weight: bold; }}
        .severity-High {{ color: {SEVERITY_COLORS['High']}; font-weight: bold; }}
        .severity-Medium {{ color: {SEVERITY_COLORS['Medium']}; }}
        .severity-Clean {{ color: {SEVERITY_COLORS['Clean']}; }}
        .severity-Error {{ color: {SEVERITY_COLORS['Error']}; }}
        
        .detection-ratio {{ display: inline-flex; align-items: center; gap: 2px; }}
        .ratio-positive {{ color: var(--color-danger); font-weight: 500; }}
        .ratio-total {{ color: var(--color-secondary); }}
        
        a {{ color: var(--color-primary); text-decoration: none; }}
        a:hover {{ color: var(--color-info); text-decoration: underline; }}
        
        .action-link {{ display: inline-flex; align-items: center; gap: 5px; font-weight: 500; }}
        
        .filter-container {{ 
            padding: 15px; 
            background-color: var(--color-card); 
            border-radius: 8px; 
            margin-bottom: 15px; 
            border: 1px solid var(--color-border); 
        }}
        
        .filter-row {{ 
            display: flex; 
            flex-wrap: wrap; 
            gap: 15px; 
            margin-bottom: 15px; 
            align-items: flex-end; 
        }}
        
        .filter-group {{ flex: 1; min-width: 200px; }}
        
        .filter-group label {{ 
            display: flex; 
            align-items: center;
            gap: 5px;
            margin-bottom: 6px; 
            font-weight: 500; 
            color: var(--color-secondary);
        }}
        
        .filter-input {{ 
            width: 100%; 
            padding: 8px 10px; 
            background-color: rgba(0, 0, 0, 0.2); 
            color: var(--color-text); 
            border: 1px solid var(--color-border); 
            border-radius: 4px; 
            font-size: 0.95rem; 
        }}
        
        .filter-input:focus {{ outline: none; border-color: var(--color-primary); }}
        
        .filter-btn {{ 
            background-color: var(--color-primary); 
            color: white; 
            border: none; 
            padding: 8px 15px; 
            border-radius: 4px; 
            cursor: pointer; 
            font-weight: 600; 
            display: flex; 
            align-items: center; 
            gap: 6px; 
        }}
        
        .filter-btn:hover {{ background-color: var(--color-info); }}
        
        .badge {{ 
            display: inline-flex; 
            align-items: center;
            justify-content: center;
            padding: 4px 8px; 
            font-size: 0.75rem; 
            font-weight: 600; 
            border-radius: 10px; 
            margin-left: 5px; 
        }}
        
        .badge-primary {{ background-color: var(--color-primary); color: white; }}
        .badge-danger {{ background-color: var(--color-danger); color: white; }}
        .badge-warning {{ background-color: var(--color-warning); color: black; }}
        .badge-info {{ background-color: var(--color-info); color: white; }}
        .badge-success {{ background-color: var(--color-success); color: white; }}
        .badge-secondary {{ background-color: var(--color-secondary); color: white; }}
        
        .modal {{ 
            display: none; 
            position: fixed; 
            z-index: 1000; 
            left: 0; 
            top: 0; 
            width: 100%; 
            height: 100%; 
            background-color: rgba(0, 0, 0, 0.7); 
            opacity: 0; 
            transition: opacity 0.3s; 
        }}
        
        .modal.show {{ display: block; opacity: 1; }}
        
        .modal-content {{ 
            background-color: var(--color-card); 
            margin: 10% auto; 
            padding: 20px; 
            border-radius: 8px; 
            max-width: 500px; 
            box-shadow: 0 10px 25px rgba(0, 0, 0, 0.5); 
            transform: translateY(-20px); 
            transition: transform 0.3s; 
            border: 1px solid var(--color-border);
        }}
        
        .modal.show .modal-content {{ transform: translateY(0); }}
        
        .modal-header {{ 
            display: flex; 
            justify-content: space-between; 
            align-items: center; 
            margin-bottom: 15px; 
            padding-bottom: 10px; 
            border-bottom: 1px solid var(--color-border); 
        }}
        
        .modal-title {{ font-size: 1.2rem; font-weight: bold; }}
        
        .close-modal {{ 
            background: none; 
            border: none; 
            font-size: 1.5rem; 
            color: var(--color-text); 
            cursor: pointer; 
        }}
        
        .close-modal:hover {{ color: var(--color-danger); }}
        
        .modal-body {{ margin-bottom: 20px; }}
        
        .modal-footer {{ display: flex; justify-content: flex-end; gap: 10px; }}
        
        .action-btn {{ 
            background-color: var(--color-primary); 
            color: white; 
            border: none; 
            padding: 8px 12px; 
            border-radius: 4px; 
            cursor: pointer; 
            font-weight: 600; 
            font-size: 0.9rem; 
            display: flex; 
            align-items: center; 
            gap: 5px; 
        }}
        
        .action-btn:hover {{ background-color: var(--color-info); }}
        .action-btn.secondary {{ background-color: var(--color-secondary); }}
        
        .pagination-controls {{ display: flex; justify-content: center; margin-top: 15px; gap: 8px; }}
        
        .pagination-btn {{ 
            background-color: var(--color-card); 
            color: var(--color-text); 
            border: 1px solid var(--color-border); 
            padding: 5px 10px; 
            border-radius: 4px; 
            cursor: pointer; 
        }}
        
        .pagination-btn:hover {{ border-color: var(--color-primary); }}
        .pagination-btn.active {{ background-color: var(--color-primary); color: white; }}
        
        .alert {{ 
            padding: 15px; 
            margin-bottom: 20px; 
            border-radius: 4px; 
            display: flex;
            align-items: center;
            gap: 10px;
        }}
        
        .alert i {{ font-size: 1.2rem; }}
        
        .alert-warning {{ 
            background-color: rgba(253, 126, 20, 0.15); 
            border-left: 4px solid var(--color-warning); 
            color: var(--color-warning);
        }}
        
        @media (max-width: 768px) {{
            .container {{ width: 100%; padding: 10px; }}
            .col {{ flex: 100%; }}
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
            <h1><i class="fas fa-shield-virus"></i> VirusTotal Scan Results</h1>
            <p>{input_filename_name} • {generation_time}</p>
        </div>
        
        <!-- Summary Stats Cards -->
        <div class="row">
            <div class="col">
                <div class="card">
                    <div class="stats-card">
                        <i class="fas fa-search" style="color: var(--color-info);"></i>
                        <h4>Total IOCs</h4>
                        <h2 style="color: var(--color-info);">{total_iocs}</h2>
                    </div>
                </div>
            </div>
            <div class="col">
                <div class="card">
                    <div class="stats-card">
                        <i class="fas fa-virus" style="color: var(--color-danger);"></i>
                        <h4>Malicious</h4>
                        <h2 style="color: var(--color-danger);">{malicious_count}</h2>
                    </div>
                </div>
            </div>
            <div class="col">
                <div class="card">
                    <div class="stats-card">
                        <i class="fas fa-exclamation-triangle" style="color: var(--color-warning);"></i>
                        <h4>Suspicious</h4>
                        <h2 style="color: var(--color-warning);">{suspicious_count}</h2>
                    </div>
                </div>
            </div>
            <div class="col">
                <div class="card">
                    <div class="stats-card">
                        <i class="fas fa-check-circle" style="color: var(--color-success);"></i>
                        <h4>Clean</h4>
                        <h2 style="color: var(--color-success);">{clean_count}</h2>
                    </div>
                </div>
            </div>
        </div>
        
        <!-- Microsoft Defender Stats & Charts Row -->
        <div class="row">
            <div class="col" style="flex: 1;">
                <div class="card">
                    <div class="stats-card">
                        <i class="fas fa-shield-alt" style="color: #e03131;"></i>
                        <h4>MS Defender - Known</h4>
                        <h2 style="color: #e03131;">{ms_known_count}</h2>
                    </div>
                </div>
            </div>
            <div class="col" style="flex: 1;">
                <div class="card">
                    <div class="stats-card">
                        <i class="fas fa-question-circle" style="color: #868e96;"></i>
                        <h4>MS Defender - Unknown</h4>
                        <h2 style="color: #868e96;">{ms_unknown_count}</h2>
                    </div>
                </div>
            </div>
            <div class="col" style="flex: 2;">
                <div class="card">
                    <div class="card-header">
                        <div><i class="fas fa-chart-pie"></i> Detection Severity</div>
                    </div>
                    <div class="card-body">
                        <div class="chart-container" id="severity-chart">
{charts['severity_chart']}
                        </div>
                    </div>
                </div>
            </div>
            <div class="col" style="flex: 2;">
                <div class="card">
                    <div class="card-header">
                        <div><i class="fas fa-shield-alt"></i> MS Defender Detection</div>
                    </div>
                    <div class="card-body">
                        <div class="chart-container" id="ms-detection-chart">
{charts['ms_defender_chart']}
                        </div>
                    </div>
                </div>
            </div>
        </div>
        
        <!-- Timeline Analysis Section -->
        <div class="card">
            <div class="card-header">
                <div>
                    <i class="fas fa-chart-line"></i> Timeline Analysis
                </div>
                <div class="actions">
                    <button class="action-btn" id="export-timeline-btn">
                        <i class="fas fa-download"></i> Export Chart
                    </button>
                </div>
            </div>
            <div class="card-body">
                <div class="chart-container" id="detection-timeline">
{charts['detection_timeline']}
                </div>
            </div>
        </div>
        
        <!-- Filter Section -->
        <div class="card">
            <div class="card-header">
                <div>
                    <i class="fas fa-filter"></i> Filter Results
                </div>
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
                        <button id="reset-filters-btn" class="filter-btn" style="background-color: var(--color-secondary);">
                            <i class="fas fa-sync-alt"></i> Reset
                        </button>
                    </div>
                </div>
            </div>
        </div>

        <!-- Critical Findings Section -->
        <div class="card">
            <div class="card-header" style="color: var(--color-danger);">
                <div>
                    <i class="fas fa-exclamation-circle"></i> Critical Findings
                    <span class="badge badge-danger">{len(critical_df)}</span>
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
            <div class="card-header" style="color: #e03131;">
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
            <div class="card-header" style="color: #868e96;">
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
                <div class="pagination-controls"></div>
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
                <i class="fas fa-shield-alt"></i> VirusTotal IOC Scanner | Scan completed in {scan_duration_str}
            </p>
        </div>
    </div>

<script>
// Store the report data for export
const reportData = {csv_export_data};

// Function to copy text to clipboard
function copyToClipboard(text) {{
    const textarea = document.createElement('textarea');
    textarea.value = text;
    document.body.appendChild(textarea);
    textarea.select();
    
    try {{
        const successful = document.execCommand('copy');
        showNotification(successful ? 'Copied to clipboard!' : 'Copy failed', successful ? 'success' : 'danger');
    }} catch (err) {{
        showNotification('Failed to copy: ' + err, 'danger');
    }}
    
    document.body.removeChild(textarea);
}}

// Function to show notification
function showNotification(message, type = 'success') {{
    const notification = document.getElementById('notification');
    
    // Add appropriate icon
    let icon = 'fa-check-circle';
    if (type === 'warning') icon = 'fa-exclamation-triangle';
    if (type === 'danger') icon = 'fa-times-circle';
    if (type === 'info') icon = 'fa-info-circle';
    
    notification.innerHTML = `<i class="fas ${{icon}}"></i> ${{message}}`;
    notification.className = `notification show ${{type}}`;
    
    setTimeout(() => {{
        notification.className = 'notification';
    }}, 3000);
}}

document.addEventListener('DOMContentLoaded', function() {{
    // Get elements
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
    const exportTimelineBtn = document.getElementById('export-timeline-btn');
    
    // Copy buttons
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
    
    // Make tables sortable
    initSortableTables();
    
    // Export timeline chart
    if (exportTimelineBtn) {{
        exportTimelineBtn.addEventListener('click', function() {{
            const timelineChart = document.getElementById('detection-timeline');
            
            if (timelineChart && window.Plotly) {{
                try {{
                    const plotlyInstance = timelineChart.querySelector('.js-plotly-plot');
                    if (plotlyInstance) {{
                        Plotly.downloadImage(plotlyInstance, {{
                            format: 'png',
                            width: 1200,
                            height: 600,
                            filename: 'ioc_timeline'
                        }});
                        showNotification('Timeline chart download started', 'info');
                    }} else {{
                        showNotification('Chart not available', 'warning');
                    }}
                }} catch (err) {{
                    console.error('Error exporting chart:', err);
                    showNotification('Could not export chart', 'danger');
                }}
            }}
        }});
    }}
    
    // Apply filters
    if (applyFiltersBtn) applyFiltersBtn.addEventListener('click', applyFilters);
    if (resetFiltersBtn) {{
        resetFiltersBtn.addEventListener('click', function() {{
            if (iocTypeFilter) iocTypeFilter.value = 'all';
            if (severityFilter) severityFilter.value = 'all';
            if (msDetectionFilter) msDetectionFilter.value = 'all';
            if (searchInput) searchInput.value = '';
            applyFilters();
            showNotification('Filters reset', 'info');
        }});
    }}
    
    // Copy functions
    if (copyAllBtn) copyAllBtn.addEventListener('click', () => copyTableContent(resultsTable));
    if (copyCriticalBtn) copyCriticalBtn.addEventListener('click', () => copyTableContent(criticalTable));
    if (copyMsKnownBtn) copyMsKnownBtn.addEventListener('click', () => copyTableContent(msDetectionTable));
    if (copyMsUnknownBtn) copyMsUnknownBtn.addEventListener('click', () => copyTableContent(msUnknownTable));
    
    // Export functions
    if (exportCsvBtn) exportCsvBtn.addEventListener('click', () => exportModal.classList.add('show'));
    if (closeExportModal) closeExportModal.addEventListener('click', () => exportModal.classList.remove('show'));
    if (cancelExport) cancelExport.addEventListener('click', () => exportModal.classList.remove('show'));
    if (exportCsvConfirm) {{
        exportCsvConfirm.addEventListener('click', function() {{
            exportToCsv();
            exportModal.classList.remove('show');
        }});
    }}
    
    // Function to initialize sortable tables
    function initSortableTables() {{
        document.querySelectorAll('table th').forEach((header, index) => {{
            if (index < 4) {{ // Only make first 4 columns sortable
                header.style.cursor = 'pointer';
                header.innerHTML += ' <i class="fas fa-sort"></i>';
                
                header.addEventListener('click', function() {{
                    const table = this.closest('table');
                    sortTable(table, index);
                }});
            }}
        }});
    }}
    
    // Function to sort table
    function sortTable(table, column) {{
        const tbody = table.querySelector('tbody');
        const rows = Array.from(tbody.querySelectorAll('tr'));
        const headers = table.querySelectorAll('th');
        const header = headers[column];
        
        // Determine sort direction
        const currentDirection = header.getAttribute('data-sort') || 'none';
        const newDirection = currentDirection === 'asc' ? 'desc' : 'asc';
        
        // Reset all headers
        headers.forEach(h => {{
            h.setAttribute('data-sort', 'none');
            h.innerHTML = h.innerHTML.replace(/ <i class="fas fa-sort.*?"><\\/i>/, ' <i class="fas fa-sort"></i>');
        }});
        
        // Set new direction on current header
        header.setAttribute('data-sort', newDirection);
        header.innerHTML = header.innerHTML.replace(/ <i class="fas fa-sort.*?"><\\/i>/, 
            newDirection === 'asc' ? ' <i class="fas fa-sort-up"></i>' : ' <i class="fas fa-sort-down"></i>');
        
        // Sort rows
        rows.sort((a, b) => {{
            let valueA, valueB;
            
            // Handle different data types
            if (column === 2) {{ // Detection percentage
                valueA = parseFloat(a.cells[column].getAttribute('data-sort') || '0');
                valueB = parseFloat(b.cells[column].getAttribute('data-sort') || '0');
            }} else {{ // Default to string comparison
                valueA = a.cells[column].textContent.trim().toLowerCase();
                valueB = b.cells[column].textContent.trim().toLowerCase();
            }}
            
            // Compare values
            if (typeof valueA === 'number' && typeof valueB === 'number') {{
                return newDirection === 'asc' ? valueA - valueB : valueB - valueA;
            }} else {{
                return newDirection === 'asc' ? 
                    valueA.localeCompare(valueB) : valueB.localeCompare(valueA);
            }}
        }});
        
        // Reinsert rows
        rows.forEach(row => tbody.appendChild(row));
    }}
    
    // Function to copy table content
    function copyTableContent(table) {{
        if (!table) return;
        
        try {{
            const rows = table.querySelectorAll('tbody tr');
            if (rows.length === 0) {{
                showNotification('No IOCs to copy', 'warning');
                return;
            }}
            
            let iocList = [];
            rows.forEach(row => {{
                if (row.style.display !== 'none') {{
                    const iocCell = row.querySelector('.ioc-value');
                    if (iocCell) iocList.push(iocCell.textContent.trim());
                }}
            }});
            
            if (iocList.length === 0) {{
                showNotification('No visible IOCs to copy', 'warning');
                return;
            }}
            
            copyToClipboard(iocList.join('\\n'));
            showNotification(`Copied ${{iocList.length}} IOCs to clipboard!`, 'success');
        }} catch (err) {{
            console.error('Error copying:', err);
            showNotification('Error copying IOCs', 'danger');
        }}
    }}
    
    // Function to export data to CSV
    function exportToCsv() {{
        try {{
            // Get headers
            const headers = Object.keys(reportData[0]);
            const csvContent = [
                headers.join(','),
                ...reportData.map(row => 
                    headers.map(header => {{
                        const value = row[header];
                        return typeof value === 'string' && (value.includes(',') || value.includes('"') || value.includes('\\n'))
                            ? `"${{value.replace(/"/g, '""')}}"` : value !== undefined ? value : '';
                    }}).join(',')
                )
            ].join('\\n');
            
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
            
            showNotification('CSV file exported successfully!', 'success');
        }} catch (err) {{
            console.error('Error exporting CSV:', err);
            showNotification('Error exporting CSV file', 'danger');
        }}
    }}
    
    // Apply filters
    function applyFilters() {{
        const iocType = iocTypeFilter ? iocTypeFilter.value : 'all';
        const severity = severityFilter ? severityFilter.value : 'all';
        const msDetection = msDetectionFilter ? msDetectionFilter.value : 'all';
        const searchText = searchInput ? searchInput.value.toLowerCase() : '';
        
        // Filter all tables
        [resultsTable, criticalTable, msDetectionTable, msUnknownTable].forEach(table => {{
            if (!table) return;
            
            table.querySelectorAll('tbody tr').forEach(row => {{
                let showRow = true;
                
                // Check filters
                if (iocType !== 'all' && row.getAttribute('data-ioc-type') !== iocType) showRow = false;
                if (severity !== 'all' && row.getAttribute('data-severity') !== severity) showRow = false;
                if (msDetection !== 'all' && row.getAttribute('data-ms-detection') !== msDetection) showRow = false;
                if (searchText && !row.textContent.toLowerCase().includes(searchText)) showRow = false;
                
                row.style.display = showRow ? '' : 'none';
            }});
        }});
        
        // Update counts in badges
        function updateBadgeCount(table, badge) {{
            if (!table || !badge) return;
            const visibleRows = Array.from(table.querySelectorAll('tbody tr'))
                .filter(row => row.style.display !== 'none').length;
            badge.textContent = visibleRows;
        }}
        
        updateBadgeCount(resultsTable, 
            document.querySelector('#results-table')?.closest('.card')?.querySelector('.badge'));
        updateBadgeCount(criticalTable, 
            document.querySelector('#critical-table')?.closest('.card')?.querySelector('.badge'));
        updateBadgeCount(msDetectionTable, 
            document.querySelector('#ms-detection-table')?.closest('.card')?.querySelector('.badge'));
        updateBadgeCount(msUnknownTable, 
            document.querySelector('#ms-unknown-table')?.closest('.card')?.querySelector('.badge'));
    }}
    
    // Set up pagination for results table
    if (resultsTable) {{
        const rows = resultsTable.querySelectorAll('tbody tr');
        const rowsPerPage = 50;
        const pageCount = Math.ceil(rows.length / rowsPerPage);
        
        if (pageCount > 1) {{
            const paginationControls = document.querySelector('.pagination-controls');
            if (paginationControls) {{
                for (let i = 1; i <= pageCount; i++) {{
                    const btn = document.createElement('button');
                    btn.className = 'pagination-btn' + (i === 1 ? ' active' : '');
                    btn.textContent = i;
                    
                    btn.addEventListener('click', function() {{
                        document.querySelectorAll('.pagination-btn').forEach(b => 
                            b.classList.remove('active'));
                        this.classList.add('active');
                        
                        const start = (i - 1) * rowsPerPage;
                        rows.forEach((row, idx) => {{
                            row.style.display = (idx >= start && idx < start + rowsPerPage) ? '' : 'none';
                        }});
                    }});
                    
                    paginationControls.appendChild(btn);
                }}
                
                // Show first page by default
                rows.forEach((row, idx) => {{
                    row.style.display = idx < rowsPerPage ? '' : 'none';
                }});
            }}
        }}
    }}
    
    // Close modal on click outside
    window.addEventListener('click', function(event) {{
        if (event.target === exportModal) exportModal.classList.remove('show');
    }});
    
    // Apply filters on page load
    setTimeout(applyFilters, 300);
}});
</script>
</body>
</html>
"""
        
        # Write the HTML report to file
        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(html_template)
            logger.info(f"HTML report generated: {output_path}")
            return output_path
                
        except Exception as e:
            logger.error(f"Error writing HTML report: {str(e)}")
            return None
    
    except Exception as e:
        import traceback
        error_details = traceback.format_exc()
        logger.error(f"Error generating HTML report: {str(e)}\n{error_details}")
        return None
