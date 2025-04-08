"""
VirusTotal IOC Scanner HTML Report Generator with Timeline Analysis

This module handles the generation of HTML reports for the VirusTotal IOC Scanner,
with enhanced timeline visualizations to analyze threat evolution over time.

Author: VT Scanner Team
Version: 1.3.1
"""

import os
import html
import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Union, Any, Tuple

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

# Color palette for charts and styling
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

# Severity mappings
SEVERITY_COLORS = {
    'Critical': COLORS['danger'], 
    'High': COLORS['warning'],
    'Medium': COLORS['info'], 
    'Clean': COLORS['success'],
    'Error': COLORS['secondary']
}

SEVERITY_BADGES = {
    'Critical': 'badge badge-danger', 
    'High': 'badge badge-warning',
    'Medium': 'badge badge-info', 
    'Clean': 'badge badge-success',
    'Error': 'badge badge-secondary'
}

def sanitize_for_html(text: Any) -> str:
    """Safely encode a string for HTML output"""
    if not isinstance(text, str):
        text = str(text)
    return html.escape(text)

def sanitize_for_js(text: Any) -> str:
    """Safely encode a string for JavaScript use"""
    if not isinstance(text, str):
        text = str(text)
    # Escape single quotes, double quotes, backslashes, and control characters
    result = text.replace('\\', '\\\\')
    result = result.replace("'", "\\'")
    result = result.replace('"', '\\"')
    result = result.replace('\n', '\\n')
    result = result.replace('\r', '\\r')
    result = result.replace('\t', '\\t')
    return result

def get_severity_class(severity: str) -> str:
    """Return the CSS class for the given severity level"""
    severity_classes = {
        'Critical': 'severity-Critical', 
        'High': 'severity-High',
        'Medium': 'severity-Medium', 
        'Clean': 'severity-Clean',
        'Error': 'severity-Error'
    }
    return severity_classes.get(severity, '')

def get_severity_badge(severity: str) -> str:
    """Return HTML for a severity badge"""
    if severity not in SEVERITY_BADGES:
        return ""
    return f'<span class="{SEVERITY_BADGES[severity]}">{severity}</span>'

def get_ms_defender_span(status: str) -> str:
    """Return HTML for MS Defender status"""
    if status == "known":
        return '<span class="ms-known"><i class="fas fa-shield-alt"></i> known</span>'
    return '<span class="ms-unknown"><i class="fas fa-question-circle"></i> unknown</span>'

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

def process_data(results_list: List[Dict]) -> Tuple[pd.DataFrame, Dict, Dict]:
    """Process and sanitize data for report generation"""
    # Process and sanitize data
    results_list_copy = [{k: sanitize_for_html(v) if isinstance(v, str) else v 
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
                # Try to convert to datetime format
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

def create_chart(data_df: pd.DataFrame, chart_type: str, **kwargs) -> str:
    """Create a chart visualization based on provided data"""
    try:
        config = {'displayModeBar': False, 'responsive': True}
        
        if chart_type == 'pie':
            names_col = kwargs.get('names', data_df.columns[0])
            values_col = kwargs.get('values', data_df.columns[1])
            color_col = kwargs.get('color', names_col)
            color_map = kwargs.get('color_map', {})
            title = kwargs.get('title', '')
            
            fig = px.pie(
                data_df, names=names_col, values=values_col,
                color=color_col, color_discrete_map=color_map, hole=0.4
            )
            fig.update_layout(
                template='plotly_dark', 
                paper_bgcolor='rgba(0,0,0,0)', 
                plot_bgcolor='rgba(0,0,0,0)',
                margin=dict(l=20, r=20, t=30, b=20), 
                height=280,
                showlegend=True,
                title=title,
                legend=dict(font=dict(size=11), orientation="h", yanchor="bottom", y=-0.25, xanchor="center", x=0.5),
                annotations=[dict(text=title, font=dict(size=15), showarrow=False)]
            )
        else:
            logger.error(f"Unsupported chart type: {chart_type}")
            return "<div>Error: Unsupported chart type</div>"
        
        return pio.to_html(fig, full_html=False, include_plotlyjs=False, config=config)
    
    except Exception as e:
        logger.error(f"Error creating chart: {e}")
        return f"<div class='error-msg'>Error creating chart: {str(e)}</div>"

def create_timeline_chart(df: pd.DataFrame) -> str:
    """Create a timeline visualization showing IOC detections over time"""
    try:
        # Check for valid date columns
        date_columns = ['vt_last_analysis_date_dt', 'vt_first_submission_date_dt']
        valid_date_col = None
        
        for col in date_columns:
            if col in df.columns and pd.to_datetime(df[col], errors='coerce').notna().any():
                valid_date_col = col
                break
        
        if not valid_date_col:
            return "<div class='alert alert-warning'><i class='fas fa-exclamation-circle'></i> Timeline analysis unavailable due to missing date information</div>"
        
        # Create a copy of the dataframe with only valid dates
        timeline_df = df.copy()
        timeline_df['date'] = pd.to_datetime(timeline_df[valid_date_col], errors='coerce')
        timeline_df = timeline_df[timeline_df['date'].notna()]
        
        if len(timeline_df) == 0:
            return "<div class='alert alert-warning'><i class='fas fa-exclamation-circle'></i> No valid timeline data available</div>"
        
        # Extract date for grouping
        timeline_df['date'] = timeline_df['date'].dt.date
        
        # Group by date and severity
        severity_pivot = pd.pivot_table(
            timeline_df, 
            index='date',
            columns='severity', 
            values='ioc',
            aggfunc='count',
            fill_value=0
        ).reset_index()
        
        # Ensure all severity levels are present
        for severity in ['Critical', 'High', 'Medium', 'Clean', 'Error']:
            if severity not in severity_pivot.columns:
                severity_pivot[severity] = 0
        
        # Calculate daily total
        severity_pivot['Total'] = severity_pivot[['Critical', 'High', 'Medium', 'Clean', 'Error']].sum(axis=1)
        
        # Create the stacked area chart
        fig = go.Figure()
        
        # Add traces in specific order (most severe first)
        for severity, color in [
            ('Critical', SEVERITY_COLORS['Critical']),
            ('High', SEVERITY_COLORS['High']),
            ('Medium', SEVERITY_COLORS['Medium']),
            ('Clean', SEVERITY_COLORS['Clean']),
            ('Error', SEVERITY_COLORS['Error'])
        ]:
            if severity in severity_pivot.columns:
                fig.add_trace(go.Scatter(
                    x=severity_pivot['date'], 
                    y=severity_pivot[severity],
                    mode='lines',
                    stackgroup='one',
                    name=severity,
                    line=dict(width=0.5, color=color),
                    fillcolor=color
                ))
        
        # Add total line
        fig.add_trace(go.Scatter(
            x=severity_pivot['date'],
            y=severity_pivot['Total'],
            mode='lines',
            name='Total',
            line=dict(color='white', width=2, dash='dot')
        ))
            
        fig.update_layout(
            title="IOC Detection Timeline",
            template='plotly_dark',
            paper_bgcolor='rgba(0,0,0,0)',
            plot_bgcolor='rgba(0,0,0,0)',
            margin=dict(l=20, r=20, t=40, b=40),
            height=300,
            yaxis_title="Number of IOCs",
            xaxis_title="Date",
            legend=dict(orientation="h", yanchor="bottom", y=-0.3, xanchor="center", x=0.5),
            hovermode="x unified"
        )
        
        return pio.to_html(fig, full_html=False, include_plotlyjs=False, config={'displayModeBar': False, 'responsive': True})
    
    except Exception as e:
        logger.error(f"Error creating timeline chart: {e}")
        return f"<div class='alert alert-warning'><i class='fas fa-exclamation-circle'></i> Could not create timeline chart: {str(e)}</div>"

def create_ioc_type_timeline(df: pd.DataFrame) -> str:
    """Create a timeline showing IOC types over time"""
    try:
        # Check for valid date columns
        date_columns = ['vt_last_analysis_date_dt', 'vt_first_submission_date_dt']
        valid_date_col = None
        
        for col in date_columns:
            if col in df.columns and pd.to_datetime(df[col], errors='coerce').notna().any():
                valid_date_col = col
                break
        
        if not valid_date_col:
            return "<div class='alert alert-warning'><i class='fas fa-exclamation-circle'></i> IOC type timeline unavailable due to missing date information</div>"
        
        # Create a copy of the dataframe with only valid dates
        timeline_df = df.copy()
        timeline_df['date'] = pd.to_datetime(timeline_df[valid_date_col], errors='coerce')
        timeline_df = timeline_df[timeline_df['date'].notna()]
        
        if len(timeline_df) == 0:
            return "<div class='alert alert-warning'><i class='fas fa-exclamation-circle'></i> No valid IOC type timeline data available</div>"
        
        # Extract date for grouping
        timeline_df['date'] = timeline_df['date'].dt.date
        
        # Create a pivot table of IOC types over time
        ioc_pivot = pd.pivot_table(
            timeline_df, 
            index='date',
            columns='ioc_type', 
            values='ioc',
            aggfunc='count',
            fill_value=0
        ).reset_index()
        
        # Get ioc types for creating bar chart
        ioc_types = [col for col in ioc_pivot.columns if col != 'date']
        
        # Create color map for IOC types
        color_map = {
            'hash': '#4cc9f0',
            'ip': '#f72585',
            'domain': '#4361ee',
            'url': '#f9c74f',
            'email': '#43aa8b'
        }
        
        # Create the grouped bar chart
        fig = go.Figure()
        
        # Add a trace for each IOC type
        for ioc_type in ioc_types:
            fig.add_trace(go.Bar(
                x=ioc_pivot['date'],
                y=ioc_pivot[ioc_type],
                name=ioc_type,
                marker_color=color_map.get(ioc_type, '#555555')
            ))
            
        fig.update_layout(
            title="IOC Types Over Time",
            template='plotly_dark',
            paper_bgcolor='rgba(0,0,0,0)',
            plot_bgcolor='rgba(0,0,0,0)',
            margin=dict(l=20, r=20, t=40, b=40),
            height=300,
            yaxis_title="Number of IOCs",
            xaxis_title="Date",
            legend_title="IOC Type",
            legend=dict(orientation="h", yanchor="bottom", y=-0.3, xanchor="center", x=0.5),
            hovermode="closest",
            barmode='group'
        )
        
        return pio.to_html(fig, full_html=False, include_plotlyjs=False, config={'displayModeBar': False, 'responsive': True})
    
    except Exception as e:
        logger.error(f"Error creating IOC type timeline: {e}")
        return f"<div class='alert alert-warning'><i class='fas fa-exclamation-circle'></i> Could not create IOC type chart: {str(e)}</div>"

def create_detection_heatmap(df: pd.DataFrame) -> str:
    """Create a heatmap showing detection percentages over time"""
    try:
        # Check for valid date and detection percentage data
        if 'vt_last_analysis_date_dt' not in df.columns or 'vt_detection_percentage' not in df.columns:
            return "<div class='alert alert-warning'><i class='fas fa-exclamation-circle'></i> Detection heatmap unavailable due to missing data</div>"
        
        # Create a copy with only valid data
        heatmap_df = df.copy()
        heatmap_df['date'] = pd.to_datetime(heatmap_df['vt_last_analysis_date_dt'], errors='coerce')
        heatmap_df = heatmap_df[heatmap_df['date'].notna()]
        
        # Convert detection percentage to numeric
        heatmap_df['detection'] = pd.to_numeric(heatmap_df['vt_detection_percentage'], errors='coerce')
        heatmap_df = heatmap_df[heatmap_df['detection'].notna()]
        
        if len(heatmap_df) == 0:
            return "<div class='alert alert-warning'><i class='fas fa-exclamation-circle'></i> No valid detection data available for heatmap</div>"
        
        # Get day of week
        heatmap_df['day_of_week'] = heatmap_df['date'].dt.day_name()
        heatmap_df['date'] = heatmap_df['date'].dt.date
        
        # Calculate average detection by date and day of week
        avg_detection = heatmap_df.groupby(['date', 'day_of_week'])['detection'].mean().reset_index()
        
        # Sort by proper day order
        day_order = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday']
        
        # Map days to integers for sorting
        day_map = {day: i for i, day in enumerate(day_order)}
        avg_detection['day_num'] = avg_detection['day_of_week'].map(day_map)
        avg_detection = avg_detection.sort_values('day_num')
        
        # Create the heatmap
        fig = px.density_heatmap(
            avg_detection,
            x='date',
            y='day_of_week',
            z='detection',
            title="Detection Percentage Heatmap",
            color_continuous_scale=[
                [0, COLORS['success']],
                [0.25, COLORS['info']],
                [0.5, COLORS['warning']],
                [1, COLORS['danger']]
            ],
            category_orders={"day_of_week": day_order}
        )
            
        fig.update_layout(
            template='plotly_dark',
            paper_bgcolor='rgba(0,0,0,0)',
            plot_bgcolor='rgba(0,0,0,0)',
            margin=dict(l=20, r=20, t=40, b=20),
            height=250,
            xaxis_title="Date",
            yaxis_title="Day of Week",
            coloraxis_colorbar=dict(title="Detection %"),
            hovermode="closest"
        )
        
        return pio.to_html(fig, full_html=False, include_plotlyjs=False, config={'displayModeBar': False, 'responsive': True})
    
    except Exception as e:
        logger.error(f"Error creating detection heatmap: {e}")
        return f"<div class='alert alert-warning'><i class='fas fa-exclamation-circle'></i> Could not create detection heatmap: {str(e)}</div>"

def generate_table_row(row: pd.Series, idx: int, with_ms_defender: bool = True, with_metadata: bool = False) -> str:
    """Generate an HTML table row for displaying an IOC"""
    vt_link = row.get('vt_link', '')
    if not isinstance(vt_link, str) or not vt_link.startswith(('http://', 'https://')):
        vt_link = ''
        
    error_display = ""
    if pd.notna(row.get('error')) and row.get('error'):
        error_display = f'<div class="error-msg">{row["error"]}</div>'
    
    # Use sanitize_for_js for the copy button to prevent issues with quotes
    safe_ioc = sanitize_for_js(row['ioc'])
        
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
        <td>{row['ioc_type']}</td>
        <td>{row.get('vt_detection_percentage', 'N/A')}</td>
        <td class="{get_severity_class(row['severity'])}">{get_severity_badge(row['severity'])}</td>
    """
    
    if with_ms_defender:
        basic_cols += f"<td>{get_ms_defender_span(row.get('ms_defender', 'unknown'))}</td>"
        
    basic_cols += f"""
        <td>{row.get('detection_names', '')}</td>
        <td><a href='{vt_link}' target='_blank'>Investigate</a></td>
    """
    
    if with_metadata:
        # Ensure category is included in the metadata columns
        category_value = row.get('category', '')
        if not category_value and row.get('category_display'):
            category_value = row.get('category_display', '')
        
        return f"""
        <tr class="{'bg-ms-known' if row['ms_defender'] == 'known' else ''}" data-ioc-type="{row['ioc_type']}" data-severity="{row['severity']}" data-ms-detection="{row['ms_defender']}" data-ioc-index="{idx}">
            {basic_cols}
            <td>{row.get('vt_detection_ratio', 'N/A')}</td>
            <td>{category_value}</td>
            <td>{row.get('vt_last_analysis_date', 'N/A')}</td>
            <td><a href='{vt_link}' target='_blank'>View</a></td>
        </tr>
        """
    
    return f"""
    <tr data-ioc-type="{row['ioc_type']}" data-severity="{row['severity']}" data-ms-detection="{row['ms_defender']}" data-ioc-index="{idx}">
        {basic_cols}
    </tr>
    """

def generate_html_report(results_list: List[Dict], 
                         scan_stats: Dict, 
                         output_path: Optional[str] = None, 
                         input_filename: str = "IOCs") -> Optional[str]:
    """
    Generate a static HTML report from scan results with timeline visualization
    
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
        # Process and transform data
        df, severity_counts, ms_defender_counts = process_data(results_list)
        
        # Extract stats from scan_stats or calculate from data
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
        charts['severity_chart'] = create_chart(
            severity_counts, 
            'pie', 
            names='Severity', 
            values='Count',
            color='Severity', 
            color_map=SEVERITY_COLORS,
            title='Severity'
        )
        
        charts['ms_defender_chart'] = create_chart(
            ms_defender_counts, 
            'pie', 
            names='Status', 
            values='Count',
            color='Status', 
            color_map={
                'known': COLORS['ms_known'], 
                'unknown': COLORS['ms_unknown'], 
                'N/A': COLORS['secondary']
            },
            title='MS Defender'
        )
        
        # Timeline charts - wrapped in try/except to ensure they don't break the report
        try:
            charts['detection_timeline'] = create_timeline_chart(df)
        except Exception as e:
            logger.error(f"Failed to generate detection timeline: {e}")
            charts['detection_timeline'] = f"<div class='alert alert-warning'><i class='fas fa-exclamation-circle'></i> Could not create timeline chart: {str(e)}</div>"
            
        try:
            charts['ioc_type_timeline'] = create_ioc_type_timeline(df)
        except Exception as e:
            logger.error(f"Failed to generate IOC type timeline: {e}")
            charts['ioc_type_timeline'] = f"<div class='alert alert-warning'><i class='fas fa-exclamation-circle'></i> Could not create IOC type chart: {str(e)}</div>"
            
        try:
            charts['detection_heatmap'] = create_detection_heatmap(df)
        except Exception as e:
            logger.error(f"Failed to generate detection heatmap: {e}")
            charts['detection_heatmap'] = f"<div class='alert alert-warning'><i class='fas fa-exclamation-circle'></i> Could not create detection heatmap: {str(e)}</div>"
        
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
        
        # Prepare export data - convert to serializable format
        export_data = []
        for _, row in df.iterrows():
            # Convert all values to simple types for JSON
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
        
        # Convert to JSON for the CSV export functionality
        try:
            csv_export_data = json.dumps(export_data, cls=DateTimeEncoder)
        except Exception as e:
            logger.error(f"Error serializing data to JSON: {e}")
            # Create a fallback version with minimal data
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
        input_filename_name = sanitize_for_html(Path(input_filename).name)
        generation_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Build the HTML template
        html_template = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="generator" content="VTScanner/1.3.1">
    <title>VirusTotal Scan Results - {input_filename_name}</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/5.15.4/css/all.min.css">
    <script src="https://cdn.plot.ly/plotly-latest.min.js"></script>
    <style>
        body {{ font-family: 'Segoe UI', sans-serif; background-color: #0b0c10; color: #ffffff; margin: 0; padding: 0; }}
        .container {{ width: 95%; margin: 0 auto; padding: 15px; }}
        .header {{ text-align: center; margin-bottom: 20px; color: #4361ee; padding: 15px 0; border-bottom: 1px solid #4361ee; }}
        .header h1 {{ font-size: 2.2rem; margin-bottom: 10px; }}
        .header p {{ font-size: 1rem; opacity: 0.8; }}
        .card {{ background-color: #1f2833; border-radius: 8px; box-shadow: 0 4px 12px rgba(0, 0, 0, 0.4); margin-bottom: 20px; overflow: hidden; }}
        .card-header {{ background-color: #1f2833; color: #e0e1dd; padding: 12px 15px; font-weight: bold; font-size: 1.1rem; border-bottom: 2px solid rgba(255, 255, 255, 0.1); display: flex; justify-content: space-between; align-items: center; }}
        .card-header .actions {{ display: flex; gap: 8px; }}
        .card-body {{ padding: 15px; }}
        .row {{ display: flex; flex-wrap: wrap; margin: 0 -10px; }}
        .col {{ flex: 1; min-width: 200px; padding: 0 10px; margin-bottom: 15px; }}
        .stats-card {{ text-align: center; padding: 15px 10px; display: flex; flex-direction: column; justify-content: center; align-items: center; height: 100%; }}
        .stats-card i {{ margin-bottom: 8px; opacity: 0.9; }}
        .stats-card h4 {{ margin-top: 5px; margin-bottom: 10px; font-size: 1rem; opacity: 0.9; }}
        .stats-card h2 {{ font-size: 2.2rem; margin: 0; font-weight: 600; }}
        .table-container {{ overflow-x: auto; border-radius: 4px; box-shadow: 0 2px 8px rgba(0, 0, 0, 0.2) inset; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 10px; overflow: hidden; }}
        th, td {{ padding: 10px 12px; text-align: left; border: 1px solid #444; }}
        th {{ background-color: #4361ee; color: white; font-weight: 600; position: sticky; top: 0; box-shadow: 0 2px 2px rgba(0, 0, 0, 0.1); }}
        tr:nth-child(even) {{ background-color: rgba(255, 255, 255, 0.05); }}
        tr:hover {{ background-color: rgba(255, 255, 255, 0.1); }}
        .chart-container {{ width: 100%; position: relative; }}
        .footer {{ text-align: center; margin-top: 30px; padding: 15px 0; border-top: 1px solid #555555; color: #e0e1dd; font-size: 1rem; }}
        .ioc-container {{ display: flex; align-items: center; justify-content: space-between; gap: 5px; }}
        .ioc-value {{ max-width: calc(100% - 30px); overflow: hidden; text-overflow: ellipsis; }}
        .copy-btn {{ background: none; border: none; color: #4361ee; cursor: pointer; padding: 3px 6px; border-radius: 3px; transition: all 0.2s; opacity: 0.6; }}
        .copy-btn:hover {{ opacity: 1; background-color: rgba(67, 97, 238, 0.1); }}
        .error-msg {{ color: #f72585; font-size: 0.85rem; margin-top: 4px; }}
        .notification {{ position: fixed; top: 20px; right: 20px; padding: 10px 20px; background-color: #4cc9f0; color: white; border-radius: 4px; box-shadow: 0 4px 8px rgba(0, 0, 0, 0.2); z-index: 1000; opacity: 0; transform: translateY(-20px); transition: all 0.3s; }}
        .notification.show {{ opacity: 1; transform: translateY(0); }}
        .primary {{ color: #4361ee; }}
        .success {{ color: #4cc9f0; }}
        .warning {{ color: #f9c74f; }}
        .danger {{ color: #f72585; }}
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
        .filter-container {{ padding: 15px; background-color: #1f2833; border-radius: 8px; margin-bottom: 15px; border: 1px solid rgba(255, 255, 255, 0.1); }}
        .filter-row {{ display: flex; flex-wrap: wrap; gap: 15px; margin-bottom: 15px; align-items: flex-end; }}
        .filter-group {{ flex: 1; min-width: 200px; }}
        .filter-group label {{ display: block; margin-bottom: 6px; font-weight: 500; opacity: 0.9; }}
        .filter-input {{ width: 100%; padding: 8px 10px; background-color: #1f2833; color: #e0e1dd; border: 1px solid #4361ee; border-radius: 4px; font-size: 0.95rem; }}
        .filter-btn {{ background-color: #4361ee; color: white; border: none; padding: 8px 15px; border-radius: 4px; cursor: pointer; font-weight: 600; display: flex; align-items: center; gap: 6px; }}
        .filter-btn:hover {{ background-color: #4895ef; }}
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
        .close-modal {{ background: none; border: none; font-size: 1.5rem; color: #e0e1dd; cursor: pointer; }}
        .close-modal:hover {{ color: #f72585; }}
        .modal-body {{ margin-bottom: 20px; }}
        .modal-footer {{ display: flex; justify-content: flex-end; gap: 10px; }}
        .action-btn {{ background-color: #4361ee; color: white; border: none; padding: 6px 12px; border-radius: 4px; cursor: pointer; font-weight: 600; font-size: 0.85rem; display: flex; align-items: center; gap: 5px; }}
        .action-btn:hover {{ background-color: #4895ef; }}
        .action-btn.secondary {{ background-color: #555555; }}
        .pagination-controls {{ display: flex; justify-content: center; margin-top: 15px; gap: 8px; }}
        .pagination-btn {{ background-color: #1f2833; color: white; border: 1px solid #4361ee; padding: 5px 10px; border-radius: 4px; cursor: pointer; }}
        .pagination-btn.active {{ background-color: #4361ee; }}
        .alert {{ padding: 15px; margin-bottom: 20px; border-radius: 4px; }}
        .alert-warning {{ background-color: rgba(249, 199, 79, 0.2); border-left: 4px solid #f9c74f; }}
        #timeline-details {{ transition: all 0.3s ease; }}
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
            <h1><i class="fas fa-shield-virus"></i> VirusTotal Scan Results - {input_filename_name}</h1>
            <p>Report generated on {generation_time}</p>
        </div>
        
        <!-- Summary Stats Cards - First Row -->
        <div class="row">
            <div class="col">
                <div class="card">
                    <div class="stats-card">
                        <i class="fas fa-search fa-2x" style="color: #4895ef;"></i>
                        <h4>Total IOCs</h4>
                        <h2 style="color: #4895ef;">{total_iocs}</h2>
                    </div>
                </div>
            </div>
            <div class="col">
                <div class="card">
                    <div class="stats-card">
                        <i class="fas fa-virus fa-2x" style="color: #f72585;"></i>
                        <h4>Malicious</h4>
                        <h2 style="color: #f72585;">{malicious_count}</h2>
                    </div>
                </div>
            </div>
            <div class="col">
                <div class="card">
                    <div class="stats-card">
                        <i class="fas fa-exclamation-triangle fa-2x" style="color: #f9c74f;"></i>
                        <h4>Suspicious</h4>
                        <h2 style="color: #f9c74f;">{suspicious_count}</h2>
                    </div>
                </div>
            </div>
            <div class="col">
                <div class="card">
                    <div class="stats-card">
                        <i class="fas fa-check-circle fa-2x" style="color: #4cc9f0;"></i>
                        <h4>Clean</h4>
                        <h2 style="color: #4cc9f0;">{clean_count}</h2>
                    </div>
                </div>
            </div>
        </div>
        
        <!-- Microsoft Defender Stats & Charts Row -->
        <div class="row">
            <div class="col" style="flex: 1;">
                <div class="card">
                    <div class="stats-card">
                        <i class="fas fa-shield-alt fa-2x" style="color: #e63946;"></i>
                        <h4>MS Defender - Known</h4>
                        <h2 style="color: #e63946;">{ms_known_count}</h2>
                    </div>
                </div>
            </div>
            <div class="col" style="flex: 1;">
                <div class="card">
                    <div class="stats-card">
                        <i class="fas fa-question-circle fa-2x" style="color: #6c757d;"></i>
                        <h4>MS Defender - Unknown</h4>
                        <h2 style="color: #6c757d;">{ms_unknown_count}</h2>
                    </div>
                </div>
            </div>
            <div class="col" style="flex: 2;">
                <div class="card">
                    <div class="card-header">
                        <i class="fas fa-chart-pie"></i> Detection Severity
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
                        <i class="fas fa-shield-alt"></i> MS Defender Detection
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
                    <button class="action-btn" id="toggle-timeline-btn">
                        <i class="fas fa-expand"></i> Expand/Collapse
                    </button>
                </div>
            </div>
            <div class="card-body">
                <div id="timeline-details">
                    <div class="row">
                        <div class="col" style="flex: 1;">
                            <div class="card">
                                <div class="card-header">
                                    <i class="fas fa-calendar-alt"></i> Detection Timeline
                                </div>
                                <div class="card-body">
                                    <div class="chart-container" id="detection-timeline">
{charts['detection_timeline']}
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                    <div class="row">
                        <div class="col" style="flex: 1;">
                            <div class="card">
                                <div class="card-header">
                                    <i class="fas fa-sitemap"></i> IOC Types Over Time
                                </div>
                                <div class="card-body">
                                    <div class="chart-container" id="ioc-type-timeline">
{charts['ioc_type_timeline']}
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                    <div class="row">
                        <div class="col" style="flex: 1;">
                            <div class="card">
                                <div class="card-header">
                                    <i class="fas fa-fire"></i> Detection Heatmap
                                </div>
                                <div class="card-body">
                                    <div class="chart-container" id="detection-heatmap">
{charts['detection_heatmap']}
                                    </div>
                                </div>
                            </div>
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
        const message = successful ? 'Copied to clipboard!' : 'Copy failed';
        showNotification(message);
    }} catch (err) {{
        showNotification('Failed to copy: ' + err);
    }}
    
    document.body.removeChild(textarea);
}}

// Function to show notification
function showNotification(message, type = 'success') {{
    const notification = document.getElementById('notification');
    notification.textContent = message;
    notification.className = 'notification show ' + type;
    
    setTimeout(() => {{
        notification.className = 'notification';
    }}, 3000);
}}

// Client-side filtering functionality
document.addEventListener('DOMContentLoaded', function() {{
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
    
    // Timeline toggle
    const toggleTimelineBtn = document.getElementById('toggle-timeline-btn');
    const timelineDetails = document.getElementById('timeline-details');
    
    if (toggleTimelineBtn && timelineDetails) {{
        // Start with timeline expanded
        toggleTimelineBtn.addEventListener('click', function() {{
            if (timelineDetails.style.display === 'none') {{
                timelineDetails.style.display = 'block';
                toggleTimelineBtn.innerHTML = '<i class="fas fa-compress"></i> Collapse';
            }} else {{
                timelineDetails.style.display = 'none';
                toggleTimelineBtn.innerHTML = '<i class="fas fa-expand"></i> Expand';
            }}
        }});
    }}
    
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
    if (resetFiltersBtn) {{
        resetFiltersBtn.addEventListener('click', function() {{
            if (iocTypeFilter) iocTypeFilter.value = 'all';
            if (severityFilter) severityFilter.value = 'all';
            if (msDetectionFilter) msDetectionFilter.value = 'all';
            if (searchInput) searchInput.value = '';
            applyFilters();
        }});
    }}
    
    // Copy all IOCs from tables
    if (copyAllBtn) {{
        copyAllBtn.addEventListener('click', function() {{
            copyTableContent(resultsTable);
        }});
    }}
    
    if (copyCriticalBtn) {{
        copyCriticalBtn.addEventListener('click', function() {{
            copyTableContent(criticalTable);
        }});
    }}
    
    if (copyMsKnownBtn) {{
        copyMsKnownBtn.addEventListener('click', function() {{
            copyTableContent(msDetectionTable);
        }});
    }}
    
    if (copyMsUnknownBtn) {{
        copyMsUnknownBtn.addEventListener('click', function() {{
            copyTableContent(msUnknownTable);
        }});
    }}
    
    // Export functionality
    if (exportCsvBtn) {{
        exportCsvBtn.addEventListener('click', function() {{
            exportModal.classList.add('show');
        }});
    }}
    
    if (closeExportModal) {{
        closeExportModal.addEventListener('click', function() {{
            exportModal.classList.remove('show');
        }});
    }}
    
    if (cancelExport) {{
        cancelExport.addEventListener('click', function() {{
            exportModal.classList.remove('show');
        }});
    }}
    
    if (exportCsvConfirm) {{
        exportCsvConfirm.addEventListener('click', function() {{
            exportToCsv();
            exportModal.classList.remove('show');
        }});
    }}
    
    // Function to copy all IOCs from a table
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
                // Only copy visible rows (respect filters)
                if (row.style.display !== 'none') {{
                    const iocCell = row.querySelector('.ioc-value');
                    if (iocCell) {{
                        iocList.push(iocCell.textContent.trim());
                    }}
                }}
            }});
            
            if (iocList.length === 0) {{
                showNotification('No visible IOCs to copy', 'warning');
                return;
            }}
            
            const iocText = iocList.join('\\n');
            copyToClipboard(iocText);
            showNotification(`Copied ${{iocList.length}} IOCs to clipboard!`);
        }} catch (err) {{
            console.error('Error copying table content:', err);
            showNotification('Error copying IOCs', 'danger');
        }}
    }}
    
    // Function to export data to CSV
    function exportToCsv() {{
        try {{
            // Prepare CSV content
            let csvContent = '';
            
            // Get headers
            const headers = [];
            for (const key in reportData[0]) {{
                headers.push(key);
            }}
            
            csvContent += headers.join(',') + '\\n';
            
            // Add rows
            reportData.forEach(row => {{
                const values = headers.map(header => {{
                    const value = row[header];
                    // Escape values containing commas, quotes, or newlines
                    if (typeof value === 'string' && (value.includes(',') || value.includes('"') || value.includes('\\n'))) {{
                        return '"' + value.replace(/"/g, '""') + '"';
                    }}
                    return value !== undefined ? value : '';
                }});
                csvContent += values.join(',') + '\\n';
            }});
            
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
    setTimeout(applyFilters, 300);
    
    function applyFilters() {{
        try {{
            const iocType = iocTypeFilter ? iocTypeFilter.value : 'all';
            const severity = severityFilter ? severityFilter.value : 'all';
            const msDetection = msDetectionFilter ? msDetectionFilter.value : 'all';
            const searchText = searchInput ? searchInput.value.toLowerCase() : '';
            
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
            
            // Update the filter status
            updateFilterStatus({{
                results: resultsCount,
                critical: criticalCount,
                msDetection: msDetectionCount,
                msUnknown: msUnknownCount
            }});
            
        }} catch (err) {{
            console.error("Error applying filters:", err);
            showNotification('Error applying filters', 'danger');
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
    
    // Setup pagination if needed
    setupPagination();
    
    function setupPagination() {{
        if (!resultsTable) return;
        
        const rows = resultsTable.querySelectorAll('tbody tr');
        const rowsPerPage = 50;
        const pageCount = Math.ceil(rows.length / rowsPerPage);
        
        if (pageCount <= 1) return;
        
        // Add pagination controls
        const paginationControls = document.querySelector('.pagination-controls');
        if (!paginationControls) return;
        
        for (let i = 1; i <= pageCount; i++) {{
            const pageBtn = document.createElement('button');
            pageBtn.className = 'pagination-btn';
            pageBtn.textContent = i;
            if (i === 1) pageBtn.classList.add('active');
            
            pageBtn.addEventListener('click', function() {{
                document.querySelectorAll('.pagination-btn').forEach(btn => {{
                    btn.classList.remove('active');
                }});
                this.classList.add('active');
                
                const start = (i - 1) * rowsPerPage;
                const end = start + rowsPerPage;
                
                rows.forEach((row, index) => {{
                    if (index >= start && index < end) {{
                        row.style.display = '';
                    }} else {{
                        row.style.display = 'none';
                    }}
                }});
                
                resultsTable.closest('.table-container').scrollTop = 0;
            }});
            
            paginationControls.appendChild(pageBtn);
        }}
        
        // Show first page by default
        for (let i = 0; i < rows.length; i++) {{
            if (i < rowsPerPage) {{
                rows[i].style.display = '';
            }} else {{
                rows[i].style.display = 'none';
            }}
        }}
    }}
    
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
