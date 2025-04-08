"""
VirusTotal IOC Scanner HTML Report Generator

This module handles the generation of HTML reports for the VirusTotal IOC Scanner,
with optimized code for better performance and responsive charts for all devices.

Author: VT Scanner Team
Version: 1.3.0
"""

import os
import html
import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Union, Any

try:
    import pandas as pd
    import plotly.graph_objects as go
    import plotly.io as pio
    from plotly.subplots import make_subplots
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
    'dark': '#1f2833',
    'background': '#0b0c10',
    'ms_known': '#e63946', 
    'ms_unknown': '#6c757d'
}

# Chart color schemes
CHART_COLORS = {
    'bar': ['#4361ee', '#f72585', '#4cc9f0', '#f9c74f', '#90be6d', '#43aa8b'],
    'severity': {
        'Critical': '#f72585', 
        'High': '#f9c74f',
        'Medium': '#4895ef', 
        'Clean': '#4cc9f0',
        'Error': '#555555'
    },
    'msdefender': {
        'known': '#e63946', 
        'unknown': '#6c757d', 
        'N/A': '#555555'
    }
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
    result = text.replace('\\', '\\\\').replace("'", "\\'").replace('"', '\\"')
    result = result.replace('\n', '\\n').replace('\r', '\\r').replace('\t', '\\t')
    return result

def get_badge_and_class(severity: str) -> tuple:
    """Return HTML for a severity badge and CSS class in one function"""
    badge_classes = {
        'Critical': 'badge badge-danger', 
        'High': 'badge badge-warning',
        'Medium': 'badge badge-info', 
        'Clean': 'badge badge-success',
        'Error': 'badge badge-secondary'
    }
    css_classes = {
        'Critical': 'severity-Critical', 
        'High': 'severity-High',
        'Medium': 'severity-Medium', 
        'Clean': 'severity-Clean',
        'Error': 'severity-Error'
    }
    badge = f'<span class="{badge_classes.get(severity, "")}">{severity}</span>' if severity in badge_classes else ""
    css_class = css_classes.get(severity, '')
    return badge, css_class

def get_ms_defender_span(status: str) -> str:
    """Return HTML for MS Defender status"""
    if status == "known":
        return '<span class="ms-known"><i class="fas fa-shield-alt"></i> known</span>'
    return '<span class="ms-unknown"><i class="fas fa-question-circle"></i> unknown</span>'

def format_category_value(category_value: str, ioc_type: str) -> str:
    """Format category values for better display"""
    if category_value == "type-unsupported" and ioc_type == "hash":
        return "Hash File"
    return category_value or ""

def create_bar_chart(data, title='IOC Type Distribution'):
    """Create a responsive bar chart optimized for all devices"""
    try:
        if not data['names'] or not data['values'] or len(data['names']) != len(data['values']):
            return '<div class="chart-error">Invalid data for chart creation</div>'
            
        # Create a figure with a single subplot
        fig = make_subplots(rows=1, cols=1)
        
        # Add a bar trace for each IOC type
        for i, (name, value) in enumerate(zip(data['names'], data['values'])):
            fig.add_trace(
                go.Bar(
                    x=[name],
                    y=[value],
                    text=[value],
                    textposition='auto',
                    name=name,
                    marker_color=CHART_COLORS['bar'][i % len(CHART_COLORS['bar'])],
                    hoverinfo='x+y',
                    showlegend=True
                ),
                row=1, col=1
            )
        
        # Update layout for better mobile and desktop display
        fig.update_layout(
            autosize=True,
            height=350,
            margin=dict(l=40, r=40, t=60, b=60),
            paper_bgcolor='rgba(0,0,0,0)',
            plot_bgcolor='rgba(0,0,0,0)',
            font=dict(
                family="Segoe UI, Arial, sans-serif",
                size=14,
                color="white"
            ),
            title={
                'text': title,
                'y': 0.95,
                'x': 0.5,
                'xanchor': 'center',
                'yanchor': 'top',
                'font': {'size': 18}
            },
            showlegend=True,
            legend=dict(
                orientation="h",
                yanchor="bottom",
                y=-0.2,
                xanchor="center",
                x=0.5,
                font=dict(size=12)
            ),
            xaxis=dict(
                title='',
                showgrid=False,
                showline=False,
                showticklabels=True,
                zeroline=False,
                tickfont=dict(size=12)
            ),
            yaxis=dict(
                title='Count',
                showgrid=True,
                gridcolor='rgba(255,255,255,0.1)',
                showline=False,
                showticklabels=True,
                zeroline=False,
                tickfont=dict(size=12),
                # Ensure y-axis starts at 0 and has appropriate steps
                rangemode='nonnegative',
                tick0=0,
                dtick=max(1, max(data['values']) // 5)  # Dynamic step size
            ),
            template='plotly_dark'
        )
        
        # Override the bar width for better display
        fig.update_traces(width=0.6)
        
        # Set a fixed range with some padding at the top
        max_value = max(data['values']) if data['values'] else 1
        fig.update_yaxes(range=[0, max_value * 1.2])
        
        # Generate HTML
        config = {
            'displayModeBar': False,
            'responsive': True,
            'staticPlot': False,
            'scrollZoom': False
        }
        
        chart_html = pio.to_html(fig, full_html=False, include_plotlyjs=False, config=config)
        
        # Add data attribute for chart identification
        chart_html = chart_html.replace('<div', '<div data-chart-type="ioc_distribution"', 1)
        
        # Add backup data
        js_data = {name: int(value) for name, value in zip(data['names'], data['values'])}
        chart_html += f'<script>window.iocTypeData = {json.dumps(js_data)};</script>'
        
        return chart_html
    
    except Exception as e:
        logger.error(f"Error creating bar chart: {e}")
        return f'<div class="chart-error">Error creating bar chart: {str(e)}</div>'

def create_pie_chart(data, title, color_map, hole=0.4):
    """Create a responsive pie chart optimized for all devices"""
    try:
        if not data['names'] or not data['values'] or len(data['names']) != len(data['values']):
            return '<div class="chart-error">Invalid data for chart creation</div>'
            
        # Create colors list based on names
        colors = [color_map.get(name, COLORS['secondary']) for name in data['names']]
        
        # Create the pie chart
        fig = go.Figure(data=[
            go.Pie(
                labels=data['names'],
                values=data['values'],
                hole=hole,
                textinfo='percent',
                hoverinfo='label+value+percent',
                textfont=dict(size=14, color='white'),
                marker=dict(
                    colors=colors,
                    line=dict(color='rgba(0,0,0,0)', width=0)
                ),
                pull=[0.03 if name == 'Critical' or name == 'known' else 0 for name in data['names']],
                direction='clockwise',
                sort=False
            )
        ])
        
        # Update layout for better display
        fig.update_layout(
            autosize=True,
            height=350,
            margin=dict(l=20, r=20, t=60, b=60),
            paper_bgcolor='rgba(0,0,0,0)',
            plot_bgcolor='rgba(0,0,0,0)',
            font=dict(
                family="Segoe UI, Arial, sans-serif",
                size=14,
                color="white"
            ),
            title={
                'text': title,
                'y': 0.95,
                'x': 0.5,
                'xanchor': 'center',
                'yanchor': 'top',
                'font': {'size': 18}
            },
            showlegend=True,
            legend=dict(
                orientation="h",
                yanchor="bottom",
                y=-0.15,
                xanchor="center",
                x=0.5,
                font=dict(size=12)
            ),
            annotations=[
                dict(
                    text=title.split()[0],  # First word of title
                    x=0.5,
                    y=0.5,
                    font=dict(size=16, color='white'),
                    showarrow=False
                )
            ]
        )
        
        # Generate HTML
        config = {
            'displayModeBar': False,
            'responsive': True,
            'staticPlot': False,
            'scrollZoom': False
        }
        
        chart_html = pio.to_html(fig, full_html=False, include_plotlyjs=False, config=config)
        
        # Add data attribute for chart identification
        chart_type = 'severity_distribution' if title.startswith('Detection') else 'ms_defender_distribution'
        chart_html = chart_html.replace('<div', f'<div data-chart-type="{chart_type}"', 1)
        
        # Add backup data
        js_data = {name: int(value) for name, value in zip(data['names'], data['values'])}
        var_name = 'severityData' if chart_type == 'severity_distribution' else 'msDefenderData'
        chart_html += f'<script>window.{var_name} = {json.dumps(js_data)};</script>'
        
        return chart_html
        
    except Exception as e:
        logger.error(f"Error creating pie chart: {e}")
        return f'<div class="chart-error">Error creating pie chart: {str(e)}</div>'

def generate_table_row(row, idx, ms_defender=True, metadata=False, last_analysis=True):
    """Generate HTML for a table row with consistent formatting"""
    vt_link = row.get('vt_link', '')
    if not isinstance(vt_link, str) or not vt_link.startswith(('http://', 'https://')):
        vt_link = ''
        
    error_display = ""
    if pd.notna(row.get('error')) and row.get('error'):
        error_display = f'<div class="error-msg">{row["error"]}</div>'
    
    # Use sanitize_for_js for copy button
    safe_ioc = sanitize_for_js(row['ioc'])
        
    # Get formatted badge and class for severity
    badge, css_class = get_badge_and_class(row['severity'])
    
    # Format category display for type-unsupported
    category_display = ""
    if 'category' in row:
        category_value = row.get('category', '')
        if category_value == "type-unsupported":
            category_display = '<span title="VT doesn\'t support detailed categorization for this type">Hash File</span>'
        else:
            category_display = category_value
    
    # Format detection percentage
    detection_pct = row.get('vt_detection_percentage', 'N/A')
    if detection_pct != 'N/A' and not pd.isna(detection_pct):
        try:
            detection_pct = f"{float(detection_pct):.1f}"
        except (ValueError, TypeError):
            pass
    
    # Get last analysis date
    last_analysis_date = row.get('vt_last_analysis_date', 'N/A')
    
    # Basic columns that appear in all tables
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
        <td>{detection_pct}</td>
        <td class="{css_class}">{badge}</td>
    """
    
    # Add MS Defender column if required
    if ms_defender:
        basic_cols += f"<td>{get_ms_defender_span(row.get('ms_defender', 'unknown'))}</td>"
        
    # Add detection names and link
    basic_cols += f"""
        <td>{row.get('detection_names', '')}</td>
        <td><a href='{vt_link}' target='_blank'>Investigate</a></td>
    """
    
    # Add last analysis date if required
    if last_analysis:
        basic_cols += f"<td>{last_analysis_date}</td>"
        
    # Add additional metadata columns for the full table
    if metadata:
        return f"""
        <tr class="{'bg-ms-known' if row['ms_defender'] == 'known' else ''}" data-ioc-type="{row['ioc_type']}" data-severity="{row['severity']}" data-ms-detection="{row['ms_defender']}" data-ioc-index="{idx}">
            {basic_cols}
            <td>{row.get('vt_detection_ratio', 'N/A')}</td>
            <td>{category_display}</td>
            <td><a href='{vt_link}' target='_blank'>View</a></td>
        </tr>
        """
    
    # Basic row for summary tables
    return f"""
    <tr data-ioc-type="{row['ioc_type']}" data-severity="{row['severity']}" data-ms-detection="{row['ms_defender']}" data-ioc-index="{idx}">
        {basic_cols}
    </tr>
    """

def generate_html_report(results_list: List[Dict], 
                         scan_stats: Dict, 
                         output_path: Optional[str] = None, 
                         input_filename: str = "IOCs") -> Optional[str]:
    """Generate HTML report with improved code organization and performance"""
    if not results_list:
        logger.warning("No results to display.")
        return None
    
    try:
        # Process and sanitize data
        results_list_copy = []
        for result in results_list:
            # Create a sanitized copy of each result
            sanitized = {}
            for k, v in result.items():
                if k == 'last_analysis_results':
                    continue
                
                # Format category values
                if k == 'category' and isinstance(v, str):
                    sanitized[k] = format_category_value(v, result.get('ioc_type', ''))
                elif isinstance(v, str):
                    sanitized[k] = sanitize_for_html(v)
                else:
                    sanitized[k] = v
                    
            results_list_copy.append(sanitized)
        
        df = pd.DataFrame(results_list_copy)
        
        # Handle missing columns
        for required_col in ['ioc_type', 'vt_detection_percentage', 'error']:
            if required_col not in df.columns:
                df[required_col] = 'unknown' if required_col == 'ioc_type' else ''
        
        # Convert detection percentage to numeric
        if 'vt_detection_percentage' in df.columns:
            df['vt_detection_percentage'] = pd.to_numeric(df['vt_detection_percentage'], errors='coerce').round(1)
        
        # Determine severity based on detection percentage
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
        
        # Add severity if not present
        if 'severity' not in df.columns:
            df["severity"] = df.apply(get_severity, axis=1)
            
        df = df.fillna("N/A")
        
        # Extract Microsoft Defender status
        def get_ms_defender_status(row):
            if 'ms_defender' in row and row['ms_defender'] in ['known', 'unknown']:
                return row['ms_defender']
            if 'detection_names' in row and isinstance(row['detection_names'], str):
                if row['detection_names'].lower().find('microsoft') != -1 or row['detection_names'].lower().find('defender') != -1:
                    return 'known'
            return 'unknown'
        
        if 'ms_defender' not in df.columns:
            df["ms_defender"] = df.apply(get_ms_defender_status, axis=1)
        
        # Prepare summary data for charts - ensure no empty values
        if 'ioc_type' in df.columns and not df['ioc_type'].empty:
            # Replace unknown values for better display
            df['ioc_type'] = df['ioc_type'].replace('', 'unknown').replace('N/A', 'unknown')
            
            # Get counts by IOC type
            ioc_type_counts = df["ioc_type"].value_counts().reset_index()
            ioc_type_counts.columns = ["IOC Type", "Count"]
            
            # Sort by count descending for better visualization
            ioc_type_counts = ioc_type_counts.sort_values('Count', ascending=False)
        else:
            # Create default data if no ioc_type data available
            ioc_type_counts = pd.DataFrame({
                "IOC Type": ["unknown"],
                "Count": [len(df)]
            })
        
        # Get severity counts
        severity_counts = df["severity"].value_counts().reset_index()
        severity_counts.columns = ["Severity", "Count"]
        
        # Reorder severity categories for better presentation
        severity_order = ['Critical', 'High', 'Medium', 'Clean', 'Error']
        severity_counts['Order'] = severity_counts['Severity'].apply(lambda x: severity_order.index(x) if x in severity_order else 999)
        severity_counts = severity_counts.sort_values('Order').drop('Order', axis=1)
        
        # Get MS Defender counts
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
        
        # Create charts with specialized functions
        ioc_type_chart = create_bar_chart(
            {
                'names': ioc_type_counts["IOC Type"].tolist(),
                'values': ioc_type_counts["Count"].tolist()
            },
            'IOC Type Distribution'
        )
        
        severity_chart = create_pie_chart(
            {
                'names': severity_counts["Severity"].tolist(),
                'values': severity_counts["Count"].tolist()
            },
            'Detection Severity',
            CHART_COLORS['severity'],
            hole=0.4
        )
        
        ms_defender_chart = create_pie_chart(
            {
                'names': ms_defender_counts["Status"].tolist(),
                'values': ms_defender_counts["Count"].tolist()
            },
            'Microsoft Defender Detection',
            CHART_COLORS['msdefender'],
            hole=0.4
        )
        
        # Prepare data for tables with filtering options
        critical_df = df[df['severity'].isin(['Critical', 'High'])]
        ms_known_df = df[df['ms_defender'] == 'known']
        ms_unknown_df = df[df['ms_defender'] == 'unknown']
        
        # Generate table rows with unified function
        critical_rows = "".join([generate_table_row(row, idx, ms_defender=True, metadata=False, last_analysis=True) 
                                for idx, row in critical_df.iterrows()]) if not critical_df.empty else "<tr><td colspan='8'>No critical findings</td></tr>"
        
        ms_detection_rows = "".join([generate_table_row(row, idx, ms_defender=False, metadata=False, last_analysis=True) 
                                    for idx, row in ms_known_df.iterrows()]) if not ms_known_df.empty else "<tr><td colspan='7'>No Microsoft Defender detections</td></tr>"
        
        ms_unknown_rows = "".join([generate_table_row(row, idx, ms_defender=False, metadata=False, last_analysis=True) 
                                  for idx, row in ms_unknown_df.iterrows()]) if not ms_unknown_df.empty else "<tr><td colspan='7'>No unknown IOCs</td></tr>"
        
        all_results_rows = "".join([generate_table_row(row, idx, ms_defender=True, metadata=True, last_analysis=True) 
                                   for idx, row in df.iterrows()]) if not df.empty else "<tr><td colspan='11'>No results</td></tr>"
        
        # Create dropdown options for filters
        unique_ioc_types = sorted(filter(None, df['ioc_type'].unique().tolist()))
        ioc_type_options = "".join([f'<option value="{ioc_type}">{ioc_type}</option>' for ioc_type in unique_ioc_types])
        
        severity_values = ['Critical', 'High', 'Medium', 'Clean', 'Error']
        unique_severities = [sev for sev in severity_values if sev in df['severity'].unique()]
        severity_options = "".join([f'<option value="{severity}">{severity}</option>' for severity in unique_severities])
        
        # Prepare export data
        export_data = []
        for _, row in df.iterrows():
            export_row = {k: v for k, v in row.items() if k != 'last_analysis_results'}
            export_data.append(export_row)
        
        # Convert to JSON for the CSV export functionality
        try:
            csv_export_data = json.dumps(export_data)
        except Exception as e:
            logger.error(f"Error serializing export data: {e}")
            # Create a simplified version if serialization fails
            simplified_data = []
            for item in export_data:
                simplified_item = {}
                for k, v in item.items():
                    if isinstance(v, (str, int, float, bool, type(None))):
                        simplified_item[k] = v
                    else:
                        simplified_item[k] = str(v)
                simplified_data.append(simplified_item)
            csv_export_data = json.dumps(simplified_data)
        
        # Load HTML template from external file if exists or use embedded template
        template_path = Path(__file__).parent / "report_template.html"
        if template_path.exists():
            with open(template_path, 'r', encoding='utf-8') as f:
                html_template = f.read()
        else:
            # Embedded template
            html_template = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>VirusTotal Scan Results - {input_filename}</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/5.15.4/css/all.min.css">
    <script src="https://cdn.plot.ly/plotly-2.24.1.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/jquery/3.6.0/jquery.min.js"></script>
    <style>
        :root {
            --primary-color: #4361ee;
            --secondary-color: #555555;
            --success-color: #4cc9f0;
            --info-color: #4895ef;
            --warning-color: #f9c74f;
            --danger-color: #f72585;
            --light-color: #e0e1dd;
            --dark-color: #1f2833;
            --background-color: #0b0c10;
            --ms-known-color: #e63946;
            --ms-unknown-color: #6c757d;
            --card-bg-color: #1f2833;
            --card-header-border: rgba(255, 255, 255, 0.1);
            --table-border-color: #444;
            --table-hover-bg: rgba(255, 255, 255, 0.1);
            --table-stripe-bg: rgba(255, 255, 255, 0.05);
        }
        
        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }
        
        body { 
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
            background-color: var(--background-color); 
            color: #ffffff; 
            margin: 0; 
            padding: 0;
            line-height: 1.6;
        }
        
        .container { 
            width: 95%; 
            margin: 0 auto; 
            padding: 20px;
        }
        
        .header { 
            text-align: center; 
            margin-bottom: 30px; 
            color: var(--primary-color); 
            padding: 20px 0; 
            border-bottom: 1px solid var(--primary-color);
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
            background-color: var(--card-bg-color); 
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
            background-color: var(--card-bg-color); 
            color: var(--light-color); 
            padding: 15px 20px; 
            font-weight: bold; 
            font-size: 1.2rem; 
            border-bottom: 2px solid var(--card-header-border); 
            display: flex; 
            justify-content: space-between; 
            align-items: center;
        }
        
        .card-header .actions { 
            display: flex; 
            gap: 10px;
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
            border: 1px solid var(--table-border-color);
        }
        
        th { 
            background-color: var(--primary-color); 
            color: white; 
            font-weight: 600; 
            position: sticky; 
            top: 0; 
            box-shadow: 0 2px 2px rgba(0, 0, 0, 0.1);
        }
        
        tr:nth-child(even) { 
            background-color: var(--table-stripe-bg);
        }
        
        tr:hover { 
            background-color: var(--table-hover-bg);
        }
        
        .chart-container { 
            width: 100%; 
            margin-top: 15px; 
            position: relative; 
            min-height: 350px;
        }
        
        .plotly-graph-div {
            min-height: 350px !important;
        }
        
        .chart-error { 
            padding: 20px; 
            text-align: center; 
            color: var(--danger-color); 
            background-color: rgba(247, 37, 133, 0.1); 
            border-radius: 4px;
        }
        
        .chart-fallback { 
            padding: 20px; 
            background-color: var(--table-stripe-bg); 
            border-radius: 4px; 
            margin-top: 15px;
        }
        
        .footer { 
            text-align: center; 
            margin-top: 40px; 
            padding: 20px 0; 
            border-top: 1px solid var(--secondary-color); 
            color: var(--light-color); 
            font-size: 1.1rem;
        }
        
        .ioc-container { 
            display: flex; 
            align-items: center; 
            justify-content: space-between; 
            gap: 5px;
        }
        
        .ioc-value { 
            max-width: calc(100% - 30px); 
            overflow: hidden; 
            text-overflow: ellipsis;
        }
        
        .copy-btn { 
            background: none; 
            border: none; 
            color: var(--primary-color); 
            cursor: pointer; 
            padding: 3px 6px; 
            border-radius: 3px; 
            transition: all 0.2s; 
            opacity: 0.6;
        }
        
        .copy-btn:hover { 
            opacity: 1; 
            background-color: rgba(67, 97, 238, 0.1);
        }
        
        .copy-btn.copied { 
            color: var(--success-color);
        }
        
        .action-btn { 
            background-color: var(--primary-color); 
            color: white; 
            border: none; 
            padding: 6px 12px; 
            border-radius: 4px; 
            cursor: pointer; 
            font-weight: 600; 
            font-size: 0.85rem; 
            display: flex; 
            align-items: center; 
            gap: 5px; 
            transition: background-color 0.2s;
        }
        
        .action-btn:hover { 
            background-color: var(--info-color);
        }
        
        .action-btn.secondary { 
            background-color: var(--secondary-color);
        }
        
        .action-btn.secondary:hover { 
            background-color: #666666;
        }
        
        .error-msg { 
            color: var(--danger-color); 
            font-size: 0.85rem; 
            margin-top: 4px;
        }
        
        .notification { 
            position: fixed; 
            top: 20px; 
            right: 20px; 
            padding: 10px 20px; 
            background-color: var(--success-color); 
            color: white; 
            border-radius: 4px; 
            box-shadow: 0 4px 8px rgba(0, 0, 0, 0.2); 
            z-index: 1000; 
            opacity: 0; 
            transform: translateY(-20px); 
            transition: all 0.3s;
        }
        
        .notification.show { 
            opacity: 1; 
            transform: translateY(0);
        }
        
        .primary { color: var(--primary-color); }
        .success { color: var(--success-color); }
        .info { color: var(--info-color); }
        .warning { color: var(--warning-color); }
        .danger { color: var(--danger-color); }
        
        .bg-danger { background-color: rgba(247, 37, 133, 0.15); }
        .bg-warning { background-color: rgba(249, 199, 79, 0.15); }
        .bg-info { background-color: rgba(72, 149, 239, 0.15); }
        .bg-success { background-color: rgba(76, 201, 240, 0.15); }
        .bg-error { background-color: rgba(85, 85, 85, 0.15); }
        
        .ms-known { color: var(--ms-known-color); }
        .ms-unknown { color: var(--ms-unknown-color); }
        .bg-ms-known { background-color: rgba(230, 57, 70, 0.15); }
        
        .severity-Critical { color: var(--danger-color); font-weight: bold; }
        .severity-High { color: var(--warning-color); font-weight: bold; }
        .severity-Medium { color: var(--info-color); }
        .severity-Clean { color: var(--success-color); }
        .severity-Error { color: var(--secondary-color); }
        
        a { 
            color: var(--info-color); 
            text-decoration: none; 
            transition: color 0.2s;
        }
        
        a:hover { 
            color: var(--primary-color); 
            text-decoration: underline;
        }
        
        .filter-container { 
            padding: 20px; 
            background-color: var(--card-bg-color); 
            border-radius: 8px; 
            margin-bottom: 20px; 
            border: 1px solid var(--card-header-border);
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
            background-color: var(--card-bg-color); 
            color: var(--light-color); 
            border: 1px solid var(--primary-color); 
            border-radius: 4px; 
            font-size: 1rem; 
            transition: all 0.2s;
        }
        
        .filter-input:focus { 
            outline: none; 
            border-color: var(--info-color); 
            box-shadow: 0 0 0 2px rgba(67, 97, 238, 0.3);
        }
        
        .filter-btn { 
            background-color: var(--primary-color); 
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
            background-color: var(--info-color);
        }
        
        .tooltip { 
            position: relative; 
            display: inline-block; 
            cursor: help;
        }
        
        .tooltip .tooltiptext { 
            visibility: hidden; 
            width: 200px; 
            background-color: var(--card-bg-color); 
            color: var(--light-color); 
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
            border: 1px solid var(--primary-color);
        }
        
        .tooltip:hover .tooltiptext { 
            visibility: visible; 
            opacity: 1;
        }
        
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
        
        .badge-primary { background-color: var(--primary-color); color: white; }
        .badge-danger { background-color: var(--danger-color); color: white; }
        .badge-warning { background-color: var(--warning-color); color: black; }
        .badge-success { background-color: var(--success-color); color: white; }
        .badge-info { background-color: var(--info-color); color: white; }
        .badge-secondary { background-color: var(--secondary-color); color: white; }
        
        .modal { 
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
        }
        
        .modal.show { 
            display: block; 
            opacity: 1;
        }
        
        .modal-content { 
            background-color: var(--card-bg-color); 
            margin: 10% auto; 
            padding: 20px; 
            border-radius: 8px; 
            max-width: 500px; 
            box-shadow: 0 5px 15px rgba(0, 0, 0, 0.5); 
            transform: translateY(-20px); 
            transition: transform 0.3s;
        }
        
        .modal.show .modal-content { 
            transform: translateY(0);
        }
        
        .modal-header { 
            display: flex; 
            justify-content: space-between; 
            align-items: center; 
            margin-bottom: 15px; 
            padding-bottom: 10px; 
            border-bottom: 1px solid var(--card-header-border);
        }
        
        .modal-title { 
            font-size: 1.2rem; 
            font-weight: bold; 
            color: var(--light-color);
        }
        
        .close-modal { 
            background: none; 
            border: none; 
            font-size: 1.5rem; 
            color: var(--light-color); 
            cursor: pointer; 
            transition: color 0.2s;
        }
        
        .close-modal:hover { 
            color: var(--danger-color);
        }
        
        .modal-body { 
            margin-bottom: 20px;
        }
        
        .modal-footer { 
            display: flex; 
            justify-content: flex-end; 
            gap: 10px;
        }
        
        .info-section { 
            background-color: rgba(67, 97, 238, 0.1); 
            border-left: 4px solid var(--primary-color); 
            padding: 10px 15px; 
            margin-bottom: 20px; 
            border-radius: 0 4px 4px 0;
        }
        
        .info-section p { 
            margin: 5px 0;
        }
        
        /* Responsive styles */
        @media (max-width: 768px) {
            .container { 
                width: 100%; 
                padding: 10px;
            }
            
            .col { 
                flex: 100%; 
                padding: 0 10px;
            }
            
            .card-header { 
                flex-direction: column; 
                align-items: stretch;
            }
            
            .card-header .actions { 
                margin-top: 10px;
            }
            
            .filter-group { 
                flex: 100%;
            }
            
            .stats-card h2 {
                font-size: 2.2rem;
            }
            
            .stats-card h4 {
                font-size: 0.95rem;
            }
            
            .stats-card i {
                font-size: 1.8rem;
            }
            
            th, td {
                padding: 8px 10px;
                font-size: 0.9rem;
            }
        }
        
        /* Mobile specific styles */
        @media (max-width: 480px) {
            .header h1 {
                font-size: 1.8rem;
            }
            
            .stats-card h2 {
                font-size: 1.8rem;
            }
            
            .card-header {
                font-size: 1rem;
                padding: 12px 15px;
            }
            
            th, td {
                padding: 6px 8px;
                font-size: 0.85rem;
            }
            
            .action-btn, .filter-btn {
                padding: 5px 10px;
                font-size: 0.8rem;
            }
            
            .chart-container {
                min-height: 300px;
            }
        }
    </style>
</head>
<body>
    <div class="notification" id="notification"></div>
    
    <div class="container">
        <div class="header">
            <h1><i class="fas fa-shield-virus"></i> VirusTotal Scan Results - {input_filename_name}</h1>
            <p>Report generated on {generation_time}</p>
        </div>
        
        <!-- Summary Stats Cards -->
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
        
        <!-- Type Unsupported Info -->
        <div class="card">
            <div class="card-header">
                <i class="fas fa-info-circle"></i> About "type-unsupported" Results
            </div>
            <div class="card-body">
                <div class="info-section">
                    <p><strong>What does "type-unsupported" mean?</strong> When you see "type-unsupported" in the Category column, it means VirusTotal has detected the hash as malicious but doesn't have detailed categorization information for the specific file type.</p>
                    <p>This is normal for many malware hashes - it doesn't mean there's an error or that the scan is invalid. The detection results from antivirus engines are still accurate.</p>
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
                                <th>Last Analysis</th>
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
                                <th>Last Analysis</th>
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
                                <th>Last Analysis</th>
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
                            <th>Last Analysis</th>
                            <th>Detection Ratio</th>
                            <th>Category</th>
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
    
    // Enhanced chart rendering and responsive display
    document.addEventListener('DOMContentLoaded', function() {{
        // Fix all charts on load
        fixAllCharts();
        
        // Also try again after a delay to ensure rendering
        setTimeout(fixAllCharts, 1500);
        
        // Listen for window resize to make charts responsive
        window.addEventListener('resize', function() {{
            // Debounce the resize event
            clearTimeout(window.resizeTimer);
            window.resizeTimer = setTimeout(function() {{
                fixAllCharts();
            }}, 250);
        }});
        
        // Function to fix all charts
        function fixAllCharts() {{
            // Fix IOC type distribution chart
            const iocTypeChart = document.querySelector('[data-chart-type="ioc_distribution"]');
            if (iocTypeChart && typeof Plotly !== 'undefined') {{
                try {{
                    // Try to relayout the chart first
                    Plotly.relayout(iocTypeChart, {{
                        'autosize': true,
                        'paper_bgcolor': 'rgba(0,0,0,0)',
                        'plot_bgcolor': 'rgba(0,0,0,0)'
                    }});
                    
                    // If chart is still not rendered properly, recreate it
                    if (!iocTypeChart.data || !iocTypeChart.data.length) {{
                        recreateBarChart(iocTypeChart);
                    }}
                }} catch (err) {{
                    console.error("Error fixing IOC type chart:", err);
                    recreateBarChart(iocTypeChart);
                }}
            }}
            
            // Fix pie charts
            document.querySelectorAll('[data-chart-type="severity_distribution"], [data-chart-type="ms_defender_distribution"]').forEach(function(chart) {{
                if (chart && typeof Plotly !== 'undefined') {{
                    try {{
                        // Try to relayout the chart first
                        Plotly.relayout(chart, {{
                            'autosize': true,
                            'paper_bgcolor': 'rgba(0,0,0,0)',
                            'plot_bgcolor': 'rgba(0,0,0,0)'
                        }});
                        
                        // If chart is still not rendered properly, recreate it
                        if (!chart.data || !chart.data.length) {{
                            recreatePieChart(chart);
                        }}
                    }} catch (err) {{
                        console.error("Error fixing pie chart:", err);
                        recreatePieChart(chart);
                    }}
                }}
            }});
        }}
        
        // Recreate a bar chart from backup data
        function recreateBarChart(chartElement) {{
            const iocData = window.iocTypeData || {{"hash": 1, "url": 1, "ip": 1}};
            
            // Prepare data for the chart
            const names = Object.keys(iocData);
            const values = Object.values(iocData);
            
            // Create traces for bar chart
            const traces = names.map((name, i) => ({{
                x: [name],
                y: [values[i]],
                type: 'bar',
                name: name,
                text: [values[i]],
                textposition: 'auto',
                marker: {{
                    color: ['#4361ee', '#f72585', '#4cc9f0', '#f9c74f', '#90be6d', '#43aa8b'][i % 6]
                }}
            }}));
            
            // Create optimized layout for mobile
            const layout = {{
                title: {{ text: 'IOC Type Distribution', font: {{ size: 18 }} }},
                autosize: true,
                height: 350,
                margin: {{ l: 40, r: 40, t: 60, b: 60 }},
                paper_bgcolor: 'rgba(0,0,0,0)',
                plot_bgcolor: 'rgba(0,0,0,0)',
                font: {{ family: 'Segoe UI, Arial, sans-serif', size: 14, color: 'white' }},
                showlegend: true,
                legend: {{ orientation: "h", yanchor: "bottom", y: -0.2, xanchor: "center", x: 0.5 }},
                xaxis: {{ showgrid: false, zeroline: false }},
                yaxis: {{ 
                    showgrid: true, 
                    gridcolor: 'rgba(255,255,255,0.1)',
                    zeroline: false,
                    rangemode: 'nonnegative',
                    tick0: 0,
                    dtick: Math.max(1, Math.max(...values) / 5)
                }},
                template: 'plotly_dark'
            }};
            
            // Create new chart
            Plotly.newPlot(chartElement, traces, layout, {{
                displayModeBar: false,
                responsive: true
            }});
        }}
        
        // Recreate a pie chart from backup data
        function recreatePieChart(chartElement) {{
            // Determine which pie chart we're dealing with
            const isDefenderChart = chartElement.closest('[data-chart-type="ms_defender_distribution"]');
            const data = isDefenderChart ? window.msDefenderData : window.severityData;
            
            if (!data) return;
            
            // Prepare colors based on chart type
            const colors = {};
            if (isDefenderChart) {{
                colors.known = '#e63946';
                colors.unknown = '#6c757d';
                colors['N/A'] = '#555555';
            }} else {{
                colors.Critical = '#f72585';
                colors.High = '#f9c74f';
                colors.Medium = '#4895ef';
                colors.Clean = '#4cc9f0';
                colors.Error = '#555555';
            }}
            
            // Create pie chart
            Plotly.newPlot(chartElement, [{{
                type: 'pie',
                labels: Object.keys(data),
                values: Object.values(data),
                hole: 0.4,
                textinfo: 'percent',
                textfont: {{ size: 14, color: 'white' }},
                marker: {{
                    colors: Object.keys(data).map(key => colors[key] || '#555555')
                }},
                hoverinfo: 'label+value+percent'
            }}], {{
                title: {{ 
                    text: isDefenderChart ? 'Microsoft Defender Detection' : 'Detection Severity',
                    font: {{ size: 18 }}
                }},
                autosize: true,
                height: 350,
                margin: {{ l: 20, r: 20, t: 60, b: 60 }},
                paper_bgcolor: 'rgba(0,0,0,0)',
                plot_bgcolor: 'rgba(0,0,0,0)',
                font: {{ family: 'Segoe UI, Arial, sans-serif', size: 14, color: 'white' }},
                showlegend: true,
                legend: {{ orientation: "h", yanchor: "bottom", y: -0.15, xanchor: "center", x: 0.5 }},
                annotations: [{{
                    text: isDefenderChart ? 'MS Defender' : 'Severity',
                    x: 0.5,
                    y: 0.5,
                    font: {{ size: 16, color: 'white' }},
                    showarrow: false
                }}]
            }}, {{
                displayModeBar: false,
                responsive: true
            }});
        }}
        
        // Client-side filtering functionality
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
        
        // Copy buttons
        const copyAllBtn = document.getElementById('copy-all-btn');
        const copyCriticalBtn = document.getElementById('copy-critical-btn');
        const copyMsKnownBtn = document.getElementById('copy-msknown-btn');
        const copyMsUnknownBtn = document.getElementById('copy-msunknown-btn');
        
        // Export buttons
        const exportCsvBtn = document.getElementById('export-csv-btn');
        const exportModal = document.getElementById('export-modal');
        const closeExportModal = document.getElementById('close-export-modal');
        const exportCsvConfirm = document.getElementById('export-csv-confirm');
        const cancelExport = document.getElementById('cancel-export');
        
        // Attach event listeners for filters
        if (iocTypeFilter) iocTypeFilter.addEventListener('change', applyFilters);
        if (severityFilter) severityFilter.addEventListener('change', applyFilters);
        if (msDetectionFilter) msDetectionFilter.addEventListener('change', applyFilters);
        if (searchInput) searchInput.addEventListener('input', applyFilters);
        if (applyFiltersBtn) applyFiltersBtn.addEventListener('click', applyFilters);
        
        // Reset filters button
        if (resetFiltersBtn) {{
            resetFiltersBtn.addEventListener('click', function() {{
                if (iocTypeFilter) iocTypeFilter.value = 'all';
                if (severityFilter) severityFilter.value = 'all';
                if (msDetectionFilter) msDetectionFilter.value = 'all';
                if (searchInput) searchInput.value = '';
                applyFilters();
            }});
        }}
        
        // Copy functionality
        if (copyAllBtn) copyAllBtn.addEventListener('click', () => copyTableContent(resultsTable));
        if (copyCriticalBtn) copyCriticalBtn.addEventListener('click', () => copyTableContent(criticalTable));
        if (copyMsKnownBtn) copyMsKnownBtn.addEventListener('click', () => copyTableContent(msDetectionTable));
        if (copyMsUnknownBtn) copyMsUnknownBtn.addEventListener('click', () => copyTableContent(msUnknownTable));
        
        // Export modal
        if (exportCsvBtn) exportCsvBtn.addEventListener('click', () => exportModal.classList.add('show'));
        if (closeExportModal) closeExportModal.addEventListener('click', () => exportModal.classList.remove('show'));
        if (cancelExport) cancelExport.addEventListener('click', () => exportModal.classList.remove('show'));
        if (exportCsvConfirm) {{
            exportCsvConfirm.addEventListener('click', function() {{
                exportToCsv();
                exportModal.classList.remove('show');
            }});
        }}
        
        // Function to copy IOCs from a table
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
                    // Only copy visible rows
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
                showNotification(`Copied ${{iocList.length}} IOCs to clipboard!`);
            }} catch (err) {{
                console.error('Error copying table content:', err);
                showNotification('Error copying IOCs', 'danger');
            }}
        }}
        
        // Function to export to CSV
        function exportToCsv() {{
            try {{
                if (!reportData || reportData.length === 0) {{
                    showNotification('No data to export', 'warning');
                    return;
                }}
                
                // Get all headers
                const headers = new Set();
                for (const row of reportData) {{
                    for (const key in row) headers.add(key);
                }}
                const headerArray = Array.from(headers);
                
                // Create CSV content
                let csvContent = headerArray.join(',') + '\\n';
                
                // Add rows
                reportData.forEach(row => {{
                    const values = headerArray.map(header => {{
                        const value = row[header] === undefined || row[header] === null ? '' : row[header];
                        const stringValue = typeof value === 'string' ? value : String(value);
                        
                        // Escape values with special characters
                        if (stringValue.includes(',') || stringValue.includes('"') || stringValue.includes('\\n')) {{
                            return '"' + stringValue.replace(/"/g, '""') + '"';
                        }}
                        return stringValue;
                    }});
                    csvContent += values.join(',') + '\\n';
                }});
                
                // Download the file
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
        
        // Filter application function
        function applyFilters() {{
            try {{
                // Show loading indicator
                if (applyFiltersBtn) {{
                    applyFiltersBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Filtering...';
                    applyFiltersBtn.disabled = true;
                }}
                
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
                        // Skip if it's a "no results" row
                        if (row.cells.length === 1 && row.cells[0].getAttribute('colspan')) {{
                            return;
                        }}
                        
                        let showRow = true;
                        
                        const rowIocType = row.getAttribute('data-ioc-type');
                        const rowSeverity = row.getAttribute('data-severity');
                        const rowMsDetection = row.getAttribute('data-ms-detection');
                        
                        // Apply filters
                        if (iocType !== 'all' && rowIocType !== iocType) showRow = false;
                        if (severity !== 'all' && rowSeverity !== severity) showRow = false;
                        if (msDetection !== 'all' && rowMsDetection !== msDetection) showRow = false;
                        
                        // Apply search text
                        if (searchText && showRow) {{
                            const rowText = row.textContent.toLowerCase();
                            if (!rowText.includes(searchText)) showRow = false;
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
                setTimeout(() => {{
                    if (applyFiltersBtn) {{
                        applyFiltersBtn.innerHTML = '<i class="fas fa-filter"></i> Apply Filters';
                        applyFiltersBtn.disabled = false;
                    }}
                    
                    // Update badge counts
                    updateBadgeCounts(resultsCount, criticalCount, msDetectionCount, msUnknownCount);
                }}, 300);
                
            }} catch (err) {{
                console.error("Error applying filters:", err);
                if (applyFiltersBtn) {{
                    applyFiltersBtn.innerHTML = '<i class="fas fa-filter"></i> Apply Filters';
                    applyFiltersBtn.disabled = false;
                }}
                showNotification('Error applying filters', 'danger');
            }}
        }}
        
        // Update count badges 
        function updateBadgeCounts(results, critical, msDetection, msUnknown) {{
            const resultsBadge = document.querySelector('#results-table')?.closest('.card')?.querySelector('.badge');
            if (resultsBadge) resultsBadge.textContent = results;
            
            const criticalBadge = document.querySelector('#critical-table')?.closest('.card')?.querySelector('.badge');
            if (criticalBadge) criticalBadge.textContent = critical;
            
            const msDetectionBadge = document.querySelector('#ms-detection-table')?.closest('.card')?.querySelector('.badge');
            if (msDetectionBadge) msDetectionBadge.textContent = msDetection;
            
            const msUnknownBadge = document.querySelector('#ms-unknown-table')?.closest('.card')?.querySelector('.badge');
            if (msUnknownBadge) msUnknownBadge.textContent = msUnknown;
        }}
        
        // Apply filters on page load with a delay
        setTimeout(applyFilters, 800);
        
        // Close modal on outside click
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
                webbrowser.open(f'file://{os.path.abspath(output_path)}')
            except Exception as e:
                logger.debug(f"Could not open browser: {e}")
                
            return output_path
                
        except Exception as e:
            logger.error(f"Error generating HTML report: {str(e)}")
            return None
    
    except Exception as e:
        import traceback
        error_details = traceback.format_exc()
        logger.error(f"Error generating HTML report: {str(e)}\n{error_details}")
        print(f"Error generating HTML report: {str(e)}")
        return None
