"""
Interactive HTML Report Dashboard Generator.
"""

import json
import os
from ..core.models import ScanResult, Severity, DriftType


class HTMLReporter:
    """
    Generates a responsive, modern HTML security dashboard.
    """

    @classmethod
    def generate_html_report(cls, result: ScanResult, output_path: str) -> str:
        summary = result.summary
        findings_json = json.dumps([f.to_dict() for f in result.findings])
        drift_json = json.dumps([d.to_dict() for d in result.drift_records])
        summary_json = json.dumps(summary.to_dict())

        # Category breakdowns
        iam_count = sum(1 for f in result.findings if "iam" in f.resource_type.value)
        storage_count = sum(1 for f in result.findings if "s3" in f.resource_type.value or "rds" in f.resource_type.value)
        network_count = sum(1 for f in result.findings if "security-group" in f.resource_type.value or "vpc" in f.resource_type.value)
        gov_count = sum(1 for f in result.findings if "cloudtrail" in f.resource_type.value or "kms" in f.resource_type.value)

        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Cloud Drift Sentinel - Security Posture & Drift Report</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        :root {{
            --bg-primary: #0a0f1d;
            --bg-card: #131b2e;
            --bg-card-hover: #1c2742;
            --border-color: rgba(255, 255, 255, 0.08);
            --text-main: #f1f5f9;
            --text-muted: #94a3b8;
            --accent-cyan: #06b6d4;
            --accent-blue: #3b82f6;
            --critical: #ef4444;
            --high: #f97316;
            --medium: #eab308;
            --low: #38bdf8;
            --success: #10b981;
        }}

        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}

        body {{
            background-color: var(--bg-primary);
            color: var(--text-main);
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
            line-height: 1.5;
            padding: 2rem 1.5rem;
            min-height: 100vh;
        }}

        .container {{
            max-width: 1280px;
            margin: 0 auto;
        }}

        /* Header */
        header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding-bottom: 2rem;
            border-bottom: 1px solid var(--border-color);
            margin-bottom: 2rem;
            flex-wrap: wrap;
            gap: 1rem;
        }}

        .brand-section {{
            display: flex;
            align-items: center;
            gap: 1rem;
        }}

        .brand-logo {{
            width: 48px;
            height: 48px;
            background: linear-gradient(135deg, var(--accent-cyan), var(--accent-blue));
            border-radius: 12px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 1.5rem;
            font-weight: 700;
            box-shadow: 0 4px 16px rgba(6, 182, 212, 0.3);
        }}

        .brand-title h1 {{
            font-size: 1.6rem;
            font-weight: 700;
            letter-spacing: -0.02em;
        }}

        .brand-title p {{
            color: var(--text-muted);
            font-size: 0.875rem;
        }}

        .meta-badges {{
            display: flex;
            gap: 0.75rem;
            align-items: center;
        }}

        .badge {{
            padding: 0.4rem 0.8rem;
            border-radius: 8px;
            font-size: 0.75rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            color: var(--text-muted);
        }}

        .badge.provider {{
            color: var(--accent-cyan);
            border-color: rgba(6, 182, 212, 0.3);
        }}

        /* KPI Cards */
        .kpi-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 1.25rem;
            margin-bottom: 2rem;
        }}

        .kpi-card {{
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 1.25rem;
            position: relative;
            overflow: hidden;
            transition: transform 0.2s, background-color 0.2s;
        }}

        .kpi-card:hover {{
            transform: translateY(-2px);
            background-color: var(--bg-card-hover);
        }}

        .kpi-label {{
            font-size: 0.8rem;
            color: var(--text-muted);
            font-weight: 500;
            margin-bottom: 0.5rem;
        }}

        .kpi-value {{
            font-size: 2rem;
            font-weight: 700;
            display: flex;
            align-items: baseline;
            gap: 0.25rem;
        }}

        .kpi-subtext {{
            font-size: 0.75rem;
            color: var(--text-muted);
            margin-top: 0.25rem;
        }}

        /* Charts Section */
        .charts-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(360px, 1fr));
            gap: 1.5rem;
            margin-bottom: 2.5rem;
        }}

        .chart-card {{
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 1.5rem;
        }}

        .chart-card h2 {{
            font-size: 1rem;
            font-weight: 600;
            margin-bottom: 1rem;
            color: var(--text-main);
        }}

        .chart-wrapper {{
            position: relative;
            height: 220px;
            display: flex;
            justify-content: center;
        }}

        /* Findings & Drift Tables */
        .section-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 1.25rem;
            flex-wrap: wrap;
            gap: 1rem;
        }}

        .section-header h2 {{
            font-size: 1.25rem;
            font-weight: 600;
        }}

        .search-filters {{
            display: flex;
            gap: 0.75rem;
            flex-wrap: wrap;
        }}

        .search-input {{
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 0.5rem 0.9rem;
            color: var(--text-main);
            font-size: 0.85rem;
            font-family: inherit;
            outline: none;
            width: 240px;
        }}

        .search-input:focus {{
            border-color: var(--accent-cyan);
        }}

        .filter-select {{
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 0.5rem 0.9rem;
            color: var(--text-main);
            font-size: 0.85rem;
            outline: none;
            cursor: pointer;
        }}

        .table-card {{
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            overflow: hidden;
            margin-bottom: 2.5rem;
        }}

        table {{
            width: 100%;
            border-collapse: collapse;
            text-align: left;
            font-size: 0.875rem;
        }}

        th {{
            background: rgba(255, 255, 255, 0.02);
            color: var(--text-muted);
            font-weight: 600;
            padding: 1rem 1.25rem;
            border-bottom: 1px solid var(--border-color);
            text-transform: uppercase;
            font-size: 0.75rem;
            letter-spacing: 0.05em;
        }}

        td {{
            padding: 1rem 1.25rem;
            border-bottom: 1px solid var(--border-color);
            color: var(--text-main);
            vertical-align: top;
        }}

        tr:hover td {{
            background-color: var(--bg-card-hover);
        }}

        .sev-tag {{
            display: inline-block;
            padding: 0.25rem 0.6rem;
            border-radius: 6px;
            font-size: 0.7rem;
            font-weight: 700;
            letter-spacing: 0.04em;
        }}

        .sev-CRITICAL {{ background: rgba(239, 68, 68, 0.2); color: var(--critical); border: 1px solid var(--critical); }}
        .sev-HIGH {{ background: rgba(249, 115, 22, 0.2); color: var(--high); border: 1px solid var(--high); }}
        .sev-MEDIUM {{ background: rgba(234, 179, 8, 0.2); color: var(--medium); border: 1px solid var(--medium); }}
        .sev-LOW {{ background: rgba(56, 189, 248, 0.2); color: var(--low); border: 1px solid var(--low); }}

        .code-box {{
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.75rem;
            background: rgba(0, 0, 0, 0.3);
            padding: 0.5rem 0.75rem;
            border-radius: 6px;
            margin-top: 0.5rem;
            color: #cbd5e1;
            border: 1px solid rgba(255, 255, 255, 0.05);
            word-break: break-all;
        }}

        .diff-added {{ color: #10b981; }}
        .diff-modified {{ color: #eab308; }}
        .diff-removed {{ color: #ef4444; }}

        footer {{
            text-align: center;
            color: var(--text-muted);
            font-size: 0.8rem;
            padding: 2rem 0;
            border-top: 1px solid var(--border-color);
        }}
    </style>
</head>
<body>
    <div class="container">
        <!-- Header -->
        <header>
            <div class="brand-section">
                <div class="brand-logo">🛡️</div>
                <div class="brand-title">
                    <h1>Cloud Drift Sentinel</h1>
                    <p>Automated Cloud Security Posture Management & Drift Analysis</p>
                </div>
            </div>
            <div class="meta-badges">
                <span class="badge provider">{result.provider.upper()}</span>
                <span class="badge">{result.scan_time[:19].replace('T', ' ')} UTC</span>
            </div>
        </header>

        <!-- KPI Grid -->
        <div class="kpi-grid">
            <div class="kpi-card">
                <div class="kpi-label">COMPLIANCE SCORE</div>
                <div class="kpi-value" style="color: {'#10b981' if summary.compliance_score >= 80 else ('#eab308' if summary.compliance_score >= 50 else '#ef4444')}">
                    {summary.compliance_score}%
                </div>
                <div class="kpi-subtext">CIS AWS Foundations Benchmark</div>
            </div>

            <div class="kpi-card">
                <div class="kpi-label">CRITICAL VULNERABILITIES</div>
                <div class="kpi-value" style="color: var(--critical)">{summary.critical_count}</div>
                <div class="kpi-subtext">Immediate action required</div>
            </div>

            <div class="kpi-card">
                <div class="kpi-label">HIGH & MEDIUM RISKS</div>
                <div class="kpi-value" style="color: var(--high)">{summary.high_count + summary.medium_count}</div>
                <div class="kpi-subtext">{summary.high_count} High, {summary.medium_count} Medium</div>
            </div>

            <div class="kpi-card">
                <div class="kpi-label">DRIFT DETECTIONS</div>
                <div class="kpi-value" style="color: var(--low)">{len(result.drift_records)}</div>
                <div class="kpi-subtext">IaC golden state deviations</div>
            </div>
        </div>

        <!-- Visual Analytics -->
        <div class="charts-grid">
            <div class="chart-card">
                <h2>Findings by Severity</h2>
                <div class="chart-wrapper">
                    <canvas id="severityChart"></canvas>
                </div>
            </div>
            <div class="chart-card">
                <h2>Findings by Cloud Domain</h2>
                <div class="chart-wrapper">
                    <canvas id="domainChart"></canvas>
                </div>
            </div>
        </div>

        <!-- Findings Table Section -->
        <div class="section-header">
            <h2>Security Posture Findings ({len(result.findings)})</h2>
            <div class="search-filters">
                <input type="text" id="findingSearch" class="search-input" placeholder="Search findings or resources..." oninput="filterFindings()">
                <select id="severityFilter" class="filter-select" onchange="filterFindings()">
                    <option value="ALL">All Severities</option>
                    <option value="CRITICAL">Critical</option>
                    <option value="HIGH">High</option>
                    <option value="MEDIUM">Medium</option>
                    <option value="LOW">Low</option>
                </select>
            </div>
        </div>

        <div class="table-card">
            <table id="findingsTable">
                <thead>
                    <tr>
                        <th style="width: 110px;">Severity</th>
                        <th style="width: 100px;">Rule</th>
                        <th style="width: 250px;">Resource</th>
                        <th>Issue & Remediation Guidance</th>
                        <th style="width: 140px;">Benchmark</th>
                    </tr>
                </thead>
                <tbody id="findingsBody">
                </tbody>
            </table>
        </div>

        <!-- Infrastructure Drift Section -->
        <div class="section-header">
            <h2>⚡ Infrastructure Drift Analysis ({len(result.drift_records)})</h2>
        </div>

        <div class="table-card">
            <table>
                <thead>
                    <tr>
                        <th style="width: 110px;">Drift Type</th>
                        <th style="width: 260px;">Resource ID</th>
                        <th style="width: 180px;">Resource Type</th>
                        <th>Configuration Drift Summary</th>
                    </tr>
                </thead>
                <tbody>
"""

        if not result.drift_records:
            html_content += """
                    <tr>
                        <td colspan="4" style="text-align: center; color: var(--text-muted); padding: 2rem;">
                            ✓ No infrastructure drift detected. Cloud state matches golden baseline.
                        </td>
                    </tr>
            """
        else:
            for d in result.drift_records:
                diff_class = f"diff-{d.drift_type.value.lower()}"
                diff_str = json.dumps(d.differences, indent=2)
                html_content += f"""
                    <tr>
                        <td><span class="badge {diff_class}">{d.drift_type.value}</span></td>
                        <td><strong>{d.resource_name}</strong><br><span style="font-size:0.75rem; color:var(--text-muted);">{d.resource_id}</span></td>
                        <td><span style="font-size:0.8rem; color:var(--accent-cyan);">{d.resource_type.value}</span></td>
                        <td><div class="code-box"><pre>{diff_str}</pre></div></td>
                    </tr>
                """

        html_content += f"""
                </tbody>
            </table>
        </div>

        <footer>
            Cloud Drift Sentinel • Automated Cloud Security & Drift Auditing Platform • Generated with ❤️ by Aditya Singh
        </footer>
    </div>

    <script>
        const rawFindings = {findings_json};

        function renderFindings(findings) {{
            const tbody = document.getElementById('findingsBody');
            tbody.innerHTML = '';

            if (findings.length === 0) {{
                tbody.innerHTML = '<tr><td colspan="5" style="text-align:center; padding: 2rem; color: var(--text-muted);">No matching findings found.</td></tr>';
                return;
            }}

            findings.forEach(f => {{
                const tr = document.createElement('tr');
                tr.innerHTML = `
                    <td><span class="sev-tag sev-${{f.severity}}">${{f.severity}}</span></td>
                    <td><strong>${{f.rule_id}}</strong></td>
                    <td>
                        <div style="font-weight: 600; color: #fff;">${{f.resource_id.split(':').pop()}}</div>
                        <div style="font-size: 0.75rem; color: var(--text-muted); word-break: break-all;">${{f.resource_id}}</div>
                    </td>
                    <td>
                        <div style="font-weight: 500; margin-bottom: 0.25rem;">${{f.description}}</div>
                        <div style="font-size: 0.8rem; color: var(--text-muted); margin-bottom: 0.35rem;"><strong>Impact:</strong> ${{f.impact}}</div>
                        <div class="code-box"><strong>Fix:</strong> ${{f.remediation_guidance}}</div>
                    </td>
                    <td><span style="font-size: 0.75rem; color: var(--text-muted);">${{f.benchmark_reference}}</span></td>
                `;
                tbody.appendChild(tr);
            }});
        }}

        function filterFindings() {{
            const searchVal = document.getElementById('findingSearch').value.toLowerCase();
            const sevVal = document.getElementById('severityFilter').value;

            const filtered = rawFindings.filter(f => {{
                const matchSearch = f.description.toLowerCase().includes(searchVal) ||
                                    f.resource_id.toLowerCase().includes(searchVal) ||
                                    f.rule_id.toLowerCase().includes(searchVal);
                const matchSev = sevVal === 'ALL' || f.severity === sevVal;
                return matchSearch && matchSev;
            }});

            renderFindings(filtered);
        }}

        // Initial render
        renderFindings(rawFindings);

        // Chart 1: Severity Breakdown
        new Chart(document.getElementById('severityChart'), {{
            type: 'doughnut',
            data: {{
                labels: ['Critical', 'High', 'Medium', 'Low'],
                datasets: [{{
                    data: [{summary.critical_count}, {summary.high_count}, {summary.medium_count}, {summary.low_count}],
                    backgroundColor: ['#ef4444', '#f97316', '#eab308', '#38bdf8'],
                    borderWidth: 0
                }}]
            }},
            options: {{
                responsive: true,
                maintainAspectRatio: false,
                plugins: {{
                    legend: {{ position: 'bottom', labels: {{ color: '#94a3b8', font: {{ family: 'Inter' }} }} }}
                }}
            }}
        }});

        // Chart 2: Domain Breakdown
        new Chart(document.getElementById('domainChart'), {{
            type: 'bar',
            data: {{
                labels: ['IAM', 'Storage/RDS', 'Network/SG', 'Governance'],
                datasets: [{{
                    label: 'Findings',
                    data: [{iam_count}, {storage_count}, {network_count}, {gov_count}],
                    backgroundColor: '#06b6d4',
                    borderRadius: 6
                }}]
            }},
            options: {{
                responsive: true,
                maintainAspectRatio: false,
                scales: {{
                    x: {{ ticks: {{ color: '#94a3b8' }}, grid: {{ display: false }} }},
                    y: {{ ticks: {{ color: '#94a3b8', stepSize: 1 }}, grid: {{ color: 'rgba(255,255,255,0.05)' }} }}
                }},
                plugins: {{
                    legend: {{ display: false }}
                }}
            }}
        }});
    </script>
</body>
</html>
"""
        os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html_content)

        return output_path
