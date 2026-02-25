from mcp import StdioServerParameters
from mcp.client.stdio import stdio_client
from strands import Agent
from strands.models.openai import OpenAIModel
from strands.tools.mcp import MCPClient
from pydantic import BaseModel, Field
from typing import List
from enum import Enum
from collections import Counter
import datetime

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich.columns import Columns
from rich.prompt import Prompt
from rich import box

aws_mcp = MCPClient(
    lambda: stdio_client(
        StdioServerParameters(
            command="uvx",
            args=[
                "mcp-proxy-for-aws@latest",
                "https://aws-mcp.us-east-1.api.aws/mcp",
                "--metadata", "AWS_REGION=us-east-1"
            ]
        )
    )
)

MODEL_ID = "gpt-5-mini"
SYSTEM_PROMPT = """You are an AWS Well-Architected advisor with access to AWS
documentation and AWS account.

When asked to audit an AWS account, autonomously:
1. Use your tools to investigate AWS resources, and AWS best practices.
2. Reason about what you find and cross-reference with AWS documentation.
3. Produce a structured report organised by the six Well-Architected pillars:
     Security · Reliability · Operational Excellence ·
     Performance Efficiency · Cost Optimization · Sustainability

For each finding include severity (CRITICAL/HIGH/MEDIUM/LOW), what the issue is,
a concrete remediation with links to AWS docs where possible, and the specific
AWS resources affected (resource type and identifier such as ARN, name, or ID).

find 30 items per every request

End with an executive summary and prioritised action list."""

agent = Agent(
    model=OpenAIModel(model_id=MODEL_ID),
    system_prompt=SYSTEM_PROMPT,
    tools=[aws_mcp],
)

class PillarType(str, Enum):
    SECURITY = 'Security'
    RELIABILITY = 'Reliability'
    OPERATIONAL_EXCELLENCE = 'Operational Excellence'
    PERFORMANCE_EFFICIENCY = 'Performance Efficiency'
    COST_OPTIMIZATION = 'Cost Optimization'
    SUSTAINABILITY = 'Sustainability'

class Serverity(str, Enum):
    CRITICAL = 'CRITICAL'
    HIGH = 'HIGH'
    MEDIUM = 'MEDIUM'
    LOW = 'LOW'
    OPTIONAL = 'OPTIONAL'

class RelatedDocs(BaseModel):
    name: str = Field(description="Name of related document")
    url: str = Field(description="URL of related document")

class AffectedResource(BaseModel):
    resource_type: str = Field(description="AWS resource type, e.g. 'IAM User', 'S3 Bucket', 'EC2 Instance'")
    identifier: str = Field(description="Resource identifier such as ARN, name, or ID")

class Findings(BaseModel):
    name: str = Field(description="Name of Best Practice vulnerability")
    description: str = Field(description="One-line brief description of Best Practice vulnerability")
    solution: str = Field(description="Detailed multi-line solution of Best Practice vulnerability")
    pillar_type: PillarType = Field(description="Pillar type of Best Practice vulnerability")
    serverity: Serverity = Field(description="Serverity of Best Practice vulnerability")
    affected_resources: List[AffectedResource] = Field(description="List of specific AWS resources affected by this finding")
    related_docs: List[RelatedDocs] = Field(description="Related documents of Best Practice vulnerability")

class ExecuteResult(BaseModel):
    findings: List[Findings] = Field(description="List of Best Practice vulnerabilities in format.")


SEVERITY_COLORS = {
    'CRITICAL': 'bold red',
    'HIGH': 'red',
    'MEDIUM': 'yellow',
    'LOW': 'cyan',
    'OPTIONAL': 'dim',
}

PILLAR_COLORS = {
    'Security': 'red',
    'Reliability': 'blue',
    'Operational Excellence': 'green',
    'Performance Efficiency': 'magenta',
    'Cost Optimization': 'yellow',
    'Sustainability': 'cyan',
}

SEVERITY_ORDER = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'OPTIONAL': 4}


def display_findings(result: ExecuteResult) -> None:
    console = Console()
    findings = result.findings
    sorted_findings = sorted(findings, key=lambda f: SEVERITY_ORDER.get(f.serverity.value, 99))

    console.print()
    console.rule("[bold cyan]AWS Well-Architected Audit Report[/bold cyan]")
    console.print()

    # Summary tables side by side
    sev_counts = Counter(f.serverity.value for f in findings)
    pillar_counts = Counter(f.pillar_type.value for f in findings)

    sev_table = Table(title="By Severity", box=box.ROUNDED, show_header=True)
    sev_table.add_column("Severity", style="bold")
    sev_table.add_column("Count", justify="right")
    for sev in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'OPTIONAL']:
        count = sev_counts.get(sev, 0)
        if count:
            sev_table.add_row(Text(sev, style=SEVERITY_COLORS[sev]), str(count))

    pillar_table = Table(title="By Pillar", box=box.ROUNDED, show_header=True)
    pillar_table.add_column("Pillar", style="bold")
    pillar_table.add_column("Count", justify="right")
    for pillar, count in sorted(pillar_counts.items(), key=lambda x: -x[1]):
        pillar_table.add_row(Text(pillar, style=PILLAR_COLORS.get(pillar, 'white')), str(count))

    console.print(Columns([sev_table, pillar_table], equal=False, expand=False))
    console.print()

    # Findings index table
    index_table = Table(
        title=f"Findings ({len(findings)} total)",
        box=box.ROUNDED,
        show_header=True,
        show_lines=True,
        expand=True,
    )
    index_table.add_column("#", style="dim", width=4, justify="right")
    index_table.add_column("Severity", width=10)
    index_table.add_column("Pillar", width=24)
    index_table.add_column("Finding", ratio=1)

    for i, f in enumerate(sorted_findings, 1):
        index_table.add_row(
            str(i),
            Text(f.serverity.value, style=SEVERITY_COLORS[f.serverity.value]),
            Text(f.pillar_type.value, style=PILLAR_COLORS.get(f.pillar_type.value, 'white')),
            f.name,
        )

    console.print(index_table)
    console.print()

    # Detailed findings
    console.rule("[bold]Detailed Findings[/bold]")
    console.print()

    for i, f in enumerate(sorted_findings, 1):
        sev_color = SEVERITY_COLORS[f.serverity.value]
        pillar_color = PILLAR_COLORS.get(f.pillar_type.value, 'white')

        title = Text()
        title.append(f" [{i}] ", style="dim")
        title.append(f.name, style="bold white")
        title.append(f"  {f.serverity.value} ", style=sev_color)
        title.append(f"  {f.pillar_type.value} ", style=pillar_color)

        body = Text()
        body.append("Description\n", style="bold underline")
        body.append(f.description)
        body.append("\n\n")
        body.append("Solution\n", style="bold underline")
        body.append(f.solution)
        body.append("\n\n")
        if f.affected_resources:
            body.append("Affected Resources\n", style="bold underline")
            for r in f.affected_resources:
                body.append(f"  • {r.resource_type}: ", style="bold")
                body.append(r.identifier, style="dim")
                body.append("\n")
            body.append("\n")
        body.append("Related Docs\n", style="bold underline")
        for doc in f.related_docs:
            body.append(f"  • {doc.name}: ", style="bold")
            body.append(doc.url, style="cyan underline")
            body.append("\n")

        border = sev_color.replace("bold ", "")
        console.print(Panel(body, title=title, border_style=border, expand=True))
        console.print()


def write_pdf(findings: List[Findings], path: str) -> None:
    from reportlab.lib import colors as C
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import cm
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
        HRFlowable, KeepTogether,
    )

    SEV_HEX = {
        'CRITICAL': '#b91c1c', 'HIGH': '#c2410c',
        'MEDIUM': '#b45309', 'LOW': '#0e7490', 'OPTIONAL': '#6b7280',
    }
    PIL_HEX = {
        'Security': '#b91c1c', 'Reliability': '#1d4ed8',
        'Operational Excellence': '#15803d', 'Performance Efficiency': '#7e22ce',
        'Cost Optimization': '#a16207', 'Sustainability': '#0e7490',
    }

    sorted_findings = sorted(findings, key=lambda f: SEVERITY_ORDER.get(f.serverity.value, 99))
    sev_counts = Counter(f.serverity.value for f in findings)
    pillar_counts = Counter(f.pillar_type.value for f in findings)

    PW, _ = A4
    LM = RM = 2 * cm
    W = PW - LM - RM
    base = getSampleStyleSheet()['Normal']

    def sty(name, **kw):
        return ParagraphStyle(name, parent=base, **kw)

    title_s  = sty('rpt_title', fontSize=20, leading=26, spaceAfter=4,
                   textColor=C.HexColor('#0a2540'), fontName='Helvetica-Bold')
    date_s   = sty('rpt_date', fontSize=9, textColor=C.HexColor('#6b7280'), spaceAfter=14)
    h2_s     = sty('rpt_h2', fontSize=12, leading=16, spaceBefore=14, spaceAfter=6,
                   textColor=C.HexColor('#0a2540'), fontName='Helvetica-Bold')
    label_s  = sty('rpt_label', fontSize=9, fontName='Helvetica-Bold', spaceBefore=6, spaceAfter=2)
    body_s   = sty('rpt_body', fontSize=9, leading=13)
    indent_s = sty('rpt_indent', fontSize=9, leading=13, leftIndent=12)
    small_s  = sty('rpt_small', fontSize=8, leading=11, leftIndent=12)
    fh_s     = sty('rpt_fh', fontSize=10, fontName='Helvetica-Bold', textColor=C.HexColor('#0a2540'))
    badge_s  = sty('rpt_badge', fontSize=8, fontName='Helvetica-Bold')
    pil_s    = sty('rpt_pil', fontSize=8)

    doc = SimpleDocTemplate(
        path, pagesize=A4,
        leftMargin=LM, rightMargin=RM,
        topMargin=2.5 * cm, bottomMargin=2 * cm,
    )
    story = []

    # Title
    story += [
        Paragraph("AWS Well-Architected Audit Report", title_s),
        Paragraph(datetime.datetime.now().strftime("Generated %B %d, %Y at %H:%M"), date_s),
        HRFlowable(width='100%', thickness=2, color=C.HexColor('#0066cc'), spaceAfter=16),
    ]

    # Summary
    story.append(Paragraph("Summary", h2_s))

    def scell(text, **kw):
        return Paragraph(text, ParagraphStyle('_s', parent=base, fontSize=9, leading=12, **kw))

    shdr = dict(fontName='Helvetica-Bold', textColor=C.white)
    sev_data = [[scell('Severity', **shdr), scell('Count', **shdr)]]
    for sev in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'OPTIONAL']:
        if sev_counts.get(sev, 0):
            sev_data.append([scell(sev), scell(str(sev_counts[sev]))])

    pil_data = [[scell('Pillar', **shdr), scell('Count', **shdr)]]
    for pillar, cnt in sorted(pillar_counts.items(), key=lambda x: -x[1]):
        pil_data.append([scell(pillar), scell(str(cnt))])

    def summary_tbl(rows, col_widths):
        tbl = Table(rows, colWidths=col_widths)
        tbl.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), C.HexColor('#0a2540')),
            ('GRID', (0, 0), (-1, -1), 0.5, C.HexColor('#e5e7eb')),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('TOPPADDING', (0, 0), (-1, -1), 4),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ]))
        return tbl

    sev_tbl = summary_tbl(sev_data, [5.5 * cm, 1.5 * cm])
    pil_tbl = summary_tbl(pil_data, [6.5 * cm, 1.5 * cm])
    pair = Table([[sev_tbl, '', pil_tbl]], colWidths=[7 * cm, 0.5 * cm, W - 7.5 * cm])
    pair.setStyle(TableStyle([('VALIGN', (0, 0), (-1, -1), 'TOP')]))
    story.append(pair)
    story.append(Spacer(1, 0.4 * cm))

    # Findings index
    story.append(Paragraph(f"Findings Index  ({len(findings)} total)", h2_s))
    idx_col = [0.7 * cm, 2.4 * cm, 4.0 * cm, W - 7.1 * cm]

    def cell(text, **kw):
        return Paragraph(text, ParagraphStyle('_c', parent=base, fontSize=8, leading=11, **kw))

    hdr_kw = dict(fontName='Helvetica-Bold', textColor=C.white)
    idx_data = [[cell('#', **hdr_kw), cell('Severity', **hdr_kw),
                 cell('Pillar', **hdr_kw), cell('Finding', **hdr_kw)]]
    for i, f in enumerate(sorted_findings, 1):
        idx_data.append([
            cell(str(i)),
            cell(f.serverity.value, fontName='Helvetica-Bold',
                 textColor=C.HexColor(SEV_HEX[f.serverity.value])),
            cell(f.pillar_type.value,
                 textColor=C.HexColor(PIL_HEX.get(f.pillar_type.value, '#374151'))),
            cell(f.name),
        ])
    idx_tbl = Table(idx_data, colWidths=idx_col)
    idx_cmds = [
        ('BACKGROUND', (0, 0), (-1, 0), C.HexColor('#0a2540')),
        ('GRID', (0, 0), (-1, -1), 0.5, C.HexColor('#e5e7eb')),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('TOPPADDING', (0, 0), (-1, -1), 4),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
    ]
    for i in range(1, len(idx_data)):
        bg = C.white if i % 2 else C.HexColor('#f9fafb')
        idx_cmds.append(('BACKGROUND', (0, i), (-1, i), bg))
    idx_tbl.setStyle(TableStyle(idx_cmds))
    story.append(idx_tbl)
    story.append(Spacer(1, 0.5 * cm))

    # Detailed findings
    story += [
        HRFlowable(width='100%', thickness=1, color=C.HexColor('#e5e7eb'), spaceAfter=4),
        Paragraph("Detailed Findings", h2_s),
    ]

    for i, f in enumerate(sorted_findings, 1):
        sev_c = C.HexColor(SEV_HEX[f.serverity.value])
        pil_c = C.HexColor(PIL_HEX.get(f.pillar_type.value, '#374151'))

        hdr = Table([[
            Paragraph(f'[{i}]  {f.name}', fh_s),
            Paragraph(f.serverity.value, badge_s),
            Paragraph(f.pillar_type.value, pil_s),
        ]], colWidths=[W * 0.6, W * 0.15, W * 0.25])
        hdr.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), C.HexColor('#f0f4f8')),
            ('TEXTCOLOR', (1, 0), (1, 0), sev_c),
            ('TEXTCOLOR', (2, 0), (2, 0), pil_c),
            ('FONTNAME', (1, 0), (1, 0), 'Helvetica-Bold'),
            ('LEFTPADDING', (0, 0), (-1, -1), 8),
            ('RIGHTPADDING', (0, 0), (-1, -1), 8),
            ('TOPPADDING', (0, 0), (-1, -1), 6),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
            ('LINEBELOW', (0, 0), (-1, -1), 2, sev_c),
        ]))

        blocks = [
            hdr,
            Paragraph('Description', label_s),
            Paragraph(f.description, body_s),
            Paragraph('Solution', label_s),
            Paragraph(f.solution, body_s),
        ]
        if f.affected_resources:
            blocks.append(Paragraph('Affected Resources', label_s))
            for r in f.affected_resources:
                blocks.append(Paragraph(
                    f'<b>{r.resource_type}:</b>  {r.identifier}', indent_s
                ))
        if f.related_docs:
            blocks.append(Paragraph('Related Docs', label_s))
            for d in f.related_docs:
                blocks.append(Paragraph(
                    f'• <b>{d.name}:</b>  '
                    f'<a href="{d.url}"><font color="#0066cc">{d.url}</font></a>',
                    small_s
                ))
        blocks.append(Spacer(1, 0.4 * cm))

        story.append(KeepTogether(blocks[:4]))  # keep header + description together
        for b in blocks[4:]:
            story.append(b)

    doc.build(story)


console = Console()
session_findings: List[Findings] = []

console.print()
console.rule(
    "[dim]Interactive mode  •  "
    "[bold]pdf[/bold] [filename]  to export  •  [bold]exit[/bold] to quit[/dim]"
)

while True:
    try:
        request = Prompt.ask("\n[cyan]>[/cyan]").strip()
    except (EOFError, KeyboardInterrupt):
        console.print("\n[dim]Exiting.[/dim]")
        break

    if not request or request.lower() in {"exit", "quit", "q"}:
        console.print("[dim]Exiting.[/dim]")
        break

    if request.lower().startswith("pdf"):
        parts = request.split(maxsplit=1)
        filename = (
            parts[1] if len(parts) > 1
            else f"aws_audit_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        )
        if not filename.endswith(".pdf"):
            filename += ".pdf"
        with console.status(f"[cyan]Writing {filename}…[/cyan]"):
            write_pdf(session_findings, filename)
        console.print(f"[green]Saved → {filename}[/green]  ({len(session_findings)} findings)")
        continue

    result = agent(request, structured_output_model=ExecuteResult)
    if isinstance(result.structured_output, ExecuteResult):
        session_findings.extend(result.structured_output.findings)
        display_findings(result.structured_output)
    else:
        raise RuntimeError(f"Unexpected output: {result.structured_output}")
