from mcp import StdioServerParameters
from mcp.client.stdio import stdio_client
from strands import Agent
from strands.models.openai import OpenAIModel
from strands.tools.mcp import MCPClient
from pydantic import BaseModel, Field
from typing import List
from enum import Enum
from collections import Counter

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich.columns import Columns
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


result = agent("Run a full AWS best practices audit of this account.", structured_output_model=ExecuteResult)
if isinstance(result.structured_output, ExecuteResult):
    display_findings(result.structured_output)
else:
    raise RuntimeError(f"Unexpected output: {result.structured_output}")
