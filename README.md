# AWS Well-Architected Audit Agent

An autonomous AI agent that audits an AWS account against the [AWS Well-Architected Framework](https://aws.amazon.com/architecture/well-architected/) and renders findings in a colour-coded terminal report.

![](./image.png)

## How it works

1. The agent connects to AWS via the [AWS MCP proxy](https://aws-mcp.us-east-1.api.aws/mcp) using the Model Context Protocol (MCP).
2. It autonomously inspects IAM, GuardDuty, CloudTrail, Config, S3, EC2, and other services.
3. Findings are returned as structured Pydantic objects, organised across the six Well-Architected pillars.
4. A `rich`-based TUI renders a summary dashboard, findings index, and detailed panels — all colour-coded by severity.

### Well-Architected pillars covered

| Pillar                 | Colour  |
| ---------------------- | ------- |
| Security               | Red     |
| Reliability            | Blue    |
| Operational Excellence | Green   |
| Performance Efficiency | Magenta |
| Cost Optimization      | Yellow  |
| Sustainability         | Cyan    |

### Severity levels

`CRITICAL` > `HIGH` > `MEDIUM` > `LOW` > `OPTIONAL`

## Prerequisites

- Python 3.14+
- [`uv`](https://docs.astral.sh/uv/) package manager
- AWS credentials configured (environment variables, `~/.aws/credentials`, or IAM role)
- OpenAI API key

The AWS principal needs at minimum read-only access. The `SecurityAudit` managed policy provides appropriate coverage.

## Installation

```bash
uv sync
```

## Configuration

```bash
export OPENAI_API_KEY="sk-..."

# AWS credentials (choose one method)
export AWS_ACCESS_KEY_ID="..."
export AWS_SECRET_ACCESS_KEY="..."
export AWS_SESSION_TOKEN="..."      # if using temporary credentials

# or configure a named profile
export AWS_PROFILE="my-audit-role"
export AWS_REGION="us-east-1"       # region for the MCP proxy
```

## Usage

```bash
uv run main.py
```

The agent runs autonomously — no interactive input is required. Depending on the number of AWS services and regions, a full audit takes a few minutes.

## Output

The terminal report has three sections:

**1. Summary dashboard** — two tables displayed side by side: findings by severity and findings by pillar.

**2. Findings index** — all findings sorted from CRITICAL to LOW, with colour-coded severity and pillar columns.

**3. Detailed panels** — one panel per finding, border colour matching its severity, containing:

- Description
- Remediation steps
- Links to relevant AWS documentation

## Project structure

```
main.py          # Agent definition, data models, and TUI display
pyproject.toml   # Project metadata and dependencies
uv.lock          # Locked dependency graph
```

## Key dependencies

| Package                | Purpose                                             |
| ---------------------- | --------------------------------------------------- |
| `strands-agents`       | Agent framework with tool-use and structured output |
| `strands-agents-tools` | Pre-built tools for Strands agents                  |
| `boto3`                | AWS SDK (used transitively by MCP tools)            |
| `pydantic`             | Structured output models                            |
| `rich`                 | Terminal UI rendering                               |
