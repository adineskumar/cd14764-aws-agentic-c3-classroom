"""
create_dashboard.py
===================
Build a CloudWatch dashboard for the NovaMart multi-agent system.

OPTIONAL "stand-out" extension - NOT part of the graded project and modifies no
graded file. It creates (or updates) a CloudWatch dashboard that visualizes
production-grade observability signals for the deployed agent:

  1. Agent invocation count over time   (per route_to_* tool / worker agent)
  2. Average response latency per agent  (how long each worker takes)
  3. Guardrail trigger frequency         (how often the safety layer intervenes)

The metrics are derived from the structured INFO logs the agents already emit to
config.AGENT_LOG_GROUP (Task 6), using CloudWatch Logs Insights metric queries,
plus the Bedrock Guardrail CloudWatch metrics AWS publishes automatically.

Usage:
    python create_dashboard.py            # create/update the dashboard
    python create_dashboard.py --delete   # remove it

Then open: CloudWatch -> Dashboards -> NovaMart-Agent-Observability
and take a screenshot for your submission.
"""

import sys
import os
import json

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import boto3
import config

DASHBOARD_NAME = "NovaMart-Agent-Observability"


def _build_body(region: str, log_group: str, guardrail_id: str) -> str:
    """Return the dashboard JSON body (CloudWatch dashboard definition)."""

    # Widget 1: agent invocations over time, from Logs Insights.
    # Each routed worker call logs:  "tool call  route_to_<agent> ..."
    # We count those per 5-minute bin to show request/routing volume over time.
    invocations_query = (
        f"SOURCE '{log_group}' "
        "| filter @message like /tool call  route_to_/ "
        "| stats count() as invocations by bin(5m)"
    )

    # Widget 2: average latency per worker agent.
    # Each routed worker call completes with:  "tool done  route_to_<agent> (<secs>s)"
    # We regex-parse the agent name and the seconds, then average per agent.
    # (Verified against the real log format emitted by agent_observability.py.)
    latency_query = (
        f"SOURCE '{log_group}' "
        "| parse @message /tool done  (?<agent>route_to_\\w+) \\((?<secs>[0-9.]+)s\\)/ "
        "| filter ispresent(secs) "
        "| stats avg(secs) as avg_latency_s by agent "
        "| sort avg_latency_s desc"
    )

    widgets = [
        {
            "type": "text", "x": 0, "y": 0, "width": 24, "height": 2,
            "properties": {
                "markdown": (
                    "# NovaMart Multi-Agent Observability\n"
                    "Invocation volume, per-agent latency, and guardrail "
                    "intervention frequency for the deployed AgentCore runtime."
                )
            },
        },
        {
            "type": "log", "x": 0, "y": 2, "width": 12, "height": 7,
            "properties": {
                "region": region,
                "title": "Agent invocations over time (5-min bins)",
                "query": invocations_query,
                "view": "timeSeries",
            },
        },
        {
            "type": "log", "x": 12, "y": 2, "width": 12, "height": 7,
            "properties": {
                "region": region,
                "title": "Average response latency per agent (seconds)",
                "query": latency_query,
                "view": "bar",
            },
        },
    ]

    # Widget 3: guardrail invocations / interventions (Bedrock-published metrics).
    # AWS publishes these under AWS/Bedrock/Guardrails with the GuardrailArn and
    # GuardrailVersion dimensions (NOT GuardrailId), so build the full ARN.
    guardrail_arn = (f"arn:aws:bedrock:{region}:{config.ACCOUNT_ID}:"
                     f"guardrail/{guardrail_id}")
    guardrail_version = config.GUARDRAIL_VERSION or "1"
    if guardrail_id:
        widgets.append({
            "type": "metric", "x": 0, "y": 9, "width": 24, "height": 7,
            "properties": {
                "region": region,
                "title": "Guardrail trigger frequency",
                "view": "timeSeries",
                "stat": "Sum",
                "period": 300,
                "metrics": [
                    ["AWS/Bedrock/Guardrails", "Invocations",
                     "GuardrailArn", guardrail_arn,
                     "GuardrailVersion", str(guardrail_version),
                     {"label": "Total guardrail evaluations"}],
                    ["AWS/Bedrock/Guardrails", "InvocationsIntervened",
                     "GuardrailArn", guardrail_arn,
                     "GuardrailVersion", str(guardrail_version),
                     {"label": "Interventions (blocked/redacted)"}],
                ],
            },
        })

    return json.dumps({"widgets": widgets})


def main():
    region = config.AWS_REGION
    log_group = config.AGENT_LOG_GROUP
    guardrail_id = config.GUARDRAIL_ID
    cw = boto3.client("cloudwatch", region_name=region)

    if "--delete" in sys.argv:
        cw.delete_dashboards(DashboardNames=[DASHBOARD_NAME])
        print(f"Deleted dashboard '{DASHBOARD_NAME}'.")
        return

    body = _build_body(region, log_group, guardrail_id)
    cw.put_dashboard(DashboardName=DASHBOARD_NAME, DashboardBody=body)

    url = (f"https://console.aws.amazon.com/cloudwatch/home?region={region}"
           f"#dashboards:name={DASHBOARD_NAME}")
    print(f"Dashboard '{DASHBOARD_NAME}' created/updated.")
    print(f"  Log group : {log_group}")
    print(f"  Guardrail : {guardrail_id or '(none - guardrail widget skipped)'}")
    print(f"\nOpen it here and take a screenshot for your submission:\n  {url}\n")
    print("Tip: run `python src/agent_orchestrator.py test` first so there is "
          "recent data for the latency and invocation widgets to render.")


if __name__ == "__main__":
    main()
