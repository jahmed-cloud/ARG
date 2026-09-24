"""
Subscription analysis CLI - runs every ARG scanner against one subscription
without the database/Celery stack and writes a structured markdown report:

    python -m scripts.subscription_analysis --subscription <id-or-name> [--output DIR]

Output layout (same structure as a manual FinOps / architecture review):

    <output>/
      README.md                      executive summary + prioritised actions
      01-current-findings/           architecture overview + resource inventory
      02-gap-analysis/               gaps by area and severity
      03-cost-drivers/               trend, breakdowns, savings register
      04-architectural-critique/     decision-by-decision critique, target, roadmap
      05-deep-dive/<area>/           per-area technical detail
      05-deep-dive/raw/              JSON evidence (inventory, cost, findings)
"""
