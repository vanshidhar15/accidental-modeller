from app.models import ThreatModelResponse


def generate_markdown_report(response: ThreatModelResponse) -> str:
    lines = []

    lines.append(f"# Threat Model Report: {response.system_name}")
    lines.append("")

    lines.append("## Risk Summary")
    lines.append("")
    lines.append(f"- Total Threats: {response.risk_summary.get('total_threats', 0)}")
    lines.append(f"- High Risk: {response.risk_summary.get('high', 0)}")
    lines.append(f"- Medium Risk: {response.risk_summary.get('medium', 0)}")
    lines.append(f"- Low Risk: {response.risk_summary.get('low', 0)}")
    lines.append("")

    lines.append("## STRIDE Coverage")
    lines.append("")
    lines.append("| Category | Covered |")
    lines.append("|---|---|")

    for category, covered in response.stride_coverage.items():
        status = "Yes" if covered else "No"
        lines.append(f"| {category} | {status} |")

    lines.append("")

    lines.append("## Assets")
    lines.append("")
    for asset in response.assets:
        lines.append(f"- {asset}")
    lines.append("")

    lines.append("## Threats")
    lines.append("")
    lines.append("| ID | STRIDE Category | Component | Risk | Description | Recommendation |")
    lines.append("|---|---|---|---|---|---|")

    for threat in response.threats:
        lines.append(
            f"| {threat.threat_id} "
            f"| {threat.stride_category} "
            f"| {threat.affected_component} "
            f"| {threat.risk_level} "
            f"| {threat.description} "
            f"| {threat.recommendation} |"
        )

    lines.append("")

    lines.append("## Security Requirements")
    lines.append("")
    for requirement in response.security_requirements:
        lines.append(f"- {requirement}")
    lines.append("")

    lines.append("## Open Questions")
    lines.append("")
    for question in response.questions:
        lines.append(f"- {question}")
    lines.append("")

    return "\n".join(lines)