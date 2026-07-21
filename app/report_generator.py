from datetime import datetime, timezone

from app.models import ThreatModelResponse


TOOL_VERSION = "0.2.0"


def escape_markdown_table_value(value: object) -> str:
    """
    Escape values before inserting them into a Markdown table.

    Pipes would otherwise create additional columns, while line breaks
    would break the table layout.
    """
    if value is None:
        return ""

    return (
        str(value)
        .replace("|", r"\|")
        .replace("\r\n", "<br>")
        .replace("\n", "<br>")
        .replace("\r", "<br>")
    )


def generate_markdown_report(response: ThreatModelResponse) -> str:
    lines: list[str] = []

    generated_on = datetime.now(timezone.utc).strftime(
        "%Y-%m-%d %H:%M UTC"
    )

    total_threats = response.risk_summary.get("total_threats", 0)
    high_risk = response.risk_summary.get("high", 0)
    medium_risk = response.risk_summary.get("medium", 0)
    low_risk = response.risk_summary.get("low", 0)

    covered_categories = [
        category
        for category, covered in response.stride_coverage.items()
        if covered
    ]

    uncovered_categories = [
        category
        for category, covered in response.stride_coverage.items()
        if not covered
    ]

    lines.append("# Threat Model Report")
    lines.append("")
    lines.append(f"**System:** {response.system_name}")
    lines.append(f"**Generated on:** {generated_on}")
    lines.append(f"**Tool version:** Accidental Modeller v{TOOL_VERSION}")
    lines.append("")

    lines.append("---")
    lines.append("")

    lines.append("## Executive Summary")
    lines.append("")

    lines.append(
        f"The analysis identified **{total_threats} potential security "
        f"threat{'s' if total_threats != 1 else ''}** for "
        f"**{response.system_name}**."
    )
    lines.append("")

    if high_risk > 0:
        lines.append(
            f"The model includes **{high_risk} high-risk "
            f"threat{'s' if high_risk != 1 else ''}** that should be "
            f"reviewed and prioritised."
        )
    elif medium_risk > 0:
        lines.append(
            "No high-risk threats were identified by the current "
            "rule-based analysis. Medium-risk findings should still be "
            "reviewed against the architecture and business context."
        )
    elif total_threats > 0:
        lines.append(
            "The current rule-based analysis identified only low-risk "
            "threats. This does not confirm that the system is secure."
        )
    else:
        lines.append(
            "No threats were generated from the supplied architecture "
            "information. The input may require more detail before the "
            "result can be treated as meaningful."
        )

    lines.append("")

    if covered_categories:
        lines.append(
            "**Covered STRIDE categories:** "
            + ", ".join(covered_categories)
        )
        lines.append("")

    if uncovered_categories:
        lines.append(
            "**Categories not currently represented:** "
            + ", ".join(uncovered_categories)
        )
        lines.append("")

    lines.append("---")
    lines.append("")

    lines.append("## Risk Summary")
    lines.append("")
    lines.append("| Risk level | Count |")
    lines.append("|---|---:|")
    lines.append(f"| High | {high_risk} |")
    lines.append(f"| Medium | {medium_risk} |")
    lines.append(f"| Low | {low_risk} |")
    lines.append(f"| **Total** | **{total_threats}** |")
    lines.append("")

    lines.append("---")
    lines.append("")

    lines.append("## STRIDE Coverage")
    lines.append("")
    lines.append("| Category | Status |")
    lines.append("|---|---|")

    for category, covered in response.stride_coverage.items():
        status = "Covered" if covered else "Not identified"
        lines.append(
            f"| {escape_markdown_table_value(category)} "
            f"| {status} |"
        )

    lines.append("")
    lines.append(
        "> A category marked as “Not identified” means the supplied "
        "architecture did not trigger a matching rule. It does not prove "
        "that the category is irrelevant."
    )
    lines.append("")

    lines.append("---")
    lines.append("")

    lines.append("## Assets")
    lines.append("")

    if response.assets:
        for index, asset in enumerate(response.assets, start=1):
            lines.append(f"{index}. {asset}")
    else:
        lines.append(
            "_No assets were identified from the supplied input._"
        )

    lines.append("")
    lines.append("---")
    lines.append("")

    lines.append("## Threat Register")
    lines.append("")

    if response.threats:
        lines.append(
            "| ID | STRIDE category | Affected component | Risk | "
            "Likelihood | Impact | Description | Recommendation |"
        )
        lines.append(
            "|---|---|---|---|---|---|---|---|"
        )

        for threat in response.threats:
            lines.append(
                f"| {escape_markdown_table_value(threat.threat_id)} "
                f"| {escape_markdown_table_value(threat.stride_category)} "
                f"| {escape_markdown_table_value(threat.affected_component)} "
                f"| {escape_markdown_table_value(threat.risk_level)} "
                f"| {escape_markdown_table_value(threat.likelihood)} "
                f"| {escape_markdown_table_value(threat.impact)} "
                f"| {escape_markdown_table_value(threat.description)} "
                f"| {escape_markdown_table_value(threat.recommendation)} |"
            )
    else:
        lines.append(
            "_No threats were generated from the supplied input._"
        )

    lines.append("")
    lines.append("---")
    lines.append("")

    lines.append("## Security Requirements")
    lines.append("")

    if response.security_requirements:
        for index, requirement in enumerate(
            response.security_requirements,
            start=1,
        ):
            lines.append(f"{index}. {requirement}")
    else:
        lines.append(
            "_No security requirements were generated._"
        )

    lines.append("")
    lines.append("---")
    lines.append("")

    lines.append("## Security Review Questions")
    lines.append("")

    if response.questions:
        for index, question in enumerate(
            response.questions,
            start=1,
        ):
            lines.append(f"**Q{index}.** {question}")
            lines.append("")
    else:
        lines.append(
            "_No open security review questions were generated._"
        )
        lines.append("")

    lines.append("---")
    lines.append("")

    lines.append("## Disclaimer")
    lines.append("")
    lines.append(
        "This report was generated automatically using rule-based "
        "STRIDE analysis."
    )
    lines.append("")
    lines.append(
        "The output should be reviewed by an application security "
        "professional and supplemented with architecture-specific "
        "analysis, business context, manual threat modelling, and "
        "validation with system owners."
    )
    lines.append("")
    lines.append(
        "Absence of a threat or STRIDE category from this report must "
        "not be interpreted as evidence that the system is secure."
    )

    return "\n".join(lines)