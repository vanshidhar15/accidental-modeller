from app.models import ThreatModelRequest, Threat, ThreatModelResponse


def calculate_risk_level(
    category: str,
    has_sensitive_data: bool,
    is_internet_facing: bool,
    has_external_integrations: bool,
    has_authentication: bool,
) -> str:
    score = 0

    if category in ["Information Disclosure", "Elevation of Privilege"]:
        score += 2

    if has_sensitive_data:
        score += 2

    if is_internet_facing:
        score += 2

    if has_external_integrations:
        score += 1

    if not has_authentication:
        score += 2

    if score >= 5:
        return "High"

    if score >= 3:
        return "Medium"

    return "Low"


def generate_threat_model(request: ThreatModelRequest) -> ThreatModelResponse:
    threats = []
    requirements = []
    questions = []
    existing_threats = set()

    threat_counter = 1

    has_sensitive_data = bool(request.sensitive_data)
    has_external_integrations = bool(request.external_integrations)
    has_authentication = bool(
        request.authentication
        and request.authentication.lower() not in ["none", "na", ""]
    )

    internet_facing_keywords = [
        "frontend",
        "api gateway",
        "web app",
        "mobile app",
        "public api",
        "internet",
    ]

    internet_facing = any(
        keyword in component.lower()
        for component in request.components
        for keyword in internet_facing_keywords
    )

    has_database = any(
        "db" in component.lower()
        or "database" in component.lower()
        or "postgres" in component.lower()
        or "mysql" in component.lower()
        or "mongodb" in component.lower()
        for component in request.components
    )

    def add_threat(
        category: str,
        component: str,
        description: str,
        impact: str,
        likelihood: str,
        recommendation: str,
    ):
        nonlocal threat_counter

        threat_key = f"{category}:{component}:{description}"

        if threat_key in existing_threats:
            return

        existing_threats.add(threat_key)

        risk = calculate_risk_level(
            category=category,
            has_sensitive_data=has_sensitive_data,
            is_internet_facing=internet_facing,
            has_external_integrations=has_external_integrations,
            has_authentication=has_authentication,
        )

        threats.append(
            Threat(
                threat_id=f"T-{threat_counter:03}",
                stride_category=category,
                affected_component=component,
                description=description,
                risk_level=risk,
                impact=impact,
                likelihood=likelihood,
                recommendation=recommendation,
            )
        )

        threat_counter += 1

    assets = sorted(list(set(request.components + request.sensitive_data)))

    if not has_authentication:
        add_threat(
            category="Spoofing",
            component="Authentication",
            description="Authentication appears to be missing or unclear.",
            impact="Unauthorized users may access protected functionality.",
            likelihood="Medium",
            recommendation="Define strong authentication using OIDC/OAuth2, MFA where needed, and secure session handling.",
        )

        requirements.append(
            "Authentication must be clearly defined and enforced for protected endpoints."
        )
    else:
        requirements.append(
            f"Authentication must be enforced using {request.authentication}."
        )

    if has_sensitive_data:
        add_threat(
            category="Information Disclosure",
            component="Sensitive Data",
            description="The system processes sensitive data that may be exposed through logs, APIs, storage, or integrations.",
            impact="Exposure of sensitive data may cause privacy, compliance, and business impact.",
            likelihood="Medium",
            recommendation="Encrypt sensitive data in transit and at rest. Avoid logging secrets or personal data.",
        )

        requirements.append("Sensitive data must be encrypted in transit and at rest.")
        requirements.append("Sensitive data must not be written to application logs.")

    if request.external_integrations:
        for integration in request.external_integrations:
            add_threat(
                category="Tampering",
                component=integration,
                description=f"External integration with {integration} may allow request or response tampering.",
                impact="Manipulated data from external systems may affect business logic or security decisions.",
                likelihood="Medium",
                recommendation="Validate all requests and responses from external integrations. Use signed callbacks where possible.",
            )

        requirements.append("External integration inputs and callbacks must be validated.")

    if request.trust_boundaries:
        for boundary in request.trust_boundaries:
            add_threat(
                category="Elevation of Privilege",
                component=boundary,
                description=f"Trust boundary '{boundary}' may allow privilege escalation if authorization is weak.",
                impact="Attackers may cross from a lower-trust zone into a higher-trust zone.",
                likelihood="Medium",
                recommendation="Enforce authorization checks at every trust boundary. Do not rely only on network location.",
            )

        requirements.append("Authorization must be enforced at every trust boundary.")

    if internet_facing:
        add_threat(
            category="Denial of Service",
            component="Internet-facing entry point",
            description="Internet-facing components may be abused through high-volume or malformed requests.",
            impact="Service availability may be affected.",
            likelihood="Medium",
            recommendation="Apply rate limiting, request validation, timeout controls, and monitoring.",
        )

        requirements.append(
            "Internet-facing endpoints must have rate limiting and input validation."
        )

    if has_database:
        add_threat(
            category="Information Disclosure",
            component="Database",
            description="Database components may expose sensitive data if access control or encryption is weak.",
            impact="Compromise of database access may expose critical system data.",
            likelihood="Medium",
            recommendation="Use least-privilege DB access, encryption, backups, and audit logging.",
        )

        requirements.append("Database access must follow least privilege.")

    for flow in request.data_flows:
        add_threat(
            category="Tampering",
            component=f"{flow.source} -> {flow.destination}",
            description=f"Data flow carrying '{flow.data}' may be modified in transit.",
            impact="Tampered data may cause incorrect processing or security bypass.",
            likelihood="Medium",
            recommendation="Use TLS, schema validation, and integrity checks for critical data flows.",
        )

    if not request.trust_boundaries:
        questions.append("Where are the trust boundaries in this architecture?")

    if not has_authentication:
        questions.append("What authentication and session management mechanism is used?")

    if has_sensitive_data:
        questions.append("Where is sensitive data stored, logged, cached, or transmitted?")

    if request.external_integrations:
        questions.append("Are external callbacks signed and verified?")

    requirements = sorted(list(set(requirements)))
    questions = sorted(list(set(questions)))

    risk_summary = {
        "total_threats": len(threats),
        "high": len([t for t in threats if t.risk_level == "High"]),
        "medium": len([t for t in threats if t.risk_level == "Medium"]),
        "low": len([t for t in threats if t.risk_level == "Low"]),
    }

    stride_categories = [
        "Spoofing",
        "Tampering",
        "Repudiation",
        "Information Disclosure",
        "Denial of Service",
        "Elevation of Privilege",
    ]

    found_categories = {threat.stride_category for threat in threats}

    stride_coverage = {
        category: category in found_categories
        for category in stride_categories
    }

    return ThreatModelResponse(
        system_name=request.system_name,
        assets=assets,
        threats=threats,
        security_requirements=requirements,
        questions=questions,
        risk_summary=risk_summary,
        stride_coverage=stride_coverage,
    )