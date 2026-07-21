from app.models import ThreatModelRequest, Threat, ThreatModelResponse


STRIDE_CATEGORIES = [
    "Spoofing",
    "Tampering",
    "Repudiation",
    "Information Disclosure",
    "Denial of Service",
    "Elevation of Privilege",
]


def calculate_risk_level(
    category: str,
    has_sensitive_data: bool,
    is_internet_facing: bool,
    has_external_integrations: bool,
    has_authentication: bool,
) -> str:
    score = 0

    if category in {
        "Information Disclosure",
        "Elevation of Privilege",
    }:
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


def generate_threat_model(
    request: ThreatModelRequest,
) -> ThreatModelResponse:
    threats: list[Threat] = []
    requirements: list[str] = []
    questions: list[str] = []
    existing_threats: set[tuple[str, str, str]] = set()

    threat_counter = 1

    has_sensitive_data = bool(request.sensitive_data)
    has_external_integrations = bool(request.external_integrations)

    authentication_method = (
        request.authentication.strip()
        if request.authentication
        else ""
    )

    has_authentication = (
        authentication_method.lower()
        not in {"", "none", "na", "n/a"}
    )

    internet_facing_keywords = [
        "frontend",
        "api gateway",
        "web app",
        "web application",
        "mobile app",
        "public api",
        "internet",
        "public endpoint",
    ]

    internet_facing = any(
        keyword in component.lower()
        for component in request.components
        for keyword in internet_facing_keywords
    )

    database_keywords = [
        "db",
        "database",
        "postgres",
        "postgresql",
        "mysql",
        "mongodb",
        "mongo",
        "oracle",
        "sql server",
        "redis",
        "dynamodb",
        "cosmos db",
    ]

    has_database = any(
        keyword in component.lower()
        for component in request.components
        for keyword in database_keywords
    )

    def add_threat(
        category: str,
        component: str,
        description: str,
        impact: str,
        likelihood: str,
        recommendation: str,
    ) -> None:
        nonlocal threat_counter

        if category not in STRIDE_CATEGORIES:
            raise ValueError(
                f"Unsupported STRIDE category: {category}"
            )

        threat_key = (
            category.strip().lower(),
            component.strip().lower(),
            description.strip().lower(),
        )

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

    assets = sorted(
        set(request.components + request.sensitive_data),
        key=str.lower,
    )

    # ------------------------------------------------------------------
    # Spoofing
    # ------------------------------------------------------------------

    if not has_authentication:
        add_threat(
            category="Spoofing",
            component="Authentication",
            description=(
                "Authentication appears to be missing or unclear."
            ),
            impact=(
                "Unauthorized users or services may impersonate "
                "legitimate identities and access protected "
                "functionality."
            ),
            likelihood="Medium",
            recommendation=(
                "Define strong authentication using OIDC or OAuth 2.0, "
                "apply MFA where appropriate, and implement secure "
                "session and token handling."
            ),
        )

        requirements.append(
            "Authentication must be clearly defined and enforced "
            "for protected endpoints."
        )
    else:
        add_threat(
            category="Spoofing",
            component="Authentication",
            description=(
                f"Credentials, sessions, or tokens associated with "
                f"{authentication_method} may be stolen, forged, "
                f"replayed, or used to impersonate a legitimate identity."
            ),
            impact=(
                "An attacker may gain unauthorized access while "
                "appearing to be a trusted user, administrator, "
                "or service."
            ),
            likelihood="Medium",
            recommendation=(
                "Protect credentials and tokens, validate token issuer "
                "and audience, use short-lived tokens, rotate signing "
                "keys, prevent replay, and revoke compromised sessions."
            ),
        )

        requirements.append(
            f"Authentication must be enforced using "
            f"{authentication_method}."
        )

        requirements.append(
            "Authentication tokens and sessions must be protected "
            "against theft, replay, forgery, and unauthorized reuse."
        )

    # ------------------------------------------------------------------
    # Information disclosure
    # ------------------------------------------------------------------

    if has_sensitive_data:
        add_threat(
            category="Information Disclosure",
            component="Sensitive Data",
            description=(
                "The system processes sensitive data that may be "
                "exposed through logs, APIs, storage, caches, backups, "
                "or external integrations."
            ),
            impact=(
                "Exposure of sensitive data may cause privacy, "
                "compliance, financial, and business impact."
            ),
            likelihood="Medium",
            recommendation=(
                "Encrypt sensitive data in transit and at rest, "
                "apply data minimisation, mask sensitive values, "
                "and prevent sensitive data from being written to logs."
            ),
        )

        requirements.append(
            "Sensitive data must be encrypted in transit and at rest."
        )

        requirements.append(
            "Sensitive data must not be written to application logs."
        )

    # ------------------------------------------------------------------
    # External integrations: tampering
    # ------------------------------------------------------------------

    if request.external_integrations:
        for integration in request.external_integrations:
            add_threat(
                category="Tampering",
                component=integration,
                description=(
                    f"Requests or responses exchanged with "
                    f"{integration} may be modified, replayed, "
                    f"or supplied in an unexpected format."
                ),
                impact=(
                    "Manipulated integration data may affect business "
                    "logic, payment processing, authorization decisions, "
                    "or downstream system behaviour."
                ),
                likelihood="Medium",
                recommendation=(
                    "Authenticate external integrations, validate all "
                    "requests and responses, verify signed callbacks, "
                    "prevent replay attacks, and fail safely when "
                    "unexpected data is received."
                ),
            )

        requirements.append(
            "External integration requests, responses, and callbacks "
            "must be authenticated and validated."
        )

    # ------------------------------------------------------------------
    # Trust boundaries: elevation of privilege
    # ------------------------------------------------------------------

    if request.trust_boundaries:
        for boundary in request.trust_boundaries:
            add_threat(
                category="Elevation of Privilege",
                component=boundary,
                description=(
                    f"Trust boundary '{boundary}' may allow a user, "
                    f"service, or attacker to access higher-privileged "
                    f"functionality if authorization controls are weak."
                ),
                impact=(
                    "An attacker may cross from a lower-trust zone "
                    "into a higher-trust zone and perform unauthorized "
                    "actions."
                ),
                likelihood="Medium",
                recommendation=(
                    "Enforce authentication and authorization at every "
                    "trust boundary, validate service identities, apply "
                    "least privilege, and do not rely only on network "
                    "location."
                ),
            )

        requirements.append(
            "Authorization must be enforced at every trust boundary."
        )

    # ------------------------------------------------------------------
    # Internet-facing components: denial of service
    # ------------------------------------------------------------------

    if internet_facing:
        add_threat(
            category="Denial of Service",
            component="Internet-facing entry point",
            description=(
                "Internet-facing components may be abused through "
                "high-volume, malformed, oversized, or computationally "
                "expensive requests."
            ),
            impact=(
                "Service availability, performance, and dependent "
                "systems may be affected."
            ),
            likelihood="Medium",
            recommendation=(
                "Apply rate limiting, request-size limits, schema "
                "validation, timeouts, circuit breakers, resource "
                "quotas, and availability monitoring."
            ),
        )

        requirements.append(
            "Internet-facing endpoints must have rate limiting, "
            "input validation, timeout controls, and abuse protection."
        )

    # ------------------------------------------------------------------
    # Database threats
    # ------------------------------------------------------------------

    if has_database:
        add_threat(
            category="Information Disclosure",
            component="Database",
            description=(
                "Database components may expose sensitive or "
                "business-critical data if access control, encryption, "
                "or query handling is weak."
            ),
            impact=(
                "Compromise of database access may expose sensitive "
                "or critical system data."
            ),
            likelihood="Medium",
            recommendation=(
                "Use least-privilege database accounts, parameterized "
                "queries, encryption, secure secret management, backups, "
                "network restrictions, and audit logging."
            ),
        )

        add_threat(
            category="Tampering",
            component="Database",
            description=(
                "Application data, configuration, permissions, or "
                "audit records stored in the database may be modified "
                "without authorization."
            ),
            impact=(
                "Unauthorized changes may corrupt business data, "
                "alter security decisions, enable fraud, or hide "
                "malicious activity."
            ),
            likelihood="Medium",
            recommendation=(
                "Use least-privilege database permissions, parameterized "
                "queries, transaction controls, integrity validation, "
                "change auditing, protected backups, and monitoring "
                "for unauthorized modifications."
            ),
        )

        requirements.append(
            "Database access must follow least privilege and use "
            "secure credential management."
        )

        requirements.append(
            "Database changes affecting sensitive or security-relevant "
            "data must be authorized, validated, and auditable."
        )

    # ------------------------------------------------------------------
    # Data-flow tampering
    # ------------------------------------------------------------------

    for flow in request.data_flows:
        add_threat(
            category="Tampering",
            component=f"{flow.source} -> {flow.destination}",
            description=(
                f"The data flow carrying '{flow.data}' from "
                f"{flow.source} to {flow.destination} may be modified, "
                f"replayed, duplicated, or replaced in transit."
            ),
            impact=(
                "Tampered data may cause incorrect processing, fraud, "
                "security bypass, or inconsistent downstream state."
            ),
            likelihood="Medium",
            recommendation=(
                "Use authenticated encryption in transit, schema "
                "validation, integrity controls, replay protection, "
                "and monitoring for critical data flows."
            ),
        )

    # ------------------------------------------------------------------
    # Repudiation
    # ------------------------------------------------------------------

    requires_auditability = bool(
        has_authentication
        or has_sensitive_data
        or has_external_integrations
        or has_database
        or request.data_flows
    )

    if requires_auditability:
        add_threat(
            category="Repudiation",
            component="Audit and Logging",
            description=(
                "Security-relevant actions may not be recorded with "
                "enough identity, timestamp, context, and integrity "
                "information to prove who performed an action."
            ),
            impact=(
                "Users, administrators, services, or external systems "
                "may deny performing sensitive or unauthorized actions, "
                "limiting incident investigation and accountability."
            ),
            likelihood="Medium",
            recommendation=(
                "Record authentication events, authorization failures, "
                "administrative actions, sensitive-data access, and "
                "critical business transactions. Protect logs against "
                "modification and deletion, synchronize timestamps, "
                "and associate events with verified identities and "
                "correlation identifiers."
            ),
        )

        requirements.append(
            "Security-relevant actions must be recorded in "
            "tamper-resistant audit logs with verified identity, "
            "timestamp, action, outcome, and correlation information."
        )

        requirements.append(
            "Access to audit logs must be restricted and monitored."
        )

    # ------------------------------------------------------------------
    # Contextual security review questions
    # ------------------------------------------------------------------

    component_names = (
        ", ".join(request.components)
        if request.components
        else "the identified system components"
    )

    sensitive_data_names = (
        ", ".join(request.sensitive_data)
        if request.sensitive_data
        else "the identified sensitive data"
    )

    integration_names = (
        ", ".join(request.external_integrations)
        if request.external_integrations
        else "the identified external integrations"
    )

    boundary_names = (
        ", ".join(request.trust_boundaries)
        if request.trust_boundaries
        else "the identified trust boundaries"
    )

    if has_authentication:
        questions.append(
            f"How are credentials, sessions, or tokens issued, "
            f"validated, rotated, revoked, and protected when using "
            f"{authentication_method}?"
        )
    else:
        questions.append(
            "Which users, services, administrators, or external "
            "systems can access the application, and what "
            "authentication mechanism is required for each identity type?"
        )

    questions.append(
        "Where are authorization decisions enforced, and are "
        "object-level, function-level, and administrative permissions "
        "checked for every protected operation?"
    )

    questions.append(
        "How are service-to-service identities authenticated, and how "
        "is least privilege enforced between components?"
    )

    if has_sensitive_data:
        questions.append(
            f"Which components store, process, cache, log, back up, "
            f"or transmit the following sensitive data: "
            f"{sensitive_data_names}?"
        )

        questions.append(
            "What data classification, retention, masking, deletion, "
            "encryption, and key-management requirements apply to the "
            "identified sensitive data?"
        )

        questions.append(
            "Can sensitive values appear in application logs, error "
            "messages, monitoring platforms, analytics tools, or "
            "support exports?"
        )

    if request.external_integrations:
        questions.append(
            f"How does the system authenticate and validate requests, "
            f"responses, callbacks, and error messages exchanged with: "
            f"{integration_names}?"
        )

        questions.append(
            "What happens when an external integration is unavailable, "
            "compromised, slow, returns malformed data, or repeats a "
            "previous request?"
        )

    if request.trust_boundaries:
        questions.append(
            f"What authentication, authorization, encryption, input "
            f"validation, and monitoring controls are enforced when "
            f"data or identities cross these trust boundaries: "
            f"{boundary_names}?"
        )
    else:
        questions.append(
            f"Where do trust levels change between these components: "
            f"{component_names}?"
        )

        questions.append(
            "Are there implicit trust boundaries between users, "
            "internet-facing services, internal services, data stores, "
            "administrative interfaces, and third-party systems?"
        )

    questions.append(
        "Which security-relevant actions must be logged, and can those "
        "events be traced to a verified user, service, or administrator?"
    )

    questions.append(
        "Who can view, alter, disable, or delete audit logs, and how is "
        "log integrity protected?"
    )

    questions.append(
        "How are failed authentication attempts, authorization "
        "failures, sensitive-data access, administrative actions, "
        "and suspicious behaviour detected and investigated?"
    )

    if internet_facing:
        questions.append(
            "What rate limits, request-size limits, timeouts, resource "
            "quotas, abuse controls, and capacity protections apply to "
            "internet-facing endpoints?"
        )

        questions.append(
            "How does the application respond to malformed, repeated, "
            "automated, or computationally expensive requests?"
        )

    if has_database:
        questions.append(
            "Which application and administrative identities can access "
            "the database, and what permissions does each identity have?"
        )

        questions.append(
            "How are database credentials stored, rotated, monitored, "
            "and prevented from being shared between environments?"
        )

        questions.append(
            "Which database changes require audit records, and how are "
            "unauthorized or unexpected changes detected?"
        )

    for flow in request.data_flows:
        questions.append(
            f"How is the '{flow.data}' flow from {flow.source} to "
            f"{flow.destination} authenticated, encrypted, validated, "
            f"authorized, and monitored?"
        )

        questions.append(
            f"What happens if the '{flow.data}' flow from "
            f"{flow.source} to {flow.destination} is delayed, replayed, "
            f"duplicated, modified, or unavailable?"
        )

    questions.append(
        "Which input fields, files, headers, parameters, or messages "
        "are controlled by users or external systems, and where are "
        "they validated?"
    )

    questions.append(
        "How are secrets, API keys, certificates, and service "
        "credentials stored, rotated, revoked, and prevented from "
        "appearing in code or logs?"
    )

    requirements = sorted(
        set(requirements),
        key=str.lower,
    )

    questions = sorted(
        set(questions),
        key=str.lower,
    )

    risk_summary = {
        "total_threats": len(threats),
        "high": sum(
            threat.risk_level == "High"
            for threat in threats
        ),
        "medium": sum(
            threat.risk_level == "Medium"
            for threat in threats
        ),
        "low": sum(
            threat.risk_level == "Low"
            for threat in threats
        ),
    }

    found_categories = {
        threat.stride_category
        for threat in threats
    }

    stride_coverage = {
        category: category in found_categories
        for category in STRIDE_CATEGORIES
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