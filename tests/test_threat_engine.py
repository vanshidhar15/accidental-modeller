from app.models import ThreatModelRequest, DataFlow
from app.threat_engine import generate_threat_model


def test_generate_threat_model_basic():
    payload = ThreatModelRequest(
        system_name="Test System",
        description="A test system",
        components=["Frontend", "API Gateway", "PostgreSQL Database"],
        data_flows=[
            DataFlow(
                source="Frontend",
                destination="API Gateway",
                data="user request"
            )
        ],
        external_integrations=["Stripe"],
        authentication="JWT",
        sensitive_data=["user id", "payment token"],
        trust_boundaries=["Internet to API Gateway"],
        environment="Cloud"
    )

    result = generate_threat_model(payload)

    assert result.system_name == "Test System"
    assert result.risk_summary["total_threats"] > 0
    assert len(result.threats) > 0
    assert len(result.security_requirements) > 0