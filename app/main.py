from fastapi import FastAPI
from fastapi.responses import PlainTextResponse

from app.models import ThreatModelRequest, ThreatModelResponse
from app.threat_engine import generate_threat_model
from app.report_generator import generate_markdown_report

app = FastAPI(
    title="Threat Model Tool",
    description="A lightweight rule-based threat modeling API.",
    version="0.1.0",
)


@app.get("/health")
def health_check():
    return {"status": "ok"}


@app.post("/threatmodel", response_model=ThreatModelResponse)
def create_threat_model(request: ThreatModelRequest):
    return generate_threat_model(request)


@app.post("/threatmodel/report", response_class=PlainTextResponse)
def create_threat_model_report(request: ThreatModelRequest):
    threat_model = generate_threat_model(request)
    return generate_markdown_report(threat_model)


@app.get("/examples")
def get_examples():
    return {
        "example": {
            "system_name": "Payment Service",
            "description": "Handles card payments for ecommerce checkout",
            "components": [
                "Frontend",
                "API Gateway",
                "Payment Service",
                "PostgreSQL",
                "Stripe",
            ],
            "data_flows": [
                {
                    "source": "Frontend",
                    "destination": "API Gateway",
                    "data": "payment request",
                },
                {
                    "source": "Payment Service",
                    "destination": "Stripe",
                    "data": "payment token",
                },
            ],
            "external_integrations": ["Stripe"],
            "authentication": "JWT",
            "sensitive_data": ["card token", "user id", "billing address"],
            "trust_boundaries": ["Internet to API Gateway", "Payment Service to Stripe"],
            "environment": "Cloud",
        }
    }