from typing import List, Optional
from pydantic import BaseModel


class DataFlow(BaseModel):
    source: str
    destination: str
    data: str


class ThreatModelRequest(BaseModel):
    system_name: str
    description: str
    components: List[str]
    data_flows: List[DataFlow]
    external_integrations: List[str] = []
    authentication: Optional[str] = None
    sensitive_data: List[str] = []
    trust_boundaries: List[str] = []
    environment: Optional[str] = None


class Threat(BaseModel):
    threat_id: str
    stride_category: str
    affected_component: str
    description: str
    risk_level: str
    impact: str
    likelihood: str
    recommendation: str


class ThreatModelResponse(BaseModel):
    system_name: str
    assets: List[str]
    threats: List[Threat]
    security_requirements: List[str]
    questions: List[str]
    risk_summary: dict
    stride_coverage: dict