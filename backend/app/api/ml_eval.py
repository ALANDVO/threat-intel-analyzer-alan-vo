from fastapi import APIRouter, Depends
from pydantic import BaseModel
from typing import Any, Dict, List
from app.api.deps import get_current_user
from app.models.entities import UserEntity
from app.services.ml_eval import AgentEvaluator, ThreatClassifier

router = APIRouter(prefix="/ml", tags=["AI & Machine Learning"])

class ClassifyRequest(BaseModel):
    text: str

class ClassifyResponse(BaseModel):
    category: str
    confidence: float
    category_scores: Dict[str, float]

class GroundingRequest(BaseModel):
    advisory_text: str
    ground_truth_facts: List[str]

@router.post("/classify", response_model=ClassifyResponse)
def classify_threat_text(payload: ClassifyRequest, user: UserEntity = Depends(get_current_user)):
    cat, conf, scores = ThreatClassifier.classify(payload.text)
    return ClassifyResponse(category=cat, confidence=conf, category_scores=scores)

@router.get("/evaluate")
def run_benchmark_evaluation(user: UserEntity = Depends(get_current_user)):
    return AgentEvaluator.evaluate_classifier()

@router.post("/grounding-eval")
def evaluate_grounding(payload: GroundingRequest, user: UserEntity = Depends(get_current_user)):
    return AgentEvaluator.evaluate_advisory_grounding(payload.advisory_text, payload.ground_truth_facts)
