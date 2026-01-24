from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field
import uvicorn
from typing import Dict, Any, Optional
from predict import MLPredictor

# Pydantic models for request validation
class BehaviorFeatures(BaseModel):
    keystroke_interval_ms: float = Field(..., ge=0)
    mouse_speed_px_s: float = Field(..., ge=0)
    session_duration_s: float = Field(..., ge=0)
    click_rate: float = Field(..., ge=0, le=1)

class ContextFeatures(BaseModel):
    new_device: int = Field(..., ge=0, le=1)
    ip_change: int = Field(..., ge=0, le=1)
    login_hour: int = Field(..., ge=0, le=23)

class RiskFeatures(BaseModel):
    keystroke_interval_ms: float = Field(..., ge=0)
    mouse_speed_px_s: float = Field(..., ge=0)
    session_duration_s: float = Field(..., ge=0)
    click_rate: float = Field(..., ge=0, le=1)
    new_device: int = Field(..., ge=0, le=1)
    ip_change: int = Field(..., ge=0, le=1)
    login_hour: int = Field(..., ge=0, le=23)
    failed_login_attempts: int = Field(..., ge=0)
    days_since_last_login: float = Field(..., ge=0)
    velocity_check: float = Field(..., ge=0)

class FraudFeatures(BaseModel):
    login_frequency_24h: int = Field(..., ge=0)
    unique_ips_24h: int = Field(..., ge=0)
    failed_attempts_ratio: float = Field(..., ge=0, le=1)
    session_duration_s: float = Field(..., ge=0)
    pages_visited: int = Field(..., ge=0)
    keystroke_rhythm_variance: float = Field(..., ge=0)
    country_changes_24h: int = Field(..., ge=0)
    impossible_travel: int = Field(..., ge=0, le=1)
    device_consistency_score: float = Field(..., ge=0, le=1)
    browser_automation_detected: int = Field(..., ge=0, le=1)
    login_hour: int = Field(..., ge=0, le=23)
    typical_time_deviation: float = Field(..., ge=0)

class AllFeatures(BaseModel):
    behavior: BehaviorFeatures
    context: ContextFeatures
    risk: RiskFeatures
    fraud: FraudFeatures

app = FastAPI(
    title="Adaptive MFA API",
    description="Authentication security ML prediction service",
    version="1.0.0"
)

# Global predictor instance
predictor = None

@app.on_event("startup")
async def startup_event():
    """Load models on startup"""
    global predictor
    try:
        predictor = MLPredictor()
    except Exception as e:
        print(f"Failed to load models: {e}")
        raise

@app.get("/")
async def root():
    """Health check endpoint"""
    return {
        "status": "online",
        "service": "Adaptive MFA API",
        "endpoints": [
            "/predict/behavior",
            "/predict/context",
            "/predict/risk",
            "/predict/fraud",
            "/predict/all"
        ]
    }

@app.get("/health")
async def health_check():
    """Detailed health check"""
    return {
        "status": "healthy",
        "models_loaded": predictor is not None
    }

@app.post("/predict/behavior")
async def predict_behavior(features: BehaviorFeatures):
    """Predict behavioral anomalies"""
    try:
        return predictor.predict_behavior(features)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/predict/context")
async def predict_context(features: ContextFeatures):
    """Predict contextual risk"""
    try:
        return predictor.predict_context(features)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/predict/risk")
async def predict_risk(features: RiskFeatures):
    """Predict overall risk score"""
    try:
        return predictor.predict_risk(features)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/predict/fraud")
async def predict_fraud(features: FraudFeatures):
    """Predict fraud probability"""
    try:
        return predictor.predict_fraud(features)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/predict/all")
async def predict_all(features: AllFeatures):
    """Run all predictions"""
    try:
        return {
            'behavior': predictor.predict_behavior(features.behavior),
            'context': predictor.predict_context(features.context),
            'risk': predictor.predict_risk(features.risk),
            'fraud': predictor.predict_fraud(features.fraud)
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)