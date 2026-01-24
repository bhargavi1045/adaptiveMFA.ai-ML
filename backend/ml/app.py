from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field
from typing import Dict, Any
import uvicorn
from contextlib import asynccontextmanager
from predict import MLPredictor

# ---------------- Pydantic models ----------------
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
    behavior_risk: float = Field(..., ge=0, le=1)
    context_risk: float = Field(..., ge=0, le=1)
    velocity_risk: float = Field(..., ge=0, le=1)

class FraudFeatures(BaseModel):
    risk_score: float = Field(..., ge=0, le=1)
    failed_attempts: int = Field(..., ge=0)
    session_duration_s: float = Field(..., ge=0)

class AllFeatures(BaseModel):
    behavior: BehaviorFeatures
    context: ContextFeatures
    risk: RiskFeatures
    fraud: FraudFeatures

# ---------------- Lifespan handler ----------------
@asynccontextmanager
async def lifespan(app: FastAPI):
    """Load models on startup using the new FastAPI lifespan method"""
    app.state.predictor = MLPredictor()
    print("✅ All models loaded successfully")
    yield
    # Optional: do shutdown cleanup here
    print("Shutting down app...")

# ---------------- FastAPI app ----------------
app = FastAPI(
    title="Adaptive MFA API",
    description="Authentication security ML prediction service",
    version="1.0.0",
    lifespan=lifespan
)

# ---------------- Routes ----------------
@app.get("/")
async def root():
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
    return {
        "status": "healthy",
        "models_loaded": hasattr(app.state, "predictor")
    }

@app.post("/predict/behavior")
async def predict_behavior(features: BehaviorFeatures):
    try:
        return app.state.predictor.predict_behavior(features.dict())
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/predict/context")
async def predict_context(features: ContextFeatures):
    try:
        return app.state.predictor.predict_context(features.dict())
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/predict/risk")
async def predict_risk(features: RiskFeatures):
    try:
        return app.state.predictor.predict_risk(features.dict())
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/predict/fraud")
async def predict_fraud(features: FraudFeatures):
    try:
        return app.state.predictor.predict_fraud(features.dict())
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/predict/all")
async def predict_all(features: AllFeatures):
    try:
        behavior = app.state.predictor.predict_behavior(features.behavior.dict())
        context = app.state.predictor.predict_context(features.context.dict())
        risk = app.state.predictor.predict_risk(features.risk.dict())
        fraud = app.state.predictor.predict_fraud(features.fraud.dict())
        return {
            "behavior": behavior,
            "context": context,
            "risk": risk,
            "fraud": fraud
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# ---------------- Main ----------------
if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
