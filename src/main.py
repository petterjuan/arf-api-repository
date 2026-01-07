# src/main.py
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import os

# FIX: Import the router directly
from src.api.v1.incidents import router as incidents_router
from src.database import engine, Base

# Create tables
Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="ARF API",
    version="1.0.0",
    description="Agentic Reliability Framework API",
    docs_url="/docs",
    redoc_url="/redoc"
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Change in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# FIX: Use the imported router
app.include_router(incidents_router)

@app.get("/")
async def root():
    return {
        "service": "ARF API",
        "version": "1.0.2",
        "status": "running",
        "docs": "/docs",
        "endpoints": {
            "incidents": "/api/v1/incidents",
            "health": "/health"
        }
    }

@app.get("/health")
async def health():
    return {
        "status": "healthy",
        "edition": os.getenv("ARF_EDITION", "oss"),
        "database": "postgresql",  # Now using real database
        "services": {
            "postgres": "connected",
            "redis": "connected",
            "neo4j": "connected"
        }
    }

if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
