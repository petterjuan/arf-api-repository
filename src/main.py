from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import os

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

@app.get("/")
async def root():
    return {
        "service": "ARF API",
        "version": "1.0.0",
        "status": "running",
        "docs": "/docs"
    }

@app.get("/health")
async def health():
    return {
        "status": "healthy",
        "edition": os.getenv("ARF_EDITION", "oss"),
        "database": "in-memory"  # Will add real DB later
    }

@app.get("/api/v1/incidents")
async def get_incidents():
    return {
        "incidents": [],
        "total": 0,
        "message": "API endpoint ready - ARF integration pending"
    }

if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
