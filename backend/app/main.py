from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(
    title="CAP Platform API",
    description="Conversational AI Platform",
    version="1.0.0",
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure properly for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
async def root():
    return {"message": "CAP Platform API is running!"}

@app.get("/health")
async def health_check():
    return {"status": "healthy", "service": "backend"}

@app.get("/api/health")
async def api_health_check():
    return {"status": "healthy", "service": "backend-api"}

# API v1 routes
@app.get("/api/v1/health")
async def api_v1_health_check():
    return {"status": "healthy", "service": "backend-api-v1"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)