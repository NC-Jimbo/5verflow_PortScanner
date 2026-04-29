from fastapi import FastAPI

app = FastAPI(title="Shadow API - Hidden Internal Service")

@app.get("/")
async def root():
    return {"message": "Shadow API is running on port 8080"}

@app.get("/shadow/user/data")
async def hidden_data():
    return {
        "status": "exposed",
        "message": "This is a Shadow API (IT 부서가 모르는 API)",
        "flag": "SHADOW_API_EXPOSED_2026"
    }

@app.get("/internal/admin")
async def internal_admin():
    return {
        "secret": "This endpoint should never be public!",
        "warning": "Shadow API Exposed - Critical Finding"
    }

print("✅ Shadow API started with hidden endpoints!")