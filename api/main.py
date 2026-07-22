import time
import logging
import asyncio
from contextlib import asynccontextmanager

from dotenv import load_dotenv
load_dotenv()  # Load .env before anything else

from fastapi import FastAPI, Request, status
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware

import routes_file
import routes_realtime
from core.session_manager import session_manager

# Logging Setup
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger("scam_detector.api.main")


async def session_purger():
    """Background task to clean inactive realtime sessions."""
    while True:
        try:
            await asyncio.sleep(600)  # 10 minutes
            logger.info("Running periodic cleanup for inactive sessions...")
            session_manager.cleanup_inactive_sessions(max_idle_seconds=1800)
        except asyncio.CancelledError:
            logger.info("Session purger stopped.")
            break
        except Exception as e:
            logger.error(f"Error in session purger: {e}")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup: Warm up all heavy models on CPU"""
    logger.info("🚀 Starting scam-detector API - Warming up models...")

    try:
        from core.transcriber import get_whisper_model
        from core.ensemble import get_bart_pipeline, get_xlm_pipeline, get_xgb_components
        from core.embeddings_scorer import get_embeddings_model, score_transcript

        get_whisper_model()
        logger.info("✅ Whisper loaded")

        get_bart_pipeline()
        logger.info("✅ BART loaded")

        get_xlm_pipeline()
        logger.info("✅ XLM-RoBERTa loaded")

        get_xgb_components()
        logger.info("✅ XGBoost loaded")

        get_embeddings_model()
        score_transcript("warmup test")
        logger.info("✅ Embeddings model loaded")

        logger.info("✅ All models warmed up successfully!")

    except Exception as e:
        logger.warning(f"Model warmup failed (will lazy load): {e}")

    # Start background cleaner
    purger_task = asyncio.create_task(session_purger())
    
    yield

    # Shutdown
    logger.info("Shutting down...")
    purger_task.cancel()
    await asyncio.gather(purger_task, return_exceptions=True)


# FastAPI App
app = FastAPI(
    title="Scam Detector API",
    description="Multilingual Scam Detection (Text + Audio) - CPU Only",
    version="1.0.0",
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def log_requests(request: Request, call_next):
    start = time.perf_counter()
    response = await call_next(request)
    duration = int((time.perf_counter() - start) * 1000)
    logger.info(f"{request.method} {request.url.path} | {response.status_code} | {duration}ms")
    return response


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error(f"Unhandled error: {exc}", exc_info=True)
    return JSONResponse(status_code=500, content={"detail": "Internal Server Error"})


# Routes
app.include_router(routes_file.router, prefix="/detect", tags=["File Processing"])
app.include_router(routes_realtime.router, prefix="/detect", tags=["Realtime Processing"])


@app.get("/")
async def health_check():
    return {
        "status": "online",
        "system": "scam-detector",
        "processor": "CPU",
        "active_sessions": len(getattr(session_manager, '_sessions', {})),
        "languages": ["en", "hi", "hinglish"]
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("api.main:app", host="0.0.0.0", port=8000, reload=True)