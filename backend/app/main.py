"""FastAPI application entrypoint."""
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.config import get_settings
from app.db import Base, SessionLocal, engine

settings = get_settings()


def _init_db() -> None:
    """Create tables and seed a single prototype user."""
    Base.metadata.create_all(bind=engine)
    os.makedirs(settings.upload_dir, exist_ok=True)

    # Import here so models are registered before create_all runs.
    from app.auth import hash_password
    from app.models import User

    db = SessionLocal()
    try:
        exists = db.query(User).filter(User.username == settings.seed_username).first()
        if not exists:
            db.add(
                User(
                    username=settings.seed_username,
                    password_hash=hash_password(settings.seed_password),
                )
            )
            db.commit()
    finally:
        db.close()


@asynccontextmanager
async def lifespan(app: FastAPI):
    _init_db()
    yield


app = FastAPI(title="Tenex Log Analysis API", version="0.1.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[settings.frontend_origin],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


# Routers are mounted in later phases (auth, uploads).
from app.api import auth as auth_routes  # noqa: E402

app.include_router(auth_routes.router)
