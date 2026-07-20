"""FastAPI application entrypoint."""
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import inspect, text

from app.config import get_settings
from app.db import Base, SessionLocal, engine

settings = get_settings()


def _init_db() -> None:
    """Create tables and seed a single prototype user."""
    # Register every ORM model before creating or inspecting its table.
    from app import models  # noqa: F401

    Base.metadata.create_all(bind=engine)

    # create_all() creates missing tables but does not add columns to tables that
    # already exist. Keep deployed databases compatible with the dashboard
    # breakdowns added after the initial schema was created.
    summary_columns = {
        column["name"] for column in inspect(engine).get_columns("analysis_summary")
    }
    if "breakdowns_json" not in summary_columns:
        with engine.begin() as connection:
            connection.execute(
                text("ALTER TABLE analysis_summary ADD COLUMN breakdowns_json TEXT")
            )

    os.makedirs(settings.upload_dir, exist_ok=True)

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


from app.api import auth as auth_routes  # noqa: E402
from app.api import uploads as upload_routes  # noqa: E402

app.include_router(auth_routes.router)
app.include_router(upload_routes.router)
