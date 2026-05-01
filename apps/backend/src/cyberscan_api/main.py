from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from cyberscan_api.core.config import get_settings
from cyberscan_api.routers import assets, audit, auth, notifications, scans, tokens

settings = get_settings()

app = FastAPI(title="Cyberscan API", version="0.1.0")

_origins = [o.strip() for o in settings.cors_origins.split(",") if o.strip()]
if "*" in _origins:
    # Spec: allow_credentials cannot be True when allow_origins is "*".
    # Use the regex form so any origin is accepted.
    app.add_middleware(
        CORSMiddleware,
        allow_origin_regex=".*",
        allow_credentials=False,
        allow_methods=["*"],
        allow_headers=["*"],
        expose_headers=["*"],
    )
else:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
        expose_headers=["*"],
    )

app.include_router(auth.router)
app.include_router(assets.router)
app.include_router(scans.router)
app.include_router(notifications.router)
app.include_router(tokens.router)
app.include_router(audit.router)


@app.get("/healthz")
def healthz() -> dict[str, str]:
    return {"status": "ok"}
