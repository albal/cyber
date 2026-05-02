from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware

from cyberscan_api.core.config import get_settings
from cyberscan_api.routers import assets, audit, auth, notifications, scans, tokens

settings = get_settings()

app = FastAPI(title="Cyberscan API", version="0.1.0")


class _SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Conservative security headers for API responses.

    The API itself returns JSON, never HTML, so a strict CSP isn't useful
    here — the frontend ships its own. These headers harden the *API*
    against being framed, sniffed, or referrer-leaked by a hostile
    client.
    """

    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault("Permissions-Policy", "()")
        # Only emit HSTS when the client reached us over HTTPS. Setting it
        # on plain HTTP is harmless but pointless; if the request came in
        # over HTTPS, lock it in for a year including subdomains.
        scheme = request.headers.get("x-forwarded-proto", request.url.scheme)
        if scheme == "https":
            response.headers.setdefault(
                "Strict-Transport-Security",
                "max-age=31536000; includeSubDomains",
            )
        return response


app.add_middleware(_SecurityHeadersMiddleware)

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
