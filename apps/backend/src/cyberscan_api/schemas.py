import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, EmailStr, Field, HttpUrl


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True, use_enum_values=True)
    id: uuid.UUID
    tenant_id: uuid.UUID
    email: EmailStr
    role: str
    is_admin: bool


class AssetCreate(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    target_url: HttpUrl
    verification_method: str = Field(default="http_file", pattern="^(http_file|dns_txt|http_header)$")


class AssetSchedule(BaseModel):
    schedule_cron: str | None = Field(default=None, max_length=64)
    schedule_enabled: bool = False


class AssetOut(BaseModel):
    model_config = ConfigDict(from_attributes=True, use_enum_values=True)
    id: uuid.UUID
    name: str
    target_url: str
    hostname: str
    verification_method: str
    verification_token: str
    verification_status: str
    verified_at: datetime | None
    schedule_cron: str | None
    schedule_enabled: bool
    last_scheduled_at: datetime | None
    created_at: datetime


class VerificationInstructions(BaseModel):
    method: str
    token: str
    instructions: str


class ScanCreate(BaseModel):
    asset_id: uuid.UUID
    intrusive: bool = False


class ScanOut(BaseModel):
    model_config = ConfigDict(from_attributes=True, use_enum_values=True)
    id: uuid.UUID
    asset_id: uuid.UUID
    status: str
    stage: str | None
    progress: int
    started_at: datetime | None
    finished_at: datetime | None
    error: str | None
    summary: dict | None
    intrusive: bool
    created_at: datetime


class FindingOut(BaseModel):
    model_config = ConfigDict(from_attributes=True, use_enum_values=True)
    id: uuid.UUID
    scan_id: uuid.UUID
    title: str
    template_id: str | None
    cve_ids: list[str]
    cwe_ids: list[str]
    severity: str
    cvss_score: float | None
    epss_score: float | None
    is_kev: bool
    risk_score: float
    location: str | None
    matcher_name: str | None
    request: str | None
    response_excerpt: str | None
    remediation: str | None
    references: list[str]
    compliance_tags: list[str]
    diff_status: str | None
    source: str


class NotificationChannelCreate(BaseModel):
    kind: str = Field(pattern="^(email|slack|teams)$")
    target: str = Field(min_length=1, max_length=2048)
    min_severity: str = Field(default="high", pattern="^(critical|high|medium|low|info)$")
    enabled: bool = True


class NotificationChannelOut(BaseModel):
    model_config = ConfigDict(from_attributes=True, use_enum_values=True)
    id: uuid.UUID
    kind: str
    target: str
    min_severity: str
    enabled: bool
    created_at: datetime


class ApiTokenCreate(BaseModel):
    name: str = Field(min_length=1, max_length=128)


class ApiTokenOut(BaseModel):
    model_config = ConfigDict(from_attributes=True, use_enum_values=True)
    id: uuid.UUID
    name: str
    token_prefix: str
    revoked_at: datetime | None
    last_used_at: datetime | None
    created_at: datetime


class ApiTokenCreated(ApiTokenOut):
    """Returned once at creation; includes the plaintext token. Never persisted."""

    token: str


# ---------- Asset credentials (authenticated scans) --------------------------


class AssetCredentialCookie(BaseModel):
    kind: str = Field(default="cookie", pattern="^cookie$")
    label: str | None = Field(default=None, max_length=255)
    cookie_header: str = Field(min_length=1, max_length=8192)


class AssetCredentialBearer(BaseModel):
    kind: str = Field(default="bearer", pattern="^bearer$")
    label: str | None = Field(default=None, max_length=255)
    token: str = Field(min_length=1, max_length=8192)


class AssetCredentialBasic(BaseModel):
    kind: str = Field(default="basic", pattern="^basic$")
    label: str | None = Field(default=None, max_length=255)
    username: str = Field(min_length=1, max_length=512)
    password: str = Field(min_length=1, max_length=2048)


class AssetCredentialHeader(BaseModel):
    kind: str = Field(default="header", pattern="^header$")
    label: str | None = Field(default=None, max_length=255)
    name: str = Field(min_length=1, max_length=255)
    value: str = Field(min_length=1, max_length=8192)


class AssetCredentialMeta(BaseModel):
    """Returned by GET — never includes the plaintext secret."""

    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    asset_id: uuid.UUID
    kind: str
    label: str | None
    created_at: datetime
