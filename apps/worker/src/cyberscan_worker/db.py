from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from cyberscan_worker.config import get_settings

_engine = create_engine(get_settings().database_url, pool_pre_ping=True)
SessionLocal = sessionmaker(bind=_engine, autoflush=False, expire_on_commit=False)
