"""Starter SQLAlchemy metadata model; run migrations before deployment."""
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy import String, DateTime, BigInteger, func

class Base(DeclarativeBase):
    pass

class StoredFile(Base):
    __tablename__ = "stored_files"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    owner_id: Mapped[str] = mapped_column(String(200), index=True)
    original_filename: Mapped[str] = mapped_column(String(255))
    blob_name: Mapped[str] = mapped_column(String(500), unique=True)
    sha256: Mapped[str] = mapped_column(String(64))
    key_vault_key_id: Mapped[str | None] = mapped_column(String(1000), nullable=True)
    size_bytes: Mapped[int] = mapped_column(BigInteger)
    created_at: Mapped[object] = mapped_column(DateTime(timezone=True), server_default=func.now())
