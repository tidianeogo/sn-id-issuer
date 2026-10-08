import uuid
from datetime import date, datetime

from sqlalchemy import (Boolean, Date, DateTime, ForeignKey, Integer, LargeBinary, String, Text,
                        create_engine, func)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship, sessionmaker

from .config import get_settings

engine = create_engine(get_settings().database_url, pool_pre_ping=True)
SessionLocal = sessionmaker(bind=engine, expire_on_commit=False)
SCHEMA = {"schema": "issuer"}


class Base(DeclarativeBase):
    pass


class Person(Base):
    """Identité de la personne, clé = NIN (verso de la carte)."""
    __tablename__ = "person"
    __table_args__ = SCHEMA

    nin: Mapped[str] = mapped_column(String(32), primary_key=True)
    given_name: Mapped[str] = mapped_column(String(128))
    family_name: Mapped[str] = mapped_column(String(128))
    date_of_birth: Mapped[date] = mapped_column(Date)
    place_of_birth: Mapped[str | None] = mapped_column(String(128))
    sex: Mapped[str] = mapped_column(String(1))
    height_cm: Mapped[int | None] = mapped_column(Integer)
    nationality: Mapped[str] = mapped_column(String(3), default="SEN")
    address: Mapped[str | None] = mapped_column(Text)
    photo_jpeg: Mapped[bytes | None] = mapped_column(LargeBinary)
    status: Mapped[str] = mapped_column(String(16), default="ACTIVE")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(),
                                                 onupdate=func.now())

    cards: Mapped[list["IdCard"]] = relationship(back_populates="person", order_by="IdCard.date_of_issue.desc()")
    electoral: Mapped["ElectoralRegistration | None"] = relationship(back_populates="person")


class IdCard(Base):
    """Carte d'identité CEDEAO (recto + MRZ du verso)."""
    __tablename__ = "id_card"
    __table_args__ = SCHEMA

    card_number: Mapped[str] = mapped_column(String(32), primary_key=True)
    nin: Mapped[str] = mapped_column(ForeignKey("issuer.person.nin"))
    date_of_issue: Mapped[date] = mapped_column(Date)
    date_of_expiry: Mapped[date] = mapped_column(Date)
    registration_center: Mapped[str | None] = mapped_column(String(64))
    issuing_country: Mapped[str] = mapped_column(String(3), default="SEN")
    mrz_line1: Mapped[str] = mapped_column(String(30))
    mrz_line2: Mapped[str] = mapped_column(String(30))
    mrz_line3: Mapped[str] = mapped_column(String(30))
    status: Mapped[str] = mapped_column(String(16), default="ACTIVE")

    person: Mapped[Person] = relationship(back_populates="cards")


class ElectoralRegistration(Base):
    """Informations électorales imprimées au verso."""
    __tablename__ = "electoral_registration"
    __table_args__ = SCHEMA

    nin: Mapped[str] = mapped_column(ForeignKey("issuer.person.nin"), primary_key=True)
    voter_number: Mapped[str] = mapped_column(String(16), unique=True)
    region: Mapped[str | None] = mapped_column(String(64))
    department: Mapped[str | None] = mapped_column(String(64))
    arrondissement: Mapped[str | None] = mapped_column(String(64))
    commune: Mapped[str | None] = mapped_column(String(128))
    polling_place: Mapped[str | None] = mapped_column(String(128))
    polling_station: Mapped[str | None] = mapped_column(String(8))

    person: Mapped[Person] = relationship(back_populates="electoral")


class IssuedCredential(Base):
    __tablename__ = "issued_credential"
    __table_args__ = SCHEMA

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    vc_id: Mapped[str] = mapped_column(String(64), unique=True)
    nin: Mapped[str] = mapped_column(ForeignKey("issuer.person.nin"))
    card_number: Mapped[str] = mapped_column(ForeignKey("issuer.id_card.card_number"))
    configuration_id: Mapped[str] = mapped_column(String(64))
    holder_id: Mapped[str | None] = mapped_column(Text)
    keycloak_subject: Mapped[str | None] = mapped_column(String(64))
    client_id: Mapped[str | None] = mapped_column(String(128))
    credential: Mapped[dict] = mapped_column(JSONB)
    status: Mapped[str] = mapped_column(String(16), default="VALID")
    issued_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class IssuerKey(Base):
    __tablename__ = "issuer_key"
    __table_args__ = SCHEMA

    kid: Mapped[str] = mapped_column(String(128), primary_key=True)
    key_type: Mapped[str] = mapped_column(String(32), default="Ed25519")
    public_key_multibase: Mapped[str] = mapped_column(String(128))
    private_key_pem: Mapped[bytes] = mapped_column(LargeBinary)  # PKCS#8 chiffré
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class CNonce(Base):
    __tablename__ = "c_nonce"
    __table_args__ = SCHEMA

    nonce: Mapped[str] = mapped_column(String(64), primary_key=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    used: Mapped[bool] = mapped_column(Boolean, default=False)
