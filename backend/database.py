"""
Base de données SQLite pour ForensIQ.
Stocke les fichiers uploadés et les alertes extraites par les parsers
(Hayabusa, Loki, module ML réseau) + enrichissement threat intel.
"""
from sqlalchemy import create_engine, Column, Integer, String, Float, DateTime, ForeignKey, Boolean
from sqlalchemy.orm import declarative_base, sessionmaker, relationship
from datetime import datetime

DATABASE_URL = "sqlite:///./forensiq.db"

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


class User(Base):
    """Utilisateur de la plateforme ForensiQ (analyste / administrateur)."""
    __tablename__ = "users"

    id              = Column(Integer, primary_key=True, index=True)
    username        = Column(String, unique=True, index=True, nullable=False)
    email           = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    role            = Column(String, default="analyst")   # "analyst" | "admin"
    is_active       = Column(Boolean, default=True)
    failed_attempts = Column(Integer, default=0)
    locked_until    = Column(DateTime, nullable=True)
    last_login      = Column(DateTime, nullable=True)
    created_at      = Column(DateTime, default=datetime.utcnow)

    case_files = relationship("CaseFile", back_populates="owner")


class LoginAttempt(Base):
    """Log de chaque tentative de connexion (succès ou échec)."""
    __tablename__ = "login_attempts"

    id          = Column(Integer, primary_key=True, index=True)
    ip_address  = Column(String)
    username    = Column(String)
    success     = Column(Boolean, default=False)
    timestamp   = Column(DateTime, default=datetime.utcnow)


class CaseFile(Base):
    """Un fichier uploadé (sortie Hayabusa, log Loki, CSV réseau, etc.)"""
    __tablename__ = "case_files"

    id = Column(Integer, primary_key=True, index=True)
    case_id = Column(String, index=True)
    filename = Column(String)
    tool = Column(String)          # "hayabusa", "loki", "ml-network", "unknown"
    status = Column(String)        # "processing", "parsed", "error", "unsupported"
    alert_count = Column(Integer, default=0)
    uploaded_at = Column(DateTime, default=datetime.utcnow)
    owner_id    = Column(Integer, ForeignKey("users.id"), nullable=True)

    alerts = relationship("Alert", back_populates="file", cascade="all, delete-orphan")
    owner  = relationship("User", back_populates="case_files")


class Alert(Base):
    """Une alerte extraite d'un fichier."""
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)
    case_id = Column(String, index=True)
    file_id = Column(Integer, ForeignKey("case_files.id"))
    tool = Column(String)
    severity = Column(String)      # critical / high / medium / low / info
    score = Column(Float, default=0)
    title = Column(String)
    target = Column(String)        # nom de fichier, IP, hôte concerné
    details = Column(String)
    timestamp = Column(String, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    # Champs spécifiques Hayabusa
    event_id = Column(String, nullable=True)
    channel = Column(String, nullable=True)
    mitre_attack = Column(String, nullable=True)
    record_id = Column(String, nullable=True)
    rule_path = Column(String, nullable=True)
    computer = Column(String, nullable=True)
    file_path = Column(String, nullable=True)
    raw_data = Column(String, nullable=True)   # ligne CSV brute complète (JSON)

    # Champs spécifiques réseau (module ML)
    src_ip = Column(String, nullable=True)
    dst_ip = Column(String, nullable=True)
    confidence = Column(Float, nullable=True)

    # Enrichissement VirusTotal (JSON texte)
    threat_intel = Column(String, nullable=True)

    file = relationship("CaseFile", back_populates="alerts")


def init_db():
    Base.metadata.create_all(bind=engine)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()