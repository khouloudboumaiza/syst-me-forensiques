"""
ForensiQ — Module d'authentification JWT.
- Hash bcrypt des mots de passe (jamais stocké en clair)
- Access token (30 min) + Refresh token (7 jours)
- Lockout après 5 tentatives échouées (15 minutes)
- Logs de toutes les tentatives de connexion
- Compte admin par défaut : admin / admin
"""
import os
import logging
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy.orm import Session

from database import get_db, User, LoginAttempt

# ─── Configuration ────────────────────────────────────────────────────────────
SECRET_KEY = os.environ.get("JWT_SECRET_KEY", "forensiq-secret-key-change-in-production-2024")
ALGORITHM = os.environ.get("JWT_ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.environ.get("ACCESS_TOKEN_EXPIRE_MINUTES", "30"))
REFRESH_TOKEN_EXPIRE_DAYS = int(os.environ.get("REFRESH_TOKEN_EXPIRE_DAYS", "7"))
MAX_FAILED_ATTEMPTS = 5
LOCKOUT_MINUTES = 15

# ─── Logger sécurité SOC ─────────────────────────────────────────────────────
security_logger = logging.getLogger("forensiq.auth")
logging.basicConfig(level=logging.INFO)

# ─── Bcrypt ──────────────────────────────────────────────────────────────────
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# ─── OAuth2 Bearer ───────────────────────────────────────────────────────────
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")


def hash_password(plain: str) -> str:
    return pwd_context.hash(plain)


def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)


# ─── JWT ─────────────────────────────────────────────────────────────────────
def create_access_token(data: dict) -> str:
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire, "type": "access"})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def create_refresh_token(data: dict) -> str:
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    to_encode.update({"exp": expire, "type": "refresh"})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def decode_token(token: str) -> dict:
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token invalide ou expiré",
            headers={"WWW-Authenticate": "Bearer"},
        )


# ─── Dépendances FastAPI ──────────────────────────────────────────────────────
def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)) -> User:
    payload = decode_token(token)
    if payload.get("type") != "access":
        raise HTTPException(status_code=401, detail="Token invalide")
    username = payload.get("sub")
    if not username:
        raise HTTPException(status_code=401, detail="Token invalide")
    user = db.query(User).filter(User.username == username).first()
    if not user or not user.is_active:
        raise HTTPException(status_code=401, detail="Compte introuvable ou désactivé")
    return user


def require_admin(current_user: User = Depends(get_current_user)) -> User:
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Accès réservé aux administrateurs")
    return current_user


# ─── Logique de connexion (avec lockout) ─────────────────────────────────────
def authenticate_user(username: str, password: str, client_ip: str, db: Session) -> Optional[User]:
    user = db.query(User).filter(
        (User.username == username) | (User.email == username)
    ).first()

    # Lockout actif ?
    if user and user.locked_until and user.locked_until > datetime.now(timezone.utc).replace(tzinfo=None):
        remaining = int((user.locked_until - datetime.utcnow()).total_seconds() / 60)
        _log_attempt(db, client_ip, username, success=False)
        raise HTTPException(
            status_code=429,
            detail=f"Compte temporairement verrouillé. Réessayez dans {remaining} minute(s)."
        )

    # Vérification du mot de passe
    if not user or not verify_password(password, user.hashed_password):
        if user:
            user.failed_attempts = (user.failed_attempts or 0) + 1
            if user.failed_attempts >= MAX_FAILED_ATTEMPTS:
                user.locked_until = datetime.utcnow() + timedelta(minutes=LOCKOUT_MINUTES)
                security_logger.warning(f"[LOCKOUT] Compte '{username}' verrouillé (IP: {client_ip})")
            db.commit()
        _log_attempt(db, client_ip, username, success=False)
        security_logger.warning(f"[AUTH FAIL] Tentative échouée pour '{username}' (IP: {client_ip})")
        # Message générique — ne pas révéler si c'est l'email ou le mdp
        raise HTTPException(status_code=401, detail="Identifiants invalides")

    # Succès
    user.failed_attempts = 0
    user.locked_until = None
    user.last_login = datetime.utcnow()
    db.commit()
    _log_attempt(db, client_ip, username, success=True)
    security_logger.info(f"[AUTH OK] Connexion réussie pour '{username}' (IP: {client_ip})")
    return user


def _log_attempt(db: Session, ip: str, username: str, success: bool):
    try:
        attempt = LoginAttempt(ip_address=ip, username=username, success=success)
        db.add(attempt)
        db.commit()
    except Exception:
        db.rollback()


# ─── Création du compte admin par défaut ─────────────────────────────────────
def ensure_default_admin(db: Session):
    """Crée le compte admin/admin s'il n'existe pas encore."""
    existing = db.query(User).filter(User.username == "admin").first()
    if not existing:
        admin = User(
            username="admin",
            email="admin@forensiq.local",
            hashed_password=hash_password("admin"),
            role="admin",
            is_active=True,
        )
        db.add(admin)
        db.commit()
        security_logger.info("[INIT] Compte admin par défaut créé (admin/admin)")
