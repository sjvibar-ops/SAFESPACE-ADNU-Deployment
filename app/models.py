"""
models.py
SafeSpace — Secure database models

Security design embedded in models:
- #4, #5, #6, #33, #34, #49: Row-level ownership, no raw IDs without authz checks
- #16, #17, #18: All queries via ORM only, parameterized by default
- #19: No stored HTML; text fields validated at form layer, escaped on render
- #35: Audit logs never include passwords/tokens; PII masked in logs
- #42: AuditLog table for every sensitive action
- #48: Sensitive fields use encryption-at-rest pattern (encryption key in env, not code)
- #49: Multi-tenant isolation via user_id/therapist_id scoping on all queries
"""

import os
import secrets
import hashlib
from datetime import datetime, timezone
from typing import Optional

from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.fernet import Fernet
from sqlalchemy import event, Index, text
from sqlalchemy.orm import validates

# We import db from app (not extensions.py since you removed it)
from app import db, login

# ---------------------------------------------------------------------------
# Encryption setup (#48 — unencrypted sensitive data)
# ---------------------------------------------------------------------------
# The encryption key MUST come from environment, never hardcoded (#3).
# Generate once with: Fernet.generate_key()
# Set in .env: ENCRYPTION_KEY=your-base64-key-here
# .env must be in .gitignore (#2 — public .env files)

_ENCRYPTION_KEY = os.environ.get("ENCRYPTION_KEY")
if _ENCRYPTION_KEY:
    _fernet = Fernet(_ENCRYPTION_KEY.encode())
else:
    _fernet = None  # Will raise on encrypt/decrypt if missing


def _encrypt(value: str) -> bytes:
    """Encrypt sensitive text at rest. Raises if no key configured."""
    if _fernet is None:
        raise RuntimeError("ENCRYPTION_KEY not set — cannot encrypt sensitive data")
    return _fernet.encrypt(value.encode("utf-8"))


def _decrypt(token: bytes) -> str:
    """Decrypt sensitive text. Raises if no key configured or tampered."""
    if _fernet is None:
        raise RuntimeError("ENCRYPTION_KEY not set — cannot decrypt sensitive data")
    return _fernet.decrypt(token).decode("utf-8")


# ---------------------------------------------------------------------------
# Mixins
# ---------------------------------------------------------------------------

class TimestampMixin:
    """Auto-created/updated timestamps for audit trail."""
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(
        db.DateTime,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )


class SoftDeleteMixin:
    """Soft delete instead of hard delete to preserve audit trail (#42)."""
    is_deleted = db.Column(db.Boolean, default=False, nullable=False)
    deleted_at = db.Column(db.DateTime, nullable=True)
    deleted_by_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)


# ---------------------------------------------------------------------------
# User model
# ---------------------------------------------------------------------------

class User(UserMixin, db.Model, TimestampMixin, SoftDeleteMixin):
    __tablename__ = "user"

    id = db.Column(db.Integer, primary_key=True)

    # Auth fields
    email = db.Column(db.String(254), unique=True, nullable=False, index=True)
    # Email hash for lookup logging without exposing raw email (#35)
    email_hash = db.Column(db.String(64), unique=True, nullable=False, index=True)

    password_hash = db.Column(db.String(256), nullable=False)
    # Track password changes to invalidate old sessions (#25)
    password_changed_at = db.Column(
        db.DateTime,
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    # Profile
    display_name = db.Column(db.String(80), nullable=True)
    role = db.Column(db.String(20), nullable=False, default="user")
    # Role is server-set only; never accept from client (#34)

    is_active = db.Column(db.Boolean, default=True, nullable=False)
    is_email_verified = db.Column(db.Boolean, default=False, nullable=False)

    # MFA / security
    mfa_secret = db.Column(db.String(32), nullable=True)  # Encrypted TOTP secret
    failed_login_attempts = db.Column(db.Integer, default=0, nullable=False)
    locked_until = db.Column(db.DateTime, nullable=True)

    # Session security (#25)
    session_token_version = db.Column(db.Integer, default=0, nullable=False)

    # Relationships
    therapist_profile = db.relationship(
        "Therapist",
        backref="user",
        uselist=False,
        lazy="joined",
    )
    sent_messages = db.relationship(
        "ChatMessage",
        foreign_keys="ChatMessage.sender_id",
        backref="sender",
        lazy="dynamic",
    )
    audit_logs = db.relationship(
        "AuditLog",
        foreign_keys="AuditLog.user_id",
        backref="user",
        lazy="dynamic",
    )

    # -----------------------------------------------------------------------
    # Validators (#16 — missing input validation at model layer)
    # -----------------------------------------------------------------------

    @validates("email")
    def validate_email(self, key, email):
        email = email.lower().strip()
        if "@" not in email or len(email) > 254:
            raise ValueError("Invalid email format")
        return email

    @validates("role")
    def validate_role(self, key, role):
        allowed = {"user", "therapist", "admin"}
        if role not in allowed:
            raise ValueError(f"Role must be one of {allowed}")
        return role

    @validates("display_name")
    def validate_display_name(self, key, name):
        if name:
            name = name.strip()
            if len(name) > 80:
                raise ValueError("Display name too long")
            # Strip HTML-like content at model layer as defense-in-depth (#19)
            import re
            if re.search(r"<[^>]+>", name):
                raise ValueError("HTML tags not allowed in display name")
        return name

    # -----------------------------------------------------------------------
    # Password methods (#4 — weak/missing authentication)
    # -----------------------------------------------------------------------

    def set_password(self, password: str):
        """Hash password with strong parameters. Never store plaintext."""
        self.password_hash = generate_password_hash(
            password,
            method="pbkdf2:sha256:600000",  # OWASP recommended minimum
        )
        self.password_changed_at = datetime.now(timezone.utc)
        self.session_token_version += 1  # Invalidate existing sessions

    def check_password(self, password: str) -> bool:
        """Verify password. Constant-time comparison via werkzeug."""
        return check_password_hash(self.password_hash, password)

    # -----------------------------------------------------------------------
    # Encryption helpers for sensitive fields (#48)
    # -----------------------------------------------------------------------

    def set_mfa_secret(self, secret: str):
        self.mfa_secret = _encrypt(secret)

    def get_mfa_secret(self) -> Optional[str]:
        return _decrypt(self.mfa_secret) if self.mfa_secret else None

    # -----------------------------------------------------------------------
    # Hooks
    # -----------------------------------------------------------------------

    def __init__(self, **kwargs):
        # Auto-compute email hash for privacy-preserving lookups
        if "email" in kwargs:
            email = kwargs["email"].lower().strip()
            kwargs["email_hash"] = hashlib.sha256(email.encode()).hexdigest()
        super().__init__(**kwargs)

    def __repr__(self):
        # Never expose email or PII in repr/logs (#35)
        return f"<User id={self.id} role={self.role}>"


# ---------------------------------------------------------------------------
# Therapist profile (1:1 with User)
# ---------------------------------------------------------------------------

class Therapist(db.Model, TimestampMixin):
    __tablename__ = "therapist"

    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), primary_key=True)

    # License info — encrypted at rest (#48)
    license_number_encrypted = db.Column(db.LargeBinary, nullable=True)
    license_verified_at = db.Column(db.DateTime, nullable=True)
    is_verified = db.Column(db.Boolean, default=False, nullable=False)
    # Verification must be done by admin, not self-serve (#5, #30)

    # Professional info
    specialties = db.Column(db.String(500), nullable=True)
    bio = db.Column(db.Text, nullable=True)

    # Relationships
    availability_slots = db.relationship(
        "AvailabilitySlot",
        backref="therapist",
        lazy="dynamic",
        cascade="all, delete-orphan",
    )
    appointments = db.relationship(
        "Appointment",
        foreign_keys="Appointment.therapist_id",
        backref="therapist",
        lazy="dynamic",
    )

    @validates("bio")
    def validate_bio(self, key, bio):
        if bio and len(bio) > 2000:
            raise ValueError("Bio too long")
        return bio

    def set_license_number(self, license_num: str):
        self.license_number_encrypted = _encrypt(license_num)

    def get_license_number(self) -> Optional[str]:
        return _decrypt(self.license_number_encrypted) if self.license_number_encrypted else None


# ---------------------------------------------------------------------------
# Appointment
# ---------------------------------------------------------------------------

class Appointment(db.Model, TimestampMixin):
    __tablename__ = "appointment"

    id = db.Column(db.Integer, primary_key=True)

    # Ownership — every query must scope by one or both (#6, #33, #49)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
    therapist_id = db.Column(db.Integer, db.ForeignKey("therapist.user_id"), nullable=False, index=True)

    scheduled_for = db.Column(db.DateTime, nullable=False, index=True)
    session_type = db.Column(db.String(20), nullable=False)  # "video", "chat", "in_person"
    status = db.Column(db.String(20), default="pending", nullable=False)
    # pending → confirmed → completed / cancelled / no_show

    notes = db.Column(db.Text, nullable=True)  # User's booking notes
    therapist_notes = db.Column(db.Text, nullable=True)  # Private clinical notes

    responded_at = db.Column(db.DateTime, nullable=True)

    # Relationships
    user = db.relationship("User", foreign_keys=[user_id], backref="appointments")

    @validates("status")
    def validate_status(self, key, status):
        allowed = {"pending", "confirmed", "completed", "cancelled", "declined", "no_show"}
        if status not in allowed:
            raise ValueError(f"Invalid status: {status}")
        return status

    @validates("session_type")
    def validate_session_type(self, key, st):
        allowed = {"video", "chat", "in_person"}
        if st not in allowed:
            raise ValueError(f"Invalid session type: {st}")
        return st


# ---------------------------------------------------------------------------
# Chat
# ---------------------------------------------------------------------------

class ChatThread(db.Model, TimestampMixin):
    __tablename__ = "chat_thread"

    id = db.Column(db.Integer, primary_key=True)

    # Peer chat or therapist session
    thread_type = db.Column(db.String(20), nullable=False, default="therapist")
    # "therapist", "peer", "ai"

    # For therapist sessions: exactly 2 participants
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True, index=True)
    therapist_id = db.Column(db.Integer, db.ForeignKey("therapist.user_id"), nullable=True, index=True)

    # For peer chats: matched anonymously
    peer_listener_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)

    is_active = db.Column(db.Boolean, default=True, nullable=False)
    closed_at = db.Column(db.DateTime, nullable=True)

    # Relationships
    messages = db.relationship(
        "ChatMessage",
        backref="thread",
        lazy="dynamic",
        cascade="all, delete-orphan",
    )

    @validates("thread_type")
    def validate_thread_type(self, key, tt):
        allowed = {"therapist", "peer", "ai"}
        if tt not in allowed:
            raise ValueError(f"Invalid thread type: {tt}")
        return tt


class ChatMessage(db.Model, TimestampMixin):
    __tablename__ = "chat_message"

    id = db.Column(db.Integer, primary_key=True)

    thread_id = db.Column(db.Integer, db.ForeignKey("chat_thread.id"), nullable=False, index=True)
    sender_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)

    # Message body — never stored as HTML, always escaped on render (#19)
    body = db.Column(db.Text, nullable=False)

    # Metadata for moderation/audit
    is_flagged = db.Column(db.Boolean, default=False, nullable=False)
    flagged_reason = db.Column(db.String(200), nullable=True)

    # Edited messages keep history
    edited_at = db.Column(db.DateTime, nullable=True)
    original_body = db.Column(db.Text, nullable=True)

    @validates("body")
    def validate_body(self, key, body):
        if not body or len(body.strip()) == 0:
            raise ValueError("Message cannot be empty")
        if len(body) > 4000:
            raise ValueError("Message too long (max 4000 chars)")
        return body.strip()


# ---------------------------------------------------------------------------
# Availability (therapist schedule)
# ---------------------------------------------------------------------------

class AvailabilitySlot(db.Model, TimestampMixin):
    __tablename__ = "availability_slot"

    id = db.Column(db.Integer, primary_key=True)

    therapist_id = db.Column(db.Integer, db.ForeignKey("therapist.user_id"), nullable=False, index=True)

    day_of_week = db.Column(db.String(10), nullable=False)  # "mon", "tue", etc.
    start_time = db.Column(db.Time, nullable=False)
    end_time = db.Column(db.Time, nullable=False)

    is_recurring = db.Column(db.Boolean, default=True, nullable=False)
    specific_date = db.Column(db.Date, nullable=True)  # For one-off slots

    is_blocked = db.Column(db.Boolean, default=False, nullable=False)  # Manual override

    @validates("day_of_week")
    def validate_day(self, key, day):
        allowed = {"mon", "tue", "wed", "thu", "fri", "sat", "sun"}
        if day not in allowed:
            raise ValueError(f"Invalid day: {day}")
        return day


# ---------------------------------------------------------------------------
# Clinical notes (therapist-only, never exposed to client)
# ---------------------------------------------------------------------------

class ClientNote(db.Model, TimestampMixin):
    __tablename__ = "client_note"

    id = db.Column(db.Integer, primary_key=True)

    # Strict ownership (#6, #33, #49)
    therapist_id = db.Column(db.Integer, db.ForeignKey("therapist.user_id"), nullable=False, index=True)
    client_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)

    # Note content — encrypted at rest for clinical privacy (#48)
    body_encrypted = db.Column(db.LargeBinary, nullable=False)

    session_date = db.Column(db.Date, nullable=True)
    diagnosis_tags = db.Column(db.String(500), nullable=True)  # Comma-separated, internal use only

    # Soft delete for audit trail
    is_deleted = db.Column(db.Boolean, default=False, nullable=False)

    @validates("diagnosis_tags")
    def validate_tags(self, key, tags):
        if tags and len(tags) > 500:
            raise ValueError("Tags too long")
        return tags

    def set_body(self, body: str):
        self.body_encrypted = _encrypt(body)

    def get_body(self) -> str:
        return _decrypt(self.body_encrypted)


# ---------------------------------------------------------------------------
# Audit log (#42 — no audit logs)
# ---------------------------------------------------------------------------

class AuditLog(db.Model):
    __tablename__ = "audit_log"

    id = db.Column(db.Integer, primary_key=True)

    timestamp = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False, index=True)

    # Who did it
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True, index=True)
    ip_address = db.Column(db.String(45), nullable=True)  # IPv6 max length
    user_agent_hash = db.Column(db.String(64), nullable=True)  # SHA-256 of UA, not raw (#35)

    # What happened
    action = db.Column(db.String(50), nullable=False, index=True)
    # e.g., "login", "password_change", "appointment_booked", "note_viewed"

    # What was affected
    resource_type = db.Column(db.String(50), nullable=True)  # "appointment", "note", etc.
    resource_id = db.Column(db.Integer, nullable=True)

    # Outcome
    success = db.Column(db.Boolean, nullable=False)
    details = db.Column(db.Text, nullable=True)  # Generic description, NO PII/tokens (#35)

    @validates("action")
    def validate_action(self, key, action):
        if len(action) > 50:
            raise ValueError("Action name too long")
        return action

    @validates("details")
    def validate_details(self, key, details):
        if details and len(details) > 1000:
            raise ValueError("Details too long")
        return details


# ---------------------------------------------------------------------------
# Login manager (#4, #25 — weak session management)
# ---------------------------------------------------------------------------

@login.user_loader
def load_user(user_id: int) -> Optional[User]:
    """Load user with soft-delete check."""
    user = db.session.get(User, int(user_id))
    if user and user.is_deleted:
        return None
    return user


# ---------------------------------------------------------------------------
# Database event listeners for defense-in-depth
# ---------------------------------------------------------------------------

@event.listens_for(User, "before_insert")
@event.listens_for(User, "before_update")
def hash_email_before_commit(mapper, connection, target):
    """Ensure email_hash is always current."""
    if target.email:
        target.email_hash = hashlib.sha256(
            target.email.lower().strip().encode()
        ).hexdigest()


# ---------------------------------------------------------------------------
# Indexes for performance (prevent DoS via slow queries, #28 adjacent)
# ---------------------------------------------------------------------------

# Composite indexes for common query patterns
Index("ix_appointment_user_scheduled", Appointment.user_id, Appointment.scheduled_for)
Index("ix_appointment_therapist_scheduled", Appointment.therapist_id, Appointment.scheduled_for)
Index("ix_chat_message_thread_sent", ChatMessage.thread_id, ChatMessage.created_at)
Index("ix_audit_log_user_action", AuditLog.user_id, AuditLog.action)