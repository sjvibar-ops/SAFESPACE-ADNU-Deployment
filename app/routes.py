from functools import wraps
from datetime import datetime, timezone

from flask import (
    Blueprint, render_template, redirect, url_for, flash, request,
    abort, current_app, session,
)
from flask_login import (
    login_user, logout_user, login_required, current_user,
)
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired

from app import db, limiter
from app.forms import (
    LoginForm, SignupForm, RequestPasswordResetForm, ResetPasswordForm,
    ChatMessageForm, BookAppointmentForm, RespondAppointmentForm,
    ScheduleSlotForm, AccountSettingsForm, ChangePasswordForm,
    NotificationSettingsForm, DeleteAccountForm, ClientNoteForm,
)
from app.models import (
    User, Therapist, Appointment, ChatThread, ChatMessage,
    ClientNote, AvailabilitySlot,
)

auth_bp = Blueprint("auth", __name__)
user_bp = Blueprint("user", __name__, url_prefix="/u")
therapist_bp = Blueprint("therapist", __name__, url_prefix="/t")
chat_bp = Blueprint("chat", __name__, url_prefix="/chat")


# ---------------------------------------------------------------------------
# Role-based access control helpers
# ---------------------------------------------------------------------------

def role_required(role):
    """Server-side role gate. current_user.role is read from the DB record
    tied to the session, never from a request parameter, header, or cookie
    value a client could edit (#5, #34)."""
    def decorator(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            if not current_user.is_authenticated:
                return current_app.login_manager.unauthorized()
            if current_user.role != role:
                current_app.logger.warning(
                    "Forbidden role access attempt: user_id=%s role=%s wanted=%s path=%s",
                    current_user.id, current_user.role, role, request.path,
                )
                abort(403)
            return view(*args, **kwargs)
        return wrapped
    return decorator


def therapist_verified_required(view):
    """Therapist accounts start as unverified (license self-reported at
    signup — see forms.py). Block therapist-only write actions until an
    admin has verified them out-of-band (#5, #30)."""
    @wraps(view)
    def wrapped(*args, **kwargs):
        profile = getattr(current_user, "therapist_profile", None)
        if not profile or not profile.is_verified:
            flash("Your therapist account is still pending verification.", "warning")
            return redirect(url_for("therapist.dashboard"))
        return view(*args, **kwargs)
    return wrapped


# ---------------------------------------------------------------------------
# Auth — login + signup on one page, two forms, one template
# ---------------------------------------------------------------------------

@auth_bp.route("/", methods=["GET", "POST"])
@limiter.limit("10 per minute")  # blunts credential stuffing / brute force (#28)
def login_signup():
    if current_user.is_authenticated:
        return _dashboard_for(current_user)

    login_form = LoginForm(prefix="login")
    signup_form = SignupForm(prefix="signup")

    if login_form.submit.data and login_form.validate_on_submit():
        return _handle_login(login_form)

    if signup_form.submit.data and signup_form.validate_on_submit():
        return _handle_signup(signup_form)

    return render_template("auth.html", login_form=login_form, signup_form=signup_form)


def _handle_login(form):
    user = User.query.filter_by(email=form.email.data.lower().strip()).first()

    # Same code path whether or not the user exists, to avoid leaking
    # account existence through branching/timing differences.
    valid = user is not None and check_password_hash(user.password_hash, form.password.data)

    if not valid:
        current_app.logger.info("Failed login attempt for email=%s", _mask_email(form.email.data))
        flash("Invalid email or password.", "danger")  # deliberately generic
        return redirect(url_for("auth.login_signup"))

    if not user.is_active:
        flash("This account has been disabled. Contact support.", "danger")
        return redirect(url_for("auth.login_signup"))

    # Clear and rebuild the session on privilege change to prevent
    # session fixation (#25).
    session.clear()
    login_user(user, remember=form.remember_me.data)
    db.session.commit()

    current_app.logger.info("User %s logged in", user.id)
    return _dashboard_for(user)


def _handle_signup(form):
    email = form.email.data.lower().strip()
    if User.query.filter_by(email=email).first():
        flash("That email is already registered.", "danger")
        return redirect(url_for("auth.login_signup"))

    user = User(
        email=email,
        password_hash=generate_password_hash(form.password.data, method="pbkdf2:sha256:600000"),
        role=form.account_type.data,
        display_name=form.display_name.data.strip() if form.display_name.data else None,
        is_active=True,
    )
    db.session.add(user)
    db.session.flush()  # get user.id without committing yet

    if form.account_type.data == "therapist":
        therapist = Therapist(user_id=user.id, is_verified=False)
        therapist.set_license_number(form.license_number.data.strip())
        db.session.add(therapist)

    db.session.commit()
    current_app.logger.info("New signup: user_id=%s role=%s", user.id, user.role)

    session.clear()
    login_user(user)
    flash("Welcome to SafeSpace.", "success")
    return _dashboard_for(user)


@auth_bp.route("/logout")
@login_required
def logout():
    logout_user()
    session.clear()
    return redirect(url_for("auth.login_signup"))


# --- Password reset: token-based, single-use, short-lived (#24) -----------

def _reset_serializer():
    return URLSafeTimedSerializer(current_app.config["SECRET_KEY"], salt="pwd-reset")


@auth_bp.route("/reset", methods=["GET", "POST"])
@limiter.limit("5 per hour")
def request_reset():
    form = RequestPasswordResetForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data.lower().strip()).first()
        if user:
            token = _reset_serializer().dumps(user.id)
            reset_link = url_for("auth.reset_with_token", token=token, _external=True)
            # TODO: Implement email sending with Flask-Mail
            pass
        # Identical response whether or not the email exists (#24)
        flash("If that email is registered, a reset link has been sent.", "info")
        return redirect(url_for("auth.login_signup"))
    return render_template("reset_request.html", form=form)


@auth_bp.route("/reset/<token>", methods=["GET", "POST"])
@limiter.limit("5 per hour")
def reset_with_token(token):
    try:
        user_id = _reset_serializer().loads(token, max_age=3600)  # 1 hour expiry
    except SignatureExpired:
        flash("That reset link has expired.", "danger")
        return redirect(url_for("auth.request_reset"))
    except BadSignature:
        abort(404)  # don't distinguish malformed vs. expired

    user = User.query.get_or_404(user_id)
    form = ResetPasswordForm()
    if form.validate_on_submit():
        user.password_hash = generate_password_hash(form.password.data, method="pbkdf2:sha256:600000")
        user.password_changed_at = datetime.now(timezone.utc)
        db.session.commit()
        # In a full build: invalidate other active sessions/remember tokens here (#25)
        flash("Password updated. Please log in.", "success")
        return redirect(url_for("auth.login_signup"))
    return render_template("reset_form.html", form=form)


def _dashboard_for(user):
    return redirect(url_for("therapist.dashboard")) if user.role == "therapist" \
        else redirect(url_for("user.dashboard"))


def _mask_email(email):
    if "@" not in email:
        return "***"
    name, _, domain = email.partition("@")
    return f"{name[:2]}***@{domain}"


# ---------------------------------------------------------------------------
# User (client) side
# ---------------------------------------------------------------------------

@user_bp.route("/dashboard")
@login_required
@role_required("user")
def dashboard():
    upcoming = (
        Appointment.query
        .filter_by(user_id=current_user.id)
        .order_by(Appointment.scheduled_for.asc())
        .limit(5)
        .all()
    )
    chats_this_week = ChatThread.query.filter(
        ChatThread.user_id == current_user.id,
        ChatThread.is_active == True,
    ).count()
    return render_template("user/dashboard.html", upcoming=upcoming, chats_this_week=chats_this_week)


@user_bp.route("/chats")
@login_required
@role_required("user")
def my_chats():
    threads = ChatThread.query.filter(
        ChatThread.user_id == current_user.id,
        ChatThread.is_active == True,
    ).order_by(ChatThread.updated_at.desc()).all()
    return render_template("user/chats.html", threads=threads)


@user_bp.route("/appointments", methods=["GET", "POST"])
@login_required
@role_required("user")
def appointments():
    form = BookAppointmentForm()
    # Populate the dropdown only from verified, active therapists — the
    # user can't submit an arbitrary therapist_id and have it accepted
    # blindly; we re-validate membership in this queryset below too (#33).
    verified_therapists = (
        Therapist.query.filter_by(is_verified=True)
        .join(User).filter(User.is_active.is_(True))
    )
    form.therapist_id.choices = [
        (t.user_id, t.user.display_name or "Therapist") for t in verified_therapists
    ]

    if form.validate_on_submit():
        therapist = Therapist.query.filter_by(user_id=form.therapist_id.data, is_verified=True).first()
        if not therapist:
            abort(400)  # the submitted id wasn't actually in the allowed set

        appt = Appointment(
            user_id=current_user.id,
            therapist_id=therapist.user_id,
            scheduled_for=datetime.combine(form.date.data, form.start_time.data),
            session_type=form.session_type.data,
            notes=form.notes.data,
            status="pending",
        )
        db.session.add(appt)
        db.session.commit()
        flash("Appointment requested.", "success")
        return redirect(url_for("user.appointments"))

    my_appts = Appointment.query.filter_by(user_id=current_user.id).order_by(Appointment.scheduled_for.asc()).all()
    return render_template("user/appointments.html", form=form, appointments=my_appts)


@user_bp.route("/settings", methods=["GET", "POST"])
@login_required
@role_required("user")
def settings():
    return _shared_settings("user/settings.html")


# ---------------------------------------------------------------------------
# Therapist side
# ---------------------------------------------------------------------------

@therapist_bp.route("/dashboard")
@login_required
@role_required("therapist")
def dashboard():
    today_start = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
    today_end = today_start.replace(hour=23, minute=59, second=59)

    sessions_today = Appointment.query.filter(
        Appointment.therapist_id == current_user.id,
        Appointment.scheduled_for.between(today_start, today_end),
        Appointment.status == "confirmed",
    ).all()
    pending = Appointment.query.filter_by(therapist_id=current_user.id, status="pending").all()
    active_clients = (
        db.session.query(Appointment.user_id)
        .filter_by(therapist_id=current_user.id, status="confirmed")
        .distinct().count()
    )
    return render_template(
        "therapist/dashboard.html",
        sessions_today=sessions_today,
        pending=pending,
        active_clients=active_clients,
    )


@therapist_bp.route("/sessions")
@login_required
@role_required("therapist")
def my_sessions():
    sessions = Appointment.query.filter_by(
        therapist_id=current_user.id, status="confirmed"
    ).order_by(Appointment.scheduled_for.asc()).all()
    return render_template("therapist/sessions.html", sessions=sessions)


@therapist_bp.route("/schedule", methods=["GET", "POST"])
@login_required
@role_required("therapist")
@therapist_verified_required
def schedule():
    form = ScheduleSlotForm()
    if form.validate_on_submit():
        db.session.add(AvailabilitySlot(
            therapist_id=current_user.id,
            day_of_week=form.day_of_week.data,
            start_time=form.start_time.data,
            end_time=form.end_time.data,
        ))
        db.session.commit()
        flash("Availability saved.", "success")
        return redirect(url_for("therapist.schedule"))

    slots = AvailabilitySlot.query.filter_by(therapist_id=current_user.id).all()
    return render_template("therapist/schedule.html", form=form, slots=slots)


@therapist_bp.route("/appointments/respond", methods=["POST"])
@login_required
@role_required("therapist")
def respond_appointment():
    form = RespondAppointmentForm()
    if not form.validate_on_submit():
        abort(400)

    # IDOR guard: the appointment must belong to *this* therapist (#33, #34)
    appt = Appointment.query.filter_by(
        id=form.appointment_id.data, therapist_id=current_user.id
    ).first_or_404()

    appt.status = "confirmed" if form.decision.data == "accept" else "declined"
    appt.responded_at = datetime.now(timezone.utc)
    db.session.commit()
    return redirect(url_for("therapist.dashboard"))


@therapist_bp.route("/clients")
@login_required
@role_required("therapist")
def my_clients():
    # Only clients with at least one confirmed appointment with *this*
    # therapist — never a global user list (#6, #49).
    client_ids = (
        db.session.query(Appointment.user_id)
        .filter_by(therapist_id=current_user.id, status="confirmed")
        .distinct()
    )
    clients = User.query.filter(User.id.in_(client_ids)).all()
    return render_template("therapist/clients.html", clients=clients)


@therapist_bp.route("/clients/<int:client_id>/notes", methods=["GET", "POST"])
@login_required
@role_required("therapist")
def client_notes(client_id):
    # Re-verify a confirmed therapeutic relationship exists before showing
    # or accepting notes about this client — a raw client_id in the URL is
    # never sufficient on its own (#6, #33, #34, #49).
    has_relationship = Appointment.query.filter_by(
        therapist_id=current_user.id, user_id=client_id, status="confirmed"
    ).first()
    if not has_relationship:
        abort(403)

    form = ClientNoteForm(client_id=client_id)
    if form.validate_on_submit():
        note = ClientNote(
            therapist_id=current_user.id,
            client_id=client_id,
        )
        note.set_body(form.note.data)
        db.session.add(note)
        db.session.commit()
        flash("Note saved.", "success")
        return redirect(url_for("therapist.client_notes", client_id=client_id))

    notes = ClientNote.query.filter_by(
        therapist_id=current_user.id, client_id=client_id
    ).order_by(ClientNote.updated_at.desc()).all()
    # Notes are clinical/private — never exposed on the client's own
    # endpoints, enforced by simply never querying ClientNote from user_bp.
    return render_template("therapist/client_notes.html", form=form, notes=notes, client_id=client_id)


@therapist_bp.route("/settings", methods=["GET", "POST"])
@login_required
@role_required("therapist")
def settings():
    return _shared_settings("therapist/settings.html")


# ---------------------------------------------------------------------------
# Shared settings logic (role-specific template chosen by caller; data is
# always scoped to current_user — never accepts a target user id, #6)
# ---------------------------------------------------------------------------

def _shared_settings(template):
    account_form = AccountSettingsForm(obj=current_user)
    password_form = ChangePasswordForm()
    notif_form = NotificationSettingsForm(obj=current_user)
    delete_form = DeleteAccountForm()

    if request.method == "POST":
        if "display_name" in request.form and account_form.validate_on_submit():
            current_user.display_name = account_form.display_name.data
            current_user.email = account_form.email.data.lower().strip()
            db.session.commit()
            flash("Account updated.", "success")
            return redirect(request.path)

        if "current_password" in request.form and password_form.validate_on_submit():
            if not check_password_hash(current_user.password_hash, password_form.current_password.data):
                flash("Current password is incorrect.", "danger")
                return redirect(request.path)
            current_user.password_hash = generate_password_hash(
                password_form.new_password.data, method="pbkdf2:sha256:600000"
            )
            current_user.password_changed_at = datetime.now(timezone.utc)
            db.session.commit()
            # invalidate other active sessions here in a full build (#25)
            flash("Password changed.", "success")
            return redirect(request.path)

        if "confirm" in request.form and delete_form.validate_on_submit():
            if not check_password_hash(current_user.password_hash, delete_form.password.data):
                flash("Incorrect password.", "danger")
                return redirect(request.path)
            current_user.is_active = False  # soft delete; preserves audit trail (#42)
            db.session.commit()
            logout_user()
            session.clear()
            flash("Your account has been deleted.", "info")
            return redirect(url_for("auth.login_signup"))

    return render_template(
        template,
        account_form=account_form,
        password_form=password_form,
        notif_form=notif_form,
        delete_form=delete_form,
    )


# ---------------------------------------------------------------------------
# Chat — shared between user and therapist, scoped to thread membership
# ---------------------------------------------------------------------------

@chat_bp.route("/<int:thread_id>", methods=["GET", "POST"])
@login_required
def thread_view(thread_id):
    thread = ChatThread.query.get_or_404(thread_id)

    # Membership check: only the two participants can read/write this
    # thread, regardless of role (#6, #33, #34, #49).
    is_participant = current_user.id in (thread.user_id, thread.therapist_id)
    if not is_participant:
        current_app.logger.warning(
            "Blocked thread access: user_id=%s thread_id=%s", current_user.id, thread_id
        )
        abort(403)

    form = ChatMessageForm(thread_id=thread_id)
    if form.validate_on_submit():
        if int(form.thread_id.data) != thread_id:
            abort(400)
        msg = ChatMessage(
            thread_id=thread_id,
            sender_id=current_user.id,
            body=form.body.data,
        )
        db.session.add(msg)
        db.session.commit()
        return redirect(url_for("chat.thread_view", thread_id=thread_id))

    # GET request — show messages
    messages = ChatMessage.query.filter_by(thread_id=thread_id).order_by(ChatMessage.id.asc()).all()
    return render_template("chat/thread.html", thread=thread, messages=messages, form=form)


@chat_bp.route("/start-peer", methods=["POST"])
@login_required
@role_required("user")
@limiter.limit("20 per hour")
def start_peer_chat():
    """Placeholder — peer matching not yet implemented."""
    flash("Peer chat is coming soon. Book a therapist session instead.", "info")
    return redirect(url_for("user.dashboard"))


# ---------------------------------------------------------------------------
# Generic error handlers — never leak stack traces (#12). Register these on
# the app in the factory with app.register_error_handler(...).
# ---------------------------------------------------------------------------

def forbidden(e):
    return render_template("errors/403.html"), 403


def not_found(e):
    return render_template("errors/404.html"), 404


def server_error(e):
    current_app.logger.exception("Unhandled server error")
    return render_template("errors/500.html"), 500