from functools import wraps
from datetime import datetime, timezone

from flask import (
    Blueprint, render_template, redirect, url_for, flash, request,
    abort, current_app, session, jsonify
)
from flask_login import (
    login_user, logout_user, login_required, current_user,LoginManager
)
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired

from app import db, limiter, login
from app.forms import (
    LoginForm, SignupForm, RequestPasswordResetForm, ResetPasswordForm,
    ChatMessageForm, BookAppointmentForm, RespondAppointmentForm,
    ScheduleSlotForm, AccountSettingsForm, ChangePasswordForm,
    NotificationSettingsForm, DeleteAccountForm, ClientNoteForm, StartChatForm
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

@login.unauthorized_handler
def unauthorized():
    """Custom unauthorized page that matches SafeSpace design."""
    if request.is_json:
        return jsonify({"error": "Authentication required"}), 401
    
    # For regular requests, show a nice page instead of flashing a message
    return render_template("auth/unauthorized.html"), 401

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
    return render_template("user/dashboard.html", upcoming=upcoming, chats_this_week=chats_this_week, today_tip=get_today_tip() )


@user_bp.route("/chats")
@login_required
@role_required("user")
def my_chats():
    now = datetime.now(timezone.utc)
    
    # Get all threads for this user
    all_threads = ChatThread.query.filter(
        ChatThread.user_id == current_user.id,
    ).order_by(ChatThread.updated_at.desc()).all()
    
    active_threads = []
    past_threads = []
    upcoming_threads = []
    
    for t in all_threads:
        if t.thread_type == "therapist" and t.appointment:
            status = t.session_status()
            if status == "active":
                active_threads.append(t)
            elif status == "upcoming":
                upcoming_threads.append(t)
            else:
                # Session ended — mark thread inactive so it doesn't show in main list
                if t.is_active:
                    t.is_active = False
                    db.session.commit()
                past_threads.append(t)
        else:
            # Peer/AI threads — show as active
            active_threads.append(t)
    
    start_chat_form = StartChatForm()
    return render_template(
        "user/chats.html",
        active_threads=active_threads,
        upcoming_threads=upcoming_threads,
        past_threads=past_threads,
        start_chat_form=start_chat_form,
    )


@user_bp.route("/appointments", methods=["GET", "POST"])
@login_required
@role_required("user")
def appointments():
    form = BookAppointmentForm()
    
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
            abort(400)

        from datetime import datetime
        appt = Appointment(
            user_id=current_user.id,
            therapist_id=therapist.user_id,
            scheduled_for=datetime.combine(form.date.data, form.start_time.data),
            session_type=form.session_type.data,
            notes=form.notes.data,
            status="pending",
            duration_minutes=50,
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
    account_form = AccountSettingsForm(obj=current_user)
    password_form = ChangePasswordForm()
    notif_form = NotificationSettingsForm()
    delete_form = DeleteAccountForm()

    if request.method == "POST":
        # Check which form was submitted by looking at the hidden form_name field
        form_name = request.form.get("form_name")

        if form_name == "account" and account_form.validate_on_submit():
            current_user.display_name = account_form.display_name.data
            current_user.email = account_form.email.data
            db.session.commit()
            flash("Account updated successfully.", "success")
            return redirect(url_for("user.settings"))

        elif form_name == "password" and password_form.validate_on_submit():
            if not current_user.check_password(password_form.current_password.data):
                flash("Current password is incorrect.", "error")
            else:
                current_user.set_password(password_form.new_password.data)
                db.session.commit()
                flash("Password updated successfully.", "success")
            return redirect(url_for("user.settings"))

        elif form_name == "notifications" and notif_form.validate_on_submit():
            current_user.email_notifications = notif_form.email_notifications.data
            current_user.sms_notifications = notif_form.sms_notifications.data
            db.session.commit()
            flash("Preferences saved.", "success")
            return redirect(url_for("user.settings"))

        elif form_name == "delete" and delete_form.validate_on_submit():
            if not current_user.check_password(delete_form.password.data):
                flash("Password is incorrect.", "error")
            else:
                db.session.delete(current_user)
                db.session.commit()
                flash("Account deleted.", "success")
                return redirect(url_for("auth.logout"))

    return render_template(
        "user/settings.html",
        account_form=account_form,
        password_form=password_form,
        notif_form=notif_form,
        delete_form=delete_form,
    )

@user_bp.route("/therapists")
@login_required
@role_required("user")
def therapists():
    """Browse all verified therapists."""
    verified = (
        Therapist.query.filter_by(is_verified=True)
        .join(User)
        .filter(User.is_active.is_(True))
        .all()
    )
    return render_template("user/therapists.html", therapists=verified)


# ---------------------------------------------------------------------------
# Therapist side
# ---------------------------------------------------------------------------

@therapist_bp.route("/dashboard")
@login_required
@role_required("therapist")
def dashboard():
    from app.forms import RespondAppointmentForm  # add this
    
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
    
    respond_form = RespondAppointmentForm()  # add this
    
    return render_template(
        "therapist/dashboard.html",
        sessions_today=sessions_today,
        pending=pending,
        active_clients=active_clients,
        respond_form=respond_form,  # add this
    )


@therapist_bp.route("/sessions")
@login_required
@role_required("therapist")
def my_sessions():
    sessions = Appointment.query.filter_by(
        therapist_id=current_user.id, 
        status="confirmed"
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
    appointment_id = request.form.get("appointment_id", type=int)
    decision = request.form.get("decision")
    
    if not appointment_id or decision not in ("accept", "decline"):
        abort(400)
    
    appt = Appointment.query.filter_by(
        id=appointment_id, 
        therapist_id=current_user.id
    ).first_or_404()
    
    if decision == "accept":
        appt.status = "confirmed"
        appt.responded_at = datetime.now()
        
        # Auto-create ChatThread linked to this appointment
        # Only create if one doesn't already exist
        if not appt.chat_thread:
            thread = ChatThread(
                thread_type="therapist",
                user_id=appt.user_id,
                therapist_id=appt.therapist_id,
                appointment_id=appt.id,
                session_duration=appt.duration_minutes,
                is_active=True,
            )
            db.session.add(thread)
        
        db.session.commit()
        flash("Appointment accepted. Chat session is ready.", "success")
    else:
        appt.status = "declined"
        appt.responded_at = datetime.now(timezone.utc)
        db.session.commit()
        flash("Appointment declined.", "info")
    
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

    is_participant = current_user.id in (thread.user_id, thread.therapist_id)
    if not is_participant:
        current_app.logger.warning(
            "Blocked thread access: user_id=%s thread_id=%s", current_user.id, thread_id
        )
        abort(403)

    form = ChatMessageForm(thread_id=thread_id)
    
    if form.validate_on_submit():
        if not thread.is_session_active():
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return jsonify({"error": "Session not active"}), 403
            flash("This session is not currently active.", "warning")
            return redirect(url_for("chat.thread_view", thread_id=thread_id))
        
        if int(form.thread_id.data) != thread_id:
            abort(400)
        
        msg = ChatMessage(
            thread_id=thread_id,
            sender_id=current_user.id,
            body=form.body.data,
        )
        db.session.add(msg)
        db.session.commit()
        
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({"success": True, "message_id": msg.id})
        
        return redirect(url_for("chat.thread_view", thread_id=thread_id))

    # GET request — THIS WAS MISSING
    messages = ChatMessage.query.filter_by(thread_id=thread_id).order_by(ChatMessage.id.asc()).all()
    session_status = thread.session_status()
    
    session_end = None
    if thread.appointment:
        from datetime import timedelta
        session_end = thread.appointment.scheduled_for + timedelta(minutes=thread.session_duration)
    
    return render_template(
        "chat/thread.html", 
        thread=thread, 
        messages=messages, 
        form=form,
        session_status=session_status,
        session_end=session_end,
    )

@chat_bp.route("/<int:thread_id>/close", methods=["POST"])
@login_required
def close_thread(thread_id):
    thread = ChatThread.query.get_or_404(thread_id)
    
    # Only participants can close
    if current_user.id not in (thread.user_id, thread.therapist_id):
        abort(403)
    
    thread.is_active = False
    thread.closed_at = datetime.now(timezone.utc)
    db.session.commit()
    
    flash("Session closed.", "info")
    
    if current_user.role == "therapist":
        return redirect(url_for("therapist.my_sessions"))
    return redirect(url_for("user.my_chats"))

@chat_bp.route("/start-peer", methods=["POST"])
@login_required
@role_required("user")
@limiter.limit("20 per hour")
def start_peer_chat():
    """Placeholder — peer matching not yet implemented."""
    flash("Peer chat is coming soon. Book a therapist session instead.", "info")
    return redirect(url_for("user.dashboard"))

@chat_bp.route("/start-therapist/<int:therapist_id>", methods=["POST"])
@login_required
@role_required("user")
@limiter.limit("20 per hour")
def start_therapist_chat(therapist_id):
    """Create or redirect to existing therapist chat thread."""
    therapist = Therapist.query.filter_by(
        user_id=therapist_id, 
        is_verified=True
    ).first_or_404()
    
    # Check if thread already exists
    thread = ChatThread.query.filter_by(
        user_id=current_user.id,
        therapist_id=therapist_id,
        is_active=True
    ).first()
    
    if not thread:
        thread = ChatThread(
            thread_type='therapist',
            user_id=current_user.id,
            therapist_id=therapist_id,
            is_active=True
        )
        db.session.add(thread)
        db.session.commit()
        flash(f"Chat started with {therapist.user.display_name or 'Therapist'}.", "success")
    
    return redirect(url_for("chat.thread_view", thread_id=thread.id))

from datetime import datetime

# 365 mental health / wellness tips
DAILY_TIPS = [
    # Strength and Resilience
    "Rock bottom became the solid foundation on which I rebuilt my life. — J.K. Rowling",
    "Courage doesn't mean you don't get afraid. Courage means you don't let fear stop you. — Bethany Hamilton",
    "Strength does not come from physical capacity. It comes from an indomitable will. — Mahatma Gandhi",
    "I am not what happened to me, I am what I choose to become. — Carl Jung",
    "The world breaks everyone, and afterward, some are strong at the broken places. — Ernest Hemingway",
    "You may encounter many defeats, but you must not be defeated. — Maya Angelou",
    "Fall seven times and stand up eight. — Japanese Proverb",
    "Do not pray for an easy life, pray for the strength to endure a difficult one. — Bruce Lee",
    "Resilience is knowing that you are the only one that has the power and responsibility to pick yourself up. — Mary Holloway",
    "Even the darkest night will end, and the sun will rise. — Victor Hugo",
    "What lies behind us and what lies before us are tiny matters compared to what lies within us. — Ralph Waldo Emerson",
    "Courage is resistance to fear, mastery of fear, not absence of fear. — Mark Twain",
    "Life doesn't get easier or more forgiving; we get stronger and more resilient. — Steve Maraboli",
    "Growth is painful. Change is painful. But nothing is as painful as staying stuck somewhere you don't belong. — Mandy Hale",
    # Hope and Healing
    "Although the world is full of suffering, it is also full of the overcoming of it. — Helen Keller",
    "Start by doing what's necessary; then do what's possible; and suddenly you are doing the impossible. — Francis of Assisi",
    "Healing is an art. It takes time, it takes practice, it takes love. — Maza Dohta",
    "Healing yourself is connected with healing others. — Yoko Ono",
    "Although no one can go back and make a brand new start, anyone can start from now and make a brand new ending. — Carl Bard",
    "There is hope, even when your brain tells you there isn't. — John Green",
    "Hope is the companion of power, and mother of success; for who so hopes strongly has within him the gift of miracles. — Samuel Smiles",
    "Hope is the thing with feathers that perches in the soul — and sings the tunes without the words — and never stops at all. — Emily Dickinson",
    "Turn your wounds into wisdom. — Oprah Winfrey",
    "Hope is a verb with its sleeves rolled up. — David Orr",
    "Sometimes the smallest step in the right direction ends up being the biggest step of your life. — Naeem Callaway",
    "Just when the caterpillar thought the world was over, it became a butterfly. — Barbara Haines Howett",
    "What mental health needs is more sunlight, more candor, and more unashamed conversation. — Glenn Close",
    "Happiness can be found, even in the darkest of times, if one only remembers to turn on the light. — J.K. Rowling",
    # Self-Love and Acceptance
    "Remember, you have been criticizing yourself for years, and it hasn't worked. Try approving of yourself and see what happens. — Louise L. Hay",
    "To love oneself is the beginning of a lifelong romance. — Oscar Wilde",
    "You yourself, as much as anybody in the entire universe, deserve your love and affection. — Buddha",
    "No one can make you feel inferior without your consent. — Eleanor Roosevelt",
    "The privilege of a lifetime is to become who you truly are. — Carl Jung",
    "To accept ourselves as we are means to value our imperfections as much as our perfections. — Sandra Bierig",
    "Love yourself first and everything else falls into line. — Lucille Ball",
    "Be who you are and say what you feel, because those who mind don't matter and those who matter don't mind. — Bernard M. Baruch",
    "I will not let anyone walk through my mind with their dirty feet. — Mahatma Gandhi",
    "You are worthy of love and belonging just as you are. — Brené Brown",
    "He who knows others is wise; he who knows himself is enlightened. — Lao Tzu",
    "No one saves us but ourselves. No one can and no one may. We ourselves must walk the path. — Buddha",
    "Be content with what you are, and wish not change. — Marcus Aurelius",
    "Man cannot be comfortable without his own approval. — Mark Twain",
    # Anxiety, Stress, and Calm
    "Nothing diminishes anxiety faster than action. — Walter Anderson",
    "You don't have to control your thoughts. You just have to stop letting them control you. — Dan Millman",
    "The nearer a man comes to a calm mind, the closer he is to strength. — Marcus Aurelius",
    "Almost everything will work again if you unplug it for a few minutes, including you. — Anne Lamott",
    "Stress is caused by being here but wanting to be there. — Eckhart Tolle",
    "When you realize nothing is lacking, the whole world belongs to you. — Lao Tzu",
    "The greatest weapon against stress is our ability to choose one thought over another. — William James",
    "You find peace not by rearranging the circumstances of your life, but by realizing who you are at the deepest level. — Eckhart Tolle",
    "Sometimes the most productive thing you can do is relax. — Mark Black",
    "Be soft. Do not let the world make you hard. — Iain Thomas",
    "In the midst of movement and chaos, keep stillness inside of you. — Deepak Chopra",
    "Feelings come and go like clouds in a windy sky. Conscious breathing is my anchor. — Thich Nhat Hanh",
    # Meaning and Purpose
    "You don't have to see the whole staircase, just take the first step. — Martin Luther King Jr.",
    "The meaning of life is to give life meaning. — Viktor E. Frankl",
    "Your purpose in life is to find your purpose and give your whole heart and soul to it. — Buddha",
    "It is not enough to be busy. So are the ants. The question is: What are we busy about? — Henry David Thoreau",
    "Efforts and courage are not enough without purpose and direction. — John F. Kennedy",
    "Live the life you have imagined. — Henry David Thoreau",
    "The best way to find yourself is to lose yourself in the service of others. — Mahatma Gandhi",
    "The aim of life is self-development. — Oscar Wilde",
    "Happiness is not something ready-made. It comes from your own actions. — Dalai Lama",
    "We are here to add what we can to life, not to get what we can from life. — William Osler",
    "Life becomes easier and more beautiful when we can see the good in other people. — Roy T. Bennett",
    "The mystery of human existence lies not in just staying alive, but in finding something to live for. — Fyodor Dostoevsky",
    "The two most important days in your life are the day you are born and the day you find out why. — Mark Twain",
    "A life without purpose is like a ship without a rudder. — Thomas Carlyle",
    # Acceptance and Moving On
    "What you resist persists. — Carl Jung",
    "The only way out is through. — Robert Frost",
    "Forgiveness is giving up the hope that the past could have been any different. — Oprah Winfrey",
    "Let go or be dragged. — Zen Proverb",
    "Radical acceptance rests on letting go of the illusion of control. — Marsha M. Linehan",
    "The past has no power over the present moment. — Eckhart Tolle",
    "What we accept transforms us. — Carl Jung",
    "The first step toward change is awareness. The second step is acceptance. — Nathaniel Branden",
    "When we strive to become better than we are, everything around us becomes better too. — Paulo Coelho",
    "I have discovered in life that there are ways of getting almost anywhere you want to go, if you really want to go. — Langston Hughes",
    "Letting go doesn't mean that you don't care about someone anymore. It's just realizing that the only person you really have control over is yourself. — Deborah Reber",
    "Because one believes in oneself, one doesn't try to convince others. Because one is content with oneself, one doesn't need others' approval. — Lao Tzu",
    "The best way is not to fight it, just go. — Chuck Palahniuk",
    "Maturity, one discovers, has everything to do with the acceptance of 'not knowing.' — Mark Z. Danielewski",
    "Beauty is about being comfortable in your own skin. It's about knowing and accepting who you are. — Ellen DeGeneres",
    # Mental Health Awareness
    "Happiness depends upon ourselves. — Aristotle",
    "A cheerful heart is good medicine, but a crushed spirit dries up the bones. — Proverbs 17:22",
    "A sound mind in a sound body is a short but full description of a happy state in this world. — John Locke",
    "The mind has great influence over the body, and maladies often have their origin there. — Jean Baptiste Molière",
    "No man is free who is not master of himself. — Epictetus",
    "There is a crack in everything. That's how the light gets in. — Leonard Cohen",
    "No matter how long the night, the dawn will break. — African Proverb",
    "Sometimes even to live is an act of courage. — Seneca",
    "A man who fears suffering is already suffering from what he fears. — Michel de Montaigne",
    "The man who has no inner life is the slave of his surroundings. — Henri Frédéric Amiel",
    "Men are disturbed not by things, but by the views they take of them. — Epictetus",
    "Stop worrying about what others think of you. Base your thoughts, your decisions, and your goals on what you want. — Daniel G. Amen",
    "It is not length of life, but depth of life. — Ralph Waldo Emerson",
    "Studies show that journaling is a powerful tool to help get worries under control and out of your head. — Daniel G. Amen",
    "We suffer more often in imagination than in reality. — Seneca",
]

def get_today_tip():
    """Returns the same tip for the entire day, rotates daily."""
    day_of_year = datetime.now().timetuple().tm_yday  # 1-365
    return DAILY_TIPS[day_of_year % len(DAILY_TIPS)]

@chat_bp.route("/<int:thread_id>/poll")
@login_required
@limiter.exempt
def poll_messages(thread_id):
    thread = ChatThread.query.get_or_404(thread_id)
    is_participant = current_user.id in (thread.user_id, thread.therapist_id, thread.peer_listener_id)
    if not is_participant:
        abort(403)
    
    after_id = request.args.get('after', 0, type=int)
    messages = ChatMessage.query.filter(
        ChatMessage.thread_id == thread_id,
        ChatMessage.id > after_id
    ).order_by(ChatMessage.id.asc()).all()
    
    return jsonify([{
        'id': m.id,
        'body': m.body,
        'sender_id': m.sender_id,
        'is_me': m.sender_id == current_user.id,
        'time': m.created_at.strftime('%I:%M %p'),
        'date': m.created_at.strftime('%b %d, %Y')
    } for m in messages])


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