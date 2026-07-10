from flask_wtf import FlaskForm
from wtforms import (
    StringField,
    PasswordField,
    SelectField,
    TextAreaField,
    DateField,
    TimeField,
    HiddenField,
    BooleanField,
    SubmitField,
)
from wtforms.validators import (
    DataRequired,
    Email,
    EqualTo,
    Length,
    Regexp,
    ValidationError,
    Optional,
)
import re


# ---------------------------------------------------------------------------
# Shared validators
# ---------------------------------------------------------------------------

PASSWORD_POLICY = Regexp(
    r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^A-Za-z0-9]).{10,}$",
    message=(
        "Password must be at least 10 characters and include an uppercase "
        "letter, a lowercase letter, a number, and a symbol."
    ),
)


def no_html_tags(form, field):
    """Reject obvious markup to reduce stored-XSS surface area at the form
    layer (vuln #19). This is a defense-in-depth check only — the real
    protection is output escaping (Jinja autoescape) and sanitizing/escaping
    on render, never trust this alone."""
    if re.search(r"<[^>]+>", field.data or ""):
        raise ValidationError("HTML tags are not allowed in this field.")


# ---------------------------------------------------------------------------
# Auth — login / signup live on the same page (separate forms, one template)
# ---------------------------------------------------------------------------

class LoginForm(FlaskForm):
    email = StringField(
        "Email",
        validators=[DataRequired(), Email(), Length(max=254)],
    )
    password = PasswordField(
        "Password",
        validators=[DataRequired(), Length(min=1, max=128)],
        # NOTE: we deliberately do NOT enforce the full password policy on
        # login — only on signup/reset. Otherwise we'd be telling an
        # attacker which accounts pre-date a policy change.
    )
    remember_me = BooleanField("Remember me")
    submit = SubmitField("Log in")

    # We do NOT include a "role" field on login. Role is looked up
    # server-side from the authenticated user record (vuln #5, #34) —
    # never trust a client-submitted role.


class SignupForm(FlaskForm):
    email = StringField(
        "Email",
        validators=[DataRequired(), Email(), Length(max=254)],
    )
    password = PasswordField(
        "Password",
        validators=[DataRequired(), PASSWORD_POLICY],
    )
    confirm_password = PasswordField(
        "Confirm password",
        validators=[DataRequired(), EqualTo("password", message="Passwords must match.")],
    )
    # "Signing up as" — User (anonymous) or Therapist, per the mockup.
    account_type = SelectField(
        "Signing up as",
        choices=[("user", "User (anonymous)"), ("therapist", "Therapist")],
        validators=[DataRequired()],
    )
    # Display name is optional for anonymous users, required for therapists
    # (enforced in validate_display_name below) — therapists are shown by
    # name/credentials (e.g. "Dr. Santos, RPsy") in the UI, users are not.
    display_name = StringField(
        "Display name",
        validators=[Optional(), Length(max=80), no_html_tags],
    )
    license_number = StringField(
        "License / registration number",
        validators=[Optional(), Length(max=64)],
    )
    submit = SubmitField("Create account")

    def validate_display_name(self, field):
        if self.account_type.data == "therapist" and not field.data:
            raise ValidationError("Therapists must provide a display name shown to clients.")

    def validate_license_number(self, field):
        if self.account_type.data == "therapist" and not field.data:
            raise ValidationError("A license/registration number is required for therapist accounts.")
        # Therapist accounts should never be auto-approved purely from a
        # self-reported license number — routes.py marks new therapist
        # accounts as "pending verification" until an admin confirms this
        # out of band. Don't trust client input as proof of credentials.


class RequestPasswordResetForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Email(), Length(max=254)])
    submit = SubmitField("Send reset link")

    # Intentionally has NO "user not found" distinguishing behavior at the
    # route level (vuln #24) — the route always returns the same generic
    # message ("if that email exists, we sent a link") so the form can't be
    # used to enumerate registered emails.


class ResetPasswordForm(FlaskForm):
    # The reset token itself travels in the URL (single-use, short-lived,
    # signed with itsdangerous — see routes.py), not as a hidden form field
    # the client could tamper with for a different account.
    password = PasswordField("New password", validators=[DataRequired(), PASSWORD_POLICY])
    confirm_password = PasswordField(
        "Confirm new password",
        validators=[DataRequired(), EqualTo("password", message="Passwords must match.")],
    )
    submit = SubmitField("Reset password")


# ---------------------------------------------------------------------------
# Chat (peer chat for users, session chat for therapist <-> user)
# ---------------------------------------------------------------------------

class ChatMessageForm(FlaskForm):
    # Plain text only. Rendered with Jinja autoescaping client-side — never
    # rendered with |safe (vuln #19). Length-capped to avoid abuse/DoS via
    # giant payloads.
    body = TextAreaField(
        "Message",
        validators=[DataRequired(), Length(min=1, max=4000)],
    )
    # The conversation/thread id is taken from the authenticated session's
    # current room, NOT trusted from a hidden field alone — routes.py
    # re-validates that the current_user is actually a participant in this
    # thread before allowing a write (vuln #6, #33, #34, #49).
    thread_id = HiddenField("Thread", validators=[DataRequired()])
    submit = SubmitField("Send")

class StartChatForm(FlaskForm):
    submit = SubmitField("Start Chat")


# ---------------------------------------------------------------------------
# Appointments / Schedule
# ---------------------------------------------------------------------------

from wtforms import TimeField, DateField, SelectField, TextAreaField, SubmitField
from wtforms.validators import DataRequired, ValidationError
from datetime import time

class BookAppointmentForm(FlaskForm):
    therapist_id = SelectField("Therapist", coerce=int, validators=[DataRequired()])
    date = DateField("Date", validators=[DataRequired()])
    start_time = TimeField("Start Time", validators=[DataRequired()])
    session_type = SelectField("Session Type", choices=[
        ("chat", "Chat"),
        ("video", "Video"),
        ("in_person", "In Person"),
    ], validators=[DataRequired()])
    notes = TextAreaField("Notes (optional)", validators=[Length(max=500)])
    submit = SubmitField("Book Appointment")
    
    def validate_start_time(self, field):
        pass  # temporarily disable all validation


class RespondAppointmentForm(FlaskForm):
    """Minimal form for CSRF token only."""
    pass


class ScheduleSlotForm(FlaskForm):
    """Therapist defining/editing their availability."""
    day_of_week = SelectField(
        "Day",
        choices=[
            ("mon", "Monday"), ("tue", "Tuesday"), ("wed", "Wednesday"),
            ("thu", "Thursday"), ("fri", "Friday"), ("sat", "Saturday"),
            ("sun", "Sunday"),
        ],
        validators=[DataRequired()],
    )
    start_time = TimeField("Start", validators=[DataRequired()])
    end_time = TimeField("End", validators=[DataRequired()])
    submit = SubmitField("Save availability")

    def validate_end_time(self, field):
        if self.start_time.data and field.data <= self.start_time.data:
            raise ValidationError("End time must be after start time.")


# ---------------------------------------------------------------------------
# Settings (shared shape, used by both roles; routes.py decides which
# extra fields to render/process based on current_user.role — never a
# client-submitted role)
# ---------------------------------------------------------------------------
class AccountSettingsForm(FlaskForm):
    display_name = StringField(
        "Display name",
        validators=[Optional(), Length(max=80), no_html_tags],
    )
    email = StringField("Email", validators=[DataRequired(), Email(), Length(max=254)])
    form_name = HiddenField(default="account")
    submit = SubmitField("Save changes")


class ChangePasswordForm(FlaskForm):
    current_password = PasswordField("Current password", validators=[DataRequired()])
    new_password = PasswordField("New password", validators=[DataRequired(), PASSWORD_POLICY])
    confirm_new_password = PasswordField(
        "Confirm new password",
        validators=[DataRequired(), EqualTo("new_password", message="Passwords must match.")],
    )
    form_name = HiddenField(default="password")
    submit = SubmitField("Update password")


class NotificationSettingsForm(FlaskForm):
    email_notifications = BooleanField("Email me about new messages and appointments")
    sms_notifications = BooleanField("Text me reminders")
    form_name = HiddenField(default="notifications")
    submit = SubmitField("Save preferences")


class DeleteAccountForm(FlaskForm):
    password = PasswordField("Confirm your password", validators=[DataRequired()])
    confirm = StringField(
        'Type "DELETE" to confirm',
        validators=[DataRequired(), Regexp(r"^DELETE$", message='Please type DELETE exactly.')],
    )
    form_name = HiddenField(default="delete")
    submit = SubmitField("Permanently delete account")


# ---------------------------------------------------------------------------
# Therapist — "My clients" notes
# ---------------------------------------------------------------------------

class ClientNoteForm(FlaskForm):
    """Private clinical note a therapist attaches to a client. Never shown
    to the client (routes.py enforces this on the read side too)."""
    client_id = HiddenField(validators=[DataRequired()])
    note = TextAreaField("Session note", validators=[DataRequired(), Length(max=5000)])
    submit = SubmitField("Save note")