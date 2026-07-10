from app import app, db
from app.models import (
    User, Therapist, Appointment, ChatThread, ChatMessage,
    ClientNote, AvailabilitySlot, AuditLog
)

@app.shell_context_processor
def make_shell_context():
    return {
        'db': db,
        'User': User,
        'Therapist': Therapist,
        'Appointment': Appointment,
        'ChatThread': ChatThread,
        'ChatMessage': ChatMessage,
        'ClientNote': ClientNote,
        'AvailabilitySlot': AvailabilitySlot,
        'AuditLog': AuditLog,
    }