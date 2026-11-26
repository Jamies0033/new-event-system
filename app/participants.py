
import secrets
from datetime import datetime
from zoneinfo import ZoneInfo

from flask import Blueprint, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required
from cryptography.fernet import Fernet
import hashlib
import os
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError

from app.permissions import permission_required, permission_any_required

from app.models import (
    Attendance,
    AttendanceSession,
    Participant,
    ParticipantSubmissionCredential,
    db,
)

EVENT_TIMEZONE = ZoneInfo("Africa/Lagos")
participants_bp = Blueprint("participants", __name__)


@participants_bp.get("/")
def home():
    if current_user.is_authenticated:
        return redirect(url_for("participants.dashboard"))

    return redirect(url_for("auth.login"))


@participants_bp.get("/dashboard")
@login_required
@permission_any_required(
    "manage_participants",
    "view_attendance",
    "scan_attendance",
    "view_account_details",
    "export_account_details",
    "export_event_workbook",
)
def dashboard():
    total = (
        db.session.scalar(
            select(func.count())
            .select_from(Participant)
            .where(Participant.is_active.is_(True))
        )
        or 0
    )

    today = datetime.now(EVENT_TIMEZONE).date()

    arrivals_today = db.session.scalar(
        select(func.count(Attendance.id))
        .join(AttendanceSession, Attendance.session_id == AttendanceSession.id)
        .where(
            AttendanceSession.session_date == today,
            AttendanceSession.checkpoint == "arrival",
        )
    ) or 0

    return render_template(
        "dashboard.html",
        total=total,
        arrivals_today=arrivals_today,
    )


@participants_bp.route("/participants/new", methods=["GET", "POST"])
@login_required
@permission_required("manage_participants")
def new_participant():
    if request.method == "POST":
        full_name = request.form.get("full_name", "").strip()
        email = request.form.get("email", "").strip() or None
        phone = request.form.get("phone", "").strip() or None

        if not full_name or len(full_name) > 160:
            flash(
                "Enter a participant name of up to 160 characters.",
                "error",
            )
            return render_template("participant_form.html"), 400

        if email and len(email) > 254:
            flash("Email must be 254 characters or fewer.", "error")
            return render_template("participant_form.html"), 400

        if phone and len(phone) > 30:
            flash("Phone number must be 30 characters or fewer.", "error")
            return render_template("participant_form.html"), 400

        participant = Participant(
            participant_code=f"TEMP-{secrets.token_hex(8)}",
            full_name=full_name,
            email=email,
            phone=phone,
        )

        try:
            alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
            submission_code = "".join(
                secrets.choice(alphabet) for _ in range(6)
            )

            encryption_key = os.environ.get("BANK_ENCRYPTION_KEY")
            if not encryption_key:
                raise RuntimeError("Bank encryption key is not configured.")

            encrypted_code = Fernet(encryption_key.encode()).encrypt(
                submission_code.encode()
            ).decode()

            code_hash = hashlib.sha256(
                submission_code.encode()
            ).hexdigest()

            db.session.add(participant)
            db.session.flush()

            participant.participant_code = f"GUEST-{participant.id:04d}"

            credential = ParticipantSubmissionCredential(
                participant_id=participant.id,
                code_hash=code_hash,
                code_encrypted=encrypted_code,
            )

            db.session.add(credential)
            db.session.commit()

        except IntegrityError:
            db.session.rollback()
            flash(
                "Registration could not be completed because of a database "
                "constraint. Please retry.",
                "error",
            )
            return render_template("participant_form.html"), 409

        flash(
            f"{participant.full_name} was registered as "
            f"{participant.participant_code}.",
            "success",
        )

        return redirect(url_for("participants.participant_list"))

    return render_template("participant_form.html")


@participants_bp.get("/participants")
@login_required
@permission_required("manage_participants")
def participant_list():
    search = request.args.get("q", "").strip()

    query = select(Participant).where(Participant.is_active.is_(True))

    if search:
        term = f"%{search}%"
        query = query.where(
            Participant.full_name.ilike(term)
            | Participant.participant_code.ilike(term)
        )

    participants = db.session.scalars(
        query.order_by(Participant.id.desc()).limit(500)
    ).all()

    return render_template(
        "participants.html",
        participants=participants,
        search=search,
    )
@participants_bp.post("/participants/<int:participant_id>/delete")
@login_required
@permission_required("manage_participants")
def delete_participant(participant_id):
    participant = db.session.get(Participant, participant_id)

    if participant is None or not participant.is_active:
        flash("Registration not found.", "error")
        return redirect(url_for("participants.participant_list"))

    if participant.attendance_records:
        flash(
            f"{participant.full_name} has attendance records and cannot "
            "be permanently deleted. Deactivate the registration instead.",
            "error",
        )
        return redirect(url_for("participants.participant_list"))

    name = participant.full_name
    participant.is_active = False
    db.session.commit()

    flash(
        f"Registration for {name} has been removed from the active directory.",
        "success",
    )
    return redirect(url_for("participants.participant_list"))
