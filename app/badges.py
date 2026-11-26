import io
import os

from cryptography.fernet import Fernet

import qrcode
from flask import Blueprint, abort, render_template, send_file
from flask_login import current_user, login_required
from sqlalchemy import select

from app.models import Participant, ParticipantSubmissionCredential, db
from app.event_config import EVENT

badges_bp = Blueprint("badges", __name__, url_prefix="/badges")


@badges_bp.get("/")
@login_required
def badge_list():
    if current_user.role != "admin":
        abort(403)

    participants = db.session.scalars(
        select(Participant)
        .where(Participant.is_active.is_(True))
        .order_by(Participant.full_name.asc())
    ).all()

    participant_ids = [participant.id for participant in participants]

    credentials = db.session.scalars(
        select(ParticipantSubmissionCredential).where(
            ParticipantSubmissionCredential.participant_id.in_(participant_ids)
        )
    ).all() if participant_ids else []

    encryption_key = os.environ.get("BANK_ENCRYPTION_KEY")
    submission_codes = {}

    if credentials:
        if not encryption_key:
            raise RuntimeError("Bank encryption key is not configured.")

        cipher = Fernet(encryption_key.encode())

        for credential in credentials:
            if credential.is_active:
                submission_codes[credential.participant_id] = (
                    cipher.decrypt(
                        credential.code_encrypted.encode()
                    ).decode()
                )

    return render_template(
        "badges.html",
        participants=participants,
        event=EVENT,
        submission_codes=submission_codes,
    )


@badges_bp.get("/<int:participant_id>/qr.png")
@login_required
def participant_qr(participant_id):
    if current_user.role != "admin":
        abort(403)

    participant = db.session.get(Participant, participant_id)

    if participant is None or not participant.is_active:
        abort(404)

    qr = qrcode.QRCode(
        version=None,
        error_correction=qrcode.constants.ERROR_CORRECT_H,
        box_size=10,
        border=4,
    )
    qr.add_data(participant.ticket_token)
    qr.make(fit=True)

    image = qr.make_image(fill_color="#102D46", back_color="white")

    image_buffer = io.BytesIO()
    image.save(image_buffer, format="PNG")
    image_buffer.seek(0)

    response = send_file(
        image_buffer,
        mimetype="image/png",
        download_name=f"{participant.participant_code}.png",
    )
    response.headers["Cache-Control"] = "no-store"
    return response
