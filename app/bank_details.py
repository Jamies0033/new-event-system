import hashlib
import io
import hmac
import os
import re
from datetime import datetime, timezone

from cryptography.fernet import Fernet
import qrcode
from flask import (Blueprint, flash, redirect, render_template, request, url_for, make_response, current_app, send_file)
from flask_login import login_required
from sqlalchemy import select, func, delete
from sqlalchemy.exc import IntegrityError

from app.permissions import permission_required

from app.models import (
    Participant,
    ParticipantAccountDetails,
    ParticipantSubmissionCredential,
    BankSubmissionAttempt,
    db,
)

bank_details_bp = Blueprint("bank_details", __name__)


@bank_details_bp.route("/account-details", methods=["GET", "POST"])
def submit_account_details():
    if request.method == "POST":
        participant_code = request.form.get("participant_code", "").strip().upper()
        submission_code = request.form.get("submission_code", "").strip().upper()
        bank_name = request.form.get("bank_name", "").strip()
        account_name = request.form.get("account_name", "").strip()
        account_number = request.form.get("account_number", "").strip()

        now = int(datetime.now(timezone.utc).timestamp())
        secret = current_app.config["SECRET_KEY"]
        ip_address = request.remote_addr or "unknown"

        def make_attempt_key(identity):
            return hmac.new(
                secret.encode(),
                identity.encode(),
                hashlib.sha256,
            ).hexdigest()

        attempt_key = make_attempt_key(
            f"participant:{ip_address}:{participant_code}"
        )
        ip_attempt_key = make_attempt_key(f"ip:{ip_address}")

        recent_attempts = db.session.scalar(
            select(func.count(BankSubmissionAttempt.id)).where(
                BankSubmissionAttempt.attempt_key == attempt_key,
                BankSubmissionAttempt.attempted_at >= now - 900,
            )
        ) or 0

        ip_recent_attempts = db.session.scalar(
            select(func.count(BankSubmissionAttempt.id)).where(
                BankSubmissionAttempt.attempt_key == ip_attempt_key,
                BankSubmissionAttempt.attempted_at >= now - 900,
            )
        ) or 0

        if recent_attempts >= 5 or ip_recent_attempts >= 20:
            flash(
                "Too many unsuccessful attempts. Please wait 15 minutes "
                "or contact event staff.",
                "error",
            )
            return render_template("account_details.html"), 429
        participant = db.session.scalar(
            select(Participant).where(
                Participant.participant_code == participant_code,
                Participant.is_active.is_(True),
            )
        )

        credential = None
        if participant:
            credential = db.session.scalar(
                select(ParticipantSubmissionCredential).where(
                    ParticipantSubmissionCredential.participant_id == participant.id,
                    ParticipantSubmissionCredential.is_active.is_(True),
                )
            )

        submitted_hash = hashlib.sha256(
            submission_code.encode()
        ).hexdigest()

        valid_code = (
            credential is not None
            and hmac.compare_digest(credential.code_hash, submitted_hash)
        )

        if not valid_code:
            db.session.add_all([
                BankSubmissionAttempt(
                    attempt_key=attempt_key,
                    attempted_at=now,
                ),
                BankSubmissionAttempt(
                    attempt_key=ip_attempt_key,
                    attempted_at=now,
                ),
            ])
            db.session.commit()

            flash(
                "We could not verify your details. Check your Participant ID "
                "and private code, or contact event staff.",
                "error",
            )
            return render_template("account_details.html"), 400
        db.session.execute(
            delete(BankSubmissionAttempt).where(
                BankSubmissionAttempt.attempt_key == attempt_key
            )
        )
        db.session.commit()

        if not bank_name or len(bank_name) > 120:
            flash("Enter a valid bank name.", "error")
            return render_template("account_details.html"), 400

        if not account_name or len(account_name) > 160:
            flash("Enter a valid account name.", "error")
            return render_template("account_details.html"), 400

        if not re.fullmatch(r"[0-9]{6,20}", account_number):
            flash("Enter an account number containing 6 to 20 digits.", "error")
            return render_template("account_details.html"), 400

        encryption_key = os.environ.get("BANK_ENCRYPTION_KEY")
        if not encryption_key:
            raise RuntimeError("Bank encryption key is not configured.")

        if db.session.scalar(
            select(ParticipantAccountDetails.id).where(
                ParticipantAccountDetails.participant_id == participant.id
            )
        ):
            flash(
                "Account details have already been submitted. Contact event "
                "staff if a correction is required.",
                "error",
            )
            return render_template("account_details.html"), 409

        encrypted_number = Fernet(encryption_key.encode()).encrypt(
            account_number.encode()
        ).decode()

        details = ParticipantAccountDetails(
            participant_id=participant.id,
            bank_name=bank_name,
            account_name=account_name,
            account_number_encrypted=encrypted_number,
        )

        try:
            db.session.add(details)
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
            flash(
                "Account details have already been submitted. Contact event "
                "staff if a correction is required.",
                "error",
            )
            return render_template("account_details.html"), 409

        flash(
            "Your account details have been submitted successfully.",
            "success",
        )
        return redirect(url_for("bank_details.submit_account_details"))

    return render_template("account_details.html")




@bank_details_bp.route("/admin/account-details")
@login_required
@permission_required("view_account_details")
def view_submitted_account_details():
    encryption_key = os.environ.get("BANK_ENCRYPTION_KEY")
    if not encryption_key:
        raise RuntimeError("Bank encryption key is not configured.")

    cipher = Fernet(encryption_key.encode())

    records = db.session.execute(
        select(ParticipantAccountDetails, Participant)
        .join(Participant, Participant.id == ParticipantAccountDetails.participant_id)
        .order_by(ParticipantAccountDetails.created_at.desc())
    ).all()

    submissions = []
    for details, participant in records:
        submissions.append({
            "participant_code": participant.participant_code,
            "full_name": participant.full_name,
            "bank_name": details.bank_name,
            "account_name": details.account_name,
            "account_number": cipher.decrypt(
                details.account_number_encrypted.encode()
            ).decode(),
            "submitted_at": details.created_at,
        })

    response = make_response(
        render_template("account_details_list.html", submissions=submissions)
    )
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, private"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    return response


@bank_details_bp.route("/admin/account-details/general-qr.png")
@login_required
@permission_required("view_account_details")
def general_account_details_qr():
    public_url = os.environ.get(
        "PUBLIC_BASE_URL",
        "https://new-event-system.onrender.com",
    ).rstrip("/")

    form_url = f"{public_url}/account-details"

    qr = qrcode.QRCode(
        version=None,
        error_correction=qrcode.constants.ERROR_CORRECT_H,
        box_size=12,
        border=4,
    )
    qr.add_data(form_url)
    qr.make(fit=True)

    image = qr.make_image(fill_color="#102D46", back_color="white")

    image_buffer = io.BytesIO()
    image.save(image_buffer, format="PNG")
    image_buffer.seek(0)

    response = send_file(
        image_buffer,
        mimetype="image/png",
        download_name="event-bank-details-qr.png",
        as_attachment=request.args.get("download") == "1",
    )
    response.headers["Cache-Control"] = "no-store"
    return response
