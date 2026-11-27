import hashlib
import hmac
import io
import os
import re
from datetime import datetime, timezone

from cryptography.fernet import Fernet
import qrcode
from flask import (
    Blueprint,
    flash,
    redirect,
    render_template,
    request,
    url_for,
    make_response,
    current_app,
)
from flask_login import login_required
from sqlalchemy import select, func, delete

from app.models import (
    BankAccountSubmission,
    Participant,
    ParticipantAccountDetails,
    BankSubmissionAttempt,
    db,
)
from app.permissions import permission_required


bank_details_bp = Blueprint("bank_details", __name__)


@bank_details_bp.route("/account-details", methods=["GET", "POST"])
def submit_account_details():
    if request.method == "POST":
        now = int(datetime.now(timezone.utc).timestamp())

        secret = str(current_app.config["SECRET_KEY"]).encode()
        ip_address = request.remote_addr or "unknown"

        ip_attempt_key = hmac.new(
            secret,
            f"ip:{ip_address}".encode(),
            hashlib.sha256,
        ).hexdigest()

        recent_attempts = db.session.scalar(
            select(func.count())
            .select_from(BankSubmissionAttempt)
            .where(
                BankSubmissionAttempt.attempt_key == ip_attempt_key,
                BankSubmissionAttempt.attempted_at >= now - 900,
            )
        ) or 0

        if recent_attempts >= 20:
            flash(
                "Too many unsuccessful attempts. Please try again later.",
                "error",
            )
            return render_template("account_details.html"), 429

        def reject(message):
            db.session.add(
                BankSubmissionAttempt(
                    attempt_key=ip_attempt_key,
                    attempted_at=now,
                )
            )
            db.session.commit()
            flash(message, "error")
            return render_template("account_details.html"), 400

        full_name = request.form.get("full_name", "").strip()
        state = request.form.get("state", "").strip()
        organization = request.form.get("organization", "").strip()
        bank_name = request.form.get("bank_name", "").strip()
        account_name = request.form.get("account_name", "").strip()
        account_number = request.form.get("account_number", "").strip()

        if not full_name or len(full_name) > 160:
            return reject("Enter a valid full name.")

        if not state or len(state) > 100:
            return reject("Enter a valid state.")

        if not organization or len(organization) > 160:
            return reject("Enter a valid organization.")

        if not bank_name or len(bank_name) > 120:
            return reject("Enter a valid bank name.")

        if not account_name or len(account_name) > 160:
            return reject("Enter a valid account name.")

        if not re.fullmatch(r"[0-9]{6,20}", account_number):
            return reject(
                "Enter an account number containing 6 to 20 digits."
            )

        encryption_key = os.environ.get("BANK_ENCRYPTION_KEY")
        if not encryption_key:
            raise RuntimeError("Bank encryption key is not configured.")

        encrypted_number = Fernet(encryption_key.encode()).encrypt(
            account_number.encode()
        ).decode()

        details = BankAccountSubmission(
            full_name=full_name,
            state=state,
            organization=organization,
            bank_name=bank_name,
            account_name=account_name,
            account_number_encrypted=encrypted_number,
        )

        db.session.add(details)

        db.session.execute(
            delete(BankSubmissionAttempt).where(
                BankSubmissionAttempt.attempt_key == ip_attempt_key
            )
        )

        db.session.commit()

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
    submissions = []

    # New independent submissions
    new_records = db.session.scalars(
        select(BankAccountSubmission).order_by(
            BankAccountSubmission.created_at.desc()
        )
    ).all()

    for details in new_records:
        submissions.append({
            "full_name": details.full_name,
            "state": details.state,
            "organization": details.organization,
            "bank_name": details.bank_name,
            "account_name": details.account_name,
            "account_number": cipher.decrypt(
                details.account_number_encrypted.encode()
            ).decode(),
            "submitted_at": details.created_at,
        })

    # Preserve visibility of previously submitted participant-linked records
    old_records = db.session.execute(
        select(ParticipantAccountDetails, Participant)
        .join(Participant, Participant.id == ParticipantAccountDetails.participant_id)
    ).all()

    for details, participant in old_records:
        submissions.append({
            "full_name": participant.full_name,
            "state": "",
            "organization": participant.organization or "",
            "bank_name": details.bank_name,
            "account_name": details.account_name,
            "account_number": cipher.decrypt(
                details.account_number_encrypted.encode()
            ).decode(),
            "submitted_at": details.created_at,
        })

    submissions.sort(
        key=lambda item: item["submitted_at"],
        reverse=True,
    )

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
