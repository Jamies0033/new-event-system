import io
import os
from datetime import datetime
from zoneinfo import ZoneInfo

from cryptography.fernet import Fernet
from flask import Blueprint, Response, abort
from flask_login import login_required
from openpyxl import Workbook
from openpyxl.styles import Font, PatternFill
from openpyxl.utils import get_column_letter
from sqlalchemy import select
from sqlalchemy.orm import joinedload

from app.models import (
    Attendance,
    AttendanceSession,
    Participant,
    ParticipantAccountDetails,
    db,
)
from app.permissions import permission_required


reports_bp = Blueprint("reports", __name__, url_prefix="/reports")

LAGOS_TIMEZONE = ZoneInfo("Africa/Lagos")


def export_date():
    return datetime.now(LAGOS_TIMEZONE).strftime("%Y%m%d")


def safe_cell(value):
    """Prevent untrusted text from being interpreted as an Excel formula."""
    if value is None:
        return ""

    if isinstance(value, str) and value.lstrip().startswith(
        ("=", "+", "-", "@", "\t", "\r")
    ):
        return "'" + value

    return value


def local_datetime(value):
    if value is None:
        return ""

    if value.tzinfo is None:
        value = value.replace(tzinfo=ZoneInfo("UTC"))

    return value.astimezone(LAGOS_TIMEZONE).replace(tzinfo=None)


def style_sheet(sheet):
    header_fill = PatternFill(
        fill_type="solid",
        fgColor="17365D",
    )

    for cell in sheet[1]:
        cell.font = Font(bold=True, color="FFFFFF")
        cell.fill = header_fill

    sheet.freeze_panes = "A2"
    sheet.auto_filter.ref = sheet.dimensions

    for column in sheet.columns:
        max_length = 0
        column_letter = get_column_letter(column[0].column)

        for cell in column:
            value = str(cell.value or "")
            max_length = max(max_length, len(value))

        sheet.column_dimensions[column_letter].width = min(
            max(max_length + 2, 14),
            40,
        )


def workbook_response(workbook):
    output = io.BytesIO()
    workbook.save(output)
    output.seek(0)

    response = Response(
        output.getvalue(),
        mimetype=(
            "application/vnd.openxmlformats-officedocument."
            "spreadsheetml.sheet"
        ),
    )

    response.headers["Content-Disposition"] = (
        f'attachment; filename="event_registration_{export_date()}.xlsx"'
    )
    response.headers["Cache-Control"] = (
        "no-store, no-cache, must-revalidate, private"
    )
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"

    return response


@reports_bp.get("/event-workbook.xlsx")
@login_required
@permission_required("manage_participants")
@permission_required("view_attendance")
@permission_required("export_account_details")
@permission_required("export_event_workbook")
def export_event_workbook():
    encryption_key = os.environ.get("BANK_ENCRYPTION_KEY")

    if not encryption_key:
        abort(500, description="Bank encryption is not configured.")

    try:
        cipher = Fernet(encryption_key.encode())
    except (TypeError, ValueError):
        abort(500, description="Bank encryption is not configured.")

    workbook = Workbook()

    # 1. Participants
    participants_sheet = workbook.active
    participants_sheet.title = "Participants"

    participants_sheet.append([
        "Participant ID",
        "Full Name",
        "Email",
        "Phone",
        "Status",
        "Registration Date",
    ])

    participants = db.session.scalars(
        select(Participant).order_by(Participant.id.asc())
    ).all()

    for participant in participants:
        participants_sheet.append([
            safe_cell(participant.participant_code),
            safe_cell(participant.full_name),
            safe_cell(participant.email),
            safe_cell(participant.phone),
            "Active" if participant.is_active else "Inactive",
            local_datetime(participant.created_at),
        ])

    # 2. Attendance
    attendance_sheet = workbook.create_sheet("Attendance")

    attendance_sheet.append([
        "Participant ID",
        "Full Name",
        "Attendance Date",
        "Arrival Time (WAT)",
        "Scanned By",
    ])

    attendance_records = db.session.scalars(
        select(Attendance)
        .options(
            joinedload(Attendance.participant),
            joinedload(Attendance.session),
            joinedload(Attendance.recorded_by),
        )
        .join(
            AttendanceSession,
            Attendance.session_id == AttendanceSession.id,
        )
        .where(AttendanceSession.checkpoint == "arrival")
        .order_by(
            AttendanceSession.session_date.asc(),
            Attendance.checked_in_at.asc(),
        )
    ).all()

    for record in attendance_records:
        attendance_sheet.append([
            safe_cell(record.participant.participant_code),
            safe_cell(record.participant.full_name),
            record.session.session_date,
            local_datetime(record.checked_in_at),
            safe_cell(record.recorded_by.username),
        ])

    # 3. Account Details
    account_sheet = workbook.create_sheet("Account Details")

    account_sheet.append([
        "Participant ID",
        "Bank Name",
        "Account Name",
        "Account Number",
    ])

    account_records = db.session.execute(
        select(ParticipantAccountDetails, Participant)
        .join(
            Participant,
            Participant.id == ParticipantAccountDetails.participant_id,
        )
        .order_by(Participant.participant_code.asc())
    ).all()

    for details, participant in account_records:
        try:
            account_number = cipher.decrypt(
                details.account_number_encrypted.encode()
            ).decode()
        except Exception:
            # Do not silently export incomplete or corrupted financial data.
            abort(500, description="An account record could not be decrypted.")

        account_sheet.append([
            safe_cell(participant.participant_code),
            safe_cell(details.bank_name),
            safe_cell(details.account_name),
            safe_cell(account_number),
        ])

    for sheet in workbook.worksheets:
        style_sheet(sheet)

    return workbook_response(workbook)
