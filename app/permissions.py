from functools import wraps

from flask import abort
from flask_login import current_user
from sqlalchemy import select

from app.models import StaffPermission, db


AVAILABLE_PERMISSIONS = {
    "manage_participants": "Register and manage participants",
    "view_attendance": "View attendance records and reports",
    "scan_attendance": "Scan participant QR codes",
    "view_account_details": "View submitted bank details",
    "export_account_details": "Export bank details",
    "export_event_workbook": "Export the complete event workbook",
    "manage_team": "Manage staff accounts and permissions",
}


def has_permission(permission):
    if permission not in AVAILABLE_PERMISSIONS:
        raise ValueError(f"Unknown permission: {permission}")

    if not current_user.is_authenticated or not current_user.is_active:
        return False

    if current_user.role == "admin":
        return True

    granted = db.session.scalar(
        select(StaffPermission.id).where(
            StaffPermission.user_id == current_user.id,
            StaffPermission.permission == permission,
        )
    )
    return granted is not None


def permission_any_required(*permissions):
    if not permissions or any(p not in AVAILABLE_PERMISSIONS for p in permissions):
        raise ValueError("Provide valid permissions.")

    def decorator(view):
        @wraps(view)
        def wrapped_view(*args, **kwargs):
            if not any(has_permission(p) for p in permissions):
                abort(403)
            return view(*args, **kwargs)
        return wrapped_view
    return decorator


def admin_required(view):
    @wraps(view)
    def wrapped_view(*args, **kwargs):
        if not current_user.is_authenticated:
            abort(403)
        if not current_user.is_active or current_user.role != "admin":
            abort(403)
        return view(*args, **kwargs)
    return wrapped_view


def permission_required(permission):
    if permission not in AVAILABLE_PERMISSIONS:
        raise ValueError(f"Unknown permission: {permission}")

    def decorator(view):
        @wraps(view)
        def wrapped_view(*args, **kwargs):
            if not has_permission(permission):
                abort(403)
            return view(*args, **kwargs)
        return wrapped_view
    return decorator
