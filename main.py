from flask import Flask, request, jsonify, render_template
from flask import send_from_directory
import json, os, uuid, csv, smtplib
from filelock import FileLock
from datetime import datetime
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.utils import formataddr
import hashlib, bcrypt
import threading
import hmac
from werkzeug.utils import secure_filename
from datetime import datetime, timezone
from zoneinfo import ZoneInfo
from db import (load_staff_from_db, find_staff_in_db, verify_manager_pin_in_db, load_programmes_from_db, save_programmes_to_db, load_manager_from_db, load_email_settings_from_db, update_email_settings_in_db, create_email_log_in_db, update_email_log_status_in_db,find_superuser_in_db, load_email_logs_from_db, delete_programme_from_db)
from dotenv import load_dotenv
from html import escape as html_escape

load_dotenv()


MALAYSIA_TZ = ZoneInfo("Asia/Kuala_Lumpur")

def utc_now_iso():
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

def malaysia_today():
    return datetime.now(MALAYSIA_TZ).strftime("%Y-%m-%d")

# def _load_config():
#     _cfg_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'config.py')
#     if os.path.exists(_cfg_path):
#         _spec = _ilu.spec_from_file_location("_app_config", _cfg_path)
#         _mod  = _ilu.module_from_spec(_spec)
#         _spec.loader.exec_module(_mod)
#         return _mod
#     return None

# _cfg = _load_config()


def required_env(name):
    value = str(os.getenv(name) or '').strip()

    if not value:
        raise RuntimeError(
            f'Required environment variable is missing: {name}'
        )

    return value


SYSTEM_URL = os.getenv(
    'SYSTEM_URL',
    'http://127.0.0.1:5001/daily-report/'
).rstrip('/') + '/'

EMAIL_SMTP_HOST = required_env('EMAIL_SMTP_HOST')
EMAIL_SMTP_PORT = int(os.getenv('EMAIL_SMTP_PORT', '587'))
EMAIL_SENDER = required_env('EMAIL_SENDER')
EMAIL_SENDER_NAME = os.getenv(
    'EMAIL_SENDER_NAME',
    'Daily Work Report System'
)
EMAIL_PASSWORD = required_env('EMAIL_PASSWORD')

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
# STAFF_CSV = os.path.join(BASE_DIR, 'staff.csv')
PROGRAMMES_FILE = os.path.join(BASE_DIR, 'programmes.json')
LOCK = FileLock(PROGRAMMES_FILE + '.lock')
UPLOAD_FOLDER = os.path.join(BASE_DIR, 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app = Flask(__name__, static_folder='.', static_url_path='')
import secrets
active_sessions = {}
APP_ROOT = '/daily-report'

@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['Referrer-Policy'] = 'same-origin'
    response.headers['Permissions-Policy'] = (
        'camera=(), microphone=(), geolocation=()'
    )

    return response


# ── Data helpers ──────────────────────────────────────────────────────────────
def get_session(request):
    token = request.headers.get('X-Auth-Token', '')
    return active_sessions.get(token)  # returns {'name':..., 'role':...} or None

def require_session(request):
    session = get_session(request)
    if not session:
        return None, jsonify({'error': 'Not authenticated'}), 401
    return session, None, None

def is_superuser(session):
    return (
        session is not None
        and session.get('role') == 'superuser'
    )

def require_superuser(request):
    session = get_session(request)

    if not session: 
        return None, jsonify({
            'error': 'Not authenticated'
        }), 401

    if session.get('role') != 'superuser':
        return None, jsonify({
            'error': 'Superuser access required'
        }), 403
    
    return session, None, None

def load_staff():
    
    return load_staff_from_db()

    
def load_manager():
    
    return load_manager_from_db()

def find_staff(name):
    return find_staff_in_db(name)


def load_programmes():
    return load_programmes_from_db()

def save_programmes(programmes):
    return save_programmes_to_db(programmes)

def save_or_500(programmes):
    if not save_programmes(programmes):
        return jsonify({'error': 'Database save failed. Check server logs.'}), 500
    return None


# ── Email ─────────────────────────────────────────────────────────────────────
def format_status(value):
    status = str(value or '').strip().lower()

    status_names = {
        'in-progress': 'In Progress',
        'completed': 'Completed',
        'blocked': 'Blocked'
    }

    return status_names.get(
        status,
        status.replace('-', ' ').title() or 'Not Set'
    )


def notify_programme_created(programme, creator_id):
    staff_directory = load_staff_email_directory()

    creator_id = str(creator_id or '').strip()

    assigned_ids = [
        str(staff_id).strip()
        for staff_id in programme.get('assignedStaff', [])
        if str(staff_id).strip()
    ]
    creator = staff_directory.get(creator_id, {})
    creator_name=creator.get('name') or creator_id

    assigned_names = [
        staff_directory.get(staff_id, {}).get('name') or staff_id
        for staff_id in assigned_ids
    ]

    recipients = resolve_recipient_emails(
        staff_ids=assigned_ids,
        staff_directory=staff_directory,
        exclude_ids=[creator_id],
        include_manager=True
    )

    title =  str(programme.get('title') or '')
    status = format_status(programme.get('status'))

    subject = (
        f"[Daily Work Report System] New Programme Created: {title}"
    )

    html_body =f"""
    <div style="font-family:sans-serif;max-width:560px;margin:0 auto">
    <h2> New Programme: {html_escape(title)}</h2>
    <p>
    <b> Created by: </b>
    {html_escape(str(creator_name))}
    </p>

    <p>
    <b> Status:</b>
    {html_escape(status)}
    </p>

    <p>
    <b> Assigned staff:</b>
    {html_escape(','.join(assigned_names)or 'None')}
    </p>

    <p style="color:#6b6b67;font-size:13px">
        Log in to the Work Report System to view details.
      </p>
    </div>
    """

    return dispatch_notification_email(
        event_type='programme_created',
        recipients=recipients,
        subject=subject,
        html_body=html_body,
        programme_id=programme.get('id')
    )

def notify_daily_report_added(programme, report, reporter_id):
    staff_directory = load_staff_email_directory()

    reporter_id = str(reporter_id or '').strip()

    involved_ids = [
        str(staff_id).strip()
        for staff_id in report.get('involvedStaff', [])
        if str(staff_id).strip()
    ]

    reporter = staff_directory.get(reporter_id, {})
    reporter_name = reporter.get('name') or reporter_id

    involved_names = [
        staff_directory.get(staff_id,{}).get('name') or staff_id
        for staff_id in involved_ids
    ]

    recipients = resolve_recipient_emails(
        staff_ids= involved_ids,
        staff_directory=staff_directory,
        exclude_ids=[reporter_id],
        include_manager=True
    )

    programme_title = str(programme.get('title') or '')
    report_date = str(report.get('date') or '')
    report_status = format_status(report.get('status') or '')
    priority = str(report.get('priority') or 'middle')
    hours = str(report.get('hours') or '-')
    summary = str(report.get('summary') or '')

    subject = (
        f"[Daily Work Report System] Daily Report Added: "
        f"{programme_title}"
    )

    html_body = f"""
    <div style="font-family:sans-serif;max-width:560px;margin:0 auto">
      <h2>New Daily Report Added</h2>

      <p>
        <b>Programme:</b>
        {html_escape(programme_title)}
      </p>

      <p>
        <b>Reported by:</b>
        {html_escape(str(reporter_name))}
      </p>

      <p>
        <b>Date:</b>
        {html_escape(report_date)}
      </p>

      <p>
        <b>Status:</b>
        {html_escape(report_status)}
      </p>

      <p>
        <b>Priority:</b>
        {html_escape(priority.capitalize())}
      </p>

      <p>
        <b>Hours:</b>
        {html_escape(hours)}
      </p>

      <p>
        <b>Involved staff:</b>
        {html_escape(', '.join(involved_names) or 'None')}
      </p>

      <p>
        <b>Summary:</b>
        {html_escape(summary)}
      </p>

      <p style="color:#6b6b67;font-size:13px">
        Log in to the
        <a href="{html_escape(SYSTEM_URL)}"
            style="color:#2563eb;font-weight:600;text-decoration:none">
            Daily Work Report System
        </a>
        to view the full report.
        </p>

     <p style="color:#181847;font-size:13px;line-height:1.6;margin-top:20px">
        Regards,<br>
        <strong>Daily Work Report System Administrator</strong>
        </p>

        <p style="color:#b91c1c;font-size:11px;font-weight:600;margin-top:12px">
        This is an automated email. Please do not reply.
        </p>
    </div>
    """

    return dispatch_notification_email(
        event_type='daily_report_added',
        recipients=recipients,
        subject=subject,
        html_body=html_body,
        programme_id=programme.get('id'),
        report_id=report.get('id')
    )

def notify_programme_status_updated(programme, updater_name, old_status=None):
    staff_directory = load_staff_email_directory()

    assigned_ids = [
        str(staff_id).strip()
        for staff_id in programme.get('assignedStaff', [])
        if str(staff_id).strip()
    ]

    recipients = resolve_recipient_emails(
        staff_ids=assigned_ids,
        staff_directory=staff_directory,
        include_manager=True
    )
    

    programme_title = str(programme.get('title') or '')
    old_status_name = format_status(old_status)
    new_status_name = format_status(programme.get('status'))
    updater_name = str(updater_name or 'Unknown')

    subject = (
        f"[Daily Work Report System] Programme Status Updated: "
        f"{programme_title} → {new_status_name}"
    )

    html_body = f"""
    <div style="font-family:sans-serif;max-width:560px;margin:0 auto">
      <h2>Programme Status Updated</h2>

      <p>
        <b>Programme:</b>
        {html_escape(programme_title)}
      </p>

      <p>
        <b>Updated by:</b>
        {html_escape(updater_name)}
      </p>

      <p>
        <b>Status changed:</b>
        {html_escape(old_status_name)}
        &rarr;
        {html_escape(new_status_name)}
        </p>

      <p style="color:#6b6b67;font-size:13px">
              Log in to the
              <a href="{html_escape(SYSTEM_URL)}"
                  style="color:#2563eb;font-weight:600;text-decoration:none">
                  Daily Work Report System
              </a>
              to view the full report.
              </p>
      
           <p style="color:#181847;font-size:13px;line-height:1.6;margin-top:20px">
            Regards,<br>
            <strong>Daily Work Report System Administrator</strong>
            </p>

            <p style="color:#b91c1c;font-size:11px;font-weight:600;margin-top:12px">
            This is an automated email. Please do not reply.
            </p>
    </div>
    """

    return dispatch_notification_email(
        event_type='status_updated',
        recipients=recipients,
        subject=subject,
        html_body=html_body,
        programme_id=programme.get('id')
    )


def notify_programme_updated(programme, updater_name, changes):
    """Notify only the programme's current assigned staff and manager."""

    staff_directory = load_staff_email_directory()
    assigned_ids = [
        str(staff_id).strip()
        for staff_id in programme.get('assignedStaff', [])
        if str(staff_id).strip()
    ]
    recipients = resolve_recipient_emails(
        staff_ids=assigned_ids,
        staff_directory=staff_directory,
        include_manager=True
    )

    programme_title = str(programme.get('title') or '')
    updater_name = str(updater_name or 'Unknown')
    change_items = ''.join(
        f'<li>{html_escape(str(change))}</li>'
        for change in changes
    )

    subject = f"[Daily Work Report System] Programme Updated: {programme_title}"
    html_body = f"""
    <div style="font-family:sans-serif;max-width:560px;margin:0 auto">
      <h2>Programme Updated</h2>
      <p><b>Programme:</b> {html_escape(programme_title)}</p>
      <p><b>Updated by:</b> {html_escape(updater_name)}</p>
      <p><b>Changes:</b></p>
      <ul>{change_items}</ul>
      <p style="color:#6b6b67;font-size:13px">
              Log in to the
              <a href="{html_escape(SYSTEM_URL)}"
                  style="color:#2563eb;font-weight:600;text-decoration:none">
                  Daily Work Report System
              </a>
              to view the full report.
              </p>
      
          <p style="color:#181847;font-size:13px;line-height:1.6;margin-top:20px">
            Regards,<br>
            <strong>Daily Work Report System Administrator</strong>
            </p>

            <p style="color:#b91c1c;font-size:11px;font-weight:600;margin-top:12px">
            This is an automated email. Please do not reply.
            </p>
    </div>
    """

    return dispatch_notification_email(
        event_type='programme_updated',
        recipients=recipients,
        subject=subject,
        html_body=html_body,
        programme_id=programme.get('id')
    )


def notify_daily_report_updated(programme, report, updater_name, changes, exclude_staff_ids=None):

    staff_directory = load_staff_email_directory()
    current_involved_ids = [
        str(staff_id).strip()
        for staff_id in report.get('involvedStaff', [])
        if str(staff_id).strip()
    ]
   

    recipients = resolve_recipient_emails(
        staff_ids=current_involved_ids,
        staff_directory=staff_directory,
        exclude_ids=exclude_staff_ids,
        include_manager=True
    )

    programme_title = str(programme.get('title') or '')
    report_date = str(report.get('date') or '')
    updater_name = str(updater_name or 'Unknown')
    change_items = ''.join(
        f'<li>{html_escape(str(change))}</li>'
        for change in changes
    )

    subject = f"[Daily Work Report System] Daily Report Updated: {programme_title}"
    html_body = f"""
    <div style="font-family:sans-serif;max-width:560px;margin:0 auto">
      <h2>Daily Report Updated</h2>

      <p><b>Programme:</b> {html_escape(programme_title)}</p>
      <p><b>Report date:</b> {html_escape(report_date)}</p>
      <p><b>Updated by:</b> {html_escape(updater_name)}</p>

      <p><b>Changes:</b></p>
      <ul>{change_items}</ul>

     <p style="color:#6b6b67;font-size:13px">
             Log in to the
             <a href="{html_escape(SYSTEM_URL)}"
                 style="color:#2563eb;font-weight:600;text-decoration:none">
                 Daily Work Report System
             </a>
             to view the full report.
             </p>
     
           <p style="color:#181847;font-size:13px;line-height:1.6;margin-top:20px">
            Regards,<br>
            <strong>System Administrator</strong>
            </p>

            <p style="color:#b91c1c;font-size:11px;font-weight:600;margin-top:12px">
            This is an automated email. Please do not reply.
            </p>
    </div>
    """

    return dispatch_notification_email(
        event_type='daily_report_updated',
        recipients=recipients,
        subject=subject,
        html_body=html_body,
        programme_id=programme.get('id'),
        report_id=report.get('id')
    )

def notify_staff_added_to_daily_report(
    programme,
    report,
    added_staff_ids,
    updater_name
):
    """Notify only staff newly added to the daily report."""

    staff_directory = load_staff_email_directory()

    recipients = resolve_recipient_emails(
        staff_ids=added_staff_ids,
        staff_directory=staff_directory,
        include_manager=False
    )

    if not recipients:
        return None

    programme_title = str(programme.get('title') or '')
    report_date = str(report.get('date') or '')
    updater_name = str(updater_name or 'Unknown')

    subject = (
        f"[Daily Work Report System] You Have Been Added: "
        f"{programme_title}"
    )

    html_body = f"""
    <div style="font-family:sans-serif;max-width:560px;margin:0 auto">
      <h2>You Have Been Added to a Daily Report</h2>

      <p>
        You have been added as an involved staff member.
      </p>

      <p><b>Programme:</b> {html_escape(programme_title)}</p>
      <p><b>Report date:</b> {html_escape(report_date)}</p>
      <p><b>Added by:</b> {html_escape(updater_name)}</p>

      <p style="color:#6b6b67;font-size:13px">
              Log in to the
              <a href="{html_escape(SYSTEM_URL)}"
                  style="color:#2563eb;font-weight:600;text-decoration:none">
                  Daily Work Report System
              </a>
              to view the full report.
              </p>
      
           <p style="color:#181847;font-size:13px;line-height:1.6;margin-top:20px">
            Regards,<br>
            <strong>Daily Work Report System Administrator</strong>
            </p>

            <p style="color:#b91c1c;font-size:11px;font-weight:600;margin-top:12px">
            This is an automated email. Please do not reply.
            </p>
    </div>
    """

    return dispatch_notification_email(
        event_type='daily_report_staff_added',
        recipients=recipients,
        subject=subject,
        html_body=html_body,
        programme_id=programme.get('id'),
        report_id=report.get('id')
    )

def notify_manager_note_added(
    programme,
    report,
    manager_name,
    was_update=False
):
    staff_directory = load_staff_email_directory()

    reporter_id = str(report.get('staff') or '').strip()

    involved_ids = [
        str(staff_id).strip()
        for staff_id in report.get('involvedStaff', [])
        if str(staff_id).strip()
    ]

    recipient_ids = list(involved_ids)

    if reporter_id and reporter_id not in recipient_ids:
        recipient_ids.append(reporter_id)

    recipients = resolve_recipient_emails(
        staff_ids=recipient_ids,
        staff_directory=staff_directory,
        include_manager=False
    )

    programme_title = str(programme.get('title') or '')
    report_date = str(report.get('date') or '')
    manager_note = str(report.get('managerNote') or '')
    manager_name = str(manager_name or 'Manager')

    action = 'Updated' if was_update else 'Added'

    subject = (
        f"[Daily Work Report System] Manager Note {action}: "
        f"{programme_title}"
    )

    html_body = f"""
    <div style="font-family:sans-serif;max-width:560px;margin:0 auto">
      <h2>Manager Note {action}</h2>

      <p>
        <b>Programme:</b>
        {html_escape(programme_title)}
      </p>

      <p>
        <b>Report date:</b>
        {html_escape(report_date)}
      </p>

      <p>
        <b>Manager:</b>
        {html_escape(manager_name)}
      </p>

      <div style="
          padding:12px;
          border-left:4px solid #1d4ed8;
          background:#eff6ff;
          color:#1e3a8a;
          margin:14px 0;
      ">
        {html_escape(manager_note)}
      </div>

    <p style="color:#6b6b67;font-size:13px">
            Log in to the
            <a href="{html_escape(SYSTEM_URL)}"
                style="color:#2563eb;font-weight:600;text-decoration:none">
                Daily Work Report System
            </a>
            to view the full report.
            </p>
    
          <p style="color:#181847;font-size:13px;line-height:1.6;margin-top:20px">
            Regards,<br>
            <strong>Daily Work Report System Administrator</strong>
            </p>

            <p style="color:#b91c1c;font-size:11px;font-weight:600;margin-top:12px">
            This is an automated email. Please do not reply.
            </p>
    </div>
    """

    return dispatch_notification_email(
        event_type='manager_note_added',
        recipients=recipients,
        subject=subject,
        html_body=html_body,
        programme_id=programme.get('id'),
        report_id=report.get('id')
    )


# ── Routes ────────────────────────────────────────────────────────────────────

@app.route(APP_ROOT)
@app.route(APP_ROOT + '/')
def index():
    try:
        with open(os.path.join(BASE_DIR, 'index.html'), 'r', encoding='utf-8') as f:
            return f.read(), 200, {'Content-Type': 'text/html'}
    except FileNotFoundError:
        return 'index.html not found', 404
    
@app.route(APP_ROOT + '/assets/<path:filename>')
def serve_asset(filename):
    return send_from_directory(
        os.path.join(BASE_DIR, 'assets'),
        filename
    )

# ── Auth ──────────────────────────────────────────────────────────────────────

@app.route(APP_ROOT + '/api/auth/staff', methods=['POST'])
def auth_staff():
    data = request.get_json(silent=True) or {}
    user_id = data.get('user_id', '').strip()
    staff = find_staff(user_id)
    if not staff:
        return jsonify({'error': 'Invalid Staff ID. Please check your ID.'}), 401
    token = secrets.token_hex(32)
    active_sessions[token] = {
        'name': staff['name'], 
        'id': staff['id'],
        'role': 'staff'
    }
    return jsonify({
        'name': staff['name'], 
        'email': staff['email'],
        'id': staff['id'],
        'token': token
    })

@app.route(APP_ROOT + '/api/auth/manager', methods=['POST'])
def auth_manager():
    data = request.get_json(silent=True) or {}
    pin = data.get('pin', '')

    def login_success():
        manager = load_manager()

        if not manager:
            manager = {
                'id': None,
                'name': 'Manager'
            }
        token = secrets.token_hex(32)

        active_sessions[token] = {
        'id': manager['id'],
        'name' : manager['name'],
        'role':'manager'
    }
        
        return jsonify({
        'ok': True,
        'token': token,
        'manager':manager
    })


    db_hex_hash = verify_manager_pin_in_db()
    if not db_hex_hash:
        return jsonify({
            'error': 'Manager PIN is not configured'
        }), 503
        
    input_hash = hashlib.md5(pin.encode()).hexdigest().upper()

    if input_hash == db_hex_hash:
            return login_success()
    
    input_hash = hashlib.md5(
        pin.encode()
    ).hexdigest().upper()

    if hmac.compare_digest(
        input_hash,
        db_hex_hash.strip().upper()
    ):
        return login_success()

    return jsonify({
        'error': 'Incorrect PIN.'
    }), 401

@app.route(
    APP_ROOT + '/api/auth/superuser',
    methods=['POST']
)
def auth_superuser():
    data = request.get_json(silent=True) or {}

    user_id = str(
        data.get('user_id') or ''
    ).strip()

    if not user_id:
        return jsonify({
            'error': 'User ID is required'
        }), 400

    superuser = find_superuser_in_db(user_id)

    if not superuser:
        return jsonify({
            'error': 'Only active MIS users can access this page'
        }), 403

    token = secrets.token_hex(32)

    active_sessions[token] = {
        'id': superuser['id'],
        'name': superuser['name'],
        'email': superuser['email'],
        'role': 'superuser',
    }

    return jsonify({
        'token': token,
        'user': {
            'id': superuser['id'],
            'name': superuser['name'],
            'email': superuser['email'],
            'role': 'superuser',
        }
    })

@app.route(
    APP_ROOT + '/api/admin/email-settings',
    methods=['GET']
)
def get_email_settings():
    session, error_response, status_code = (
        require_superuser(request)
    )

    if error_response:
        return error_response, status_code

    settings = load_email_settings_from_db()

    return jsonify(settings)

@app.route(
    APP_ROOT + '/api/admin/email-settings',
    methods=['PUT']
)
def update_email_settings():
    session, error_response, status_code = (
        require_superuser(request)
    )

    if error_response:
        return error_response, status_code

    data = request.get_json(silent=True) or {}

    boolean_fields = [
        'emailEnabled',
        'notifyProgrammeCreated',
        'notifyDailyReportAdded',
        'notifyStatusUpdated',
        'notifyManagerNoteAdded',
    ]

    for field in boolean_fields:
        if field not in data:
            return jsonify({
                'error': f'Missing setting: {field}'
            }), 400

        if not isinstance(data[field], bool):
            return jsonify({
                'error': f'{field} must be true or false'
            }), 400

    manager_email = str(
        data.get('managerEmail') or ''
    ).strip()

    if data['emailEnabled'] and not manager_email:
        return jsonify({
            'error': (
                'Manager email is required when '
                'email notifications are enabled'
            )
        }), 400

    if manager_email:
        has_at = '@' in manager_email
        domain = manager_email.rsplit('@', 1)[-1]
        has_dot = '.' in domain

        if not has_at or not has_dot:
            return jsonify({
                'error': 'Enter a valid manager email address'
            }), 400

    settings = {
        'emailEnabled': data['emailEnabled'],
        'notifyProgrammeCreated': (
            data['notifyProgrammeCreated']
        ),
        'notifyDailyReportAdded': (
            data['notifyDailyReportAdded']
        ),
        'notifyStatusUpdated': (
            data['notifyStatusUpdated']
        ),
        'notifyManagerNoteAdded': (
            data['notifyManagerNoteAdded']
        ),
        'managerEmail': manager_email,
    }

    updated = update_email_settings_in_db(
        settings=settings,
        updated_by=session.get('id')
    )

    if not updated:
        return jsonify({
            'error': 'Unable to update email settings'
        }), 500

    return jsonify({
        'ok': True,
        'settings': load_email_settings_from_db()
    })

@app.route(
    APP_ROOT + '/api/admin/email-logs',
    methods=['GET']
)
def get_email_logs():
    session, error_response, status_code = (
        require_superuser(request)
    )

    if error_response:
        return error_response, status_code

    try:
        limit = int(request.args.get('limit', 100))
    except (TypeError, ValueError):
        return jsonify({
            'error': 'limit must be a number'
        }), 400

    limit = max(1, min(limit, 500))

    logs = load_email_logs_from_db(limit=limit)

    return jsonify({
        'logs': logs,
        'count': len(logs)
    })

@app.route(APP_ROOT + '/api/me', methods=['GET'])
def get_current_user():
    token = request.headers.get('X-Auth-Token', '')
    return jsonify(active_sessions.get(token) or {})

@app.route(APP_ROOT + '/api/staff', methods=['GET'])
def get_staff():
    session, error_response, status_code = require_session(request)

    if error_response:
        return error_response, status_code
    
    return jsonify(load_staff())


# ── Programmes ────────────────────────────────────────────────────────────────

@app.route(APP_ROOT + '/api/programmes', methods=['GET'])
def get_programmes():
    session, error_response, status_code = require_session(request)

    if error_response:
        return error_response, status_code
    
    programmes = load_programmes()
    programmes.sort(key=lambda p: p.get('createdAt', ''), reverse=True)
    for prog in programmes:
        for report in prog.get('dailyReports', []):
            report['files'] = [
                {
                    'name': f.get('name'),
                    'path': f.get('path'),
                    'data': f.get('data'),
                    'type': f.get('type'),
                }
                for f in report.get('files', [])
            ]
    return jsonify(programmes)


@app.route(APP_ROOT + '/api/programmes', methods=['POST'])
def create_programme():
    session, error_response, status_code = require_session(request)

    if error_response:
        return error_response, status_code
    data = request.get_json(silent=True) or {}
    title = data.get('title', '').strip()
    creator = session['id']
    if not title:
        return jsonify({'error': 'Title is required'}), 400

    programme = {
        'id': uuid.uuid4().hex.upper(),
        'title': title,
        'createdBy': creator,
        'assignedStaff': data.get('assignedStaff', [creator]),
        'status': data.get('status', 'in-progress'),
        'createdAt': utc_now_iso(),
        'updatedAt': utc_now_iso(),
        'dailyReports': [],
    }

    programmes = load_programmes()
    programmes.insert(0, programme)
    save_error = save_or_500(programmes)
    if save_error:
        return save_error
    notify_programme_created(programme, creator)
    return jsonify(programme), 201


@app.route(APP_ROOT + '/api/programmes/<prog_id>', methods=['PUT'])
def update_programme(prog_id):
    session = get_session(request)

    if not session:
        return jsonify({'error': 'Not authenticated'}), 401
    data = request.get_json(silent=True) or {}
    programmes = load_programmes()
    prog = next((p for p in programmes if p['id'] == prog_id), None)
    if not prog:
        return jsonify({'error': 'Programme not found'}), 404

    is_manager_user = session.get('role') == 'manager'
    is_superuser_user = is_superuser(session)
    is_creator = session.get('id') == prog.get('createdBy')
    is_assigned = (
        session.get('id') in prog.get('assignedStaff', [])
    )

    if not (
        is_manager_user
        or is_superuser_user
        or is_creator
        or is_assigned
    ):
        return jsonify({
            'error': 'You cannot edit this programme'
        }), 403

    updater = (
        session.get('name')
        or session.get('id')
        or 'Unknown'
    )
    update_type = data.get('updateType', 'status')

    if 'status' in data and update_type == 'status':
        old_status = str(prog.get('status') or '')
        new_status = str(data.get('status') or '')

        if old_status != new_status:
            prog['status'] = new_status
            prog['updatedAt'] = utc_now_iso()

            save_error = save_or_500(programmes)
            if save_error:
                return save_error

            notify_programme_status_updated(
                programme=prog,
                updater_name=updater,
                old_status=old_status
            )

    elif update_type == 'staff' and 'assignedStaff' in data:
        old_staff = list(prog.get('assignedStaff', []))
        new_staff = list(data.get('assignedStaff') or [])
        if old_staff != new_staff:
            prog['assignedStaff'] = new_staff
            prog['updatedAt'] = utc_now_iso()

            save_error = save_or_500(programmes)
            if save_error:
                return save_error

            notify_programme_updated(
                programme=prog,
                updater_name=updater,
                changes=['Assigned staff']
            )
        

    elif update_type == 'details':
        changes = []
      
        if 'title' in data:
            old_title = str(prog.get('title') or '')
            new_title = str(data.get('title') or '').strip()

            if old_title != new_title:
                prog['title'] = new_title
                changes.append(
                    f'Title: {old_title or "Not set"} -> '
                    f'{new_title or "Not set"}'
                )
        if 'assignedStaff' in data:
            old_staff = list(prog.get('assignedStaff', []))
            new_staff = list(data.get('assignedStaff') or [])

            if old_staff != new_staff:
                prog['assignedStaff'] = new_staff
                changes.append('Assigned staff')
                    
        if 'status' in data:
            old_status = str(prog.get('status') or '')
            new_status = str(data.get('status') or '')

            if old_status != new_status:
                prog['status'] = new_status
                changes.append(
                    f'Status: {format_status(old_status)} -> '
                    f'{format_status(new_status)}'
                )

        if changes:
            prog['updatedAt'] = utc_now_iso()

            save_error = save_or_500(programmes)
            if save_error:
                return save_error

            notify_programme_updated(
                programme=prog,
                updater_name=updater,
                changes=changes
            )
        

    return jsonify(prog)

@app.route(APP_ROOT + '/api/programmes/<prog_id>', methods=['DELETE'])
def delete_programme(prog_id):
    session = get_session(request)
    if not session:
        return jsonify({'error': 'Not authenticated'}), 401

    programmes = load_programmes()
    prog = next((p for p in programmes if p['id'] == prog_id), None)
    if not prog:
        return jsonify({'error': 'Programme not found'}), 404

    # Auth check: must be the creator or manager
    is_manager_user = session.get('role') == 'manager'
    is_superuser_user = is_superuser(session)
    is_creator = session['id'] == prog.get('createdBy')
    is_assigned = (
        session.get('id') in prog.get('assignedStaff', [])
    )

    if not (
        is_manager_user
        or is_superuser_user
        or is_creator
        or is_assigned
    ):
        return jsonify({
            'error': 'You cannot delete this programme'
        }), 403

    deleted = delete_programme_from_db(prog_id)

    if not deleted:
        return jsonify({
            'error':'Unable to delete programme'
        }), 500
    
    return jsonify({'ok': True,  'message': 'Programme and related email logs deleted'})

@app.route(APP_ROOT + '/api/programmes/<prog_id>/reports/<report_id>', methods=['DELETE'])
def delete_daily_report(prog_id, report_id):
    session = get_session(request)
    if not session:
        return jsonify({'error': 'Not authenticated'}), 401

    programmes = load_programmes()

    prog = next((p for p in programmes if p['id'] == prog_id), None)
    if not prog:
        return jsonify({'error': 'Programme not found'}), 404

    report = next((r for r in prog.get('dailyReports', []) if r['id'] == report_id), None)
    if not report:
        return jsonify({'error': 'Report not found'}), 404
    
    is_manager_user = session.get('role') == 'manager'
    is_superuser_user = is_superuser(session)
    is_owner = session.get('id') == report.get('staff')

    if not (
        is_manager_user
        or is_superuser_user
        or is_owner
    ):
        return jsonify({
            'error': 'You cannot delete this report'
        }), 403


    prog['dailyReports'] = [r for r in prog.get('dailyReports', []) if r['id'] != report_id]
    prog['updatedAt'] = utc_now_iso()
    save_error = save_or_500(programmes)
    if save_error:
        return save_error
    
    return jsonify({
        'ok': True,
        'programme': prog
    })


# ── Daily Reports inside a Programme ─────────────────────────────────────────

@app.route(APP_ROOT + '/api/programmes/<prog_id>/reports', methods=['POST'])
def add_daily_report(prog_id):
    session = get_session(request)
    if not session:
        return jsonify({'error': 'Not authenticated'}), 401

    data = request.get_json(silent=True) or {}
    programmes = load_programmes()
    prog = next((p for p in programmes if p['id'] == prog_id), None)
    if not prog:
        return jsonify({'error': 'Programme not found'}), 404

    # Auth check: must be assigned to this programme
    if session['role'] != 'manager' and session['id'] not in prog.get('assignedStaff', []):
        return jsonify({'error': 'You are not assigned to this programme'}), 403

    reporter = session['id']  # use token identity, not request body

    report = {
        'id': uuid.uuid4().hex.upper(),
        'staff': reporter,
        'date': data.get('date', malaysia_today()),
        'hours': str(data.get('hours', '')),
        'status': data.get('status', 'in-progress'),
        'priority': data.get('priority', 'middle'),
        'summary': data.get('summary', '').strip(),
        'involvedStaff': data.get('involvedStaff', []),
        'files': data.get('files', []),
        'submittedAt': utc_now_iso(),
        'editedAt': '',
    }

    if not report['summary']:
        return jsonify({'error': 'Summary required'}), 400

    newly_added = []
    for usr_id in report['involvedStaff']:
        if usr_id not in prog['assignedStaff']:
            prog['assignedStaff'].append(usr_id)
            newly_added.append(usr_id)

    prog.setdefault('dailyReports', []).insert(0, report)
    prog['updatedAt'] = utc_now_iso()
    save_error = save_or_500(programmes)
    if save_error:
        return save_error

    notify_daily_report_added(
        programme=prog,
        report=report,
        reporter_id=reporter
    )

    return jsonify({'programme': prog, 'report': report}), 201


@app.route(APP_ROOT + '/api/programmes/<prog_id>/reports/<report_id>', methods=['PUT'])
def edit_daily_report(prog_id, report_id):
    session = get_session(request)
    if not session:
        return jsonify({'error': 'Not authenticated'}), 401

    data = request.get_json(silent=True) or {}
    programmes = load_programmes()
    prog = next((p for p in programmes if p['id'] == prog_id), None)
    if not prog:
        return jsonify({'error': 'Programme not found'}), 404
    
    report = next((r for r in prog.get('dailyReports', []) if r['id'] == report_id), None)
    if not report:
        return jsonify({'error': 'Report not found'}), 404

    is_superuser_user = is_superuser(session)
    is_owner = session.get('id') == report.get('staff')
    is_involved = (
        session.get('id')
        in report.get('involvedStaff', [])
    )

    if not (
        is_superuser_user
        or is_owner
        or is_involved
    ):
        return jsonify({
            'error': 'You cannot edit this report'
        }), 403

    

    updater = (session.get('name') or session.get('id') or 'Unknown')

    old_values = {
        field: report.get(field)
        for field in ['hours', 'status', 'priority', 'summary']
    }

    old_involved = {
        str(staff_id).strip()
        for staff_id in report.get('involvedStaff', [])
        if str(staff_id).strip()
    }

    old_files = sorted(
        (
            str(file.get('name') or ''),
            str(file.get('path') or file.get('data') or ''),
            str(file.get('type') or ''),
            str(file.get('size') or '')
        )
        for file in report.get('files', [])
        if isinstance(file, dict)
    )

    editable_fields = [
        'hours',
        'status',
        'priority',
        'summary',
        'involvedStaff',
        'files',
        'editReason',
        'editedBy'
    ]

    for field in editable_fields:
        if field in data:
            report[field] = data[field]

    prog.setdefault('assignedStaff', [])

    # Add newly involved staff to programme
    for staff_id in report.get('involvedStaff', []):
        if staff_id not in prog['assignedStaff']:
            prog['assignedStaff'].append(staff_id)

    report['editedAt'] = utc_now_iso()
    prog['updatedAt'] = utc_now_iso()
    save_error = save_or_500(programmes)
    if save_error:
        return save_error
    
    content_changes = []

    field_labels = {
        'hours': 'Hours of work',
        'status': 'Status',
        'priority': 'Priority',
        'summary': 'Summary'
    }

    for field, label in field_labels.items():
        old_value = str(old_values.get(field) or '')
        new_value = str(report.get(field) or '')

        if old_value != new_value:
            if field == 'status':
                content_changes.append(
                    f"Status: {format_status(old_value)} "
                    f"→ {format_status(new_value)}"
                )
            else:
                content_changes.append(label)

    new_involved = {
        str(staff_id).strip()
        for staff_id in report.get('involvedStaff', [])
        if str(staff_id).strip()
    }

    added_staff = sorted(new_involved - old_involved)
    removed_staff = sorted(old_involved - new_involved)

    if added_staff:
        content_changes.append(
            f"Involved staff added: {', '.join(added_staff)}"
        )

    if removed_staff:
        content_changes.append(
            f"Involved staff removed: {', '.join(removed_staff)}"
        )

    new_files = sorted(
        (
            str(file.get('name') or ''),
            str(file.get('path') or file.get('data') or ''),
            str(file.get('type') or ''),
            str(file.get('size') or '')
        )
        for file in report.get('files', [])
        if isinstance(file, dict)
    )

    if new_files != old_files:
        content_changes.append('Attachments')

    if content_changes:
        notify_daily_report_updated(
            programme=prog,
            report=report,
            updater_name=updater,
            changes=content_changes,
            exclude_staff_ids=added_staff
        )

    if added_staff:
        notify_staff_added_to_daily_report(
            programme=prog,
            report=report,
            added_staff_ids=added_staff,
            updater_name=updater
        )
    
    return jsonify({'programme': prog, 'report': report})


# ── Manager note on daily report ──────────────────────────────────────────────

@app.route(APP_ROOT + '/api/programmes/<prog_id>/reports/<report_id>/note', methods=['PUT'])
def manager_note(prog_id, report_id):
    session = get_session(request)
    if not session:
        return jsonify({'error': 'Not authenticated'}), 401

    # Auth check: managers only
    if session['role'] != 'manager':
        return jsonify({'error': 'Only managers can add notes'}), 403

    data = request.get_json(silent=True) or {}
    programmes = load_programmes()
    prog = next((p for p in programmes if p['id'] == prog_id), None)
    if not prog:
        return jsonify({'error': 'Programme not found'}), 404

    report = next((r for r in prog.get('dailyReports', []) if r['id'] == report_id), None)
    if not report:
        return jsonify({'error': 'Report not found'}), 404

    previous_note = str(
        report.get('managerNote') or ''
    ).strip()

    new_note = str(
        data.get("managerNote") or '').strip()
  
    report['managerNote'] = new_note
    prog['updatedAt'] = utc_now_iso()

    save_error = save_or_500(programmes)

    if save_error:
        return save_error
    
    if new_note:
        notify_manager_note_added(
            programme=prog,
            report=report,
            manager_name=session.get('name') or 'Manager',
            was_update=bool(previous_note)
        )


    return jsonify(report)

from flask import send_from_directory

@app.route(APP_ROOT + '/api/upload', methods=['POST'])
def upload_file():
    session, error_response, status_code = require_session(request)

    if error_response:
        return error_response, status_code
    
    if 'file' not in request.files:
        return jsonify({'error': 'No file'}), 400
    f = request.files['file']
    filename = secure_filename(f.filename)
    unique_name = uuid.uuid4().hex + '_' + filename
    f.save(os.path.join(UPLOAD_FOLDER, unique_name))
    return jsonify({'name': filename, 'path': f'/daily-report/uploads/{unique_name}'})

@app.route(APP_ROOT + '/uploads/<filename>')
def serve_upload(filename):
    return send_from_directory(UPLOAD_FOLDER, filename)

@app.errorhandler(404)
def not_found(e):
    return jsonify({'error': 'Not found'}), 404

# ── Email  ────────────────────────────────────────────────────────────────────
def send_email(to_addresses, subject, html_body):
    """Send an email and return (success, error_message)."""

    if not to_addresses:
        return False, 'No recipients supplied'

    try:
        msg = MIMEMultipart('alternative')
        msg['Subject'] = subject
        msg['From'] = formataddr((EMAIL_SENDER_NAME, EMAIL_SENDER))
        msg['To'] = ', '.join(to_addresses)
        msg.attach(MIMEText(html_body, 'html', 'utf-8'))

        with smtplib.SMTP(
            EMAIL_SMTP_HOST,
            EMAIL_SMTP_PORT,
            timeout=10
        ) as server:
            server.ehlo()
            server.starttls()
            server.ehlo()
            server.login(EMAIL_SENDER, EMAIL_PASSWORD)
            server.sendmail(
                EMAIL_SENDER,
                to_addresses,
                msg.as_string()
            )

        print(f"[EMAIL] Sent to {to_addresses}: {subject}")
        return True, None

    except Exception as error:
        error_message = str(error)
        print(f"[EMAIL ERROR] {error_message}")
        return False, error_message

EMAIL_EVENT_SETTING_KEYS = {
    'programme_created': 'notifyProgrammeCreated',
    'programme_updated':'notifyStatusUpdated',
    'daily_report_added': 'notifyDailyReportAdded',
    'daily_report_updated': 'notifyDailyReportAdded',
    'daily_report_staff_added': 'notifyDailyReportAdded',
    'status_updated': 'notifyStatusUpdated',
    'manager_note_added': 'notifyManagerNoteAdded',
}

def dispatch_notification_email(
    event_type,
    recipients,
    subject,
    html_body,
    programme_id=None,
    report_id=None
):
    """
    Check notification settings, create an audit log,
    and send the email asynchronously.
    """

    setting_key = EMAIL_EVENT_SETTING_KEYS.get(event_type)

    if not setting_key:
        raise ValueError(
            f'Unsupported email event type: {event_type}'
        )

    settings = load_email_settings_from_db()

    # Remove blanks and duplicates while preserving order.
    clean_recipients = []
    seen = set()

    for address in recipients or []:
        address = str(address or '').strip()
        normalized = address.lower()

        if address and normalized not in seen:
            seen.add(normalized)
            clean_recipients.append(address)

    email_enabled = settings.get('emailEnabled', False)
    event_enabled = settings.get(setting_key, False)

    log_id = create_email_log_in_db(
        event_type=event_type,
        recipients=clean_recipients,
        subject=subject,
        programme_id=programme_id,
        report_id=report_id,
    )

    if not email_enabled:
        if log_id:
            update_email_log_status_in_db(
                log_id,
                'skipped',
                'Email notifications are globally disabled'
            )

        return log_id

    if not event_enabled:
        if log_id:
            update_email_log_status_in_db(
                log_id,
                'skipped',
                f'Notification event is disabled: {event_type}'
            )

        return log_id

    if not clean_recipients:
        if log_id:
            update_email_log_status_in_db(
                log_id,
                'skipped',
                'No valid recipients'
            )

        return log_id

    def delivery_worker():
        success, error_message = send_email(
            clean_recipients,
            subject,
            html_body
        )

        if log_id:
            update_email_log_status_in_db(
                log_id,
                'sent' if success else 'failed',
                error_message
            )

    threading.Thread(
        target=delivery_worker,
        daemon=True,
        name=f'email-{event_type}'
    ).start()

    return log_id

def load_staff_email_directory():
    """Return active staff indexed by staff ID."""

    directory = {}

    for staff in load_staff():
        staff_id = str(staff.get('id') or '').strip()

        if staff_id:
            directory[staff_id] = staff

    return directory


def resolve_recipient_emails(
    staff_ids,
    staff_directory,
    exclude_ids=None,
    include_manager=False
):
    """Convert staff IDs into unique email addresses."""

    excluded = {
        str(staff_id).strip()
        for staff_id in (exclude_ids or [])
    }

    recipients = []

    for staff_id in staff_ids or []:
        staff_id = str(staff_id).strip()

        if not staff_id or staff_id in excluded:
            continue

        staff = staff_directory.get(staff_id, {})
        email = str(staff.get('email') or '').strip()

        if email:
            recipients.append(email)

    if include_manager:
        settings = load_email_settings_from_db()
        manager_email = str(
            settings.get('managerEmail') or ''
        ).strip()

        if manager_email:
            recipients.append(manager_email)

    return recipients



if __name__ == '__main__':
    app.run(
        host='127.0.0.1',
        port=5001,
        debug=False
    )