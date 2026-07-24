import pyodbc
import os, csv, json
from datetime import datetime, timezone

import uuid

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
EMAIL_SETTING_CODE = 'EMAIL_NOTIFICATION'

def _to_dt(value):
    if not value:
        return datetime.now(timezone.utc).replace(tzinfo=None)
    if isinstance(value, datetime):
        return value
    return datetime.fromisoformat(value.replace('Z', ''))

def _to_iso(value):
    if not value:
        return ''
    return value.isoformat() + 'Z'

def _hours(value):
    if value in (None, ''):
        return None
    return float(value)

def _clean(value):
    return str(value).strip() if value is not None else ''

def _build_conn_str(prefix, default_database):
    conn_str = (
        f"DRIVER={{{os.getenv(prefix + '_DRIVER', 'ODBC Driver 17 for SQL Server')}}};"
        f"SERVER={os.getenv(prefix + '_SERVER', 'localhost')};"
        f"DATABASE={os.getenv(prefix + '_DATABASE', default_database)};"
        f"UID={os.getenv(prefix + '_USERNAME', 'sa')};"
        f"PWD={os.getenv(prefix + '_PASSWORD', 'your_password')};"
        f"TrustServerCertificate={os.getenv(prefix + '_TRUST_CERTIFICATE', 'yes')};"
        f"Encrypt={os.getenv(prefix + '_ENCRYPT', 'no')};"
    )
    return pyodbc.connect(conn_str)

def get_mamsys_connection():
    print(f"[DB] Connecting to MAM_SYS: {os.getenv('MAMSYS_SERVER')}")
    return _build_conn_str('MAMSYS', 'MAM_SYS')

def get_dwr_connection():
    print(f"[DB] Connecting to DWR: {os.getenv('DWR_SERVER')}")
    return _build_conn_str('DWR', 'DWR')

# Backward-compatible default for existing login/staff helpers.
def get_db_connection():
    return get_mamsys_connection()

def load_staff_from_db():
    """Load staff/users from TBL_USR table"""
    staff = []
    try:
        conn = get_mamsys_connection()
        cursor = conn.cursor()
        
        # Adjust column names based on your actual TBL_USR structure
        cursor.execute("""
            SELECT USR_ID, USR_NAME, USR_MAIL
            FROM TBL_USR 
            WHERE USR_STS = 'A' AND USR_DEPT IN ('QE') AND (USR_ID LIKE 'S%' OR USR_ID LIKE 'MS%') AND ( USR_PIN_HASH IS NULL OR LOWER(LTRIM(RTRIM(USR_PIN_HASH))) <> 'inactive')
        """)
        
        for row in cursor.fetchall():
            staff.append({
                'id': row.USR_ID,
                'name': row.USR_NAME,
                'email': row.USR_MAIL,
                
            })
        
        cursor.close()
        conn.close()
        print(f"[DB] Loaded {len(staff)} staff records")
    except Exception as e:
        print(f"[DB ERROR] {e}")
        # Fallback to CSV if needed
        # return load_staff_from_csv()
    
    return staff

def find_staff_in_db(user_id):
    """Find specific staff by name"""
    try:
        conn = get_mamsys_connection()
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT USR_ID, USR_NAME, USR_MAIL
            FROM TBL_USR 
            WHERE USR_STS = 'A' AND USR_DEPT IN ('QE', 'MIS') AND (USR_ID LIKE 'S%' OR USR_ID LIKE 'MS%')  AND ( USR_PIN_HASH IS NULL OR LOWER(LTRIM(RTRIM(USR_PIN_HASH))) <> 'inactive') AND USR_ID = ?
        """, (user_id,))
        
        row = cursor.fetchone()
        cursor.close()
        conn.close()
        
        if row:
            return {'id': row.USR_ID,'name': row.USR_NAME, 'email': row.USR_MAIL}
    except Exception as e:
        print(f"[DB ERROR] {e}")
    
    return None

def verify_manager_pin_in_db():
  
    try:
        conn = get_mamsys_connection()
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT USR_PIN_HASH
            FROM TBL_USR 
            WHERE VC_USR_ROLE = 'MANAGER' AND USR_STS = 'A'
        """)
        
        row = cursor.fetchone()
        cursor.close()
        conn.close()
        
        if row and row.USR_PIN_HASH:
            return row.USR_PIN_HASH.strip()
    except Exception as e:
        print(f"[DB ERROR] {e}")
    
    return None

def load_manager_from_db():
  
    try:
        conn = get_mamsys_connection()
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT USR_ID, USR_NAME
            FROM TBL_USR 
            WHERE VC_USR_ROLE = 'MANAGER' AND USR_PIN_HASH IS NOT NULL AND USR_STS = 'A'
        """)
        
        row = cursor.fetchone()
        cursor.close()
        conn.close()
        
        if row:
            return { 
                'id': row.USR_ID,
                'name': row.USR_NAME
            }
    except Exception as e:
        print(f"[DB ERROR] {e}")
    
    return None

def find_superuser_in_db(user_id):
    conn = None
    cursor = None

    try:
        conn = get_mamsys_connection()
        cursor = conn.cursor()

        cursor.execute("""
                       SELECT USR_ID,USR_NAME,USR_MAIL
                       FROM TBL_USR WHERE USR_ID=? AND USR_DEPT = 'MIS' AND USR_STS='A'
                       """, (str(user_id).strip(),))
        
        row = cursor.fetchone()

        if not row:
            return None
        
        return {
            'id': str(row.USR_ID).strip(),
            'name': row.USR_NAME or '',
            'email': row.USR_MAIL or '',
        }

    except Exception as error:
        print(f"[DB ERROR] find_superuser_in_db: {error}")
        return None
    
    finally: 
        if cursor is not None:
            cursor.close()

        if conn is not None:
            conn.close()

                       

def load_staff_maps():
    staff = load_staff_from_db()
    by_id = {str(s['id']).strip(): s for s in staff}
    by_name = {s['name'].strip(): s for s in staff}
    return by_id, by_name

def _staff_id(value, by_id, by_name):
    value = _clean(value)
    if value in by_id:
        return value
    return _clean(by_name.get(value, {}).get('id', value))

def _staff_name(value, by_id, by_name):
    value = _clean(value)
    if value in by_id:
        return by_id[value].get('name', value)
    return by_name.get(value, {}).get('name', value)

def load_programmes_from_db():
    programmes = []
    conn = get_dwr_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT id, title, created_by, status, created_at, updated_at
        FROM ts_programme
        ORDER BY created_at DESC
    """)

    for p in cursor.fetchall():
        programme = {
            'id': p.id.strip(),
            'title': p.title,
            'createdBy': p.created_by,
            'assignedStaff': [],
            'status': p.status or '',
            'createdAt': _to_iso(p.created_at),
            'updatedAt': _to_iso(p.updated_at),
            'dailyReports': [],
        }

        cursor.execute("""
            SELECT usr_id
            FROM ml_programme_staff
            WHERE programme_id = ?
        """, (programme['id'],))

        programme['assignedStaff'] = [r.usr_id for r in cursor.fetchall()]

        cursor.execute("""
            SELECT id, usr_id, report_date, hours, status, priority, summary,
                   involved_staff, manager_note, edit_reason, edited_by,
                   submitted_at, edited_at
            FROM ts_daily_report
            WHERE programme_id = ?
            ORDER BY submitted_at DESC
        """, (programme['id'],))

        reports = cursor.fetchall()

        for r in reports:
            report_id = r.id.strip()

            try:
                involved = json.loads(r.involved_staff) if r.involved_staff else []
            except Exception:
                involved = []

            report = {
                'id': report_id,
                'staff': r.usr_id,
                'date': r.report_date.isoformat(),
                'hours': '' if r.hours is None else str(r.hours),
                'status': r.status,
                'priority': r.priority,
                'summary': r.summary,
                'involvedStaff': involved,
                'files': [],
                'submittedAt': _to_iso(r.submitted_at),
                'editedAt': _to_iso(r.edited_at),
                'managerNote': r.manager_note or '',
                'editReason': r.edit_reason or '',
                'editedBy': r.edited_by or '',
            }

            cursor.execute("""
                SELECT file_name, file_path, file_type, file_size
                FROM ts_daily_report_file
                WHERE daily_report_id = ?
            """, (report_id,))

            report['files'] = [
                {
                    'name': f.file_name,
                    'path': f.file_path,
                    'type': f.file_type,
                    'size': f.file_size,
                }
                for f in cursor.fetchall()
            ]

            programme['dailyReports'].append(report)

        programmes.append(programme)

    cursor.close()
    conn.close()
    return programmes

def save_programmes_to_db(programmes):
    staff_by_id, staff_by_name = load_staff_maps()
    conn = get_dwr_connection()
    cursor = conn.cursor()

    try:
        cursor.execute("""
            DELETE FROM ts_daily_report_file
            WHERE daily_report_id IN (SELECT id FROM ts_daily_report)
        """)
        cursor.execute("DELETE FROM ts_daily_report")
        cursor.execute("DELETE FROM ml_programme_staff")
        cursor.execute("DELETE FROM ts_programme")

        for p in programmes:
            cursor.execute("""
                INSERT INTO ts_programme
                (id, title, created_by, status, created_at, updated_at, update_by)
                VALUES (?, ?, ?, ?, ?, ?,?)
            """, (
                p['id'].upper(),
                p['title'],
                p.get('createdBy', ''),
                p.get('status', ''),
                _to_dt(p.get('createdAt')),
                _to_dt(p.get('updatedAt')),
                 p.get('createdBy', ''),
            ))

            for staff in p.get('assignedStaff', []):
                usr_id = _staff_id(staff, staff_by_id, staff_by_name)
                usr_name = _staff_name(staff, staff_by_id, staff_by_name)
                cursor.execute("""
                    INSERT INTO ml_programme_staff
                    (id, programme_id, usr_id, usr_name, created_at)
                    VALUES (?, ?, ?, ?, ?)
                """, (
                    __import__('uuid').uuid4().hex.upper(),
                    p['id'].upper(),
                    usr_id,
                    usr_name,
                    datetime.now(timezone.utc).replace(tzinfo=None),
                ))

            for r in p.get('dailyReports', []):
                report_usr_id = _staff_id(r.get('staff', ''), staff_by_id, staff_by_name)
                involved_staff = [
                    _staff_id(staff, staff_by_id, staff_by_name)
                    for staff in r.get('involvedStaff', [])
                ]
                cursor.execute("""
                    INSERT INTO ts_daily_report
                    (id, programme_id, usr_id, report_date, hours, status,
                     priority, summary, involved_staff, manager_note,
                     edit_reason, edited_by, submitted_at, edited_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    r['id'].upper(),
                    p['id'].upper(),
                    report_usr_id,
                    r.get('date'),
                    _hours(r.get('hours')),
                    r.get('status', 'in-progress'),
                    r.get('priority', 'middle'),
                    r.get('summary', ''),
                    json.dumps(involved_staff),
                    r.get('managerNote', ''),
                    r.get('editReason', ''),
                    r.get('editedBy', ''),
                    _to_dt(r.get('submittedAt')),
                    _to_dt(r.get('editedAt')) if r.get('editedAt') else None,
                ))

                for f in r.get('files', []):
                    cursor.execute("""
                        INSERT INTO ts_daily_report_file
                        (id, daily_report_id, file_name, file_path, file_type, file_size, uploaded_at)
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                    """, (
                        __import__('uuid').uuid4().hex.upper(),
                        r['id'].upper(),
                        f.get('name', ''),
                        f.get('path', ''),
                        f.get('type', ''),
                        f.get('size'),
                        datetime.now(timezone.utc).replace(tzinfo=None),
                    ))

        conn.commit()
        return True

    except Exception as e:
        conn.rollback()
        print(f"[DB ERROR] {e}")
        return False

    finally:
        cursor.close()
        conn.close()

def update_programme_in_db(programme_id, title=None, status=None):
    try:
        conn = get_dwr_connection()
        cursor = conn.cursor()

        updates = []
        params = []

        if title is not None:
            updates.append("title = ?")
            params.append(title)
        if status is not None:
            updates.append("status = ?")
            params.append(status)
        
        if not updates:
            return True
    
        updates.append("updated_at = GETUTCDATE()")
        params.append(programme_id)

        query = f"UPDATE ts_programme SET {','.join(updates)} WHERE id = ?"
        cursor.execute(query, params)
        conn.commit()

        cursor.close()
        conn.close()
        return True
    except Exception as e:
        print(f"[DB ERROR] update_programme: {e}")
        return False
    
def delete_programme_from_db(programme_id):
    
    conn = None
    cursor = None

    try:
        programme_id = str(programme_id or '' ).strip()

        if not programme_id:
            return False
        
        conn = get_dwr_connection()
        cursor = conn.cursor()

        cursor.execute(
            """
            DELETE FROM dbo.email_log
            WHERE programme_id = ?
            """,
            (programme_id,)
        )
        
        # Delete in correct order (child tables first)
        cursor.execute("""
            DELETE FROM ts_daily_report_file 
            WHERE daily_report_id IN (
                SELECT id FROM ts_daily_report WHERE programme_id = ?
            )
        """, (programme_id,))
        
        cursor.execute("DELETE FROM ts_daily_report WHERE programme_id = ?", (programme_id,))
        cursor.execute("DELETE FROM ml_programme_staff WHERE programme_id = ?", (programme_id,))
        cursor.execute("DELETE FROM ts_programme WHERE id = ?", (programme_id,))
        if cursor.rowcount != 1:
            conn.rollback()
            print(
                f"[DB ERROR] Programme not found during deletion: "
                f"{programme_id}"
            )
            return False
        
        conn.commit()
        return True
    except Exception as e:
        if conn is not None:
            conn.rollback()
        print(f"[DB ERROR] delete_programme: {e}")
        return False
    
    finally:
        if cursor is not None:
            cursor.close()

        if conn is not None:
            conn.close()
    
def update_report_in_db(report_id, data):
   
    try:
        conn = get_dwr_connection()
        cursor = conn.cursor()
        
        # Build dynamic UPDATE
        fields = []
        params = []
        
        if 'hours' in data:
            fields.append("hours = ?")
            params.append(data['hours'])
        if 'status' in data:
            fields.append("status = ?")
            params.append(data['status'])
        if 'priority' in data:
            fields.append("priority = ?")
            params.append(data['priority'])
        if 'summary' in data:
            fields.append("summary = ?")
            params.append(data['summary'])
        if 'managerNote' in data:
            fields.append("manager_note = ?")
            params.append(data['managerNote'])
        if 'editReason' in data:
            fields.append("edit_reason = ?")
            params.append(data['editReason'])
        if 'editedBy' in data:
            fields.append("edited_by = ?")
            params.append(data['editedBy'])
        if 'involvedStaff' in data:
            fields.append("involved_staff = ?")
            params.append(json.dumps(data['involvedStaff']))
        
        if not fields:
            return True
            
        fields.append("edited_at = GETUTCDATE()")
        params.append(report_id)
        
        query = f"UPDATE ts_daily_report SET {', '.join(fields)} WHERE id = ?"
        cursor.execute(query, params)
        conn.commit()
        
        cursor.close()
        conn.close()
        return True
    except Exception as e:
        print(f"[DB ERROR] update_report: {e}")
        return False

def delete_report_from_db(report_id):
    """Delete specific report and its files"""
    try:
        conn = get_dwr_connection()
        cursor = conn.cursor()
        
        # Delete files first
        cursor.execute("DELETE FROM ts_daily_report_file WHERE daily_report_id = ?", (report_id,))
        cursor.execute("DELETE FROM ts_daily_report WHERE id = ?", (report_id,))
        
        conn.commit()
        cursor.close()
        conn.close()
        return True
    except Exception as e:
        print(f"[DB ERROR] delete_report: {e}")
        return False
    
def add_staff_to_programme(programme_id, usr_id, usr_name):
    """Add a staff member to programme"""
    try:
        conn = get_dwr_connection()
        cursor = conn.cursor()
        
        cursor.execute("""
            INSERT INTO ml_programme_staff (id, programme_id, usr_id, usr_name, created_at)
            VALUES (?, ?, ?, ?, GETUTCDATE())
        """, (uuid.uuid4().hex.upper(), programme_id, usr_id, usr_name))
        
        conn.commit()
        cursor.close()
        conn.close()
        return True
    except Exception as e:
        print(f"[DB ERROR] add_staff: {e}")
        return False

def remove_staff_from_programme(programme_id, usr_id):
    """Remove a staff member from programme"""
    try:
        conn = get_dwr_connection()
        cursor = conn.cursor()
        
        cursor.execute("""
            DELETE FROM ml_programme_staff 
            WHERE programme_id = ? AND usr_id = ?
        """, (programme_id, usr_id))
        
        conn.commit()
        cursor.close()
        conn.close()
        return True
    except Exception as e:
        print(f"[DB ERROR] remove_staff: {e}")
        return False
    
def add_file_to_report(report_id, file_data):
    try:
        conn = get_dwr_connection()
        cursor = conn.cursor()
        
        cursor.execute("""
            INSERT INTO ts_daily_report_file 
            (id, daily_report_id, file_name, file_path, file_type, file_size, uploaded_at)
            VALUES (?, ?, ?, ?, ?, ?, GETUTCDATE())
        """, (
            uuid.uuid4().hex.upper(),
            report_id,
            file_data.get('name', ''),
            file_data.get('path', ''),
            file_data.get('type', ''),
            file_data.get('size')
        ))
        
        conn.commit()
        cursor.close()
        conn.close()
        return True
    except Exception as e:
        print(f"[DB ERROR] add_file: {e}")
        return False

def delete_file_from_report(file_id):

    try:
        conn = get_dwr_connection()
        cursor = conn.cursor()
        
        cursor.execute("DELETE FROM ts_daily_report_file WHERE id = ?", (file_id,))
        
        conn.commit()
        cursor.close()
        conn.close()
        return True
    except Exception as e:
        print(f"[DB ERROR] delete_file: {e}")
        return False

#Email Notification
def load_email_settings_from_db():
    default_settings = {
        'id': '',
        'settingCode': EMAIL_SETTING_CODE,
        'emailEnabled': False,
        'notifyProgrammeCreated': True,
        'notifyDailyReportAdded': True,
        'notifyStatusUpdated': True,
        'notifyManagerNoteAdded': True,
        'managerEmail': '',
        'updatedBy': '',
        'updatedAt': '',
    }

    conn = None
    cursor = None

    try:
        conn = get_dwr_connection()
        cursor = conn.cursor()

        cursor.execute("""
                       SELECT TOP (1) id, setting_code,
                        email_enabled,
                        notify_programme_created,
                        notify_daily_report_added,
                        notify_status_updated,
                        notify_manager_note_added,
                        manager_email,
                        updated_by,
                        updated_at
                    FROM dbo.email_settings
                    WHERE setting_code = ?
                """, (EMAIL_SETTING_CODE,))
        
        row = cursor.fetchone()

        if not row:
            print("[EMAIL SETTING] Configuration row not found")
            return default_settings
        
        return {
            'id': str(row.id).strip(),
            'settingCode': row.setting_code,
            'emailEnabled': bool(row.email_enabled),
            'notifyProgrammeCreated': bool(
                row.notify_programme_created
            ),
            'notifyDailyReportAdded': bool(
                row.notify_daily_report_added
            ),
            'notifyStatusUpdated': bool(
                row.notify_status_updated
            ),
            'notifyManagerNoteAdded': bool(
                row.notify_manager_note_added
            ),
            'managerEmail': row.manager_email or '',
            'updatedBy': row.updated_by or '',
            'updatedAt': (
                row.updated_at.isoformat() + 'Z'
                if row.updated_at
                else ''
            ),
        }
    
    except Exception as error:
        print(f"[EMAIL SETTINGS ERROR] {error}")
        return default_settings
    
    finally:
        if cursor is not None:
            cursor.close()

        if conn is not None:
            conn.close()


def update_email_settings_in_db(settings, updated_by):
    """Update the singleton email notification settings."""

    conn = None
    cursor = None

    try:
        conn = get_dwr_connection()
        cursor = conn.cursor()

        cursor.execute("""
            UPDATE dbo.email_settings
            SET
                email_enabled = ?,
                notify_programme_created = ?,
                notify_daily_report_added = ?,
                notify_status_updated = ?,
                notify_manager_note_added = ?,
                manager_email = ?,
                updated_by = ?,
                updated_at = SYSUTCDATETIME()
            WHERE setting_code = ?
        """, (
            int(bool(settings.get('emailEnabled'))),
            int(bool(settings.get('notifyProgrammeCreated'))),
            int(bool(settings.get('notifyDailyReportAdded'))),
            int(bool(settings.get('notifyStatusUpdated'))),
            int(bool(settings.get('notifyManagerNoteAdded'))),
            str(settings.get('managerEmail') or '').strip(),
            str(updated_by or '').strip(),
            EMAIL_SETTING_CODE,
        ))

        if cursor.rowcount != 1:
            conn.rollback()
            print("[EMAIL SETTINGS] Configuration row not found")
            return False

        conn.commit()
        return True

    except Exception as error:
        if conn is not None:
            conn.rollback()

        print(f"[EMAIL SETTINGS ERROR] Update failed: {error}")
        return False

    finally:
        if cursor is not None:
            cursor.close()

        if conn is not None:
            conn.close()

def create_email_log_in_db(
    event_type,
    recipients,
    subject,
    programme_id=None,
    report_id=None
):
    """Create a pending email log and return its 32-character ID."""

    log_id = uuid.uuid4().hex.upper()
    recipients_json = json.dumps(
        sorted(set(
            str(address).strip()
            for address in recipients
            if str(address).strip()
        ))
    )

    conn = None
    cursor = None

    try:
        conn = get_dwr_connection()
        cursor = conn.cursor()

        cursor.execute("""
            INSERT INTO dbo.email_log (
                id,
                event_type,
                programme_id,
                report_id,
                recipients,
                subject,
                delivery_status,
                error_message,
                created_at,
                completed_at
            )
            VALUES (?, ?, ?, ?, ?, ?, 'pending', NULL,
                    SYSUTCDATETIME(), NULL)
        """, (
            log_id,
            str(event_type).strip(),
            str(programme_id).strip() if programme_id else None,
            str(report_id).strip() if report_id else None,
            recipients_json,
            str(subject).strip(),
        ))

        conn.commit()
        return log_id

    except Exception as error:
        if conn is not None:
            conn.rollback()

        print(f"[EMAIL LOG ERROR] Could not create log: {error}")
        return None

    finally:
        if cursor is not None:
            cursor.close()

        if conn is not None:
            conn.close()

def update_email_log_status_in_db(
    log_id,
    delivery_status,
    error_message=None
):
    """Update the result of an email-delivery attempt."""

    allowed_statuses = {'sent', 'failed', 'skipped'}

    if delivery_status not in allowed_statuses:
        raise ValueError(
            f"Invalid email delivery status: {delivery_status}"
        )

    conn = None
    cursor = None

    try:
        conn = get_dwr_connection()
        cursor = conn.cursor()

        cursor.execute("""
            UPDATE dbo.email_log
            SET
                delivery_status = ?,
                error_message = ?,
                completed_at = SYSUTCDATETIME()
            WHERE id = ?
        """, (
            delivery_status,
            str(error_message)[:4000] if error_message else None,
            str(log_id).strip(),
        ))

        if cursor.rowcount != 1:
            conn.rollback()
            print(f"[EMAIL LOG] Log not found: {log_id}")
            return False

        conn.commit()
        return True

    except Exception as error:
        if conn is not None:
            conn.rollback()

        print(f"[EMAIL LOG ERROR] Could not update log: {error}")
        return False

    finally:
        if cursor is not None:
            cursor.close()

        if conn is not None:
            conn.close()

def load_email_logs_from_db(limit=100):
    """Load the latest email logs."""

    limit = max(1, min(int(limit), 500))

    conn = None
    cursor = None

    try:
        conn = get_dwr_connection()
        cursor = conn.cursor()

        cursor.execute(f"""
            SELECT TOP ({limit})
                id,
                event_type,
                programme_id,
                report_id,
                recipients,
                subject,
                delivery_status,
                error_message,
                created_at,
                completed_at
            FROM dbo.email_log
            ORDER BY created_at DESC
        """)

        logs = []

        for row in cursor.fetchall():
            try:
                recipients = json.loads(row.recipients or '[]')
            except (TypeError, json.JSONDecodeError):
                recipients = []

            logs.append({
                'id': str(row.id).strip(),
                'eventType': row.event_type,
                'programmeId': (
                    str(row.programme_id).strip()
                    if row.programme_id
                    else ''
                ),
                'reportId': (
                    str(row.report_id).strip()
                    if row.report_id
                    else ''
                ),
                'recipients': recipients,
                'subject': row.subject,
                'deliveryStatus': row.delivery_status,
                'errorMessage': row.error_message or '',
                'createdAt': (
                    row.created_at.isoformat() + 'Z'
                    if row.created_at
                    else ''
                ),
                'completedAt': (
                    row.completed_at.isoformat() + 'Z'
                    if row.completed_at
                    else ''
                ),
            })

        return logs

    except Exception as error:
        print(f"[EMAIL LOG ERROR] Could not load logs: {error}")
        return []

    finally:
        if cursor is not None:
            cursor.close()

        if conn is not None:
            conn.close()

# # Fallback to CSV if database fails
# def load_staff_from_csv():
#     """Original CSV loading as fallback"""
#     staff = []
#     try:
#         with open(STAFF_CSV, newline='', encoding='utf-8') as f:
#             reader = csv.DictReader(f)
#             for row in reader:
#                 name = row.get('name', '').strip()
#                 email = row.get('email', '').strip()
#                 if name:
#                     staff.append({'name': name, 'email': email})
#     except FileNotFoundError:
#         pass
#     return staff
