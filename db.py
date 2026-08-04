import pyodbc
import os, csv, json,uuid
from datetime import datetime, timezone
from dotenv import load_dotenv

load_dotenv()

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
EMAIL_SETTING_CODE = 'EMAIL_NOTIFICATION'
ENCRYPTION_DLL_PATH = os.path.abspath(
    os.getenv(
        'ENCRYPTION_DLL_PATH',
    os.path.join(BASE_DIR, 'lib','MAM_Encryption.dll')
    )
   
)

_mam_encryption = None

def _get_mam_encryption():
    """Load MAM_Encryption.dll once and return its public module."""

    global _mam_encryption

    if _mam_encryption is not None:
        return _mam_encryption

    if not os.path.isfile(ENCRYPTION_DLL_PATH):
        raise RuntimeError(
            f'MAM encryption DLL was not found: {ENCRYPTION_DLL_PATH}'
        )

    try:
        import clr
    except ImportError as exc:
        raise RuntimeError(
            'pythonnet is required to load MAM_Encryption.dll'
        ) from exc

    try:
        clr.AddReference(ENCRYPTION_DLL_PATH)
        from MTP import mod_General
    except Exception as exc:
        raise RuntimeError(
            f'Unable to load MAM encryption DLL: {ENCRYPTION_DLL_PATH}'
        ) from exc

    _mam_encryption = mod_General
    return _mam_encryption


def encrypt_password(plain_password):
    """Encrypt a password using MAM_Encryption.dll."""

    if plain_password is None:
        raise ValueError('Password cannot be None')

    mam_encryption = _get_mam_encryption()

    try:
        encrypted = mam_encryption.Encrypt(str(plain_password))
    except Exception as exc:
        raise RuntimeError(
            'MAM password encryption failed'
        ) from exc

    if encrypted is None:
        raise RuntimeError(
            'MAM password encryption returned an empty result'
        )

    return str(encrypted)


def decrypt_password(encrypted_password):
    """Decrypt a DWR_PWD value using MAM_Encryption.dll."""

    if encrypted_password is None:
        raise ValueError('Encrypted password cannot be None')

    encrypted_password = str(encrypted_password).strip()

    if not encrypted_password:
        raise ValueError('Encrypted password cannot be empty')

    mam_encryption = _get_mam_encryption()

    try:
        decrypted = mam_encryption.Decrypt(encrypted_password)
    except Exception as exc:
        raise RuntimeError(
            'MAM password decryption failed'
        ) from exc

    if decrypted is None:
        raise RuntimeError(
            'MAM password decryption returned an empty result'
        )

    return str(decrypted)

def get_user_encrypted_password_in_db(user_id):
    """Retrieve the current encrypted DWR_PWD for an active user."""

    conn = None
    cursor = None

    try:
        clean_user_id = str(user_id or '').strip()

        if not clean_user_id:
            return None

        conn = get_mamsys_connection()
        cursor = conn.cursor()

        cursor.execute("""
            SELECT DWR_PWD
            FROM TBL_USR
            WHERE USR_ID = ?
              AND USR_STS = 'A'
              AND DWR_PWD IS NOT NULL
              AND LTRIM(RTRIM(DWR_PWD)) <> ''
              AND LOWER(LTRIM(RTRIM(DWR_PWD))) <> 'inactive'
        """, (clean_user_id,))

        row = cursor.fetchone()

        if not row or not row.DWR_PWD:
            return None

        return str(row.DWR_PWD).strip()

    except Exception as exc:
        print(
            f'[DB ERROR] Unable to retrieve user password: {exc}'
        )
        return None

    finally:
        if cursor is not None:
            cursor.close()

        if conn is not None:
            conn.close()


def change_user_password_in_db(
    user_id,
    current_encrypted_password,
    new_encrypted_password
):
    """
    Change DWR_PWD only when the current encrypted value still matches.

    Checking the previous value prevents another request from
    overwriting a password that was changed concurrently.
    """

    conn = None
    cursor = None

    try:
        clean_user_id = str(user_id or '').strip()
        current_encrypted = str(
            current_encrypted_password or ''
        ).strip()
        new_encrypted = str(
            new_encrypted_password or ''
        ).strip()

        if (
            not clean_user_id
            or not current_encrypted
            or not new_encrypted
        ):
            return False

        conn = get_mamsys_connection()
        cursor = conn.cursor()

        cursor.execute("""
            UPDATE TBL_USR
            SET DWR_PWD = ?
            WHERE USR_ID = ?
              AND USR_STS = 'A'
              AND DWR_PWD = ?
        """, (
            new_encrypted,
            clean_user_id,
            current_encrypted
        ))

        changed = cursor.rowcount == 1
        conn.commit()

        return changed

    except Exception as exc:
        if conn is not None:
            conn.rollback()

        print(
            f'[DB ERROR] Unable to change user password: {exc}'
        )

        raise

    finally:
        if cursor is not None:
            cursor.close()

        if conn is not None:
            conn.close()

def get_staff_auth_record(user_id):
    """Retrieve a normal staff record for authentication."""

    conn = None
    cursor = None

    try:
        clean_user_id = str(user_id or '').strip()

        if not clean_user_id:
            return None

        conn = get_mamsys_connection()
        cursor = conn.cursor()

        cursor.execute("""
            SELECT
                USR_ID,
                USR_NAME,
                USR_MAIL,
                DWR_PWD
            FROM TBL_USR
            WHERE USR_ID = ?
              AND USR_STS = 'A'
              AND USR_DEPT IN ('QE', 'MIS')
              AND (USR_ID LIKE 'S%' OR USR_ID LIKE 'MS%' OR USR_ID = 'D8798')
              AND (
                    VC_USR_ROLE IS NULL
                    OR VC_USR_ROLE <> 'MANAGER'
                  )
              AND (
                    DWR_PWD IS NULL
                    OR LOWER(LTRIM(RTRIM(DWR_PWD))) <> 'inactive'
                  )
        """, (clean_user_id,))

        row = cursor.fetchone()

        if not row:
            return None

        encrypted_password = None

        if row.DWR_PWD is not None:
            encrypted_password = str(row.DWR_PWD).strip() or None

        return {
            'id': str(row.USR_ID).strip(),
            'name': str(row.USR_NAME).strip(),
            'email': str(row.USR_MAIL or '').strip(),
            'encrypted_password': encrypted_password
        }

    except Exception as exc:
        print(
            f'[DB ERROR] Unable to retrieve staff credentials: {exc}'
        )
        return None

    finally:
        if cursor is not None:
            cursor.close()

        if conn is not None:
            conn.close()


def create_staff_password_in_db(user_id, encrypted_password):
    """
    Create a first-time staff password.

    Existing passwords cannot be changed using this function.
    """

    conn = None
    cursor = None

    try:
        clean_user_id = str(user_id or '').strip()
        clean_password = str(encrypted_password or '').strip()

        if not clean_user_id or not clean_password:
            return False

        conn = get_mamsys_connection()
        cursor = conn.cursor()

        cursor.execute("""
            UPDATE TBL_USR
            SET DWR_PWD = ?
            WHERE USR_ID = ?
              AND USR_STS = 'A'
              AND USR_DEPT IN ('QE', 'MIS')
              AND (USR_ID LIKE 'S%' OR USR_ID LIKE 'MS%'OR USR_ID = 'D8798')
              AND (
                    VC_USR_ROLE IS NULL
                    OR VC_USR_ROLE <> 'MANAGER'
                  )
              AND (
                    DWR_PWD IS NULL
                    OR LTRIM(RTRIM(DWR_PWD)) = ''
                  )
        """, (
            clean_password,
            clean_user_id
        ))

        password_created = cursor.rowcount == 1

        conn.commit()

        return password_created

    except Exception as exc:
        if conn is not None:
            conn.rollback()

        print(
            f'[DB ERROR] Unable to create staff password: {exc}'
        )

        raise

    finally:
        if cursor is not None:
            cursor.close()

        if conn is not None:
            conn.close()

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
            WHERE USR_STS = 'A' AND USR_DEPT IN ('QE') AND (USR_ID LIKE 'S%' OR USR_ID LIKE 'MS%'OR USR_ID = 'D8798') AND ( DWR_PWD IS NULL OR LOWER(LTRIM(RTRIM(DWR_PWD))) <> 'inactive')
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
            WHERE USR_STS = 'A' AND USR_DEPT IN ('QE', 'MIS') AND (USR_ID LIKE 'S%' OR USR_ID LIKE 'MS%'OR USR_ID = 'D8798')  AND ( DWR_PWD IS NULL OR LOWER(LTRIM(RTRIM(DWR_PWD))) <> 'inactive') AND USR_ID = ?
        """, (user_id,))
        
        row = cursor.fetchone()
        cursor.close()
        conn.close()
        
        if row:
            return {'id': row.USR_ID,'name': row.USR_NAME, 'email': row.USR_MAIL}
    except Exception as e:
        print(f"[DB ERROR] {e}")
    
    return None

def load_managers_for_auth():
    """
    Return all active managers with an encrypted DWR_PWD.
    """

    conn = None
    cursor = None

    try:
        conn = get_mamsys_connection()
        cursor = conn.cursor()

        cursor.execute("""
            SELECT
                USR_ID,
                USR_NAME,
                USR_MAIL,
                DWR_PWD
            FROM TBL_USR
            WHERE VC_USR_ROLE LIKE '%MANAGER%'
              AND USR_STS = 'A'
              AND DWR_PWD IS NOT NULL
              AND LTRIM(RTRIM(DWR_PWD)) <> ''
              AND LOWER(LTRIM(RTRIM(DWR_PWD))) <> 'inactive'
            ORDER BY USR_ID
        """)

        managers = []

        for row in cursor.fetchall():
            managers.append({
                'id': str(row.USR_ID).strip(),
                'name': str(row.USR_NAME or '').strip(),
                'email': str(row.USR_MAIL or '').strip(),
                'encrypted_password': str(
                    row.DWR_PWD
                ).strip()
            })

        return managers

    except Exception as exc:
        print(
            f'[DB ERROR] Unable to load managers: {exc}'
        )

        return []

    finally:
        if cursor is not None:
            cursor.close()

        if conn is not None:
            conn.close()

def load_superusers_for_auth():
    """
    Return active MIS superusers that have an encrypted DWR_PWD.

    DWR_PWD is returned only for server-side authentication.
    """

    conn = None
    cursor = None

    try:
        conn = get_mamsys_connection()
        cursor = conn.cursor()

        cursor.execute("""
            SELECT
                USR_ID,
                USR_NAME,
                USR_MAIL,
                DWR_PWD
            FROM TBL_USR
            WHERE USR_DEPT = 'MIS'
              AND USR_STS = 'A'
              AND DWR_PWD IS NOT NULL
              AND LTRIM(RTRIM(DWR_PWD)) <> ''
              AND LOWER(LTRIM(RTRIM(DWR_PWD))) <> 'inactive'
              AND VC_USR_ROLE = 'SUPERUSER'
        """)

        superusers = []

        for row in cursor.fetchall():
            superusers.append({
                'id': str(row.USR_ID).strip(),
                'name': str(row.USR_NAME).strip(),
                'email': str(row.USR_MAIL or '').strip(),
                'encrypted_password': str(
                    row.DWR_PWD
                ).strip()
            })

        return superusers

    except Exception as exc:
        print(
            f'[DB ERROR] Unable to load superusers: {exc}'
        )

        return []

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
