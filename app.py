from flask import Flask, render_template, url_for, request, redirect, session, flash, jsonify, Response, send_from_directory, has_request_context
import sqlite3
import html
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.utils import safe_join
import os
import re
import secrets
import smtplib
import logging
import uuid
from email.message import EmailMessage
from urllib.parse import urlparse
from zoneinfo import ZoneInfo

from dotenv import load_dotenv
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.utils import secure_filename
import time
from datetime import datetime, timedelta

from decorators import login_required, admin_required

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'mungstagram_dev_secret_key_change_me')
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)
logger = logging.getLogger(__name__)

APP_ENV = os.getenv('APP_ENV', 'development').strip().lower() or 'development'
IS_PRODUCTION = APP_ENV == 'production'
DATABASE_URL = os.getenv('DATABASE_URL', 'sqlite:///mungstagram.db').strip() or 'sqlite:///mungstagram.db'
UPLOAD_FOLDER = 'static/uploads'
DIARY_UPLOAD_FOLDER = os.path.join(UPLOAD_FOLDER, 'diary')
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp'}
ALLOWED_IMAGE_MIME_TYPES = {'image/jpeg', 'image/png', 'image/gif', 'image/webp'}
MAX_IMAGE_SIZE_BYTES = 10 * 1024 * 1024
PET_PERSONALITY_OPTIONS = ['온순함', '활발함', '사교적임', '애교쟁이', '겁이 많음', '독립적임']
USERNAME_PATTERN = re.compile(r'^[a-z0-9_]{4,20}$')
EMAIL_PATTERN = re.compile(r'^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$')
SIGNUP_USERNAME_PATTERN = re.compile(r'^[a-z][a-z0-9]{1,12}$')
SIGNUP_NAME_PATTERN = re.compile(r'^[가-힣a-zA-Z]{1,14}$')
SIGNUP_PASSWORD_PATTERN = re.compile(r'^(?=.*[A-Za-z])(?=.*\d)(?=.*[!@#$%^&*])[A-Za-z\d!@#$%^&*]{8,29}$')
SIGNUP_EMAIL_PATTERN = re.compile(r'^[0-9a-zA-Z]([_.-]?[0-9a-zA-Z])*@[0-9a-zA-Z]([_.-]?[0-9a-zA-Z])*\.[a-zA-Z]{2,3}$')
PHONE_PATTERN = re.compile(r'^010-\d{4}-\d{4}$')
VERIFICATION_CODE_LENGTH = 6
VERIFICATION_EXPIRY_MINUTES = 5
VERIFICATION_RESEND_COOLDOWN_SECONDS = 60
VERIFICATION_MAX_ATTEMPTS = 5
SSL_CERT_FILE = os.getenv('SSL_CERT_FILE', '').strip()
SSL_KEY_FILE = os.getenv('SSL_KEY_FILE', '').strip()
UTC_TZ = ZoneInfo('UTC')
KST_TZ = ZoneInfo('Asia/Seoul')
XSS_PATTERNS = (
    re.compile(r'<\s*/?\s*(script|img|svg|iframe|object|embed|link|meta|style)\b', re.IGNORECASE),
    re.compile(r'on\w+\s*=', re.IGNORECASE),
    re.compile(r'javascript\s*:', re.IGNORECASE),
    re.compile(r'<[^>]+>', re.IGNORECASE),
)
SQLI_PATTERNS = (
    re.compile(r'\b(?:select|insert|update|delete|drop|alter|union)\b', re.IGNORECASE),
    re.compile(r"(?:'|\")?\s*or\s+(?:'?\d+'?\s*=\s*'?\d+'?|'.*'\s*=\s*'.*'|\".*\"\s*=\s*\".*\")", re.IGNORECASE),
    re.compile(r'--'),
    re.compile(r';\s*--', re.IGNORECASE),
    re.compile(r'/\*|\*/'),
    re.compile(r'@@'),
    re.compile(r'\b(?:char|nchar|varchar|nvarchar)\s*\(', re.IGNORECASE),
)

def resolve_database_path():
    if DATABASE_URL.startswith('sqlite:///'):
        return DATABASE_URL.replace('sqlite:///', '', 1)
    logger.warning('Unsupported DATABASE_URL for current SQLite build: %s. Falling back to mungstagram.db', DATABASE_URL)
    return 'mungstagram.db'

DATABASE = resolve_database_path()

# Security logging: security event storage schema for SQLite
CREATE_SECURITY_LOGS_TABLE_SQL = '''
    CREATE TABLE IF NOT EXISTS security_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        occurred_at TEXT NOT NULL,
        attack_type TEXT NOT NULL,
        request_ip TEXT,
        request_url TEXT,
        request_method TEXT,
        user_identifier TEXT NOT NULL,
        input_preview TEXT,
        blocked INTEGER NOT NULL DEFAULT 1,
        reason TEXT NOT NULL
    )
'''
CREATE_SECURITY_LOGS_OCCURRED_AT_INDEX_SQL = '''
    CREATE INDEX IF NOT EXISTS idx_security_logs_occurred_at
    ON security_logs(occurred_at DESC, id DESC)
'''
INSERT_SECURITY_LOG_SQL = '''
    INSERT INTO security_logs (
        occurred_at,
        attack_type,
        request_ip,
        request_url,
        request_method,
        user_identifier,
        input_preview,
        blocked,
        reason
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
'''

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_SECURE'] = IS_PRODUCTION

limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=[],
    storage_uri='memory://'
)

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)
if not os.path.exists(DIARY_UPLOAD_FOLDER):
    os.makedirs(DIARY_UPLOAD_FOLDER)

def create_security_logs_table(conn):
    # Security logging: isolated schema creation for report and migration use
    conn.execute(CREATE_SECURITY_LOGS_TABLE_SQL)
    conn.execute(CREATE_SECURITY_LOGS_OCCURRED_AT_INDEX_SQL)

def build_security_input_preview(*values):
    previews = []
    for value in values:
        if value is None:
            continue
        if isinstance(value, (list, tuple, set)):
            for item in value:
                if item is not None:
                    previews.append(str(item).strip())
            continue
        previews.append(str(value).strip())

    joined = ' | '.join(part for part in previews if part)
    return sanitize_input(joined)[:200] if joined else ''

def get_security_user_identifier():
    if not has_request_context():
        return 'guest'
    if session.get('user_id'):
        return str(session['user_id'])
    return 'guest'

def get_security_request_metadata():
    if not has_request_context():
        return {
            'request_ip': 'unknown',
            'request_url': '',
            'request_method': '',
            'user_identifier': get_security_user_identifier()
        }

    return {
        'request_ip': request.headers.get('X-Forwarded-For', request.remote_addr or '').split(',')[0].strip() or 'unknown',
        'request_url': request.url,
        'request_method': request.method,
        'user_identifier': get_security_user_identifier()
    }

def save_security_log(attack_type, input_preview='', blocked=True, reason=''):
    # Security logging: centralized persistence function used by all detection points
    metadata = get_security_request_metadata()
    occurred_at = datetime.now(KST_TZ).strftime('%Y-%m-%d %H:%M:%S')

    try:
        conn = sqlite3.connect(DATABASE)
        conn.execute(
            INSERT_SECURITY_LOG_SQL,
            (
                occurred_at,
                attack_type,
                metadata['request_ip'],
                metadata['request_url'],
                metadata['request_method'],
                metadata['user_identifier'],
                input_preview,
                1 if blocked else 0,
                reason
            )
        )
        conn.commit()
        conn.close()
    except sqlite3.Error:
        logger.exception('Failed to persist security log')

def log_abnormal_api_request(reason, input_preview=''):
    save_security_log(
        'ABNORMAL_API_CALL',
        input_preview=build_security_input_preview(input_preview),
        blocked=True,
        reason=reason
    )

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def validate_image_file(file_storage):
    if not file_storage or not file_storage.filename:
        return

    if not allowed_file(file_storage.filename):
        save_security_log(
            'FILE_UPLOAD_ATTACK',
            input_preview=build_security_input_preview(file_storage.filename, file_storage.mimetype),
            blocked=True,
            reason='허용되지 않은 이미지 확장자 업로드 시도'
        )
        raise ValueError('이미지 파일만 업로드 가능합니다.')

    mimetype = (file_storage.mimetype or '').lower()
    if mimetype not in ALLOWED_IMAGE_MIME_TYPES:
        save_security_log(
            'FILE_UPLOAD_ATTACK',
            input_preview=build_security_input_preview(file_storage.filename, mimetype),
            blocked=True,
            reason='허용되지 않은 MIME 타입 업로드 시도'
        )
        raise ValueError('이미지 파일만 업로드 가능합니다.')

    stream = file_storage.stream
    current_position = stream.tell()
    stream.seek(0, os.SEEK_END)
    file_size = stream.tell()
    stream.seek(current_position)

    if file_size > MAX_IMAGE_SIZE_BYTES:
        save_security_log(
            'FILE_UPLOAD_ATTACK',
            input_preview=build_security_input_preview(file_storage.filename, f'{file_size} bytes'),
            blocked=True,
            reason='허용 크기를 초과한 파일 업로드 시도'
        )
        raise ValueError('파일 크기는 10MB 이하만 업로드 가능합니다.')

def normalize_username_value(value):
    return (value or '').strip().lower()

def is_valid_username(value):
    return bool(USERNAME_PATTERN.match(normalize_username_value(value)))

def normalize_email(value):
    return (value or '').strip().lower()

def is_valid_email(value):
    return bool(EMAIL_PATTERN.match(normalize_email(value)))

def is_valid_signup_username(value):
    return bool(SIGNUP_USERNAME_PATTERN.match(normalize_username_value(value)))

def is_valid_signup_name(value):
    return bool(SIGNUP_NAME_PATTERN.match((value or '').strip()))

def is_valid_signup_password(value):
    return bool(SIGNUP_PASSWORD_PATTERN.match(value or ''))

def is_valid_signup_email(value):
    email = normalize_email(value)
    return len(email) < 30 and bool(SIGNUP_EMAIL_PATTERN.match(email))

def is_valid_phone_number(value):
    return bool(PHONE_PATTERN.match((value or '').strip()))

def sanitize_input(value):
    return html.escape(str(value or ''), quote=True)

def detect_xss(value):
    if value is None:
        return False

    normalized = str(value).strip()
    if not normalized:
        return False

    for _ in range(2):
        decoded = html.unescape(normalized)
        if decoded == normalized:
            break
        normalized = decoded

    lowered = normalized.lower()
    matched = any(pattern.search(lowered) for pattern in XSS_PATTERNS)
    if matched:
        save_security_log(
            'XSS',
            input_preview=build_security_input_preview(normalized),
            blocked=True,
            reason='XSS 패턴이 포함된 입력 감지'
        )
        logger.warning('Potential XSS payload blocked on %s: %s', request.path, sanitize_input(normalized)[:200])
    return matched

def contains_xss(*values):
    return any(detect_xss(value) for value in values)

def detect_sqli(value):
    if value is None:
        return False

    normalized = str(value).strip()
    if not normalized:
        return False

    matched = any(pattern.search(normalized) for pattern in SQLI_PATTERNS)
    if matched:
        save_security_log(
            'SQL_INJECTION',
            input_preview=build_security_input_preview(normalized),
            blocked=True,
            reason='SQL Injection 패턴이 포함된 입력 감지'
        )
        logger.warning('Potential SQLi payload blocked on %s: %s', request.path, sanitize_input(normalized)[:200])
    return matched

def contains_sqli(*values):
    return any(detect_sqli(value) for value in values)

def block_sqli_form():
    return alert_and_back('비정상적인 입력이 감지되었습니다.')

def block_sqli_ajax():
    return jsonify({'error': '비정상적인 요청입니다.'}), 400

def alert_and_back(message):
    escaped_message = (
        (message or '')
        .replace('\\', '\\\\')
        .replace("'", "\\'")
        .replace('\n', '\\n')
    )
    return Response(
        f"<script>alert('{escaped_message}'); history.go(-1);</script>",
        mimetype='text/html'
    )

def alert_and_redirect(message, target_url):
    escaped_message = (
        (message or '')
        .replace('\\', '\\\\')
        .replace("'", "\\'")
        .replace('\n', '\\n')
    )
    return Response(
        f"<script>alert('{escaped_message}'); window.location.href = '{target_url}';</script>",
        mimetype='text/html'
    )

def diary_login_required_response():
    return alert_and_redirect('로그인 후 이용 가능합니다.', url_for('login'))

def get_csp_policy():
    directives = {
        'default-src': "'self'",
        'script-src': "'self' 'unsafe-inline' https://unpkg.com",
        'style-src': "'self' 'unsafe-inline' https://fonts.googleapis.com https://unpkg.com",
        'img-src': "'self' data: https: https://tile.openstreetmap.org",
        'font-src': "'self' https://fonts.gstatic.com",
        'connect-src': "'self'",
        'object-src': "'none'",
        'base-uri': "'self'",
        'form-action': "'self'",
        'frame-ancestors': "'none'"
    }
    if IS_PRODUCTION:
        directives['upgrade-insecure-requests'] = ''

    return '; '.join(
        f"{name} {value}".strip()
        for name, value in directives.items()
    )

def build_ssl_context():
    if not SSL_CERT_FILE or not SSL_KEY_FILE:
        return None
    if not os.path.exists(SSL_CERT_FILE) or not os.path.exists(SSL_KEY_FILE):
        logger.warning('SSL certificate file not found. cert=%s key=%s', SSL_CERT_FILE, SSL_KEY_FILE)
        return None
    return (SSL_CERT_FILE, SSL_KEY_FILE)

def get_post_upload_filename(image_url):
    if not image_url:
        return None

    parsed_path = urlparse(str(image_url)).path
    uploads_prefix = url_for('static', filename='uploads/').rstrip('/') + '/'
    if not parsed_path.startswith(uploads_prefix):
        return None

    relative_path = parsed_path[len(uploads_prefix):]
    filename = os.path.basename(relative_path)
    if not filename or filename != relative_path or not allowed_file(filename):
        return None
    return filename

def utcnow():
    return datetime.now(UTC_TZ).replace(microsecond=0)

def kst_now():
    return datetime.now(KST_TZ).replace(microsecond=0)

def format_db_timestamp(value):
    if not value:
        return None
    if isinstance(value, datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=UTC_TZ)
        value = value.astimezone(UTC_TZ)
        return value.replace(microsecond=0, tzinfo=None).isoformat(sep=' ')
    return str(value)

def parse_db_timestamp(value):
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value))
        if parsed.tzinfo is None:
            return parsed.replace(tzinfo=UTC_TZ)
        return parsed.astimezone(UTC_TZ)
    except ValueError:
        pass

    for fmt in ('%Y-%m-%d %H:%M:%S', '%Y-%m-%dT%H:%M:%S'):
        try:
            return datetime.strptime(str(value), fmt).replace(tzinfo=UTC_TZ)
        except ValueError:
            continue
    return None

def to_kst(value):
    parsed = parse_db_timestamp(value)
    if not parsed:
        return None
    return parsed.astimezone(KST_TZ)

def get_kst_day_bounds_utc(target=None):
    target_kst = target.astimezone(KST_TZ) if isinstance(target, datetime) and target.tzinfo else (target or kst_now())
    start_kst = target_kst.replace(hour=0, minute=0, second=0, microsecond=0)
    end_kst = start_kst + timedelta(days=1)
    return start_kst.astimezone(UTC_TZ), end_kst.astimezone(UTC_TZ)

def clear_signup_verification_session():
    session.pop('verified_signup_email', None)
    session.pop('verified_signup_at', None)

def parse_env_bool(name, default=False):
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {'1', 'true', 'yes', 'on'}

def get_mail_settings():
    settings = {
        'server': os.getenv('MAIL_SERVER', '').strip(),
        'port': os.getenv('MAIL_PORT', '').strip(),
        'username': os.getenv('MAIL_USERNAME', '').strip(),
        'password': os.getenv('MAIL_PASSWORD', '').strip(),
        'use_tls': parse_env_bool('MAIL_USE_TLS', True),
        'use_ssl': parse_env_bool('MAIL_USE_SSL', False),
        'default_sender': os.getenv('MAIL_DEFAULT_SENDER', '').strip()
    }
    required_fields = {
        'MAIL_SERVER': settings['server'],
        'MAIL_PORT': settings['port'],
        'MAIL_USERNAME': settings['username'],
        'MAIL_PASSWORD': settings['password'],
        'MAIL_DEFAULT_SENDER': settings['default_sender']
    }
    missing = [key for key, value in required_fields.items() if not value]
    if missing:
        raise RuntimeError(
            '이메일 발송 설정이 비어 있습니다. .env에 '
            + ', '.join(missing)
            + ' 값을 설정해 주세요.'
        )
    if settings['use_tls'] and settings['use_ssl']:
        raise RuntimeError('MAIL_USE_TLS와 MAIL_USE_SSL은 동시에 사용할 수 없습니다.')
    try:
        settings['port'] = int(settings['port'])
    except ValueError as exc:
        raise RuntimeError('MAIL_PORT는 숫자로 설정해 주세요.') from exc
    return settings

def is_mail_configured():
    try:
        get_mail_settings()
        return True
    except RuntimeError as exc:
        logger.warning('Mail configuration unavailable: %s', exc)
        return False

def generate_verification_code():
    upper_bound = 10 ** VERIFICATION_CODE_LENGTH
    return f'{secrets.randbelow(upper_bound):0{VERIFICATION_CODE_LENGTH}d}'

def send_signup_verification_email(recipient_email, code):
    settings = get_mail_settings()
    message = EmailMessage()
    message['Subject'] = '[멍스타그램] 이메일 인증번호 안내'
    message['From'] = settings['default_sender']
    message['To'] = recipient_email
    message.set_content(
        '\n'.join([
            '안녕하세요, 멍스타그램입니다.',
            '',
            '아래 인증번호를 입력하고 회원가입을 완료해 주세요.',
            '',
            f'인증번호: {code}',
            '',
            f'본 인증번호는 {VERIFICATION_EXPIRY_MINUTES}분 후 만료됩니다.',
            '',
            '본인이 요청하지 않았다면 이 메일을 무시해 주세요.'
        ])
    )

    if settings['use_ssl']:
        with smtplib.SMTP_SSL(settings['server'], settings['port']) as server:
            server.login(settings['username'], settings['password'])
            server.send_message(message)
    else:
        with smtplib.SMTP(settings['server'], settings['port']) as server:
            server.ehlo()
            if settings['use_tls']:
                server.starttls()
                server.ehlo()
            server.login(settings['username'], settings['password'])
            server.send_message(message)

def generate_temporary_password(length=10):
    alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%^&*'
    while True:
        candidate = ''.join(secrets.choice(alphabet) for _ in range(length))
        if (
            re.search(r'[A-Za-z]', candidate)
            and re.search(r'\d', candidate)
            and re.search(r'[!@#$%^&*]', candidate)
        ):
            return candidate

def send_temporary_password_email(recipient_email, temp_password):
    settings = get_mail_settings()
    message = EmailMessage()
    message['Subject'] = '[멍스타그램] 임시 비밀번호 안내'
    message['From'] = settings['default_sender']
    message['To'] = recipient_email
    message.set_content(
        '\n'.join([
            '안녕하세요, 멍스타그램입니다.',
            '',
            '요청하신 임시 비밀번호는 아래와 같습니다.',
            '',
            f'임시 비밀번호: {temp_password}',
            '',
            '로그인 후 반드시 비밀번호를 변경해주세요.'
        ])
    )

    if settings['use_ssl']:
        with smtplib.SMTP_SSL(settings['server'], settings['port']) as server:
            server.login(settings['username'], settings['password'])
            server.send_message(message)
    else:
        with smtplib.SMTP(settings['server'], settings['port']) as server:
            server.ehlo()
            if settings['use_tls']:
                server.starttls()
                server.ehlo()
            server.login(settings['username'], settings['password'])
            server.send_message(message)

def cleanup_email_verifications(conn):
    cutoff = format_db_timestamp(utcnow() - timedelta(days=1))
    conn.execute(
        '''
        DELETE FROM email_verifications
        WHERE ((verified = 0 AND expires_at IS NOT NULL AND expires_at < ?)
            OR created_at < ?)
        ''',
        (format_db_timestamp(utcnow()), cutoff)
    )

def get_latest_email_verification(conn, email):
    return conn.execute(
        '''
        SELECT *
        FROM email_verifications
        WHERE email = ?
        ORDER BY id DESC
        LIMIT 1
        ''',
        (email,)
    ).fetchone()

@app.after_request
def apply_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'
    response.headers['Content-Security-Policy'] = get_csp_policy()
    if IS_PRODUCTION:
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    return response

@app.errorhandler(429)
def handle_rate_limit(error):
    message = '요청이 너무 많습니다. 잠시 후 다시 시도해주세요.'
    if request.path in {'/signup/send-verification'}:
        return jsonify({'success': False, 'message': message}), 429
    if request.path in {'/login', '/reset-password'}:
        return alert_and_back(message), 429
    if request.accept_mimetypes.accept_json and not request.accept_mimetypes.accept_html:
        return jsonify({'success': False, 'message': message}), 429
    return alert_and_back(message), 429

def sanitize_username_base(value):
    value = normalize_username_value(value)
    value = re.sub(r'[^a-z0-9_]+', '_', value)
    value = re.sub(r'_+', '_', value).strip('_')
    return value

def username_base_from_fields(name=None, email=None, fallback='user'):
    email_local = ''
    if email and '@' in email:
        email_local = email.split('@', 1)[0]

    candidates = [
        sanitize_username_base(email_local),
        sanitize_username_base(name),
        sanitize_username_base(fallback)
    ]
    for candidate in candidates:
        if candidate:
            if len(candidate) < 4:
                candidate = f'{candidate}_user'
            return candidate[:20]
    return 'user'

def build_unique_username(conn, base_value, exclude_user_id=None):
    base_value = username_base_from_fields(base_value)
    if len(base_value) < 4:
        base_value = f'{base_value}_user'
    candidate = base_value[:20]
    suffix = 1

    while True:
        existing_user = conn.execute(
            'SELECT id FROM users WHERE username = ?',
            (candidate,)
        ).fetchone()
        if not existing_user or existing_user['id'] == exclude_user_id:
            return candidate

        suffix_text = str(suffix)
        candidate = f"{base_value[:max(1, 20 - len(suffix_text))]}{suffix_text}"
        suffix += 1

def ensure_usernames(conn):
    rows = conn.execute(
        'SELECT id, name, email, username FROM users ORDER BY id ASC'
    ).fetchall()

    for row in rows:
        username = normalize_username_value(row['username'])
        if username and is_valid_username(username):
            continue

        generated_username = build_unique_username(
            conn,
            username_base_from_fields(row['name'], row['email'], f"user{row['id']}"),
            exclude_user_id=row['id']
        )
        conn.execute(
            'UPDATE users SET username = ? WHERE id = ?',
            (generated_username, row['id'])
        )

def profile_url_for_user(user_id=None, username=None):
    if username:
        return url_for('profile_by_username', username=username)
    return url_for('profile', user_id=user_id)

def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def format_relative_time(timestamp_value):
    if not timestamp_value:
        return '방금 전'

    parsed_time = to_kst(timestamp_value)
    if not parsed_time:
        return str(timestamp_value)

    now = kst_now()
    delta = now - parsed_time
    seconds = max(int(delta.total_seconds()), 0)

    if seconds < 60:
        return '방금 전'
    if seconds < 3600:
        return f'{seconds // 60}분 전'
    if parsed_time.date() == now.date():
        return '오늘 ' + parsed_time.strftime('%p %I:%M').replace('AM', '오전').replace('PM', '오후')
    return parsed_time.strftime('%Y.%m.%d %p %I:%M').replace('AM', '오전').replace('PM', '오후')

def normalize_post_row(post_row):
    post = dict(post_row)
    image_url = post.get('image_url') or url_for('static', filename='hero.png')
    author_name = post.get('user_name') or post.get('author_name') or '멍스타그래머'
    author_username = post.get('user_username') or post.get('author_username') or f"user{post.get('user_id', '')}"
    post['author_name'] = author_name
    post['author_username'] = author_username
    post['author_handle'] = f'@{author_username}'
    post['author_profile_url'] = profile_url_for_user(post.get('user_id'), author_username)
    post['author_avatar'] = user_image_url(post.get('user_profile_image'), author_username)
    post['display_image'] = image_url
    post['display_time'] = format_relative_time(post.get('created_at'))
    post['like_count'] = post.get('like_count') or 0
    post['comment_count'] = post.get('comment_count') or 0
    post['is_liked'] = bool(post.get('is_liked'))
    post['content_preview'] = (post.get('content') or '')[:110]
    return post

def normalize_comment_row(comment_row):
    comment = dict(comment_row)
    author_name = comment.get('user_name') or '멍스타그래머'
    author_username = comment.get('user_username') or f"user{comment.get('user_id', '')}"
    comment['author_name'] = author_name
    comment['author_username'] = author_username
    comment['author_handle'] = f'@{author_username}'
    comment['author_profile_url'] = profile_url_for_user(comment.get('user_id'), author_username)
    comment['author_avatar'] = user_image_url(comment.get('user_profile_image'), author_username)
    comment['display_time'] = format_relative_time(comment.get('updated_at') or comment.get('created_at'))
    comment['is_edited'] = bool(comment.get('updated_at')) and comment.get('updated_at') != comment.get('created_at')
    comment['is_owner'] = bool(comment.get('is_owner'))
    comment['can_edit'] = bool(comment.get('can_edit'))
    comment['can_delete'] = bool(comment.get('can_delete'))
    return comment

def format_message_time(timestamp_value):
    if not timestamp_value:
        return ''

    parsed_time = to_kst(timestamp_value)
    if not parsed_time:
        return str(timestamp_value)

    return parsed_time.strftime('%p %I:%M').replace('AM', '오전').replace('PM', '오후')

def format_message_list_time(timestamp_value):
    if not timestamp_value:
        return ''

    parsed_time = to_kst(timestamp_value)
    if not parsed_time:
        return str(timestamp_value)

    now = kst_now()
    if parsed_time.date() == now.date():
        return '오늘 ' + parsed_time.strftime('%p %I:%M').replace('AM', '오전').replace('PM', '오후')
    return parsed_time.strftime('%Y.%m.%d %p %I:%M').replace('AM', '오전').replace('PM', '오후')

def format_diary_time(timestamp_value):
    if not timestamp_value:
        return ''

    parsed_time = to_kst(timestamp_value)
    if not parsed_time:
        return str(timestamp_value)
    return parsed_time.strftime('%p %I:%M').replace('AM', '오전').replace('PM', '오후')

def format_diary_date_parts(timestamp_value):
    parsed_time = to_kst(timestamp_value)
    if not parsed_time:
        return {'day': '', 'month': ''}
    return {
        'day': parsed_time.strftime('%d'),
        'month': parsed_time.strftime('%m월')
    }

def normalize_message_row(message_row, viewer_id):
    message = dict(message_row)
    message['is_mine'] = message.get('sender_id') == viewer_id
    message['display_time'] = format_message_time(message.get('created_at'))
    message['display_day'] = format_message_list_time(message.get('created_at'))
    return message

def diary_image_url(image_filename):
    if not image_filename:
        return None
    return url_for('static', filename=image_filename)

def normalize_diary_entry(entry_row):
    if not entry_row:
        return None

    entry = dict(entry_row)
    entry['meal_checked'] = bool(entry.get('meal_checked'))
    entry['water_checked'] = bool(entry.get('water_checked'))
    entry['walk_checked'] = bool(entry.get('walk_checked'))
    entry['supplement_checked'] = bool(entry.get('supplement_checked'))
    entry['image_url'] = diary_image_url(entry.get('image_filename'))
    entry['display_time'] = format_diary_time(entry.get('created_at'))
    entry['date_parts'] = format_diary_date_parts(entry.get('created_at'))
    return entry

def normalize_diary_entries(entry_rows):
    return [normalize_diary_entry(entry_row) for entry_row in entry_rows]

def save_diary_image(file_storage):
    if not file_storage or not file_storage.filename:
        return None
    validate_image_file(file_storage)

    original_name = secure_filename(file_storage.filename)
    if not original_name:
        raise ValueError('유효한 파일명을 가진 이미지만 업로드할 수 있습니다.')

    unique_name = f"{uuid.uuid4().hex}_{original_name}"
    absolute_path = os.path.join(DIARY_UPLOAD_FOLDER, unique_name)
    file_storage.save(absolute_path)
    return f"uploads/diary/{unique_name}"

def delete_diary_image(image_filename):
    if not image_filename:
        return
    absolute_path = os.path.join(app.root_path, 'static', image_filename)
    if os.path.isfile(absolute_path):
        os.remove(absolute_path)

def parse_checkbox_value(name):
    return 1 if request.form.get(name) in {'on', '1', 'true', 'yes'} else 0

def parse_weight_value(raw_value):
    value = (raw_value or '').strip()
    if not value:
        return None
    try:
        return float(value)
    except ValueError:
        raise ValueError('몸무게는 숫자로 입력해 주세요.')

def extract_diary_form_data(existing_image_filename=None):
    dog_name = (request.form.get('dog_name') or '').strip()
    mood = (request.form.get('mood') or '').strip()
    title = (request.form.get('title') or '').strip()
    content = (request.form.get('content') or '').strip()
    walk_type = (request.form.get('walk_type') or '').strip()

    if contains_xss(dog_name, mood, title, content, walk_type):
        raise ValueError('공격이 감지되었습니다.')
    if contains_sqli(dog_name, mood, title, content, walk_type):
        raise ValueError('비정상적인 입력이 감지되었습니다.')

    if not title:
        raise ValueError('제목을 입력해 주세요.')
    if not content:
        raise ValueError('내용을 입력해 주세요.')

    image_filename = existing_image_filename
    file = request.files.get('image')
    if file and file.filename:
        image_filename = save_diary_image(file)

    return {
        'dog_name': dog_name,
        'mood': mood,
        'title': title,
        'content': content,
        'walk_type': walk_type,
        'weight': parse_weight_value(request.form.get('weight')),
        'meal_checked': parse_checkbox_value('meal_checked'),
        'water_checked': parse_checkbox_value('water_checked'),
        'walk_checked': parse_checkbox_value('walk_checked'),
        'supplement_checked': parse_checkbox_value('supplement_checked'),
        'image_filename': image_filename
    }

def build_diary_defaults_for_user(conn, user_id):
    current_user = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
    pet = get_user_pet(conn, user_id)
    latest_entry = conn.execute(
        '''
        SELECT *
        FROM diary_entries
        WHERE user_id = ?
        ORDER BY created_at DESC, id DESC
        LIMIT 1
        ''',
        (user_id,)
    ).fetchone()
    dog_name = ''
    if latest_entry and latest_entry['dog_name']:
        dog_name = latest_entry['dog_name']
    elif pet and pet.get('pet_name'):
        dog_name = pet['pet_name']
    elif current_user:
        dog_name = f"{current_user['name']}의 반려견"

    return {
        'current_user': current_user,
        'pet': pet,
        'dog_name': dog_name
    }

def default_diary_checklist_texts():
    return {
        'meal_text': '오늘의 식사 체크',
        'water_text': '오늘 물 섭취 체크',
        'walk_text': '오늘 산책 완료 체크',
        'supplement_text': '오늘 영양제 체크'
    }

def get_or_create_diary_settings(conn, user_id):
    settings = conn.execute(
        'SELECT * FROM diary_settings WHERE user_id = ?',
        (user_id,)
    ).fetchone()
    if settings:
        settings_dict = dict(settings)
    else:
        defaults = default_diary_checklist_texts()
        conn.execute(
            '''
            INSERT INTO diary_settings (user_id, meal_text, water_text, walk_text, supplement_text, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ''',
            (
                user_id,
                defaults['meal_text'],
                defaults['water_text'],
                defaults['walk_text'],
                defaults['supplement_text'],
                format_db_timestamp(utcnow()),
                format_db_timestamp(utcnow())
            )
        )
        conn.commit()
        settings = conn.execute(
            'SELECT * FROM diary_settings WHERE user_id = ?',
            (user_id,)
        ).fetchone()
        settings_dict = dict(settings)

    defaults = default_diary_checklist_texts()
    for key, default_value in defaults.items():
        if not (settings_dict.get(key) or '').strip():
            settings_dict[key] = default_value
    return settings_dict

def ensure_today_diary_entry(conn, user_id):
    day_start_utc, day_end_utc = get_kst_day_bounds_utc()
    today_entry = conn.execute(
        '''
        SELECT *
        FROM diary_entries
        WHERE user_id = ?
          AND created_at >= ?
          AND created_at < ?
        ORDER BY created_at DESC, id DESC
        LIMIT 1
        ''',
        (user_id, format_db_timestamp(day_start_utc), format_db_timestamp(day_end_utc))
    ).fetchone()
    if today_entry:
        return today_entry

    defaults = build_diary_defaults_for_user(conn, user_id)
    conn.execute(
        '''
        INSERT INTO diary_entries (user_id, dog_name, title, content, created_at)
        VALUES (?, ?, ?, ?, ?)
        ''',
        (
            user_id,
            defaults['dog_name'],
            '오늘의 건강 체크',
            '데일리 건강 체크리스트를 기록했습니다.',
            format_db_timestamp(utcnow())
        )
    )
    conn.commit()
    return conn.execute(
        'SELECT * FROM diary_entries WHERE id = last_insert_rowid()'
    ).fetchone()

def build_month_streak_summary(entry_rows, today=None):
    today = today or kst_now()
    distinct_dates = sorted(
        {
            to_kst(row['created_at']).date()
            for row in entry_rows
            if to_kst(row['created_at'])
        },
        reverse=True
    )

    current_streak = 0
    if distinct_dates:
        comparison_day = today.date()
        if distinct_dates[0] == comparison_day:
            current_streak = 1
            for entry_date in distinct_dates[1:]:
                comparison_day = comparison_day - timedelta(days=1)
                if entry_date == comparison_day:
                    current_streak += 1
                else:
                    break

    month_dates = sorted(
        {
            entry_date.day
            for entry_date in distinct_dates
            if entry_date.year == today.year and entry_date.month == today.month
        }
    )

    return {
        'current_streak': current_streak,
        'month_dates': month_dates,
        'month_entry_count': len(month_dates)
    }

def normalize_conversation_row(conversation_row, viewer_id):
    conversation = dict(conversation_row)
    partner_name = conversation.get('partner_name') or '멍친구'
    partner_username = conversation.get('partner_username') or f"user{conversation.get('partner_id', '')}"
    conversation['partner_name'] = partner_name
    conversation['partner_username'] = partner_username
    conversation['partner_handle'] = f'@{partner_username}'
    conversation['partner_profile_url'] = profile_url_for_user(conversation.get('partner_id'), partner_username)
    conversation['partner_avatar'] = user_image_url(conversation.get('partner_profile_image'), partner_username)
    conversation['last_message_preview'] = (conversation.get('last_message') or '아직 메시지가 없습니다.').strip()
    if len(conversation['last_message_preview']) > 38:
        conversation['last_message_preview'] = conversation['last_message_preview'][:38] + '...'
    conversation['display_time'] = format_message_list_time(
        conversation.get('last_message_at') or conversation.get('updated_at') or conversation.get('created_at')
    )
    conversation['unread_count'] = conversation.get('unread_count') or 0
    conversation['has_unread'] = conversation['unread_count'] > 0
    conversation['is_active'] = False
    conversation['is_partner_followed'] = bool(conversation.get('is_partner_followed'))
    conversation['viewer_id'] = viewer_id
    return conversation

def fetch_post_by_id(conn, post_id, viewer_id=None):
    post = conn.execute('''
        SELECT
            p.*,
            u.name AS user_name,
            u.username AS user_username,
            u.profile_image AS user_profile_image,
            COALESCE(l.like_count, 0) AS like_count,
            COALESCE(c.comment_count, 0) AS comment_count,
            CASE
                WHEN ? IS NOT NULL AND ul.id IS NOT NULL THEN 1
                ELSE 0
            END AS is_liked
        FROM posts p
        JOIN users u ON p.user_id = u.id
        LEFT JOIN (
            SELECT post_id, COUNT(*) AS like_count
            FROM likes
            GROUP BY post_id
        ) l ON l.post_id = p.id
        LEFT JOIN (
            SELECT post_id, COUNT(*) AS comment_count
            FROM comments
            GROUP BY post_id
        ) c ON c.post_id = p.id
        LEFT JOIN likes ul
            ON ul.post_id = p.id
           AND ul.user_id = ?
        WHERE p.id = ?
    ''', (viewer_id, viewer_id, post_id)).fetchone()
    return normalize_post_row(post) if post else None

def fetch_comments_for_post(conn, post_id, viewer_id=None, viewer_role='user'):
    viewer_is_admin = 1 if viewer_role == 'admin' else 0
    comments = conn.execute('''
        SELECT
            c.*,
            u.name AS user_name,
            u.username AS user_username,
            u.profile_image AS user_profile_image,
            CASE
                WHEN ? IS NOT NULL AND c.user_id = ? THEN 1
                ELSE 0
            END AS is_owner
            ,
            CASE
                WHEN ? IS NOT NULL AND c.user_id = ? THEN 1
                ELSE 0
            END AS can_edit,
            CASE
                WHEN ? = 1 OR (? IS NOT NULL AND c.user_id = ?) THEN 1
                ELSE 0
            END AS can_delete
        FROM comments c
        JOIN users u ON c.user_id = u.id
        WHERE c.post_id = ?
        ORDER BY c.created_at ASC, c.id ASC
    ''', (viewer_id, viewer_id, viewer_id, viewer_id, viewer_is_admin, viewer_id, viewer_id, post_id)).fetchall()
    return [normalize_comment_row(comment) for comment in comments]

def fetch_posts(conn, viewer_id=None, limit=None, featured=False):
    order_clause = 'like_count DESC, p.created_at DESC' if featured else 'p.created_at DESC'
    limit_clause = f'LIMIT {int(limit)}' if limit else ''
    posts = conn.execute(f'''
        SELECT
            p.*,
            u.name AS user_name,
            u.username AS user_username,
            u.profile_image AS user_profile_image,
            COALESCE(l.like_count, 0) AS like_count,
            COALESCE(c.comment_count, 0) AS comment_count,
            CASE
                WHEN ? IS NOT NULL AND ul.id IS NOT NULL THEN 1
                ELSE 0
            END AS is_liked
        FROM posts p
        JOIN users u ON p.user_id = u.id
        LEFT JOIN (
            SELECT post_id, COUNT(*) AS like_count
            FROM likes
            GROUP BY post_id
        ) l ON l.post_id = p.id
        LEFT JOIN (
            SELECT post_id, COUNT(*) AS comment_count
            FROM comments
            GROUP BY post_id
        ) c ON c.post_id = p.id
        LEFT JOIN likes ul
            ON ul.post_id = p.id
           AND ul.user_id = ?
        ORDER BY {order_clause}
        {limit_clause}
    ''', (viewer_id, viewer_id)).fetchall()
    return [normalize_post_row(post) for post in posts]

def pet_image_url(image_value, fallback_seed='pet'):
    if image_value:
        if image_value.startswith(('http://', 'https://', '/static/')):
            return image_value
        return url_for('static', filename=image_value)
    return f'https://api.dicebear.com/7.x/avataaars/svg?seed={fallback_seed}'

def user_image_url(image_value, fallback_seed='user'):
    if image_value:
        if image_value.startswith(('http://', 'https://')):
            return image_value
        if image_value.startswith('/static/'):
            relative_static_path = image_value.replace('/static/', '', 1)
            absolute_path = os.path.join(app.root_path, 'static', relative_static_path)
            if os.path.isfile(absolute_path):
                return f"{image_value}?v={int(os.path.getmtime(absolute_path))}"
            return image_value

        relative_static_path = image_value
        absolute_path = os.path.join(app.root_path, 'static', relative_static_path)
        asset_url = url_for('static', filename=relative_static_path)
        if os.path.isfile(absolute_path):
            return f"{asset_url}?v={int(os.path.getmtime(absolute_path))}"
        return asset_url
    return f'https://api.dicebear.com/7.x/avataaars/svg?seed={fallback_seed}'

def normalize_user_row(user_row):
    if not user_row:
        return None

    user = dict(user_row)
    user['role'] = user.get('role') or 'user'
    user['is_admin'] = user['role'] == 'admin'
    username = normalize_username_value(user.get('username')) or (f"user{user.get('id')}" if user.get('id') else 'user')
    user['username'] = username
    user['display_handle'] = f'@{username}'
    user['profile_url'] = profile_url_for_user(user.get('id'), username)
    user['profile_image_url'] = user_image_url(user.get('profile_image'), username)
    return user

def normalize_user_rows(user_rows):
    return [normalize_user_row(user_row) for user_row in user_rows]

def fetch_current_user():
    user_id = session.get('user_id')
    if not user_id:
        return None

    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
    conn.close()
    return normalize_user_row(user)

def fetch_unread_message_count():
    user_id = session.get('user_id')
    if not user_id:
        return 0

    conn = get_db_connection()
    unread_count = conn.execute(
        '''
        SELECT COUNT(*)
        FROM messages
        WHERE receiver_id = ?
          AND is_read = 0
        ''',
        (user_id,)
    ).fetchone()[0]
    conn.close()
    return unread_count or 0

def fetch_unread_notification_count():
    user_id = session.get('user_id')
    if not user_id:
        return 0

    conn = get_db_connection()
    unread_count = conn.execute(
        '''
        SELECT COUNT(*)
        FROM notifications
        WHERE recipient_id = ?
          AND is_read = 0
        ''',
        (user_id,)
    ).fetchone()[0]
    conn.close()
    return unread_count or 0

@app.context_processor
def inject_current_user():
    unread_message_count = fetch_unread_message_count()
    unread_notification_count = fetch_unread_notification_count()
    return {
        'current_user': fetch_current_user(),
        'unread_message_count': unread_message_count,
        'unread_message_badge': '99+' if unread_message_count > 99 else str(unread_message_count),
        'unread_notification_count': unread_notification_count,
        'unread_notification_badge': '99+' if unread_notification_count > 99 else str(unread_notification_count)
    }

def conversation_pair(user_a_id, user_b_id):
    return tuple(sorted((int(user_a_id), int(user_b_id))))

def ensure_conversation(conn, user_a_id, user_b_id):
    if int(user_a_id) == int(user_b_id):
        raise ValueError('본인과는 대화를 시작할 수 없습니다.')

    user1_id, user2_id = conversation_pair(user_a_id, user_b_id)
    conversation = conn.execute(
        'SELECT * FROM conversations WHERE user1_id = ? AND user2_id = ?',
        (user1_id, user2_id)
    ).fetchone()
    if conversation:
        return conversation['id']

    cursor = conn.execute(
        'INSERT INTO conversations (user1_id, user2_id) VALUES (?, ?)',
        (user1_id, user2_id)
    )
    conn.commit()
    return cursor.lastrowid

def fetch_conversation_list(conn, viewer_id):
    conversations = conn.execute('''
        SELECT
            c.*,
            CASE
                WHEN c.user1_id = ? THEN u2.id
                ELSE u1.id
            END AS partner_id,
            CASE
                WHEN c.user1_id = ? THEN u2.name
                ELSE u1.name
            END AS partner_name,
            CASE
                WHEN c.user1_id = ? THEN u2.username
                ELSE u1.username
            END AS partner_username,
            CASE
                WHEN c.user1_id = ? THEN u2.profile_image
                ELSE u1.profile_image
            END AS partner_profile_image,
            CASE
                WHEN c.user1_id = ? THEN u2.status_message
                ELSE u1.status_message
            END AS partner_status_message,
            CASE
                WHEN c.user1_id = ? THEN u2.location
                ELSE u1.location
            END AS partner_location,
            lm.content AS last_message,
            lm.created_at AS last_message_at,
            (
                SELECT COUNT(*)
                FROM messages um
                WHERE um.conversation_id = c.id
                  AND um.receiver_id = ?
                  AND um.is_read = 0
            ) AS unread_count,
            EXISTS(
                SELECT 1
                FROM follows f
                WHERE f.follower_id = ?
                  AND f.following_id = CASE WHEN c.user1_id = ? THEN u2.id ELSE u1.id END
            ) AS is_partner_followed
        FROM conversations c
        JOIN users u1 ON u1.id = c.user1_id
        JOIN users u2 ON u2.id = c.user2_id
        LEFT JOIN messages lm ON lm.id = (
            SELECT m1.id
            FROM messages m1
            WHERE m1.conversation_id = c.id
            ORDER BY m1.created_at DESC, m1.id DESC
            LIMIT 1
        )
        WHERE c.user1_id = ? OR c.user2_id = ?
        ORDER BY COALESCE(lm.created_at, c.updated_at, c.created_at) DESC, c.id DESC
    ''', (
        viewer_id, viewer_id, viewer_id, viewer_id, viewer_id, viewer_id,
        viewer_id, viewer_id, viewer_id,
        viewer_id, viewer_id
    )).fetchall()
    return [normalize_conversation_row(row, viewer_id) for row in conversations]

def fetch_conversation_detail(conn, conversation_id, viewer_id):
    conversation = conn.execute('''
        SELECT
            c.*,
            CASE
                WHEN c.user1_id = ? THEN u2.id
                ELSE u1.id
            END AS partner_id,
            CASE
                WHEN c.user1_id = ? THEN u2.name
                ELSE u1.name
            END AS partner_name,
            CASE
                WHEN c.user1_id = ? THEN u2.username
                ELSE u1.username
            END AS partner_username,
            CASE
                WHEN c.user1_id = ? THEN u2.profile_image
                ELSE u1.profile_image
            END AS partner_profile_image,
            CASE
                WHEN c.user1_id = ? THEN u2.status_message
                ELSE u1.status_message
            END AS partner_status_message,
            CASE
                WHEN c.user1_id = ? THEN u2.location
                ELSE u1.location
            END AS partner_location,
            EXISTS(
                SELECT 1
                FROM follows f
                WHERE f.follower_id = ?
                  AND f.following_id = CASE WHEN c.user1_id = ? THEN u2.id ELSE u1.id END
            ) AS is_partner_followed
        FROM conversations c
        JOIN users u1 ON u1.id = c.user1_id
        JOIN users u2 ON u2.id = c.user2_id
        WHERE c.id = ?
          AND (c.user1_id = ? OR c.user2_id = ?)
    ''', (
        viewer_id, viewer_id, viewer_id, viewer_id, viewer_id, viewer_id,
        viewer_id, viewer_id,
        conversation_id, viewer_id, viewer_id
    )).fetchone()
    return normalize_conversation_row(conversation, viewer_id) if conversation else None

def fetch_messages_for_conversation(conn, conversation_id, viewer_id):
    messages = conn.execute('''
        SELECT m.*
        FROM messages m
        JOIN conversations c ON c.id = m.conversation_id
        WHERE m.conversation_id = ?
          AND (c.user1_id = ? OR c.user2_id = ?)
        ORDER BY m.created_at ASC, m.id ASC
    ''', (conversation_id, viewer_id, viewer_id)).fetchall()
    return [normalize_message_row(row, viewer_id) for row in messages]

def mark_conversation_as_read(conn, conversation_id, viewer_id):
    conn.execute(
        '''
        UPDATE messages
        SET is_read = 1
        WHERE conversation_id = ?
          AND receiver_id = ?
          AND is_read = 0
        ''',
        (conversation_id, viewer_id)
    )
    conn.commit()

def search_message_users(conn, viewer_id, query):
    search_term = f"%{query.strip()}%"
    rows = conn.execute('''
        SELECT id, name, username, email, profile_image, status_message, location
        FROM users
        WHERE id != ?
          AND (name LIKE ? OR email LIKE ?)
        ORDER BY name COLLATE NOCASE ASC
        LIMIT 8
    ''', (viewer_id, search_term, search_term)).fetchall()
    return normalize_user_rows(rows)

NOTIFICATION_CONFIG = {
    'message': {
        'icon': 'message-circle-more',
        'class': 'message'
    },
    'comment': {
        'icon': 'message-square-text',
        'class': 'comment'
    },
    'like': {
        'icon': 'heart',
        'class': 'like'
    },
    'follow': {
        'icon': 'user-plus',
        'class': 'follow'
    }
}

NOTIFICATION_SETTING_FIELDS = [
    ('activity_push', 1),
    ('activity_email', 0),
    ('message_push', 1),
    ('message_email', 1),
    ('walk_friend_push', 0),
    ('walk_friend_email', 0),
    ('notice_push', 1),
    ('notice_email', 1)
]

def build_notification_message(notification_type, actor_name):
    message_map = {
        'message': f'{actor_name}님이 메시지를 보냈습니다.',
        'comment': f'{actor_name}님이 회원님의 게시물에 댓글을 달았습니다.',
        'like': f'{actor_name}님이 회원님의 게시물을 좋아합니다.',
        'follow': f'{actor_name}님이 회원님을 팔로우하기 시작했습니다.'
    }
    return message_map.get(notification_type, f'{actor_name}님의 새 알림이 도착했습니다.')

def get_notification_settings(conn, user_id):
    row = conn.execute(
        'SELECT * FROM notification_settings WHERE user_id = ?',
        (user_id,)
    ).fetchone()

    if not row:
        defaults = {field: default for field, default in NOTIFICATION_SETTING_FIELDS}
        conn.execute(
            '''
            INSERT INTO notification_settings (
                user_id, activity_push, activity_email, message_push, message_email,
                walk_friend_push, walk_friend_email, notice_push, notice_email
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''',
            (
                user_id,
                defaults['activity_push'],
                defaults['activity_email'],
                defaults['message_push'],
                defaults['message_email'],
                defaults['walk_friend_push'],
                defaults['walk_friend_email'],
                defaults['notice_push'],
                defaults['notice_email']
            )
        )
        conn.commit()
        row = conn.execute(
            'SELECT * FROM notification_settings WHERE user_id = ?',
            (user_id,)
        ).fetchone()

    return dict(row)

def create_notification(conn, recipient_id, actor_id, notification_type, target_id=None, message=None):
    if not recipient_id or not actor_id or int(recipient_id) == int(actor_id):
        return

    conn.execute(
        '''
        INSERT INTO notifications (recipient_id, actor_id, type, target_id, message, is_read)
        VALUES (?, ?, ?, ?, ?, ?)
        ''',
        (recipient_id, actor_id, notification_type, target_id, message, 0)
    )

def delete_matching_notification(conn, recipient_id, actor_id, notification_type, target_id=None):
    if target_id is None:
        conn.execute(
            'DELETE FROM notifications WHERE recipient_id = ? AND actor_id = ? AND type = ?',
            (recipient_id, actor_id, notification_type)
        )
    else:
        conn.execute(
            'DELETE FROM notifications WHERE recipient_id = ? AND actor_id = ? AND type = ? AND target_id = ?',
            (recipient_id, actor_id, notification_type, target_id)
        )

def delete_user_account(conn, user_id):
    diary_rows = conn.execute(
        'SELECT image_filename FROM diary_entries WHERE user_id = ?',
        (user_id,)
    ).fetchall()
    post_ids = [
        row['id']
        for row in conn.execute(
            'SELECT id FROM posts WHERE user_id = ?',
            (user_id,)
        ).fetchall()
    ]
    conversation_ids = [
        row['id']
        for row in conn.execute(
            'SELECT id FROM conversations WHERE user1_id = ? OR user2_id = ?',
            (user_id, user_id)
        ).fetchall()
    ]

    if post_ids:
        post_placeholders = ','.join('?' for _ in post_ids)
        conn.execute(
            f'DELETE FROM likes WHERE post_id IN ({post_placeholders})',
            post_ids
        )
        conn.execute(
            f'DELETE FROM comments WHERE post_id IN ({post_placeholders})',
            post_ids
        )
        conn.execute(
            f"DELETE FROM notifications WHERE type IN ('comment', 'like') AND target_id IN ({post_placeholders})",
            post_ids
        )

    if conversation_ids:
        conversation_placeholders = ','.join('?' for _ in conversation_ids)
        conn.execute(
            f'DELETE FROM notifications WHERE type = ? AND target_id IN ({conversation_placeholders})',
            ['message', *conversation_ids]
        )
        conn.execute(
            f'DELETE FROM messages WHERE conversation_id IN ({conversation_placeholders})',
            conversation_ids
        )
        conn.execute(
            f'DELETE FROM conversations WHERE id IN ({conversation_placeholders})',
            conversation_ids
        )

    conn.execute('DELETE FROM likes WHERE user_id = ?', (user_id,))
    conn.execute('DELETE FROM comments WHERE user_id = ?', (user_id,))
    conn.execute('DELETE FROM messages WHERE sender_id = ? OR receiver_id = ?', (user_id, user_id))
    conn.execute('DELETE FROM follows WHERE follower_id = ? OR following_id = ?', (user_id, user_id))
    conn.execute('DELETE FROM pets WHERE user_id = ?', (user_id,))
    conn.execute('DELETE FROM diary_entries WHERE user_id = ?', (user_id,))
    conn.execute('DELETE FROM diary_settings WHERE user_id = ?', (user_id,))
    conn.execute('DELETE FROM notification_settings WHERE user_id = ?', (user_id,))
    conn.execute('DELETE FROM notifications WHERE recipient_id = ? OR actor_id = ?', (user_id, user_id))
    conn.execute('DELETE FROM posts WHERE user_id = ?', (user_id,))
    conn.execute('DELETE FROM users WHERE id = ?', (user_id,))

    for diary_row in diary_rows:
        delete_diary_image(diary_row['image_filename'])

def normalize_notification_row(notification_row):
    notification = dict(notification_row)
    actor_name = notification.get('actor_name') or '멍친구'
    actor_username = notification.get('actor_username') or f"user{notification.get('actor_id', '')}"
    config = NOTIFICATION_CONFIG.get(notification.get('type'), {'icon': 'bell', 'class': 'message'})
    notification['actor_name'] = actor_name
    notification['actor_username'] = actor_username
    notification['actor_handle'] = f'@{actor_username}'
    notification['actor_profile_url'] = profile_url_for_user(notification.get('actor_id'), actor_username)
    notification['actor_avatar'] = user_image_url(notification.get('actor_profile_image'), actor_username)
    notification['icon'] = config['icon']
    notification['type_class'] = config['class']
    notification['message'] = notification.get('message') or build_notification_message(notification.get('type'), actor_name)
    notification['display_time'] = format_relative_time(notification.get('created_at'))
    notification['unread'] = not bool(notification.get('is_read'))
    notification['target_url'] = url_for('open_notification', notification_id=notification['id'])
    return notification

def fetch_notifications_for_user(conn, user_id):
    rows = conn.execute(
        '''
        SELECT
            n.*,
            u.name AS actor_name,
            u.username AS actor_username,
            u.profile_image AS actor_profile_image
        FROM notifications n
        LEFT JOIN users u ON u.id = n.actor_id
        WHERE n.recipient_id = ?
        ORDER BY n.created_at DESC, n.id DESC
        ''',
        (user_id,)
    ).fetchall()
    return [normalize_notification_row(row) for row in rows]

def resolve_notification_redirect(notification):
    notification_type = notification.get('type')
    actor_id = notification.get('actor_id')
    target_id = notification.get('target_id')

    if notification_type == 'follow' and actor_id:
        return url_for('profile', user_id=actor_id)
    if notification_type in {'comment', 'like'} and target_id:
        return url_for('post_comments', post_id=target_id)
    if notification_type == 'message':
        if target_id:
            return url_for('messages_page', conversation=target_id)
        if actor_id:
            return url_for('start_conversation', user_id=actor_id)
    return url_for('notifications_page')

def normalize_pet_row(pet_row):
    if not pet_row:
        return None

    pet = dict(pet_row)
    normalized = {
        'id': pet.get('id'),
        'user_id': pet.get('user_id'),
        'pet_name': pet.get('pet_name') or pet.get('name') or '',
        'pet_breed': pet.get('pet_breed') or pet.get('breed') or '',
        'pet_age': pet.get('pet_age') or pet.get('age') or '',
        'pet_gender': pet.get('pet_gender') or pet.get('gender') or '남아',
        'pet_feature': pet.get('pet_feature') or pet.get('pet_description') or pet.get('description') or '',
        'pet_personality': pet.get('pet_personality') or pet.get('personality') or '',
        'pet_image': pet.get('pet_image') or pet.get('image') or '',
        'created_at': pet.get('created_at'),
        'updated_at': pet.get('updated_at')
    }
    normalized['personality_list'] = [tag.strip() for tag in normalized['pet_personality'].split(',') if tag.strip()]
    normalized['pet_image_url'] = pet_image_url(normalized['pet_image'], normalized['pet_name'] or 'pet')
    return normalized

def get_user_pet(conn, user_id):
    pet_row = conn.execute('SELECT * FROM pets WHERE user_id = ?', (user_id,)).fetchone()
    return normalize_pet_row(pet_row)

def save_pet_record(conn, user_id, form, file_storage):
    pet_name = (form.get('pet_name') or form.get('name') or '').strip()
    pet_breed = (form.get('pet_breed') or form.get('breed') or '').strip()
    pet_age = (form.get('pet_age') or form.get('age') or '').strip()
    pet_gender = (form.get('pet_gender') or form.get('gender') or '남아').strip()
    pet_feature = (form.get('pet_feature') or form.get('pet_description') or form.get('description') or '').strip()
    pet_personality = (form.get('pet_personality') or form.get('personality') or '').strip()

    if contains_xss(pet_name, pet_breed, pet_age, pet_gender, pet_feature, pet_personality):
        raise ValueError('공격이 감지되었습니다.')

    if not pet_name:
        raise ValueError('반려견 이름은 필수입니다.')

    existing_pet = conn.execute('SELECT * FROM pets WHERE user_id = ?', (user_id,)).fetchone()
    normalized_existing_pet = normalize_pet_row(existing_pet) if existing_pet else None

    pet_image = normalized_existing_pet['pet_image'] if normalized_existing_pet else None
    if file_storage and file_storage.filename:
        validate_image_file(file_storage)
        filename = secure_filename(file_storage.filename)
        unique_filename = f"pet_{user_id}_{int(time.time())}_{filename}"
        file_storage.save(os.path.join(app.config['UPLOAD_FOLDER'], unique_filename))
        pet_image = f'uploads/{unique_filename}'

    if existing_pet:
        conn.execute('''
            UPDATE pets
            SET name = ?, breed = ?, age = ?, gender = ?, personality = ?, description = ?, image = ?,
                pet_name = ?, pet_breed = ?, pet_age = ?, pet_gender = ?, pet_feature = ?,
                pet_description = ?, pet_personality = ?, pet_image = ?, updated_at = CURRENT_TIMESTAMP
            WHERE user_id = ?
        ''', (
            pet_name, pet_breed, pet_age, pet_gender, pet_personality, pet_feature, pet_image,
            pet_name, pet_breed, pet_age, pet_gender, pet_feature,
            pet_feature, pet_personality, pet_image, user_id
        ))
    else:
        conn.execute('''
            INSERT INTO pets (
                user_id, name, breed, age, gender, personality, description, image,
                pet_name, pet_breed, pet_age, pet_gender, pet_feature, pet_description,
                pet_personality, pet_image
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            user_id, pet_name, pet_breed, pet_age, pet_gender, pet_personality, pet_feature, pet_image,
            pet_name, pet_breed, pet_age, pet_gender, pet_feature, pet_feature,
            pet_personality, pet_image
        ))

def init_db():
    if not os.path.exists(DATABASE):
        conn = get_db_connection()
        create_security_logs_table(conn)
        conn.execute('''
            CREATE TABLE users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                bio TEXT,
                profile_image TEXT,
                role TEXT DEFAULT 'user',
                email_verified INTEGER DEFAULT 0,
                is_temp_password INTEGER DEFAULT 0
            )
        ''')
        conn.execute('''
            CREATE TABLE email_verifications (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL,
                code_hash TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                verified INTEGER DEFAULT 0,
                used INTEGER DEFAULT 0,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                last_sent_at TEXT DEFAULT CURRENT_TIMESTAMP,
                attempt_count INTEGER DEFAULT 0
            )
        ''')
        conn.execute('CREATE INDEX idx_email_verifications_email ON email_verifications(email)')
        conn.execute('''
            CREATE TABLE follows (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                follower_id INTEGER NOT NULL,
                following_id INTEGER NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (follower_id) REFERENCES users (id),
                FOREIGN KEY (following_id) REFERENCES users (id),
                UNIQUE(follower_id, following_id)
            )
        ''')
        conn.execute('''
            CREATE TABLE pets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                name TEXT,
                breed TEXT,
                age TEXT,
                gender TEXT,
                personality TEXT,
                description TEXT,
                image TEXT,
                pet_name TEXT,
                pet_breed TEXT,
                pet_age TEXT,
                pet_gender TEXT,
                pet_feature TEXT,
                pet_description TEXT,
                pet_personality TEXT,
                pet_image TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')
        conn.execute('''
            CREATE TABLE posts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                content TEXT NOT NULL,
                image_url TEXT,
                location TEXT,
                hashtags TEXT,
                walk_distance TEXT,
                walk_duration TEXT,
                walk_completed_time TEXT,
                walk_memo TEXT,
                latitude REAL,
                longitude REAL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')
        conn.execute('''
            CREATE TABLE likes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                post_id INTEGER NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id),
                FOREIGN KEY (post_id) REFERENCES posts (id),
                UNIQUE(user_id, post_id)
            )
        ''')
        conn.execute('''
            CREATE TABLE comments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                post_id INTEGER NOT NULL,
                content TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id),
                FOREIGN KEY (post_id) REFERENCES posts (id)
            )
        ''')
        conn.execute('''
            CREATE TABLE conversations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user1_id INTEGER NOT NULL,
                user2_id INTEGER NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user1_id) REFERENCES users (id),
                FOREIGN KEY (user2_id) REFERENCES users (id),
                UNIQUE(user1_id, user2_id),
                CHECK (user1_id != user2_id)
            )
        ''')
        conn.execute('''
            CREATE TABLE messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                conversation_id INTEGER NOT NULL,
                sender_id INTEGER NOT NULL,
                receiver_id INTEGER NOT NULL,
                content TEXT NOT NULL,
                is_read INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (conversation_id) REFERENCES conversations (id),
                FOREIGN KEY (sender_id) REFERENCES users (id),
                FOREIGN KEY (receiver_id) REFERENCES users (id)
            )
        ''')
        conn.execute('''
            CREATE TABLE notifications (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                recipient_id INTEGER NOT NULL,
                actor_id INTEGER NOT NULL,
                type TEXT NOT NULL,
                target_id INTEGER,
                message TEXT,
                is_read INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (recipient_id) REFERENCES users (id),
                FOREIGN KEY (actor_id) REFERENCES users (id)
            )
        ''')
        conn.execute('''
            CREATE TABLE notification_settings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL UNIQUE,
                activity_push INTEGER DEFAULT 1,
                activity_email INTEGER DEFAULT 0,
                message_push INTEGER DEFAULT 1,
                message_email INTEGER DEFAULT 1,
                walk_friend_push INTEGER DEFAULT 0,
                walk_friend_email INTEGER DEFAULT 0,
                notice_push INTEGER DEFAULT 1,
                notice_email INTEGER DEFAULT 1,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')
        conn.execute('''
            CREATE TABLE diary_entries (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                dog_name TEXT,
                mood TEXT,
                title TEXT NOT NULL,
                content TEXT NOT NULL,
                walk_type TEXT,
                weight REAL,
                meal_checked INTEGER DEFAULT 0,
                water_checked INTEGER DEFAULT 0,
                walk_checked INTEGER DEFAULT 0,
                supplement_checked INTEGER DEFAULT 0,
                daily_goal TEXT,
                image_filename TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')
        conn.execute('''
            CREATE TABLE diary_settings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL UNIQUE,
                meal_text TEXT,
                water_text TEXT,
                walk_text TEXT,
                supplement_text TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')
        conn.commit()
        conn.close()

init_db()

# Migration for existing DB
def migrate_db():
    conn = get_db_connection()
    create_security_logs_table(conn)
    new_columns = [
        ('location', 'TEXT'),
        ('hashtags', 'TEXT'),
        ('walk_distance', 'TEXT'),
        ('walk_duration', 'TEXT'),
        ('walk_completed_time', 'TEXT'),
        ('walk_memo', 'TEXT'),
        ('latitude', 'REAL'),
        ('longitude', 'REAL')
    ]
    for col_name, col_type in new_columns:
        try:
            conn.execute(f'ALTER TABLE posts ADD COLUMN {col_name} {col_type}')
            conn.commit()
        except sqlite3.OperationalError:
            pass
            
    # Migration for users table
    try:
        conn.execute("ALTER TABLE users ADD COLUMN role TEXT DEFAULT 'user'")
        conn.commit()
    except sqlite3.OperationalError:
        pass
    try:
        conn.execute('ALTER TABLE users ADD COLUMN username TEXT')
        conn.commit()
    except sqlite3.OperationalError:
        pass
    try:
        conn.execute('ALTER TABLE users ADD COLUMN email_verified INTEGER DEFAULT 0')
        conn.commit()
    except sqlite3.OperationalError:
        pass
    try:
        conn.execute('ALTER TABLE users ADD COLUMN is_temp_password INTEGER DEFAULT 0')
        conn.commit()
    except sqlite3.OperationalError:
        pass
    try:
        conn.execute('ALTER TABLE users ADD COLUMN bio TEXT')
        conn.commit()
    except: pass
    try:
        conn.execute('ALTER TABLE users ADD COLUMN profile_image TEXT')
        conn.commit()
    except: pass
    try:
        conn.execute('ALTER TABLE users ADD COLUMN status_message TEXT')
        conn.commit()
    except: pass
    try:
        conn.execute('ALTER TABLE users ADD COLUMN location TEXT')
        conn.commit()
    except: pass
    conn.execute("UPDATE users SET role = COALESCE(NULLIF(role, ''), 'user')")
    conn.execute("UPDATE users SET email_verified = COALESCE(email_verified, 0)")
    conn.execute("UPDATE users SET is_temp_password = COALESCE(is_temp_password, 0)")
    ensure_usernames(conn)
    conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_users_username ON users(username)")
    conn.execute('''
        CREATE TABLE IF NOT EXISTS email_verifications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT NOT NULL,
            code_hash TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            verified INTEGER DEFAULT 0,
            used INTEGER DEFAULT 0,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            last_sent_at TEXT DEFAULT CURRENT_TIMESTAMP,
            attempt_count INTEGER DEFAULT 0
        )
    ''')
    conn.execute('CREATE INDEX IF NOT EXISTS idx_email_verifications_email ON email_verifications(email)')

    # Create new tables if not exists
    conn.execute('''
        CREATE TABLE IF NOT EXISTS follows (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            follower_id INTEGER NOT NULL,
            following_id INTEGER NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (follower_id) REFERENCES users (id),
            FOREIGN KEY (following_id) REFERENCES users (id),
            UNIQUE(follower_id, following_id)
        )
    ''')
    conn.execute('''
        CREATE TABLE IF NOT EXISTS pets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            name TEXT,
            breed TEXT,
            age TEXT,
            gender TEXT,
            personality TEXT,
            description TEXT,
            image TEXT,
            pet_name TEXT,
            pet_breed TEXT,
            pet_age TEXT,
            pet_gender TEXT,
            pet_feature TEXT,
            pet_description TEXT,
            pet_personality TEXT,
            pet_image TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    conn.execute('''
        CREATE TABLE IF NOT EXISTS likes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            post_id INTEGER NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id),
            FOREIGN KEY (post_id) REFERENCES posts (id),
            UNIQUE(user_id, post_id)
        )
    ''')
    conn.execute('''
        CREATE TABLE IF NOT EXISTS comments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            post_id INTEGER NOT NULL,
            content TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id),
            FOREIGN KEY (post_id) REFERENCES posts (id)
        )
    ''')
    conn.execute('''
        CREATE TABLE IF NOT EXISTS conversations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user1_id INTEGER NOT NULL,
            user2_id INTEGER NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user1_id) REFERENCES users (id),
            FOREIGN KEY (user2_id) REFERENCES users (id),
            UNIQUE(user1_id, user2_id),
            CHECK (user1_id != user2_id)
        )
    ''')
    conn.execute('''
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            conversation_id INTEGER NOT NULL,
            sender_id INTEGER NOT NULL,
            receiver_id INTEGER NOT NULL,
            content TEXT NOT NULL,
            is_read INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (conversation_id) REFERENCES conversations (id),
            FOREIGN KEY (sender_id) REFERENCES users (id),
            FOREIGN KEY (receiver_id) REFERENCES users (id)
        )
    ''')
    conn.execute('''
        CREATE TABLE IF NOT EXISTS notifications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            recipient_id INTEGER NOT NULL,
            actor_id INTEGER NOT NULL,
            type TEXT NOT NULL,
            target_id INTEGER,
            message TEXT,
            is_read INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (recipient_id) REFERENCES users (id),
            FOREIGN KEY (actor_id) REFERENCES users (id)
        )
    ''')
    conn.execute('''
        CREATE TABLE IF NOT EXISTS notification_settings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL UNIQUE,
            activity_push INTEGER DEFAULT 1,
            activity_email INTEGER DEFAULT 0,
            message_push INTEGER DEFAULT 1,
            message_email INTEGER DEFAULT 1,
            walk_friend_push INTEGER DEFAULT 0,
            walk_friend_email INTEGER DEFAULT 0,
            notice_push INTEGER DEFAULT 1,
            notice_email INTEGER DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    conn.execute('''
        CREATE TABLE IF NOT EXISTS diary_entries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            dog_name TEXT,
            mood TEXT,
            title TEXT NOT NULL,
            content TEXT NOT NULL,
            walk_type TEXT,
            weight REAL,
            meal_checked INTEGER DEFAULT 0,
            water_checked INTEGER DEFAULT 0,
            walk_checked INTEGER DEFAULT 0,
            supplement_checked INTEGER DEFAULT 0,
            daily_goal TEXT,
            image_filename TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    conn.execute('CREATE INDEX IF NOT EXISTS idx_diary_entries_user_created_at ON diary_entries(user_id, created_at DESC)')
    conn.execute('''
        CREATE TABLE IF NOT EXISTS diary_settings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL UNIQUE,
            meal_text TEXT,
            water_text TEXT,
            walk_text TEXT,
            supplement_text TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    try:
        conn.execute('ALTER TABLE diary_entries ADD COLUMN daily_goal TEXT')
        conn.commit()
    except sqlite3.OperationalError:
        pass
    try:
        conn.execute('ALTER TABLE comments ADD COLUMN updated_at TEXT')
        conn.commit()
    except sqlite3.OperationalError:
        pass
    conn.execute('''
        UPDATE comments
        SET updated_at = COALESCE(updated_at, created_at, CURRENT_TIMESTAMP)
    ''')

    pet_columns = [
        ('pet_name', 'TEXT'),
        ('pet_breed', 'TEXT'),
        ('pet_age', 'TEXT'),
        ('pet_gender', 'TEXT'),
        ('pet_feature', 'TEXT'),
        ('pet_description', 'TEXT'),
        ('pet_personality', 'TEXT'),
        ('pet_image', 'TEXT'),
        ('created_at', 'TEXT'),
        ('updated_at', 'TEXT')
    ]
    for col_name, col_type in pet_columns:
        try:
            conn.execute(f'ALTER TABLE pets ADD COLUMN {col_name} {col_type}')
            conn.commit()
        except sqlite3.OperationalError:
            pass

    conn.execute('''
        UPDATE pets
        SET pet_name = COALESCE(pet_name, name),
            pet_breed = COALESCE(pet_breed, breed),
            pet_age = COALESCE(pet_age, age),
            pet_gender = COALESCE(pet_gender, gender),
            pet_feature = COALESCE(pet_feature, description),
            pet_description = COALESCE(pet_description, description),
            pet_personality = COALESCE(pet_personality, personality),
            pet_image = COALESCE(pet_image, image),
            created_at = COALESCE(created_at, CURRENT_TIMESTAMP),
            updated_at = COALESCE(updated_at, CURRENT_TIMESTAMP)
    ''')
    conn.commit()
    conn.close()

migrate_db()

@app.route('/mypage')
@login_required
def mypage():
    return redirect(url_for('profile', user_id=session['user_id']))

@app.route('/diary')
@app.route('/my-diary')
def diary():
    if 'user_id' not in session:
        return diary_login_required_response()

    current_user_id = session['user_id']
    conn = get_db_connection()
    diary_defaults = build_diary_defaults_for_user(conn, current_user_id)
    diary_settings = get_or_create_diary_settings(conn, current_user_id)
    current_user = diary_defaults['current_user']
    pet = diary_defaults['pet']
    latest_entry_row = conn.execute(
        '''
        SELECT *
        FROM diary_entries
        WHERE user_id = ?
        ORDER BY created_at DESC, id DESC
        LIMIT 1
        ''',
        (current_user_id,)
    ).fetchone()
    day_start_utc, day_end_utc = get_kst_day_bounds_utc()
    today_entry_row = conn.execute(
        '''
        SELECT *
        FROM diary_entries
        WHERE user_id = ?
          AND created_at >= ?
          AND created_at < ?
        ORDER BY created_at DESC, id DESC
        LIMIT 1
        ''',
        (current_user_id, format_db_timestamp(day_start_utc), format_db_timestamp(day_end_utc))
    ).fetchone()
    diary_entry_rows = conn.execute(
        '''
        SELECT *
        FROM diary_entries
        WHERE user_id = ?
        ORDER BY created_at DESC, id DESC
        ''',
        (current_user_id,)
    ).fetchall()
    conn.close()

    latest_entry = normalize_diary_entry(latest_entry_row)
    today_entry = normalize_diary_entry(today_entry_row)
    diary_entries = normalize_diary_entries(diary_entry_rows)
    streak_summary = build_month_streak_summary(diary_entry_rows)
    checklist_source = today_entry or latest_entry

    checklist_items = [
        {
            'label': '식사',
            'description': diary_settings['meal_text'],
            'checked': bool(checklist_source and checklist_source['meal_checked']),
            'icon': 'utensils-crossed',
            'field': 'meal_checked',
            'settings_field': 'meal_text'
        },
        {
            'label': '수분 섭취',
            'description': diary_settings['water_text'],
            'checked': bool(checklist_source and checklist_source['water_checked']),
            'icon': 'droplets',
            'field': 'water_checked',
            'settings_field': 'water_text'
        },
        {
            'label': '산책',
            'description': diary_settings['walk_text'],
            'checked': bool(checklist_source and checklist_source['walk_checked']),
            'icon': 'footprints',
            'field': 'walk_checked',
            'settings_field': 'walk_text'
        },
        {
            'label': '영양제 복용',
            'description': diary_settings['supplement_text'],
            'checked': bool(checklist_source and checklist_source['supplement_checked']),
            'icon': 'pill',
            'field': 'supplement_checked',
            'settings_field': 'supplement_text'
        }
    ]
    checklist_completed = sum(1 for item in checklist_items if item['checked'])
    checklist_percent = int((checklist_completed / len(checklist_items)) * 100) if checklist_items else 0

    today = datetime.now()
    next_month = (today.replace(day=28) + timedelta(days=4)).replace(day=1)
    days_in_month = (next_month - timedelta(days=1)).day
    calendar_days = list(range(1, days_in_month + 1))
    return render_template(
        'my_diary.html',
        user=normalize_user_row(current_user),
        pet=pet,
        dog_name=diary_defaults['dog_name'],
        latest_entry=latest_entry,
        today_entry=today_entry,
        diary_entries=diary_entries,
        checklist_items=checklist_items,
        checklist_completed=checklist_completed,
        checklist_percent=checklist_percent,
        streak_summary=streak_summary,
        calendar_days=calendar_days,
        current_month_label=f'{today.month}월',
        current_year=today.year,
        latest_entry_id=latest_entry['id'] if latest_entry else None,
        today_entry_id=today_entry['id'] if today_entry else None
    )

@app.route('/diary/new', methods=['GET', 'POST'])
def diary_new():
    if 'user_id' not in session:
        return diary_login_required_response()

    current_user_id = session['user_id']
    conn = get_db_connection()
    current_user = conn.execute('SELECT * FROM users WHERE id = ?', (current_user_id,)).fetchone()
    pet = get_user_pet(conn, current_user_id)

    if request.method == 'POST':
        try:
            diary_data = extract_diary_form_data()
        except ValueError as exc:
            conn.close()
            if str(exc) in {'공격이 감지되었습니다.', '비정상적인 입력이 감지되었습니다.', '이미지 파일만 업로드 가능합니다.', '파일 크기는 10MB 이하만 업로드 가능합니다.'}:
                return alert_and_back(str(exc))
            flash(str(exc), 'danger')
            return render_template(
                'diary_form.html',
                form_mode='create',
                entry=request.form.to_dict(),
                user=normalize_user_row(current_user),
                pet=pet
            )

        conn.execute(
            '''
            INSERT INTO diary_entries (
                user_id, dog_name, mood, title, content, walk_type, weight,
                meal_checked, water_checked, walk_checked, supplement_checked,
                image_filename, created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''',
            (
                current_user_id,
                diary_data['dog_name'],
                diary_data['mood'],
                diary_data['title'],
                diary_data['content'],
                diary_data['walk_type'],
                diary_data['weight'],
                diary_data['meal_checked'],
                diary_data['water_checked'],
                diary_data['walk_checked'],
                diary_data['supplement_checked'],
                diary_data['image_filename'],
                format_db_timestamp(utcnow())
            )
        )
        conn.commit()
        conn.close()
        flash('다이어리가 저장되었습니다.', 'success')
        return redirect(url_for('diary'))

    conn.close()
    initial_entry = {
        'dog_name': pet['pet_name'] if pet and pet.get('pet_name') else '',
        'mood': '',
        'title': '',
        'content': '',
        'walk_type': '',
        'weight': '',
        'meal_checked': 0,
        'water_checked': 0,
        'walk_checked': 0,
        'supplement_checked': 0
    }
    return render_template(
        'diary_form.html',
        form_mode='create',
        entry=initial_entry,
        user=normalize_user_row(current_user),
        pet=pet
    )

@app.route('/diary/<int:entry_id>/edit', methods=['GET', 'POST'])
def diary_edit(entry_id):
    if 'user_id' not in session:
        return diary_login_required_response()

    current_user_id = session['user_id']
    conn = get_db_connection()
    current_user = conn.execute('SELECT * FROM users WHERE id = ?', (current_user_id,)).fetchone()
    pet = get_user_pet(conn, current_user_id)
    entry_row = conn.execute(
        'SELECT * FROM diary_entries WHERE id = ? AND user_id = ?',
        (entry_id, current_user_id)
    ).fetchone()
    if not entry_row:
        conn.close()
        flash('수정할 다이어리를 찾을 수 없습니다.', 'danger')
        return redirect(url_for('diary'))

    entry = normalize_diary_entry(entry_row)

    if request.method == 'POST':
        previous_image_filename = entry.get('image_filename')
        try:
            diary_data = extract_diary_form_data(existing_image_filename=previous_image_filename)
        except ValueError as exc:
            conn.close()
            if str(exc) in {'공격이 감지되었습니다.', '비정상적인 입력이 감지되었습니다.', '이미지 파일만 업로드 가능합니다.', '파일 크기는 10MB 이하만 업로드 가능합니다.'}:
                return alert_and_back(str(exc))
            flash(str(exc), 'danger')
            draft_entry = request.form.to_dict()
            draft_entry['id'] = entry_id
            draft_entry['image_url'] = entry.get('image_url')
            return render_template(
                'diary_form.html',
                form_mode='edit',
                entry=draft_entry,
                user=normalize_user_row(current_user),
                pet=pet
            )

        conn.execute(
            '''
            UPDATE diary_entries
            SET dog_name = ?, mood = ?, title = ?, content = ?, walk_type = ?,
                weight = ?, meal_checked = ?, water_checked = ?, walk_checked = ?,
                supplement_checked = ?, image_filename = ?
            WHERE id = ? AND user_id = ?
            ''',
            (
                diary_data['dog_name'],
                diary_data['mood'],
                diary_data['title'],
                diary_data['content'],
                diary_data['walk_type'],
                diary_data['weight'],
                diary_data['meal_checked'],
                diary_data['water_checked'],
                diary_data['walk_checked'],
                diary_data['supplement_checked'],
                diary_data['image_filename'],
                entry_id,
                current_user_id
            )
        )
        conn.commit()
        conn.close()
        if diary_data['image_filename'] != previous_image_filename:
            delete_diary_image(previous_image_filename)
        flash('다이어리가 수정되었습니다.', 'success')
        return redirect(url_for('diary'))

    conn.close()
    return render_template(
        'diary_form.html',
        form_mode='edit',
        entry=entry,
        user=normalize_user_row(current_user),
        pet=pet
    )

@app.route('/diary/<int:entry_id>/delete', methods=['POST'])
def diary_delete(entry_id):
    if 'user_id' not in session:
        return diary_login_required_response()

    current_user_id = session['user_id']
    conn = get_db_connection()
    entry = conn.execute(
        'SELECT image_filename FROM diary_entries WHERE id = ? AND user_id = ?',
        (entry_id, current_user_id)
    ).fetchone()
    if not entry:
        conn.close()
        flash('삭제할 다이어리를 찾을 수 없습니다.', 'danger')
        return redirect(url_for('diary'))

    conn.execute(
        'DELETE FROM diary_entries WHERE id = ? AND user_id = ?',
        (entry_id, current_user_id)
    )
    conn.commit()
    conn.close()
    delete_diary_image(entry['image_filename'])
    flash('다이어리가 삭제되었습니다.', 'success')
    return redirect(url_for('diary'))

@app.route('/diary/checklist', methods=['POST'])
def diary_toggle_checklist():
    if 'user_id' not in session:
        log_abnormal_api_request('비로그인 사용자의 다이어리 체크리스트 API 호출')
        return jsonify({'success': False, 'message': '로그인 후 이용 가능합니다.'}), 401

    payload = request.get_json(silent=True) or request.form
    field = (payload.get('field') or '').strip()
    allowed_fields = {
        'meal_checked': 'meal_checked',
        'water_checked': 'water_checked',
        'walk_checked': 'walk_checked',
        'supplement_checked': 'supplement_checked'
    }
    if field not in allowed_fields:
        log_abnormal_api_request('허용되지 않은 다이어리 체크 항목 요청', field)
        return jsonify({'success': False, 'message': '잘못된 체크 항목입니다.'}), 400

    current_user_id = session['user_id']
    conn = get_db_connection()
    entry = ensure_today_diary_entry(conn, current_user_id)
    next_value = 0 if entry[field] else 1
    conn.execute(
        f'UPDATE diary_entries SET {allowed_fields[field]} = ? WHERE id = ? AND user_id = ?',
        (next_value, entry['id'], current_user_id)
    )
    conn.commit()
    updated_entry = conn.execute(
        'SELECT * FROM diary_entries WHERE id = ? AND user_id = ?',
        (entry['id'], current_user_id)
    ).fetchone()
    conn.close()

    completed = sum(
        1 for key in allowed_fields.values()
        if updated_entry[key]
    )
    percent = int((completed / len(allowed_fields)) * 100)
    return jsonify({
        'success': True,
        'entry_id': updated_entry['id'],
        'field': field,
        'checked': bool(updated_entry[field]),
        'completed_count': completed,
        'completed_percent': percent
    })

@app.route('/diary/weight', methods=['POST'])
def diary_update_weight():
    if 'user_id' not in session:
        log_abnormal_api_request('비로그인 사용자의 몸무게 저장 API 호출')
        return jsonify({'success': False, 'message': '로그인 후 이용 가능합니다.'}), 401

    payload = request.get_json(silent=True) or request.form
    try:
        weight = parse_weight_value(payload.get('weight'))
    except ValueError as exc:
        log_abnormal_api_request('유효하지 않은 몸무게 입력', payload.get('weight'))
        return jsonify({'success': False, 'message': str(exc)}), 400

    current_user_id = session['user_id']
    conn = get_db_connection()
    latest_entry = conn.execute(
        '''
        SELECT *
        FROM diary_entries
        WHERE user_id = ?
        ORDER BY created_at DESC, id DESC
        LIMIT 1
        ''',
        (current_user_id,)
    ).fetchone()
    if not latest_entry:
        latest_entry = ensure_today_diary_entry(conn, current_user_id)

    conn.execute(
        'UPDATE diary_entries SET weight = ? WHERE id = ? AND user_id = ?',
        (weight, latest_entry['id'], current_user_id)
    )
    conn.commit()
    updated_entry = conn.execute(
        'SELECT * FROM diary_entries WHERE id = ? AND user_id = ?',
        (latest_entry['id'], current_user_id)
    ).fetchone()
    conn.close()

    return jsonify({
        'success': True,
        'entry_id': updated_entry['id'],
        'weight': updated_entry['weight'],
        'weight_label': f"{updated_entry['weight']:.1f} kg" if updated_entry['weight'] is not None else '미기록'
    })

@app.route('/diary/checklist-text', methods=['POST'])
def diary_update_checklist_text():
    if 'user_id' not in session:
        log_abnormal_api_request('비로그인 사용자의 체크리스트 텍스트 변경 API 호출')
        return jsonify({'success': False, 'message': '로그인 후 이용 가능합니다.'}), 401

    payload = request.get_json(silent=True) or request.form
    field = (payload.get('field') or '').strip()
    value = (payload.get('value') or '').strip()
    allowed_fields = {
        'meal_text': '오늘의 식사 체크',
        'water_text': '오늘 물 섭취 체크',
        'walk_text': '오늘 산책 완료 체크',
        'supplement_text': '오늘 영양제 체크'
    }
    if field not in allowed_fields:
        log_abnormal_api_request('허용되지 않은 체크리스트 텍스트 필드 요청', field)
        return jsonify({'success': False, 'message': '잘못된 설정 항목입니다.'}), 400
    if contains_xss(value):
        return jsonify({'success': False, 'message': '공격이 감지되었습니다.'}), 400

    current_user_id = session['user_id']
    conn = get_db_connection()
    get_or_create_diary_settings(conn, current_user_id)
    final_value = value or allowed_fields[field]
    conn.execute(
        f'UPDATE diary_settings SET {field} = ?, updated_at = ? WHERE user_id = ?',
        (final_value, format_db_timestamp(utcnow()), current_user_id)
    )
    conn.commit()
    conn.close()

    return jsonify({
        'success': True,
        'field': field,
        'value': final_value
    })

@app.route('/u/<username>')
def profile_by_username(username):
    conn = get_db_connection()
    user = conn.execute(
        'SELECT id FROM users WHERE username = ?',
        (normalize_username_value(username),)
    ).fetchone()
    conn.close()
    if not user:
        flash('사용자를 찾을 수 없습니다.', 'danger')
        return redirect(url_for('posts'))
    return redirect(url_for('profile', user_id=user['id']))

@app.route('/admin')
@admin_required
def admin_dashboard():
    return redirect(url_for('admin_users'))

@app.route('/admin/users')
@admin_required
def admin_users():
    conn = get_db_connection()
    users = conn.execute('''
        SELECT
            u.*,
            COUNT(DISTINCT p.id) AS post_count,
            COUNT(DISTINCT fr.id) AS follower_count
        FROM users u
        LEFT JOIN posts p ON p.user_id = u.id
        LEFT JOIN follows fr ON fr.following_id = u.id
        GROUP BY u.id
        ORDER BY CASE WHEN COALESCE(u.role, 'user') = 'admin' THEN 0 ELSE 1 END, u.id ASC
    ''').fetchall()
    users = normalize_user_rows(users)
    conn.close()
    return render_template('admin_users.html', users=users)

@app.route('/admin/security-logs')
@admin_required
def admin_security_logs():
    conn = get_db_connection()
    logs = conn.execute(
        '''
        SELECT *
        FROM security_logs
        ORDER BY occurred_at DESC, id DESC
        LIMIT 300
        '''
    ).fetchall()
    conn.close()
    return render_template('admin_security_logs.html', logs=logs)

@app.route('/admin/users/<int:user_id>/delete', methods=['POST'])
@admin_required
def admin_delete_user(user_id):
    if user_id == session['user_id']:
        flash('현재 로그인한 관리자 계정은 삭제할 수 없습니다.', 'danger')
        return redirect(url_for('admin_users'))

    conn = get_db_connection()
    user = conn.execute('SELECT id, name FROM users WHERE id = ?', (user_id,)).fetchone()
    if not user:
        conn.close()
        flash('삭제할 사용자를 찾을 수 없습니다.', 'danger')
        return redirect(url_for('admin_users'))

    delete_user_account(conn, user_id)
    conn.commit()
    conn.close()
    flash(f"{user['name']} 계정을 삭제했습니다.", 'success')
    return redirect(url_for('admin_users'))

@app.route('/profile/<int:user_id>')
def profile(user_id):
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
    if not user:
        conn.close()
        flash('사용자를 찾을 수 없습니다.', 'danger')
        return redirect(url_for('posts'))
    
    # Get user's posts
    user_posts = conn.execute('SELECT * FROM posts WHERE user_id = ? ORDER BY created_at DESC', (user_id,)).fetchall()
    
    # Get followers/following count
    follower_count = conn.execute('SELECT COUNT(*) FROM follows WHERE following_id = ?', (user_id,)).fetchone()[0]
    following_count = conn.execute('SELECT COUNT(*) FROM follows WHERE follower_id = ?', (user_id,)).fetchone()[0]
    
    # Check if current user is following this user
    is_following = False
    if 'user_id' in session and session['user_id'] != user_id:
        follow_record = conn.execute('SELECT 1 FROM follows WHERE follower_id = ? AND following_id = ?', 
                                    (session['user_id'], user_id)).fetchone()
        is_following = True if follow_record else False
    
    # Get pet info
    pet = get_user_pet(conn, user_id)
    
    user = normalize_user_row(user)
    conn.close()
    return render_template('profile.html', 
                          user=user, 
                          posts=user_posts, 
                          follower_count=follower_count, 
                          following_count=following_count,
                          is_following=is_following,
                          pet=pet)

@app.route('/profile/edit', methods=['GET', 'POST'])
@login_required
def edit_profile():
    conn = get_db_connection()
    if request.method == 'POST':
        nickname = (request.form.get('name') or '').strip()
        username = normalize_username_value(request.form.get('username'))
        bio = (request.form.get('bio') or '').strip()
        status_message = (request.form.get('status_message') or '').strip()
        location = (request.form.get('location') or '').strip()
        profile_file = request.files.get('profile_image')

        if contains_xss(nickname, username, bio, status_message, location):
            conn.close()
            return alert_and_back('공격이 감지되었습니다.')
        if contains_sqli(nickname, username, bio, status_message, location):
            conn.close()
            return block_sqli_form()

        if not nickname:
            conn.close()
            flash('닉네임은 필수입니다.', 'danger')
            return redirect(url_for('edit_profile'))

        if not is_valid_username(username):
            conn.close()
            flash('아이디는 영문 소문자, 숫자, 언더스코어만 사용해 4~20자로 입력해 주세요.', 'danger')
            return redirect(url_for('edit_profile'))

        username_owner = conn.execute(
            'SELECT id FROM users WHERE username = ? AND id != ?',
            (username, session['user_id'])
        ).fetchone()
        if username_owner:
            conn.close()
            flash('이미 사용 중인 아이디입니다.', 'danger')
            return redirect(url_for('edit_profile'))

        user = conn.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()
        profile_image = user['profile_image']
        if profile_file and profile_file.filename:
            try:
                validate_image_file(profile_file)
            except ValueError as exc:
                conn.close()
                return alert_and_back(str(exc))
            filename = secure_filename(profile_file.filename)
            unique_filename = f"profile_{session['user_id']}_{int(time.time())}_{filename}"
            profile_file.save(os.path.join(app.config['UPLOAD_FOLDER'], unique_filename))
            profile_image = f'uploads/{unique_filename}'

        conn.execute(
            '''
            UPDATE users
            SET name = ?, username = ?, bio = ?, profile_image = ?, status_message = ?, location = ?
            WHERE id = ?
            ''',
            (nickname, username, bio, profile_image, status_message, location, session['user_id'])
        )
        conn.commit()
        session['user_name'] = nickname
        session['user_username'] = username
        conn.close()
        flash('프로필이 수정되었습니다.', 'success')
        return redirect(url_for('mypage'))
    
    user = conn.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    user = normalize_user_row(user)
    conn.close()
    return render_template('profile_edit.html', user=user)

@app.route('/account/settings', methods=['GET', 'POST'])
@login_required
def account_settings():
    conn = get_db_connection()
    if request.method == 'POST':
        user = conn.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()
        current_password = request.form.get('current_password') or ''
        new_password = request.form.get('new_password') or ''
        confirm_new_password = request.form.get('confirm_new_password') or ''

        updated_password = user['password']
        reset_temp_password_flag = user['is_temp_password'] if 'is_temp_password' in user.keys() else 0
        if current_password or new_password or confirm_new_password:
            if not current_password or not new_password or not confirm_new_password:
                conn.close()
                flash('비밀번호 변경 시 현재 비밀번호, 새 비밀번호, 새 비밀번호 확인을 모두 입력해 주세요.', 'danger')
                return redirect(url_for('account_settings'))
            if not check_password_hash(user['password'], current_password):
                conn.close()
                flash('현재 비밀번호가 올바르지 않습니다.', 'danger')
                return redirect(url_for('account_settings'))
            if not is_valid_signup_password(new_password):
                conn.close()
                flash('새 비밀번호를 정책에 맞게 입력해 주세요.', 'danger')
                return redirect(url_for('account_settings'))
            if new_password != confirm_new_password:
                conn.close()
                flash('새 비밀번호가 일치하지 않습니다.', 'danger')
                return redirect(url_for('account_settings'))
            updated_password = generate_password_hash(new_password)
            reset_temp_password_flag = 0

        conn.execute(
            '''
            UPDATE users
            SET password = ?, is_temp_password = ?
            WHERE id = ?
            ''',
            (updated_password, reset_temp_password_flag, session['user_id'])
        )
        conn.commit()
        session['is_temp_password'] = reset_temp_password_flag
        conn.close()
        flash('계정 설정이 저장되었습니다.', 'success')
        return redirect(url_for('account_settings'))

    user = conn.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    user = normalize_user_row(user)
    conn.close()
    return render_template('account_settings.html', user=user)

def render_pet_form(mode):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    conn = get_db_connection()
    pet = get_user_pet(conn, session['user_id'])

    if mode == 'register' and pet:
        conn.close()
        return redirect(url_for('edit_pet'))

    if mode == 'edit' and not pet and request.method == 'GET':
        conn.close()
        return redirect(url_for('register_pet'))

    if request.method == 'POST':
        try:
            save_pet_record(conn, session['user_id'], request.form, request.files.get('image'))
        except ValueError as exc:
            conn.close()
            if str(exc) in {'공격이 감지되었습니다.', '비정상적인 입력이 감지되었습니다.', '이미지 파일만 업로드 가능합니다.', '파일 크기는 10MB 이하만 업로드 가능합니다.'}:
                return alert_and_back(str(exc))
            flash(str(exc), 'danger')
            return redirect(request.url)
        conn.commit()
        conn.close()
        flash('반려견 정보가 저장되었습니다.', 'success')
        return redirect(url_for('mypage'))

    conn.close()
    return render_template(
        'pet_edit.html',
        pet=pet,
        mode=mode,
        personality_options=PET_PERSONALITY_OPTIONS
    )

@app.route('/pet/register', methods=['GET', 'POST'])
@login_required
def register_pet():
    return render_pet_form('register')

@app.route('/pet/edit', methods=['GET', 'POST'])
@login_required
def edit_pet():
    return render_pet_form('edit')

@app.route('/follow/<int:user_id>', methods=['POST'])
def follow(user_id):
    if 'user_id' not in session:
        log_abnormal_api_request('비로그인 사용자의 팔로우 API 호출', f'user_id={user_id}')
        return jsonify({'error': 'Unauthorized'}), 401
    
    if session['user_id'] == user_id:
        log_abnormal_api_request('자기 자신을 팔로우하려는 비정상 요청', f'user_id={user_id}')
        return jsonify({'error': 'Cannot follow yourself'}), 400
    
    conn = get_db_connection()
    follow_record = conn.execute('SELECT 1 FROM follows WHERE follower_id = ? AND following_id = ?', 
                                (session['user_id'], user_id)).fetchone()
    
    if follow_record:
        conn.execute('DELETE FROM follows WHERE follower_id = ? AND following_id = ?', 
                    (session['user_id'], user_id))
        delete_matching_notification(conn, user_id, session['user_id'], 'follow')
        action = 'unfollowed'
    else:
        conn.execute('INSERT INTO follows (follower_id, following_id) VALUES (?, ?)', 
                    (session['user_id'], user_id))
        actor_name = session.get('user_name') or '멍친구'
        create_notification(conn, user_id, session['user_id'], 'follow', user_id, build_notification_message('follow', actor_name))
        action = 'followed'
    
    conn.commit()
    conn.close()
    return jsonify({'status': 'success', 'action': action})

@app.route('/messages')
@login_required
def messages_page():
    viewer_id = session['user_id']
    requested_conversation_id = request.args.get('conversation', type=int)
    start_user_id = request.args.get('user', type=int)
    search_query = (request.args.get('q') or '').strip()

    if contains_sqli(search_query):
        return block_sqli_form()

    conn = get_db_connection()
    if start_user_id and start_user_id != viewer_id:
        target_user = conn.execute('SELECT id FROM users WHERE id = ?', (start_user_id,)).fetchone()
        if target_user:
            requested_conversation_id = ensure_conversation(conn, viewer_id, start_user_id)

    conversations = fetch_conversation_list(conn, viewer_id)

    active_conversation = None
    messages = []
    if requested_conversation_id:
        active_conversation = fetch_conversation_detail(conn, requested_conversation_id, viewer_id)
    elif conversations:
        active_conversation = fetch_conversation_detail(conn, conversations[0]['id'], viewer_id)

    if active_conversation:
        mark_conversation_as_read(conn, active_conversation['id'], viewer_id)
        messages = fetch_messages_for_conversation(conn, active_conversation['id'], viewer_id)
        conversations = fetch_conversation_list(conn, viewer_id)
        for conversation in conversations:
            conversation['is_active'] = conversation['id'] == active_conversation['id']
        active_conversation = fetch_conversation_detail(conn, active_conversation['id'], viewer_id)

    search_results = search_message_users(conn, viewer_id, search_query) if search_query else []
    conn.close()
    return render_template(
        'messages.html',
        conversations=conversations,
        active_conversation=active_conversation,
        messages=messages,
        search_query=search_query,
        search_results=search_results
    )

@app.route('/messages/start/<int:user_id>')
@login_required
def start_conversation(user_id):
    if session['user_id'] == user_id:
        flash('본인과는 대화를 시작할 수 없습니다.', 'danger')
        return redirect(url_for('messages_page'))

    conn = get_db_connection()
    target_user = conn.execute('SELECT id FROM users WHERE id = ?', (user_id,)).fetchone()
    if not target_user:
        conn.close()
        flash('대화를 시작할 사용자를 찾을 수 없습니다.', 'danger')
        return redirect(url_for('messages_page'))

    conversation_id = ensure_conversation(conn, session['user_id'], user_id)
    conn.close()
    return redirect(url_for('messages_page', conversation=conversation_id))

@app.route('/messages/<int:conversation_id>/send', methods=['POST'])
def send_message(conversation_id):
    if 'user_id' not in session:
        log_abnormal_api_request('비로그인 사용자의 메시지 전송 API 호출', f'conversation_id={conversation_id}')
        return jsonify({'error': 'Unauthorized'}), 401

    content = (request.form.get('content') or '').strip()
    if not content:
        log_abnormal_api_request('빈 메시지 전송 요청', f'conversation_id={conversation_id}')
        return jsonify({'error': '빈 메시지는 전송할 수 없습니다.'}), 400
    if contains_xss(content):
        return jsonify({'error': '공격이 감지되었습니다.'}), 400
    if contains_sqli(content):
        return block_sqli_ajax()

    viewer_id = session['user_id']
    conn = get_db_connection()
    conversation = fetch_conversation_detail(conn, conversation_id, viewer_id)
    if not conversation:
        conn.close()
        log_abnormal_api_request('존재하지 않거나 접근할 수 없는 대화방 전송 시도', f'conversation_id={conversation_id}')
        return jsonify({'error': 'Conversation not found'}), 404

    receiver_id = conversation['partner_id']
    cursor = conn.execute(
        '''
        INSERT INTO messages (conversation_id, sender_id, receiver_id, content, is_read)
        VALUES (?, ?, ?, ?, 0)
        ''',
        (conversation_id, viewer_id, receiver_id, content)
    )
    actor_name = session.get('user_name') or '멍친구'
    create_notification(
        conn,
        receiver_id,
        viewer_id,
        'message',
        conversation_id,
        build_notification_message('message', actor_name)
    )
    conn.execute(
        'UPDATE conversations SET updated_at = CURRENT_TIMESTAMP WHERE id = ?',
        (conversation_id,)
    )
    conn.commit()
    message = conn.execute(
        'SELECT * FROM messages WHERE id = ?',
        (cursor.lastrowid,)
    ).fetchone()
    conn.close()
    return jsonify({
        'status': 'success',
        'message': normalize_message_row(message, viewer_id),
        'conversation_id': conversation_id,
        'preview': content[:38] + ('...' if len(content) > 38 else ''),
        'display_time': format_message_list_time(message['created_at'])
    })

@app.route('/notifications')
@login_required
def notifications_page():
    conn = get_db_connection()
    conn.execute(
        'UPDATE notifications SET is_read = 1 WHERE recipient_id = ? AND is_read = 0',
        (session['user_id'],)
    )
    conn.commit()
    notifications = fetch_notifications_for_user(conn, session['user_id'])
    conn.close()
    return render_template(
        'notifications.html',
        notifications=notifications
    )

@app.route('/notifications/settings', methods=['GET', 'POST'])
@login_required
def notification_settings_page():
    conn = get_db_connection()
    if request.method == 'POST':
        values = {}
        for field, default in NOTIFICATION_SETTING_FIELDS:
            values[field] = 1 if request.form.get(field) == 'on' else 0

        get_notification_settings(conn, session['user_id'])
        conn.execute(
            '''
            UPDATE notification_settings
            SET activity_push = ?, activity_email = ?, message_push = ?, message_email = ?,
                walk_friend_push = ?, walk_friend_email = ?, notice_push = ?, notice_email = ?,
                updated_at = CURRENT_TIMESTAMP
            WHERE user_id = ?
            ''',
            (
                values['activity_push'],
                values['activity_email'],
                values['message_push'],
                values['message_email'],
                values['walk_friend_push'],
                values['walk_friend_email'],
                values['notice_push'],
                values['notice_email'],
                session['user_id']
            )
        )
        conn.commit()
        conn.close()
        flash('알림 설정이 저장되었습니다.', 'success')
        return redirect(url_for('notification_settings_page'))

    settings = get_notification_settings(conn, session['user_id'])
    conn.close()
    setting_cards = [
        {
            'key': 'activity',
            'title': '활동 알림',
            'description': '좋아요, 댓글, 팔로우 알림',
            'icon': 'heart',
            'push_field': 'activity_push',
            'email_field': 'activity_email'
        },
        {
            'key': 'message',
            'title': '메시지 알림',
            'description': '새 메시지 도착 알림',
            'icon': 'message-square-text',
            'push_field': 'message_push',
            'email_field': 'message_email'
        },
        {
            'key': 'walk',
            'title': '산책 친구',
            'description': '주변 친구들의 산책 시작 소식',
            'icon': 'person-standing',
            'push_field': 'walk_friend_push',
            'email_field': 'walk_friend_email'
        },
        {
            'key': 'notice',
            'title': '공지 및 혜택',
            'description': '서비스 공지 및 이벤트 소식',
            'icon': 'megaphone',
            'push_field': 'notice_push',
            'email_field': 'notice_email'
        }
    ]
    return render_template(
        'notification_settings.html',
        settings=settings,
        setting_cards=setting_cards
    )

@app.route('/notifications/read-all', methods=['POST'])
@login_required
def read_all_notifications():
    conn = get_db_connection()
    conn.execute(
        'UPDATE notifications SET is_read = 1 WHERE recipient_id = ? AND is_read = 0',
        (session['user_id'],)
    )
    conn.commit()
    conn.close()
    return redirect(url_for('notifications_page'))

@app.route('/notifications/<int:notification_id>/open')
@login_required
def open_notification(notification_id):
    conn = get_db_connection()
    notification = conn.execute(
        'SELECT * FROM notifications WHERE id = ? AND recipient_id = ?',
        (notification_id, session['user_id'])
    ).fetchone()
    if not notification:
        conn.close()
        flash('알림을 찾을 수 없습니다.', 'danger')
        return redirect(url_for('notifications_page'))

    conn.execute(
        'UPDATE notifications SET is_read = 1 WHERE id = ?',
        (notification_id,)
    )
    conn.commit()
    redirect_url = resolve_notification_redirect(dict(notification))
    conn.close()
    return redirect(redirect_url)

@app.route('/notifications/<int:notification_id>/delete', methods=['POST'])
@login_required
def delete_notification(notification_id):
    conn = get_db_connection()
    conn.execute(
        'DELETE FROM notifications WHERE id = ? AND recipient_id = ?',
        (notification_id, session['user_id'])
    )
    conn.commit()
    conn.close()
    return redirect(url_for('notifications_page'))

@app.route('/')
def index():
    conn = get_db_connection()
    featured_posts = fetch_posts(conn, session.get('user_id'), limit=3, featured=True)
    conn.close()
    return render_template('index.html', featured_posts=featured_posts)

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit('5 per minute', methods=['POST'])
def login():
    if request.method == 'POST':
        identifier = (request.form.get('identifier') or '').strip()
        password = request.form.get('password')
        if contains_sqli(identifier, password):
            return block_sqli_form()
        
        conn = get_db_connection()
        user = conn.execute(
            'SELECT * FROM users WHERE email = ? OR username = ?',
            (identifier, normalize_username_value(identifier))
        ).fetchone()
        conn.close()
        
        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            session['user_name'] = user['name']
            session['user_username'] = user['username']
            session['role'] = user['role'] or 'user'
            session['is_temp_password'] = user['is_temp_password'] or 0
            if user['is_temp_password']:
                return alert_and_redirect(
                    '현재 임시 비밀번호를 사용 중입니다. 비밀번호를 변경해주세요.',
                    url_for('change_temp_password')
                )
            flash(f"환영합니다, {user['name']}님!", 'success')
            return redirect(url_for('index'))
        else:
            save_security_log(
                'LOGIN_FAILURE',
                input_preview=build_security_input_preview(identifier),
                blocked=True,
                reason='로그인 식별자 또는 비밀번호 불일치'
            )
            flash('이메일 또는 비밀번호가 올바르지 않습니다.', 'danger')
    
    return render_template('login.html')

@app.route('/signup/send-verification', methods=['POST'])
@limiter.limit('3 per minute', methods=['POST'])
def send_signup_verification():
    payload = request.get_json(silent=True) or request.form
    email = normalize_email(payload.get('email'))

    if contains_sqli(email):
        return jsonify({'success': False, 'message': '비정상적인 요청입니다.'}), 400

    if not is_valid_signup_email(email):
        return jsonify({'success': False, 'message': '올바른 이메일 주소를 입력해 주세요.'}), 400

    clear_signup_verification_session()

    conn = get_db_connection()
    try:
        cleanup_email_verifications(conn)

        existing_user = conn.execute(
            'SELECT id FROM users WHERE email = ?',
            (email,)
        ).fetchone()
        if existing_user:
            return jsonify({'success': False, 'message': '이미 사용 중인 이메일입니다.'}), 400

        latest = get_latest_email_verification(conn, email)
        now = utcnow()
        if latest:
            last_sent_at = parse_db_timestamp(latest['last_sent_at'])
            if last_sent_at:
                elapsed = (now - last_sent_at).total_seconds()
                if elapsed < VERIFICATION_RESEND_COOLDOWN_SECONDS:
                    remaining = int(VERIFICATION_RESEND_COOLDOWN_SECONDS - elapsed)
                    return jsonify({
                        'success': False,
                        'message': f'인증번호는 잠시 후 다시 요청해 주세요. ({remaining}초 남음)'
                    }), 429

        code = generate_verification_code()
        now_text = format_db_timestamp(now)
        expires_at = format_db_timestamp(now + timedelta(minutes=VERIFICATION_EXPIRY_MINUTES))
        code_hash = generate_password_hash(code)

        conn.execute(
            'UPDATE email_verifications SET used = 1 WHERE email = ? AND used = 0',
            (email,)
        )
        cursor = conn.execute(
            '''
            INSERT INTO email_verifications (
                email, code_hash, expires_at, verified, used, created_at, last_sent_at, attempt_count
            )
            VALUES (?, ?, ?, 0, 0, ?, ?, 0)
            ''',
            (email, code_hash, expires_at, now_text, now_text)
        )
        verification_id = cursor.lastrowid
        conn.commit()

        try:
            send_signup_verification_email(email, code)
        except RuntimeError as exc:
            logger.exception('Signup verification mail configuration error for %s', email)
            conn.execute('DELETE FROM email_verifications WHERE id = ?', (verification_id,))
            conn.commit()
            return jsonify({
                'success': False,
                'message': '현재 이메일 인증 서비스를 사용할 수 없습니다. 잠시 후 다시 시도해 주세요.'
            }), 500
        except Exception:
            logger.exception('Failed to send signup verification email to %s', email)
            conn.execute('DELETE FROM email_verifications WHERE id = ?', (verification_id,))
            conn.commit()
            return jsonify({
                'success': False,
                'message': '현재 이메일 인증 서비스를 사용할 수 없습니다. 잠시 후 다시 시도해 주세요.'
            }), 500

        return jsonify({
            'success': True,
            'message': f'인증번호를 전송했습니다. {VERIFICATION_EXPIRY_MINUTES}분 안에 입력해 주세요.'
        })
    finally:
        conn.close()

@app.route('/signup/verify-code', methods=['POST'])
def verify_signup_code():
    payload = request.get_json(silent=True) or request.form
    email = normalize_email(payload.get('email'))
    code = (payload.get('code') or '').strip()

    if contains_sqli(email, code):
        return jsonify({'success': False, 'message': '비정상적인 요청입니다.'}), 400

    if not is_valid_signup_email(email):
        return jsonify({'success': False, 'message': '올바른 이메일 주소를 입력해 주세요.'}), 400
    if not re.fullmatch(r'\d{6}', code):
        return jsonify({'success': False, 'message': '인증번호 6자리를 입력해 주세요.'}), 400

    conn = get_db_connection()
    try:
        cleanup_email_verifications(conn)

        latest = get_latest_email_verification(conn, email)
        if not latest:
            return jsonify({'success': False, 'message': '먼저 인증번호를 전송해 주세요.'}), 400

        if latest['verified']:
            session['verified_signup_email'] = email
            session['verified_signup_at'] = format_db_timestamp(utcnow())
            return jsonify({'success': True, 'message': '이미 인증이 완료된 이메일입니다. 회원가입을 진행해 주세요.'})

        if latest['used']:
            return jsonify({'success': False, 'message': '이 인증번호는 더 이상 사용할 수 없습니다. 다시 전송해 주세요.'}), 400

        expires_at = parse_db_timestamp(latest['expires_at'])
        if not expires_at or expires_at < utcnow():
            conn.execute(
                'UPDATE email_verifications SET used = 1 WHERE id = ?',
                (latest['id'],)
            )
            conn.commit()
            return jsonify({'success': False, 'message': '인증번호가 만료되었습니다. 다시 전송해 주세요.'}), 400

        next_attempt_count = (latest['attempt_count'] or 0) + 1
        if not check_password_hash(latest['code_hash'], code):
            used_value = 1 if next_attempt_count >= VERIFICATION_MAX_ATTEMPTS else 0
            conn.execute(
                'UPDATE email_verifications SET attempt_count = ?, used = ? WHERE id = ?',
                (next_attempt_count, used_value, latest['id'])
            )
            conn.commit()
            if used_value:
                return jsonify({
                    'success': False,
                    'message': '인증번호 입력 횟수를 초과했습니다. 새 인증번호를 다시 요청해 주세요.'
                }), 400
            return jsonify({'success': False, 'message': '인증번호가 올바르지 않습니다.'}), 400

        conn.execute(
            'UPDATE email_verifications SET verified = 1, used = 1, attempt_count = ? WHERE id = ?',
            (next_attempt_count, latest['id'])
        )
        conn.commit()
        session['verified_signup_email'] = email
        session['verified_signup_at'] = format_db_timestamp(utcnow())
        return jsonify({'success': True, 'message': '이메일 인증이 완료되었습니다. 회원가입을 진행해 주세요.'})
    finally:
        conn.close()

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        name = (request.form.get('name') or '').strip()
        username = normalize_username_value(request.form.get('username'))
        email = normalize_email(request.form.get('email'))
        phone = (request.form.get('phone') or '').strip()
        password = request.form.get('password') or ''
        confirm_password = request.form.get('confirm_password') or ''

        if contains_xss(name, username):
            return alert_and_back('공격이 감지되었습니다.')
        if contains_sqli(name, username, email):
            return block_sqli_form()

        if not name or not username or not email or not phone or not password or not confirm_password:
            return alert_and_back('모든 값을 다 입력해주세요.')

        if not is_valid_signup_username(username):
            return alert_and_back('아이디를 정책에 맞게 입력해주세요.')

        if not is_valid_signup_name(name):
            return alert_and_back('이름을 정책에 맞게 입력해주세요.')

        if not is_valid_signup_password(password):
            return alert_and_back('비밀번호를 정책에 맞게 입력해주세요.')

        if not is_valid_signup_email(email):
            return alert_and_back('이메일을 정책에 맞게 입력해주세요.')

        if not is_valid_phone_number(phone):
            return alert_and_back('전화번호를 정책에 맞게 입력해주세요.')
        
        if password != confirm_password:
            return alert_and_back('비밀번호가 일치하지 않습니다.')
            
        hashed_pw = generate_password_hash(password)
        
        conn = get_db_connection()
        try:
            cleanup_email_verifications(conn)

            duplicate_user = conn.execute(
                'SELECT id FROM users WHERE email = ? OR username = ?',
                (email, username)
            ).fetchone()
            if duplicate_user:
                return alert_and_back('이미 사용 중인 이메일 또는 아이디입니다.')

            latest_verification = get_latest_email_verification(conn, email)
            verified_email = normalize_email(session.get('verified_signup_email'))
            if verified_email != email or not latest_verification or not latest_verification['verified']:
                return alert_and_back('이메일 인증을 완료한 뒤 회원가입해 주세요.')

            conn.execute(
                '''
                INSERT INTO users (name, username, email, password, role, email_verified)
                VALUES (?, ?, ?, ?, ?, ?)
                ''',
                (name, username, email, hashed_pw, 'user', 1)
            )
            conn.execute('DELETE FROM email_verifications WHERE email = ?', (email,))
            conn.commit()
            clear_signup_verification_session()
            flash('회원가입이 완료되었습니다. 로그인해 주세요.', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            return alert_and_back('이미 사용 중인 이메일 또는 아이디입니다.')
        finally:
            conn.close()
            
    return render_template(
        'signup.html',
        mail_configured=is_mail_configured(),
        verified_signup_email=normalize_email(session.get('verified_signup_email'))
    )

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

def extract_hashtags(text):
    return re.findall(r'#(\w+)', text)

# Board/Post functionality (Mandatory Requirement)
@app.route('/community', endpoint='community')
@app.route('/posts')
def posts():
    conn = get_db_connection()
    posts_list = fetch_posts(conn, session.get('user_id'))
    
    # Fetch actual users for suggestions
    all_users = conn.execute('SELECT id, name, username, profile_image FROM users').fetchall()
    all_users = normalize_user_rows(all_users)
    
    # Extract actual hashtags from all posts
    all_hashtags = []
    for post in posts_list:
        tags = extract_hashtags(post['content'])
        all_hashtags.extend(tags)
    
    # Get unique hashtags and count them (returning top 5)
    from collections import Counter
    trending_tags = [tag for tag, count in Counter(all_hashtags).most_common(5)]
    
    conn.close()
    is_guest = 'user_id' not in session
    open_guest_modal = is_guest and request.args.get('preview') == '1'
    return render_template('posts.html', 
                          posts=posts_list, 
                          suggested_users=all_users, 
                          trending_tags=trending_tags,
                          is_guest=is_guest,
                          open_guest_modal=open_guest_modal)

@app.route('/post/<int:post_id>/like', methods=['POST'])
def toggle_post_like(post_id):
    if 'user_id' not in session:
        log_abnormal_api_request('비로그인 사용자의 좋아요 API 호출', f'post_id={post_id}')
        return jsonify({'error': 'Unauthorized'}), 401

    conn = get_db_connection()
    post = conn.execute('SELECT id, user_id FROM posts WHERE id = ?', (post_id,)).fetchone()
    if not post:
        conn.close()
        log_abnormal_api_request('존재하지 않는 게시물 좋아요 요청', f'post_id={post_id}')
        return jsonify({'error': 'Post not found'}), 404

    like = conn.execute(
        'SELECT id FROM likes WHERE user_id = ? AND post_id = ?',
        (session['user_id'], post_id)
    ).fetchone()

    if like:
        conn.execute('DELETE FROM likes WHERE id = ?', (like['id'],))
        delete_matching_notification(conn, post['user_id'], session['user_id'], 'like', post_id)
        liked = False
    else:
        conn.execute(
            'INSERT INTO likes (user_id, post_id) VALUES (?, ?)',
            (session['user_id'], post_id)
        )
        actor_name = session.get('user_name') or '멍친구'
        create_notification(conn, post['user_id'], session['user_id'], 'like', post_id, build_notification_message('like', actor_name))
        liked = True

    conn.commit()
    like_count = conn.execute(
        'SELECT COUNT(*) FROM likes WHERE post_id = ?',
        (post_id,)
    ).fetchone()[0]
    conn.close()
    return jsonify({'status': 'success', 'liked': liked, 'like_count': like_count})

@app.route('/post/<int:post_id>/comments')
def post_comments(post_id):
    conn = get_db_connection()
    post = fetch_post_by_id(conn, post_id, session.get('user_id'))
    if not post:
        conn.close()
        flash('게시물을 찾을 수 없습니다.', 'danger')
        return redirect(url_for('community'))

    comments = fetch_comments_for_post(conn, post_id, session.get('user_id'), session.get('role', 'user'))
    is_following_author = False
    if session.get('user_id') and session['user_id'] != post['user_id']:
        follow_record = conn.execute(
            'SELECT 1 FROM follows WHERE follower_id = ? AND following_id = ?',
            (session['user_id'], post['user_id'])
        ).fetchone()
        is_following_author = bool(follow_record)
    conn.close()
    return render_template(
        'post_comments.html',
        post=post,
        comments=comments,
        is_following_author=is_following_author
    )

@app.route('/download/post/<int:post_id>')
def download_post_image(post_id):
    if 'user_id' not in session:
        return alert_and_redirect('로그인 후 이용 가능합니다.', url_for('login'))

    conn = get_db_connection()
    post = conn.execute(
        'SELECT id, image_url FROM posts WHERE id = ?',
        (post_id,)
    ).fetchone()
    conn.close()

    if not post:
        return alert_and_back('파일을 찾을 수 없습니다.')

    filename = get_post_upload_filename(post['image_url'])
    if not filename:
        return alert_and_back('파일을 찾을 수 없습니다.')

    file_path = safe_join(app.config['UPLOAD_FOLDER'], filename)
    if not file_path or not os.path.isfile(file_path):
        return alert_and_back('파일을 찾을 수 없습니다.')

    return send_from_directory(
        app.config['UPLOAD_FOLDER'],
        filename,
        as_attachment=True,
        download_name=filename
    )

@app.route('/post/<int:post_id>/comments', methods=['POST'])
def create_comment(post_id):
    if 'user_id' not in session:
        log_abnormal_api_request('비로그인 사용자의 댓글 작성 API 호출', f'post_id={post_id}')
        return jsonify({'error': 'Unauthorized'}), 401

    content = (request.form.get('content') or '').strip()
    if not content:
        log_abnormal_api_request('빈 댓글 작성 요청', f'post_id={post_id}')
        return jsonify({'error': '빈 댓글은 등록할 수 없습니다.'}), 400
    if contains_xss(content):
        return jsonify({'error': '공격이 감지되었습니다.'}), 400
    if contains_sqli(content):
        return block_sqli_ajax()

    conn = get_db_connection()
    post = conn.execute('SELECT id, user_id FROM posts WHERE id = ?', (post_id,)).fetchone()
    if not post:
        conn.close()
        log_abnormal_api_request('존재하지 않는 게시물에 댓글 작성 시도', f'post_id={post_id}')
        return jsonify({'error': 'Post not found'}), 404

    cursor = conn.execute(
        'INSERT INTO comments (post_id, user_id, content) VALUES (?, ?, ?)',
        (post_id, session['user_id'], content)
    )
    actor_name = session.get('user_name') or '멍친구'
    create_notification(conn, post['user_id'], session['user_id'], 'comment', post_id, build_notification_message('comment', actor_name))
    conn.commit()
    comment = conn.execute('''
        SELECT
            c.*,
            u.name AS user_name,
            u.username AS user_username,
            u.profile_image AS user_profile_image,
            1 AS is_owner
        FROM comments c
        JOIN users u ON c.user_id = u.id
        WHERE c.id = ?
    ''', (cursor.lastrowid,)).fetchone()
    comment_count = conn.execute(
        'SELECT COUNT(*) FROM comments WHERE post_id = ?',
        (post_id,)
    ).fetchone()[0]
    conn.close()
    return jsonify({
        'status': 'success',
        'comment': normalize_comment_row(comment),
        'comment_count': comment_count
    })

@app.route('/comment/<int:comment_id>/update', methods=['POST'])
def update_comment(comment_id):
    if 'user_id' not in session:
        log_abnormal_api_request('비로그인 사용자의 댓글 수정 API 호출', f'comment_id={comment_id}')
        return jsonify({'error': 'Unauthorized'}), 401

    content = (request.form.get('content') or '').strip()
    if not content:
        log_abnormal_api_request('빈 댓글 수정 요청', f'comment_id={comment_id}')
        return jsonify({'error': '빈 댓글은 저장할 수 없습니다.'}), 400
    if contains_xss(content):
        return jsonify({'error': '공격이 감지되었습니다.'}), 400
    if contains_sqli(content):
        return block_sqli_ajax()

    conn = get_db_connection()
    comment = conn.execute('SELECT * FROM comments WHERE id = ?', (comment_id,)).fetchone()
    if not comment:
        conn.close()
        log_abnormal_api_request('존재하지 않는 댓글 수정 시도', f'comment_id={comment_id}')
        return jsonify({'error': 'Comment not found'}), 404
    if comment['user_id'] != session['user_id']:
        conn.close()
        log_abnormal_api_request('타인 댓글 수정 권한 우회 시도', f'comment_id={comment_id}')
        return jsonify({'error': 'Forbidden'}), 403

    conn.execute(
        'UPDATE comments SET content = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?',
        (content, comment_id)
    )
    conn.commit()
    updated_comment = conn.execute('''
        SELECT
            c.*,
            u.name AS user_name,
            u.username AS user_username,
            u.profile_image AS user_profile_image,
            1 AS is_owner,
            1 AS can_edit,
            1 AS can_delete
        FROM comments c
        JOIN users u ON c.user_id = u.id
        WHERE c.id = ?
    ''', (comment_id,)).fetchone()
    conn.close()
    return jsonify({'status': 'success', 'comment': normalize_comment_row(updated_comment)})

@app.route('/comment/<int:comment_id>/delete', methods=['POST'])
def delete_comment(comment_id):
    if 'user_id' not in session:
        log_abnormal_api_request('비로그인 사용자의 댓글 삭제 API 호출', f'comment_id={comment_id}')
        return jsonify({'error': 'Unauthorized'}), 401

    conn = get_db_connection()
    comment = conn.execute('SELECT * FROM comments WHERE id = ?', (comment_id,)).fetchone()
    if not comment:
        conn.close()
        log_abnormal_api_request('존재하지 않는 댓글 삭제 시도', f'comment_id={comment_id}')
        return jsonify({'error': 'Comment not found'}), 404
    if comment['user_id'] != session['user_id'] and session.get('role') != 'admin':
        conn.close()
        log_abnormal_api_request('타인 댓글 삭제 권한 우회 시도', f'comment_id={comment_id}')
        return jsonify({'error': 'Forbidden'}), 403

    post_id = comment['post_id']
    conn.execute('DELETE FROM comments WHERE id = ?', (comment_id,))
    conn.commit()
    comment_count = conn.execute(
        'SELECT COUNT(*) FROM comments WHERE post_id = ?',
        (post_id,)
    ).fetchone()[0]
    conn.close()
    return jsonify({'status': 'success', 'comment_id': comment_id, 'comment_count': comment_count})

@app.route('/post/create', methods=['GET', 'POST'])
@login_required
def create_post():
    conn = get_db_connection()
    if request.method == 'POST':
        content = (request.form.get('content') or '').strip()
        location = (request.form.get('location') or '').strip()
        hashtags = (request.form.get('hashtags') or '').strip()
        walk_distance = request.form.get('walk_distance')
        walk_duration = request.form.get('walk_duration')
        walk_completed_time = request.form.get('walk_completed_time')
        walk_memo = (request.form.get('walk_memo') or '').strip()
        latitude = request.form.get('latitude') or request.form.get('walk_lat')
        longitude = request.form.get('longitude') or request.form.get('walk_lng')
        file = request.files.get('image')
        image_url = None

        if contains_xss(content, location, hashtags, walk_memo):
            conn.close()
            return alert_and_back('공격이 감지되었습니다.')
        if contains_sqli(content, location, hashtags, walk_memo):
            conn.close()
            return block_sqli_form()
        
        if file and file.filename:
            try:
                validate_image_file(file)
            except ValueError as exc:
                conn.close()
                return alert_and_back(str(exc))
            filename = secure_filename(file.filename)
            unique_filename = f"{int(time.time())}_{filename}"
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], unique_filename))
            image_url = url_for('static', filename='uploads/' + unique_filename)

        conn.execute('''
            INSERT INTO posts 
            (user_id, content, image_url, location, hashtags, walk_distance, walk_duration, walk_completed_time, walk_memo, latitude, longitude, created_at) 
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            session['user_id'],
            content,
            image_url,
            location,
            hashtags,
            walk_distance,
            walk_duration,
            walk_completed_time,
            walk_memo,
            latitude,
            longitude,
            format_db_timestamp(utcnow())
        ))
        conn.commit()
        conn.close()
        flash('포스트가 성공적으로 등록되었습니다!', 'success')
        return redirect(url_for('posts'))

    current_user = conn.execute(
        'SELECT * FROM users WHERE id = ?',
        (session['user_id'],)
    ).fetchone()
    current_user = normalize_user_row(current_user)
    pet = get_user_pet(conn, session['user_id'])
    recent_place_rows = conn.execute(
        '''
        SELECT location
        FROM posts
        WHERE user_id = ?
          AND TRIM(COALESCE(location, '')) <> ''
        ORDER BY created_at DESC
        ''',
        (session['user_id'],)
    ).fetchall()

    recent_places = []
    seen_places = set()
    for row in recent_place_rows:
        place = (row['location'] or '').strip()
        if not place or place in seen_places:
            continue
        seen_places.add(place)
        recent_places.append(place)
        if len(recent_places) >= 5:
            break

    conn.close()
    return render_template(
        'post_create.html',
        pet=pet,
        post_creator=current_user,
        recent_places=recent_places
    )

@app.route('/post/edit/<int:post_id>', methods=['GET', 'POST'])
@login_required
def edit_post(post_id):
    conn = get_db_connection()
    post = conn.execute('SELECT * FROM posts WHERE id = ?', (post_id,)).fetchone()
    
    if not post:
        conn.close()
        flash('포스트를 찾을 수 없습니다.', 'danger')
        return redirect(url_for('posts'))
        
    if post['user_id'] != session['user_id']:
        conn.close()
        flash('수정 권한이 없습니다.', 'danger')
        return redirect(url_for('posts'))
        
    if request.method == 'POST':
        content = (request.form.get('content') or '').strip()
        if contains_xss(content):
            conn.close()
            return alert_and_back('공격이 감지되었습니다.')
        if contains_sqli(content):
            conn.close()
            return block_sqli_form()
        conn.execute('UPDATE posts SET content = ? WHERE id = ?', (content, post_id))
        conn.commit()
        conn.close()
        flash('포스트가 수정되었습니다.', 'success')
        return redirect(url_for('posts'))
        
    conn.close()
    return render_template('post_edit.html', post=post)

@app.route('/post/delete/<int:post_id>')
@login_required
def delete_post(post_id):
    conn = get_db_connection()
    post = conn.execute('SELECT * FROM posts WHERE id = ?', (post_id,)).fetchone()
    
    if post and (post['user_id'] == session['user_id'] or session.get('role') == 'admin'):
        conn.execute('DELETE FROM posts WHERE id = ?', (post_id,))
        conn.commit()
        flash('포스트가 삭제되었습니다.', 'success')
    else:
        flash('삭제 권한이 없거나 포스트가 없습니다.', 'danger')
        
    conn.close()
    return redirect(url_for('posts'))

@app.route('/find-id', methods=['GET', 'POST'])
def find_id():
    if request.method == 'POST':
        name = request.form.get('name')
        if contains_sqli(name):
            return block_sqli_form()
        conn = get_db_connection()
        user = conn.execute('SELECT email FROM users WHERE name = ?', (name,)).fetchone()
        conn.close()
        
        if user:
            flash(f"계정의 이메일(아이디)은 [{user['email']}] 입니다.", 'success')
            return redirect(url_for('login'))
        else:
            flash('일치하는 사용자 정보가 없습니다.', 'danger')
            
    return render_template('find_id.html')

@app.route('/reset-password', methods=['GET', 'POST'])
@limiter.limit('3 per minute', methods=['POST'])
def reset_password():
    if request.method == 'POST':
        identifier = (request.form.get('identifier') or '').strip()
        if contains_sqli(identifier):
            return block_sqli_form()
        if not identifier:
            return alert_and_back('이메일 주소를 입력해주세요.')

        conn = get_db_connection()
        user = conn.execute(
            'SELECT * FROM users WHERE email = ? OR username = ?',
            (normalize_email(identifier), normalize_username_value(identifier))
        ).fetchone()

        if not user:
            conn.close()
            return alert_and_back('가입된 이메일이 없습니다.')

        email = normalize_email(user['email'])
        temp_password = generate_temporary_password()
        hashed_pw = generate_password_hash(temp_password)

        try:
            send_temporary_password_email(email, temp_password)
        except RuntimeError:
            logger.exception('Temporary password mail configuration error for %s', email)
            conn.close()
            return alert_and_back('현재 이메일 인증 서비스를 사용할 수 없습니다. 잠시 후 다시 시도해 주세요.')
        except Exception:
            logger.exception('Failed to send temporary password email to %s', email)
            conn.close()
            return alert_and_back('현재 이메일 인증 서비스를 사용할 수 없습니다. 잠시 후 다시 시도해 주세요.')

        conn.execute(
            'UPDATE users SET password = ?, is_temp_password = 1 WHERE id = ?',
            (hashed_pw, user['id'])
        )
        conn.commit()
        conn.close()
        return alert_and_redirect('임시 비밀번호를 이메일로 발송했습니다.', url_for('login'))

    return render_template('reset_password.html')

@app.route('/change-temp-password', methods=['GET', 'POST'])
@login_required
def change_temp_password():
    conn = get_db_connection()
    user = conn.execute(
        'SELECT id, is_temp_password FROM users WHERE id = ?',
        (session['user_id'],)
    ).fetchone()

    if not user:
        conn.close()
        session.clear()
        return redirect(url_for('login'))

    if not user['is_temp_password']:
        conn.close()
        return redirect(url_for('mypage'))

    if request.method == 'POST':
        new_password = request.form.get('new_password') or ''
        confirm_password = request.form.get('confirm_password') or ''

        if not new_password or not confirm_password:
            conn.close()
            return alert_and_back('모든 값을 다 입력해주세요.')

        if not is_valid_signup_password(new_password):
            conn.close()
            return alert_and_back('비밀번호를 정책에 맞게 입력해주세요.')

        if new_password != confirm_password:
            conn.close()
            return alert_and_back('비밀번호가 일치하지 않습니다.')

        conn.execute(
            'UPDATE users SET password = ?, is_temp_password = 0 WHERE id = ?',
            (generate_password_hash(new_password), session['user_id'])
        )
        conn.commit()
        conn.close()
        session.clear()
        return alert_and_redirect('비밀번호가 변경되었습니다. 다시 로그인해주세요.', url_for('login'))

    conn.close()
    return render_template('change_temp_password.html')

if __name__ == '__main__':
    app.run(
        debug=not IS_PRODUCTION,
        host=os.getenv('APP_HOST', '127.0.0.1'),
        port=int(os.getenv('APP_PORT', '8000')),
        ssl_context=build_ssl_context()
    )
