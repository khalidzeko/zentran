import os
import csv
from io import StringIO
from datetime import datetime

import pytz
from flask import (
    Flask, jsonify, render_template, redirect, url_for,
    request, flash, abort, send_from_directory, Response
)
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager, UserMixin, login_user, login_required,
    logout_user, current_user
)
from flask_bcrypt import Bcrypt
from flask_mail import Mail
from werkzeug.utils import secure_filename

# AD / LDAP
from ldap3 import Server, Connection, ALL, SIMPLE, NTLM, SUBTREE
from ldap3.core.exceptions import LDAPException


app = Flask(__name__)

# -----------------------------
# Config
# -----------------------------
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'your-secret-key')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URI', 'sqlite:///ticketapp.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager(app)
bcrypt = Bcrypt(app)
mail = Mail(app)

login_manager.login_view = 'login'

# Riyadh timezone configuration
RIYADH_TZ = pytz.timezone('Asia/Riyadh')


def get_riyadh_time_naive():
    return datetime.now(RIYADH_TZ).replace(tzinfo=None)


def format_riyadh_datetime(dt):
    if dt is None:
        return 'N/A'
    if dt.tzinfo is None:
        riyadh_dt = RIYADH_TZ.localize(dt)
    else:
        riyadh_dt = dt.astimezone(RIYADH_TZ)
    return riyadh_dt.strftime('%Y-%m-%d %H:%M')


# -----------------------------
# Models
# -----------------------------
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)

    username = db.Column(db.String(50), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)

    full_name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), nullable=False)

    role = db.Column(db.String(20), nullable=False)  # agent / supervisor / manager / it_staff / admin
    room = db.Column(db.String(20), nullable=False)

    profile_picture = db.Column(db.String(200), nullable=True)

    # local | ad
    auth_source = db.Column(db.String(20), default='local', nullable=False)

    def check_password(self, password: str) -> bool:
        return bcrypt.check_password_hash(self.password_hash, password)


class Ticket(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    submitter_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    room = db.Column(db.String(20), nullable=False)
    category = db.Column(db.String(50), nullable=False)
    description = db.Column(db.Text, nullable=False)

    file_name = db.Column(db.String(200), nullable=True)  # backward compatibility
    status = db.Column(db.String(20), default='Open')

    assigned_to_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)

    ip_address = db.Column(db.String(100))
    created_at = db.Column(db.DateTime, default=get_riyadh_time_naive)
    updated_at = db.Column(db.DateTime, default=get_riyadh_time_naive, onupdate=get_riyadh_time_naive)

    submitter = db.relationship('User', foreign_keys=[submitter_id], backref='submitted_tickets')
    assigned_to = db.relationship('User', foreign_keys=[assigned_to_id], backref='assigned_tickets')


class TicketComment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ticket_id = db.Column(db.Integer, db.ForeignKey('ticket.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    comment = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=get_riyadh_time_naive)

    ticket = db.relationship('Ticket', backref=db.backref('comments', lazy=True, cascade='all, delete-orphan'))
    user = db.relationship('User')


class TicketAttachment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ticket_id = db.Column(db.Integer, db.ForeignKey('ticket.id'), nullable=False)
    uploaded_by_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    filename = db.Column(db.String(200), nullable=False)
    uploaded_at = db.Column(db.DateTime, default=get_riyadh_time_naive)

    ticket = db.relationship('Ticket', backref=db.backref('attachments', lazy=True, cascade='all, delete-orphan'))
    uploaded_by = db.relationship('User')


class TicketReassignmentRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ticket_id = db.Column(db.Integer, db.ForeignKey('ticket.id'), nullable=False)
    requested_by_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    reason = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(20), default='Pending')
    created_at = db.Column(db.DateTime, default=get_riyadh_time_naive)

    ticket = db.relationship('Ticket', backref=db.backref('reassignment_requests', lazy=True, cascade='all, delete-orphan'))
    requested_by = db.relationship('User')


class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    ticket_id = db.Column(db.Integer, db.ForeignKey('ticket.id'), nullable=False)
    title = db.Column(db.String(200), nullable=False)
    message = db.Column(db.Text, nullable=False)
    notification_type = db.Column(db.String(50), nullable=False)
    is_read = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=get_riyadh_time_naive)

    user = db.relationship('User', backref=db.backref('notifications', lazy=True))
    ticket = db.relationship('Ticket', backref=db.backref('notifications', lazy=True))


# -----------------------------
# Asset Management Models
# -----------------------------
class Asset(db.Model):
    id             = db.Column(db.Integer, primary_key=True)
    asset_tag      = db.Column(db.String(50),  unique=True, nullable=False)
    name           = db.Column(db.String(150), nullable=False)
    category       = db.Column(db.String(50),  nullable=False)
    brand          = db.Column(db.String(100), nullable=True)
    model          = db.Column(db.String(100), nullable=True)
    serial_number  = db.Column(db.String(100), nullable=True)
    status         = db.Column(db.String(30),  default='Available')
    condition      = db.Column(db.String(30),  default='Good')
    room           = db.Column(db.String(20),  nullable=True)
    assigned_to_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    purchase_date  = db.Column(db.Date,        nullable=True)
    warranty_until = db.Column(db.Date,        nullable=True)
    cost           = db.Column(db.Float,       nullable=True)
    ip_address     = db.Column(db.String(50),  nullable=True)
    mac_address    = db.Column(db.String(50),  nullable=True)
    notes          = db.Column(db.Text,        nullable=True)
    created_at     = db.Column(db.DateTime, default=get_riyadh_time_naive)
    updated_at     = db.Column(db.DateTime, default=get_riyadh_time_naive, onupdate=get_riyadh_time_naive)
    created_by_id  = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)

    assigned_to = db.relationship('User', foreign_keys=[assigned_to_id], backref='assigned_assets')
    created_by  = db.relationship('User', foreign_keys=[created_by_id])


class AssetHistory(db.Model):
    id            = db.Column(db.Integer, primary_key=True)
    asset_id      = db.Column(db.Integer, db.ForeignKey('asset.id'), nullable=False)
    changed_by_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    action        = db.Column(db.String(100), nullable=False)
    detail        = db.Column(db.Text,        nullable=True)
    created_at    = db.Column(db.DateTime, default=get_riyadh_time_naive)

    asset      = db.relationship('Asset', backref=db.backref('history', lazy=True, cascade='all, delete-orphan'))
    changed_by = db.relationship('User')


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# -----------------------------
# Upload config
# -----------------------------
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 1 * 1024 * 1024 * 1024  # 1GB
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'pdf', 'docx', 'xlsx', 'txt', 'exe', 'gif'}


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


# -----------------------------
# Notification Helpers
# -----------------------------
def create_notification(user_id, ticket_id, title, message, notification_type):
    notification = Notification(
        user_id=user_id,
        ticket_id=ticket_id,
        title=title,
        message=message,
        notification_type=notification_type
    )
    db.session.add(notification)


def notify_ticket_status_change(ticket, old_status, new_status, changed_by):
    users_to_notify = []
    if ticket.submitter_id != changed_by.id:
        users_to_notify.append(ticket.submitter_id)
    if ticket.assigned_to_id and ticket.assigned_to_id != changed_by.id:
        users_to_notify.append(ticket.assigned_to_id)

    supervisors = User.query.filter(
        User.room == ticket.room,
        User.role.in_(['supervisor', 'manager'])
    ).all()

    for supervisor in supervisors:
        if supervisor.id != changed_by.id:
            users_to_notify.append(supervisor.id)

    for uid in set(users_to_notify):
        create_notification(
            user_id=uid,
            ticket_id=ticket.id,
            title=f"Ticket #{ticket.id} Status Changed",
            message=f"Status changed from '{old_status}' to '{new_status}' by {changed_by.full_name}",
            notification_type='status_change'
        )


def notify_ticket_assignment(ticket, assigned_by):
    users_to_notify = []
    if ticket.assigned_to_id:
        users_to_notify.append(ticket.assigned_to_id)
    if ticket.submitter_id != assigned_by.id:
        users_to_notify.append(ticket.submitter_id)

    for uid in set(users_to_notify):
        create_notification(
            user_id=uid,
            ticket_id=ticket.id,
            title=f"Ticket #{ticket.id} Assigned",
            message=f"Ticket has been assigned to {ticket.assigned_to.full_name}" if ticket.assigned_to else "Ticket assignment updated",
            notification_type='assignment'
        )


def notify_new_comment(ticket, comment_text, commenter):
    users_to_notify = []
    if ticket.submitter_id != commenter.id:
        users_to_notify.append(ticket.submitter_id)
    if ticket.assigned_to_id and ticket.assigned_to_id != commenter.id:
        users_to_notify.append(ticket.assigned_to_id)

    previous_commenters = db.session.query(TicketComment.user_id).filter(
        TicketComment.ticket_id == ticket.id,
        TicketComment.user_id != commenter.id
    ).distinct().all()

    for (uid,) in previous_commenters:
        users_to_notify.append(uid)

    for uid in set(users_to_notify):
        create_notification(
            user_id=uid,
            ticket_id=ticket.id,
            title=f"New Comment on Ticket #{ticket.id}",
            message=f"{commenter.full_name} added a comment: {comment_text[:100]}{'...' if len(comment_text) > 100 else ''}",
            notification_type='comment'
        )


def notify_escalation(ticket, escalated_by):
    admins = User.query.filter_by(role='admin').all()
    for admin in admins:
        create_notification(
            user_id=admin.id,
            ticket_id=ticket.id,
            title=f"Ticket #{ticket.id} Escalated",
            message=f"Ticket escalated by {escalated_by.full_name} - requires admin attention",
            notification_type='escalation'
        )


@app.template_filter('riyadh_datetime')
def riyadh_datetime_filter(dt):
    return format_riyadh_datetime(dt)


# -----------------------------
# Asset Helpers
# -----------------------------
ASSET_ROLES = ('it_staff', 'admin')

ASSET_CATEGORIES = [
    'Desktop PC', 'Laptop', 'Monitor', 'Printer', 'Scanner',
    'Switch', 'Router', 'Access Point', 'Server', 'UPS',
    'Phone', 'Tablet', 'Projector', 'Other'
]

ASSET_STATUSES   = ['Available', 'In Use', 'Under Maintenance', 'Retired', 'Lost']
ASSET_CONDITIONS = ['Good', 'Fair', 'Poor', 'Damaged']


def log_asset_history(asset_id, user_id, action, detail=None):
    db.session.add(AssetHistory(
        asset_id=asset_id,
        changed_by_id=user_id,
        action=action,
        detail=detail
    ))


# -----------------------------
# AD / LDAP config
# -----------------------------
AD_SERVER        = os.environ.get("AD_SERVER",        "192.168.101.250")
AD_DOMAIN        = os.environ.get("AD_DOMAIN",        "exp.local")
AD_BASE_DN       = os.environ.get("AD_BASE_DN",       "DC=exp,DC=local")
AD_NETBIOS       = os.environ.get("AD_NETBIOS",       "EXP")
AD_USE_SSL       = os.environ.get("AD_USE_SSL",       "false").lower() == "true"
AD_REQUIRE_GROUP_DN = os.environ.get("AD_REQUIRE_GROUP_DN", "").strip()
DEFAULT_AD_ROLE  = os.environ.get("DEFAULT_AD_ROLE",  "agent")
DEFAULT_AD_ROOM  = os.environ.get("DEFAULT_AD_ROOM",  "HQ")


def ad_authenticate_and_fetch(username: str, password: str):
    if not username or not password:
        return False, "Missing username/password"

    server = Server(AD_SERVER, get_info=ALL, use_ssl=AD_USE_SSL)
    upn = username if "@" in username else f"{username}@{AD_DOMAIN}"

    try:
        with Connection(server, user=upn, password=password, authentication=SIMPLE, auto_bind=True) as conn:
            user_filter = f"(|(sAMAccountName={username})(userPrincipalName={upn}))"
            conn.search(
                search_base=AD_BASE_DN,
                search_filter=f"(&(objectClass=user){user_filter})",
                search_scope=SUBTREE,
                attributes=["displayName", "mail", "sAMAccountName", "memberOf"]
            )
            if not conn.entries:
                return False, "AD user not found after bind"

            entry = conn.entries[0]
            member_of = entry.memberOf.values if "memberOf" in entry else []

            if AD_REQUIRE_GROUP_DN and AD_REQUIRE_GROUP_DN not in member_of:
                return False, "User not in required group"

            attrs = {
                "full_name":      str(entry.displayName.value) if entry.displayName.value else username,
                "email":          str(entry.mail.value) if entry.mail.value else f"{username}@{AD_DOMAIN}",
                "samaccountname": str(entry.sAMAccountName.value) if entry.sAMAccountName.value else username
            }
            return True, attrs
    except LDAPException:
        pass

    try:
        ntlm_user = f"{AD_NETBIOS}\\{username}"
        with Connection(server, user=ntlm_user, password=password, authentication=NTLM, auto_bind=True) as conn:
            conn.search(
                search_base=AD_BASE_DN,
                search_filter=f"(&(objectClass=user)(sAMAccountName={username}))",
                search_scope=SUBTREE,
                attributes=["displayName", "mail", "sAMAccountName", "memberOf"]
            )
            if not conn.entries:
                return False, "AD user not found after NTLM bind"

            entry = conn.entries[0]
            member_of = entry.memberOf.values if "memberOf" in entry else []

            if AD_REQUIRE_GROUP_DN and AD_REQUIRE_GROUP_DN not in member_of:
                return False, "User not in required group"

            attrs = {
                "full_name":      str(entry.displayName.value) if entry.displayName.value else username,
                "email":          str(entry.mail.value) if entry.mail.value else f"{username}@{AD_DOMAIN}",
                "samaccountname": str(entry.sAMAccountName.value) if entry.sAMAccountName.value else username
            }
            return True, attrs
    except LDAPException:
        pass

    return False, "AD authentication failed"


def get_or_create_local_user_from_ad(ad_attrs: dict):
    sam = ad_attrs["samaccountname"]
    user = User.query.filter_by(username=sam).first()
    if user:
        user.full_name = ad_attrs.get("full_name", user.full_name)
        user.email     = ad_attrs.get("email",     user.email)
        user.auth_source = "ad"
        db.session.commit()
        return user

    random_pw_hash = bcrypt.generate_password_hash(os.urandom(24).hex()).decode('utf-8')
    user = User(
        username=sam,
        password_hash=random_pw_hash,
        full_name=ad_attrs.get("full_name", sam),
        email=ad_attrs.get("email", f"{sam}@{AD_DOMAIN}"),
        role=DEFAULT_AD_ROLE,
        room=DEFAULT_AD_ROOM,
        auth_source="ad"
    )
    db.session.add(user)
    db.session.commit()
    return user


# ==============================
# Routes – Auth
# ==============================
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        username = (request.form.get('username') or "").strip()
        password = request.form.get('password') or ""

        user = User.query.filter_by(username=username).first()
        if user and user.auth_source != "ad":
            if user.check_password(password):
                login_user(user)
                return redirect(url_for('dashboard'))
            return redirect(url_for('login', error='invalid_credentials'))

        try:
            ok, data_or_reason = ad_authenticate_and_fetch(username, password)
            if ok:
                local_user = get_or_create_local_user_from_ad(data_or_reason)
                login_user(local_user)
                return redirect(url_for('dashboard'))
        except ValueError as e:
            if 'MD4' in str(e):
                flash('AD authentication unavailable. Please contact IT support or use local account.', 'warning')
                return redirect(url_for('login'))
            raise
        except Exception as e:
            print(f"AD authentication error: {e}")

        return redirect(url_for('login', error='invalid_credentials'))

    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


# ==============================
# Routes – Dashboard
# ==============================
@app.route('/')
@login_required
def dashboard():
    user = current_user
    filter_type   = request.args.get('filter', 'all')
    status_filter = request.args.get('status')
    date_filter   = request.args.get('date')
    page          = request.args.get('page', 1, type=int)
    per_page      = 5

    tickets_query = Ticket.query

    if user.role == 'agent':
        tickets_query = tickets_query.filter_by(submitter_id=user.id)
    elif user.role in ['supervisor', 'manager']:
        tickets_query = tickets_query.filter_by(room=user.room)
    elif user.role in ['it_staff', 'admin']:
        if filter_type == 'assigned':
            tickets_query = tickets_query.filter_by(assigned_to_id=user.id)
        elif filter_type == 'new':
            tickets_query = tickets_query.filter_by(assigned_to_id=None)

    if status_filter:
        tickets_query = tickets_query.filter_by(status=status_filter)

    if date_filter:
        try:
            date_obj    = datetime.strptime(date_filter, '%Y-%m-%d')
            start_naive = RIYADH_TZ.localize(date_obj.replace(hour=0,  minute=0,  second=0)).replace(tzinfo=None)
            end_naive   = RIYADH_TZ.localize(date_obj.replace(hour=23, minute=59, second=59)).replace(tzinfo=None)
            tickets_query = tickets_query.filter(Ticket.created_at.between(start_naive, end_naive))
        except ValueError:
            flash("Invalid date format", "danger")

    pagination = tickets_query.order_by(Ticket.created_at.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )

    unread_notifications_count = Notification.query.filter_by(
        user_id=user.id, is_read=False
    ).count()

    return render_template(
        'dashboard.html',
        tickets=pagination.items,
        pagination=pagination,
        user=user,
        unread_notifications_count=unread_notifications_count
    )


# ==============================
# Routes – Notifications
# ==============================
@app.route('/notifications')
@login_required
def notifications():
    page = request.args.get('page', 1, type=int)
    notifications_pg = Notification.query.filter_by(user_id=current_user.id) \
        .order_by(Notification.created_at.desc()) \
        .paginate(page=page, per_page=20, error_out=False)
    return render_template('notifications.html', notifications=notifications_pg, user=current_user)


@app.route('/notifications/mark_read/<int:notification_id>')
@login_required
def mark_notification_read(notification_id):
    notification = Notification.query.filter_by(
        id=notification_id, user_id=current_user.id
    ).first_or_404()
    notification.is_read = True
    db.session.commit()
    return redirect(url_for('ticket_detail', ticket_id=notification.ticket_id))


@app.route('/notifications/mark_all_read')
@login_required
def mark_all_notifications_read():
    Notification.query.filter_by(user_id=current_user.id, is_read=False).update({'is_read': True})
    db.session.commit()
    flash('All notifications marked as read.', 'success')
    return redirect(url_for('notifications'))


@app.route('/api/notifications/count')
@login_required
def get_notification_count():
    count = Notification.query.filter_by(user_id=current_user.id, is_read=False).count()
    return jsonify({'count': count})


@app.route('/api/notifications/recent')
@login_required
def get_recent_notifications():
    notifs = Notification.query.filter_by(user_id=current_user.id) \
        .order_by(Notification.created_at.desc()).limit(5).all()
    return jsonify([{
        'id':         n.id,
        'title':      n.title,
        'message':    n.message,
        'type':       n.notification_type,
        'is_read':    n.is_read,
        'created_at': format_riyadh_datetime(n.created_at),
        'ticket_id':  n.ticket_id
    } for n in notifs])


# ==============================
# Routes – Profile
# ==============================
@app.route('/profile')
@login_required
def profile():
    total_tickets    = Ticket.query.filter_by(submitter_id=current_user.id).count()
    open_tickets     = Ticket.query.filter_by(submitter_id=current_user.id, status='Open').count()
    resolved_tickets = Ticket.query.filter_by(submitter_id=current_user.id, status='Resolved').count()
    return render_template(
        'profile.html', user=current_user,
        total_tickets=total_tickets,
        open_tickets=open_tickets,
        resolved_tickets=resolved_tickets
    )


@app.route('/profile/upload_picture', methods=['POST'])
@login_required
def upload_profile_picture():
    if 'profile_picture' not in request.files:
        return jsonify({'success': False, 'message': 'No file selected'}), 400

    file = request.files['profile_picture']
    if not file or file.filename == '':
        return jsonify({'success': False, 'message': 'No file selected'}), 400

    allowed_extensions = {'png', 'jpg', 'jpeg', 'gif'}
    if not ('.' in file.filename and file.filename.rsplit('.', 1)[1].lower() in allowed_extensions):
        return jsonify({'success': False, 'message': 'Unsupported file type'}), 400

    file.seek(0, 2)
    file_size = file.tell()
    file.seek(0)
    if file_size > 5 * 1024 * 1024:
        return jsonify({'success': False, 'message': 'File too large (max 5MB)'}), 400

    profile_pictures_dir = os.path.join(app.config['UPLOAD_FOLDER'], 'profile_pictures')
    os.makedirs(profile_pictures_dir, exist_ok=True)

    filename        = secure_filename(file.filename)
    unique_filename = f"user_{current_user.id}_{int(datetime.now().timestamp())}_{filename}"
    filepath        = os.path.join(profile_pictures_dir, unique_filename)

    try:
        if current_user.profile_picture:
            old_path = os.path.join(app.config['UPLOAD_FOLDER'], current_user.profile_picture)
            if os.path.exists(old_path):
                os.remove(old_path)

        file.save(filepath)
        current_user.profile_picture = f"profile_pictures/{unique_filename}"
        db.session.commit()

        return jsonify({
            'success':   True,
            'message':   'Profile picture updated',
            'image_url': url_for('uploads', filename=current_user.profile_picture)
        }), 200

    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500


# ==============================
# Routes – Tickets
# ==============================
@app.route('/submit_ticket', methods=['GET', 'POST'])
@login_required
def submit_ticket():
    if request.method == 'POST':
        category    = request.form.get('category', '').strip()
        description = request.form.get('description', '').strip()

        if request.headers.get('X-Forwarded-For'):
            ip_address = request.headers.get('X-Forwarded-For').split(',')[0].strip()
        else:
            ip_address = request.remote_addr

        if not category or not description:
            flash('Category and description are required.', 'danger')
            return redirect(url_for('submit_ticket'))

        ticket = Ticket(
            submitter_id=current_user.id,
            room=current_user.room,
            category=category,
            description=description,
            status='Open',
            ip_address=ip_address
        )
        db.session.add(ticket)
        db.session.commit()

        files = request.files.getlist('files')
        if files:
            os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
            ticket_folder = os.path.join(app.config['UPLOAD_FOLDER'], f'ticket_{ticket.id}')
            os.makedirs(ticket_folder, exist_ok=True)

            for file in files:
                if file and file.filename and allowed_file(file.filename):
                    file.seek(0, 2)
                    file_size = file.tell()
                    file.seek(0)

                    if file_size > 100 * 1024 * 1024:
                        flash(f'File {file.filename} too large (max 100MB)', 'warning')
                        continue

                    filename        = secure_filename(file.filename)
                    unique_filename = f"{int(datetime.now().timestamp())}_{filename}"
                    filepath        = os.path.join(ticket_folder, unique_filename)
                    try:
                        file.save(filepath)
                        attachment = TicketAttachment(
                            ticket_id=ticket.id,
                            uploaded_by_id=current_user.id,
                            filename=f'ticket_{ticket.id}/{unique_filename}'
                        )
                        db.session.add(attachment)

                        if not ticket.file_name:
                            ticket.file_name = f'ticket_{ticket.id}/{unique_filename}'

                    except Exception as e:
                        flash(f'Upload failed for {filename}: {str(e)}', 'danger')

            db.session.commit()

        it_staff    = User.query.filter_by(role='it_staff').all()
        supervisors = User.query.filter(
            User.room == ticket.room,
            User.role.in_(['supervisor', 'manager'])
        ).all()

        for u in set(it_staff + supervisors):
            if u.id != current_user.id:
                create_notification(
                    user_id=u.id,
                    ticket_id=ticket.id,
                    title=f"New Ticket #{ticket.id} Submitted",
                    message=f"New {category} ticket submitted by {current_user.full_name} from {ticket.room}",
                    notification_type='new_ticket'
                )

        db.session.commit()
        flash('Ticket submitted successfully!', 'success')
        return redirect(url_for('dashboard'))

    return render_template('submit_ticket.html', user=current_user)


@app.route('/ticket/<int:ticket_id>', methods=['GET', 'POST'])
@login_required
def ticket_detail(ticket_id):
    ticket = Ticket.query.get_or_404(ticket_id)
    user   = current_user

    if user.role == 'agent'      and ticket.submitter_id != user.id:   return "Access Denied", 403
    if user.role == 'supervisor' and ticket.room          != user.room: return "Access Denied", 403

    if ticket.assigned_to_id is None and user.role in ['it_staff', 'admin'] and ticket.status != 'Escalated':
        ticket.assigned_to_id = user.id
        ticket.status         = 'In Progress'
        db.session.commit()
        notify_ticket_assignment(ticket, user)
        db.session.commit()

    if request.method == 'POST':
        action = request.form.get('action')

        if action == 'add_comment':
            comment_text = (request.form.get('comment') or '').strip()
            if comment_text:
                new_comment = TicketComment(ticket_id=ticket.id, user_id=user.id, comment=comment_text)
                db.session.add(new_comment)
                db.session.commit()
                notify_new_comment(ticket, comment_text, user)
                db.session.commit()
                flash('Comment added successfully.', 'success')

        elif action == 'change_status':
            if user.role not in ['admin', 'it_staff']:
                flash('You are not authorized to change ticket status.', 'danger')
            else:
                old_status = ticket.status
                new_status = request.form.get('status')
                if new_status in ['Open', 'In Progress', 'Escalated', 'Resolved', 'Closed']:
                    ticket.status = new_status
                    db.session.commit()
                    if old_status != new_status:
                        notify_ticket_status_change(ticket, old_status, new_status, user)
                        db.session.commit()
                    flash('Ticket status updated successfully.', 'success')
                else:
                    flash('Invalid status value.', 'danger')

        elif action == 'request_reassignment':
            if user.role not in ['admin', 'it_staff']:
                flash('You are not authorized to request reassignment.', 'danger')
            elif not ticket.assigned_to_id or ticket.assigned_to_id == user.id:
                flash('Ticket is not assigned to another user.', 'warning')
            else:
                reason = (request.form.get('reason') or '').strip()
                if not reason:
                    flash('Reason is required for reassignment request.', 'danger')
                else:
                    existing_request = TicketReassignmentRequest.query.filter_by(
                        ticket_id=ticket.id, requested_by_id=user.id, status='Pending'
                    ).first()
                    if existing_request:
                        flash('You already have a pending reassignment request for this ticket.', 'warning')
                    else:
                        req = TicketReassignmentRequest(
                            ticket_id=ticket.id, requested_by_id=user.id,
                            reason=reason, status='Pending'
                        )
                        db.session.add(req)
                        db.session.commit()

                        if ticket.assigned_to_id:
                            create_notification(
                                user_id=ticket.assigned_to_id, ticket_id=ticket.id,
                                title=f"Reassignment Request for Ticket #{ticket.id}",
                                message=f"{user.full_name} requests reassignment: {reason[:100]}{'...' if len(reason) > 100 else ''}",
                                notification_type='reassignment_request'
                            )
                            db.session.commit()

                        flash('Reassignment request submitted.', 'success')

        elif action == 'handle_reassignment':
            if user.id != ticket.assigned_to_id:
                flash('You are not authorized to handle reassignment requests.', 'danger')
            else:
                req_id   = request.form.get('request_id')
                decision = request.form.get('decision')
                reassignment_request = TicketReassignmentRequest.query.get(req_id)

                if (not reassignment_request) or reassignment_request.ticket_id != ticket.id or reassignment_request.status != 'Pending':
                    flash('Invalid reassignment request.', 'danger')
                else:
                    if decision == 'accept':
                        ticket.assigned_to_id        = reassignment_request.requested_by_id
                        ticket.status                = 'In Progress'
                        reassignment_request.status  = 'Accepted'
                        db.session.commit()

                        notify_ticket_assignment(ticket, user)
                        create_notification(
                            user_id=reassignment_request.requested_by_id, ticket_id=ticket.id,
                            title=f"Reassignment Accepted for Ticket #{ticket.id}",
                            message=f"Your reassignment request was accepted by {user.full_name}",
                            notification_type='reassignment_accepted'
                        )
                        db.session.commit()
                        flash('Reassignment accepted.', 'success')

                    elif decision == 'reject':
                        reassignment_request.status = 'Rejected'
                        db.session.commit()

                        create_notification(
                            user_id=reassignment_request.requested_by_id, ticket_id=ticket.id,
                            title=f"Reassignment Rejected for Ticket #{ticket.id}",
                            message=f"Your reassignment request was rejected by {user.full_name}",
                            notification_type='reassignment_rejected'
                        )
                        db.session.commit()
                        flash('Reassignment rejected.', 'info')

        elif action == 'escalate_ticket':
            if user.role == 'it_staff' and ticket.assigned_to_id == user.id:
                ticket.status         = 'Escalated'
                ticket.assigned_to_id = None
                db.session.commit()
                notify_escalation(ticket, user)
                db.session.commit()
                flash('Ticket escalated to admin.', 'info')
            else:
                flash('You are not authorized to escalate this ticket.', 'danger')

        elif action == 'accept_escalated_ticket':
            if user.role == 'admin' and ticket.status == 'Escalated':
                ticket.assigned_to_id = user.id
                ticket.status         = 'In Progress'
                db.session.commit()

                notify_ticket_assignment(ticket, user)
                create_notification(
                    user_id=ticket.submitter_id, ticket_id=ticket.id,
                    title=f"Escalated Ticket #{ticket.id} Accepted",
                    message=f"Your escalated ticket has been accepted by admin {user.full_name}",
                    notification_type='escalation_accepted'
                )
                db.session.commit()
                flash('You accepted the escalated ticket.', 'success')
            else:
                flash('You are not authorized to accept this escalated ticket.', 'danger')

        return redirect(url_for('ticket_detail', ticket_id=ticket.id))

    pending_requests = []
    if user.id == ticket.assigned_to_id:
        pending_requests = TicketReassignmentRequest.query.filter_by(ticket_id=ticket.id, status='Pending').all()

    reassignment_request = TicketReassignmentRequest.query.filter_by(
        ticket_id=ticket.id, requested_by_id=user.id
    ).order_by(TicketReassignmentRequest.created_at.desc()).first()

    return render_template(
        'ticket_detail.html',
        ticket=ticket, user=user,
        comments=ticket.comments,
        pending_requests=pending_requests,
        reassignment_request=reassignment_request
    )


# ==============================
# Routes – User Management
# ==============================
@app.route('/create_user', methods=['GET', 'POST'])
@login_required
def create_user():
    if current_user.role != 'admin':
        abort(403)

    if request.method == 'POST':
        username  = request.form['username'].strip()
        password  = request.form['password']
        full_name = request.form['full_name'].strip()
        email     = request.form['email'].strip()
        role      = request.form['role'].strip()
        room      = request.form['room'].strip()

        if User.query.filter((User.username == username) | (User.email == email)).first():
            flash('Username or email already exists', 'danger')
            return redirect(url_for('create_user'))

        hashed_pw = bcrypt.generate_password_hash(password).decode('utf-8')
        new_user  = User(
            username=username, password_hash=hashed_pw,
            full_name=full_name, email=email,
            role=role, room=room, auth_source="local"
        )
        db.session.add(new_user)
        db.session.commit()
        flash('User created successfully.', 'success')
        return redirect(url_for('manage_users'))

    return render_template('create_user.html')


@app.route('/manage_users')
@login_required
def manage_users():
    if current_user.role not in ['admin', 'it_staff']:
        abort(403)
    users = User.query.order_by(User.id.asc()).all()
    return render_template('manage_users.html', users=users, user=current_user)


@app.route('/user/<int:user_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_user(user_id):
    if current_user.role not in ['admin', 'it_staff']:
        abort(403)

    user_obj = User.query.get_or_404(user_id)

    if request.method == 'POST':
        user_obj.full_name = request.form['full_name'].strip()
        user_obj.email     = request.form['email'].strip()
        user_obj.role      = request.form['role'].strip()
        user_obj.room      = request.form['room'].strip()

        new_password = request.form.get('password', '').strip()
        if new_password:
            user_obj.password_hash = bcrypt.generate_password_hash(new_password).decode('utf-8')
            user_obj.auth_source   = "local"

        db.session.commit()
        flash('User updated successfully.', 'success')
        return redirect(url_for('manage_users'))

    return render_template('edit_user.html', user=user_obj)


@app.route('/user/<int:user_id>/delete', methods=['POST'])
@login_required
def delete_user(user_id):
    if current_user.role not in ['admin', 'it_staff']:
        abort(403)

    user_obj = User.query.get_or_404(user_id)

    if user_obj.id == current_user.id:
        flash("You cannot delete your own account.", "warning")
        return redirect(url_for('manage_users'))

    if user_obj.submitted_tickets or user_obj.assigned_tickets:
        flash("Cannot delete user with assigned or submitted tickets.", "danger")
        return redirect(url_for('manage_users'))

    db.session.delete(user_obj)
    db.session.commit()
    flash(f"User '{user_obj.username}' deleted successfully.", "success")
    return redirect(url_for('manage_users'))


# ==============================
# Routes – Reports
# ==============================
@app.route('/report', methods=['GET', 'POST'])
@login_required
def report():
    if current_user.role not in ['admin', 'it_staff', 'manager', 'supervisor']:
        abort(403)

    query = Ticket.query

    if request.method == 'POST':
        status    = request.form.get('status')
        room      = request.form.get('room')
        date_from = request.form.get('date_from')
        date_to   = request.form.get('date_to')

        if status: query = query.filter_by(status=status)
        if room:   query = query.filter_by(room=room)

        if date_from and date_to:
            try:
                start       = datetime.strptime(date_from, '%Y-%m-%d')
                end         = datetime.strptime(date_to,   '%Y-%m-%d')
                start_naive = RIYADH_TZ.localize(start.replace(hour=0,  minute=0,  second=0)).replace(tzinfo=None)
                end_naive   = RIYADH_TZ.localize(end.replace(hour=23,   minute=59, second=59)).replace(tzinfo=None)
                query = query.filter(Ticket.created_at.between(start_naive, end_naive))
            except ValueError:
                flash('Invalid date format.', 'danger')

    tickets = query.order_by(Ticket.created_at.desc()).all()
    return render_template('report.html', tickets=tickets, user=current_user)


@app.route('/export_csv')
@login_required
def export_csv():
    if current_user.role not in ['admin', 'it_staff', 'manager', 'supervisor']:
        abort(403)

    tickets = Ticket.query.order_by(Ticket.created_at.desc()).all()
    si      = StringIO()
    writer  = csv.writer(si)
    writer.writerow(['ID', 'Submitter', 'Room', 'Category', 'Status', 'Assigned To',
                     'Created At (Riyadh)', 'Updated At (Riyadh)'])

    for t in tickets:
        writer.writerow([
            t.id, t.submitter.full_name, t.room, t.category, t.status,
            t.assigned_to.full_name if t.assigned_to else '',
            format_riyadh_datetime(t.created_at),
            format_riyadh_datetime(t.updated_at)
        ])

    output = si.getvalue()
    si.close()
    return Response(output, mimetype='text/csv',
                    headers={'Content-Disposition': 'attachment; filename=ticket_report_riyadh.csv'})


# ==============================
# Routes – Asset Management
# ==============================
@app.route('/assets')
@login_required
def assets_list():
    if current_user.role not in ASSET_ROLES:
        abort(403)

    search      = request.args.get('search', '').strip()
    cat_filter  = request.args.get('category', '')
    stat_filter = request.args.get('status', '')
    room_filter = request.args.get('room', '')
    page        = request.args.get('page', 1, type=int)
    per_page    = 15

    q = Asset.query

    if search:
        like = f'%{search}%'
        q = q.filter(db.or_(
            Asset.asset_tag.ilike(like),
            Asset.name.ilike(like),
            Asset.serial_number.ilike(like),
            Asset.brand.ilike(like),
            Asset.model.ilike(like),
            Asset.ip_address.ilike(like)
        ))
    if cat_filter:  q = q.filter_by(category=cat_filter)
    if stat_filter: q = q.filter_by(status=stat_filter)
    if room_filter: q = q.filter_by(room=room_filter)

    pagination = q.order_by(Asset.created_at.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )

    stats = {
        'total':       Asset.query.count(),
        'available':   Asset.query.filter_by(status='Available').count(),
        'in_use':      Asset.query.filter_by(status='In Use').count(),
        'maintenance': Asset.query.filter_by(status='Under Maintenance').count(),
    }

    rooms = [r[0] for r in db.session.query(Asset.room).filter(Asset.room != None).distinct().all()]

    return render_template(
        'assets.html',
        assets=pagination.items,
        pagination=pagination,
        stats=stats,
        categories=ASSET_CATEGORIES,
        statuses=ASSET_STATUSES,
        rooms=rooms,
        search=search,
        cat_filter=cat_filter,
        stat_filter=stat_filter,
        room_filter=room_filter,
        user=current_user
    )


@app.route('/assets/new', methods=['GET', 'POST'])
@login_required
def asset_create():
    if current_user.role not in ASSET_ROLES:
        abort(403)

    users = User.query.order_by(User.full_name).all()

    if request.method == 'POST':
        asset_tag = request.form.get('asset_tag', '').strip()
        if Asset.query.filter_by(asset_tag=asset_tag).first():
            flash('Asset tag already exists.', 'danger')
            return redirect(url_for('asset_create'))

        def date_or_none(field):
            val = request.form.get(field, '').strip()
            try:   return datetime.strptime(val, '%Y-%m-%d').date() if val else None
            except ValueError: return None

        cost_raw       = request.form.get('cost', '').strip()
        cost           = float(cost_raw) if cost_raw else None
        assigned_to_id = request.form.get('assigned_to_id') or None
        if assigned_to_id: assigned_to_id = int(assigned_to_id)

        asset = Asset(
            asset_tag      = asset_tag,
            name           = request.form.get('name', '').strip(),
            category       = request.form.get('category', '').strip(),
            brand          = request.form.get('brand', '').strip() or None,
            model          = request.form.get('model', '').strip() or None,
            serial_number  = request.form.get('serial_number', '').strip() or None,
            status         = request.form.get('status', 'Available'),
            condition      = request.form.get('condition', 'Good'),
            room           = request.form.get('room', '').strip() or None,
            assigned_to_id = assigned_to_id,
            purchase_date  = date_or_none('purchase_date'),
            warranty_until = date_or_none('warranty_until'),
            cost           = cost,
            ip_address     = request.form.get('ip_address', '').strip() or None,
            mac_address    = request.form.get('mac_address', '').strip() or None,
            notes          = request.form.get('notes', '').strip() or None,
            created_by_id  = current_user.id
        )
        db.session.add(asset)
        db.session.flush()
        log_asset_history(asset.id, current_user.id, 'Created', f'Asset {asset.asset_tag} created')
        db.session.commit()
        flash('Asset created successfully.', 'success')
        return redirect(url_for('asset_detail', asset_id=asset.id))

    return render_template('asset_form.html',
                           asset=None, users=users,
                           categories=ASSET_CATEGORIES,
                           statuses=ASSET_STATUSES,
                           conditions=ASSET_CONDITIONS,
                           user=current_user)


@app.route('/assets/<int:asset_id>')
@login_required
def asset_detail(asset_id):
    if current_user.role not in ASSET_ROLES:
        abort(403)
    asset = Asset.query.get_or_404(asset_id)
    return render_template('asset_detail.html', asset=asset, user=current_user)


@app.route('/assets/<int:asset_id>/edit', methods=['GET', 'POST'])
@login_required
def asset_edit(asset_id):
    if current_user.role not in ASSET_ROLES:
        abort(403)

    asset = Asset.query.get_or_404(asset_id)
    users = User.query.order_by(User.full_name).all()

    if request.method == 'POST':
        changes = []

        def track(field, label, new_val):
            old_val = getattr(asset, field)
            if str(old_val or '') != str(new_val or ''):
                changes.append(f"{label}: '{old_val}' → '{new_val}'")
            setattr(asset, field, new_val)

        new_tag = request.form.get('asset_tag', '').strip()
        if new_tag != asset.asset_tag:
            existing = Asset.query.filter_by(asset_tag=new_tag).first()
            if existing and existing.id != asset.id:
                flash('Asset tag already in use.', 'danger')
                return redirect(url_for('asset_edit', asset_id=asset.id))

        def date_or_none(field):
            val = request.form.get(field, '').strip()
            try:   return datetime.strptime(val, '%Y-%m-%d').date() if val else None
            except ValueError: return None

        cost_raw       = request.form.get('cost', '').strip()
        cost           = float(cost_raw) if cost_raw else None
        assigned_to_id = request.form.get('assigned_to_id') or None
        if assigned_to_id: assigned_to_id = int(assigned_to_id)

        track('asset_tag',      'Asset Tag',     new_tag)
        track('name',           'Name',          request.form.get('name', '').strip())
        track('category',       'Category',      request.form.get('category', '').strip())
        track('brand',          'Brand',         request.form.get('brand', '').strip() or None)
        track('model',          'Model',         request.form.get('model', '').strip() or None)
        track('serial_number',  'Serial No',     request.form.get('serial_number', '').strip() or None)
        track('status',         'Status',        request.form.get('status', 'Available'))
        track('condition',      'Condition',     request.form.get('condition', 'Good'))
        track('room',           'Room',          request.form.get('room', '').strip() or None)
        track('assigned_to_id', 'Assigned To',  assigned_to_id)
        track('purchase_date',  'Purchase Date', date_or_none('purchase_date'))
        track('warranty_until', 'Warranty Until',date_or_none('warranty_until'))
        track('cost',           'Cost',          cost)
        track('ip_address',     'IP Address',    request.form.get('ip_address', '').strip() or None)
        track('mac_address',    'MAC Address',   request.form.get('mac_address', '').strip() or None)
        track('notes',          'Notes',         request.form.get('notes', '').strip() or None)

        if changes:
            log_asset_history(asset.id, current_user.id, 'Updated', '; '.join(changes))

        db.session.commit()
        flash('Asset updated successfully.', 'success')
        return redirect(url_for('asset_detail', asset_id=asset.id))

    return render_template('asset_form.html',
                           asset=asset, users=users,
                           categories=ASSET_CATEGORIES,
                           statuses=ASSET_STATUSES,
                           conditions=ASSET_CONDITIONS,
                           user=current_user)


@app.route('/assets/<int:asset_id>/delete', methods=['POST'])
@login_required
def asset_delete(asset_id):
    if current_user.role not in ASSET_ROLES:
        abort(403)
    asset = Asset.query.get_or_404(asset_id)
    db.session.delete(asset)
    db.session.commit()
    flash(f"Asset '{asset.asset_tag}' deleted.", 'success')
    return redirect(url_for('assets_list'))


@app.route('/assets/export')
@login_required
def assets_export():
    if current_user.role not in ASSET_ROLES:
        abort(403)

    assets = Asset.query.order_by(Asset.asset_tag).all()
    si     = StringIO()
    writer = csv.writer(si)
    writer.writerow([
        'Asset Tag', 'Name', 'Category', 'Brand', 'Model',
        'Serial No', 'Status', 'Condition', 'Room', 'Assigned To',
        'IP Address', 'MAC Address', 'Purchase Date', 'Warranty Until',
        'Cost (SAR)', 'Notes', 'Created At'
    ])
    for a in assets:
        writer.writerow([
            a.asset_tag, a.name, a.category, a.brand or '', a.model or '',
            a.serial_number or '', a.status, a.condition, a.room or '',
            a.assigned_to.full_name if a.assigned_to else '',
            a.ip_address or '', a.mac_address or '',
            a.purchase_date.strftime('%Y-%m-%d') if a.purchase_date else '',
            a.warranty_until.strftime('%Y-%m-%d') if a.warranty_until else '',
            a.cost or '', a.notes or '',
            format_riyadh_datetime(a.created_at)
        ])

    output = si.getvalue()
    si.close()
    return Response(output, mimetype='text/csv',
                    headers={'Content-Disposition': 'attachment; filename=assets_export.csv'})


# ==============================
# Routes – Misc
# ==============================
@app.route('/uploads/<path:filename>')
def uploads(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)


@app.route('/debug/users')
@login_required
def debug_users():
    if current_user.role != 'admin':
        abort(403)
    users = User.query.order_by(User.id.asc()).all()
    return jsonify([{
        "id": u.id, "username": u.username, "full_name": u.full_name,
        "email": u.email, "role": u.role, "room": u.room, "auth_source": u.auth_source
    } for u in users])


# ==============================
# Startup
# ==============================
def create_default_admin():
    admin = User.query.filter_by(username='admin').first()
    if not admin:
        pw_hash = bcrypt.generate_password_hash('admin').decode('utf-8')
        admin   = User(
            username='admin', password_hash=pw_hash,
            full_name='Administrator', email='admin@gmail.com',
            role='admin', room='HQ', auth_source='local'
        )
        db.session.add(admin)
        db.session.commit()
        print("Default admin created: username=admin, password=admin")


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        create_default_admin()
    app.run(host='0.0.0.0', port=5005, debug=True)