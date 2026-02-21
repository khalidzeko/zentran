from flask import Flask, jsonify, render_template, redirect, url_for, request, flash, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_bcrypt import Bcrypt
from flask_mail import Mail, Message
from datetime import datetime, timedelta
import imaplib
import email
from email.header import decode_header
import os
from werkzeug.utils import secure_filename
from flask import send_from_directory

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///ticketapp.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager(app)
bcrypt = Bcrypt(app)
mail = Mail(app)

login_manager.login_view = 'login'

# Models
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    full_name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), nullable=False)
    role = db.Column(db.String(20), nullable=False)
    room = db.Column(db.String(20), nullable=False)

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password_hash, password)

class Ticket(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    submitter_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    room = db.Column(db.String(20), nullable=False)
    category = db.Column(db.String(50), nullable=False)
    description = db.Column(db.Text, nullable=False)
    file_name = db.Column(db.String(200), nullable=True)
    status = db.Column(db.String(20), default='Open')
    assigned_to_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    ip_address = db.Column(db.String(100))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    submitter = db.relationship('User', foreign_keys=[submitter_id], backref='submitted_tickets')
    assigned_to = db.relationship('User', foreign_keys=[assigned_to_id], backref='assigned_tickets')

class TicketComment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ticket_id = db.Column(db.Integer, db.ForeignKey('ticket.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    comment = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    ticket = db.relationship('Ticket', backref=db.backref('comments', lazy=True, cascade='all, delete-orphan'))
    user = db.relationship('User')

class TicketAttachment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ticket_id = db.Column(db.Integer, db.ForeignKey('ticket.id'), nullable=False)
    uploaded_by_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    filename = db.Column(db.String(200), nullable=False)
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow)

    ticket = db.relationship('Ticket', backref=db.backref('attachments', lazy=True, cascade='all, delete-orphan'))
    uploaded_by = db.relationship('User')

class TicketReassignmentRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ticket_id = db.Column(db.Integer, db.ForeignKey('ticket.id'), nullable=False)
    requested_by_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    reason = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(20), default='Pending')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    ticket = db.relationship('Ticket', backref=db.backref('reassignment_requests', lazy=True, cascade='all, delete-orphan'))
    requested_by = db.relationship('User')

# NEW: Notification Model
class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    ticket_id = db.Column(db.Integer, db.ForeignKey('ticket.id'), nullable=False)
    title = db.Column(db.String(200), nullable=False)
    message = db.Column(db.Text, nullable=False)
    notification_type = db.Column(db.String(50), nullable=False)  # 'status_change', 'assignment', 'comment', 'escalation', etc.
    is_read = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    user = db.relationship('User', backref=db.backref('notifications', lazy=True))
    ticket = db.relationship('Ticket', backref=db.backref('notifications', lazy=True))

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # Max 16MB
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'pdf', 'docx', 'xlsx', 'txt'}

# NEW: Notification Helper Functions
def create_notification(user_id, ticket_id, title, message, notification_type):
    """Create a new notification for a user"""
    notification = Notification(
        user_id=user_id,
        ticket_id=ticket_id,
        title=title,
        message=message,
        notification_type=notification_type
    )
    db.session.add(notification)

def notify_ticket_status_change(ticket, old_status, new_status, changed_by):
    """Create notifications when ticket status changes"""
    users_to_notify = []
    
    # Notify submitter
    if ticket.submitter_id != changed_by.id:
        users_to_notify.append(ticket.submitter_id)
    
    # Notify assigned user
    if ticket.assigned_to_id and ticket.assigned_to_id != changed_by.id:
        users_to_notify.append(ticket.assigned_to_id)
    
    # Notify room supervisors/managers
    supervisors = User.query.filter(
        User.room == ticket.room,
        User.role.in_(['supervisor', 'manager'])
    ).all()
    
    for supervisor in supervisors:
        if supervisor.id != changed_by.id:
            users_to_notify.append(supervisor.id)
    
    # Create notifications
    for user_id in set(users_to_notify):  # Remove duplicates
        create_notification(
            user_id=user_id,
            ticket_id=ticket.id,
            title=f"Ticket #{ticket.id} Status Changed",
            message=f"Status changed from '{old_status}' to '{new_status}' by {changed_by.full_name}",
            notification_type='status_change'
        )

def notify_ticket_assignment(ticket, assigned_by):
    """Create notifications when ticket is assigned"""
    users_to_notify = []
    
    # Notify the assigned user
    if ticket.assigned_to_id:
        users_to_notify.append(ticket.assigned_to_id)
    
    # Notify submitter
    if ticket.submitter_id != assigned_by.id:
        users_to_notify.append(ticket.submitter_id)
    
    for user_id in set(users_to_notify):
        create_notification(
            user_id=user_id,
            ticket_id=ticket.id,
            title=f"Ticket #{ticket.id} Assigned",
            message=f"Ticket has been assigned to {ticket.assigned_to.full_name}" if ticket.assigned_to else "Ticket assignment updated",
            notification_type='assignment'
        )

def notify_new_comment(ticket, comment, commenter):
    """Create notifications when a new comment is added"""
    users_to_notify = []
    
    # Notify submitter
    if ticket.submitter_id != commenter.id:
        users_to_notify.append(ticket.submitter_id)
    
    # Notify assigned user
    if ticket.assigned_to_id and ticket.assigned_to_id != commenter.id:
        users_to_notify.append(ticket.assigned_to_id)
    
    # Notify other users who have commented on this ticket
    previous_commenters = db.session.query(TicketComment.user_id).filter(
        TicketComment.ticket_id == ticket.id,
        TicketComment.user_id != commenter.id
    ).distinct().all()
    
    for (user_id,) in previous_commenters:
        users_to_notify.append(user_id)
    
    for user_id in set(users_to_notify):
        create_notification(
            user_id=user_id,
            ticket_id=ticket.id,
            title=f"New Comment on Ticket #{ticket.id}",
            message=f"{commenter.full_name} added a comment: {comment[:100]}{'...' if len(comment) > 100 else ''}",
            notification_type='comment'
        )

def notify_escalation(ticket, escalated_by):
    """Create notifications when ticket is escalated"""
    # Notify all admins
    admins = User.query.filter_by(role='admin').all()
    
    for admin in admins:
        create_notification(
            user_id=admin.id,
            ticket_id=ticket.id,
            title=f"Ticket #{ticket.id} Escalated",
            message=f"Ticket escalated by {escalated_by.full_name} - requires admin attention",
            notification_type='escalation'
        )

# Routes
@app.route('/')
@login_required
def dashboard():
    user = current_user
    filter_type = request.args.get('filter', 'all')
    status_filter = request.args.get('status')
    date_filter = request.args.get('date')

    tickets_query = Ticket.query

    # Permissions: which tickets the user can see
    if user.role == 'agent':
        tickets_query = tickets_query.filter_by(submitter_id=user.id)
    elif user.role in ['supervisor', 'manager']:
        tickets_query = tickets_query.filter_by(room=user.room)
    elif user.role in ['it_staff', 'admin']:
        if filter_type == 'assigned':
            tickets_query = tickets_query.filter_by(assigned_to_id=user.id)
        elif filter_type == 'new':
            tickets_query = tickets_query.filter_by(assigned_to_id=None)

    # Apply status filter
    if status_filter:
        tickets_query = tickets_query.filter_by(status=status_filter)

    # Apply date filter
    if date_filter:
        try:
            date_obj = datetime.strptime(date_filter, '%Y-%m-%d').date()
            tickets_query = tickets_query.filter(db.func.date(Ticket.created_at) == date_obj)
        except ValueError:
            flash("Invalid date format", "danger")

    tickets = tickets_query.order_by(Ticket.created_at.desc()).all()
    
    # Get unread notifications count for the current user
    unread_notifications_count = Notification.query.filter_by(
        user_id=user.id, 
        is_read=False
    ).count()
    
    return render_template('dashboard.html', 
                         tickets=tickets, 
                         user=user, 
                         unread_notifications_count=unread_notifications_count)

# NEW: Notifications Routes
@app.route('/notifications')
@login_required
def notifications():
    """Display all notifications for the current user"""
    page = request.args.get('page', 1, type=int)
    notifications = Notification.query.filter_by(user_id=current_user.id)\
                                    .order_by(Notification.created_at.desc())\
                                    .paginate(page=page, per_page=20, error_out=False)
    
    return render_template('notifications.html', notifications=notifications, user=current_user)

@app.route('/notifications/mark_read/<int:notification_id>')
@login_required
def mark_notification_read(notification_id):
    """Mark a specific notification as read"""
    notification = Notification.query.filter_by(
        id=notification_id, 
        user_id=current_user.id
    ).first_or_404()
    
    notification.is_read = True
    db.session.commit()
    
    return redirect(url_for('ticket_detail', ticket_id=notification.ticket_id))

@app.route('/notifications/mark_all_read')
@login_required
def mark_all_notifications_read():
    """Mark all notifications as read for the current user"""
    Notification.query.filter_by(user_id=current_user.id, is_read=False)\
                     .update({'is_read': True})
    db.session.commit()
    
    flash('All notifications marked as read.', 'success')
    return redirect(url_for('notifications'))

@app.route('/api/notifications/count')
@login_required
def get_notification_count():
    """API endpoint to get unread notification count"""
    count = Notification.query.filter_by(user_id=current_user.id, is_read=False).count()
    return jsonify({'count': count})

@app.route('/api/notifications/recent')
@login_required
def get_recent_notifications():
    """API endpoint to get recent notifications"""
    notifications = Notification.query.filter_by(user_id=current_user.id)\
                                     .order_by(Notification.created_at.desc())\
                                     .limit(5).all()
    
    return jsonify([{
        'id': n.id,
        'title': n.title,
        'message': n.message,
        'type': n.notification_type,
        'is_read': n.is_read,
        'created_at': n.created_at.strftime('%Y-%m-%d %H:%M'),
        'ticket_id': n.ticket_id
    } for n in notifications])

@app.route('/create_user', methods=['GET', 'POST'])
@login_required
def create_user():
    if current_user.role != 'admin':
        abort(403)

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        full_name = request.form['full_name']
        email = request.form['email']
        role = request.form['role']
        room = request.form['room']

        if User.query.filter((User.username == username) | (User.email == email)).first():
            flash('Username or email already exists', 'danger')
            return redirect(url_for('create_user'))

        hashed_pw = bcrypt.generate_password_hash(password).decode('utf-8')
        new_user = User(username=username, password_hash=hashed_pw, full_name=full_name,
                        email=email, role=role, room=room)
        db.session.add(new_user)
        db.session.commit()
        flash('User created successfully', 'success')
        return redirect(url_for('dashboard'))

    return render_template('create_user.html')

@app.route('/user/<int:user_id>/delete', methods=['POST'])
@login_required
def delete_user(user_id):
    if current_user.role not in ['admin', 'it_staff']:
        abort(403)

    user = User.query.get_or_404(user_id)

    if user.id == current_user.id:
        flash("You cannot delete your own account.", "warning")
        return redirect(url_for('manage_users'))

    if user.submitted_tickets or user.assigned_tickets:
        flash("Cannot delete user with assigned or submitted tickets.", "danger")
        return redirect(url_for('manage_users'))

    db.session.delete(user)
    db.session.commit()
    flash(f"User '{user.username}' deleted successfully.", "success")
    return redirect(url_for('manage_users'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password', 'danger')
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/submit_ticket', methods=['GET', 'POST'])
@login_required
def submit_ticket():
    if request.method == 'POST':
        category = request.form['category']
        description = request.form['description']
        file = request.files.get('file')
        filename = None

        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

        # Get the real IP address even behind reverse proxies
        if request.headers.get('X-Forwarded-For'):
            ip_address = request.headers.get('X-Forwarded-For').split(',')[0].strip()
        else:
            ip_address = request.remote_addr

        ticket = Ticket(
            submitter_id=current_user.id,
            room=current_user.room,
            category=category,
            description=description,
            status='Open',
            ip_address=ip_address,
            file_name=filename
        )
        
        db.session.add(ticket)
        db.session.commit()
        
        # NEW: Notify IT staff and supervisors about new ticket
        it_staff = User.query.filter_by(role='it_staff').all()
        supervisors = User.query.filter(
            User.room == ticket.room,
            User.role.in_(['supervisor', 'manager'])
        ).all()
        
        users_to_notify = it_staff + supervisors
        for user in users_to_notify:
            if user.id != current_user.id:
                create_notification(
                    user_id=user.id,
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
    user = current_user

    # Permission checks
    if user.role == 'agent' and ticket.submitter_id != user.id:
        return "Access Denied", 403
    if user.role == 'supervisor' and ticket.room != user.room:
        return "Access Denied", 403

    # Auto-assign if unassigned
    if ticket.assigned_to_id is None and user.role in ['it_staff', 'admin'] and ticket.status != 'Escalated':
        old_assigned = ticket.assigned_to_id
        ticket.assigned_to_id = user.id
        ticket.status = 'In Progress'
        db.session.commit()
        
        # NEW: Notify about assignment
        notify_ticket_assignment(ticket, user)
        db.session.commit()

    if request.method == 'POST':
        action = request.form.get('action')

        if action == 'add_comment':
            comment_text = request.form.get('comment')
            if comment_text:
                new_comment = TicketComment(ticket_id=ticket.id, user_id=user.id, comment=comment_text)
                db.session.add(new_comment)
                db.session.commit()
                
                # NEW: Notify about new comment
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
                    
                    # NEW: Notify about status change
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
                reason = request.form.get('reason')
                if not reason:
                    flash('Reason is required for reassignment request.', 'danger')
                else:
                    existing_request = TicketReassignmentRequest.query.filter_by(
                        ticket_id=ticket.id,
                        requested_by_id=user.id,
                        status='Pending'
                    ).first()
                    if existing_request:
                        flash('You already have a pending reassignment request for this ticket.', 'warning')
                    else:
                        req = TicketReassignmentRequest(
                            ticket_id=ticket.id,
                            requested_by_id=user.id,
                            reason=reason,
                            status='Pending'
                        )
                        db.session.add(req)
                        db.session.commit()
                        
                        # NEW: Notify assigned user about reassignment request
                        if ticket.assigned_to_id:
                            create_notification(
                                user_id=ticket.assigned_to_id,
                                ticket_id=ticket.id,
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
                req_id = request.form.get('request_id')
                decision = request.form.get('decision')
                reassignment_request = TicketReassignmentRequest.query.get(req_id)
                if not reassignment_request or reassignment_request.ticket_id != ticket.id or reassignment_request.status != 'Pending':
                    flash('Invalid reassignment request.', 'danger')
                else:
                    if decision == 'accept':
                        old_assigned_id = ticket.assigned_to_id
                        ticket.assigned_to_id = reassignment_request.requested_by_id
                        ticket.status = 'In Progress'
                        reassignment_request.status = 'Accepted'
                        db.session.commit()
                        
                        # NEW: Notify about reassignment acceptance
                        notify_ticket_assignment(ticket, user)
                        create_notification(
                            user_id=reassignment_request.requested_by_id,
                            ticket_id=ticket.id,
                            title=f"Reassignment Accepted for Ticket #{ticket.id}",
                            message=f"Your reassignment request was accepted by {user.full_name}",
                            notification_type='reassignment_accepted'
                        )
                        db.session.commit()
                        
                        flash('Reassignment accepted.', 'success')
                    elif decision == 'reject':
                        reassignment_request.status = 'Rejected'
                        db.session.commit()
                        
                        # NEW: Notify about reassignment rejection
                        create_notification(
                            user_id=reassignment_request.requested_by_id,
                            ticket_id=ticket.id,
                            title=f"Reassignment Rejected for Ticket #{ticket.id}",
                            message=f"Your reassignment request was rejected by {user.full_name}",
                            notification_type='reassignment_rejected'
                        )
                        db.session.commit()
                        
                        flash('Reassignment rejected.', 'info')
                    else:
                        flash('Invalid decision.', 'danger')

        elif action == 'escalate_ticket':
            if user.role == 'it_staff' and ticket.assigned_to_id == user.id:
                ticket.status = 'Escalated'
                ticket.assigned_to_id = None
                db.session.commit()
                
                # NEW: Notify admins about escalation
                notify_escalation(ticket, user)
                db.session.commit()
                
                flash('Ticket escalated to admin.', 'info')
            else:
                flash('You are not authorized to escalate this ticket.', 'danger')

        elif action == 'accept_escalated_ticket':
            if user.role == 'admin' and ticket.status == 'Escalated':
                ticket.assigned_to_id = user.id
                ticket.status = 'In Progress'
                db.session.commit()
                
                # NEW: Notify about escalation acceptance
                notify_ticket_assignment(ticket, user)
                create_notification(
                    user_id=ticket.submitter_id,
                    ticket_id=ticket.id,
                    title=f"Escalated Ticket #{ticket.id} Accepted",
                    message=f"Your escalated ticket has been accepted by admin {user.full_name}",
                    notification_type='escalation_accepted'
                )
                db.session.commit()
                
                flash('You accepted the escalated ticket.', 'success')
            else:
                flash('You are not authorized to accept this escalated ticket.', 'danger')

        elif action == 'upload_file':
            file = request.files.get('file')
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(filepath)

                attachment = TicketAttachment(
                    ticket_id=ticket.id,
                    uploaded_by_id=user.id,
                    filename=filename
                )
                db.session.add(attachment)
                db.session.commit()
                
                # NEW: Notify about file upload
                users_to_notify = []
                if ticket.submitter_id != user.id:
                    users_to_notify.append(ticket.submitter_id)
                if ticket.assigned_to_id and ticket.assigned_to_id != user.id:
                    users_to_notify.append(ticket.assigned_to_id)
                
                for user_id in set(users_to_notify):
                    create_notification(
                        user_id=user_id,
                        ticket_id=ticket.id,
                        title=f"File Uploaded to Ticket #{ticket.id}",
                        message=f"{user.full_name} uploaded a file: {filename}",
                        notification_type='file_upload'
                    )
                
                db.session.commit()
                flash('File uploaded successfully.', 'success')
            else:
                flash('Invalid file type or no file selected.', 'danger')

        return redirect(url_for('ticket_detail', ticket_id=ticket.id))

    # Get pending reassignment requests
    pending_requests = []
    if user.id == ticket.assigned_to_id:
        pending_requests = TicketReassignmentRequest.query.filter_by(ticket_id=ticket.id, status='Pending').all()

    reassignment_request = TicketReassignmentRequest.query.filter_by(
        ticket_id=ticket.id,
        requested_by_id=user.id
    ).order_by(TicketReassignmentRequest.created_at.desc()).first()

    return render_template('ticket_detail.html',
                           ticket=ticket,
                           user=user,
                           comments=ticket.comments,
                           pending_requests=pending_requests,
                           reassignment_request=reassignment_request)

@app.route('/user/<int:user_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_user(user_id):
    if current_user.role not in ['admin', 'it_staff']:
        abort(403)

    user = User.query.get_or_404(user_id)

    if request.method == 'POST':
        user.full_name = request.form['full_name']
        user.email = request.form['email']
        user.role = request.form['role']
        user.room = request.form['room']

        # Reset password if provided
        new_password = request.form.get('password')
        if new_password:
            user.password_hash = bcrypt.generate_password_hash(new_password).decode('utf-8')

        db.session.commit()
        flash('User updated successfully.', 'success')
        return redirect(url_for('manage_users'))

    return render_template('edit_user.html', user=user)

@app.route('/manage_users')
@login_required
def manage_users():
    if current_user.role not in ['admin', 'it_staff']:
        abort(403)
    users = User.query.all()
    return render_template('manage_users.html', users=users, user=current_user)

@app.route('/profile')
@login_required
def profile():
    return render_template('profile.html', user=current_user)

def create_default_admin():
    admin = User.query.filter_by(username='admin').first()
    if not admin:
        pw_hash = bcrypt.generate_password_hash('admin').decode('utf-8')
        admin = User(username='admin', password_hash=pw_hash,
                     full_name='Administrator', email='admin@gmail.com',
                     role='admin', room='HQ')
        db.session.add(admin)
        db.session.commit()
        print("Default admin created: username=admin, password=admin")

@app.route('/uploads/<filename>')
def uploads(filename):
    return send_from_directory('uploads', filename)

from io import StringIO
import csv
from flask import Response

@app.route('/report', methods=['GET', 'POST'])
@login_required
def report():
    if current_user.role not in ['admin', 'it_staff', 'manager', 'supervisor']:
        abort(403)

    query = Ticket.query

    if request.method == 'POST':
        status = request.form.get('status')
        room = request.form.get('room')
        date_from = request.form.get('date_from')
        date_to = request.form.get('date_to')

        if status:
            query = query.filter_by(status=status)

        if room:
            query = query.filter_by(room=room)

        if date_from and date_to:
            try:
                start = datetime.strptime(date_from, '%Y-%m-%d')
                end = datetime.strptime(date_to, '%Y-%m-%d')
                query = query.filter(Ticket.created_at.between(start, end))
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

    si = StringIO()
    writer = csv.writer(si)

    writer.writerow(['ID', 'Submitter', 'Room', 'Category', 'Status', 'Assigned To', 'Created At'])

    for t in tickets:
        writer.writerow([
            t.id,
            t.submitter.full_name,
            t.room,
            t.category,
            t.status,
            t.assigned_to.full_name if t.assigned_to else '',
            t.created_at.strftime('%Y-%m-%d %H:%M')
        ])

    output = si.getvalue()
    si.close()

    return Response(
        output,
        mimetype='text/csv',
        headers={'Content-Disposition': 'attachment; filename=ticket_report.csv'}
    )


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        create_default_admin()
    app.run(host='0.0.0.0', port=5000, debug=True)