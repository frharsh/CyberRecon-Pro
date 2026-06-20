"""
CyberRecon Pro - Main Flask Application
Production-grade cybersecurity reconnaissance platform
For authorized security assessments and educational purposes only.
"""

import os
import json
import threading
import subprocess
import shlex
import shutil
from datetime import datetime, timedelta
from functools import wraps

from flask import (Flask, render_template, redirect, url_for, request,
                   flash, session, jsonify, send_file, abort, Response)
from flask_sqlalchemy import SQLAlchemy
from flask_login import (LoginManager, UserMixin, login_user, logout_user,
                         login_required, current_user)
from flask_wtf.csrf import CSRFProtect
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from config import config

# ─── App Factory ──────────────────────────────────────────────────────────────
app = Flask(__name__)
app.config.from_object(config['development'])

db        = SQLAlchemy(app)
csrf      = CSRFProtect(app)
login_mgr = LoginManager(app)
login_mgr.login_view      = 'login'
login_mgr.login_message   = 'Please log in to access CyberRecon Pro.'
login_mgr.login_message_category = 'warning'

# Ensure required directories exist
for d in [app.config['REPORTS_DIR'], app.config['SCREENSHOTS_DIR']]:
    os.makedirs(d, exist_ok=True)

# ─── Database Models ───────────────────────────────────────────────────────────
class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id            = db.Column(db.Integer, primary_key=True)
    username      = db.Column(db.String(80), unique=True, nullable=False)
    email         = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    role          = db.Column(db.String(20), default='analyst')   # admin | analyst
    is_active     = db.Column(db.Boolean, default=True)
    created_at    = db.Column(db.DateTime, default=datetime.utcnow)
    last_login    = db.Column(db.DateTime)

    targets  = db.relationship('Target', backref='owner', lazy='dynamic')
    scans    = db.relationship('Scan',   backref='operator', lazy='dynamic')
    notes    = db.relationship('Note',   backref='author',  lazy='dynamic')
    reports  = db.relationship('Report', backref='creator', lazy='dynamic')
    logs     = db.relationship('ActivityLog', backref='user', lazy='dynamic')

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f'<User {self.username}>'


class Target(db.Model):
    __tablename__ = 'targets'
    id          = db.Column(db.Integer, primary_key=True)
    user_id     = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    name        = db.Column(db.String(200), nullable=False)
    domain      = db.Column(db.String(255))
    ip_address  = db.Column(db.String(45))
    description = db.Column(db.Text)
    scope       = db.Column(db.Text)       # in-scope IPs/domains
    out_of_scope = db.Column(db.Text)      # out-of-scope IPs/domains
    status      = db.Column(db.String(30), default='active')  # active|inactive|completed
    target_type = db.Column(db.String(50), default='web')
    bug_bounty  = db.Column(db.Boolean, default=False)
    created_at  = db.Column(db.DateTime,  default=datetime.utcnow)
    updated_at  = db.Column(db.DateTime,  default=datetime.utcnow, onupdate=datetime.utcnow)

    scans   = db.relationship('Scan',   backref='target', lazy='dynamic')
    notes   = db.relationship('Note',   backref='target', lazy='dynamic')
    reports = db.relationship('Report', backref='target', lazy='dynamic')


class Scan(db.Model):
    __tablename__ = 'scans'
    id           = db.Column(db.Integer, primary_key=True)
    target_id    = db.Column(db.Integer, db.ForeignKey('targets.id'), nullable=False, index=True)
    user_id      = db.Column(db.Integer, db.ForeignKey('users.id'),   nullable=False, index=True)
    tool         = db.Column(db.String(50), nullable=False)   # nmap|subfinder|amass|...
    scan_type    = db.Column(db.String(100))
    options      = db.Column(db.Text)         # JSON string of scan options
    status       = db.Column(db.String(20), default='pending')  # pending|running|completed|failed
    raw_output   = db.Column(db.Text)
    started_at   = db.Column(db.DateTime, default=datetime.utcnow)
    completed_at = db.Column(db.DateTime)

    results = db.relationship('ScanResult', backref='scan', lazy='dynamic',
                               cascade='all, delete-orphan')


class ScanResult(db.Model):
    __tablename__ = 'scan_results'
    id          = db.Column(db.Integer, primary_key=True)
    scan_id     = db.Column(db.Integer, db.ForeignKey('scans.id'), nullable=False, index=True)
    result_type = db.Column(db.String(50))   # port|subdomain|dns|tech|directory|whois
    data        = db.Column(db.Text)          # JSON
    risk_level  = db.Column(db.String(20), default='informational', index=True)
    ai_analysis = db.Column(db.Text)
    created_at  = db.Column(db.DateTime, default=datetime.utcnow)


class Report(db.Model):
    __tablename__ = 'reports'
    id          = db.Column(db.Integer, primary_key=True)
    user_id     = db.Column(db.Integer, db.ForeignKey('users.id'),    nullable=False)
    target_id   = db.Column(db.Integer, db.ForeignKey('targets.id'),  nullable=True)
    title       = db.Column(db.String(255))
    filename    = db.Column(db.String(255))
    report_type = db.Column(db.String(50), default='full')
    created_at  = db.Column(db.DateTime,  default=datetime.utcnow)


class Note(db.Model):
    __tablename__ = 'notes'
    id         = db.Column(db.Integer, primary_key=True)
    user_id    = db.Column(db.Integer, db.ForeignKey('users.id'),   nullable=False)
    target_id  = db.Column(db.Integer, db.ForeignKey('targets.id'), nullable=True)
    title      = db.Column(db.String(255), nullable=False)
    content    = db.Column(db.Text)
    tags       = db.Column(db.String(500))
    priority   = db.Column(db.String(20), default='medium')  # low|medium|high|critical
    note_type  = db.Column(db.String(50), default='general')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class ActivityLog(db.Model):
    __tablename__ = 'activity_logs'
    id         = db.Column(db.Integer, primary_key=True)
    user_id    = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True, index=True)
    action     = db.Column(db.String(100))
    details    = db.Column(db.Text)
    ip_address = db.Column(db.String(45))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


@login_mgr.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# ─── Helpers ───────────────────────────────────────────────────────────────────
def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'admin':
            abort(403)
        return f(*args, **kwargs)
    return decorated


def log_activity(action, details=''):
    try:
        log = ActivityLog(
            user_id    = current_user.id if current_user.is_authenticated else None,
            action     = action,
            details    = details,
            ip_address = request.remote_addr
        )
        db.session.add(log)
        db.session.commit()
    except Exception:
        pass


def check_tool(tool_name):
    """Check if an external tool is available on PATH."""
    return shutil.which(tool_name) is not None


# ─── Auth Routes ───────────────────────────────────────────────────────────────
@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password) and user.is_active:
            login_user(user, remember=request.form.get('remember'))
            user.last_login = datetime.utcnow()
            db.session.commit()
            log_activity('LOGIN', f'User {username} logged in')
            return redirect(url_for('dashboard'))
        flash('Invalid username or password.', 'danger')
    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email    = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        confirm  = request.form.get('confirm_password', '')

        if not username or not email or not password:
            flash('All fields are required.', 'danger')
        elif password != confirm:
            flash('Passwords do not match.', 'danger')
        elif len(password) < 8:
            flash('Password must be at least 8 characters.', 'danger')
        elif User.query.filter_by(username=username).first():
            flash('Username already taken.', 'danger')
        elif User.query.filter_by(email=email).first():
            flash('Email already registered.', 'danger')
        else:
            # First user becomes admin
            role = 'admin' if User.query.count() == 0 else 'analyst'
            user = User(username=username, email=email, role=role)
            user.set_password(password)
            db.session.add(user)
            db.session.commit()
            log_activity('REGISTER', f'New user registered: {username}')
            flash('Account created! Please log in.', 'success')
            return redirect(url_for('login'))
    return render_template('register.html')


@app.route('/logout')
@login_required
def logout():
    log_activity('LOGOUT', f'User {current_user.username} logged out')
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))


# ─── Dashboard ─────────────────────────────────────────────────────────────────
@app.route('/dashboard')
@login_required
def dashboard():
    targets_count  = Target.query.filter_by(user_id=current_user.id).count()
    scans_count    = Scan.query.filter_by(user_id=current_user.id).count()

    open_ports = ScanResult.query.join(Scan).filter(
        Scan.user_id == current_user.id,
        ScanResult.result_type == 'port'
    ).count()

    subdomains = ScanResult.query.join(Scan).filter(
        Scan.user_id == current_user.id,
        ScanResult.result_type == 'subdomain'
    ).count()

    recent_activity = ActivityLog.query.filter_by(
        user_id=current_user.id
    ).order_by(ActivityLog.created_at.desc()).limit(10).all()

    recent_scans = Scan.query.filter_by(
        user_id=current_user.id
    ).order_by(Scan.started_at.desc()).limit(5).all()

    # Chart data: scans per tool
    from sqlalchemy import func
    tool_counts = db.session.query(
        Scan.tool, func.count(Scan.id)
    ).filter_by(user_id=current_user.id).group_by(Scan.tool).all()

    # Risk distribution
    risk_counts = db.session.query(
        ScanResult.risk_level, func.count(ScanResult.id)
    ).join(Scan).filter(Scan.user_id == current_user.id
    ).group_by(ScanResult.risk_level).all()

    # Scans last 7 days
    seven_days_ago = datetime.utcnow() - timedelta(days=7)
    daily_scans = db.session.query(
        func.date(Scan.started_at), func.count(Scan.id)
    ).filter(
        Scan.user_id == current_user.id,
        Scan.started_at >= seven_days_ago
    ).group_by(func.date(Scan.started_at)).all()

    # Group stats for dashboard.html
    stats = {
        'total_targets': targets_count,
        'total_scans': scans_count,
        'open_ports': open_ports,
        'subdomains': subdomains
    }

    # Format chart data
    tool_labels = [x[0].upper() for x in tool_counts]
    tool_values = [x[1] for x in tool_counts]

    risk_labels = [x[0].upper() for x in risk_counts]
    risk_values = [x[1] for x in risk_counts]

    sorted_daily = sorted(daily_scans, key=lambda x: x[0]) if daily_scans else []
    timeline_dates = [str(x[0]) for x in sorted_daily]
    timeline_counts = [x[1] for x in sorted_daily]

    chart_data = {
        'tool_labels': tool_labels,
        'tool_values': tool_values,
        'risk_labels': risk_labels,
        'risk_values': risk_values,
        'timeline_dates': timeline_dates,
        'timeline_counts': timeline_counts
    }

    # Format activity feed description & timestamp
    activities = []
    for act in recent_activity:
        desc = act.details if act.details else act.action
        activities.append({
            'description': desc,
            'timestamp': act.created_at
        })

    # Tool status check
    tools_status = {
        'nmap':      check_tool('nmap'),
        'subfinder': check_tool('subfinder'),
        'amass':     check_tool('amass'),
        'ffuf':      check_tool('ffuf'),
        'whatweb':   check_tool('whatweb'),
    }

    return render_template('dashboard.html',
        stats           = stats,
        chart_data      = chart_data,
        recent_scans    = recent_scans,
        activities      = activities,
        tools_status    = tools_status,
    )


# ─── Targets ───────────────────────────────────────────────────────────────────
@app.route('/targets')
@login_required
def targets():
    q      = request.args.get('q', '').strip()
    status = request.args.get('status', '')
    query  = Target.query.filter_by(user_id=current_user.id)
    if q:
        query = query.filter(
            db.or_(Target.name.ilike(f'%{q}%'), Target.domain.ilike(f'%{q}%'))
        )
    if status:
        query = query.filter_by(status=status)
    all_targets = query.order_by(Target.created_at.desc()).all()
    return render_template('targets.html', targets=all_targets, q=q, status=status)


@app.route('/targets/add', methods=['GET', 'POST'])
@login_required
def add_target():
    if request.method == 'POST':
        name   = request.form.get('name', '').strip()
        domain = request.form.get('domain', '').strip()
        ip     = request.form.get('ip_address', '').strip()
        desc   = request.form.get('description', '').strip()
        scope  = request.form.get('scope', '').strip()
        target_type  = request.form.get('target_type', 'web').strip()
        out_of_scope = request.form.get('out_of_scope', '').strip()
        bug_bounty   = True if request.form.get('bug_bounty') else False

        if not name:
            flash('Target name is required.', 'danger')
            return redirect(url_for('targets'))
        t = Target(user_id=current_user.id, name=name, domain=domain,
                   ip_address=ip, description=desc, scope=scope,
                   target_type=target_type, out_of_scope=out_of_scope,
                   bug_bounty=bug_bounty)
        db.session.add(t)
        db.session.commit()
        log_activity('ADD_TARGET', f'Added target: {name}')
        flash(f'Target "{name}" added successfully.', 'success')
        return redirect(url_for('targets'))
    else:
        return render_template('add_target.html')


@app.route('/targets/<int:target_id>')
@login_required
def target_detail(target_id):
    t = Target.query.filter_by(id=target_id, user_id=current_user.id).first_or_404()
    scans   = Scan.query.filter_by(target_id=target_id).order_by(Scan.started_at.desc()).all()
    notes   = Note.query.filter_by(target_id=target_id, user_id=current_user.id).order_by(Note.created_at.desc()).all()
    reports = Report.query.filter_by(target_id=target_id, user_id=current_user.id).all()
    return render_template('target_detail.html', target=t, scans=scans, notes=notes, reports=reports)


@app.route('/targets/<int:target_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_target(target_id):
    t = Target.query.filter_by(id=target_id, user_id=current_user.id).first_or_404()
    if request.method == 'POST':
        t.name        = request.form.get('name', t.name).strip()
        t.domain      = request.form.get('domain', t.domain).strip()
        t.ip_address  = request.form.get('ip_address', t.ip_address).strip()
        t.description = request.form.get('description', t.description).strip()
        t.scope       = request.form.get('scope', t.scope).strip()
        t.status      = request.form.get('status', t.status)
        t.target_type  = request.form.get('target_type', t.target_type).strip()
        t.out_of_scope = request.form.get('out_of_scope', t.out_of_scope).strip()
        t.bug_bounty   = True if request.form.get('bug_bounty') else False
        t.updated_at  = datetime.utcnow()
        db.session.commit()
        log_activity('EDIT_TARGET', f'Edited target ID {target_id}')
        flash('Target updated successfully.', 'success')
        return redirect(url_for('target_detail', target_id=target_id))
    else:
        return render_template('edit_target.html', target=t)


@app.route('/targets/<int:target_id>/delete', methods=['GET', 'POST'])
@login_required
def delete_target(target_id):
    t = Target.query.filter_by(id=target_id, user_id=current_user.id).first_or_404()
    name = t.name
    db.session.delete(t)
    db.session.commit()
    log_activity('DELETE_TARGET', f'Deleted target: {name}')
    flash(f'Target "{name}" deleted.', 'success')
    return redirect(url_for('targets'))


# ─── Reconnaissance ─────────────────────────────────────────────────────────────
# In-memory scan output buffer (keyed by scan_id)
_scan_buffers = {}
_scan_lock    = threading.Lock()


def _run_scan_thread(scan_id, app_ctx):
    """Background thread: executes the scan tool and updates DB."""
    with app_ctx:
        scan = Scan.query.get(scan_id)
        if not scan:
            return
        scan.status = 'running'
        db.session.commit()

        opts   = json.loads(scan.options or '{}')
        target = scan.target
        output_lines = []

        try:
            if scan.tool == 'nmap':
                from modules.nmap_scan import run_nmap
                results, raw = run_nmap(target, opts, scan_id, _scan_buffers, _scan_lock)
            elif scan.tool == 'subfinder':
                from modules.subfinder_scan import run_subfinder
                results, raw = run_subfinder(target, opts, scan_id, _scan_buffers, _scan_lock)
            elif scan.tool == 'amass':
                from modules.amass_scan import run_amass
                results, raw = run_amass(target, opts, scan_id, _scan_buffers, _scan_lock)
            elif scan.tool == 'whois':
                from modules.whois_lookup import run_whois
                results, raw = run_whois(target, opts, scan_id, _scan_buffers, _scan_lock)
            elif scan.tool == 'nslookup':
                from modules.whois_lookup import run_nslookup
                results, raw = run_nslookup(target, opts, scan_id, _scan_buffers, _scan_lock)
            elif scan.tool == 'dig':
                from modules.whois_lookup import run_dig
                results, raw = run_dig(target, opts, scan_id, _scan_buffers, _scan_lock)
            elif scan.tool == 'ffuf':
                from modules.ffuf_scan import run_ffuf
                results, raw = run_ffuf(target, opts, scan_id, _scan_buffers, _scan_lock)
            elif scan.tool == 'whatweb':
                from modules.whatweb_scan import run_whatweb
                results, raw = run_whatweb(target, opts, scan_id, _scan_buffers, _scan_lock)
            else:
                raise ValueError(f'Unknown tool: {scan.tool}')

            # AI analysis
            from modules.ai_analyzer import analyze_results
            for r in results:
                r['ai_analysis'], r['risk_level'] = analyze_results(r)
                sr = ScanResult(
                    scan_id     = scan_id,
                    result_type = r.get('type', 'unknown'),
                    data        = json.dumps(r),
                    risk_level  = r.get('risk_level', 'informational'),
                    ai_analysis = r.get('ai_analysis', ''),
                )
                db.session.add(sr)

            scan.raw_output   = raw[:50000]   # Limit storage
            scan.status       = 'completed'
            scan.completed_at = datetime.utcnow()
        except Exception as e:
            scan.status     = 'failed'
            scan.raw_output = str(e)
            scan.completed_at = datetime.utcnow()
        finally:
            db.session.commit()
            with _scan_lock:
                _scan_buffers.pop(scan_id, None)


# Tools registry: (tool_id, display_name, fa_icon, short_desc)
_TOOLS = [
    ('nmap',      'Nmap',        'fa-network-wired',  'Port scanner & service detection'),
    ('subfinder', 'Subfinder',   'fa-sitemap',        'Subdomain enumeration'),
    ('amass',     'Amass',       'fa-diagram-project','In-depth subdomain mapping'),
    ('whois',     'Whois',       'fa-id-card',        'Domain registration info'),
    ('nslookup',  'Nslookup',    'fa-server',         'DNS resolution lookup'),
    ('dig',       'Dig',         'fa-magnifying-glass','Advanced DNS queries'),
    ('ffuf',      'FFUF',        'fa-folder-tree',    'Directory & file fuzzing'),
    ('whatweb',   'WhatWeb',     'fa-globe',          'Web technology fingerprinting'),
]


@app.route('/recon')
@login_required
def recon():
    targets     = Target.query.filter_by(user_id=current_user.id).all()
    recent_scans = Scan.query.filter_by(user_id=current_user.id).order_by(
        Scan.started_at.desc()
    ).limit(8).all()
    tool_status = {t[0]: check_tool(t[0]) for t in _TOOLS}
    # whois/nslookup/dig are Python-based (always available)
    for t in ('whois', 'nslookup', 'dig'):
        tool_status[t] = True
    return render_template('recon.html',
        targets      = targets,
        tools        = _TOOLS,
        tool_status  = tool_status,
        recent_scans = recent_scans,
    )


@app.route('/recon/start', methods=['POST'])
@login_required
def start_scan():
    data      = request.get_json() or request.form
    target_id = int(data.get('target_id', 0))
    tool      = data.get('tool', '').strip().lower()
    options   = data.get('options', {})
    if isinstance(options, str):
        try:
            options = json.loads(options)
        except Exception:
            options = {}

    target = Target.query.filter_by(id=target_id, user_id=current_user.id).first_or_404()
    allowed = {'nmap','subfinder','amass','whois','nslookup','dig','ffuf','whatweb'}
    if tool not in allowed:
        return jsonify({'error': 'Invalid tool'}), 400

    scan = Scan(target_id=target_id, user_id=current_user.id,
                tool=tool, options=json.dumps(options), status='pending')
    db.session.add(scan)
    db.session.commit()

    with _scan_lock:
        _scan_buffers[scan.id] = []

    ctx = app.app_context()
    t   = threading.Thread(target=_run_scan_thread, args=(scan.id, ctx), daemon=True)
    t.start()

    log_activity('RUN_SCAN', f'Tool={tool} Target={target.name}')
    return jsonify({'scan_id': scan.id, 'status': 'started',
                    'success': True, 'target': target.name})


@app.route('/recon/status/<int:scan_id>')
@login_required
def recon_status(scan_id):
    scan = Scan.query.filter_by(id=scan_id, user_id=current_user.id).first_or_404()
    with _scan_lock:
        # Pop-and-clear: drain new lines to avoid duplicating on next poll
        new_output = list(_scan_buffers.get(scan_id, []))
        if scan_id in _scan_buffers:
            _scan_buffers[scan_id] = []
    return jsonify({
        'status':       scan.status,
        'scan_id':      scan_id,
        'new_output':   new_output,
        'progress':     100 if scan.status == 'completed' else (50 if scan.status == 'running' else 0),
        'completed_at': scan.completed_at.isoformat() if scan.completed_at else None,
    })


@app.route('/recon/output/<int:scan_id>')
@login_required
def recon_output(scan_id):
    scan = Scan.query.filter_by(id=scan_id, user_id=current_user.id).first_or_404()
    results = ScanResult.query.filter_by(scan_id=scan_id).all()
    results_data = []
    for r in results:
        try:
            d = json.loads(r.data)
        except Exception:
            d = {}
        d['ai_analysis'] = r.ai_analysis
        d['risk_level']  = r.risk_level
        results_data.append(d)
    return jsonify({
        'scan':    {'tool': scan.tool, 'status': scan.status, 'raw_output': scan.raw_output},
        'results': results_data,
    })


@app.route('/recon/results/<int:scan_id>')
@login_required
def recon_results(scan_id):
    scan = Scan.query.filter_by(id=scan_id, user_id=current_user.id).first_or_404()
    raw_results = ScanResult.query.filter_by(scan_id=scan_id).all()
    results = []
    for r in raw_results:
        try:
            d = json.loads(r.data)
        except Exception:
            d = {}
        d['id']          = r.id
        d['result_type'] = r.result_type
        d['risk_level']  = r.risk_level
        d['ai_analysis'] = r.ai_analysis
        d['created_at']  = r.created_at
        results.append(d)
    return render_template('results.html', scan=scan, results=results,
                           targets=[], sel_tool=scan.tool, sel_risk='', sel_target='')


# ─── Results ───────────────────────────────────────────────────────────────────
@app.route('/results')
@login_required
def results():
    tool       = request.args.get('tool', '')
    risk       = request.args.get('risk', '')
    target_id  = request.args.get('target_id', '')
    q          = request.args.get('q', '')

    query = ScanResult.query.join(Scan).filter(Scan.user_id == current_user.id)
    if tool:
        query = query.filter(Scan.tool == tool)
    if risk:
        query = query.filter(ScanResult.risk_level == risk)
    if target_id:
        query = query.filter(Scan.target_id == int(target_id))

    all_results = query.order_by(ScanResult.created_at.desc()).all()
    enriched = []
    for r in all_results:
        try:
            d = json.loads(r.data)
        except Exception:
            d = {}
        d['id']          = r.id
        d['risk_level']  = r.risk_level
        d['ai_analysis'] = r.ai_analysis
        d['result_type'] = r.result_type
        d['scan']        = r.scan
        d['created_at']  = r.created_at
        enriched.append(d)

    targets = Target.query.filter_by(user_id=current_user.id).all()
    return render_template('results.html', results=enriched, targets=targets,
                           sel_tool=tool, sel_risk=risk, sel_target=target_id)


# ─── Notes ─────────────────────────────────────────────────────────────────────
@app.route('/notes')
@login_required
def notes():
    tag    = request.args.get('tag', '')
    target = request.args.get('target_id', '')
    q_arg  = request.args.get('q', '')
    query  = Note.query.filter_by(user_id=current_user.id)
    if target:
        query = query.filter_by(target_id=int(target))
    if q_arg:
        query = query.filter(
            db.or_(Note.title.ilike(f'%{q_arg}%'), Note.content.ilike(f'%{q_arg}%'))
        )
    all_notes = query.order_by(Note.updated_at.desc()).all()
    targets   = Target.query.filter_by(user_id=current_user.id).all()
    return render_template('notes.html', notes=all_notes, targets=targets)


@app.route('/notes/add', methods=['GET', 'POST'])
@login_required
def add_note():
    if request.method == 'GET':
        targets = Target.query.filter_by(user_id=current_user.id).all()
        prefill_target = request.args.get('target_id', '')
        return render_template('add_note.html', targets=targets, prefill_target=prefill_target)
    data = request.get_json() or request.form
    note = Note(
        user_id   = current_user.id,
        target_id = int(data.get('target_id')) if data.get('target_id') else None,
        title     = data.get('title', 'Untitled').strip(),
        content   = data.get('content', '').strip(),
        tags      = data.get('tags', '').strip(),
        priority  = data.get('priority', 'medium'),
        note_type = data.get('note_type', 'general'),
    )
    db.session.add(note)
    db.session.commit()
    log_activity('ADD_NOTE', f'Note: {note.title}')
    if request.is_json:
        return jsonify({'id': note.id, 'status': 'ok'})
    flash('Note saved.', 'success')
    return redirect(url_for('notes'))


@app.route('/notes/<int:note_id>')
@login_required
def note_detail(note_id):
    n       = Note.query.filter_by(id=note_id, user_id=current_user.id).first_or_404()
    targets = Target.query.filter_by(user_id=current_user.id).all()
    return render_template('note_detail.html', note=n, targets=targets)


@app.route('/notes/<int:note_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_note(note_id):
    n    = Note.query.filter_by(id=note_id, user_id=current_user.id).first_or_404()
    if request.method == 'GET':
        targets = Target.query.filter_by(user_id=current_user.id).all()
        return render_template('add_note.html', note=n, targets=targets)
    data = request.get_json() or request.form
    n.title    = data.get('title', n.title).strip()
    n.content  = data.get('content', n.content).strip()
    n.tags     = data.get('tags', n.tags).strip()
    n.priority = data.get('priority', n.priority)
    n.note_type = data.get('note_type', n.note_type)
    n.updated_at = datetime.utcnow()
    db.session.commit()
    log_activity('EDIT_NOTE', f'Note ID {note_id}')
    if request.is_json:
        return jsonify({'status': 'ok'})
    flash('Note updated.', 'success')
    return redirect(url_for('note_detail', note_id=note_id))


@app.route('/notes/<int:note_id>/delete', methods=['GET', 'POST'])
@login_required
def delete_note(note_id):
    n = Note.query.filter_by(id=note_id, user_id=current_user.id).first_or_404()
    db.session.delete(n)
    db.session.commit()
    log_activity('DELETE_NOTE', f'Note ID {note_id}')
    if request.is_json:
        return jsonify({'status': 'ok'})
    flash('Note deleted.', 'success')
    return redirect(request.referrer or url_for('notes'))


@app.route('/notes/<int:note_id>/get')
@login_required
def get_note(note_id):
    n = Note.query.filter_by(id=note_id, user_id=current_user.id).first_or_404()
    return jsonify({
        'id': n.id, 'title': n.title, 'content': n.content,
        'tags': n.tags, 'priority': n.priority,
        'target_id': n.target_id
    })


# ─── Reports ───────────────────────────────────────────────────────────────────
@app.route('/reports')
@login_required
def reports():
    all_reports = Report.query.filter_by(user_id=current_user.id).order_by(Report.created_at.desc()).all()
    targets     = Target.query.filter_by(user_id=current_user.id).all()
    return render_template('reports.html', reports=all_reports, targets=targets)


@app.route('/reports/generate', methods=['POST'])
@login_required
def generate_report():
    from modules.report_generator import generate_pdf_report
    data      = request.get_json() or request.form
    target_id = data.get('target_id')
    title     = data.get('title', 'Security Assessment Report').strip()

    target = Target.query.filter_by(
        id=int(target_id), user_id=current_user.id
    ).first_or_404() if target_id else None

    scans = Scan.query.filter_by(
        target_id=target_id, user_id=current_user.id
    ).filter(Scan.status == 'completed').all() if target_id else []

    filename = f"report_{current_user.id}_{int(datetime.utcnow().timestamp())}.pdf"
    filepath = os.path.join(app.config['REPORTS_DIR'], filename)

    generate_pdf_report(
        filepath   = filepath,
        title      = title,
        target     = target,
        scans      = scans,
        analyst    = current_user.username,
        generated  = datetime.utcnow(),
    )

    rpt = Report(user_id=current_user.id, target_id=target.id if target else None,
                 title=title, filename=filename, report_type='full')
    db.session.add(rpt)
    db.session.commit()
    log_activity('GENERATE_REPORT', f'Report: {title}')
    return jsonify({'filename': filename, 'status': 'ok'})


@app.route('/reports/download/<filename>')
@login_required
def download_report(filename):
    filename = secure_filename(filename)
    # Verify user owns this report
    rpt = Report.query.filter_by(filename=filename, user_id=current_user.id).first_or_404()
    filepath = os.path.join(app.config['REPORTS_DIR'], filename)
    if not os.path.exists(filepath):
        abort(404)
    return send_file(filepath, as_attachment=True, download_name=filename)


@app.route('/reports/<int:rid>/delete', methods=['POST'])
@login_required
def delete_report(rid):
    rpt = Report.query.filter_by(id=rid, user_id=current_user.id).first_or_404()
    try:
        os.remove(os.path.join(app.config['REPORTS_DIR'], rpt.filename))
    except FileNotFoundError:
        pass
    db.session.delete(rpt)
    db.session.commit()
    flash('Report deleted.', 'success')
    return redirect(url_for('reports'))


# ─── History ───────────────────────────────────────────────────────────────────
@app.route('/history')
@login_required
def history():
    tool      = request.args.get('tool', '')
    status    = request.args.get('status', '')
    target_id = request.args.get('target_id', '')

    query = Scan.query.filter_by(user_id=current_user.id)
    if tool:
        query = query.filter_by(tool=tool)
    if status:
        query = query.filter_by(status=status)
    if target_id:
        query = query.filter_by(target_id=int(target_id))

    all_scans = query.order_by(Scan.started_at.desc()).all()
    targets   = Target.query.filter_by(user_id=current_user.id).all()
    return render_template('history.html', scans=all_scans, targets=targets,
                           sel_tool=tool, sel_status=status, sel_target=target_id)


@app.route('/history/<int:scan_id>/delete', methods=['POST'])
@login_required
def delete_scan(scan_id):
    scan = Scan.query.filter_by(id=scan_id, user_id=current_user.id).first_or_404()
    db.session.delete(scan)
    db.session.commit()
    flash('Scan deleted.', 'success')
    return redirect(url_for('history'))


@app.route('/history/export')
@login_required
def export_history():
    import csv, io
    scans = Scan.query.filter_by(user_id=current_user.id).order_by(Scan.started_at.desc()).all()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['ID', 'Target', 'Tool', 'Status', 'Started', 'Completed'])
    for s in scans:
        writer.writerow([
            s.id, s.target.name, s.tool, s.status,
            s.started_at, s.completed_at
        ])
    output.seek(0)
    return Response(
        output.getvalue(),
        mimetype='text/csv',
        headers={'Content-Disposition': 'attachment; filename=scan_history.csv'}
    )


# ─── Screenshots ───────────────────────────────────────────────────────────────
@app.route('/screenshots')
@login_required
def screenshots():
    img_dir   = app.config['SCREENSHOTS_DIR']
    files     = sorted(os.listdir(img_dir), reverse=True) if os.path.isdir(img_dir) else []
    images    = [f for f in files if f.lower().endswith(('.png', '.jpg', '.jpeg'))]
    targets   = Target.query.filter_by(user_id=current_user.id).all()
    return render_template('screenshots.html', images=images, targets=targets)


@app.route('/screenshots/capture', methods=['POST'])
@login_required
def capture_screenshot():
    from modules.screenshot import take_screenshot
    data = request.get_json() or request.form
    url  = data.get('url', '').strip()
    if not url:
        return jsonify({'error': 'URL is required'}), 400
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url

    filename = f"screenshot_{current_user.id}_{int(datetime.utcnow().timestamp())}.png"
    filepath = os.path.join(app.config['SCREENSHOTS_DIR'], filename)

    success, message = take_screenshot(url, filepath)
    log_activity('SCREENSHOT', f'URL: {url}')
    if success:
        return jsonify({'filename': filename, 'status': 'ok'})
    return jsonify({'error': message}), 500


@app.route('/screenshots/view/<filename>')
@login_required
def view_screenshot(filename):
    filename = secure_filename(filename)
    filepath = os.path.join(app.config['SCREENSHOTS_DIR'], filename)
    if not os.path.exists(filepath):
        abort(404)
    return send_file(filepath, mimetype='image/png')


@app.route('/screenshots/<filename>/delete', methods=['POST'])
@login_required
def delete_screenshot(filename):
    filename = secure_filename(filename)
    filepath = os.path.join(app.config['SCREENSHOTS_DIR'], filename)
    try:
        os.remove(filepath)
        flash('Screenshot deleted.', 'success')
    except FileNotFoundError:
        flash('Screenshot not found.', 'warning')
    return redirect(url_for('screenshots'))


# ─── Vulnerability Knowledge Base ──────────────────────────────────────────────
VULN_KB = [
    {
        'id': 'xss', 'name': 'Cross-Site Scripting (XSS)',
        'category': 'Injection', 'risk': 'High',
        'description': 'XSS allows attackers to inject malicious scripts into web pages viewed by other users, potentially stealing session cookies, credentials, or performing actions on behalf of victims.',
        'impact': 'Session hijacking, credential theft, defacement, phishing, malware distribution.',
        'testing': [
            'Identify all user-controlled inputs (forms, URL params, headers)',
            'Test with payloads: <script>alert(1)</script>',
            'Try event handlers: "><img src=x onerror=alert(1)>',
            'Test in all contexts: HTML, JS, CSS, attribute values',
            'Check for DOM-based XSS in client-side JS',
            'Use Burp Suite scanner or OWASP ZAP',
        ],
        'detection': ['Reflected input in response without encoding', 'Missing Content-Security-Policy header', 'Missing X-XSS-Protection header'],
        'mitigation': ['Output encode all user input', 'Implement strict Content Security Policy', 'Use HttpOnly and Secure cookie flags', 'Validate input server-side'],
        'cve_examples': ['CVE-2021-40444', 'CVE-2020-11022'],
        'tools': ['Burp Suite', 'XSStrike', 'OWASP ZAP', 'Dalfox'],
    },
    {
        'id': 'sqli', 'name': 'SQL Injection',
        'category': 'Injection', 'risk': 'Critical',
        'description': 'SQL Injection allows attackers to manipulate database queries by inserting malicious SQL code, potentially leading to unauthorized data access, data modification, or complete database compromise.',
        'impact': 'Data exfiltration, authentication bypass, data modification, remote code execution.',
        'testing': [
            "Test with single quote: '",
            'Boolean-based: AND 1=1 vs AND 1=2',
            'Time-based: AND SLEEP(5)',
            'Use sqlmap: sqlmap -u "URL" --dbs',
            'Test all input parameters including cookies and headers',
            'Check for Out-of-Band SQLi via DNS lookups',
        ],
        'detection': ['Database error messages in response', 'Inconsistent responses with boolean payloads', 'Time delays with SLEEP/WAITFOR'],
        'mitigation': ['Use parameterized queries / prepared statements', 'Implement stored procedures', 'Apply principle of least privilege to DB user', 'Use WAF rules'],
        'cve_examples': ['CVE-2021-27928', 'CVE-2023-23752'],
        'tools': ['SQLMap', 'Burp Suite', 'OWASP ZAP', 'Havij'],
    },
    {
        'id': 'ssrf', 'name': 'Server-Side Request Forgery (SSRF)',
        'category': 'Access Control', 'risk': 'Critical',
        'description': 'SSRF forces the server to make HTTP requests to arbitrary destinations, allowing attackers to access internal services, cloud metadata endpoints, and bypass firewalls.',
        'impact': 'Internal network enumeration, cloud metadata theft (AWS keys), RCE via internal services.',
        'testing': [
            'Identify URL parameters (url=, path=, redirect=)',
            'Test with Burp Collaborator or interactsh',
            'Try: http://169.254.169.254/latest/meta-data/',
            'Test for blind SSRF via DNS lookup',
            'Try protocol wrappers: file://, gopher://, dict://',
        ],
        'detection': ['Server making outbound requests', 'Access to internal IP ranges', 'Cloud metadata endpoint access'],
        'mitigation': ['Implement allowlist for outbound requests', 'Disable unnecessary URL schemes', 'Implement network-level controls', 'Use SSRF-safe HTTP libraries'],
        'cve_examples': ['CVE-2021-21985', 'CVE-2023-44487'],
        'tools': ['Burp Suite', 'SSRFmap', 'Interactsh', 'FFUF'],
    },
    {
        'id': 'lfi', 'name': 'Local File Inclusion (LFI)',
        'category': 'Injection', 'risk': 'High',
        'description': 'LFI allows attackers to include files from the server\'s filesystem, potentially exposing sensitive configuration files, credentials, or enabling code execution via log poisoning.',
        'impact': 'Sensitive file disclosure, credential theft, RCE via log poisoning.',
        'testing': [
            'Identify file inclusion parameters (file=, page=, include=)',
            'Test: ../../../../etc/passwd',
            'Test null byte: ../../../../etc/passwd%00',
            'Try PHP wrappers: php://filter/convert.base64-encode/resource=index.php',
            'Attempt log poisoning via User-Agent injection',
        ],
        'detection': ['File path traversal sequences accepted', 'System file contents in response', 'Error messages revealing file paths'],
        'mitigation': ['Validate and sanitize file paths', 'Use allowlists for includeable files', 'Disable dangerous PHP functions', 'Implement proper file permissions'],
        'cve_examples': ['CVE-2021-41773', 'CVE-2022-22947'],
        'tools': ['Burp Suite', 'LFISuite', 'FFUF', 'Wfuzz'],
    },
    {
        'id': 'rfi', 'name': 'Remote File Inclusion (RFI)',
        'category': 'Injection', 'risk': 'Critical',
        'description': 'RFI allows attackers to include and execute remote files hosted on external servers, typically leading to remote code execution and full system compromise.',
        'impact': 'Remote Code Execution, full server compromise, webshell installation.',
        'testing': [
            'Test with external URL in file parameter',
            'http://attacker.com/shell.php',
            'Test with PHP wrappers and data:// streams',
            'Check php.ini for allow_url_include=On',
        ],
        'detection': ['Application fetching external URLs', 'PHP allow_url_include enabled', 'Outbound HTTP requests to attacker-controlled servers'],
        'mitigation': ['Disable allow_url_include in PHP', 'Never pass user input directly to include()', 'Implement allowlist validation'],
        'cve_examples': ['CVE-2021-25294'],
        'tools': ['Burp Suite', 'FFUF', 'Wfuzz'],
    },
    {
        'id': 'xxe', 'name': 'XML External Entity (XXE)',
        'category': 'Injection', 'risk': 'High',
        'description': 'XXE exploits XML parsers that process external entity references, allowing attackers to read local files, perform SSRF, or cause denial of service.',
        'impact': 'File disclosure, SSRF, DoS via Billion Laughs attack.',
        'testing': [
            'Identify XML input (SOAP, REST with XML, file uploads)',
            'Inject DOCTYPE with external entity',
            '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>',
            'Test for blind XXE via out-of-band (Burp Collaborator)',
            'Try SVG, DOCX, XLSX file uploads',
        ],
        'detection': ['XML parser error messages', 'Application accepting XML input', 'SYSTEM entity keywords in XML'],
        'mitigation': ['Disable XML external entity processing', 'Use safe XML parsers', 'Validate and sanitize XML input', 'Implement allowlists for XML processing'],
        'cve_examples': ['CVE-2021-23906', 'CVE-2022-22965'],
        'tools': ['Burp Suite', 'XXEinjector', 'OWASP ZAP'],
    },
    {
        'id': 'ssti', 'name': 'Server-Side Template Injection (SSTI)',
        'category': 'Injection', 'risk': 'Critical',
        'description': 'SSTI allows attackers to inject template directives into user input that is rendered by a template engine, potentially leading to full remote code execution.',
        'impact': 'Remote Code Execution, data exfiltration, server takeover.',
        'testing': [
            'Identify template engine in use (Jinja2, Twig, Freemarker)',
            'Test: {{7*7}}, ${7*7}, #{7*7}',
            'For Jinja2: {{config.__class__.__init__.__globals__}}',
            'Use tplmap for automated detection',
            'Test in all user-controlled input fields',
        ],
        'detection': ['Mathematical expressions evaluated in response', '{{7*7}} returns 49', 'Template error messages in response'],
        'mitigation': ['Never render user input directly in templates', 'Use sandboxed template environments', 'Implement strict input validation', 'Upgrade template engines to latest versions'],
        'cve_examples': ['CVE-2019-11043', 'CVE-2022-22963'],
        'tools': ['Tplmap', 'Burp Suite', 'OWASP ZAP'],
    },
    {
        'id': 'csrf', 'name': 'Cross-Site Request Forgery (CSRF)',
        'category': 'Access Control', 'risk': 'Medium',
        'description': 'CSRF tricks authenticated users into unknowingly submitting malicious requests, allowing attackers to perform actions on behalf of the victim.',
        'impact': 'Unauthorized actions (password change, fund transfer, account modification).',
        'testing': [
            'Identify state-changing requests (POST, PUT, DELETE)',
            'Check for CSRF token in request',
            'Test if CSRF token is validated server-side',
            'Try removing token or using invalid token',
            'Check SameSite cookie attribute',
        ],
        'detection': ['Missing CSRF token in forms', 'CSRF token not validated', 'Missing SameSite cookie attribute'],
        'mitigation': ['Implement CSRF tokens on all state-changing operations', 'Use SameSite=Strict or SameSite=Lax cookies', 'Verify Origin/Referer headers', 'Use double-submit cookie pattern'],
        'cve_examples': ['CVE-2021-23226'],
        'tools': ['Burp Suite', 'OWASP ZAP', 'CSRFTester'],
    },
    {
        'id': 'idor', 'name': 'Insecure Direct Object Reference (IDOR)',
        'category': 'Access Control', 'risk': 'High',
        'description': 'IDOR occurs when an application uses user-controllable input to access objects without proper authorization checks, allowing attackers to access other users\' data.',
        'impact': 'Unauthorized data access, PII exposure, privilege escalation, data manipulation.',
        'testing': [
            'Identify object references in URLs, body, headers',
            'Test by substituting IDs (1 → 2, 100 → 101)',
            'Try accessing other users\' resources',
            'Test with unpredictable IDs (UUIDs)',
            'Check horizontal and vertical privilege escalation',
        ],
        'detection': ['Numeric or guessable object identifiers', 'No authorization checks server-side', 'Access to other users\' resources'],
        'mitigation': ['Implement server-side authorization checks', 'Use indirect references (GUIDs)', 'Validate user owns the requested object', 'Implement access control matrix'],
        'cve_examples': ['CVE-2021-41182'],
        'tools': ['Burp Suite', 'Autorize (Burp Plugin)', 'OWASP ZAP'],
    },
    {
        'id': 'open_redirect', 'name': 'Open Redirect',
        'category': 'Validation', 'risk': 'Medium',
        'description': 'Open redirects allow attackers to redirect users to arbitrary external URLs, enabling phishing attacks and bypassing security controls.',
        'impact': 'Phishing attacks, credential theft, OAuth token theft, bypassing referrer checks.',
        'testing': [
            'Find URL/redirect parameters (redirect=, next=, url=, return=)',
            'Test with external URL: ?redirect=https://evil.com',
            'Try URL encoding: ?redirect=%68%74%74%70%73%3A%2F%2Fevil.com',
            'Test // bypass: ?redirect=//evil.com',
            'Try @ bypass: ?redirect=https://target.com@evil.com',
        ],
        'detection': ['Unvalidated redirect URL parameter', 'HTTP 301/302 redirecting to external domain', 'Missing URL allowlist validation'],
        'mitigation': ['Implement URL allowlist validation', 'Use relative redirects only', 'Require user confirmation for external redirects', 'Reject redirects to external domains'],
        'cve_examples': ['CVE-2021-23157'],
        'tools': ['Burp Suite', 'OWASP ZAP', 'FFUF'],
    },
]


@app.route('/vulnkb')
@login_required
def vuln_kb():
    category = request.args.get('category', '')
    risk     = request.args.get('risk', '')
    filtered = VULN_KB
    if category:
        filtered = [v for v in filtered if v['category'] == category]
    if risk:
        filtered = [v for v in filtered if v['risk'] == risk]
    return render_template('vulnkb.html', vulns=filtered, sel_cat=category, sel_risk=risk)


# ─── Admin Panel ───────────────────────────────────────────────────────────────
@app.route('/admin')
@login_required
@admin_required
def admin_panel():
    users   = User.query.order_by(User.created_at.desc()).all()
    scans   = Scan.query.order_by(Scan.started_at.desc()).limit(50).all()
    targets = Target.query.order_by(Target.created_at.desc()).all()
    logs    = ActivityLog.query.order_by(ActivityLog.created_at.desc()).limit(50).all()
    stats   = {
        'total_users':   User.query.count(),
        'total_targets': Target.query.count(),
        'total_scans':   Scan.query.count(),
        'total_notes':   Note.query.count(),
        'total_reports': Report.query.count(),
    }
    return render_template('admin.html', users=users, scans=scans,
                           targets=targets, logs=logs, stats=stats)


@app.route('/admin/users/<int:uid>/toggle', methods=['POST'])
@login_required
@admin_required
def admin_toggle_user(uid):
    u = User.query.get_or_404(uid)
    if u.id == current_user.id:
        flash('Cannot deactivate your own account.', 'warning')
    else:
        u.is_active = not u.is_active
        db.session.commit()
        state = 'activated' if u.is_active else 'deactivated'
        flash(f'User {u.username} {state}.', 'success')
    return redirect(url_for('admin_panel'))


@app.route('/admin/users/<int:uid>/make-admin', methods=['POST'])
@login_required
@admin_required
def admin_make_admin(uid):
    u = User.query.get_or_404(uid)
    u.role = 'admin' if u.role != 'admin' else 'analyst'
    db.session.commit()
    flash(f'User {u.username} role updated to {u.role}.', 'success')
    return redirect(url_for('admin_panel'))


@app.route('/admin/scans/<int:sid>/delete', methods=['POST'])
@login_required
@admin_required
def admin_delete_scan(sid):
    s = Scan.query.get_or_404(sid)
    db.session.delete(s)
    db.session.commit()
    flash('Scan deleted.', 'success')
    return redirect(url_for('admin_panel'))


@app.route('/admin/users/<int:user_id>/delete', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_delete_user(user_id):
    u = User.query.get_or_404(user_id)
    if u.id == current_user.id:
        flash('Cannot delete your own account.', 'danger')
        return redirect(url_for('admin_panel'))
    db.session.delete(u)
    db.session.commit()
    flash('User deleted.', 'success')
    return redirect(url_for('admin_panel'))


@app.route('/admin/scans/clear', methods=['POST'])
@login_required
@admin_required
def admin_clear_scans():
    db.session.query(ScanResult).delete()
    db.session.query(Scan).delete()
    db.session.commit()
    flash('All scan data cleared.', 'success')
    return redirect(url_for('admin_panel'))


@app.route('/admin/reports/clear', methods=['POST'])
@login_required
@admin_required
def admin_clear_reports():
    reports = Report.query.all()
    for r in reports:
        try:
            os.remove(os.path.join(app.config['REPORTS_DIR'], r.filename))
        except FileNotFoundError:
            pass
    db.session.query(Report).delete()
    db.session.commit()
    flash('All reports cleared.', 'success')
    return redirect(url_for('admin_panel'))


# ─── Disclaimer ────────────────────────────────────────────────────────────────
@app.route('/disclaimer')
def disclaimer():
    return render_template('disclaimer.html')


# ─── Error Handlers ────────────────────────────────────────────────────────────
@app.errorhandler(403)
def forbidden(e):
    return render_template('login.html', error='Access denied.'), 403


@app.errorhandler(404)
def not_found(e):
    return render_template('login.html', error='Page not found.'), 404


# ─── CLI / Init ────────────────────────────────────────────────────────────────
def init_db():
    """Initialize the database and create tables."""
    with app.app_context():
        db.create_all()
        # Create default admin if no users exist
        if User.query.count() == 0:
            admin = User(username='admin', email='admin@cyberrecon.local', role='admin')
            admin.set_password('CyberRecon@2024!')
            db.session.add(admin)
            db.session.commit()
            print('[+] Default admin created: admin / CyberRecon@2024!')
        print('[+] Database initialized.')


if __name__ == '__main__':
    init_db()
    app.run(debug=True, host='0.0.0.0', port=5000, threaded=True)
