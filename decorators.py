from functools import wraps

from flask import flash, redirect, session, url_for


def login_required(view_func):
    @wraps(view_func)
    def wrapped_view(*args, **kwargs):
        if 'user_id' not in session:
            flash('로그인이 필요합니다.', 'danger')
            return redirect(url_for('login'))
        return view_func(*args, **kwargs)

    return wrapped_view


def admin_required(view_func):
    @wraps(view_func)
    def wrapped_view(*args, **kwargs):
        if 'user_id' not in session:
            flash('로그인이 필요합니다.', 'danger')
            return redirect(url_for('login'))
        if session.get('role') != 'admin':
            flash('관리자 권한이 필요합니다.', 'danger')
            return redirect(url_for('index'))
        return view_func(*args, **kwargs)

    return wrapped_view
