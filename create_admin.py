from getpass import getpass

from werkzeug.security import generate_password_hash

from app import get_db_connection, is_valid_email, is_valid_username, normalize_email, normalize_username_value


def prompt_non_empty(label):
    while True:
        value = input(label).strip()
        if value:
            return value
        print('값을 입력해 주세요.')


def create_admin():
    name = prompt_non_empty('이름: ')

    while True:
        username = normalize_username_value(input('아이디(username): '))
        if not is_valid_username(username):
            print('아이디는 영문 소문자, 숫자, 언더스코어만 사용해 4~20자로 입력해 주세요.')
            continue
        break

    while True:
        email = normalize_email(input('이메일: '))
        if not is_valid_email(email):
            print('올바른 이메일 주소를 입력해 주세요.')
            continue
        break

    while True:
        password = getpass('비밀번호: ')
        confirm_password = getpass('비밀번호 확인: ')
        if not password:
            print('비밀번호를 입력해 주세요.')
            continue
        if password != confirm_password:
            print('비밀번호가 일치하지 않습니다.')
            continue
        break

    conn = get_db_connection()
    try:
        existing_user = conn.execute(
            'SELECT id FROM users WHERE email = ? OR username = ?',
            (email, username)
        ).fetchone()
        if existing_user:
            print('이미 사용 중인 이메일 또는 아이디입니다.')
            return

        conn.execute(
            '''
            INSERT INTO users (name, username, email, password, role, email_verified)
            VALUES (?, ?, ?, ?, ?, ?)
            ''',
            (name, username, email, generate_password_hash(password), 'admin', 1)
        )
        conn.commit()
        print(f'관리자 계정이 생성되었습니다. username={username}')
    finally:
        conn.close()


if __name__ == '__main__':
    create_admin()
