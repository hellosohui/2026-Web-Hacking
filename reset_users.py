from app import get_db_connection, delete_user_account


def reset_all_users():
    conn = get_db_connection()
    try:
        users = conn.execute(
            'SELECT id, username, email, role FROM users ORDER BY id ASC'
        ).fetchall()

        if not users:
            print('삭제할 회원 데이터가 없습니다.')
            conn.execute('DELETE FROM email_verifications')
            conn.commit()
            return

        print('다음 회원 데이터가 삭제됩니다:')
        for user in users:
            print(f"- id={user['id']} username={user['username']} email={user['email']} role={user['role']}")

        confirmation = input("계속하려면 'RESET USERS'를 입력하세요: ").strip()
        if confirmation != 'RESET USERS':
            print('작업을 취소했습니다.')
            return

        for user in users:
            delete_user_account(conn, user['id'])

        conn.execute('DELETE FROM email_verifications')
        conn.commit()
        print(f'총 {len(users)}명의 회원 데이터를 삭제했습니다.')
    finally:
        conn.close()


if __name__ == '__main__':
    reset_all_users()
