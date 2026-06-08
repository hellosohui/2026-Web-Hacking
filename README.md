# Meongstagram

Flask + SQLite 기반 웹 애플리케이션입니다. 회원가입 이메일 인증, 임시 비밀번호 발송, 로그인, 커뮤니티 기능을 유지하면서 HTTPS/보안 헤더/세션 쿠키/요청 제한을 추가했습니다.

## 개발환경 개요

- Web Application: Flask
- WAS:
  - 개발: Flask 내장 서버
  - Windows Server 권장: `waitress`
  - Linux 계열 선택: Gunicorn/uWSGI
- Database:
  - 현재 기본값: SQLite
  - 환경변수 `DATABASE_URL` 구조 준비
  - 현재 코드 빌드는 `sqlite:///...`를 즉시 사용
  - MySQL URL은 추후 전환용 구조만 준비되어 있으며, 현재는 SQLite로 fallback

## .env란 무엇인가

- `.env`는 서버 설정 파일입니다.
- 회원가입하는 사용자의 메일 비밀번호를 저장하는 파일이 아닙니다.
- 사용자는 자신의 이메일 주소만 입력합니다.
- 서버는 `.env`에 저장된 발신 전용 이메일 계정 1개로 인증 메일과 임시 비밀번호 메일을 보냅니다.
- Gmail SMTP는 일반 로그인 비밀번호 대신 앱 비밀번호 사용이 권장됩니다.

## .env 작성 예시

```env
APP_ENV=development
APP_HOST=127.0.0.1
APP_PORT=8000
SECRET_KEY=change-me

MAIL_SERVER=smtp.gmail.com
MAIL_PORT=587
MAIL_USERNAME=example@gmail.com
MAIL_PASSWORD=your-app-password
MAIL_DEFAULT_SENDER=example@gmail.com
MAIL_USE_TLS=true
MAIL_USE_SSL=false

DATABASE_URL=sqlite:///mungstagram.db

SSL_CERT_FILE=
SSL_KEY_FILE=
```

## 로컬 실행 방법

1. 가상환경 생성
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   ```
2. 패키지 설치
   ```bash
   pip install -r requirements.txt
   ```
3. `.env.example`을 복사해 `.env` 작성
   ```bash
   cp .env.example .env
   ```
4. 앱 실행
   ```bash
   python3 app.py
   ```
5. 개발 기본 주소
   - `http://127.0.0.1:8000`

## HTTPS / SSL 적용

### 로컬 개발

- 일반 개발:
  ```bash
  python3 app.py
  ```
- Flask self-signed 인증서 예시:
  ```bash
  flask run --cert=cert.pem --key=key.pem
  ```
- 앱 자체 SSL 실행 예시:
  `.env`에 아래를 채운 뒤
  ```env
  SSL_CERT_FILE=cert.pem
  SSL_KEY_FILE=key.pem
  ```
  실행:
  ```bash
  python3 app.py
  ```

### 운영 / 시연 환경

- `APP_ENV=production` 설정
- HTTPS 인증서 적용
- `SESSION_COOKIE_SECURE=True`, `Strict-Transport-Security` 자동 적용

### VMware Windows Server / IIS / Reverse Proxy 예시

- 방법 1: Flask/Waitress는 내부 8000 포트로 실행하고 IIS Reverse Proxy로 443 HTTPS 종단 처리
- 방법 2: 자체 `cert.pem`, `key.pem`로 HTTPS 직접 실행

인증서 사용 시 확인사항:
- `cert.pem`, `key.pem` 경로가 실제 존재해야 함
- Reverse Proxy 사용 시 `X-Forwarded-Proto`가 전달되어야 함
- 방화벽에서 443 또는 내부 8000 포트 허용 필요

## Windows Server / VMware 실행 방법

1. Windows Server에 Python 설치
2. 프로젝트 폴더 이동
3. 가상환경 생성
   ```powershell
   py -3 -m venv .venv
   .\.venv\Scripts\activate
   ```
4. 의존성 설치
   ```powershell
   pip install -r requirements.txt
   ```
5. `.env` 작성
6. 개발 서버 실행
   ```powershell
   py app.py
   ```
7. Windows 권장 WSGI 서버 실행
   ```powershell
   waitress-serve --host=0.0.0.0 --port=8000 app:app
   ```
8. 방화벽에서 `8000` 또는 `443` 포트 허용
9. HTTPS 필요 시:
   - `cert.pem`, `key.pem` 사용
   - 또는 IIS Reverse Proxy + HTTPS 인증서 적용

## 이메일 설정 방법

- `MAIL_USERNAME`, `MAIL_DEFAULT_SENDER`: 서버 발신 전용 Gmail 계정
- `MAIL_PASSWORD`: Gmail 앱 비밀번호
- 사용자는 자신의 Gmail 비밀번호를 입력하지 않습니다

## 회원가입 이메일 인증 흐름

1. 회원가입 화면에서 이름, 아이디, 이메일, 전화번호, 비밀번호를 입력
2. `인증번호 전송` 버튼으로 이메일 발송
3. 6자리 숫자 코드 검증
4. 인증 완료 이메일만 회원가입 가능

## 비밀번호 찾기 / 임시 비밀번호

1. 로그인 화면에서 ID 또는 이메일 입력
2. 가입된 계정이면 임시 비밀번호 메일 발송
3. 임시 비밀번호는 해시로 저장되고 `users.is_temp_password=1` 처리
4. 임시 비밀번호 로그인 시 비밀번호 변경 페이지로 강제 이동
5. 새 비밀번호 저장 시 `is_temp_password=0`으로 복구

## 기존 회원 삭제 방법

```bash
python3 reset_users.py
```

- 사용자, 관리자, 게시글, 댓글, 좋아요, 메시지, 알림, 반려견 데이터까지 함께 정리
- 앱 실행 때마다 자동 삭제되지는 않음

## 새 관리자 생성 방법

```bash
python3 create_admin.py
```

- 이름, 아이디(username), 이메일, 비밀번호 입력
- `role='admin'`, `email_verified=1` 상태로 생성

## 추가된 Network Security 포인트

- 운영환경에서 HTTPS 준비
- 보안 헤더 추가
  - `X-Content-Type-Options: nosniff`
  - `X-Frame-Options: DENY`
  - `Referrer-Policy: strict-origin-when-cross-origin`
  - `Permissions-Policy: geolocation=(), microphone=(), camera=()`
  - `Content-Security-Policy`
  - 운영환경 전용 `Strict-Transport-Security`
- 세션 쿠키 보안
  - `SESSION_COOKIE_HTTPONLY=True`
  - `SESSION_COOKIE_SAMESITE=Lax`
  - 운영환경 전용 `SESSION_COOKIE_SECURE=True`
- Rate Limit
  - 로그인: 1분 5회
  - 이메일 인증번호 전송: 1분 3회
  - 임시 비밀번호 발송: 1분 3회
- 민감정보 환경변수 분리
  - `SECRET_KEY`
  - `MAIL_PASSWORD`
  - `DATABASE_URL`

## 시연 발표에서 설명할 수 있는 포인트

1. 로그인/회원가입/비밀번호 찾기 구간은 개인정보와 인증정보가 오가므로 HTTPS 전제와 보안 쿠키를 적용했다.
2. 브라우저 보안 헤더로 클릭재킹, MIME sniffing, 과도한 브라우저 권한, 취약한 외부 리소스 로딩을 줄였다.
3. 로그인/인증 메일/임시 비밀번호 발송에 Rate Limit을 걸어 브루트포스와 자동화 요청을 완화했다.
4. 메일 계정 비밀번호와 시크릿키를 코드가 아니라 `.env`로 분리해 민감정보 노출을 줄였다.
5. `DATABASE_URL` 구조를 미리 잡아 SQLite에서 출발하되 추후 DB 전환 기반을 마련했다.
