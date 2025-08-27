# 🥊 파이트클럽 커뮤니티

현대적이고 완전한 기능을 갖춘 커뮤니티 플랫폼

[![Node.js](https://img.shields.io/badge/Node.js-18+-green.svg)](https://nodejs.org/)
[![MongoDB](https://img.shields.io/badge/MongoDB-7.0-green.svg)](https://www.mongodb.com/)
[![Docker](https://img.shields.io/badge/Docker-Ready-blue.svg)](https://www.docker.com/)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

## 🚀 빠른 시작

### 1. 저장소 복제
```bash
git clone https://github.com/your-username/fightclub-community.git
cd fightclub-community
```

### 2. 의존성 설치
```bash
npm install
```

### 3. 환경변수 설정
```bash
cp .env.example .env
# .env 파일을 편집하여 데이터베이스 설정 등을 수정하세요
```

### 4. 데이터베이스 설정
MongoDB와 Redis가 실행 중인지 확인하세요.

### 5. 개발 서버 시작
```bash
npm run dev
```

서버가 http://localhost:3000에서 시작됩니다.

## 🐳 Docker로 실행

```bash
# Docker Compose로 전체 스택 실행
docker-compose up -d

# 로그 확인
docker-compose logs -f
```

## 📋 주요 기능

- ✅ **사용자 인증**: JWT 기반 로그인/회원가입
- ✅ **다중 게시판**: 카테고리별 게시판 시스템
- ✅ **실시간 댓글**: 중첩 댓글 지원
- ✅ **파일 업로드**: 이미지/문서 업로드
- ✅ **관리자 패널**: 사용자/게시판 관리
- ✅ **반응형 디자인**: 모바일/태블릿/데스크톱 최적화
- ✅ **실시간 알림**: 댓글, 좋아요 알림
- ✅ **검색 기능**: 전문 검색 지원
- ✅ **보안 강화**: Rate Limiting, CSRF 보호
- ✅ **SEO 최적화**: 메타 태그, 사이트맵

## 🛠️ 기술 스택

### 백엔드
- **Node.js** - 서버 런타임
- **Express.js** - 웹 프레임워크
- **MongoDB** - 데이터베이스
- **Redis** - 캐싱 및 세션 저장
- **JWT** - 인증 시스템
- **Multer** - 파일 업로드
- **Socket.io** - 실시간 통신

### 프론트엔드
- **HTML5/CSS3** - 마크업/스타일링
- **JavaScript ES6+** - 클라이언트 로직
- **Font Awesome** - 아이콘
- **반응형 디자인** - 모바일 최적화

### 배포
- **Docker** - 컨테이너화
- **PM2** - 프로세스 관리
- **Nginx** - 리버스 프록시
- **Let's Encrypt** - SSL 인증서

## 📡 API 엔드포인트

### 인증
- `POST /api/auth/register` - 회원가입
- `POST /api/auth/login` - 로그인
- `POST /api/auth/logout` - 로그아웃

### 게시글
- `GET /api/posts` - 게시글 목록
- `GET /api/posts/:id` - 게시글 상세
- `POST /api/posts` - 게시글 작성
- `PUT /api/posts/:id` - 게시글 수정
- `DELETE /api/posts/:id` - 게시글 삭제

### 게시판
- `GET /api/boards` - 게시판 목록
- `POST /api/boards` - 게시판 생성 (관리자)
- `DELETE /api/boards/:id` - 게시판 삭제 (관리자)

### 사용자
- `GET /api/users/profile` - 프로필 조회
- `PUT /api/users/profile` - 프로필 수정

## 🔧 개발 명령어

```bash
npm run dev          # 개발 서버 시작
npm run build        # 프로덕션 빌드
npm run start        # 프로덕션 서버 시작
npm run test         # 테스트 실행
npm run lint         # 코드 린팅
npm run deploy       # PM2로 배포
```

## 🚀 배포 가이드

### 자동 배포 (권장)
```bash
# 자동 배포 스크립트 실행
chmod +x scripts/auto-deploy.sh
./scripts/auto-deploy.sh --domain your-domain.com --email your@email.com
```

### 수동 배포
```bash
# 1. 서버에서 프로젝트 복제
git clone https://github.com/your-username/fightclub-community.git
cd fightclub-community

# 2. 의존성 설치
npm install --production

# 3. 환경변수 설정
cp .env.example .env
# .env 파일 편집

# 4. PM2로 시작
npm run deploy
```

## 📊 관리자 기능

### 기본 관리자 계정
- **아이디**: admin
- **비밀번호**: admin123

### 관리 기능
- 사용자 관리 (활성화/비활성화)
- 게시판 생성/삭제
- 게시글 관리
- 시스템 설정
- 통계 대시보드

## 🔒 보안 기능

- **JWT 인증**: 안전한 토큰 기반 인증
- **Rate Limiting**: API 호출 제한
- **CSRF 보호**: Cross-Site Request Forgery 방지
- **XSS 보호**: Cross-Site Scripting 방지
- **SQL 인젝션 방지**: MongoDB ODM 사용
- **파일 업로드 검증**: 허용된 파일 형식만
- **HTTPS 강제**: SSL/TLS 암호화

## 🔧 설정

### 환경변수
주요 환경변수는 `.env` 파일에서 설정할 수 있습니다:

```env
NODE_ENV=production
PORT=3000
MONGODB_URI=mongodb://localhost:27017/fightclub_community
JWT_SECRET=your-secret-key
```

### 데이터베이스
MongoDB 인덱스는 자동으로 생성됩니다:
- 사용자: username, email (unique)
- 게시글: board, createdAt, 전문검색
- 댓글: post, createdAt

## 📈 모니터링

### PM2 모니터링
```bash
pm2 status           # 프로세스 상태
pm2 logs            # 로그 확인
pm2 monit           # 실시간 모니터링
pm2 restart all     # 프로세스 재시작
```

### 로그 관리
로그는 다음 위치에 저장됩니다:
- `logs/combined.log` - 종합 로그
- `logs/error.log` - 에러 로그
- `logs/out.log` - 출력 로그

## 🧪 테스트

```bash
npm test                # 전체 테스트 실행
npm run test:unit      # 단위 테스트
npm run test:integration # 통합 테스트
```

## 📝 라이센스

이 프로젝트는 MIT 라이센스 하에 배포됩니다. 자세한 내용은 [LICENSE](LICENSE) 파일을 참조하세요.

## 🤝 기여하기

1. 이 저장소를 포크하세요
2. 기능 브랜치를 생성하세요 (`git checkout -b feature/amazing-feature`)
3. 변경사항을 커밋하세요 (`git commit -m 'Add some amazing feature'`)
4. 브랜치에 푸시하세요 (`git push origin feature/amazing-feature`)
5. Pull Request를 열어주세요

## 📞 지원

- 📋 [Issues](https://github.com/your-username/fightclub-community/issues)
- 📧 Email: support@fightclub-community.com
- 💬 Discord: [커뮤니티 서버](https://discord.gg/fightclub)

## 🙏 감사의 말

이 프로젝트는 다음 오픈소스 프로젝트들의 도움을 받았습니다:
- Node.js
- Express.js
- MongoDB
- Redis
- Font Awesome

---

**🥊 파이트클럽 커뮤니티에 오신 것을 환영합니다!**