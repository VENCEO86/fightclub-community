FROM node:18-alpine

# 작업 디렉토리 설정
WORKDIR /app

# 보안 및 최적화를 위한 사용자 생성
RUN addgroup -g 1001 -S nodejs
RUN adduser -S nextjs -u 1001

# 시스템 패키지 업데이트 및 필수 도구 설치
RUN apk add --no-cache \
    libc6-compat \
    python3 \
    make \
    g++ \
    cairo-dev \
    jpeg-dev \
    pango-dev \
    giflib-dev \
    pixman-dev

# 패키지 파일 복사
COPY package*.json ./

# 의존성 설치
RUN npm ci --only=production && npm cache clean --force

# 애플리케이션 코드 복사
COPY . .

# 업로드 디렉토리 생성
RUN mkdir -p uploads && chown -R nextjs:nodejs uploads

# 정적 파일 디렉토리 생성
RUN mkdir -p public && chown -R nextjs:nodejs public

# 포트 노출
EXPOSE 3000

# 사용자 변경
USER nextjs

# 헬스체크 추가
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://localhost:3000/api/health || exit 1

# 애플리케이션 시작
CMD ["npm", "start"]
