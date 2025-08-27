const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const compression = require('compression');
const morgan = require('morgan');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-here';
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/fightclub_community';

// Middleware
app.use(helmet());
app.use(compression());
app.use(morgan('combined'));
app.use(cors({
    origin: process.env.FRONTEND_URL || 'http://localhost:8080',
    credentials: true
}));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use('/uploads', express.static('uploads'));
app.use(express.static('public'));

// Rate Limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15분
    max: 100 // 최대 100 요청
});
app.use('/api/', limiter);

// MongoDB 연결
mongoose.connect(MONGODB_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
})
.then(() => console.log('✅ MongoDB 연결 성공'))
.catch(err => console.error('❌ MongoDB 연결 실패:', err));

// 스키마 정의
const UserSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    role: { type: String, enum: ['user', 'admin'], default: 'user' },
    avatar: { type: String, default: '' },
    joinDate: { type: Date, default: Date.now },
    lastActive: { type: Date, default: Date.now },
    isActive: { type: Boolean, default: true },
    stats: {
        posts: { type: Number, default: 0 },
        comments: { type: Number, default: 0 },
        likes: { type: Number, default: 0 }
    }
}, { timestamps: true });

const PostSchema = new mongoose.Schema({
    title: { type: String, required: true, maxlength: 200 },
    content: { type: String, required: true },
    author: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    board: { type: String, required: true },
    category: { type: String, default: 'general' },
    tags: [String],
    attachments: [{
        filename: String,
        originalName: String,
        mimeType: String,
        size: Number,
        url: String
    }],
    status: { type: String, enum: ['draft', 'published', 'hidden'], default: 'published' },
    isNotice: { type: Boolean, default: false },
    isPinned: { type: Boolean, default: false },
    stats: {
        views: { type: Number, default: 0 },
        likes: { type: Number, default: 0 },
        dislikes: { type: Number, default: 0 },
        comments: { type: Number, default: 0 }
    }
}, { timestamps: true });

const CommentSchema = new mongoose.Schema({
    content: { type: String, required: true },
    author: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    post: { type: mongoose.Schema.Types.ObjectId, ref: 'Post', required: true },
    parent: { type: mongoose.Schema.Types.ObjectId, ref: 'Comment' },
    isDeleted: { type: Boolean, default: false },
    stats: {
        likes: { type: Number, default: 0 },
        dislikes: { type: Number, default: 0 }
    }
}, { timestamps: true });

const BoardSchema = new mongoose.Schema({
    id: { type: String, required: true, unique: true },
    name: { type: String, required: true },
    description: { type: String, required: true },
    category: { type: String, default: 'general' },
    isActive: { type: Boolean, default: true },
    postCount: { type: Number, default: 0 }
}, { timestamps: true });

// 모델 생성
const User = mongoose.model('User', UserSchema);
const Post = mongoose.model('Post', PostSchema);
const Comment = mongoose.model('Comment', CommentSchema);
const Board = mongoose.model('Board', BoardSchema);

// JWT 인증 미들웨어
const authenticateToken = async (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ error: '인증 토큰이 필요합니다.' });
    }

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        const user = await User.findById(decoded.userId).select('-password');
        if (!user || !user.isActive) {
            return res.status(401).json({ error: '유효하지 않은 사용자입니다.' });
        }
        
        req.user = user;
        user.lastActive = new Date();
        await user.save();
        
        next();
    } catch (error) {
        return res.status(403).json({ error: '유효하지 않은 토큰입니다.' });
    }
};

// 관리자 권한 확인 미들웨어
const requireAdmin = (req, res, next) => {
    if (req.user.role !== 'admin') {
        return res.status(403).json({ error: '관리자 권한이 필요합니다.' });
    }
    next();
};

// 파일 업로드 설정
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        const uploadDir = 'uploads/';
        if (!fs.existsSync(uploadDir)) {
            fs.mkdirSync(uploadDir, { recursive: true });
        }
        cb(null, uploadDir);
    },
    filename: function (req, file, cb) {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, file.fieldname + '-' + uniqueSuffix + path.extname(file.originalname));
    }
});

const upload = multer({ 
    storage: storage,
    limits: { fileSize: 10 * 1024 * 1024 } // 10MB 제한
});

// API 라우트

// 1. 기본 라우트
app.get('/api/health', (req, res) => {
    res.json({
        status: 'OK',
        timestamp: new Date().toISOString(),
        uptime: process.uptime(),
        environment: process.env.NODE_ENV || 'development',
        version: '1.0.0'
    });
});

app.get('/api', (req, res) => {
    res.json({
        message: '🥊 파이트클럽 커뮤니티 API',
        version: '1.0.0',
        endpoints: {
            auth: {
                'POST /api/auth/register': '회원가입',
                'POST /api/auth/login': '로그인',
                'POST /api/auth/logout': '로그아웃'
            },
            posts: {
                'GET /api/posts': '게시글 목록',
                'GET /api/posts/:id': '게시글 상세',
                'POST /api/posts': '게시글 작성',
                'PUT /api/posts/:id': '게시글 수정',
                'DELETE /api/posts/:id': '게시글 삭제'
            },
            boards: {
                'GET /api/boards': '게시판 목록',
                'POST /api/boards': '게시판 생성 (관리자)',
                'DELETE /api/boards/:id': '게시판 삭제 (관리자)'
            }
        }
    });
});

// 2. 인증 관련 API
app.post('/api/auth/register', async (req, res) => {
    try {
        const { username, email, password, passwordConfirm } = req.body;

        if (!username || !email || !password) {
            return res.status(400).json({ error: '모든 필드를 입력해주세요.' });
        }

        if (password !== passwordConfirm) {
            return res.status(400).json({ error: '비밀번호가 일치하지 않습니다.' });
        }

        const existingUser = await User.findOne({
            $or: [{ username }, { email }]
        });

        if (existingUser) {
            return res.status(400).json({ 
                error: existingUser.username === username ? 
                    '이미 사용중인 아이디입니다.' : '이미 사용중인 이메일입니다.'
            });
        }

        const hashedPassword = await bcrypt.hash(password, 12);

        const user = new User({
            username,
            email,
            password: hashedPassword
        });

        await user.save();

        const token = jwt.sign(
            { userId: user._id, username: user.username },
            JWT_SECRET,
            { expiresIn: '7d' }
        );

        res.status(201).json({
            message: '회원가입이 완료되었습니다.',
            token,
            user: {
                id: user._id,
                username: user.username,
                email: user.email,
                role: user.role,
                joinDate: user.joinDate
            }
        });
    } catch (error) {
        console.error('회원가입 오류:', error);
        res.status(500).json({ error: '서버 오류가 발생했습니다.' });
    }
});

app.post('/api/auth/login', async (req, res) => {
    try {
        const { username, password, remember } = req.body;

        if (!username || !password) {
            return res.status(400).json({ error: '아이디와 비밀번호를 입력해주세요.' });
        }

        const user = await User.findOne({
            $or: [{ username }, { email: username }],
            isActive: true
        });

        if (!user) {
            return res.status(400).json({ error: '존재하지 않는 사용자입니다.' });
        }

        const isValidPassword = await bcrypt.compare(password, user.password);
        if (!isValidPassword) {
            return res.status(400).json({ error: '비밀번호가 올바르지 않습니다.' });
        }

        const expiresIn = remember ? '30d' : '7d';
        const token = jwt.sign(
            { userId: user._id, username: user.username },
            JWT_SECRET,
            { expiresIn }
        );

        user.lastActive = new Date();
        await user.save();

        res.json({
            message: '로그인되었습니다.',
            token,
            user: {
                id: user._id,
                username: user.username,
                email: user.email,
                role: user.role,
                stats: user.stats
            }
        });
    } catch (error) {
        console.error('로그인 오류:', error);
        res.status(500).json({ error: '서버 오류가 발생했습니다.' });
    }
});

// 3. 게시판 관련 API
app.get('/api/boards', async (req, res) => {
    try {
        const boards = await Board.find({ isActive: true }).sort({ name: 1 });
        res.json(boards);
    } catch (error) {
        console.error('게시판 조회 오류:', error);
        res.status(500).json({ error: '서버 오류가 발생했습니다.' });
    }
});

// 4. 게시글 관련 API
app.get('/api/posts', async (req, res) => {
    try {
        const { 
            board = 'best', 
            page = 1, 
            limit = 30, 
            sort = 'latest'
        } = req.query;

        const skip = (page - 1) * limit;
        let query = { status: 'published' };

        if (board !== 'best') {
            query.board = board;
        }

        let sortOption = {};
        switch (sort) {
            case 'popular':
                sortOption = { 'stats.likes': -1, createdAt: -1 };
                break;
            case 'views':
                sortOption = { 'stats.views': -1, createdAt: -1 };
                break;
            case 'comments':
                sortOption = { 'stats.comments': -1, createdAt: -1 };
                break;
            default:
                sortOption = { isPinned: -1, createdAt: -1 };
        }

        const posts = await Post.find(query)
            .populate('author', 'username avatar')
            .sort(sortOption)
            .skip(skip)
            .limit(parseInt(limit));

        const totalPosts = await Post.countDocuments(query);
        const totalPages = Math.ceil(totalPosts / limit);

        res.json({
            posts,
            pagination: {
                currentPage: parseInt(page),
                totalPages,
                totalPosts,
                hasNext: page < totalPages,
                hasPrev: page > 1
            }
        });
    } catch (error) {
        console.error('게시글 조회 오류:', error);
        res.status(500).json({ error: '서버 오류가 발생했습니다.' });
    }
});

app.post('/api/posts', authenticateToken, upload.array('files'), async (req, res) => {
    try {
        const { title, content, board, category, tags } = req.body;

        if (!title || !content || !board) {
            return res.status(400).json({ error: '제목, 내용, 게시판을 모두 입력해주세요.' });
        }

        const attachments = req.files ? req.files.map(file => ({
            filename: file.filename,
            originalName: file.originalname,
            mimeType: file.mimetype,
            size: file.size,
            url: `/uploads/${file.filename}`
        })) : [];

        const post = new Post({
            title,
            content,
            board,
            category: category || 'general',
            tags: tags ? tags.split(',').map(tag => tag.trim()) : [],
            author: req.user._id,
            attachments
        });

        await post.save();
        await post.populate('author', 'username avatar');

        res.status(201).json({
            message: '게시글이 작성되었습니다.',
            post
        });
    } catch (error) {
        console.error('게시글 작성 오류:', error);
        res.status(500).json({ error: '서버 오류가 발생했습니다.' });
    }
});

// 5. 통계 API
app.get('/api/stats/online', async (req, res) => {
    try {
        const onlineUsers = await User.countDocuments({
            lastActive: { $gte: new Date(Date.now() - 5 * 60 * 1000) }
        });

        const todayUsers = await User.countDocuments({
            createdAt: { $gte: new Date(new Date().setHours(0, 0, 0, 0)) }
        });

        const todayPosts = await Post.countDocuments({
            createdAt: { $gte: new Date(new Date().setHours(0, 0, 0, 0)) },
            status: 'published'
        });

        res.json({
            onlineUsers,
            todayUsers,
            todayPosts,
            timestamp: new Date()
        });
    } catch (error) {
        console.error('온라인 통계 조회 오류:', error);
        res.status(500).json({ error: '서버 오류가 발생했습니다.' });
    }
});

// 초기 데이터 설정
async function initializeData() {
    try {
        const defaultBoards = [
            { id: 'best', name: '일간-베스트', description: '가장 인기있는 게시글들' },
            { id: 'politics', name: '정치', description: '정치 이야기' },
            { id: 'issue', name: '이슈', description: '핫한 이슈들' },
            { id: 'society', name: '사회', description: '사회 문제 토론' },
            { id: 'celeb', name: '걸그룹/연예인', description: '연예계 소식' },
            { id: 'stock', name: '주식', description: '투자와 경제 정보' }
        ];

        for (const boardData of defaultBoards) {
            const existingBoard = await Board.findOne({ id: boardData.id });
            if (!existingBoard) {
                await new Board(boardData).save();
                console.log(`게시판 생성됨: ${boardData.name}`);
            }
        }

        const adminExists = await User.findOne({ username: 'admin' });
        if (!adminExists) {
            const adminUser = new User({
                username: 'admin',
                email: 'admin@fightclub.com',
                password: await bcrypt.hash('admin123', 12),
                role: 'admin'
            });
            await adminUser.save();
            console.log('기본 관리자 계정이 생성되었습니다. (username: admin, password: admin123)');
        }

        console.log('초기 데이터 설정이 완료되었습니다.');
    } catch (error) {
        console.error('초기 데이터 설정 오류:', error);
    }
}

// 에러 핸들링
app.use((error, req, res, next) => {
    console.error('서버 에러:', error);
    res.status(500).json({ error: '서버 내부 오류가 발생했습니다.' });
});

app.use((req, res) => {
    res.status(404).json({ error: 'API 엔드포인트를 찾을 수 없습니다.' });
});

// 서버 시작
async function startServer() {
    try {
        await initializeData();
        
        app.listen(PORT, () => {
            console.log(`
╔══════════════════════════════════════════╗
║        🥊 파이트클럽 커뮤니티 서버        ║
║                                          ║
║  서버 주소: http://localhost:${PORT}       ║
║  API 문서: http://localhost:${PORT}/api   ║
║  상태: 정상 구동 중                       ║
║                                          ║
║  관리자 계정:                             ║
║  - 아이디: admin                         ║
║  - 비밀번호: admin123                    ║
╚══════════════════════════════════════════╝
            `);
        });
    } catch (error) {
        console.error('서버 시작 오류:', error);
        process.exit(1);
    }
}

startServer();
