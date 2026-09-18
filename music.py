import base64
import os
import time
import requests
from flask import (
    Flask,
    jsonify,
    redirect,
    render_template_string,
    request,
    url_for,
)
from flask_sqlalchemy import SQLAlchemy
from flask_socketio import SocketIO, emit
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

# محاولة تحميل متغيرات البيئة من ملف .env محلياً إن وُجد
try:
  from dotenv import load_dotenv

  load_dotenv()
except ImportError:
  pass

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'super_secret_key_musicy')
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')# قراءة الرابط من Render أو استخدام SQLite محلياً للتجربة
database_url = os.getenv("DATABASE_URL", "sqlite:///site.db")

if database_url.startswith("postgres://?"):
    database_url = database_url.replace("postgres://", "postgresql://", 1)

app.config["SQLALCHEMY_DATABASE_URI"] = database_url
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# حماية إضافية للتحكم بحجم الملفات المرفوعة (حد أقصى 2 ميجابايت لمنع هجمات DoS عبر الرفع)
app.config['MAX_CONTENT_LENGTH'] = 2 * 1024 * 1024

# إعداد مجلد حفظ الصور المرفوعة والامتدادات المسموح بها بدقة لمنع رفع ملفات خبيثة
UPLOAD_FOLDER = 'static/uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'webp'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# التأكد من وجود مجلد الرفع والصلاحيات
os.makedirs(UPLOAD_FOLDER, exist_ok=True)


def allowed_file(filename):
  return (
      '.' in filename
      and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS
  )


db = SQLAlchemy(app)

# بيانات توثيق Spotify الرسمية مسحوبة بأمان تام من متغيرات البيئة (Environment Variables)
SPOTIFY_CLIENT_ID = os.environ.get('SPOTIFY_CLIENT_ID')
SPOTIFY_CLIENT_SECRET = os.environ.get('SPOTIFY_CLIENT_SECRET')


class User(db.Model):
  id = db.Column(db.Integer, primary_key=True)
  username = db.Column(db.String(100), unique=True, nullable=False)
  email = db.Column(db.String(120), unique=True, nullable=False)
  password_hash = db.Column(db.String(200), nullable=False)
  avatar = db.Column(
      db.String(500),
      default=(
          'https://images.unsplash.com/photo-1534528741775-53994a69daeb?auto=format&fit=crop&q=80&w=200'
      ),
      nullable=True,
  )


class Song(db.Model):
  id = db.Column(db.Integer, primary_key=True)
  spotify_id = db.Column(db.String(100), unique=True, nullable=True)
  title = db.Column(db.String(200), nullable=False)
  artist = db.Column(db.String(200), nullable=False)
  img = db.Column(db.String(500), nullable=True)
  preview_url = db.Column(db.String(500), nullable=True)
  rating = db.Column(db.Float, default=0.0)
  votes = db.Column(db.Integer, default=0)
  release_year = db.Column(db.String(10), default='2020')
  genre = db.Column(db.String(50), default='Pop')


class Review(db.Model):
  id = db.Column(db.Integer, primary_key=True)
  song_id = db.Column(db.Integer, db.ForeignKey('song.id'), nullable=False)
  username = db.Column(db.String(100), nullable=False)
  rating = db.Column(db.Float, nullable=False)
  comment = db.Column(db.Text, nullable=True)
  likes = db.Column(db.Integer, default=0)
  timestamp = db.Column(db.Float, default=time.time)


class ReviewLike(db.Model):
  id = db.Column(db.Integer, primary_key=True)
  review_id = db.Column(db.Integer, db.ForeignKey('review.id'), nullable=False)
  username = db.Column(db.String(100), nullable=False)


with app.app_context():
  db.create_all()


def get_spotify_token():
  if not SPOTIFY_CLIENT_ID or not SPOTIFY_CLIENT_SECRET:
    return None
  auth_url = 'https://accounts.spotify.com/api/token'
  credentials = f'{SPOTIFY_CLIENT_ID}:{SPOTIFY_CLIENT_SECRET}'
  encoded_credentials = base64.b64encode(credentials.encode()).decode()
  headers = {
      'Authorization': f'Basic {encoded_credentials}',
      'Content-Type': 'application/x-www-form-urlencoded',
  }
  data = {'grant_type': 'client_credentials'}
  try:
    response = requests.post(
        auth_url, headers=headers, data=data, timeout=5
    )
    if response.status_code == 200:
      return response.json().get('access_token')
  except requests.exceptions.RequestException:
    pass
  return None


@app.route('/')
def home():
  songs = Song.query.order_by(db.func.random()).all()
  if not songs:
    s = Song(
        spotify_id='blinding_lights_default',
        title='Blinding Lights',
        artist='The Weeknd',
        rating=4.5,
        votes=245,
        preview_url=(
            'https://p.scdn.co/mp3-preview/612215112674e7dd92f44c4fa63102c918ee9eb1'
        ),
        img='https://images.unsplash.com/photo-1514525253161-7a46d19cd819?auto=format&fit=crop&q=80&w=500',
        release_year='2020',
        genre='Synthwave',
    )
    db.session.add(s)
    db.session.commit()
    songs = Song.query.all()
  return render_template_string(html_template, songs=songs)


@app.route('/top-rated')
def top_rated_page():
  all_top_songs = Song.query.order_by(
      Song.rating.desc(), Song.votes.desc()
  ).all()
  return render_template_string(top_rated_html, songs=all_top_songs)


@app.route('/login')
def login_page():
  return render_template_string(login_html)


@app.route('/register')
def register_page():
  return render_template_string(register_html)


@app.route('/profile')
def profile_page():
  return render_template_string(profile_html)


@app.route('/song/<spotify_id>')
def song_detail(spotify_id):
  if not spotify_id or len(spotify_id) > 100:
    return 'Invalid ID', 400

  song = Song.query.filter_by(spotify_id=spotify_id).first()
  if not song:
    token = get_spotify_token()
    if token:
      headers = {'Authorization': f'Bearer {token}'}
      try:
        res = requests.get(
            f'https://api.spotify.com/v1/tracks/{spotify_id}',
            headers=headers,
            timeout=5,
        )
        if res.status_code == 200:
          item = res.json()
          song = Song(
              spotify_id=item['id'],
              title=item['name'],
              artist=item['artists'][0]['name'],
              img=(
                  item['album']['images'][0]['url']
                  if item['album']['images']
                  else ''
              ),
              preview_url=item.get('preview_url'),
              rating=0.0,
              votes=0,
              release_year=item['album']['release_date'][:4],
              genre='Pop',
          )
          db.session.add(song)
          db.session.commit()
      except requests.exceptions.RequestException:
        pass

  if not song:
    return 'Song not found', 404

  reviews_data = []
  raw_reviews = Review.query.filter_by(song_id=song.id).all()
  for r in raw_reviews:
    u = User.query.filter_by(username=r.username).first()
    avatar_url = (
        u.avatar
        if u and u.avatar
        else (
            'https://images.unsplash.com/photo-1534528741775-53994a69daeb?auto=format&fit=crop&q=80&w=200'
        )
    )
    reviews_data.append({
        'id': r.id,
        'username': r.username,
        'rating': r.rating,
        'comment': r.comment,
        'likes': r.likes,
        'timestamp': r.timestamp if r.timestamp else time.time(),
        'avatar': avatar_url,
    })

  return render_template_string(
      song_detail_template, song=song, reviews=reviews_data
  )


@app.route('/api/search')
def search_spotify():
  query = request.args.get('q', '').strip()
  if not query or len(query) > 100:
    return jsonify([])
  token = get_spotify_token()
  if not token:
    return jsonify([])
  headers = {'Authorization': f'Bearer {token}'}
  params = {'q': query, 'type': 'track,artist', 'limit': 6}
  try:
    response = requests.get(
        'https://api.spotify.com/v1/search',
        headers=headers,
        params=params,
        timeout=5,
    )
    if response.status_code == 200:
      data = response.json()
      tracks = []
      for item in data.get('tracks', {}).get('items', []):
        tracks.append({
            'spotify_id': item['id'],
            'title': item['name'],
            'artist': item['artists'][0]['name'],
            'img': (
                item['album']['images'][0]['url']
                if item['album']['images']
                else ''
            ),
        })
      return jsonify(tracks)
  except requests.exceptions.RequestException:
    pass
  return jsonify([])


@app.route('/api/register', methods=['POST'])
def register():
  data = request.json
  if not data:
    return jsonify({'success': False, 'message': 'بيانات غير صالحة'})

  username = str(data.get('username', '')).strip()
  email = str(data.get('email', '')).strip().lower()
  password = str(data.get('password', ''))

  if not username or not email or not password:
    return jsonify({'success': False, 'message': 'يرجى ملء جميع الحقول!'})

  if len(username) > 50 or len(email) > 100 or len(password) > 100:
    return jsonify({'success': False, 'message': 'البيانات المدخلة طويلة جداً!'})

  if User.query.filter_by(email=email).first():
    return jsonify({'success': False, 'message': 'البريد الإلكتروني مسجل مسبقاً!'})
  if User.query.filter_by(username=username).first():
    return jsonify({'success': False, 'message': 'اسم المستخدم مستخدم بالفعل!'})

  hashed_password = generate_password_hash(password)
  new_user = User(username=username, email=email, password_hash=hashed_password)
  db.session.add(new_user)
  db.session.commit()
  return jsonify(
      {'success': True, 'username': username, 'avatar': new_user.avatar}
  )


@app.route('/api/login', methods=['POST'])
def login():
  data = request.json
  if not data:
    return jsonify({'success': False, 'message': 'بيانات غير صالحة'})

  email = str(data.get('email', '')).strip().lower()
  password = str(data.get('password', ''))

  user = User.query.filter_by(email=email).first()
  if user and check_password_hash(user.password_hash, password):
    return jsonify(
        {'success': True, 'username': user.username, 'avatar': user.avatar}
    )
  return jsonify(
      {'success': False, 'message': 'البريد الإلكتروني أو كلمة المرور غير صحيحة!'}
  )


@app.route('/api/update_avatar_file', methods=['POST'])
def update_avatar_file():
  username = request.form.get('username')
  user = User.query.filter_by(username=username).first()
  if not user:
    return jsonify({'success': False, 'message': 'المستخدم غير موجود'})

  if 'avatar_file' not in request.files:
    return jsonify({'success': False, 'message': 'لم يتم اختيار أي ملف'})

  file = request.files['avatar_file']
  if file.filename == '':
    return jsonify({'success': False, 'message': 'اسم الملف فارغ'})

  if file and allowed_file(file.filename):
    ext = file.filename.rsplit('.', 1)[1].lower()
    filename = secure_filename(f'{int(time.time())}_avatar.{ext}')
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(filepath)

    avatar_url = f'/static/uploads/{filename}'
    user.avatar = avatar_url
    db.session.commit()
    return jsonify({'success': True, 'avatar': user.avatar})

  return jsonify({'success': False, 'message': 'صيغة الملف غير مدعومة'})


@app.route('/api/update_avatar', methods=['POST'])
def update_avatar():
  data = request.json
  if not data:
    return jsonify({'success': False, 'message': 'خطأ في البيانات'})
  username = data.get('username')
  avatar_url = str(data.get('avatar', ''))

  user = User.query.filter_by(username=username).first()
  if not user:
    return jsonify({'success': False, 'message': 'المستخدم غير موجود'})

  user.avatar = avatar_url
  db.session.commit()
  return jsonify({'success': True, 'avatar': user.avatar})


@app.route('/api/get_user_info')
def get_user_info():
  username = request.args.get('username')
  user = User.query.filter_by(username=username).first()
  if user:
    return jsonify(
        {'success': True, 'username': user.username, 'avatar': user.avatar}
    )
  return jsonify({'success': False})


@app.route('/api/rate', methods=['POST'])
def add_review():
  data = request.json
  if not data:
    return jsonify({'success': False, 'message': 'بيانات غير صالحة'})

  spotify_id = data.get('spotify_id')
  try:
    score = float(data.get('rating'))
  except (TypeError, ValueError):
    return jsonify({'success': False, 'message': 'تقييم غير صالح'})

  comment = str(data.get('comment', ''))[:1000]
  username = data.get('username')

  if not username:
    return jsonify(
        {'success': False, 'message': 'يجب تسجيل الدخول أولاً لتقييم الأغنية!'}
    )

  if score < 1 or score > 5:
    return jsonify({'success': False, 'message': 'التقييم يجب أن يكون بين 1 و 5'})

  song = Song.query.filter_by(spotify_id=spotify_id).first()
  if not song:
    return jsonify({'success': False, 'message': 'الأغنية غير موجودة'}), 400

  user = User.query.filter_by(username=username).first()
  user_avatar = (
      user.avatar
      if user and user.avatar
      else (
          'https://images.unsplash.com/photo-1534528741775-53994a69daeb?auto=format&fit=crop&q=80&w=200'
      )
  )

  existing_review = Review.query.filter_by(
      song_id=song.id, username=username
  ).first()

  current_time = time.time()
  if existing_review:
    existing_review.rating = score
    existing_review.comment = comment
    existing_review.timestamp = current_time
  else:
    new_rev = Review(
        song_id=song.id,
        username=username,
        rating=score,
        comment=comment,
        likes=0,
        timestamp=current_time,
    )
    db.session.add(new_rev)

  db.session.commit()

  all_reviews = Review.query.filter_by(song_id=song.id).all()
  song.votes = len(all_reviews)
  if song.votes > 0:
    song.rating = round(sum(r.rating for r in all_reviews) / song.votes, 1)
  else:
    song.rating = 0.0

  db.session.commit()

  return jsonify({
      'success': True,
      'new_rating': song.rating,
      'votes': song.votes,
      'song_title': song.title,
      'artist': song.artist,
      'img': song.img,
      'avatar': user_avatar,
      'timestamp': current_time,
  })


@app.route('/api/like_review', methods=['POST'])
def like_review():
  data = request.json
  if not data:
    return jsonify({'success': False, 'message': 'بيانات غير صالحة'})
  review_id = data.get('review_id')
  username = data.get('username')

  if not username:
    return jsonify({'success': False, 'message': 'يجب تسجيل الدخول'})

  rev = Review.query.get(review_id)
  if not rev:
    return jsonify({'success': False, 'message': 'Review not found'})

  existing_like = ReviewLike.query.filter_by(
      review_id=review_id, username=username
  ).first()

  if existing_like:
    db.session.delete(existing_like)
    rev.likes = max(0, rev.likes - 1)
    liked = False
  else:
    new_like = ReviewLike(review_id=review_id, username=username)
    db.session.add(new_like)
    rev.likes += 1
    liked = True

  db.session.commit()
  return jsonify({'success': True, 'likes': rev.likes, 'liked': liked})


background_styles = """
<style>
    @keyframes backgroundMove {
        0% { background-position: 0% 50%; }
        50% { background-position: 100% 50%; }
        100% { background-position: 0% 50%; }
    }
    @keyframes pulseGlow {
        0%, 100% { opacity: 0.3; transform: scale(1) translateY(0); }
        50% { opacity: 0.65; transform: scale(1.2) translateY(-25px); }
    }
    @keyframes floatParticle {
        0% { transform: translateY(0px) rotate(0deg) scale(1); opacity: 0.3; }
        50% { transform: translateY(-50px) rotate(180deg) scale(1.3); opacity: 0.8; }
        100% { transform: translateY(0px) rotate(360deg) scale(1); opacity: 0.3; }
    }
    @keyframes neonPulse {
        0%, 100% { box-shadow: 0 0 15px rgba(29, 185, 84, 0.4), inset 0 0 10px rgba(29, 185, 84, 0.2); }
        50% { box-shadow: 0 0 35px rgba(29, 185, 84, 0.8), inset 0 0 20px rgba(29, 185, 84, 0.5); }
    }
    @keyframes heartbeat {
        0%, 100% { transform: scale(1); }
        15% { transform: scale(1.25); }
        30% { transform: scale(1); }
        45% { transform: scale(1.15); }
        60% { transform: scale(1); }
    }
    .ammar-love-badge {
        display: inline-flex;
        align-items: center;
        gap: 8px;
        background: linear-gradient(135deg, rgba(14, 28, 20, 0.95), rgba(5, 15, 10, 0.95));
        padding: 8px 16px;
        border-radius: 9999px;
        border: 1px solid rgba(29, 185, 84, 0.5);
        box-shadow: 0 0 20px rgba(29, 185, 84, 0.35), inset 0 1px 0 rgba(29, 185, 84, 0.3);
        backdrop-filter: blur(16px);
        font-size: 12px;
        font-weight: 700;
        color: #f8fafc;
        letter-spacing: 0.8px;
        white-space: nowrap;
    }
    .ammar-love-badge i.fa-heart {
        color: #ef4444;
        filter: drop-shadow(0 0 8px rgba(239, 68, 68, 0.9));
        animation: heartbeat 1.6s infinite ease-in-out;
        font-size: 14px;
    }
    body {
        background: linear-gradient(135deg, #020403, #060d08, #010201, #08120b);
        background-size: 400% 400%;
        animation: backgroundMove 20s ease infinite;
        position: relative;
        overflow-x: hidden;
    }
    .animated-bg-glow {
        position: fixed;
        width: 800px;
        height: 800px;
        background: radial-gradient(circle, rgba(29, 185, 84, 0.22) 0%, rgba(0, 0, 0, 0) 70%);
        top: -300px;
        right: -250px;
        z-index: -1;
        animation: pulseGlow 8s ease-in-out infinite;
        pointer-events: none;
        border-radius: 50%;
        filter: blur(60px);
    }
    .animated-bg-glow-2 {
        position: fixed;
        width: 750px;
        height: 750px;
        background: radial-gradient(circle, rgba(16, 185, 129, 0.16) 0%, rgba(0, 0, 0, 0) 70%);
        bottom: -250px;
        left: -250px;
        z-index: -1;
        animation: pulseGlow 10s ease-in-out infinite alternate;
        pointer-events: none;
        border-radius: 50%;
        filter: blur(70px);
    }
    .floating-orb {
        position: fixed;
        width: 6px;
        height: 6px;
        background: #1db954;
        box-shadow: 0 0 16px #1db954, 0 0 30px #1db954;
        border-radius: 50%;
        z-index: -1;
        animation: floatParticle 6s ease-in-out infinite;
        pointer-events: none;
    }
    .glass-card {
        background: rgba(10, 20, 14, 0.85);
        backdrop-filter: blur(20px);
        border: 1px solid rgba(29, 185, 84, 0.3);
        box-shadow: 0 15px 35px rgba(0, 0, 0, 0.6), inset 0 1px 0 rgba(29, 185, 84, 0.2);
        transition: all 0.4s cubic-bezier(0.4, 0, 0.2, 1);
    }
    .glass-card:hover {
        border-color: rgba(29, 185, 84, 0.7);
        box-shadow: 0 20px 50px rgba(29, 185, 84, 0.25), inset 0 1px 0 rgba(29, 185, 84, 0.4);
        transform: translateY(-4px);
    }
    .neon-border {
        animation: neonPulse 3s infinite;
    }
    ::-webkit-scrollbar { width: 8px; }
    ::-webkit-scrollbar-track { background: #030504; }
    ::-webkit-scrollbar-thumb { background: #153822; border-radius: 4px; border: 1px solid rgba(29,185,84,0.3); }
    ::-webkit-scrollbar-thumb:hover { background: #1db954; box-shadow: 0 0 10px #1db954; }
</style>
<div class="animated-bg-glow"></div>
<div class="animated-bg-glow-2"></div>
<div class="floating-orb" style="top: 15%; left: 8%; animation-delay: 0s;"></div>
<div class="floating-orb" style="top: 55%; left: 90%; animation-delay: 1.5s;"></div>
<div class="floating-orb" style="top: 85%; left: 20%; animation-delay: 3s;"></div>
<div class="floating-orb" style="top: 25%; left: 80%; animation-delay: 4.5s;"></div>

<script>
    const translations = {
        en: {
            brandName: "Musicy",
            searchPlaceholder: "Search songs or artists on Spotify...",
            home: "Home",
            topRated: "Top Rated",
            heroTag: "Real fans. Real ratings.",
            heroTitle1: "Discover Rate",
            heroTitle2: "Share Music.",
            heroDesc: "Search any song from Spotify to view ratings, read reviews",
            trendingTitle: "Trending & Random Songs",
            refreshSongs: "Refresh Songs",
            votesText: "votes",
            topRatedTitle: "All Top Rated Songs",
            topRatedDesc: "Explore the highest-rated songs ranked by user reviews and votes on Musicy.",
            noRated: "No rated songs found yet. Start searching and rating songs!",
            welcomeBack: "Welcome Back",
            loginDesc: "Sign in to rate songs and share your reviews on Musicy",
            emailLabel: "Email Address",
            passwordLabel: "Password",
            signInBtn: "Sign In",
            noAccount: "Don't have an account?",
            createAccountLink: "Create Account",
            createAccountTitle: "Create Account",
            createAccountDesc: "Join Musicy community and start rating today",
            usernameLabel: "Username",
            alreadyAccount: "Already have an account?",
            signInLink: "Sign In",
            listenSpotify: "Listen on Spotify",
            rateSongBtn: "Rate This Song",
            editReviewBtn: "Edit Your Review",
            reviewsTitle: "Reviews & Ratings",
            writeReviewBtn: "Write Review",
            noReviews: "No reviews yet. Be the first to review this song!",
            ratingDetails: "Rating Details",
            overallRating: "Overall Rating",
            totalVotes: "Total Votes",
            rateModalTitle: "Rate",
            ratingScoreLabel: "Rating Stars (1 to 5):",
            commentLabel: "Your Review / Comment:",
            submitRatingBtn: "Submit Rating & Generate Story",
            cancelBtn: "Cancel",
            logoutTitle: "Logout",
            profileTitle: "Edit Profile & Avatar",
            avatarFileLabel: "Choose image from device (PC or Phone):",
            saveAvatarBtn: "Upload & Save Avatar",
            storyModalTitle: "Luxury Instagram Story Preview",
            downloadStoryBtn: "Download Luxury Story",
            closeStoryBtn: "Close & Continue"
        },
        ar: {
            brandName: "Musicy",
            searchPlaceholder: "ابحث عن الأغاني أو الفنانين في سبوتيفاي...",
            home: "الرئيسية",
            topRated: "الأعلى تقييماً",
            heroTag: "معجبون حقيقيون. تقييمات حقيقية.",
            heroTitle1: "اكتشف. تقييم.",
            heroTitle2: "شارك الموسيقى.",
            heroDesc: "ابحث عن أي أغنية من سبوتيفاي لعرض التقييمات، قراءة المراجعات، أو نشر تقييمك الخاص بتصميم فاخر وخيالي.",
            trendingTitle: "الأغاني الرائجة والعشوائية",
            refreshSongs: "تحديث الأغاني",
            votesText: "أصوات",
            topRatedTitle: "جميع الأغاني الأعلى تقييماً",
            topRatedDesc: "استكشف الأغاني الأعلى تقييماً بناءً على آراء المستخدمين والأصوات في Musicy.",
            noRated: "لا توجد أغاني مقيمة بعد. ابدأ بالبحث وتقييم الأغاني!",
            welcomeBack: "مرحباً بك مجدداً",
            loginDesc: "سجل الدخول لتقييم الأغاني ومشاركة آرائك على Musicy",
            emailLabel: "البريد الإلكتروني",
            passwordLabel: "كلمة المرور",
            signInBtn: "تسجيل الدخول",
            noAccount: "ليس لديك حساب؟",
            createAccountLink: "إنشاء حساب",
            createAccountTitle: "إنشاء حساب",
            createAccountDesc: "انضم إلى مجتمع Musicy وابدأ التقييم اليوم",
            usernameLabel: "اسم المستخدم",
            alreadyAccount: "لديك حساب بالفعل؟",
            signInLink: "تسجيل الدخول",
            listenSpotify: "استمع وتشغيل على Spotify",
            rateSongBtn: "قيم هذه الأغنية",
            editReviewBtn: "تعديل تقييمك ورأيك",
            reviewsTitle: "التقييمات والآراء",
            writeReviewBtn: "اكتب رأيك",
            noReviews: "لا توجد تقييمات بعد. كن أول من يقيّم هذه الأغنية!",
            ratingDetails: "تفاصيل التقييم",
            overallRating: "التقييم العام",
            totalVotes: "عدد الأصوات",
            rateModalTitle: "تقييم",
            ratingScoreLabel: "اختر النجوم (من 1 إلى 5):",
            commentLabel: "رأيك أو تعليقك:",
            submitRatingBtn: "إرسال التقييم وإنشاء الستوري",
            cancelBtn: "إلغاء",
            logoutTitle: "تسجيل الخروج",
            profileTitle: "تعديل الصورة الشخصية",
            avatarFileLabel: "اختر صورة من جهازك (كمبيوتر أو هاتف):",
            saveAvatarBtn: "رفع وحفظ الصورة الشخصية",
            storyModalTitle: "معاينة ستوري انستقرام الخارقة الفخامة",
            downloadStoryBtn: "تحميل ستوري الفخامة",
            closeStoryBtn: "إغلاق ومتابعة"
        }
    };

    function setLanguage(lang) {
        localStorage.setItem('musicy_lang', lang);
        document.documentElement.setAttribute('dir', lang === 'ar' ? 'rtl' : 'ltr');
        document.documentElement.setAttribute('lang', lang);
        
        document.querySelectorAll('[data-i18n]').forEach(el => {
            const key = el.getAttribute('data-i18n');
            if(translations[lang][key]) {
                el.innerText = translations[lang][key];
            }
        });
        document.querySelectorAll('[data-i18n-placeholder]').forEach(el => {
            const key = el.getAttribute('data-i18n-placeholder');
            if(translations[lang][key]) {
                el.placeholder = translations[lang][key];
            }
        });
        if(typeof updateAllTimes === 'function') {
            updateAllTimes();
        }
        if(typeof updateUserNav === 'function') {
            updateUserNav();
        }
    }

    document.addEventListener('DOMContentLoaded', () => {
        let savedLang = localStorage.getItem('musicy_lang') || 'en';
        setLanguage(savedLang);
    });
</script>
"""

lang_switcher_html = """
<div class="flex items-center space-x-3">
    <div class="ammar-love-badge hidden sm:inline-flex items-center gap-2">
        <span>Made with</span>
        <i class="fa-solid fa-heart"></i>
        <span>by Ammar</span>
    </div>
    <div class="flex items-center space-x-2 bg-[#0e1c14]/90 px-3.5 py-2 rounded-full border border-[#1db954]/50 shadow-[0_0_15px_rgba(29,185,84,0.3)] backdrop-blur-md">
        <button onclick="setLanguage('en')" title="English" class="hover:scale-125 transition transform duration-200 text-base drop-shadow-[0_0_8px_rgba(255,255,255,0.4)]">🇺🇸</button>
        <span class="text-[#1db954]/60 text-xs font-light">|</span>
        <button onclick="setLanguage('ar')" title="العربية" class="hover:scale-125 transition transform duration-200 text-base drop-shadow-[0_0_8px_rgba(255,255,255,0.4)]">🇮🇶</button>
    </div>
</div>
"""

html_template = (
    """<!DOCTYPE html>
<html lang="en" class="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Musicy - Discover, Rate, Share Music</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    """
    + background_styles
    + """
</head>
<body class="text-gray-100 font-sans antialiased min-h-screen flex flex-col">
    <header class="border-b border-[#1db954]/30 bg-[#020403]/90 backdrop-blur-2xl sticky top-0 z-50 h-16 flex items-center px-4 md:px-8 justify-between shadow-[0_4px_30px_rgba(0,0,0,0.8)]">
        <div class="flex items-center space-x-6 md:space-x-12 w-full">
            <a href="/" class="flex items-center space-x-2 text-[#1db954] font-bold text-xl tracking-wider group">
                <i class="fa-solid fa-music text-[#1db954] group-hover:rotate-45 group-hover:scale-125 transition transform duration-500 drop-shadow-[0_0_10px_#1db954]"></i>
                <span class="tracking-widest bg-gradient-to-r from-white via-gray-200 to-[#1db954] bg-clip-text text-transparent font-extrabold" data-i18n="brandName">Musicy</span>
            </a>
            <div class="relative flex-1 max-w-xl hidden md:block">
                <span class="absolute inset-y-0 left-0 flex items-center pl-3.5 text-[#1db954]"><i class="fa-solid fa-magnifying-glass text-xs"></i></span>
                <input type="text" id="searchInput" data-i18n-placeholder="searchPlaceholder" placeholder="Search songs or artists on Spotify..." class="w-full bg-[#050b07] text-xs text-gray-200 pl-10 pr-4 py-3 rounded-2xl border border-[#1db954]/40 focus:outline-none focus:border-[#1db954] focus:ring-4 focus:ring-[#1db954]/30 transition shadow-inner">
                <div id="searchResults" class="absolute left-0 right-0 mt-2 bg-[#050b07]/95 border border-[#1db954]/50 rounded-2xl shadow-2xl hidden z-50 max-h-80 overflow-y-auto backdrop-blur-2xl"></div>
            </div>
        </div>
        <div class="flex items-center space-x-4 text-xs font-medium text-gray-300">
            """
    + lang_switcher_html
    + """
            <a href="/" class="hidden sm:flex items-center space-x-1.5 text-[#1db954] hover:text-[#1ed760] transition"><i class="fa-solid fa-house"></i> <span data-i18n="home">Home</span></a>
            <div id="userProfileArea">
                <a href="/login" class="w-10 h-10 rounded-full bg-gradient-to-tr from-[#1db954] to-[#1ed760] text-gray-950 font-extrabold border border-[#1db954]/70 flex items-center justify-center shadow-[0_0_15px_rgba(29,185,84,0.6)] hover:scale-110 transition transform duration-300">
                    <i class="fa-solid fa-user text-xs"></i>
                </a>
            </div>
        </div>
    </header>
    <div class="flex flex-1">
        <aside class="w-64 border-r border-[#1db954]/25 bg-[#020403]/80 p-4 hidden lg:flex flex-col justify-between shrink-0 backdrop-blur-2xl">
            <div class="space-y-6">
                <nav class="space-y-2 text-xs font-medium">
                    <a href="/" class="flex items-center space-x-3 px-4 py-3 rounded-2xl text-gray-400 hover:bg-[#1db954]/20 hover:text-white transition duration-300"><i class="fa-solid fa-house w-4 text-[#1db954]"></i><span data-i18n="home">Home</span></a>
                    <a href="/top-rated" class="flex items-center space-x-3 px-4 py-3 rounded-2xl bg-[#1db954]/25 text-[#1db954] font-semibold border-l-4 border-[#1db954] shadow-[0_0_15px_rgba(29,185,84,0.2)]"><i class="fa-solid fa-star w-4"></i><span data-i18n="topRated">Top Rated</span></a>
                </nav>
            </div>
        </aside>
        <main class="flex-1 p-6 md:p-10 space-y-10 overflow-x-hidden">
            <div class="relative rounded-3xl overflow-hidden bg-gradient-to-r from-[#081a10] via-[#040e08] to-[#020403] border border-[#1db954]/50 p-8 md:p-14 shadow-[0_20px_50px_rgba(0,0,0,0.8)] flex flex-col justify-between backdrop-blur-2xl group neon-border">
                <div class="absolute -right-12 -bottom-12 w-80 h-80 bg-[#1db954]/20 rounded-full blur-3xl group-hover:scale-150 transition duration-1000 pointer-events-none"></div>
                <div class="relative z-10 space-y-5 max-w-xl">
                    <span class="text-[11px] tracking-widest text-[#1db954] uppercase font-bold bg-[#1db954]/20 px-4 py-2 rounded-full border border-[#1db954]/40 shadow-sm" data-i18n="heroTag">Real fans. Real ratings.</span>
                    <h1 class="text-3xl md:text-5xl font-extrabold tracking-tight text-white leading-tight"><span data-i18n="heroTitle1">Discover. Rate.</span><br><span class="text-[#1db954] drop-shadow-[0_0_20px_rgba(29,185,84,0.6)]" data-i18n="heroTitle2">Share Music.</span></h1>
                    <p class="text-xs md:text-sm text-gray-300 leading-relaxed font-light" data-i18n="heroDesc">Search any song from Spotify to view ratings</p>
                </div>
            </div>
            <section class="space-y-5">
                <div class="flex items-center justify-between">
                    <h2 class="text-base font-bold text-white flex items-center space-x-2.5"><i class="fa-solid fa-fire text-[#1db954] text-xs animate-bounce"></i><span data-i18n="trendingTitle">Trending & Random Songs</span> <span class="text-xs text-gray-400 font-normal">({{ songs|length }})</span></h2>
                    <button onclick="location.reload()" class="text-xs text-[#1db954] hover:text-white font-semibold flex items-center space-x-2 bg-[#050b07] border border-[#1db954]/40 px-4 py-2.5 rounded-2xl transition hover:border-[#1db954] hover:shadow-[0_0_15px_rgba(29,185,84,0.4)] shadow">
                        <i class="fa-solid fa-rotate"></i> <span data-i18n="refreshSongs">Refresh Songs</span>
                    </button>
                </div>
                <div class="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 lg:grid-cols-6 gap-5">
                    {% for song in songs %}
                    <div onclick="window.location.href='/song/{{ song.spotify_id }}'" class="glass-card rounded-2xl p-4 space-y-3 cursor-pointer group flex flex-col justify-between">
                        <div class="relative overflow-hidden rounded-xl">
                            <img src="{{ song.img }}" class="w-full h-36 object-cover group-hover:scale-115 transition duration-700">
                            <div class="absolute inset-0 bg-gradient-to-t from-black/70 via-transparent to-transparent opacity-0 group-hover:opacity-100 transition duration-300"></div>
                        </div>
                        <div class="space-y-1">
                            <h4 class="font-bold text-xs text-white truncate group-hover:text-[#1db954] transition">{{ song.title }}</h4>
                            <p class="text-[11px] text-gray-400 truncate">{{ song.artist }}</p>
                        </div>
                        <div class="flex items-center justify-between text-[11px] pt-2 border-t border-[#1db954]/20">
                            <span class="text-[#1db954] font-bold flex items-center"><i class="fa-solid fa-star text-[10px] mr-1"></i> {{ song.rating }}</span>
                            <span class="text-gray-500 text-[10px]">({{ song.votes }} <span data-i18n="votesText">votes</span>)</span>
                        </div>
                    </div>
                    {% endfor %}
                </div>
            </section>
        </main>
    </div>
    <script>
        document.addEventListener('DOMContentLoaded', () => { 
            updateUserNav();
            let savedLang = localStorage.getItem('musicy_lang') || 'en';
            setLanguage(savedLang);
        });
        function updateUserNav() {
            let currentUser = localStorage.getItem('songdb_user');
            let currentAvatar = localStorage.getItem('songdb_avatar') || 'https://images.unsplash.com/photo-1534528741775-53994a69daeb?auto=format&fit=crop&q=80&w=200';
            let area = document.getElementById('userProfileArea');
            if (currentUser) {
                let logoutText = (localStorage.getItem('musicy_lang') === 'ar') ? 'تسجيل الخروج' : 'Logout';
                area.innerHTML = `
                    <div class="flex items-center space-x-3">
                        <a href="/profile" class="flex items-center space-x-2 bg-[#050b07] px-3.5 py-2 rounded-full border border-[#1db954]/50 shadow-[0_0_15px_rgba(29,185,84,0.3)] backdrop-blur-md hover:opacity-80 transition">
                            <img src="${currentAvatar}" class="w-7 h-7 rounded-full object-cover border border-[#1db954]">
                            <span class="text-[#1db954] font-bold text-xs">${currentUser}</span>
                        </a>
                        <button onclick="handleLogout()" class="bg-[#050b07] text-gray-400 hover:text-red-400 w-9 h-9 rounded-full border border-red-500/40 hover:border-red-500 flex items-center justify-center transition shadow-md" title="${logoutText}">
                            <i class="fa-solid fa-right-from-bracket text-xs"></i>
                        </button>
                    </div>
                `;
            } else {
                area.innerHTML = `
                    <a href="/login" class="w-10 h-10 rounded-full bg-gradient-to-tr from-[#1db954] to-[#1ed760] text-gray-950 font-extrabold border border-[#1db954]/70 flex items-center justify-center shadow-[0_0_15px_rgba(29,185,84,0.6)] hover:scale-110 transition transform duration-300">
                        <i class="fa-solid fa-user text-xs"></i>
                    </a>
                `;
            }
        }
        function handleLogout() { 
            localStorage.removeItem('songdb_user'); 
            localStorage.removeItem('songdb_avatar'); 
            location.reload(); 
        }
        const searchInput = document.getElementById('searchInput');
        const searchResults = document.getElementById('searchResults');
        let timeout = null;
        searchInput.addEventListener('input', function() {
            clearTimeout(timeout);
            let query = this.value.trim();
            if (query.length < 2) { searchResults.classList.add('hidden'); return; }
            timeout = setTimeout(() => {
                fetch(`/api/search?q=${encodeURIComponent(query)}`).then(res => res.json()).then(data => {
                    searchResults.innerHTML = '';
                    if (data.length === 0) { searchResults.innerHTML = '<div class="p-3 text-xs text-gray-400">No songs found.</div>'; }
                    else {
                        data.forEach(song => {
                            let div = document.createElement('div');
                            div.className = 'flex items-center space-x-3 p-3 hover:bg-[#1db954]/25 border-b border-[#1db954]/10 cursor-pointer transition';
                            div.innerHTML = `<img src="${song.img}" class="w-11 h-11 object-cover rounded-xl border border-[#1db954]/30"><div><div class="text-xs font-bold text-white">${song.title}</div><div class="text-[10px] text-gray-400">${song.artist}</div></div>`;
                            div.addEventListener('click', () => { window.location.href = `/song/${song.spotify_id}`; });
                            searchResults.appendChild(div);
                        });
                    }
                    searchResults.classList.remove('hidden');
                });
            }, 300);
        });
    </script>
</body>
</html>"""
)

top_rated_html = (
    """<!DOCTYPE html>
<html lang="en" class="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Top Rated Songs - Musicy</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    """
    + background_styles
    + """
</head>
<body class="text-gray-100 font-sans antialiased min-h-screen flex flex-col">
    <header class="border-b border-[#1db954]/30 bg-[#020403]/90 backdrop-blur-2xl sticky top-0 z-50 h-16 flex items-center px-4 md:px-8 justify-between shadow-[0_4px_30px_rgba(0,0,0,0.8)]">
        <div class="flex items-center space-x-12 w-full"><a href="/" class="flex items-center space-x-2 text-[#1db954] font-bold text-xl tracking-wider"><i class="fa-solid fa-music text-[#1db954]"></i><span class="tracking-widest" data-i18n="brandName">Musicy</span></a></div>
        <div class="flex items-center space-x-4 text-xs font-medium text-gray-300">
            """
    + lang_switcher_html
    + """
            <a href="/" class="flex items-center space-x-1.5 text-[#1db954] hover:text-white transition"><i class="fa-solid fa-house"></i> <span data-i18n="home">Home</span></a>
        </div>
    </header>
    <div class="flex flex-1">
        <aside class="w-64 border-r border-[#1db954]/25 bg-[#020403]/80 p-4 hidden lg:flex flex-col justify-between shrink-0 backdrop-blur-2xl">
            <div class="space-y-6">
                <nav class="space-y-2 text-xs font-medium">
                    <a href="/" class="flex items-center space-x-3 px-4 py-3 rounded-2xl text-gray-400 hover:bg-[#1db954]/20 hover:text-white transition duration-300"><i class="fa-solid fa-house w-4 text-[#1db954]"></i><span data-i18n="home">Home</span></a>
                    <a href="/top-rated" class="flex items-center space-x-3 px-4 py-3 rounded-2xl bg-[#1db954]/25 text-[#1db954] font-semibold border-l-4 border-[#1db954] shadow-[0_0_15px_rgba(29,185,84,0.2)]"><i class="fa-solid fa-star w-4"></i><span data-i18n="topRated">Top Rated</span></a>
                </nav>
            </div>
        </aside>
        <main class="flex-1 p-6 md:p-10 space-y-8 max-w-6xl mx-auto w-full">
            <div class="space-y-2">
                <h1 class="text-2xl md:text-3xl font-extrabold text-white flex items-center space-x-3"><i class="fa-solid fa-star text-[#1db954] animate-spin"></i><span data-i18n="topRatedTitle">All Top Rated Songs</span></h1>
                <p class="text-xs text-gray-400" data-i18n="topRatedDesc">Explore the highest-rated songs ranked by user reviews and votes on Musicy.</p>
            </div>
            <div class="space-y-4">
                {% for song in songs %}
                <div onclick="window.location.href='/song/{{ song.spotify_id }}'" class="glass-card rounded-2xl p-4.5 flex items-center justify-between cursor-pointer group">
                    <div class="flex items-center space-x-4">
                        <span class="text-sm font-bold text-gray-500 w-6 text-center">#{{ loop.index }}</span>
                        <img src="{{ song.img }}" class="w-14 h-14 object-cover rounded-2xl border border-[#1db954]/40 shadow-md">
                        <div>
                            <h3 class="font-bold text-sm text-white group-hover:text-[#1db954] transition">{{ song.title }}</h3>
                            <p class="text-xs text-gray-400">{{ song.artist }} &bull; <span class="text-gray-500">{{ song.release_year }}</span></p>
                        </div>
                    </div>
                    <div class="flex items-center space-x-6 text-right">
                        <div>
                            <div class="text-sm font-extrabold text-[#1db954] flex items-center justify-end space-x-1">
                                <i class="fa-solid fa-star text-xs"></i>
                                <span>{{ song.rating }}</span>
                                <span class="text-[10px] text-gray-400 font-normal">/5</span>
                            </div>
                            <div class="text-[10px] text-gray-500"><span class="font-bold">{{ song.votes }}</span> <span data-i18n="votesText">votes</span></div>
                        </div>
                        <i class="fa-solid fa-chevron-right text-xs text-gray-600 group-hover:text-[#1db954] group-hover:translate-x-1 transition pr-2"></i>
                    </div>
                </div>
                {% else %}
                <div class="glass-card rounded-2xl p-12 text-center text-gray-400 text-xs" data-i18n="noRated">No rated songs found yet. Start searching and rating songs!</div>
                {% endfor %}
            </div>
        </main>
    </div>
    <script>
        document.addEventListener('DOMContentLoaded', () => {
            let savedLang = localStorage.getItem('musicy_lang') || 'en';
            setLanguage(savedLang);
        });
    </script>
</body>
</html>"""
)

login_html = (
    """<!DOCTYPE html>
<html lang="en" class="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Sign In - Musicy</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    """
    + background_styles
    + """
</head>
<body class="text-gray-100 font-sans min-h-screen flex items-center justify-center p-4">
    <div class="absolute top-6 right-6">
        """
    + lang_switcher_html
    + """
    </div>
    <div class="w-full max-w-md glass-card rounded-3xl p-8 shadow-2xl space-y-6 relative neon-border">
        <a href="/" class="absolute top-6 left-6 text-gray-400 hover:text-white text-xs flex items-center space-x-1 transition"><i class="fa-solid fa-arrow-left"></i> <span data-i18n="home">Home</span></a>
        <div class="text-center space-y-2.5 pt-4">
            <div class="inline-flex w-16 h-16 rounded-2xl bg-[#1db954]/20 border border-[#1db954]/40 text-[#1db954] items-center justify-center text-2xl shadow-inner"><i class="fa-solid fa-music"></i></div>
            <h1 class="text-2xl font-extrabold text-white tracking-tight" data-i18n="welcomeBack">Welcome Back</h1>
            <p class="text-xs text-gray-400" data-i18n="loginDesc">Sign in to rate songs and share your reviews on Musicy</p>
        </div>
        <div class="space-y-4 text-xs">
            <div class="space-y-1.5"><label class="text-gray-400 font-medium" data-i18n="emailLabel">Email Address</label><input type="email" id="loginEmail" placeholder="name@example.com" class="w-full bg-[#050b07] text-gray-200 px-4 py-3.5 rounded-2xl border border-[#1db954]/40 focus:outline-none focus:border-[#1db954] focus:ring-4 focus:ring-[#1db954]/30 transition shadow-inner"></div>
            <div class="space-y-1.5"><label class="text-gray-400 font-medium" data-i18n="passwordLabel">Password</label><input type="password" id="loginPassword" placeholder="••••••••" class="w-full bg-[#050b07] text-gray-200 px-4 py-3.5 rounded-2xl border border-[#1db954]/40 focus:outline-none focus:border-[#1db954] focus:ring-4 focus:ring-[#1db954]/30 transition shadow-inner"></div>
            <button onclick="handleLogin()" class="w-full bg-gradient-to-r from-[#1db954] to-[#1ed760] hover:opacity-95 text-gray-950 font-bold py-4 rounded-2xl transition shadow-[0_0_20px_rgba(29,185,84,0.4)] text-sm mt-2 hover:scale-[1.02] transform duration-300" data-i18n="signInBtn">Sign In</button>
        </div>
        <div class="text-center text-xs text-gray-400 pt-2"><span data-i18n="noAccount">Don't have an account?</span> <a href="/register" class="text-[#1db954] font-bold hover:underline" data-i18n="createAccountLink">Create Account</a></div>
    </div>
    <script>
        document.addEventListener('DOMContentLoaded', () => {
            let savedLang = localStorage.getItem('musicy_lang') || 'en';
            setLanguage(savedLang);
        });
        function handleLogin() {
            let email = document.getElementById('loginEmail').value;
            let password = document.getElementById('loginPassword').value;
            if(!email || !password) { alert('Please fill in all fields'); return; }
            fetch('/api/login', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({email, password}) }).then(res => res.json()).then(data => {
                if(data.success) { 
                    localStorage.setItem('songdb_user', data.username); 
                    localStorage.setItem('songdb_avatar', data.avatar); 
                    window.location.href = '/'; 
                } else { alert(data.message); }
            });
        }
    </script>
</body>
</html>"""
)

register_html = (
    """<!DOCTYPE html>
<html lang="en" class="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Create Account - Musicy</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    """
    + background_styles
    + """
</head>
<body class="text-gray-100 font-sans min-h-screen flex items-center justify-center p-4">
    <div class="absolute top-6 right-6">
        """
    + lang_switcher_html
    + """
    </div>
    <div class="w-full max-w-md glass-card rounded-3xl p-8 shadow-2xl space-y-6 relative neon-border">
        <a href="/" class="absolute top-6 left-6 text-gray-400 hover:text-white text-xs flex items-center space-x-1 transition"><i class="fa-solid fa-arrow-left"></i> <span data-i18n="home">Home</span></a>
        <div class="text-center space-y-2.5 pt-4">
            <div class="inline-flex w-16 h-16 rounded-2xl bg-[#1db954]/20 border border-[#1db954]/40 text-[#1db954] items-center justify-center text-2xl shadow-inner"><i class="fa-solid fa-music"></i></div>
            <h1 class="text-2xl font-extrabold text-white tracking-tight" data-i18n="createAccountTitle">Create Account</h1>
            <p class="text-xs text-gray-400" data-i18n="createAccountDesc">Join Musicy community and start rating today</p>
        </div>
        <div class="space-y-4 text-xs">
            <div class="space-y-1.5"><label class="text-gray-400 font-medium" data-i18n="usernameLabel">Username</label><input type="text" id="regUsername" placeholder="musiclover99" class="w-full bg-[#050b07] text-gray-200 px-4 py-3.5 rounded-2xl border border-[#1db954]/40 focus:outline-none focus:border-[#1db954] focus:ring-4 focus:ring-[#1db954]/30 transition shadow-inner"></div>
            <div class="space-y-1.5"><label class="text-gray-400 font-medium" data-i18n="emailLabel">Email Address</label><input type="email" id="regEmail" placeholder="name@example.com" class="w-full bg-[#050b07] text-gray-200 px-4 py-3.5 rounded-2xl border border-[#1db954]/40 focus:outline-none focus:border-[#1db954] focus:ring-4 focus:ring-[#1db954]/30 transition shadow-inner"></div>
            <div class="space-y-1.5"><label class="text-gray-400 font-medium" data-i18n="passwordLabel">Password</label><input type="password" id="regPassword" placeholder="••••••••" class="w-full bg-[#050b07] text-gray-200 px-4 py-3.5 rounded-2xl border border-[#1db954]/40 focus:outline-none focus:border-[#1db954] focus:ring-4 focus:ring-[#1db954]/30 transition shadow-inner"></div>
            <button onclick="handleRegister()" class="w-full bg-gradient-to-r from-[#1db954] to-[#1ed760] hover:opacity-95 text-gray-950 font-bold py-4 rounded-2xl transition shadow-[0_0_20px_rgba(29,185,84,0.4)] text-sm mt-2 hover:scale-[1.02] transform duration-300" data-i18n="createAccountTitle">Create Account</button>
        </div>
        <div class="text-center text-xs text-gray-400 pt-2"><span data-i18n="alreadyAccount">Already have an account?</span> <a href="/login" class="text-[#1db954] font-bold hover:underline" data-i18n="signInLink">Sign In</a></div>
    </div>
    <script>
        document.addEventListener('DOMContentLoaded', () => {
            let savedLang = localStorage.getItem('musicy_lang') || 'en';
            setLanguage(savedLang);
        });
        function handleRegister() {
            let username = document.getElementById('regUsername').value;
            let email = document.getElementById('regEmail').value;
            let password = document.getElementById('regPassword').value;
            if(!username || !email || !password) { alert('Please fill in all fields'); return; }
            fetch('/api/register', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({username, email, password}) }).then(res => res.json()).then(data => {
                if(data.success) { 
                    localStorage.setItem('songdb_user', data.username); 
                    localStorage.setItem('songdb_avatar', data.avatar); 
                    window.location.href = '/'; 
                } else { alert(data.message); }
            });
        }
    </script>
</body>
</html>"""
)

profile_html = (
    """<!DOCTYPE html>
<html lang="en" class="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Edit Profile - Musicy</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    """
    + background_styles
    + """
</head>
<body class="text-gray-100 font-sans min-h-screen flex items-center justify-center p-4">
    <div class="absolute top-6 right-6">
        """
    + lang_switcher_html
    + """
    </div>
    <div class="w-full max-w-md glass-card rounded-3xl p-8 shadow-2xl space-y-6 relative neon-border">
        <a href="/" class="absolute top-6 left-6 text-gray-400 hover:text-white text-xs flex items-center space-x-1 transition"><i class="fa-solid fa-arrow-left"></i> <span data-i18n="home">Home</span></a>
        <div class="text-center space-y-3 pt-4">
            <div class="relative w-24 h-24 mx-auto group">
                <img id="profileAvatarPreview" src="https://images.unsplash.com/photo-1534528741775-53994a69daeb?auto=format&fit=crop&q=80&w=200" class="w-24 h-24 rounded-full object-cover border-2 border-[#1db954] shadow-xl">
            </div>
            <h1 class="text-xl font-extrabold text-white tracking-tight" id="profileUsernameDisplay">Username</h1>
            <p class="text-xs text-gray-400" data-i18n="profileTitle">تعديل الصورة الشخصية</p>
        </div>
        <div class="space-y-4 text-xs">
            <div class="space-y-1.5">
                <label class="text-gray-400 font-medium" data-i18n="avatarFileLabel">اختر صورة من جهازك (كمبيوتر أو هاتف):</label>
                <input type="file" id="avatarFileInput" accept="image/*" class="w-full bg-[#050b07] text-gray-200 file:mr-4 file:py-2.5 file:px-4 file:rounded-xl file:border-0 file:text-xs file:font-semibold file:bg-[#1db954] file:text-gray-950 hover:file:bg-[#1ed760] file:cursor-pointer p-3.5 rounded-2xl border border-[#1db954]/40 focus:outline-none transition shadow-inner">
            </div>
            <button onclick="saveAvatarFile()" class="w-full bg-gradient-to-r from-[#1db954] to-[#1ed760] hover:opacity-95 text-gray-950 font-bold py-4 rounded-2xl transition shadow-[0_0_20px_rgba(29,185,84,0.4)] text-sm mt-2 hover:scale-[1.02] transform duration-300" data-i18n="saveAvatarBtn">رفع وحفظ الصورة الشخصية</button>
        </div>
    </div>
    <script>
        document.addEventListener('DOMContentLoaded', () => {
            let savedLang = localStorage.getItem('musicy_lang') || 'en';
            setLanguage(savedLang);

            let currentUser = localStorage.getItem('songdb_user');
            if(!currentUser) { window.location.href = '/login'; return; }
            document.getElementById('profileUsernameDisplay').innerText = '@' + currentUser;
            
            let currentAvatar = localStorage.getItem('songdb_avatar');
            if(currentAvatar) {
                document.getElementById('profileAvatarPreview').src = currentAvatar;
            }

            fetch(`/api/get_user_info?username=${encodeURIComponent(currentUser)}`).then(res => res.json()).then(data => {
                if(data.success && data.avatar) {
                    document.getElementById('profileAvatarPreview').src = data.avatar;
                    localStorage.setItem('songdb_avatar', data.avatar);
                }
            });
        });

        function saveAvatarFile() {
            let currentUser = localStorage.getItem('songdb_user');
            let fileInput = document.getElementById('avatarFileInput');
            if(fileInput.files.length === 0) {
                alert('Please select an image file first');
                return;
            }

            let formData = new FormData();
            formData.append('username', currentUser);
            formData.append('avatar_file', fileInput.files[0]);

            fetch('/api/update_avatar_file', {
                method: 'POST',
                body: formData
            }).then(res => res.json()).then(data => {
                if(data.success) {
                    localStorage.setItem('songdb_avatar', data.avatar);
                    alert('Avatar uploaded and updated successfully!');
                    window.location.href = '/';
                } else {
                    alert(data.message || 'Error uploading avatar');
                }
            });
        }
    </script>
</body>
</html>"""
)

song_detail_template = (
    """<!DOCTYPE html>
<html lang="en" class="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{ song.title }} - Musicy</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    """
    + background_styles
    + """
</head>
<body class="text-gray-100 font-sans antialiased min-h-screen flex flex-col">
    <header class="border-b border-[#1db954]/30 bg-[#020403]/90 backdrop-blur-2xl sticky top-0 z-50 h-16 flex items-center px-4 md:px-8 justify-between shadow-[0_4px_30px_rgba(0,0,0,0.8)]">
        <div class="flex items-center space-x-12 w-full"><a href="/" class="flex items-center space-x-2 text-[#1db954] font-bold text-xl tracking-wider"><i class="fa-solid fa-music text-[#1db954]"></i><span class="tracking-widest" data-i18n="brandName">Musicy</span></a></div>
        <div class="flex items-center space-x-4 text-xs font-medium text-gray-300">
            """
    + lang_switcher_html
    + """
            <a href="/" class="flex items-center space-x-1.5 text-[#1db954] hover:text-white transition"><i class="fa-solid fa-house"></i> <span data-i18n="home">Home</span></a>
        </div>
    </header>
    <main class="flex-1 p-6 md:p-10 space-y-10 max-w-5xl mx-auto w-full">
        <div class="bg-gradient-to-r from-[#081a10] via-[#040e08] to-[#020403] border border-[#1db954]/50 rounded-3xl p-6 md:p-10 flex flex-col md:flex-row items-center gap-8 shadow-[0_20px_50px_rgba(0,0,0,0.8)] backdrop-blur-2xl neon-border">
            <div class="relative shrink-0 group">
                <img id="songCoverImg" src="{{ song.img }}" crossorigin="anonymous" class="w-52 h-52 md:w-60 md:h-60 object-cover rounded-2xl shadow-2xl border border-[#1db954]/50 group-hover:scale-105 transition duration-700">
                <div class="absolute inset-0 bg-[#1db954]/20 rounded-2xl filter blur-xl opacity-0 group-hover:opacity-100 transition duration-700 -z-10"></div>
            </div>
            <div class="flex-1 space-y-4 text-center md:text-left w-full">
                <div>
                    <h1 class="text-3xl md:text-4xl font-extrabold text-white">{{ song.title }}</h1>
                    <p class="text-lg text-gray-300 font-medium">{{ song.artist }}</p>
                    <p class="text-xs text-gray-400 mt-1">{{ song.release_year }} &bull; {{ song.genre }}</p>
                </div>
                <div class="flex items-center justify-center md:justify-start space-x-3">
                    <div class="flex text-[#1db954] text-sm"><i class="fa-solid fa-star"></i></div>
                    <span class="text-xl font-bold text-white">{{ song.rating }} <span class="text-xs text-gray-400 font-normal">/5</span></span>
                    <span class="text-xs text-gray-400">({{ song.votes }} <span data-i18n="votesText">votes</span>)</span>
                </div>
                <div class="flex flex-wrap items-center justify-center md:justify-start gap-4 pt-2">
                    <button id="mainRateBtn" onclick="openRateModal()" class="bg-gradient-to-r from-[#1db954] to-[#1ed760] hover:opacity-95 text-gray-950 font-bold px-7 py-3.5 rounded-2xl text-xs flex items-center space-x-2 transition shadow-[0_0_20px_rgba(29,185,84,0.4)] hover:scale-105 transform duration-300">
                        <i class="fa-solid fa-star"></i>
                        <span id="mainRateBtnText" data-i18n="rateSongBtn">Rate This Song</span>
                    </button>
                    <a href="https://open.spotify.com/track/{{ song.spotify_id }}" target="_blank" class="bg-[#050b07] border border-[#1db954]/50 hover:bg-[#1db954]/25 text-[#1db954] font-bold px-7 py-3.5 rounded-2xl text-xs flex items-center space-x-2 transition shadow-lg hover:scale-105 transform duration-300">
                        <i class="fa-brands fa-spotify text-sm"></i>
                        <span data-i18n="listenSpotify">Listen on Spotify</span>
                    </a>
                </div>
            </div>
        </div>

        <div class="grid grid-cols-1 lg:grid-cols-3 gap-8">
            <div class="lg:col-span-2 space-y-6">
                <div class="flex items-center justify-between"><h3 class="text-base font-bold text-white" data-i18n="reviewsTitle">Reviews & Ratings</h3><button id="secRateBtn" onclick="openRateModal()" class="bg-[#050b07] hover:bg-[#1db954]/25 text-[#1db954] font-bold px-4 py-2.5 rounded-2xl text-xs border border-[#1db954]/40 transition shadow" data-i18n="writeReviewBtn">Write Review</button></div>
                {% if reviews %}
                    <div class="space-y-4">
                        {% for rev in reviews %}
                        <div class="glass-card rounded-2xl p-5 space-y-3" data-username="{{ rev.username }}">
                            <div class="flex items-center justify-between">
                                <div class="flex items-center space-x-3">
                                    <img src="{{ rev.avatar }}" class="w-10 h-10 rounded-full object-cover border border-[#1db954]/60 shadow-md">
                                    <div>
                                        <h4 class="font-bold text-xs text-white">{{ rev.username }}</h4>
                                        <span class="text-[10px] text-gray-500 time-ago-el" data-timestamp="{{ rev.timestamp }}"></span>
                                    </div>
                                </div>
                                <div class="flex items-center space-x-1 text-[#1db954] text-xs font-bold"><i class="fa-solid fa-star text-[10px]"></i><span>{{ rev.rating }}/5</span></div>
                            </div>
                            <p class="text-xs text-gray-300 leading-relaxed font-light">{{ rev.comment }}</p>
                            <div class="flex items-center justify-between pt-2 border-t border-[#1db954]/20 text-xs">
                                <button onclick="likeReview({{ rev.id }}, this)" class="flex items-center space-x-2 text-gray-400 hover:text-[#1db954] transition bg-[#050b07] px-3.5 py-2 rounded-xl border border-[#1db954]/30 shadow">
                                    <i class="fa-solid fa-heart text-gray-500 like-icon-{{ rev.id }}"></i>
                                    <span>Like</span>
                                    <span class="font-bold text-white ml-1 like-count-{{ rev.id }}">{{ rev.likes }}</span>
                                </button>
                            </div>
                        </div>
                        {% endfor %}
                    </div>
                {% else %}
                    <div class="glass-card rounded-2xl p-8 text-center text-gray-400 text-xs" data-i18n="noReviews">No reviews yet. Be the first to review this song!</div>
                {% endif %}
            </div>
            <div class="glass-card rounded-2xl p-6 space-y-4 h-fit">
                <h4 class="font-bold text-xs text-white uppercase tracking-wider" data-i18n="ratingDetails">Rating Details</h4>
                <div class="space-y-3 text-xs text-gray-400">
                    <div class="flex items-center justify-between"><span data-i18n="overallRating">Overall Rating</span><span class="text-[#1db954] font-bold">{{ song.rating }} / 5</span></div>
                    <div class="flex items-center justify-between"><span data-i18n="totalVotes">Total Votes</span><span class="text-white font-bold">{{ song.votes }}</span></div>
                </div>
            </div>
        </div>
    </main>

    <!-- Modal Rate -->
    <div id="rateModal" class="fixed inset-0 bg-black/90 flex items-center justify-center hidden z-50 p-4 backdrop-blur-xl">
        <div class="glass-card border border-[#1db954]/60 rounded-3xl p-8 w-full max-w-md space-y-6 shadow-2xl animate-in fade-in zoom-in duration-300">
            <h3 class="text-base font-bold text-white"><span data-i18n="rateModalTitle">Rate</span> "{{ song.title }}"</h3>
            <div class="space-y-4 text-xs">
                <div>
                    <label class="text-gray-400 block mb-2.5 font-medium" data-i18n="ratingScoreLabel">اختر النجوم (من 1 إلى 5):</label>
                    <div class="flex items-center space-x-3 text-3xl text-gray-600 cursor-pointer" id="starContainer">
                        <i class="fa-solid fa-star hover:text-[#1db954] transition transform hover:scale-125" onclick="setStarRating(1)" data-value="1"></i>
                        <i class="fa-solid fa-star hover:text-[#1db954] transition transform hover:scale-125" onclick="setStarRating(2)" data-value="2"></i>
                        <i class="fa-solid fa-star hover:text-[#1db954] transition transform hover:scale-125" onclick="setStarRating(3)" data-value="3"></i>
                        <i class="fa-solid fa-star hover:text-[#1db954] transition transform hover:scale-125" onclick="setStarRating(4)" data-value="4"></i>
                        <i class="fa-solid fa-star hover:text-[#1db954] transition transform hover:scale-125" onclick="setStarRating(5)" data-value="5"></i>
                        <span id="starValueText" class="text-sm font-extrabold text-[#1db954] ml-3">5/5</span>
                    </div>
                    <input type="hidden" id="hiddenRating" value="5">
                </div>
                <div><label class="text-gray-400 block mb-2 font-medium" data-i18n="commentLabel">Your Review / Comment:</label><textarea id="commentInput" rows="3" placeholder="This song is amazing..." class="w-full bg-[#050b07] text-gray-200 p-3.5 rounded-2xl border border-[#1db954]/40 focus:outline-none focus:border-[#1db954] focus:ring-4 focus:ring-[#1db954]/30 shadow-inner"></textarea></div>
            </div>
            <div class="flex space-x-3 pt-2">
                <button onclick="submitRating()" class="flex-1 bg-gradient-to-r from-[#1db954] to-[#1ed760] hover:opacity-95 text-gray-950 font-bold py-3.5 rounded-2xl text-xs transition shadow-[0_0_20px_rgba(29,185,84,0.4)]" data-i18n="submitRatingBtn">Submit Rating & Generate Story</button>
                <button onclick="closeRateModal()" class="flex-1 bg-[#050b07] hover:bg-gray-800 border border-gray-700 text-gray-300 font-semibold py-3.5 rounded-2xl text-xs transition" data-i18n="cancelBtn">Cancel</button>
            </div>
        </div>
    </div>

    <!-- Modal Instagram Story Preview -->
    <div id="storyModal" class="fixed inset-0 bg-black/95 flex items-center justify-center hidden z-50 p-4 backdrop-blur-2xl">
        <div class="glass-card border border-[#1db954]/70 rounded-3xl p-6 w-full max-w-sm space-y-5 shadow-2xl text-center">
            <h3 class="text-sm font-bold text-white" data-i18n="storyModalTitle">معاينة ستوري انستقرام الخارقة الفخامة</h3>
            <div class="relative flex justify-center">
                <canvas id="storyCanvas" width="1080" height="1920" class="w-full max-h-[450px] object-contain rounded-2xl border border-[#1db954]/40 shadow-2xl"></canvas>
            </div>
            <div class="space-y-2.5">
                <button onclick="downloadStory()" class="w-full bg-gradient-to-r from-[#1db954] to-[#1ed760] hover:opacity-95 text-gray-950 font-bold py-3.5 rounded-2xl text-xs transition shadow-[0_0_20px_rgba(29,185,84,0.5)] flex items-center justify-center space-x-2">
                    <i class="fa-solid fa-download"></i>
                    <span data-i18n="downloadStoryBtn">تحميل ستوري الفخامة</span>
                </button>
                <button onclick="closeStoryModal()" class="w-full bg-[#050b07] hover:bg-gray-800 border border-gray-700 text-gray-300 font-semibold py-3 rounded-2xl text-xs transition" data-i18n="closeStoryBtn">إغلاق ومتابعة</button>
            </div>
        </div>
    </div>

    <script>
        let currentRatingVal = 5;
        let userHasReviewed = false;
        let userExistingComment = "";
        let lastRatedData = null;

        document.addEventListener('DOMContentLoaded', () => {
            let savedLang = localStorage.getItem('musicy_lang') || 'en';
            setLanguage(savedLang);
            checkUserReviewStatus();
            updateAllTimes();
            setInterval(updateAllTimes, 60000);
        });

        function timeAgo(timestamp, lang) {
            const now = Date.now() / 1000;
            const elapsed = Math.floor(now - timestamp);

            if (lang === 'ar') {
                if (elapsed < 60) return 'الآن';
                let minutes = Math.floor(elapsed / 60);
                if (minutes < 60) return `منذ ${minutes} دقيقة`;
                let hours = Math.floor(minutes / 60);
                if (hours < 24) return `منذ ${hours} ساعة`;
                let days = Math.floor(hours / 24);
                if (days < 30) return `منذ ${days} يوم`;
                let months = Math.floor(days / 30);
                if (months < 12) return `منذ ${months} شهر`;
                let years = Math.floor(months / 12);
                return `منذ ${years} سنة`;
            } else {
                if (elapsed < 60) return 'Just now';
                let minutes = Math.floor(elapsed / 60);
                if (minutes === 1) return '1 minute ago';
                if (minutes < 60) return `${minutes} minutes ago`;
                let hours = Math.floor(minutes / 60);
                if (hours === 1) return '1 hour ago';
                if (hours < 24) return `${hours} hours ago`;
                let days = Math.floor(hours / 24);
                if (days === 1) return '1 day ago';
                if (days < 30) return `${days} days ago`;
                let months = Math.floor(days / 30);
                if (months === 1) return '1 month ago';
                if (months < 12) return `${months} months ago`;
                let years = Math.floor(months / 12);
                if (years === 1) return '1 year ago';
                return `${years} years ago`;
            }
        }

        function updateAllTimes() {
            let lang = localStorage.getItem('musicy_lang') || 'en';
            document.querySelectorAll('.time-ago-el').forEach(el => {
                let ts = parseFloat(el.getAttribute('data-timestamp'));
                if (!isNaN(ts)) {
                    el.innerText = timeAgo(ts, lang);
                }
            });
        }

        function checkUserReviewStatus() {
            let currentUser = localStorage.getItem('songdb_user');
            if(!currentUser) return;
            
            const reviewCards = document.querySelectorAll('[data-username]');
            reviewCards.forEach(card => {
                if(card.getAttribute('data-username') === currentUser) {
                    userHasReviewed = true;
                    let commentTextEl = card.querySelector('p');
                    if(commentTextEl) userExistingComment = commentTextEl.innerText;
                    
                    let mainText = document.getElementById('mainRateBtnText');
                    let secBtn = document.getElementById('secRateBtn');
                    let editLabel = (localStorage.getItem('musicy_lang') === 'ar') ? 'تعديل تقييمك ورأيك' : 'Edit Your Review';
                    if(mainText) mainText.innerText = editLabel;
                    if(secBtn) secBtn.innerText = editLabel;
                }
            });
        }

        function setStarRating(val) {
            currentRatingVal = val;
            document.getElementById('hiddenRating').value = val;
            document.getElementById('starValueText').innerText = val + '/5';
            
            let stars = document.querySelectorAll('#starContainer i');
            stars.forEach((star, index) => {
                if(index < val) {
                    star.classList.add('text-[#1db954]', 'drop-shadow-[0_0_10px_#1db954]');
                    star.classList.remove('text-gray-600');
                } else {
                    star.classList.remove('text-[#1db954]', 'drop-shadow-[0_0_10px_#1db954]');
                    star.classList.add('text-gray-600');
                }
            });
        }

        function openRateModal() {
            let currentUser = localStorage.getItem('songdb_user');
            if (!currentUser) { 
                alert('Please login first to rate songs!'); 
                window.location.href = '/login'; 
                return; 
            }
            if(userHasReviewed && userExistingComment) {
                document.getElementById('commentInput').value = userExistingComment;
            }
            setStarRating(currentRatingVal);
            document.getElementById('rateModal').classList.remove('hidden');
        }

        function closeRateModal() { document.getElementById('rateModal').classList.add('hidden'); }
        function closeStoryModal() { document.getElementById('storyModal').classList.add('hidden'); location.reload(); }

        function submitRating() {
            let currentUser = localStorage.getItem('songdb_user');
            if (!currentUser) {
                alert('Please login first!');
                window.location.href = '/login';
                return;
            }
            let rating = parseFloat(document.getElementById('hiddenRating').value);
            let comment = document.getElementById('commentInput').value;
            if (isNaN(rating) || rating < 1 || rating > 5) { alert('Please select a rating between 1 and 5 stars.'); return; }
            
            fetch('/api/rate', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({ spotify_id: '{{ song.spotify_id }}', rating: rating, username: currentUser, comment: comment })
            }).then(res => res.json()).then(resp => {
                if (resp.success) {
                    closeRateModal();
                    let currentAvatar = localStorage.getItem('songdb_avatar') || resp.avatar;
                    lastRatedData = {
                        username: currentUser,
                        avatar: currentAvatar,
                        rating: rating,
                        comment: comment,
                        title: '{{ song.title }}',
                        artist: '{{ song.artist }}',
                        img: '{{ song.img }}'
                    };
                    generateInstagramStory(lastRatedData);
                    document.getElementById('storyModal').classList.remove('hidden');
                } else {
                    alert(resp.message || 'Error submitting rating.');
                }
            });
        }

        function generateInstagramStory(data) {
            const canvas = document.getElementById('storyCanvas');
            const ctx = canvas.getContext('2d');
            
            const bgGrad = ctx.createLinearGradient(0, 0, 0, 1920);
            bgGrad.addColorStop(0, '#010502');
            bgGrad.addColorStop(0.3, '#040d07');
            bgGrad.addColorStop(1, '#000000');
            ctx.fillStyle = bgGrad;
            ctx.fillRect(0, 0, 1080, 1920);

            ctx.save();
            ctx.shadowColor = 'rgba(29, 185, 84, 0.4)';
            ctx.shadowBlur = 80;
            ctx.fillStyle = 'rgba(10, 20, 14, 0.9)';
            ctx.beginPath();
            ctx.roundRect(80, 120, 920, 1680, 60);
            ctx.fill();
            ctx.strokeStyle = 'rgba(29, 185, 84, 0.5)';
            ctx.lineWidth = 4;
            ctx.stroke();
            ctx.restore();

            ctx.fillStyle = '#1db954';
            ctx.font = 'bold 36px sans-serif';
            ctx.textAlign = 'center';
            ctx.fillText('MUSICY REVIEW & RATING', 540, 220);

            const img = new Image();
            img.crossOrigin = 'anonymous';
            img.src = data.img;
            img.onload = function() {
                ctx.save();
                ctx.shadowColor = 'rgba(0,0,0,0.8)';
                ctx.shadowBlur = 50;
                ctx.shadowOffsetY = 25;
                ctx.beginPath();
                ctx.roundRect(190, 280, 700, 700, 40);
                ctx.closePath();
                ctx.clip();
                ctx.drawImage(img, 190, 280, 700, 700);
                ctx.restore();

                ctx.save();
                ctx.strokeStyle = 'rgba(29, 185, 84, 0.6)';
                ctx.lineWidth = 6;
                ctx.beginPath();
                ctx.roundRect(190, 280, 700, 700, 40);
                ctx.stroke();
                ctx.restore();

                ctx.fillStyle = '#ffffff';
                ctx.font = 'bold 52px sans-serif';
                ctx.textAlign = 'center';
                ctx.fillText(data.title, 540, 1060, 850);

                ctx.fillStyle = '#9ca3af';
                ctx.font = '36px sans-serif';
                ctx.fillText(data.artist, 540, 1130, 850);

                let starStr = '★'.repeat(data.rating) + '☆'.repeat(5 - Math.floor(data.rating));
                ctx.fillStyle = '#1db954';
                ctx.font = 'bold 50px sans-serif';
                ctx.fillText(starStr + ` (${data.rating}/5)`, 540, 1240);

                if(data.comment) {
                    ctx.fillStyle = '#d1d5db';
                    ctx.font = 'italic 34px sans-serif';
                    wrapText(ctx, `"${data.comment}"`, 540, 1340, 800, 50);
                }

                ctx.fillStyle = '#1db954';
                ctx.font = 'bold 28px sans-serif';
                ctx.fillText(`Reviewed by @${data.username} on Musicy`, 540, 1680);
            };
        }

        function wrapText(context, text, x, y, maxWidth, lineHeight) {
            let words = text.split(' ');
            let line = '';
            for(let n = 0; n < words.length; n++) {
                let testLine = line + words[n] + ' ';
                let metrics = context.measureText(testLine);
                let testWidth = metrics.width;
                if (testWidth > maxWidth && n > 0) {
                    context.fillText(line, x, y);
                    line = words[n] + ' ';
                    y += lineHeight;
                } else {
                    line = testLine;
                }
            }
            context.fillText(line, x, y);
        }

        function downloadStory() {
            const canvas = document.getElementById('storyCanvas');
            let link = document.createElement('a');
            link.download = 'Musicy_Story.png';
            link.href = canvas.toDataURL('image/png');
            link.click();
        }

        function likeReview(reviewId, btn) {
            let currentUser = localStorage.getItem('songdb_user');
            if(!currentUser) { alert('Please login first to like reviews!'); window.location.href = '/login'; return; }
            fetch('/api/like_review', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({ review_id: reviewId, username: currentUser })
            }).then(res => res.json()).then(resp => {
                if(resp.success) {
                    let countEl = document.querySelector(`.like-count-${reviewId}`);
                    let iconEl = document.querySelector(`.like-icon-${reviewId}`);
                    if(countEl) countEl.innerText = resp.likes;
                    if(iconEl) {
                        if(resp.liked) {
                            iconEl.classList.remove('text-gray-500');
                            iconEl.classList.add('text-red-500');
                        } else {
                            iconEl.classList.remove('text-red-500');
                            iconEl.classList.add('text-gray-500');
                        }
                    }
                } else {
                    alert(resp.message || 'Error liking review');
                }
            });
        }
    </script>
</body>
</html>
"""
)

if __name__ == '__main__':
  socketio.run(app, debug=True)
[cite: 1]
