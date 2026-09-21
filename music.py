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
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

# قراءة الرابط من Render أو استخدام SQLite محلياً للتجربة
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


@app.route('/api/check_likes', methods=['POST'])
def check_likes():
  data = request.json
  if not data:
    return jsonify({})
  username = data.get('username')
  review_ids = data.get('review_ids', [])
  liked_dict = {}
  if username:
    for rid in review_ids:
      chk = ReviewLike.query.filter_by(review_id=rid, username=username).first()
      if chk:
        liked_dict[rid] = True
  return jsonify(liked_dict)


background_styles = """
<style>
    /* ==========================================================
       MUSICY — design system (Modified to Dynamic Album Color Theme)
       --theme-color is rewritten dynamically by the song page from the cover art,
       so every accent below re-tints itself per album (e.g. blue for Billie Eilish).
       ========================================================== */
    :root {
        --theme-color: 16, 185, 129;
        --theme-color-dark: 5, 150, 105;

        --bg: #030712;
        --bg-2: #0b0f19;
        --bg-3: #111827;
        --text: #f9fafb;
        --muted: #9ca3af;
        --faint: #6b7280;
        --line: rgba(16, 185, 129, 0.15);
        --line-strong: rgba(16, 185, 129, 0.3);
        --track: rgba(16, 185, 129, 0.2);
        --scrim: rgba(3, 7, 18, 0.85);
        --accent: rgb(var(--theme-color));
        --accent-ink: rgb(var(--theme-color));

        --display: "Bodoni Moda", "Amiri", "Iowan Old Style", "Palatino Linotype", Georgia, serif;
        --sans: "Hanken Grotesk", "IBM Plex Sans Arabic", "Segoe UI", system-ui, -apple-system, sans-serif;
        --gutter: clamp(20px, 4.5vw, 64px);
        --max: 1240px;
        --dir: 1;
        --ease: cubic-bezier(0.2, 0.7, 0.2, 1);
    }
    [dir="rtl"] { --dir: -1; }

    body.light-mode {
        --bg: #f0fdf4;
        --bg-2: #dcfce7;
        --bg-3: #bbf7d0;
        --text: #022c22;
        --muted: #047857;
        --faint: #065f46;
        --line: rgba(16, 185, 129, 0.2);
        --line-strong: rgba(16, 185, 129, 0.4);
        --track: rgba(16, 185, 129, 0.25);
        --scrim: rgba(2, 44, 34, 0.6);
        --accent-ink: rgb(var(--theme-color-dark));
    }
    @supports (color: color-mix(in srgb, red 50%, white)) {
        :root { --accent-ink: color-mix(in srgb, rgb(var(--theme-color)) 74%, #ffffff); }
        body.light-mode { --accent-ink: color-mix(in srgb, rgb(var(--theme-color)) 50%, #000000); }
    }

    /* ---------- base ---------- */
    *, *::before, *::after { box-sizing: border-box; }
    html {
        scroll-behavior: smooth;
        -webkit-text-size-adjust: 100%;
        scrollbar-width: thin;
        scrollbar-color: rgba(var(--theme-color), 0.45) transparent;
    }
    body.musicy {
        margin: 0;
        min-height: 100vh;
        min-height: 100dvh;
        display: flex;
        flex-direction: column;
        background: var(--bg);
        color: var(--text);
        font-family: var(--sans);
        font-size: 16px;
        font-weight: 400;
        line-height: 1.65;
        -webkit-font-smoothing: antialiased;
        text-rendering: optimizeLegibility;
        overflow-x: clip;
        transition: background-color 0.5s ease, color 0.5s ease;
    }
    html[lang="ar"] body.musicy { line-height: 1.85; }
    [dir="rtl"] body.musicy * { letter-spacing: normal !important; }
    body.musicy ::selection { background: rgba(var(--theme-color), 0.38); color: var(--text); }
    body.musicy :focus-visible { outline: 2px solid var(--accent-ink); outline-offset: 3px; }
    :where(body.musicy) a { color: inherit; text-decoration: none; }
    :where(body.musicy) img { display: block; }
    body.musicy .search-input:focus-visible, body.musicy .input:focus-visible, body.musicy .textarea:focus-visible { outline: none; }
    .hidden { display: none !important; }
    ::-webkit-scrollbar { width: 8px; height: 8px; }
    ::-webkit-scrollbar-track { background: transparent; }
    ::-webkit-scrollbar-thumb { background: rgba(var(--theme-color), 0.4); border-radius: 8px; border: 2px solid transparent; background-clip: content-box; }
    ::-webkit-scrollbar-thumb:hover { background: rgba(var(--theme-color), 0.7); background-clip: content-box; }

    /* ---------- ambient theme (canvas + grain + musical background animations) ---------- */
    #ambientCanvas { position: fixed; inset: 0; width: 100%; height: 100%; z-index: -2; pointer-events: none; }
    .grain {
        position: fixed; inset: 0; z-index: -1; pointer-events: none; opacity: 0.07;
        background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='180' height='180'%3E%3Cfilter id='n'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='.85' numOctaves='2' stitchTiles='stitch'/%3E%3CfeColorMatrix type='saturate' values='0'/%3E%3C/filter%3E%3Crect width='100%25' height='100%25' filter='url(%23n)'/%3E%3C/svg%3E");
    }
    body.light-mode .grain { opacity: 0.09; mix-blend-mode: multiply; }

    /* Floating Musical Background Elements */
    .musical-bg-container {
        position: fixed; inset: 0; width: 100%; height: 100%; z-index: -3; pointer-events: none; overflow: hidden;
    }
    .musical-note {
        position: absolute;
        color: rgba(var(--theme-color), 0.25);
        animation: floatNote linear infinite;
        user-select: none;
        will-change: transform;
    }
    @keyframes floatNote {
        0% { transform: translateY(110vh) rotate(0deg) scale(0.8); opacity: 0; }
        20% { opacity: 0.6; }
        80% { opacity: 0.6; }
        100% { transform: translateY(-15vh) rotate(360deg) scale(1.2); opacity: 0; }
    }

    /* ---------- typography helpers ---------- */
    .display { font-family: var(--display); font-weight: 500; font-optical-sizing: auto; }
    [dir="rtl"] .display { line-height: 1.3 !important; }
    .h2 { font-family: var(--display); font-weight: 500; font-size: clamp(1.5rem, 2.6vw, 2.1rem); line-height: 1.15; margin: 0; }
    .h3 { font-family: var(--display); font-weight: 500; font-size: clamp(1.35rem, 2.2vw, 1.8rem); line-height: 1.2; margin: 0; }
    .count { font-family: var(--sans); font-size: 14px; font-weight: 400; color: var(--faint); margin-inline-start: 0.5em; }
    .lede { margin: 12px 0 0; color: var(--muted); max-width: 52ch; }
    .sep { display: inline-block; width: 1px; height: 12px; background: var(--line-strong); flex-shrink: 0; }

    /* ---------- header ---------- */
    .top {
        position: sticky; top: 0; z-index: 40;
        border-bottom: 1px solid var(--line);
        background: rgba(3, 7, 18, 0.85);
        -webkit-backdrop-filter: blur(18px) saturate(1.15);
        backdrop-filter: blur(18px) saturate(1.15);
    }
    body.light-mode .top { background: rgba(240, 253, 244, 0.85); }
    @supports (color: color-mix(in srgb, red 50%, white)) {
        .top, body.light-mode .top { background: color-mix(in srgb, var(--bg) 74%, transparent); }
    }
    .top-inner {
        width: min(100% - 2 * var(--gutter), var(--max));
        margin-inline: auto;
        min-height: 72px;
        display: grid;
        grid-template-columns: auto minmax(0, 1fr) auto;
        align-items: center;
        column-gap: 28px;
    }
    .top-left { grid-column: 1; grid-row: 1; display: flex; align-items: center; gap: 36px; }
    .search { grid-column: 2; grid-row: 1; justify-self: center; width: 100%; max-width: 460px; position: relative; }
    .top-tools { grid-column: 3; grid-row: 1; justify-self: end; display: flex; align-items: center; gap: 12px; }

    .brand { display: inline-flex; align-items: center; gap: 11px; flex-shrink: 0; color: var(--text); }
    .brand-mark { width: 27px; height: 27px; color: var(--text); flex-shrink: 0; }
    .brand-mark .ring-b { opacity: 0.45; }
    .brand-mark .core { fill: rgb(var(--theme-color)); transition: fill 0.9s ease; }
    .brand-mark .hole { fill: var(--bg); }
    .brand-name { font-family: var(--display); font-style: italic; font-weight: 500; font-size: 27px; line-height: 1; letter-spacing: -0.01em; }

    .top-nav { display: none; align-items: center; gap: 28px; }
    .top-nav a { position: relative; font-size: 14px; color: var(--muted); padding: 6px 0; transition: color 0.25s; }
    .top-nav a:hover, .top-nav a.is-active { color: var(--text); }
    .top-nav a.is-active::after { content: ""; position: absolute; inset-inline: 0; bottom: -1px; height: 1px; background: var(--accent-ink); }

    .search-ico { position: absolute; inset-inline-start: 17px; top: 50%; transform: translateY(-50%); font-size: 13px; color: var(--faint); pointer-events: none; }
    .search-input {
        width: 100%; height: 44px; padding-inline: 44px 18px;
        border: 1px solid var(--line-strong); border-radius: 999px;
        background: transparent; color: var(--text);
        font-family: var(--sans); font-size: 14px;
        transition: border-color 0.25s, background-color 0.25s;
    }
    .search-input::placeholder { color: var(--faint); opacity: 1; }
    .search-input:hover { border-color: var(--faint); }
    .search-input:focus { outline: none; border-color: var(--accent-ink); background: var(--bg-2); }
    .results {
        position: absolute; inset-inline: 0; top: calc(100% + 10px); z-index: 60;
        max-height: 360px; overflow-y: auto;
        background: var(--bg-2); border: 1px solid var(--line-strong); border-radius: 4px;
        box-shadow: 0 40px 80px -30px rgba(0, 0, 0, 0.7);
    }

    .tools { display: flex; align-items: center; gap: 10px; }
    .lang { display: inline-flex; padding: 3px; border: 1px solid var(--line); border-radius: 999px; }
    .lang-btn {
        border: 0; background: transparent; min-width: 44px; height: 30px; padding: 0 12px; border-radius: 999px;
        font-family: var(--sans); font-size: 12px; font-weight: 500; line-height: 1;
        color: var(--faint); cursor: pointer; transition: background-color 0.25s, color 0.25s;
    }
    .lang-btn:hover { color: var(--text); }
    html[lang="en"] .lang-btn[data-l="en"], html[lang="ar"] .lang-btn[data-l="ar"] { background: var(--text); color: var(--bg); }
    .mode-btn {
        display: inline-flex; align-items: center; gap: 9px; height: 38px; padding: 0 13px;
        border: 1px solid var(--line); border-radius: 999px; background: transparent;
        color: var(--muted); font-family: var(--sans); font-size: 13px; cursor: pointer;
        transition: border-color 0.25s, color 0.25s;
    }
    .mode-btn:hover { border-color: var(--line-strong); color: var(--text); }
    .mode-btn i { color: var(--accent-ink) !important; font-size: 13px; }
    .mode-btn span { display: none; }
    .mode-btn { width: 38px; padding: 0; justify-content: center; }
    .icon-link { display: none; width: 38px; height: 38px; align-items: center; justify-content: center; border: 1px solid var(--line); border-radius: 50%; color: var(--accent-ink); font-size: 13px; transition: border-color 0.25s; }
    .icon-link:hover { border-color: var(--line-strong); }

    #userProfileArea { display: flex; align-items: center; }
    #userProfileArea > div { display: flex; align-items: center; gap: 10px; }
    #userProfileArea * { margin: 0; }
    #userProfileArea a[href="/login"] {
        width: 38px; height: 38px; display: flex; align-items: center; justify-content: center;
        border: 1px solid var(--line-strong); border-radius: 50%; background: transparent; background-image: none;
        color: var(--text); box-shadow: none; transform: none; font-size: 13px;
        transition: border-color 0.25s, color 0.25s;
    }
    #userProfileArea a[href="/login"]:hover { border-color: var(--accent-ink); color: var(--accent-ink); transform: none; }
    #userProfileArea a[href="/login"] i { color: inherit; }
    #userProfileArea a[href="/profile"] {
        display: flex; align-items: center; gap: 9px; height: 38px; padding: 4px 14px 4px 4px;
        border: 1px solid var(--line-strong); border-radius: 999px; background: transparent; box-shadow: none; opacity: 1;
        transition: border-color 0.25s;
    }
    [dir="rtl"] #userProfileArea a[href="/profile"] { padding: 4px 4px 4px 14px; }
    #userProfileArea a[href="/profile"]:hover { border-color: var(--accent-ink); opacity: 1; }
    #userProfileArea a[href="/profile"] img { width: 30px; height: 30px; border-radius: 50%; object-fit: cover; border: 0; }
    #userProfileArea a[href="/profile"] span { color: var(--text); font-size: 13px; font-weight: 500; max-width: 110px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    #userProfileArea button {
        width: 38px; height: 38px; display: flex; align-items: center; justify-content: center;
        border: 1px solid var(--line); border-radius: 50%; background: transparent; box-shadow: none; color: var(--muted);
        transition: border-color 0.25s, color 0.25s;
    }
    #userProfileArea button:hover { border-color: rgba(214, 84, 108, 0.7); color: #d6546c; }

    /* search dropdown rows are built by the page script, so they're styled by structure */
    #searchResults > div { display: flex; align-items: center; gap: 14px; padding: 10px 14px; border-bottom: 1px solid var(--line); cursor: pointer; background: transparent; transition: background-color 0.2s; }
    #searchResults > div:last-child { border-bottom: 0; }
    #searchResults > div:hover { background: var(--bg-3); }
    #searchResults > div > * { margin: 0; }
    #searchResults img { width: 44px; height: 44px; flex-shrink: 0; object-fit: cover; border: 0; border-radius: 2px; }
    #searchResults .font-bold { font-family: var(--display); font-size: 15px; font-weight: 500; line-height: 1.3; color: var(--text); }
    #searchResults .text-gray-400 { font-size: 12.5px; color: var(--muted); }

    /* ---------- buttons ---------- */
    .btn {
        display: inline-flex; align-items: center; justify-content: center; gap: 10px;
        height: 48px; padding: 0 26px; border: 1px solid transparent; border-radius: 2px;
        font-family: var(--sans); font-size: 14px; font-weight: 500; line-height: 1; letter-spacing: 0.02em;
        cursor: pointer; white-space: nowrap;
        transition: background-color 0.3s, color 0.3s, border-color 0.3s, transform 0.2s;
    }
    .btn:active { transform: translateY(1px); }
    .btn i { font-size: 13px; }
    .btn-primary { background: var(--text); color: var(--bg); border-color: var(--text); }
    .btn-primary:hover { background: var(--accent-ink); }
    .btn-ghost { border-color: var(--line-strong); color: var(--text); background: transparent; }
    .btn-primary:hover { border-color: var(--accent-ink); }
    .btn-ghost:hover { border-color: var(--accent-ink); color: var(--accent-ink); }
    .btn-sm { height: 38px; padding: 0 18px; font-size: 13px; }
    .btn-block { width: 100%; }

    /* ---------- stars (fractional, driven by --r) ---------- */
    .stars {
        --r: 0;
        display: inline-block; flex-shrink: 0;
        width: calc(5 * 1.25em); height: 1em; font-size: 13px; vertical-align: -0.14em;
        background: linear-gradient(90deg, var(--accent-ink) calc(var(--r) / 5 * 100%), var(--track) 0);
        -webkit-mask: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 30 24'%3E%3Cpath transform='translate(3 0)' d='M12 2.2l2.95 6.2 6.85.9-5 4.75 1.25 6.75L12 17.4 5.9 20.8l1.25-6.75-5-4.75 6.85-.9z'/%3E%3C/svg%3E") 0 0 / 1.25em 1em repeat-x;
        mask: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 30 24'%3E%3Cpath transform='translate(3 0)' d='M12 2.2l2.95 6.2 6.85.9-5 4.75 1.25 6.75L12 17.4 5.9 20.8l1.25-6.75-5-4.75 6.85-.9z'/%3E%3C/svg%3E") 0 0 / 1.25em 1em repeat-x;
    }
    .stars.lg { font-size: 20px; }
    [dir="rtl"] .stars { background: linear-gradient(270deg, var(--accent-ink) calc(var(--r) / 5 * 100%), var(--track) 0); }

    /* ---------- sleeve + vinyl (the signature object) ---------- */
    .sleeve { position: relative; aspect-ratio: 1; }
    .sleeve .cover {
        position: absolute; inset: 0; z-index: 2; width: 100%; height: 100%; object-fit: cover; border-radius: 2px;
        background: var(--bg-3);
        box-shadow: 0 40px 70px -34px rgba(0, 0, 0, 0.85), 0 0 0 1px rgba(var(--theme-color), 0.15);
    }
    body.light-mode .sleeve .cover { box-shadow: 0 34px 60px -30px rgba(var(--theme-color), 0.25), 0 0 0 1px rgba(var(--theme-color), 0.15); }
    .vinyl-wrap {
        position: absolute; z-index: 1; top: 4%; inset-inline-start: 2%; width: 92%; aspect-ratio: 1;
        transform: translateX(calc(var(--dir) * 30%));
        transition: transform 1.1s var(--ease);
        animation: slideOut 1.6s 0.7s var(--ease) backwards;
    }
    .vinyl-wrap::after {
        content: ""; position: absolute; inset: 0; border-radius: 50%; pointer-events: none;
        background: conic-gradient(from 35deg, transparent 0 8%, rgba(255, 255, 255, 0.11) 14%, transparent 22% 50%, rgba(255, 255, 255, 0.08) 64%, transparent 72%);
    }
    .vinyl {
        position: absolute; inset: 0; border-radius: 50%;
        background: repeating-radial-gradient(circle at 50% 50%, #030712 0 1px, #0b0f19 1px 2px);
        box-shadow: 0 24px 40px -22px rgba(0, 0, 0, 0.8), inset 0 0 0 2px #020408;
        animation: spin 30s linear infinite;
    }
    .vinyl::before {
        content: ""; position: absolute; inset: 33%; border-radius: 50%;
        background: conic-gradient(from 0deg, rgb(var(--theme-color)) 0 64%, rgba(var(--theme-color-dark), 1) 64% 100%);
        box-shadow: inset 0 0 0 1px rgba(0, 0, 0, 0.35);
    }
    .vinyl::after { content: ""; position: absolute; inset: 48.4%; border-radius: 50%; background: #030712; }
    .spotlight:hover .vinyl-wrap, .track-art:hover .vinyl-wrap { transform: translateX(calc(var(--dir) * 40%)); }
    @keyframes slideOut { from { transform: translateX(0); } to { transform: translateX(calc(var(--dir) * 30%)); } }
    @keyframes spin { to { transform: rotate(360deg); } }
    @keyframes rise { from { transform: translateY(105%); } to { transform: none; } }
    @keyframes fadeUp { from { opacity: 0; transform: translateY(14px); } to { opacity: 1; transform: none; } }
    @keyframes fadeIn { from { opacity: 0; } to { opacity: 1; } }
    @keyframes dialogIn { from { opacity: 0; transform: translateY(18px) scale(0.985); } to { opacity: 1; transform: none; } }

    /* ---------- pages ---------- */
    .page { width: min(100% - 2 * var(--gutter), var(--max)); margin-inline: auto; flex: 1 0 auto; overflow-x: clip; }
    .page.narrow { width: min(100% - 2 * var(--gutter), 900px); }
    .section { margin-top: clamp(48px, 7vw, 96px); }
    .section-head { display: flex; align-items: baseline; justify-content: space-between; gap: 16px; padding-bottom: 18px; margin-bottom: clamp(24px, 3vw, 40px); border-bottom: 1px solid var(--line); }

    /* home hero */
    .hero {
        display: grid; grid-template-columns: minmax(0, 1.1fr) minmax(0, 0.9fr); align-items: center;
        gap: clamp(28px, 6vw, 96px);
        padding-block: clamp(36px, 7vw, 96px) 0;
    }
    .hero-title { margin: 0; font-size: clamp(2.7rem, 6.4vw, 5.7rem); line-height: 0.98; letter-spacing: -0.028em; }
    .hero-title .line { display: block; overflow: hidden; padding-bottom: 0.12em; }
    .hero-title .line > span { display: block; animation: rise 1.1s var(--ease) backwards; }
    .hero-title .line:nth-child(2) { padding-inline-start: 1.05em; }
    .hero-title .line:nth-child(2) > span { animation-delay: 0.14s; }
    html[lang="ar"] .hero-title { font-size: clamp(2.3rem, 5vw, 4.3rem); }
    .hero-tag { margin: clamp(22px, 3vw, 36px) 0 0; font-family: var(--display); font-style: italic; font-size: clamp(1.1rem, 1.8vw, 1.4rem); color: var(--accent-ink); animation: fadeUp 0.9s 0.55s var(--ease) backwards; }
    [dir="rtl"] .hero-tag { font-style: normal; }
    .hero-desc { margin: 12px 0 0; max-width: 44ch; color: var(--muted); animation: fadeUp 0.9s 0.68s var(--ease) backwards; }
    .hero-cta { margin-top: 32px; animation: fadeUp 0.9s 0.8s var(--ease) backwards; }

    .spotlight { display: block; justify-self: center; width: min(100%, 400px); padding-inline-end: 18%; animation: fadeUp 1s 0.2s var(--ease) backwards; }
    .spot-meta { margin-top: 26px; padding-inline-end: 4%; }
    .spot-title { font-family: var(--display); font-size: 1.35rem; font-weight: 500; line-height: 1.2; transition: color 0.25s; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    .spotlight:hover .spot-title { color: var(--accent-ink); }
    .spot-artist { margin-top: 2px; color: var(--muted); font-size: 14px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    .spot-rate { display: flex; align-items: center; gap: 10px; margin-top: 10px; color: var(--muted); font-size: 13px; }
    .spot-rate b { color: var(--accent-ink); font-weight: 600; }

    /* album wall */
    .wall { display: grid; grid-template-columns: repeat(auto-fill, minmax(min(100%, 176px), 1fr)); gap: clamp(26px, 3vw, 44px) clamp(16px, 2vw, 28px); }
    .tile { display: block; min-width: 0; }
    .tile-cover { aspect-ratio: 1; overflow: hidden; border-radius: 2px; background: var(--bg-3); box-shadow: 0 0 0 1px rgba(var(--theme-color), 0.15); }
    body.light-mode .tile-cover { box-shadow: 0 0 0 1px rgba(var(--theme-color), 0.2); }
    .tile-cover img { width: 100%; height: 100%; object-fit: cover; transition: transform 0.8s var(--ease); }
    .tile:hover .tile-cover img { transform: scale(1.045); }
    .tile-meta { margin-top: 14px; }
    .tile-title { margin: 0; font-family: var(--display); font-size: 1.05rem; font-weight: 500; line-height: 1.25; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; text-decoration: underline; text-decoration-color: transparent; text-decoration-thickness: 1px; text-underline-offset: 5px; transition: text-decoration-color 0.3s; }
    .tile:hover .tile-title { text-decoration-color: var(--accent-ink); }
    .tile-artist { margin: 1px 0 0; font-size: 13.5px; color: var(--muted); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    .tile-foot { display: flex; align-items: center; flex-wrap: wrap; gap: 3px 8px; margin-top: 9px; font-size: 12.5px; color: var(--faint); min-width: 0; }
    .tile-foot b { color: var(--accent-ink); font-weight: 600; }
    .tile-foot .votes-note { flex-basis: 100%; white-space: nowrap; }

    /* ranked list */
    .page-head { padding-block: clamp(36px, 6vw, 80px) clamp(22px, 3vw, 36px); }
    .h1 { margin: 0; font-size: clamp(2.2rem, 5vw, 3.8rem); line-height: 1.02; letter-spacing: -0.025em; }
    .rank { list-style: none; margin: 0; padding: 0; border-top: 1px solid var(--line-strong); }
    .rank-row { display: grid; grid-template-columns: clamp(34px, 6vw, 56px) 64px minmax(0, 1fr) auto 18px; align-items: center; column-gap: clamp(12px, 2.4vw, 28px); padding: 18px 8px; border-bottom: 1px solid var(--line); transition: background-color 0.25s; }
    .rank-row:hover { background: var(--bg-2); }
    .rank-num { font-family: var(--display); font-size: clamp(1.6rem, 3vw, 2.3rem); font-weight: 400; line-height: 1; text-align: center; color: var(--faint); }
    .is-first .rank-num { color: var(--accent-ink); }
    .rank-cover { width: 64px; height: 64px; object-fit: cover; border-radius: 2px; background: var(--bg-3); }
    .rank-main { min-width: 0; }
    .rank-title { display: block; font-family: var(--display); font-size: clamp(1.05rem, 1.8vw, 1.3rem); font-weight: 500; line-height: 1.25; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; transition: color 0.25s; }
    .rank-row:hover .rank-title { color: var(--accent-ink); }
    .rank-sub { display: flex; align-items: center; gap: 10px; margin-top: 4px; min-width: 0; font-size: 13px; color: var(--muted); }
    .rank-sub > span:first-child { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    .rank-score { display: flex; flex-direction: column; align-items: flex-end; gap: 5px; }
    .score-num { font-family: var(--display); font-size: 1.5rem; line-height: 1; color: var(--accent-ink); }
    .rank-votes { font-size: 12px; color: var(--faint); white-space: nowrap; }
    .rank-votes b { color: var(--muted); font-weight: 600; }
    .chev { font-size: 12px; color: var(--faint); transition: transform 0.25s, color 0.25s; }
    [dir="rtl"] .chev { rotate: 180deg; }
    .rank-row:hover .chev { transform: translateX(calc(var(--dir) * 4px)); color: var(--accent-ink); }
    .empty { padding: 56px 20px; text-align: center; color: var(--muted); border: 1px dashed var(--line-strong); border-radius: 2px; }

    /* song page */
    .track { display: grid; grid-template-columns: minmax(0, 400px) minmax(0, 1fr); align-items: center; gap: clamp(32px, 6vw, 88px); padding-block: clamp(32px, 6vw, 72px) 0; }
    .track-art { padding-inline-end: 18%; }
    .track-art .cover { box-shadow: 0 50px 90px -42px rgba(var(--theme-color), 0.65), 0 24px 48px -24px rgba(0, 0, 0, 0.7), 0 0 0 1px rgba(var(--theme-color), 0.2); transition: box-shadow 1.2s ease; }
    body.light-mode .track-art .cover { box-shadow: 0 50px 90px -42px rgba(var(--theme-color), 0.7), 0 24px 48px -26px rgba(var(--theme-color), 0.3), 0 0 0 1px rgba(var(--theme-color), 0.2); }
    .track-info { min-width: 0; }
    .track-title { margin: 0; font-size: clamp(2.1rem, 5.2vw, 4.3rem); line-height: 1.02; letter-spacing: -0.025em; overflow-wrap: anywhere; text-wrap: balance; }
    .track-artist { margin: 14px 0 0; font-family: var(--display); font-size: clamp(1.15rem, 2.2vw, 1.6rem); font-weight: 400; color: var(--muted); }
    .track-meta { display: flex; align-items: center; gap: 12px; margin: 14px 0 0; font-size: 14px; color: var(--faint); }
    .track-rating { display: flex; align-items: center; flex-wrap: wrap; gap: 6px 16px; margin-top: clamp(24px, 3vw, 36px); }
    .big-score { font-family: var(--display); font-size: clamp(2.6rem, 5vw, 3.8rem); font-weight: 500; line-height: 1; color: var(--accent-ink); transition: color 0.9s ease; }
    .of { margin-inline-start: 4px; font-size: 15px; color: var(--faint); }
    .votes { font-size: 14px; color: var(--muted); }
    .actions { display: flex; flex-wrap: wrap; gap: 12px; margin-top: clamp(24px, 3vw, 36px); }

    .cols { display: grid; grid-template-columns: minmax(0, 1fr) 320px; align-items: start; gap: clamp(32px, 6vw, 88px); }
    .ledger { position: sticky; top: 104px; padding-top: 22px; border-top: 1px solid var(--line-strong); }
    .ledger h4 { margin: 0 0 8px; font-family: var(--display); font-size: 1.3rem; font-weight: 500; }
    .ledger dl { margin: 0; }
    .ledger .row { display: flex; align-items: baseline; justify-content: space-between; gap: 12px; padding-block: 15px; border-bottom: 1px solid var(--line); font-size: 14px; color: var(--muted); }
    .ledger dt, .ledger dd { margin: 0; }
    .ledger dd { font-weight: 600; color: var(--text); }
    .ledger dd.accent { font-family: var(--display); font-size: 1.25rem; font-weight: 500; color: var(--accent-ink); }

    .review { padding-block: 28px; border-bottom: 1px solid var(--line); }
    .review:first-child { padding-top: 4px; }
    .review-head { display: flex; align-items: center; gap: 14px; }
    .avatar { width: 44px; height: 44px; flex-shrink: 0; border-radius: 50%; object-fit: cover; background: var(--bg-3); box-shadow: 0 0 0 1px var(--line-strong); }
    .who { flex: 1; min-width: 0; }
    .who h4 { margin: 0; font-size: 15px; font-weight: 600; line-height: 1.3; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    .when { font-size: 12.5px; color: var(--faint); }
    .review-score { display: flex; align-items: center; gap: 10px; flex-shrink: 0; font-size: 13px; color: var(--muted); }
    .review-text { unicode-bidi: plaintext; text-align: start; margin: 16px 0 0; padding-inline-start: 58px; font-size: 16.5px; line-height: 1.75; overflow-wrap: anywhere; }
    .review-foot { margin-top: 16px; padding-inline-start: 58px; }
    .like-btn {
        display: inline-flex; align-items: center; gap: 9px; height: 36px; padding: 0 16px;
        border: 1px solid var(--line-strong); border-radius: 999px; background: transparent;
        font-family: var(--sans); font-size: 13px; color: var(--muted); cursor: pointer;
        transition: border-color 0.25s, color 0.25s;
    }
    .like-btn:hover { border-color: var(--accent-ink); color: var(--text); }
    .like-btn i { font-size: 13px; }
    .like-btn i.text-gray-400 { color: var(--faint); }
    .like-btn i.liked-red { color: #ff2255 !important; }
    .like-btn b { color: var(--text); font-weight: 600; }
    .like-animate { animation: luxuryLikePop 0.4s ease-in-out; }
    @keyframes luxuryLikePop { 0% { transform: scale(1); } 50% { transform: scale(1.4) rotate(10deg); } 100% { transform: scale(1); } }

    /* ---------- forms + auth ---------- */
    .field { margin-top: 22px; }
    .field label { display: block; margin-bottom: 4px; font-size: 13px; font-weight: 500; color: var(--muted); }
    .input {
        display: block; width: 100%; padding: 12px 2px; border: 0; border-bottom: 1px solid var(--line-strong); border-radius: 0;
        background: transparent; color: var(--text); font-family: var(--sans); font-size: 16px;
        transition: border-color 0.25s, box-shadow 0.25s;
    }
    .input::placeholder { color: var(--faint); opacity: 1; }
    .input:focus { outline: none; border-bottom-color: var(--accent-ink); box-shadow: 0 1px 0 0 var(--accent-ink); }
    .textarea {
        display: block; width: 100%; margin-top: 8px; padding: 14px; resize: vertical;
        border: 1px solid var(--line-strong); border-radius: 2px; background: transparent; color: var(--text);
        font-family: var(--sans); font-size: 16px; line-height: 1.6;
        transition: border-color 0.25s;
    }
    .textarea::placeholder { color: var(--faint); opacity: 1; }
    .textarea:focus { outline: none; border-color: var(--accent-ink); }
    .file {
        display: block; width: 100%; padding: 14px; border: 1px dashed var(--line-strong); border-radius: 2px;
        background: transparent; color: var(--muted); font-family: var(--sans); font-size: 14px; cursor: pointer;
    }
    .file::file-selector-button {
        margin-inline-end: 14px; height: 34px; padding: 0 16px; border: 1px solid var(--line-strong); border-radius: 2px;
        background: transparent; color: var(--text); font-family: var(--sans); font-size: 13px; font-weight: 500; cursor: pointer;
    }

    .auth-main { flex: 1 0 auto; display: grid; align-items: center; padding-block: clamp(28px, 5vw, 64px); width: min(100% - 2 * var(--gutter), var(--max)); margin-inline: auto; grid-template-columns: minmax(0, 1fr); }
    .auth-art { display: none; }
    .auth-panel { width: min(100%, 460px); margin-inline: auto; padding: clamp(28px, 4vw, 48px); border: 1px solid var(--line-strong); border-radius: 2px; background: var(--bg-2); }
    @supports (color: color-mix(in srgb, red 50%, white)) {
        .auth-panel { background: color-mix(in srgb, var(--bg-2) 86%, transparent); -webkit-backdrop-filter: blur(10px); backdrop-filter: blur(10px); }
    }
    .back { display: inline-flex; align-items: center; gap: 9px; margin-bottom: 30px; font-size: 13px; color: var(--muted); transition: color 0.25s; }
    .back:hover { color: var(--text); }
    .back i { font-size: 11px; }
    [dir="rtl"] .back i { rotate: 180deg; }
    .auth-title { margin: 0; font-size: clamp(2rem, 4vw, 2.7rem); line-height: 1.08; letter-spacing: -0.02em; }
    .auth-panel .btn-block { margin-top: 34px; }
    .switch { margin: 26px 0 0; font-size: 14px; color: var(--muted); }
    .switch a { color: var(--accent-ink); font-weight: 600; margin-inline-start: 6px; border-bottom: 1px solid transparent; transition: border-color 0.25s; }
    .switch a:hover { border-bottom-color: var(--accent-ink); }
    .auth-top { width: min(100% - 2 * var(--gutter), var(--max)); margin-inline: auto; min-height: 72px; display: flex; align-items: center; justify-content: space-between; gap: 16px; }
    .avatar-lg { width: 112px; height: 112px; border-radius: 50%; object-fit: cover; margin-bottom: 22px; background: var(--bg-3); box-shadow: 0 0 0 5px var(--bg-2), 0 0 0 6px var(--accent-ink); }
    .auth-panel .who-line { margin: 0 0 6px; font-family: var(--display); font-size: 1.7rem; font-weight: 500; line-height: 1.15; overflow-wrap: anywhere; }
    .auth-art .vinyl-wrap { position: relative; inset: auto; top: auto; width: 100%; transform: none; animation: none; transition: none; }

    /* ---------- modals ---------- */
    .modal {
        position: fixed; inset: 0; z-index: 100; display: flex; align-items: center; justify-content: center; padding: 20px;
        background: var(--scrim); -webkit-backdrop-filter: blur(10px); backdrop-filter: blur(10px);
        animation: fadeIn 0.25s ease;
    }
    .dialog {
        width: min(100%, 480px); max-height: calc(100dvh - 40px); overflow-y: auto; padding: clamp(24px, 4vw, 36px);
        background: var(--bg-2); border: 1px solid var(--line-strong); border-radius: 4px;
        box-shadow: 0 50px 100px -30px rgba(0, 0, 0, 0.8);
        animation: dialogIn 0.4s var(--ease);
    }
    .dialog-title { margin: 0; font-family: var(--display); font-size: 1.55rem; font-weight: 500; line-height: 1.2; overflow-wrap: anywhere; }
    .dialog .field label { margin-bottom: 0; }
    .dialog-actions { display: flex; flex-direction: column; gap: 10px; margin-top: 28px; }
    .dialog.story { width: min(100%, 400px); text-align: center; }
    .dialog.story .dialog-title { font-size: 1.2rem; }
    #storyCanvas { display: block; height: min(52vh, 430px); width: auto; max-width: 100%; aspect-ratio: 1080 / 1920; margin: 22px auto 0; border-radius: 4px; box-shadow: 0 0 0 1px var(--line-strong); }
    .dialog.story .dialog-actions { margin-top: 22px; }

    #starContainer { display: flex; align-items: center; gap: 4px; margin-top: 10px; }
    #starContainer i { padding: 4px; font-size: 30px; color: var(--track); cursor: pointer; filter: none !important; transition: transform 0.18s var(--ease), color 0.25s; }
    #starContainer i.text-theme { color: var(--accent-ink); }
    #starContainer i:hover { transform: scale(1.14); }
    #starValueText { margin-inline-start: 12px; font-family: var(--display); font-size: 1.4rem; color: var(--accent-ink); }

    /* ---------- footer ---------- */
    .foot { margin-top: clamp(64px, 9vw, 120px); }
    .auth-page .foot { margin-top: 0; }
    .foot-inner { width: min(100% - 2 * var(--gutter), var(--max)); margin-inline: auto; padding: 26px 0 34px; border-top: 1px solid var(--line); display: flex; align-items: center; justify-content: space-between; gap: 16px; font-size: 13px; color: var(--faint); }
    .foot .fa-heart { margin-inline: 4px; color: rgb(var(--theme-color)); font-size: 11px; }
    .foot-brand { font-family: var(--display); font-style: italic; font-size: 16px; }

    /* ---------- responsive ---------- */
    @media (min-width: 640px) {
        .top-nav { display: flex; }
        .dialog-actions { flex-direction: row-reverse; }
        .dialog-actions .btn { flex: 1; }
    }
    @media (min-width: 1100px) {
        .mode-btn { width: auto; padding: 0 13px; }
        .mode-btn span { display: inline; }
    }
    @media (min-width: 960px) {
        .auth-main { grid-template-columns: minmax(0, 1fr) minmax(0, 480px); column-gap: clamp(40px, 8vw, 120px); }
        .auth-art { display: block; justify-self: center; width: min(100%, 460px); }
        .auth-panel { margin-inline: 0; }
    }
    @media (max-width: 859px) {
        .top-inner { grid-template-columns: 1fr auto; min-height: 0; padding-block: 12px; row-gap: 12px; }
        .top-left { grid-column: 1; }
        .top-tools { grid-column: 2; }
        .search { grid-column: 1 / -1; grid-row: 2; max-width: none; }
        .search-input { font-size: 16px; }
    }
    @media (max-width: 859px) {
        .hero { grid-template-columns: minmax(0, 1fr); }
        .spotlight { justify-self: start; width: min(100%, 340px); }
        .track { grid-template-columns: minmax(0, 1fr); }
        .track-art { width: min(100%, 340px); margin-inline: auto; }
        .cols { grid-template-columns: minmax(0, 1fr); }
        .ledger { position: static; }
    }
    @media (max-width: 639px) {
        body.musicy { font-size: 15px; }
        .icon-link { display: flex; }
        .brand-name { font-size: 24px; }
        .top-left { gap: 0; }
        .top-inner { column-gap: 12px; }
        .top-tools, .tools { gap: 8px; }
        .lang-btn { min-width: 34px; padding: 0 8px; }
        .wall { grid-template-columns: repeat(2, minmax(0, 1fr)); }
        .rank-row { grid-template-columns: 30px 52px minmax(0, 1fr) auto; padding-inline: 2px; }
        .rank-cover { width: 52px; height: 52px; }
        .rank-score .stars, .chev { display: none; }
        .review-text, .review-foot { padding-inline-start: 0; }
        .review-score .stars { display: none; }
        .section-head { flex-wrap: wrap; }
        .foot-inner { flex-direction: column; align-items: flex-start; gap: 6px; }
        .hero-title .line:nth-child(2) { padding-inline-start: 0.6em; }
    }

    /* ---------- motion preferences ---------- */
    @media (prefers-reduced-motion: reduce) {
        *, *::before, *::after { animation-duration: 0.001ms !important; animation-iteration-count: 1 !important; transition-duration: 0.001ms !important; scroll-behavior: auto !important; }
        .vinyl { animation: none; }
    }
</style>

<script>
    document.addEventListener('mousemove', (e) => {
        const mouseX = e.clientX;
        const mouseY = e.clientY;
        document.querySelectorAll('.musical-note').forEach(note => {
            const speed = parseFloat(note.getAttribute('data-speed')) || 0.03;
            const rect = note.getBoundingClientRect();
            const noteX = rect.left + rect.width / 2;
            const noteY = rect.top + rect.height / 2;
            
            const offsetX = (mouseX - noteX) * speed;
            const offsetY = (mouseY - noteY) * speed;
            
            note.style.transform = `translate(${offsetX}px, ${offsetY}px) scale(1.15)`;
            note.style.color = 'rgba(var(--theme-color), 0.8)';
        });
    });

    document.addEventListener('mouseleave', () => {
        document.querySelectorAll('.musical-note').forEach(note => {
            note.style.transform = 'translate(0px, 0px) scale(1)';
            note.style.color = 'rgba(var(--theme-color), 0.35)';
        });
    });

    function toggleDarkMode() {
        document.body.classList.toggle('light-mode');
        let isLight = document.body.classList.contains('light-mode');
        localStorage.setItem('musicy_theme', isLight ? 'light' : 'dark');
        let icon = document.getElementById('darkModeIcon');
        let text = document.getElementById('darkModeText');
        if(isLight) {
            if(icon) icon.className = 'fa-solid fa-sun w-4 text-emerald-600';
            if(text) text.innerText = (localStorage.getItem('musicy_lang') === 'ar') ? 'الوضع الساطع' : 'Light Mode';
        } else {
            if(icon) icon.className = 'fa-solid fa-moon w-4 text-theme';
            if(text) text.innerText = (localStorage.getItem('musicy_lang') === 'ar') ? 'الوضع الداكن' : 'Dark Mode';
        }
    }

    document.addEventListener('DOMContentLoaded', () => {
        let savedTheme = localStorage.getItem('musicy_theme');
        if(savedTheme === 'light') {
            document.body.classList.add('light-mode');
            let icon = document.getElementById('darkModeIcon');
            let text = document.getElementById('darkModeText');
            if(icon) icon.className = 'fa-solid fa-sun w-4 text-emerald-600';
            if(text) text.innerText = (localStorage.getItem('musicy_lang') === 'ar') ? 'الوضع الساطع' : 'Light Mode';
        }
    });

    const translations = {
        en: {
            brandName: "Musicy",
            searchPlaceholder: "Search songs or artists on Spotify...",
            home: "Home",
            topRated: "Top Rated",
            darkMode: "Dark Mode",
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
            darkMode: "الوضع الداكن",
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
        let isLight = document.body.classList.contains('light-mode');
        let text = document.getElementById('darkModeText');
        if(text) {
            if(isLight) {
                text.innerText = (lang === 'ar') ? 'الوضع الساطع' : 'Light Mode';
            } else {
                text.innerText = (lang === 'ar') ? 'الوضع الداكن' : 'Dark Mode';
            }
        }
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

ambient_html = """
<canvas id="ambientCanvas" aria-hidden="true"></canvas>
<div class="grain" aria-hidden="true"></div>
<div class="musical-bg-container" aria-hidden="true">
    <div class="musical-note" style="left: 5%; font-size: 24px; animation-duration: 12s; animation-delay: 0s;" data-speed="0.02"><i class="fa-solid fa-music"></i></div>
    <div class="musical-note" style="left: 18%; font-size: 32px; animation-duration: 16s; animation-delay: 3s;" data-speed="0.04"><i class="fa-solid fa-headphones"></i></div>
    <div class="musical-note" style="left: 32%; font-size: 20px; animation-duration: 10s; animation-delay: 1s;" data-speed="0.025"><i class="fa-solid fa-compact-disc"></i></div>
    <div class="musical-note" style="left: 48%; font-size: 28px; animation-duration: 14s; animation-delay: 5s;" data-speed="0.05"><i class="fa-solid fa-note-sticky"></i></div>
    <div class="musical-note" style="left: 65%; font-size: 35px; animation-duration: 18s; animation-delay: 2s;" data-speed="0.03"><i class="fa-solid fa-radio"></i></div>
    <div class="musical-note" style="left: 78%; font-size: 22px; animation-duration: 11s; animation-delay: 4s;" data-speed="0.045"><i class="fa-solid fa-microphone-lines"></i></div>
    <div class="musical-note" style="left: 90%; font-size: 30px; animation-duration: 15s; animation-delay: 1.5s;" data-speed="0.035"><i class="fa-solid fa-guitar"></i></div>
</div>
<script>
(function () {
    try {
        if (localStorage.getItem('musicy_theme') === 'light') { document.body.classList.add('light-mode'); }
        var savedLang = localStorage.getItem('musicy_lang');
        if (savedLang === 'ar' || savedLang === 'en') {
            document.documentElement.setAttribute('lang', savedLang);
            document.documentElement.setAttribute('dir', savedLang === 'ar' ? 'rtl' : 'ltr');
        }
    } catch (e) {}

    var cv = document.getElementById('ambientCanvas');
    if (!cv || !cv.getContext) return;
    var ctx = cv.getContext('2d');
    var reduce = window.matchMedia ? window.matchMedia('(prefers-reduced-motion: reduce)') : { matches: false };

    var W = 0, H = 0, DPR = 1, raf = 0, running = false;
    var pointer = 0.5, pointerSmooth = 0.5, scrollY = 0;
    var cur = [16, 185, 129], goal = [16, 185, 129];
    var LINES = 15;

    function readColor() {
        var raw = getComputedStyle(document.documentElement).getPropertyValue('--theme-color').split(',');
        if (raw.length !== 3) return;
        var n = raw.map(function (v) { return parseFloat(v); });
        for (var i = 0; i < 3; i++) { if (isNaN(n[i])) return; }
        goal = n;
    }

    function resize() {
        DPR = Math.min(window.devicePixelRatio || 1, 1.5);
        W = window.innerWidth;
        H = window.innerHeight;
        cv.width = Math.round(W * DPR);
        cv.height = Math.round(H * DPR);
        ctx.setTransform(DPR, 0, 0, DPR, 0, 0);
    }

    function draw(ms) {
        var t = ms / 1000;
        var light = document.body.classList.contains('light-mode');
        var k = light ? 0.6 : 1;
        for (var i = 0; i < 3; i++) { cur[i] += (goal[i] - cur[i]) * 0.05; }
        var r = Math.round(cur[0] * k), g = Math.round(cur[1] * k), b = Math.round(cur[2] * k);

        pointerSmooth += (pointer - pointerSmooth) * 0.04;
        var shift = (pointerSmooth - 0.5) * 0.9;
        var compact = W < 700;
        var amp = Math.min(H * 0.17, compact ? 90 : 150);
        var cy = H * (compact ? 0.3 : 0.4) - scrollY * 0.06;
        var step = compact ? 8 : 5;

        ctx.clearRect(0, 0, W, H);
        ctx.lineWidth = 1;
        for (var n = 0; n < LINES; n++) {
            var u = n / (LINES - 1);
            var ph = u * 2.4;
            ctx.beginPath();
            for (var x = 0; x <= W + step; x += step) {
                var nx = Math.min(x / W, 1);
                var env = Math.pow(Math.sin(Math.PI * nx), 1.15);
                var y = cy
                    + Math.sin(nx * 5.2 + t * 0.32 + ph + shift) * amp * 0.62 * env
                    + Math.sin(nx * 9.4 - t * 0.21 + ph * 1.8) * amp * 0.2 * env
                    + (u - 0.5) * amp * 1.05 * env * Math.sin(nx * 2.1 + t * 0.14);
                if (x === 0) { ctx.moveTo(x, y); } else { ctx.lineTo(x, y); }
            }
            var a = (0.07 + 0.26 * Math.sin(Math.PI * u)) * (light ? 1.15 : 1);
            ctx.strokeStyle = 'rgba(' + r + ',' + g + ',' + b + ',' + a.toFixed(3) + ')';
            ctx.stroke();
        }
    }

    function loop(ms) {
        if (!running) return;
        draw(ms);
        raf = requestAnimationFrame(loop);
    }
    function start() { if (running || reduce.matches) return; running = true; raf = requestAnimationFrame(loop); }
    function stop() { running = false; cancelAnimationFrame(raf); }
    function still() { for (var i = 0; i < 3; i++) { cur[i] = goal[i]; } draw(7000); }

    resize();
    readColor();
    cur = goal.slice();
    if (reduce.matches) { still(); } else { start(); }

    window.addEventListener('resize', function () { resize(); if (reduce.matches) { still(); } }, { passive: true });
    window.addEventListener('pointermove', function (e) { pointer = e.clientX / Math.max(W, 1); }, { passive: true });
    window.addEventListener('scroll', function () { scrollY = window.scrollY || 0; }, { passive: true });
    document.addEventListener('visibilitychange', function () { if (document.hidden) { stop(); } else { start(); } });

    setInterval(function () {
        readColor();
        if (reduce.matches) { still(); }
    }, 700);
})();
</script>
"""

lang_switcher_html = """
<div class="tools">
    <div class="lang" role="group" aria-label="Language">
        <button type="button" onclick="setLanguage('en')" title="English" data-l="en" class="lang-btn">EN</button>
        <button type="button" onclick="setLanguage('ar')" title="العربية" data-l="ar" class="lang-btn">عربي</button>
    </div>
    <button type="button" onclick="toggleDarkMode()" class="mode-btn" title="Theme">
        <i id="darkModeIcon" class="fa-solid fa-moon w-4 text-theme"></i>
        <span data-i18n="darkMode" id="darkModeText">Dark Mode</span>
    </button>
</div>
"""

html_template = (
    """<!DOCTYPE html>
<html lang="en" class="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="theme-color" content="#030712">
    <title>Musicy - Discover, Rate, Share Music</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script>
        tailwind.config = {
            darkMode: 'class',
            theme: {
                extend: {
                    colors: {
                        theme: 'rgba(var(--theme-color), <alpha-value>)',
                        themeDark: 'rgba(var(--theme-color-dark), <alpha-value>)',
                    }
                }
            }
        }
    </script>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Amiri:ital,wght@0,400;0,700;1,400&amp;family=Bodoni+Moda:ital,opsz,wght@0,6..96,400..700;1,6..96,400..700&amp;family=Hanken+Grotesk:wght@300..700&amp;family=IBM+Plex+Sans+Arabic:wght@300;400;500;600&amp;display=swap" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    """
    + background_styles
    + """
</head>
<body class="musicy">
    """
    + ambient_html
    + """
    <header class="top">
        <div class="top-inner">
            <div class="top-left">
                <a href="/" class="brand" aria-label="Musicy">
                    <svg class="brand-mark" viewBox="0 0 32 32" aria-hidden="true"><circle cx="16" cy="16" r="14.6" fill="none" stroke="currentColor" stroke-width="1.1"/><circle class="ring-b" cx="16" cy="16" r="9.6" fill="none" stroke="currentColor" stroke-width="0.8"/><circle class="core" cx="16" cy="16" r="4.6"/><circle class="hole" cx="16" cy="16" r="1.1"/></svg>
                    <span class="brand-name" data-i18n="brandName">Musicy</span>
                </a>
                <nav class="top-nav">
                    <a href="/" class="is-active" data-i18n="home">Home</a>
                    <a href="/top-rated" data-i18n="topRated">Top Rated</a>
                </nav>
            </div>
            <div class="search">
                <i class="fa-solid fa-magnifying-glass search-ico"></i>
                <input type="text" id="searchInput" data-i18n-placeholder="searchPlaceholder" placeholder="Search songs or artists on Spotify..." class="search-input" autocomplete="off">
                <div id="searchResults" class="results hidden"></div>
            </div>
            <div class="top-tools">
                """
    + lang_switcher_html
    + """
                <a href="/top-rated" class="icon-link" title="Top Rated"><i class="fa-solid fa-star"></i></a>
                <div id="userProfileArea">
                    <a href="/login" aria-label="Sign in"><i class="fa-solid fa-user"></i></a>
                </div>
            </div>
        </div>
    </header>
    <main class="page">
        <section class="hero">
            <div class="hero-copy">
                <h1 class="display hero-title">
                    <span class="line"><span data-i18n="heroTitle1">Discover. Rate.</span></span>
                    <span class="line"><span data-i18n="heroTitle2">Share Music.</span></span>
                </h1>
                <p class="hero-tag" data-i18n="heroTag">Real fans. Real ratings.</p>
                <p class="hero-desc" data-i18n="heroDesc">Search any song from Spotify to view ratings</p>
                <div class="hero-cta"><a href="/top-rated" class="btn btn-ghost" data-i18n="topRated">Top Rated</a></div>
            </div>
            {% if songs %}
            {% set spot = songs[0] %}
            <a href="/song/{{ spot.spotify_id }}" class="spotlight">
                <div class="sleeve">
                    <div class="vinyl-wrap"><div class="vinyl"></div></div>
                    <img class="cover" src="{{ spot.img }}" alt="{{ spot.title }}">
                </div>
                <div class="spot-meta">
                    <div class="spot-title">{{ spot.title }}</div>
                    <div class="spot-artist">{{ spot.artist }}</div>
                    <div class="spot-rate"><span class="stars" style="--r: {{ spot.rating }}"></span><b>{{ spot.rating }}</b></div>
                </div>
            </a>
            {% endif %}
        </section>

        <section class="section">
            <div class="section-head">
                <h2 class="h2"><span data-i18n="trendingTitle">Trending &amp; Random Songs</span><span class="count">({{ songs|length }})</span></h2>
                <button type="button" onclick="location.reload()" class="btn btn-ghost btn-sm"><i class="fa-solid fa-rotate"></i><span data-i18n="refreshSongs">Refresh Songs</span></button>
            </div>
            <div class="wall">
                {% for song in songs %}
                <a href="/song/{{ song.spotify_id }}" class="tile">
                    <div class="tile-cover"><img src="{{ song.img }}" alt="" loading="lazy"></div>
                    <div class="tile-meta">
                        <h4 class="tile-title">{{ song.title }}</h4>
                        <p class="tile-artist">{{ song.artist }}</p>
                        <div class="tile-foot"><span class="stars" style="--r: {{ song.rating }}"></span><b>{{ song.rating }}</b><span class="votes-note">({{ song.votes }} <span data-i18n="votesText">votes</span>)</span></div>
                    </div>
                </a>
                {% endfor %}
            </div>
        </section>
    </main>

    <footer class="foot">
        <div class="foot-inner">
            <span class="credit">Made with <i class="fa-solid fa-heart"></i> by Ammar</span>
            <span class="foot-brand">Musicy</span>
        </div>
    </footer>

    <script>
        document.addEventListener('DOMContentLoaded', () => { 
            updateUserNav();
            let savedLang = localStorage.getItem('musicy_lang') || 'en';
            setLanguage(savedLang);
            let savedTheme = localStorage.getItem('musicy_theme');
            if(savedTheme === 'light') {
                document.body.classList.add('light-mode');
                let icon = document.getElementById('darkModeIcon');
                let text = document.getElementById('darkModeText');
                if(icon) icon.className = 'fa-solid fa-sun w-4 text-emerald-600';
                if(text) text.innerText = (savedLang === 'ar') ? 'الوضع الساطع' : 'Light Mode';
            }
        });
        function updateUserNav() {
            let currentUser = localStorage.getItem('songdb_user');
            let currentAvatar = localStorage.getItem('songdb_avatar') || 'https://images.unsplash.com/photo-1534528741775-53994a69daeb?auto=format&fit=crop&q=80&w=200';
            let area = document.getElementById('userProfileArea');
            if (currentUser) {
                let logoutText = (localStorage.getItem('musicy_lang') === 'ar') ? 'تسجيل الخروج' : 'Logout';
                area.innerHTML = `
                    <div class="flex items-center space-x-1.5 sm:space-x-3">
                        <a href="/profile" class="flex items-center space-x-1.5 bg-[#030712] px-2 sm:px-3 py-1.5 rounded-full border border-theme/60 shadow-[0_0_20px_rgba(var(--theme-color),0.15)] hover:border-theme transition">
                            <img src="${currentAvatar}" class="w-7 h-7 rounded-full object-cover">
                            <span class="text-xs sm:text-sm font-medium text-white max-w-[100px] truncate">${currentUser}</span>
                        </a>
                        <button onclick="logout()" title="${logoutText}" class="w-9 h-9 flex items-center justify-center rounded-full border border-theme/40 text-gray-400 hover:text-red-500 hover:border-red-500/50 transition">
                            <i class="fa-solid fa-right-from-bracket text-sm"></i>
                        </button>
                    </div>
                `;
            } else {
                area.innerHTML = `<a href="/login" class="w-9 h-9 flex items-center justify-center rounded-full border border-theme/40 text-white hover:border-theme transition"><i class="fa-solid fa-user text-sm"></i></a>`;
            }
        }
        function logout() {
            localStorage.removeItem('songdb_user');
            localStorage.removeItem('songdb_avatar');
            window.location.href = '/';
        }

        const searchInput = document.getElementById('searchInput');
        const searchResults = document.getElementById('searchResults');
        let searchTimeout = null;

        if(searchInput) {
            searchInput.addEventListener('input', (e) => {
                clearTimeout(searchTimeout);
                let q = e.target.value.trim();
                if(!q) {
                    searchResults.classList.add('hidden');
                    searchResults.innerHTML = '';
                    return;
                }
                searchTimeout = setTimeout(() => {
                    fetch(`/api/search?q=${encodeURIComponent(q)}`)
                    .then(res => res.json())
                    .then(data => {
                        if(data.length === 0) {
                            searchResults.innerHTML = `<div class="p-3 text-sm text-gray-400 text-center">No tracks found</div>`;
                            searchResults.classList.remove('hidden');
                            return;
                        }
                        let html = '';
                        data.forEach(item => {
                            html += `
                                <div onclick="location.href='/song/${item.spotify_id}'">
                                    <img src="${item.img}" class="w-10 h-10 object-cover rounded">
                                    <div>
                                        <p class="font-bold">${item.title}</p>
                                        <p class="text-xs text-gray-400">${item.artist}</p>
                                    </div>
                                </div>
                            `;
                        });
                        searchResults.innerHTML = html;
                        searchResults.classList.remove('hidden');
                    });
                }, 300);
            });

            document.addEventListener('click', (e) => {
                if(!searchInput.contains(e.target) && !searchResults.contains(e.target)) {
                    searchResults.classList.add('hidden');
                }
            });
        }
    </script>
</body>
</html>
"""
)

top_rated_html = (
    """<!DOCTYPE html>
<html lang="en" class="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Top Rated Songs - Musicy</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://fonts.googleapis.com/css2?family=Amiri:ital,wght@0,400;0,700;1,400&amp;family=Bodoni+Moda:ital,opsz,wght@0,6..96,400..700;1,6..96,400..700&amp;family=Hanken+Grotesk:wght@300..700&amp;family=IBM+Plex+Sans+Arabic:wght@300;400;500;600&amp;display=swap" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    """
    + background_styles
    + """
</head>
<body class="musicy">
    """
    + ambient_html
    + """
    <header class="top">
        <div class="top-inner">
            <div class="top-left">
                <a href="/" class="brand" aria-label="Musicy">
                    <svg class="brand-mark" viewBox="0 0 32 32" aria-hidden="true"><circle cx="16" cy="16" r="14.6" fill="none" stroke="currentColor" stroke-width="1.1"/><circle class="ring-b" cx="16" cy="16" r="9.6" fill="none" stroke="currentColor" stroke-width="0.8"/><circle class="core" cx="16" cy="16" r="4.6"/><circle class="hole" cx="16" cy="16" r="1.1"/></svg>
                    <span class="brand-name" data-i18n="brandName">Musicy</span>
                </a>
                <nav class="top-nav">
                    <a href="/" data-i18n="home">Home</a>
                    <a href="/top-rated" class="is-active" data-i18n="topRated">Top Rated</a>
                </nav>
            </div>
            <div class="search">
                <i class="fa-solid fa-magnifying-glass search-ico"></i>
                <input type="text" id="searchInput" data-i18n-placeholder="searchPlaceholder" placeholder="Search songs or artists on Spotify..." class="search-input" autocomplete="off">
                <div id="searchResults" class="results hidden"></div>
            </div>
            <div class="top-tools">
                """
    + lang_switcher_html
    + """
                <a href="/top-rated" class="icon-link" title="Top Rated"><i class="fa-solid fa-star"></i></a>
                <div id="userProfileArea">
                    <a href="/login" aria-label="Sign in"><i class="fa-solid fa-user"></i></a>
                </div>
            </div>
        </div>
    </header>

    <main class="page narrow">
        <div class="page-head">
            <h1 class="display h1" data-i18n="topRatedTitle">All Top Rated Songs</h1>
            <p class="lede" data-i18n="topRatedDesc">Explore the highest-rated songs ranked by user reviews and votes on Musicy.</p>
        </div>

        {% if songs %}
        <ul class="rank">
            {% for song in songs %}
            <li>
                <a href="/song/{{ song.spotify_id }}" class="rank-row {% if loop.index == 1 %}is-first{% endif %}">
                    <div class="rank-num">#{{ loop.index }}</div>
                    <img class="rank-cover" src="{{ song.img }}" alt="{{ song.title }}">
                    <div class="rank-main">
                        <span class="rank-title">{{ song.title }}</span>
                        <div class="rank-sub"><span>{{ song.artist }}</span><span class="sep"></span><span>{{ song.release_year }}</span></div>
                    </div>
                    <div class="rank-score">
                        <span class="score-num">{{ song.rating }}</span>
                        <span class="rank-votes"><b>{{ song.votes }}</b> <span data-i18n="votesText">votes</span></span>
                    </div>
                    <i class="fa-solid fa-chevron-right chev"></i>
                </a>
            </li>
            {% endfor %}
        </ul>
        {% else %}
        <div class="empty" data-i18n="noRated">No rated songs found yet. Start searching and rating songs!</div>
        {% endif %}
    </main>

    <footer class="foot">
        <div class="foot-inner">
            <span class="credit">Made with <i class="fa-solid fa-heart"></i> by Ammar</span>
            <span class="foot-brand">Musicy</span>
        </div>
    </footer>

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
                    <div class="flex items-center space-x-1.5 sm:space-x-3">
                        <a href="/profile" class="flex items-center space-x-1.5 bg-[#030712] px-2 sm:px-3 py-1.5 rounded-full border border-theme/60 shadow-[0_0_20px_rgba(var(--theme-color),0.15)] hover:border-theme transition">
                            <img src="${currentAvatar}" class="w-7 h-7 rounded-full object-cover">
                            <span class="text-xs sm:text-sm font-medium text-white max-w-[100px] truncate">${currentUser}</span>
                        </a>
                        <button onclick="logout()" title="${logoutText}" class="w-9 h-9 flex items-center justify-center rounded-full border border-theme/40 text-gray-400 hover:text-red-500 hover:border-red-500/50 transition">
                            <i class="fa-solid fa-right-from-bracket text-sm"></i>
                        </button>
                    </div>
                `;
            } else {
                area.innerHTML = `<a href="/login" class="w-9 h-9 flex items-center justify-center rounded-full border border-theme/40 text-white hover:border-theme transition"><i class="fa-solid fa-user text-sm"></i></a>`;
            }
        }
        function logout() {
            localStorage.removeItem('songdb_user');
            localStorage.removeItem('songdb_avatar');
            window.location.href = '/';
        }

        const searchInput = document.getElementById('searchInput');
        const searchResults = document.getElementById('searchResults');
        let searchTimeout = null;

        if(searchInput) {
            searchInput.addEventListener('input', (e) => {
                clearTimeout(searchTimeout);
                let q = e.target.value.trim();
                if(!q) {
                    searchResults.classList.add('hidden');
                    searchResults.innerHTML = '';
                    return;
                }
                searchTimeout = setTimeout(() => {
                    fetch(`/api/search?q=${encodeURIComponent(q)}`)
                    .then(res => res.json())
                    .then(data => {
                        if(data.length === 0) {
                            searchResults.innerHTML = `<div class="p-3 text-sm text-gray-400 text-center">No tracks found</div>`;
                            searchResults.classList.remove('hidden');
                            return;
                        }
                        let html = '';
                        data.forEach(item => {
                            html += `
                                <div onclick="location.href='/song/${item.spotify_id}'">
                                    <img src="${item.img}" class="w-10 h-10 object-cover rounded">
                                    <div>
                                        <p class="font-bold">${item.title}</p>
                                        <p class="text-xs text-gray-400">${item.artist}</p>
                                    </div>
                                </div>
                            `;
                        });
                        searchResults.innerHTML = html;
                        searchResults.classList.remove('hidden');
                    });
                }, 300);
            });

            document.addEventListener('click', (e) => {
                if(!searchInput.contains(e.target) && !searchResults.contains(e.target)) {
                    searchResults.classList.add('hidden');
                }
            });
        }
    </script>
</body>
</html>
"""
)

login_html = (
    """<!DOCTYPE html>
<html lang="en" class="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Sign In - Musicy</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://fonts.googleapis.com/css2?family=Amiri:ital,wght@0,400;0,700;1,400&amp;family=Bodoni+Moda:ital,opsz,wght@0,6..96,400..700;1,6..96,400..700&amp;family=Hanken+Grotesk:wght@300..700&amp;family=IBM+Plex+Sans+Arabic:wght@300;400;500;600&amp;display=swap" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    """
    + background_styles
    + """
</head>
<body class="musicy auth-page">
    """
    + ambient_html
    + """
    <div class="auth-top">
        <a href="/" class="brand" aria-label="Musicy">
            <svg class="brand-mark" viewBox="0 0 32 32" aria-hidden="true"><circle cx="16" cy="16" r="14.6" fill="none" stroke="currentColor" stroke-width="1.1"/><circle class="ring-b" cx="16" cy="16" r="9.6" fill="none" stroke="currentColor" stroke-width="0.8"/><circle class="core" cx="16" cy="16" r="4.6"/><circle class="hole" cx="16" cy="16" r="1.1"/></svg>
            <span class="brand-name" data-i18n="brandName">Musicy</span>
        </a>
        """
    + lang_switcher_html
    + """
    </div>

    <main class="auth-main">
        <div class="auth-art">
            <div class="sleeve">
                <div class="vinyl-wrap"><div class="vinyl"></div></div>
                <img class="cover" src="https://images.unsplash.com/photo-1514525253161-7a46d19cd819?auto=format&fit=crop&q=80&w=500" alt="Album Art">
            </div>
        </div>
        <div class="auth-panel">
            <a href="/" class="back"><i class="fa-solid fa-chevron-left"></i><span data-i18n="home">Home</span></a>
            <h1 class="display auth-title" data-i18n="welcomeBack">Welcome Back</h1>
            <p class="lede" data-i18n="loginDesc">Sign in to rate songs and share your reviews on Musicy</p>
            
            <form id="loginForm" onsubmit="handleLogin(event)">
                <div class="field">
                    <label data-i18n="emailLabel">Email Address</label>
                    <input type="email" id="email" required class="input" placeholder="name@example.com">
                </div>
                <div class="field">
                    <label data-i18n="passwordLabel">Password</label>
                    <input type="password" id="password" required class="input" placeholder="••••••••">
                </div>
                <div id="loginError" class="text-red-400 text-sm mt-3 hidden"></div>
                <button type="submit" class="btn btn-primary btn-block" data-i18n="signInBtn">Sign In</button>
            </form>
            <p class="switch"><span data-i18n="noAccount">Don't have an account?</span><a href="/register" data-i18n="createAccountLink">Create Account</a></p>
        </div>
    </main>

    <footer class="foot">
        <div class="foot-inner">
            <span class="credit">Made with <i class="fa-solid fa-heart"></i> by Ammar</span>
            <span class="foot-brand">Musicy</span>
        </div>
    </footer>

    <script>
        document.addEventListener('DOMContentLoaded', () => { 
            let savedLang = localStorage.getItem('musicy_lang') || 'en';
            setLanguage(savedLang);
        });

        function handleLogin(e) {
            e.preventDefault();
            const email = document.getElementById('email').value.trim();
            const password = document.getElementById('password').value;
            const errDiv = document.getElementById('loginError');

            fetch('/api/login', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({email, password})
            })
            .then(res => res.json())
            .then(data => {
                if(data.success) {
                    localStorage.setItem('songdb_user', data.username);
                    localStorage.setItem('songdb_avatar', data.avatar);
                    window.location.href = '/';
                } else {
                    errDiv.innerText = data.message;
                    errDiv.classList.remove('hidden');
                }
            })
            .catch(err => {
                errDiv.innerText = "حدث خطأ أثناء الاتصال بالخادم";
                errDiv.classList.remove('hidden');
            });
        }
    </script>
</body>
</html>
"""
)

register_html = (
    """<!DOCTYPE html>
<html lang="en" class="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Create Account - Musicy</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://fonts.googleapis.com/css2?family=Amiri:ital,wght@0,400;0,700;1,400&amp;family=Bodoni+Moda:ital,opsz,wght@0,6..96,400..700;1,6..96,400..700&amp;family=Hanken+Grotesk:wght@300..700&amp;family=IBM+Plex+Sans+Arabic:wght@300;400;500;600&amp;display=swap" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    """
    + background_styles
    + """
</head>
<body class="musicy auth-page">
    """
    + ambient_html
    + """
    <div class="auth-top">
        <a href="/" class="brand" aria-label="Musicy">
            <svg class="brand-mark" viewBox="0 0 32 32" aria-hidden="true"><circle cx="16" cy="16" r="14.6" fill="none" stroke="currentColor" stroke-width="1.1"/><circle class="ring-b" cx="16" cy="16" r="9.6" fill="none" stroke="currentColor" stroke-width="0.8"/><circle class="core" cx="16" cy="16" r="4.6"/><circle class="hole" cx="16" cy="16" r="1.1"/></svg>
            <span class="brand-name" data-i18n="brandName">Musicy</span>
        </a>
        """
    + lang_switcher_html
    + """
    </div>

    <main class="auth-main">
        <div class="auth-art">
            <div class="sleeve">
                <div class="vinyl-wrap"><div class="vinyl"></div></div>
                <img class="cover" src="https://images.unsplash.com/photo-1514525253161-7a46d19cd819?auto=format&fit=crop&q=80&w=500" alt="Album Art">
            </div>
        </div>
        <div class="auth-panel">
            <a href="/" class="back"><i class="fa-solid fa-chevron-left"></i><span data-i18n="home">Home</span></a>
            <h1 class="display auth-title" data-i18n="createAccountTitle">Create Account</h1>
            <p class="lede" data-i18n="createAccountDesc">Join Musicy community and start rating today</p>
            
            <form id="registerForm" onsubmit="handleRegister(event)">
                <div class="field">
                    <label data-i18n="usernameLabel">Username</label>
                    <input type="text" id="username" required class="input" placeholder="Your Name">
                </div>
                <div class="field">
                    <label data-i18n="emailLabel">Email Address</label>
                    <input type="email" id="email" required class="input" placeholder="name@example.com">
                </div>
                <div class="field">
                    <label data-i18n="passwordLabel">Password</label>
                    <input type="password" id="password" required class="input" placeholder="••••••••">
                </div>
                <div id="registerError" class="text-red-400 text-sm mt-3 hidden"></div>
                <button type="submit" class="btn btn-primary btn-block" data-i18n="createAccountLink">Create Account</button>
            </form>
            <p class="switch"><span data-i18n="alreadyAccount">Already have an account?</span><a href="/login" data-i18n="signInLink">Sign In</a></p>
        </div>
    </main>

    <footer class="foot">
        <div class="foot-inner">
            <span class="credit">Made with <i class="fa-solid fa-heart"></i> by Ammar</span>
            <span class="foot-brand">Musicy</span>
        </div>
    </footer>

    <script>
        document.addEventListener('DOMContentLoaded', () => { 
            let savedLang = localStorage.getItem('musicy_lang') || 'en';
            setLanguage(savedLang);
        });

        function handleRegister(e) {
            e.preventDefault();
            const username = document.getElementById('username').value.trim();
            const email = document.getElementById('email').value.trim();
            const password = document.getElementById('password').value;
            const errDiv = document.getElementById('registerError');

            fetch('/api/register', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({username, email, password})
            })
            .then(res => res.json())
            .then(data => {
                if(data.success) {
                    localStorage.setItem('songdb_user', data.username);
                    localStorage.setItem('songdb_avatar', data.avatar);
                    window.location.href = '/';
                } else {
                    errDiv.innerText = data.message;
                    errDiv.classList.remove('hidden');
                }
            })
            .catch(err => {
                errDiv.innerText = "حدث خطأ أثناء الاتصال بالخادم";
                errDiv.classList.remove('hidden');
            });
        }
    </script>
</body>
</html>
"""
)

profile_html = (
    """<!DOCTYPE html>
<html lang="en" class="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Profile - Musicy</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://fonts.googleapis.com/css2?family=Amiri:ital,wght@0,400;0,700;1,400&amp;family=Bodoni+Moda:ital,opsz,wght@0,6..96,400..700;1,6..96,400..700&amp;family=Hanken+Grotesk:wght@300..700&amp;family=IBM+Plex+Sans+Arabic:wght@300;400;500;600&amp;display=swap" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    """
    + background_styles
    + """
</head>
<body class="musicy auth-page">
    """
    + ambient_html
    + """
    <div class="auth-top">
        <a href="/" class="brand" aria-label="Musicy">
            <svg class="brand-mark" viewBox="0 0 32 32" aria-hidden="true"><circle cx="16" cy="16" r="14.6" fill="none" stroke="currentColor" stroke-width="1.1"/><circle class="ring-b" cx="16" cy="16" r="9.6" fill="none" stroke="currentColor" stroke-width="0.8"/><circle class="core" cx="16" cy="16" r="4.6"/><circle class="hole" cx="16" cy="16" r="1.1"/></svg>
            <span class="brand-name" data-i18n="brandName">Musicy</span>
        </a>
        """
    + lang_switcher_html
    + """
    </div>

    <main class="auth-main" style="grid-template-columns: 1fr;">
        <div class="auth-panel" style="width: min(100%, 520px);">
            <a href="/" class="back"><i class="fa-solid fa-chevron-left"></i><span data-i18n="home">Home</span></a>
            <div class="text-center flex flex-col items-center">
                <img id="profileAvatarImg" src="https://images.unsplash.com/photo-1534528741775-53994a69daeb?auto=format&fit=crop&q=80&w=200" alt="Avatar" class="avatar-lg">
                <h2 id="profileUsernameText" class="who-line">User</h2>
            </div>

            <form id="avatarForm" onsubmit="handleAvatarUpload(event)" class="mt-6">
                <div class="field">
                    <label data-i18n="avatarFileLabel">Choose image from device (PC or Phone):</label>
                    <input type="file" id="avatarFileInput" accept="image/png, image/jpeg, image/webp" required class="file mt-2">
                </div>
                <div id="profileError" class="text-red-400 text-sm mt-3 hidden"></div>
                <button type="submit" class="btn btn-primary btn-block mt-4" data-i18n="saveAvatarBtn">Upload &amp; Save Avatar</button>
            </form>
        </div>
    </main>

    <footer class="foot">
        <div class="foot-inner">
            <span class="credit">Made with <i class="fa-solid fa-heart"></i> by Ammar</span>
            <span class="foot-brand">Musicy</span>
        </div>
    </footer>

    <script>
        document.addEventListener('DOMContentLoaded', () => { 
            let savedLang = localStorage.getItem('musicy_lang') || 'en';
            setLanguage(savedLang);

            let currentUser = localStorage.getItem('songdb_user');
            if(!currentUser) {
                window.location.href = '/login';
                return;
            }
            document.getElementById('profileUsernameText').innerText = currentUser;
            let currentAvatar = localStorage.getItem('songdb_avatar');
            if(currentAvatar) {
                document.getElementById('profileAvatarImg').src = currentAvatar;
            }

            fetch(`/api/get_user_info?username=${encodeURIComponent(currentUser)}`)
            .then(res => res.json())
            .then(data => {
                if(data.success) {
                    document.getElementById('profileAvatarImg').src = data.avatar;
                    localStorage.setItem('songdb_avatar', data.avatar);
                }
            });
        });

        function handleAvatarUpload(e) {
            e.preventDefault();
            const fileInput = document.getElementById('avatarFileInput');
            const errDiv = document.getElementById('profileError');
            const currentUser = localStorage.getItem('songdb_user');

            if(!fileInput.files[0]) return;

            const formData = new FormData();
            formData.append('username', currentUser);
            formData.append('avatar_file', fileInput.files[0]);

            fetch('/api/update_avatar_file', {
                method: 'POST',
                body: formData
            })
            .then(res => res.json())
            .then(data => {
                if(data.success) {
                    document.getElementById('profileAvatarImg').src = data.avatar;
                    localStorage.setItem('songdb_avatar', data.avatar);
                    alert("تم تحديث الصورة الشخصية بنجاح!");
                    window.location.href = '/';
                } else {
                    errDiv.innerText = data.message;
                    errDiv.classList.remove('hidden');
                }
            })
            .catch(err => {
                errDiv.innerText = "حدث خطأ أثناء رفع الصورة";
                errDiv.classList.remove('hidden');
            });
        }
    </script>
</body>
</html>
"""
)

song_detail_template = (
    """<!DOCTYPE html>
<html lang="en" class="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{ song.title }} by {{ song.artist }} - Musicy</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://fonts.googleapis.com/css2?family=Amiri:ital,wght@0,400;0,700;1,400&amp;family=Bodoni+Moda:ital,opsz,wght@0,6..96,400..700;1,6..96,400..700&amp;family=Hanken+Grotesk:wght@300..700&amp;family=IBM+Plex+Sans+Arabic:wght@300;400;500;600&amp;display=swap" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    """
    + background_styles
    + """
</head>
<body class="musicy">
    """
    + ambient_html
    + """
    <header class="top">
        <div class="top-inner">
            <div class="top-left">
                <a href="/" class="brand" aria-label="Musicy">
                    <svg class="brand-mark" viewBox="0 0 32 32" aria-hidden="true"><circle cx="16" cy="16" r="14.6" fill="none" stroke="currentColor" stroke-width="1.1"/><circle class="ring-b" cx="16" cy="16" r="9.6" fill="none" stroke="currentColor" stroke-width="0.8"/><circle class="core" cx="16" cy="16" r="4.6"/><circle class="hole" cx="16" cy="16" r="1.1"/></svg>
                    <span class="brand-name" data-i18n="brandName">Musicy</span>
                </a>
                <nav class="top-nav">
                    <a href="/" data-i18n="home">Home</a>
                    <a href="/top-rated" data-i18n="topRated">Top Rated</a>
                </nav>
            </div>
            <div class="search">
                <i class="fa-solid fa-magnifying-glass search-ico"></i>
                <input type="text" id="searchInput" data-i18n-placeholder="searchPlaceholder" placeholder="Search songs or artists on Spotify..." class="search-input" autocomplete="off">
                <div id="searchResults" class="results hidden"></div>
            </div>
            <div class="top-tools">
                """
    + lang_switcher_html
    + """
                <a href="/top-rated" class="icon-link" title="Top Rated"><i class="fa-solid fa-star"></i></a>
                <div id="userProfileArea">
                    <a href="/login" aria-label="Sign in"><i class="fa-solid fa-user"></i></a>
                </div>
            </div>
        </div>
    </header>

    <main class="page">
        <section class="track">
            <div class="track-art">
                <div class="sleeve">
                    <div class="vinyl-wrap"><div class="vinyl"></div></div>
                    <img id="songCoverImg" class="cover" src="{{ song.img }}" alt="{{ song.title }}">
                </div>
            </div>
            <div class="track-info">
                <h1 class="display track-title">{{ song.title }}</h1>
                <p class="track-artist">{{ song.artist }}</p>
                <div class="track-meta"><span>{{ song.release_year }}</span><span class="sep"></span><span>{{ song.genre }}</span></div>
                
                <div class="track-rating">
                    <div class="big-score" id="songRatingNum">{{ song.rating }}</div>
                    <div>
                        <span class="stars lg" id="songStarsEl" style="--r: {{ song.rating }}"></span>
                        <div class="votes"><b id="songVotesCount">{{ song.votes }}</b> <span data-i18n="votesText">votes</span></div>
                    </div>
                </div>

                <div class="actions">
                    <a href="https://open.spotify.com/track/{{ song.spotify_id }}" target="_blank" class="btn btn-primary" data-i18n="listenSpotify"><i class="fa-brands fa-spotify"></i><span>Listen on Spotify</span></a>
                    <button type="button" onclick="openRateModal()" class="btn btn-ghost" id="rateModalBtnText"><i class="fa-solid fa-star"></i><span data-i18n="rateSongBtn">Rate This Song</span></button>
                </div>
            </div>
        </section>

        <section class="section">
            <div class="cols">
                <div class="feed">
                    <div class="section-head">
                        <h2 class="h2" data-i18n="reviewsTitle">Reviews &amp; Ratings</h2>
                    </div>
                    <div id="reviewsContainer">
                        {% if reviews %}
                            {% for r in reviews %}
                            <div class="review" data-review-id="{{ r.id }}">
                                <div class="review-head">
                                    <img class="avatar" src="{{ r.avatar }}" alt="{{ r.username }}">
                                    <div class="who">
                                        <h4>{{ r.username }}</h4>
                                        <div class="when" data-timestamp="{{ r.timestamp }}">Just now</div>
                                    </div>
                                    <div class="review-score">
                                        <span class="stars" style="--r: {{ r.rating }}"></span>
                                        <b>{{ r.rating }}</b>
                                    </div>
                                </div>
                                {% if r.comment %}
                                <div class="review-text">{{ r.comment }}</div>
                                {% endif %}
                                <div class="review-foot">
                                    <button type="button" onclick="likeReview({{ r.id }})" class="like-btn" id="like-btn-{{ r.id }}">
                                        <i class="fa-solid fa-heart text-gray-400" id="like-icon-{{ r.id }}"></i>
                                        <span id="like-count-{{ r.id }}">{{ r.likes }}</span>
                                    </button>
                                </div>
                            </div>
                            {% endfor %}
                        {% else %}
                            <div class="empty" id="noReviewsMsg" data-i18n="noReviews">No reviews yet. Be the first to review this song!</div>
                        {% endif %}
                    </div>
                </div>

                <div class="ledger">
                    <h4 data-i18n="ratingDetails">Rating Details</h4>
                    <dl>
                        <div class="row"><dt data-i18n="overallRating">Overall Rating</dt><dd class="accent" id="ledgerRating">{{ song.rating }}</dd></div>
                        <div class="row"><dt data-i18n="totalVotes">Total Votes</dt><dd id="ledgerVotes">{{ song.votes }}</dd></div>
                    </dl>
                </div>
            </div>
        </section>
    </main>

    <!-- Rate Modal -->
    <div id="rateModal" class="modal hidden" role="dialog" aria-hidden="true">
        <div class="dialog">
            <h3 class="dialog-title"><span data-i18n="rateModalTitle">Rate</span>: {{ song.title }}</h3>
            <div class="field">
                <label data-i18n="ratingScoreLabel">Rating Stars (1 to 5):</label>
                <div id="starContainer">
                    <i class="fa-solid fa-star" onclick="setModalRating(1)" onmouseover="hoverModalRating(1)" onmouseout="resetModalRatingHover()"></i>
                    <i class="fa-solid fa-star" onclick="setModalRating(2)" onmouseover="hoverModalRating(2)" onmouseout="resetModalRatingHover()"></i>
                    <i class="fa-solid fa-star" onclick="setModalRating(3)" onmouseover="hoverModalRating(3)" onmouseout="resetModalRatingHover()"></i>
                    <i class="fa-solid fa-star" onclick="setModalRating(4)" onmouseover="hoverModalRating(4)" onmouseout="resetModalRatingHover()"></i>
                    <i class="fa-solid fa-star" onclick="setModalRating(5)" onmouseover="hoverModalRating(5)" onmouseout="resetModalRatingHover()"></i>
                    <span id="starValueText">5</span>
                </div>
            </div>
            <div class="field">
                <label data-i18n="commentLabel">Your Review / Comment:</label>
                <textarea id="modalCommentInput" rows="4" class="textarea" placeholder="Write your thoughts..."></textarea>
            </div>
            <div id="rateModalError" class="text-red-400 text-sm mt-3 hidden"></div>
            <div class="dialog-actions">
                <button type="button" onclick="submitReview()" class="btn btn-primary" data-i18n="submitRatingBtn">Submit Rating &amp; Generate Story</button>
                <button type="button" onclick="closeRateModal()" class="btn btn-ghost" data-i18n="cancelBtn">Cancel</button>
            </div>
        </div>
    </div>

    <!-- Luxury Instagram Story Modal -->
    <div id="storyModal" class="modal hidden" role="dialog" aria-hidden="true">
        <div class="dialog story">
            <h3 class="dialog-title" data-i18n="storyModalTitle">Luxury Instagram Story Preview</h3>
            <canvas id="storyCanvas" width="1080" height="1920"></canvas>
            <div class="dialog-actions">
                <button type="button" onclick="downloadStory()" class="btn btn-primary" data-i18n="downloadStoryBtn">Download Luxury Story</button>
                <button type="button" onclick="closeStoryModal()" class="btn btn-ghost" data-i18n="closeStoryBtn">Close &amp; Continue</button>
            </div>
        </div>
    </div>

    <footer class="foot">
        <div class="foot-inner">
            <span class="credit">Made with <i class="fa-solid fa-heart"></i> by Ammar</span>
            <span class="foot-brand">Musicy</span>
        </div>
    </footer>

    <script>
        let currentModalRatingScore = 5;
        const spotifyId = "{{ song.spotify_id }}";

        document.addEventListener('DOMContentLoaded', () => {
            updateUserNav();
            let savedLang = localStorage.getItem('musicy_lang') || 'en';
            setLanguage(savedLang);
            updateAllTimes();
            checkUserLikesOnLoad();
            
            // Extract dominant color from cover art for luxury dynamic theme
            const img = document.getElementById('songCoverImg');
            if(img) {
                if(img.complete) {
                    extractColor(img);
                } else {
                    img.onload = () => extractColor(img);
                }
            }
        });

        function extractColor(img) {
            try {
                const canvas = document.createElement('canvas');
                const ctx = canvas.getContext('2d');
                canvas.width = 50;
                canvas.height = 50;
                ctx.drawImage(img, 0, 0, 50, 50);
                const data = ctx.getImageData(0, 0, 50, 50).data;
                let r = 0, g = 0, b = 0, count = 0;
                for(let i = 0; i < data.length; i += 16) {
                    r += data[i];
                    g += data[i+1];
                    b += data[i+2];
                    count++;
                }
                r = Math.floor(r / count);
                g = Math.floor(g / count);
                b = Math.floor(b / count);
                
                // Ensure sufficient brightness for contrast
                const brightness = (r * 299 + g * 587 + b * 114) / 1000;
                if(brightness < 50) {
                    r = Math.min(255, r + 80);
                    g = Math.min(255, g + 80);
                    b = Math.min(255, b + 80);
                }
                
                document.documentElement.style.setProperty('--theme-color', `${r}, ${g}, ${b}`);
                document.documentElement.style.setProperty('--theme-color-dark', `${Math.max(0, r-40)}, ${Math.max(0, g-40)}, ${Math.max(0, b-40)}`);
            } catch(e) {
                console.error(e);
            }
        }

        function checkUserLikesOnLoad() {
            let currentUser = localStorage.getItem('songdb_user');
            if(!currentUser) return;
            
            let reviewCards = document.querySelectorAll('.review');
            let reviewIds = [];
            reviewCards.forEach(card => {
                reviewIds.push(parseInt(card.getAttribute('data-review-id')));
            });

            if(reviewIds.length === 0) return;

            fetch('/api/check_likes', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({username: currentUser, review_ids: reviewIds})
            })
            .then(res => res.json())
            .then(likedDict => {
                for(let rid in likedDict) {
                    if(likedDict[rid]) {
                        let icon = document.getElementById(`like-icon-${rid}`);
                        if(icon) {
                            icon.classList.remove('text-gray-400');
                            icon.classList.add('liked-red');
                        }
                    }
                }
            });
        }

        function updateUserNav() {
            let currentUser = localStorage.getItem('songdb_user');
            let currentAvatar = localStorage.getItem('songdb_avatar') || 'https://images.unsplash.com/photo-1534528741775-53994a69daeb?auto=format&fit=crop&q=80&w=200';
            let area = document.getElementById('userProfileArea');
            if (currentUser) {
                let logoutText = (localStorage.getItem('musicy_lang') === 'ar') ? 'تسجيل الخروج' : 'Logout';
                area.innerHTML = `
                    <div class="flex items-center space-x-1.5 sm:space-x-3">
                        <a href="/profile" class="flex items-center space-x-1.5 bg-[#030712] px-2 sm:px-3 py-1.5 rounded-full border border-theme/60 shadow-[0_0_20px_rgba(var(--theme-color),0.15)] hover:border-theme transition">
                            <img src="${currentAvatar}" class="w-7 h-7 rounded-full object-cover">
                            <span class="text-xs sm:text-sm font-medium text-white max-w-[100px] truncate">${currentUser}</span>
                        </a>
                        <button onclick="logout()" title="${logoutText}" class="w-9 h-9 flex items-center justify-center rounded-full border border-theme/40 text-gray-400 hover:text-red-500 hover:border-red-500/50 transition">
                            <i class="fa-solid fa-right-from-bracket text-sm"></i>
                        </button>
                    </div>
                `;
            } else {
                area.innerHTML = `<a href="/login" class="w-9 h-9 flex items-center justify-center rounded-full border border-theme/40 text-white hover:border-theme transition"><i class="fa-solid fa-user text-sm"></i></a>`;
            }
        }

        function logout() {
            localStorage.removeItem('songdb_user');
            localStorage.removeItem('songdb_avatar');
            window.location.href = '/';
        }

        function updateAllTimes() {
            document.querySelectorAll('.when').forEach(el => {
                const ts = parseFloat(el.getAttribute('data-timestamp'));
                if(!ts) return;
                const diff = (Date.now() / 1000) - ts;
                let lang = localStorage.getItem('musicy_lang') || 'en';
                let txt = "Just now";
                if(lang === 'ar') {
                    if(diff < 60) txt = "الآن عيوني";
                    else if(diff < 3600) txt = `منذ ${Math.floor(diff/60)} دقيقة`;
                    else if(diff < 86400) txt = `منذ ${Math.floor(diff/3600)} ساعة`;
                    else txt = `منذ ${Math.floor(diff/86400)} يوم`;
                } else {
                    if(diff < 60) txt = "Just now";
                    else if(diff < 3600) txt = `${Math.floor(diff/60)}m ago`;
                    else if(diff < 86400) txt = `${Math.floor(diff/3600)}h ago`;
                    else txt = `${Math.floor(diff/86400)}d ago`;
                }
                el.innerText = txt;
            });
        }

        function openRateModal() {
            let currentUser = localStorage.getItem('songdb_user');
            if(!currentUser) {
                window.location.href = '/login';
                return;
            }
            document.getElementById('rateModal').classList.remove('hidden');
        }

        function closeRateModal() {
            document.getElementById('rateModal').classList.add('hidden');
        }

        function setModalRating(val) {
            currentModalRatingScore = val;
            document.getElementById('starValueText').innerText = val;
            let stars = document.querySelectorAll('#starContainer i');
            stars.forEach((s, idx) => {
                if(idx < val) s.classList.add('text-theme');
                else s.classList.remove('text-theme');
            });
        }

        function hoverModalRating(val) {
            let stars = document.querySelectorAll('#starContainer i');
            stars.forEach((s, idx) => {
                if(idx < val) s.classList.add('text-theme');
                else s.classList.remove('text-theme');
            });
        }

        function resetModalRatingHover() {
            setModalRating(currentModalRatingScore);
        }

        function submitReview() {
            let currentUser = localStorage.getItem('songdb_user');
            let comment = document.getElementById('modalCommentInput').value.trim();
            let errDiv = document.getElementById('rateModalError');

            fetch('/api/rate', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({
                    spotify_id: spotifyId,
                    rating: currentModalRatingScore,
                    comment: comment,
                    username: currentUser
                })
            })
            .then(res => res.json())
            .then(data => {
                if(data.success) {
                    closeRateModal();
                    document.getElementById('songRatingNum').innerText = data.new_rating;
                    document.getElementById('songStarsEl').style.setProperty('--r', data.new_rating);
                    document.getElementById('songVotesCount').innerText = data.votes;
                    document.getElementById('ledgerRating').innerText = data.new_rating;
                    document.getElementById('ledgerVotes').innerText = data.votes;

                    // Generate Luxury Instagram Story
                    openStoryModal(data);
                } else {
                    errDiv.innerText = data.message;
                    errDiv.classList.remove('hidden');
                }
            })
            .catch(err => {
                errDiv.innerText = "حدث خطأ أثناء إرسال التقييم";
                errDiv.classList.remove('hidden');
            });
        }

        let latestStoryData = null;
        function openStoryModal(data) {
            latestStoryData = data;
            document.getElementById('storyModal').classList.remove('hidden');
            drawStoryCanvas(data);
        }

        function closeStoryModal() {
            document.getElementById('storyModal').classList.add('hidden');
            location.reload();
        }

        function drawStoryCanvas(data) {
            const canvas = document.getElementById('storyCanvas');
            const ctx = canvas.getContext('2d');
            const width = 1080;
            const height = 1920;

            // Background Gradient
            let grad = ctx.createLinearGradient(0, 0, 0, height);
            grad.addColorStop(0, '#030712');
            grad.addColorStop(0.5, '#0b0f19');
            grad.addColorStop(1, '#020408');
            ctx.fillStyle = grad;
            ctx.fillRect(0, 0, width, height);

            // Glowing circle ambient
            let radial = ctx.createRadialGradient(width/2, 650, 50, width/2, 650, 600);
            radial.addColorStop(0, 'rgba(16, 185, 129, 0.35)');
            radial.addColorStop(1, 'transparent');
            ctx.fillStyle = radial;
            ctx.fillRect(0, 0, width, height);

            // Draw Album Art Cover with Shadow & Rounded corners
            const img = new Image();
            img.crossOrigin = "anonymous";
            img.src = data.img;
            img.onload = () => {
                ctx.save();
                ctx.shadowColor = 'rgba(0,0,0,0.85)';
                ctx.shadowBlur = 80;
                ctx.shadowOffsetX = 0;
                ctx.shadowOffsetY = 40;
                
                const coverSize = 640;
                const coverX = (width - coverSize) / 2;
                const coverY = 320;
                
                ctx.fillStyle = '#111827';
                ctx.beginPath();
                ctx.roundRect(coverX, coverY, coverSize, coverSize, 24);
                ctx.fill();
                ctx.clip();
                ctx.drawImage(img, coverX, coverY, coverSize, coverSize);
                ctx.restore();

                // Draw Song Title
                ctx.fillStyle = '#f9fafb';
                ctx.font = '700 56px "Bodoni Moda", serif';
                ctx.textAlign = 'center';
                ctx.fillText(truncateText(ctx, data.song_title, 900), width / 2, 1080);

                // Draw Artist
                ctx.fillStyle = '#9ca3af';
                ctx.font = '400 36px sans-serif';
                ctx.fillText(truncateText(ctx, data.artist, 900), width / 2, 1146);

                // Draw Rating Badge Box
                ctx.fillStyle = 'rgba(17, 24, 39, 0.85)';
                ctx.strokeStyle = 'rgba(16, 185, 129, 0.4)';
                ctx.lineWidth = 3;
                ctx.beginPath();
                ctx.roundRect(width/2 - 200, 1220, 400, 110, 55);
                ctx.fill();
                ctx.stroke();

                // Stars & Score inside badge
                ctx.fillStyle = '#10b981';
                ctx.font = '700 45px sans-serif';
                ctx.fillText(`★ ${data.new_rating} / 5.0`, width / 2, 1290);

                // Footer branding
                ctx.fillStyle = '#6b7280';
                ctx.font = '500 28px sans-serif';
                ctx.fillText("MUSICY — Rated & Shared by Real Fans", width / 2, 1780);
            };
        }

        function truncateText(ctx, text, maxWidth) {
            let width = ctx.measureText(text).width;
            if(width <= maxWidth) return text;
            let sub = text;
            while(width > maxWidth && sub.length > 0) {
                sub = sub.substring(0, sub.length - 1);
                width = ctx.measureText(sub + '...').width;
            }
            return sub + '...';
        }

        function downloadStory() {
            const canvas = document.getElementById('storyCanvas');
            const link = document.createElement('a');
            link.download = 'musicy-story.png';
            link.href = canvas.toDataURL('image/png');
            link.click();
        }

        function likeReview(reviewId) {
            let currentUser = localStorage.getItem('songdb_user');
            if(!currentUser) {
                window.location.href = '/login';
                return;
            }

            fetch('/api/like_review', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({review_id: reviewId, username: currentUser})
            })
            .then(res => res.json())
            .then(data => {
                if(data.success) {
                    document.getElementById(`like-count-${reviewId}`).innerText = data.likes;
                    let icon = document.getElementById(`like-icon-${reviewId}`);
                    let btn = document.getElementById(`like-btn-${reviewId}`);
                    
                    if(data.liked) {
                        icon.classList.remove('text-gray-400');
                        icon.classList.add('liked-red');
                    } else {
                        icon.classList.remove('liked-red');
                        icon.classList.add('text-gray-400');
                    }
                    
                    btn.classList.add('like-animate');
                    setTimeout(() => btn.classList.remove('like-animate'), 400);
                }
            });
        }

        const searchInput = document.getElementById('searchInput');
        const searchResults = document.getElementById('searchResults');
        let searchTimeout = null;

        if(searchInput) {
            searchInput.addEventListener('input', (e) => {
                clearTimeout(searchTimeout);
                let q = e.target.value.trim();
                if(!q) {
                    searchResults.classList.add('hidden');
                    searchResults.innerHTML = '';
                    return;
                }
                searchTimeout = setTimeout(() => {
                    fetch(`/api/search?q=${encodeURIComponent(q)}`)
                    .then(res => res.json())
                    .then(data => {
                        if(data.length === 0) {
                            searchResults.innerHTML = `<div class="p-3 text-sm text-gray-400 text-center">No tracks found</div>`;
                            searchResults.classList.remove('hidden');
                            return;
                        }
                        let html = '';
                        data.forEach(item => {
                            html += `
                                <div onclick="location.href='/song/${item.spotify_id}'">
                                    <img src="${item.img}" class="w-10 h-10 object-cover rounded">
                                    <div>
                                        <p class="font-bold">${item.title}</p>
                                        <p class="text-xs text-gray-400">${item.artist}</p>
                                    </div>
                                </div>
                            `;
                        });
                        searchResults.innerHTML = html;
                        searchResults.classList.remove('hidden');
                    });
                }, 300);
            });

            document.addEventListener('click', (e) => {
                if(!searchInput.contains(e.target) && !searchResults.contains(e.target)) {
                    searchResults.classList.add('hidden');
                }
            });
        }
    </script>
</body>
</html>
"""
)

if __name__ == '__main__':
  port = int(os.environ.get('PORT', 5000))
  socketio.run(app, host='0.0.0.0', port=port, debug=False)
