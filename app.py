from flask import Flask, render_template, request, redirect, url_for, session, flash, g, abort, jsonify
from flask_socketio import SocketIO, send, join_room, leave_room, emit
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime, timedelta
from flask_wtf import CSRFProtect
from dotenv import load_dotenv
from functools import wraps
import sqlite3
import uuid
import os
import re

load_dotenv() # .env 파일에서 환경 변수를 로드한다. 

# 파일 관련 상수 
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'} # 파일 확장자 
UPLOAD_FOLDER = os.getenv('UPLOAD_FOLDER')                   # 파일 경로 
MAX_CONTENT_LENGTH = 2 * 1024 * 1024               # 2MB 제한

DATABASE = os.getenv('DATABASE')
SECRET_KEY = os.getenv('SECRET_KEY')

app = Flask(__name__)

app.config['SECRET_KEY'] = SECRET_KEY
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = MAX_CONTENT_LENGTH
app.permanent_session_lifetime = timedelta(minutes=45)  # 세션 만료 시간 45분

# csrf 토큰 처리
csrf = CSRFProtect()
csrf.init_app(app)


socketio = SocketIO(app)

#======================================================
#                데이터 베이스 ↓
#======================================================
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row 
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

def init_db():
    with app.app_context():
        db = get_db()
        cursor = db.cursor()
        # cursor.execute("ALTER TABLE user ADD COLUMN balance INTEGER DEFAULT 50000")
        # 사용자 테이블 생성
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS user (
                id TEXT PRIMARY KEY,                   
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                privilege INTEGER NOT NULL,
                status INTEGER NOT NULL,
                failed_attempts INTEGER DEFAULT 0,  
                lock_time INTEGER DEFAULT 0,        
                decl INTEGER NOT NULL,
                bio TEXT,
                created_ip TEXT,
                created_at TEXT,
                balance INTEGER 
            )
        """)
        # 상품 테이블 생성
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS product (
                id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                description TEXT NOT NULL,
                price TEXT NOT NULL,
                seller_id TEXT NOT NULL,
                decl INTEGER NOT NULL,
                image TEXT,
                FOREIGN KEY (seller_id) REFERENCES user(id)
            )
        """)
        # 신고 테이블 생성
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS report (
                id TEXT PRIMARY KEY,
                reporter_id TEXT NOT NULL,
                target_id TEXT NOT NULL,
                reason TEXT NOT NULL,
                FOREIGN KEY (reporter_id) REFERENCES user(id),
                FOREIGN KEY (target_id) REFERENCES user(id)
            )
        """)
        # 채팅방 관리 
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS chat_rooms (
                id TEXT PRIMARY KEY,
                user1_id INTEGER NOT NULL,
                user2_id INTEGER NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user1_id) REFERENCES user(id),
                FOREIGN KEY (user2_id) REFERENCES user(id)
            );
        """)
        # 메세지 저장
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                room_id TEXT NOT NULL,
                sender_id INTEGER NOT NULL,
                message TEXT NOT NULL,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (room_id) REFERENCES chat_rooms(id),
                FOREIGN KEY (sender_id) REFERENCES user(id)
            );
        """)

        # 장바구니 기능 
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS cart (
                id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                product_id TEXT NOT NULL,
                created_at TEXT,
                FOREIGN KEY (user_id) REFERENCES user(id),
                FOREIGN KEY (product_id) REFERENCES product(id)
            );
        """)
        db.commit()


#=================================================================
#                           검증 함수 ↓
#=================================================================

# id 유효성 검사 함수
def is_valid_username(username):
    return re.match(r'^[a-zA-Z0-9_]{4,20}$', username)

# 비밀 번호 유효성 검사 함수
def is_valid_password(password):
    return (
        len(password) >= 8 and
        re.search(r'[A-Z]', password) and
        re.search(r'[a-z]', password) and
        re.search(r'[0-9]', password) and
        re.search(r'[!@#$%^&*(),.?":{}|<>]', password)
    )


# 파일 확장자 검사 함수
def allowed_file(filename):  
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


# 파일 헤더 시그니처 추출 함수
def get_file_signature(file_bytes):
    return file_bytes[:8].hex().upper()


# 파일 헤더 시그니처 검증 함수
def is_valid_image(file):
    file_bytes = file.read(8)
    file.seek(0)  

    signature = get_file_signature(file_bytes)

    if signature.startswith("89504E47"):  # PNG
        return True
    elif signature.startswith("FFD8FF"):   # JPG, JPEG
        return True
    elif signature.startswith("47494638"):  # GIF
        return True
    else:
        return False


# 사용자 계정 정지 여부 검사 함수
def status_check(user):
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT status FROM user WHERE id=?", (user, ))
    res = cursor.fetchone()
    return res 


# 세션 만료시 자동 로그아웃 함수 
@app.before_request
def check_session_expiration():
    if 'user_id' in session:

        expiration_time = session.get('expiration_time')
        now = datetime.utcnow() 

        if isinstance(expiration_time, str):
            expiration_time = datetime.fromisoformat(expiration_time)

        if expiration_time and now > expiration_time:
            session.pop('user_id', None)
            session.pop('expiration_time', None)
            flash("세션이 만료되었습니다. 다시 로그인해 주세요.")
            return redirect(url_for('index'))


# 관리자 페이지 접근제어 함수 
def admin_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not session.get('is_admin'):
            abort(404)  # 404 에러로 서비스 존재여부 위장 처리 
        return f(*args, **kwargs)
    return wrapper



#=================================================================
#                     참여 중인 채팅 방 조회 함수
#=================================================================
@app.context_processor
def inject_chat_rooms():
    if 'user_id' not in session:
        return {}

    db = get_db()
    cursor = db.cursor()

    # 1. 내가 속한 채팅방 조회
    cursor.execute("""
        SELECT * FROM chat_rooms 
        WHERE user1_id = ? OR user2_id = ?
    """, (session['user_id'], session['user_id']))
    
    rooms_raw = cursor.fetchall()
    chat_rooms = []

    for room in rooms_raw:
        # 상대 유저 ID 계산
        my_id = session['user_id']
        partner_id = room['user2_id'] if room['user1_id'] == my_id else room['user1_id']

        # 상대 유저 이름 조회
        cursor.execute("SELECT username FROM user WHERE id = ?", (partner_id,))
        partner = cursor.fetchone()
        partner_name = partner['username'] if partner else '알 수 없음'

        # 딕셔너리로 조합
        chat_rooms.append({
            'id': room['id'],
            'partner_id': partner_id,
            'partner_name': partner_name,
            'created_at': room['created_at']
        })

    return {'chat_rooms': chat_rooms}



#=================================================================
#                          index 
#=================================================================
@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('index.html')




#=================================================================
#                      일반 유저 사용자 조회 
#=================================================================
@app.route('/search_user')
def search_user():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    status = status_check(session['user_id'])
    if status['status'] == 0:
        session.pop('user_id', None)
        flash("정지된 계정 입니다.")
        return redirect(url_for("index"))

    query = request.args.get('q', '').strip()
    db = get_db()
    cursor = db.cursor()

    # 사용자명 또는 등록한 상품명(title) 기준으로 사용자 조회
    cursor.execute("""
        SELECT DISTINCT u.username
        FROM user u
        LEFT JOIN product p ON u.id = p.seller_id
        WHERE u.username LIKE ? OR p.title LIKE ?
        LIMIT 10
    """, (f"%{query}%", f"%{query}%"))

    users = cursor.fetchall()
    return jsonify([dict(u) for u in users])

#=================================================================
#                           회원 가입 
#=================================================================
@app.route('/register', methods=['GET', 'POST'])
def register():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        created_ip = request.remote_addr  # 클라이언트 IP 주소
        created_at = datetime.now().isoformat()

        # 아이디 비밀번호 유효성 검사 
        if not (username):
            flash('아이디는 4~20자의 영문자, 숫자, 밑줄만 가능합니다.')
            return redirect(url_for('register'))
        if not is_valid_password(password):
            flash('비밀번호는 8자 이상이고, 대소문자/숫자/특수문자를 포함해야 합니다.')
            return redirect(url_for('register'))

        password = generate_password_hash(password) # 비밀 번호 암호화
        db = get_db()
        cursor = db.cursor()

        # 사용자 중복 여부 체크
        cursor.execute("SELECT * FROM user WHERE username = ?", (username,))
        if cursor.fetchone() is not None:
            flash('이미 존재하는 사용자명입니다.')
            return redirect(url_for('register'))
        
        # 계정 등록
        user_id = str(uuid.uuid4())
        cursor.execute("INSERT INTO user (id, username, password, privilege, status, decl, created_ip, created_at) VALUES (?, ?, ?, 0, 1, 0, ?, ?)",
                       (user_id, username, password, created_ip, created_at))
        db.commit()

        flash('회원가입이 완료되었습니다. 로그인 해주세요.')
        return redirect(url_for('index'))
    return render_template('register.html')




#=================================================================
#                          로그인
#=================================================================
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        db = get_db()
        cursor = db.cursor()
        cursor.execute("SELECT * FROM user WHERE username = ?", (username,))
        user = cursor.fetchone()

        # 계정 정지 여부 및 비밀 번호 일치 여부 
        if user:
            # 사용자 계정 
            if user['lock_time'] > datetime.now().timestamp():
                lock_time_remaining = datetime.fromtimestamp(user['lock_time']) - datetime.now()
                flash(f"계정이 잠겨 있습니다. {lock_time_remaining.seconds // 60}분 후에 다시 시도하세요.")
                return redirect(url_for('index'))
            
            stored_password = user['password']
            if user['status'] == 1 and check_password_hash(stored_password, password):
                # 로그인 실패 횟수 초기화 
                cursor.execute("UPDATE user SET failed_attempts = 0 WHERE username = ?", (username,))
                db.commit()

                # 세션 만료 시간 적용 45분 
                session['user_id'] = user['id']
                session['is_admin'] = (user['privilege'] == 1) # 관리자 계정 로그인시 True
                session.permanent = True
                app.permanent_session_lifetime = timedelta(minutes=45)
                session['expiration_time'] = (datetime.utcnow() + timedelta(minutes=45)).isoformat()

                return redirect(url_for('dashboard'))
            else:
                # 로그인 실패 횟수 조회
                failed_attempts = user['failed_attempts'] + 1

                if failed_attempts >= 5: # 5번 이상의 잘못된 로그인 시도 발생시 로그인 기능 10분 정지 (무차별 대입 공격 방지 목적)
                    lock_time = datetime.now() + timedelta(minutes=10)  
                    cursor.execute("UPDATE user SET failed_attempts = ?, lock_time = ? WHERE username = ?", 
                                   (failed_attempts, lock_time.timestamp(), username))
                    db.commit()
                    flash('잘못된 비밀번호가 5회 입력되었습니다. 계정이 잠겼습니다. 10분 후에 다시 시도해주세요.')
                else:
                    cursor.execute("UPDATE user SET failed_attempts = ? WHERE username = ?", (failed_attempts, username))
                    db.commit()
                return redirect(url_for("index"))
            


        return render_template('index.html')




#=================================================================
#                           로그아웃 
#=================================================================
@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('로그아웃되었습니다.')
    return redirect(url_for('index'))





#=================================================================
#                           Dashboard 
#=================================================================
@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('index'))
    status = status_check(session['user_id'])
    if status['status'] == 0:
        session.pop('user_id', None)
        flash("정지된 계정 입니다.")
        return redirect(url_for("index"))
    
    user_id = session['user_id']
    db = get_db()
    cursor = db.cursor()

    # 현재 사용자 조회
    cursor.execute("SELECT * FROM user WHERE id = ?", (session['user_id'],))
    current_user = cursor.fetchone()


    # 상품 검색 처리 
    search_query = request.args.get('search_query', '')
    if search_query:
        cursor.execute("SELECT * FROM product WHERE title LIKE ?", ('%' + search_query + '%',))
    else:
        cursor.execute("SELECT * FROM product")
    all_products = cursor.fetchall()

    return render_template('dashboard.html', products=all_products, user=current_user)






#=================================================================
#                        사용자 프로필 
#=================================================================
@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if 'user_id' not in session:
        return redirect(url_for('index'))
    status = status_check(session['user_id'])
    if status['status'] == 0:
        session.pop('user_id', None)
        flash("정지된 계정 입니다.")
        return redirect(url_for("index"))
    
    db = get_db()
    cursor = db.cursor()
    if request.method == 'POST':
        bio = request.form.get('bio', '')
        # 소개글 길이 검사 
        if len(bio) > 500:
            flash("소개글은 500자 이하로 작성해주세요.")
            return redirect(url_for('profile'))

        cursor.execute("UPDATE user SET bio = ? WHERE id = ?", (bio, session['user_id']))
        db.commit()
        flash('프로필이 업데이트되었습니다.')
        return redirect(url_for('profile'))
    cursor.execute("SELECT * FROM user WHERE id = ?", (session['user_id'],))
    current_user = cursor.fetchone()
    return render_template('profile.html', user=current_user)





#=================================================================
#                           상품 등록
#=================================================================
@app.route('/product/new', methods=['GET', 'POST'])
def new_product():
    if 'user_id' not in session:
        return redirect(url_for('index'))
    status = status_check(session['user_id'])
    if status['status'] == 0:
        session.pop('user_id', None)
        flash("정지된 계정 입니다.")
        return redirect(url_for("index"))

    if request.method == 'POST':
        title = request.form['title'].strip()
        description = request.form['description'].strip()
        price = request.form['price'].strip()
        f = request.files.get('file')



        # 파일 헤더 시그니처 검사 (webshell 업로드 등 파일 업로드 공격 방지 목적)
        if f:
            if not is_valid_image(f):
                flash('유효하지 않은 이미지 파일입니다.')
                return redirect(url_for('new_product'))

        # 유효성 검사 (제목, 설명, 가격, file 확장자) 등 검사  <유효하지 않은 값으로 인한 버그 방지 목적적>
        errors = []
        if not title or len(title) > 100:
            errors.append("제목은 1자 이상 100자 이하여야 합니다.")
        if not description or len(description) < 10 or len(description) > 1000:
            errors.append("설명은 10자 이상 1000자 이하여야 합니다.")
        if not price or not price.replace('.', '', 1).isdigit() or float(price) < 0:
            errors.append("가격은 0 이상의 숫자여야 합니다.")
        if f:
            if not allowed_file(f.filename):
                errors.append("이미지는 PNG, JPG, JPEG, GIF 형식만 가능합니다.")

        if errors:
            for error in errors:
                flash(error)
            return redirect(url_for('new_product'))

        # 상품 사진 저장 
        if f:
            filename = secure_filename(f.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            f.save(file_path)
            image_path_for_db = f'uploads/{filename}'
        else:
            image_path_for_db = None


        # 상품 데이터 저장 
        db = get_db()
        cursor = db.cursor()
        product_id = str(uuid.uuid4())
        cursor.execute(
            """
            INSERT INTO product 
            (id, title, description, price, seller_id, decl, image)
            VALUES (?, ?, ?, ?, ?, 0, ?)
            """,
            (product_id, title, description, float(price), session['user_id'], image_path_for_db)
        )
        db.commit()

        flash('상품이 등록되었습니다.')
        return redirect(url_for('dashboard'))

    return render_template('new_product.html')








#=================================================================
#                         상품 상세 정보
#=================================================================
@app.route('/product/<product_id>')
def view_product(product_id):
    if 'user_id' not in session:
        return redirect(url_for('index'))
    status = status_check(session['user_id'])
    if status['status'] == 0:
        session.pop('user_id', None)
        flash("정지된 계정 입니다.")
        return redirect(url_for("index"))

    db = get_db()
    cursor = db.cursor()

    # 상품 정보 조회 (상품 상세 정보 출력 목적적)
    cursor.execute("SELECT * FROM product WHERE id = ?", (product_id,))
    product = cursor.fetchone()
    if not product:
        flash('상품을 찾을 수 없습니다.')
        return redirect(url_for('dashboard'))
    
    # 판매자 정보 조회 (상품 수정, 삭제 기능 구현 목적)
    cursor.execute("SELECT * FROM user WHERE id = ?", (product['seller_id'],))
    seller = cursor.fetchone()
    return render_template('view_product.html', product=product, seller=seller)





#=================================================================
#                           상품 수정 
#=================================================================
@app.route('/product/<product_id>/edit', methods=['GET', 'POST'])
def edit_product(product_id):
    if 'user_id' not in session:
        return redirect(url_for('index'))
    status = status_check(session['user_id'])
    if status['status'] == 0:
        session.pop('user_id', None)
        flash("정지된 계정 입니다.")
        return redirect(url_for("index"))

    db = get_db()
    cursor = db.cursor()

    # 수정 할 상품 정보 조회 
    cursor.execute("SELECT * FROM product WHERE id = ?", (product_id,))
    product = cursor.fetchone()

    # 유효하지 않은 조회 결과 처리
    if not product:
        flash("상품을 찾을 수 없습니다.")
        return redirect(url_for('dashboard'))

    # 수정 권한 확인 
    if (product['seller_id'] != session['user_id']) and (not session.get('is_admin')):
        flash("수정 권한이 없습니다.")
        return redirect(url_for('dashboard'))


    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        price = request.form['price']
        f = request.files.get('file')

        # 이미지 파일 헤더 시그니처 검사 (web shell 등 파일 업로드 공격 방지 목적)
        if f:
            if not is_valid_image(f):
                flash('유효하지 않은 이미지 파일입니다.')
                return redirect(url_for('edit_product'))


        # 입력 값에 대한 유효성 검사 (제목, 설명, 가격, 파일 확장자 등)
        errors = []
        if not title or len(title) > 100:
            errors.append("제목은 1자 이상 100자 이하여야 합니다.")
        if not description or len(description) < 10 or len(description) > 1000:
            errors.append("설명은 10자 이상 1000자 이하여야 합니다.")
        if not price or not price.replace('.', '', 1).isdigit() or float(price) < 0:
            errors.append("가격은 0 이상의 숫자여야 합니다.")
        if f and not allowed_file(f.filename):
            errors.append("이미지 형식이 올바르지 않습니다.")

        if errors:
            for error in errors:
                flash(error)
            return redirect(url_for('edit_product', product_id=product_id))


        # 이미지 업데이트
        image_path = product['image']
        if f and is_valid_image(f):
            filename = secure_filename(f.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            f.save(file_path)
            image_path = f'uploads/{filename}'

        # 데이터 업데이트 
        cursor.execute(
            "UPDATE product SET title = ?, description = ?, price = ?, image = ? WHERE id = ?",
            (title, description, price, image_path, product_id)
        )
        db.commit()
        flash("상품이 수정되었습니다.")
        return redirect(url_for('view_product', product_id=product_id))

    return render_template('edit_product.html', product=product)





#=================================================================
#                           상품 삭제 
#================================================================= 
@app.route('/product/<product_id>/delete', methods=['POST'])
def delete_product(product_id):
    if 'user_id' not in session:
        return redirect(url_for('index'))
    status = status_check(session['user_id'])
    if status['status'] == 0:
        session.pop('user_id', None)
        flash("정지된 계정 입니다.")
        return redirect(url_for("index"))

    db = get_db()
    cursor = db.cursor()

    # 상품 정보 조회 (삭제 상품 확인 및 권한 검사 목적)
    cursor.execute("SELECT * FROM product WHERE id = ?", (product_id,))
    product = cursor.fetchone()

    # 유효하지 않은 결과 처리
    if not product:
        flash("상품이 존재하지 않습니다.")
        return redirect(url_for('dashboard'))

    # 사용자 권한 확인 
    if (product['seller_id'] != session['user_id']) and (not session.get('is_admin')):
        flash("삭제 권한이 없습니다.")
        return redirect(url_for('dashboard'))

    cursor.execute("DELETE FROM product WHERE id = ?", (product_id,))
    db.commit()
    flash("상품이 삭제되었습니다.")
    return redirect(url_for('dashboard'))



#=================================================================
#                        상품 구입 (금액 송금)
#=================================================================
@app.route('/product/<product_id>/buy', methods=['POST'])
def buy_product(product_id):
    if 'user_id' not in session:
        return redirect(url_for('index'))
    status = status_check(session['user_id'])
    if status['status'] == 0:
        session.pop('user_id', None)
        flash("정지된 계정 입니다.")
        return redirect(url_for("index"))

    db = get_db()
    cursor = db.cursor()

    # 상품 정보 조회 ()
    cursor.execute("SELECT * FROM product WHERE id = ?", (product_id,))
    product = cursor.fetchone()
    price = int(float(product['price']))

    # 유효 하지 안은 결과, 동일한 사용자의 상품 게시 및 구매 등을 확인 
    if not product or product['seller_id'] == session['user_id']:
        flash("구입할 수 없습니다.")
        return redirect(url_for('dashboard'))

    # 사용저의 보유 잔액과 상품 가격 비교
    cursor.execute("SELECT * FROM user WHERE id = ?", (str(session['user_id']), ))
    buyer = cursor.fetchone()


    if  buyer['balance'] < price:
        flash("잔액이 부족합니다.")
        return redirect(url_for('dashboard'))

    # 구매자 자산 감소 
    cursor.execute("UPDATE user set balance = balance-? WHERE id = ?", (price, str(session['user_id'])))
    db.commit()

    # 판매자 자산 증가
    cursor.execute("UPDATE user set balance = balance+? WHERE id = ?", (price, product['seller_id']))
    db.commit()

    flash("상품을 구입했습니다.")
    return redirect(url_for('dashboard'))


#=================================================================
#                         카트(장바구니)
#=================================================================
@app.route('/cart')
def view_cart():
    if 'user_id' not in session:
        return redirect(url_for('index'))
    status = status_check(session['user_id'])
    if status['status'] == 0:
        session.pop('user_id', None)
        flash("정지된 계정 입니다.")
        return redirect(url_for("index"))
    
    db = get_db()
    cursor = db.cursor()

    # 카트의 정보를 토대로 상품 정보 조회 
    cursor.execute("""
        SELECT p.* FROM cart c
        JOIN product p ON c.product_id = p.id
        WHERE c.user_id = ?
    """, (session['user_id'],))
    products = cursor.fetchall()

    return render_template('cart.html', products=products)



#=================================================================
#                           카트 담기
#=================================================================
@app.route('/add_to_cart/<product_id>', methods=['POST'])
def add_to_cart(product_id):
    if 'user_id' not in session:
        return redirect(url_for('index'))
    status = status_check(session['user_id'])
    if status['status'] == 0:
        session.pop('user_id', None)
        flash("정지된 계정 입니다.")
        return redirect(url_for("index"))

    db = get_db()
    cursor = db.cursor()

    # 이미 장바구니에 있는지 확인
    cursor.execute("SELECT * FROM cart WHERE user_id = ? AND product_id = ?", (session['user_id'], product_id))
    if cursor.fetchone():
        flash("이미 장바구니에 담긴 상품입니다.")
        return redirect(url_for('dashboard'))

    # 구입한 상품 정보 및 사용자 정보 저장 
    cart_id = str(uuid.uuid4())
    cursor.execute(
        "INSERT INTO cart (id, user_id, product_id, created_at) VALUES (?, ?, ?, ?)",
        (cart_id, session['user_id'], product_id, datetime.now().isoformat())
    )
    db.commit()
    flash("장바구니에 상품을 담았습니다.")
    return redirect(url_for('dashboard'))



#=================================================================
#                        카트 상품 삭제
#=================================================================
@app.route('/remove_from_cart/<product_id>', methods=['POST'])
def remove_from_cart(product_id):
    if 'user_id' not in session:
        return redirect(url_for('index'))
    status = status_check(session['user_id'])
    if status['status'] == 0:
        session.pop('user_id', None)
        flash("정지된 계정 입니다.")
        return redirect(url_for("index"))

    db = get_db()
    cursor = db.cursor()

    # 사용자 정보를 토대로 카트의 상품 정보를 삭제 
    cursor.execute("DELETE FROM cart WHERE user_id = ? AND product_id = ?", (session['user_id'], product_id))
    db.commit()
    flash("장바구니에서 제거했습니다.")
    return redirect(url_for('view_cart'))



#=================================================================
#                        사용자, 게시물 신고 
#=================================================================
@app.route('/report', methods=['GET', 'POST'])
def report():
    if 'user_id' not in session:
        return redirect(url_for('index'))
    status = status_check(session['user_id'])
    if status['status'] == 0:
        session.pop('user_id', None)
        flash("정지된 계정 입니다.")
        return redirect(url_for("index"))


    if request.method == 'POST':
        db = get_db()
        cursor = db.cursor()
        if request.form['select']:
            option = request.form['select']
            if option == "user":
                tar_user = request.form["target_id"]
                cursor.execute("SELECT id FROM user WHERE username = ?", (tar_user, ))
                user = cursor.fetchone()
                if not user:
                    flash("존재하지 않는 사용자 입니다.")
                    return redirect(url_for("report"))
                cursor.execute("UPDATE user SET decl=1 WHERE username=?", (tar_user, ))
                db.commit()
                target_id = user['id']
                reason = request.form['reason']
                db = get_db()
                cursor = db.cursor()
                report_id = str(uuid.uuid4())
                cursor.execute(
                    "INSERT INTO report (id, reporter_id, target_id, reason) VALUES (?, ?, ?, ?)",
                    (report_id, session['user_id'], target_id, reason)
                )
                db.commit()
                flash('신고가 접수되었습니다.')
                return redirect(url_for('dashboard'))

            if option == "product":
                tar_product = request.form['target_id']
                cursor.execute("SELECT seller_id FROM product WHERE title = ?", (tar_product, ))
                product = cursor.fetchone()
                if not product:
                    flash("존재하지 않는 상품 입니다.")
                    return redirect(url_for("report"))
                cursor.execute("UPDATE product SET decl=decl+1 WHERE seller_id=? and title=?", (str(product['seller_id']), tar_product))
                db.commit()
                target_id = product['seller_id']
                reason = request.form['reason']
                db = get_db()
                cursor = db.cursor()
                report_id = str(uuid.uuid4())
                cursor.execute(
                    "INSERT INTO report (id, reporter_id, target_id, reason) VALUES (?, ?, ?, ?)",
                    (report_id, session['user_id'], target_id, reason)
                )
                db.commit()
                flash('신고가 접수되었습니다.')
                return redirect(url_for('dashboard'))

            if not (option == 'user' or option == 'product'):
                flash("대상이 올바르지 않습니다.")
                return redirect(url_for("report"))

    return render_template('report.html')




#=================================================================
#                        관리자 페이지 
#=================================================================
@app.route('/admin_test', methods=['GET', 'POST'])
@admin_required
def admin_test():
        

    query = '''SELECT u.id AS user_id, u.username, u.password, u.privilege, u.status, u.decl AS user_decl, u.bio, 
               p.id AS product_id, p.title, p.description, p.price, p.seller_id, p.decl AS product_decl, p.image, 
               r.id AS report_id, r.reason AS report_reason 
               FROM user u 
               LEFT JOIN product p ON u.id = p.seller_id 
               LEFT JOIN report r ON p.id = r.target_id 
               WHERE u.username LIKE ? OR p.title LIKE ? OR u.status LIKE ?;'''

    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM user")
    all_user = cursor.fetchall()
    cursor.execute("SELECT * FROM product")
    all_product = cursor.fetchall()

    if request.args.get('query', ''):
        search = request.args.get('query')
        cursor.execute(query, ('%' + search + '%', '%' + search + '%', '%' + search + '%'))
        rows = cursor.fetchall()
        if rows:
            result = []
            for row in rows:
                result.append({
                    'user_id': row['user_id'],
                    'username': row['username'],
                    'password': row['password'],
                    'privilege': row['privilege'],
                    'status': row['status'],
                    'user_decl': row['user_decl'],
                    'bio': row['bio'],
                    'product_id': row['product_id'],
                    'title': row['title'],
                    'description': row['description'],
                    'price': row['price'],
                    'seller_id': row['seller_id'],
                    'product_decl': row['product_decl'],
                    'image': row['image'],
                    'report_id': row['report_id'],
                    'report_reason': row['report_reason']
                })
            return jsonify({'data': result})
        else:
            flash("No results found.")
            return render_template("admin_test.html", users=all_user, products=all_product)

    return render_template("admin_test.html", users=all_user, products=all_product)



#=================================================================
#                         신고 내역 확인
#=================================================================
@app.route('/admin/reports', methods=['GET'])
@admin_required
def reports():
    try:
        db = get_db()
        cursor = db.cursor()
        
        # 신고 목록 조회
        cursor.execute("""
            SELECT 
                r.id AS report_id,
                r.reporter_id,
                r.target_id,
                r.reason AS report_reason,
                COALESCE(u1.username, 'Unknown') AS reporter_username, 
                COALESCE(u2.username, 'Unknown') AS target_username
            FROM report r
            LEFT JOIN user u1 ON r.reporter_id = u1.id
            LEFT JOIN user u2 ON r.target_id = u2.id
            ORDER BY r.id DESC;
        """)
        
        reports = cursor.fetchall()
        
        return render_template('reports.html', reports=reports)
    
    except Exception as e:
        print(f"Error occurred: {e}")
        return render_template('error.html', message="Failed to load reports.")


#=================================================================
#                    신고 내역 조회 상세 조회회
#=================================================================
@app.route('/admin/view_report/<report_id>', methods=['GET'])
@admin_required
def view_report(report_id):
    db = get_db()
    cursor = db.cursor()

    # 신고 ID로 신고 상세 정보 조회
    cursor.execute("""
        SELECT 
            r.id AS report_id,
            r.reporter_id,
            r.target_id,
            r.reason AS report_reason,
            u1.username AS reporter_username, 
            u2.username AS target_username
        FROM report r
        LEFT JOIN user u1 ON r.reporter_id = u1.id
        LEFT JOIN user u2 ON r.target_id = u2.id
        WHERE r.id = ?
    """, (report_id,))
    
    report = cursor.fetchone()
    
    if report:
        # 신고 상세 정보를 view_report.html로 전달
        return render_template('view_report.html', report=report)
    else:
        # 신고 정보를 찾을 수 없을 경우 에러 페이지 표시
        return "신고를 찾을 수 없습니다.", 404


#=================================================================
#                 사용자 상세 정보 (ip, 생성 시간 등)
#=================================================================
@app.route('/admin/user_logs')
@admin_required
def user_logs():
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT id, username, created_ip, created_at, decl FROM user ORDER BY created_at DESC")
    users = cursor.fetchall()
    return render_template('user_logs.html', users=users)


#=================================================================
#                         사용자 계정 삭제
#=================================================================
@app.route("/admin/user_delete", methods=["GET"])
@admin_required
def delete_user():
    del_target = request.args.get('del')
    if del_target:
        db = get_db()
        cursor = db.cursor()
        cursor.execute("DELETE FROM user WHERE id = ?", (del_target,))
        db.commit()
        flash("사용자 계정이 삭제되었습니다.")
    return redirect(url_for("admin_test"))


#=================================================================
#                           게시물 삭제 
#=================================================================
@app.route("/admin/content_delete", methods=["GET"])
@admin_required
def delete_content():
    del_content = request.args.get('pro_id')
    if del_content:
        db = get_db()
        cursor = db.cursor()
        cursor.execute("DELETE FROM product WHERE id = ?", (del_content,))
        db.commit()
        flash("상품이 삭제되었습니다.")
    return redirect(url_for("admin_test"))



#=================================================================
#                      사용자 계정 정지 
#=================================================================
@app.route("/user_freezing", methods=["GET"])
@admin_required
def user_freezing():
    user_id = request.args.get('sleep')
    if user_id:
        db = get_db()
        cursor = db.cursor()
        cursor.execute("UPDATE user SET status = 0 WHERE id = ?", (user_id,))
        db.commit()
        flash("사용자가 휴면 상태로 변경되었습니다.")
    return redirect(url_for("admin_test"))


#=================================================================
#                      사용자 계정 정지 해제
#=================================================================
@app.route("/user_wakeup", methods=["GET"])
@admin_required
def user_wakeup():
    user_id = request.args.get("wakeup")
    if user_id:
        db = get_db()
        cursor = db.cursor()
        cursor.execute("UPDATE user SET status = 1 WHERE id = ?", (user_id,))
        db.commit()
        flash("사용자의 휴면 상태가 해제되었습니다.")
    return redirect(url_for("admin_test"))


#=================================================================
#                      신고 내역 삭제
#=================================================================
@app.route("/report_delete", methods=["POST"])
@admin_required
def report_delete():
    del_report = request.form.get('del_report')
    if del_report:
        db = get_db()
        cursor = db.cursor()
        cursor.execute("DELETE FROM report WHERE id = ?", (del_report,))
        db.commit()
        flash("신고가 삭제되었습니다.")
    return redirect(url_for("reports"))


#=================================================================
#                      비밀 번호 변경 
#=================================================================
@app.route("/profile/change_password", methods=["POST"])
def change_password():
    if request.method == "POST":
        new_pw = request.form['new_password']

        hashed_pw = generate_password_hash(new_pw) # 비밀 번호 암호화 
        db = get_db()
        cursor = db.cursor()
        cursor.execute("UPDATE user SET password=? WHERE id = ?", (hashed_pw, session['user_id']))
        db.commit()
        flash("password change success!!")
        return redirect(url_for('profile'))



#=================================================================
#                        1대1 채팅 방 생성
#=================================================================
@app.route('/start_chat/<other_id>')
def start_chat(other_id):
    if 'user_id' not in session:
        return redirect(url_for('index'))
    status = status_check(session['user_id'])
    if status['status'] == 0:
        session.pop('user_id', None)
        flash("정지된 계정 입니다.")
        return redirect(url_for("index"))

    user_id = session['user_id']
    if user_id == other_id:
        flash("자기 자신과는 채팅할 수 없습니다.")
        return redirect(url_for('dashboard'))

    db = get_db()
    cursor = db.cursor()

    # 채팅 방 존재 여부 확인 
    cursor.execute("""
        SELECT id FROM chat_rooms 
        WHERE (user1_id = ? AND user2_id = ?) 
        OR (user1_id = ? AND user2_id = ?)
    """, (user_id, other_id, other_id, user_id))
    room = cursor.fetchone()

    # 채팅 방이 존재하지 않는다면, 생성
    if not room:
        room_id = str(uuid.uuid4())
        cursor.execute("INSERT INTO chat_rooms (id, user1_id, user2_id) VALUES (?, ?, ?)", (room_id, user_id, other_id))
        db.commit()
    else:
        room_id = room['id']

    return redirect(url_for('chat_room', room_id=room_id))



#=================================================================
#                           1대1 채팅 방 
#=================================================================
@app.route('/chat_room/<room_id>')
def chat_room(room_id):
    if 'user_id' not in session:
        return redirect(url_for('index'))
    status = status_check(session['user_id'])
    if status['status'] == 0:
        session.pop('user_id', None)
        flash("정지된 계정 입니다.")
        return redirect(url_for("index"))

    user_id = session['user_id']
    db = get_db()
    cursor = db.cursor()

    # 유저가 참여한 채팅방인지 확인
    cursor.execute("""
        SELECT * FROM chat_rooms 
        WHERE id = ? AND (user1_id = ? OR user2_id = ?)
    """, (room_id, user_id, user_id))
    room = cursor.fetchone()

    if not room:
        flash("접근 권한이 없습니다.")
        return redirect(url_for('dashboard'))

    # 채팅 기록 가져온 후 반영 
    cursor.execute("SELECT * FROM messages WHERE room_id = ? ORDER BY timestamp", (room_id,))
    messages = cursor.fetchall()

    cursor.execute("SELECT username FROM user WHERE id=?", (user_id,))
    username = cursor.fetchone()
    username = username[0]
    

    return render_template('chat_room.html', messages=messages, room=room, user_id=username)





#=================================================================
#                         1대1 채팅 방 삭제  
#=================================================================
@app.route('/leave_chat/<room_id>', methods=['POST'])
def leave_chat(room_id):
    if 'user_id' not in session:
        return redirect(url_for('index'))

    user_id = session['user_id']
    db = get_db()
    cursor = db.cursor()

    # 채팅방 확인
    cursor.execute("SELECT * FROM  WHERE id = ?", (room_id,))
    room = cursor.fetchone()

    if not room or (room['user1_id'] != user_id and room['user2_id'] != user_id):
        flash("잘못된 요청입니다.")
        return redirect(url_for('dashboard'))

    # 대화 내용 삭제
    cursor.execute("DELETE FROM messages WHERE room_id = ?", (room_id,))
    
    # 채팅 방 삭제 
    cursor.execute("DELETE FROM chat_rooms WHERE id = ?", (room_id,))
    db.commit()

    flash("채팅방을 나갔습니다.")
    return redirect(url_for('dashboard'))




#=================================================================
#                           전체 채팅 소켓 
#=================================================================
@socketio.on('send_message')
def handle_send_message_event(data):
    print(data)
    data['message_id'] = str(uuid.uuid4())
    send(data, broadcast=True)



#=================================================================
#                     1대1 채팅 소켓 (room 생성) 
#=================================================================
@socketio.on('join_room')
def handle_join_room(room_id):
    join_room(room_id)
    print(f"Socket joined room {room_id}")




#=================================================================
#                    1대1 채팅 소켓 (message 교환) 
#=================================================================
@socketio.on('chat_message')
def handle_chat_message(data):
    room_id = data['room_id']
    sender_id = data['sender_id']
    message = data['message']

    # 대화 내용 저장 (채팅방 나가기 전 까지 메세지 유지)
    db = get_db()
    cursor = db.cursor()
    cursor.execute("INSERT INTO messages (room_id, sender_id, message) VALUES (?, ?, ?)",(room_id, sender_id, message))
    db.commit()

    # 동일한 채팅방의 유저 사이의 메세지 교환 
    emit('chat_message', data, room=room_id)




if __name__ == '__main__':
    init_db()  
    socketio.run(app, debug=False) # 실제 서비스 할 때, debug 모드 False로 변경  
