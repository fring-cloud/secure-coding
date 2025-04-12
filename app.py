import sqlite3
import uuid
import os
from werkzeug.utils import secure_filename
from flask import Flask, render_template, request, redirect, url_for, session, flash, g, abort, jsonify
from flask_socketio import SocketIO, send, join_room, leave_room, emit

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret!'
DATABASE = 'market.db'
socketio = SocketIO(app)

def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row  # 결과를 dict처럼 사용하기 위함
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

# 테이블 생성 (최초 실행 시에만)
def init_db():
    with app.app_context():
        db = get_db()
        cursor = db.cursor()
        # 사용자 테이블 생성
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS user (
                id TEXT PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                privilege INTEGER NOT NULL,
                status INTEGER NOT NULL,
                decl INTEGER NOT NULL,
                bio TEXT
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
                image TEXT
            )
        """)
        # 신고 테이블 생성
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS report (
                id TEXT PRIMARY KEY,
                reporter_id TEXT NOT NULL,
                target_id TEXT NOT NULL,
                reason TEXT NOT NULL
            )
        """)
        db.commit()


def status_check(user):
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT status FROM user WHERE id=?", (user, ))
    res = cursor.fetchone()
    return res




# 기본 라우트
@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

# 회원가입
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        db = get_db()
        cursor = db.cursor()
        # 중복 사용자 체크
        cursor.execute("SELECT * FROM user WHERE username = ?", (username,))
        if cursor.fetchone() is not None:
            flash('이미 존재하는 사용자명입니다.')
            return redirect(url_for('register'))
        user_id = str(uuid.uuid4())
        cursor.execute("INSERT INTO user (id, username, password, privilege, status, decl) VALUES (?, ?, ?, 0, 1, 0)",
                       (user_id, username, password))
        db.commit()
        flash('회원가입이 완료되었습니다. 로그인 해주세요.')
        return redirect(url_for('login'))
    return render_template('register.html')

# 로그인
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        db = get_db()
        cursor = db.cursor()
        cursor.execute("SELECT * FROM user WHERE username = ? AND password = ?", (username, password))
        user = cursor.fetchone()
        if user:
            status = status_check(user['id'])
            if status['status'] == 1:
                session['user_id'] = user['id']
                flash('로그인 성공!')
                return redirect(url_for('dashboard'))
            else:
                flash('사용 정지된 계정 입니다.')
                return redirect(url_for("login"))
        else:
            flash('아이디 또는 비밀번호가 올바르지 않습니다.')
            return redirect(url_for('login'))
    return render_template('login.html')

# 로그아웃
@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('로그아웃되었습니다.')
    return redirect(url_for('index'))

# 대시보드: 사용자 정보와 전체 상품 리스트 표시
@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    status = status_check(session['user_id'])
    if status['status'] == 0:
        session.pop('user_id', None)
        flash("정지된 계정 입니다.")
        return redirect(url_for("index"))
    db = get_db()
    cursor = db.cursor()
    # 현재 사용자 조회
    cursor.execute("SELECT * FROM user WHERE id = ?", (session['user_id'],))
    current_user = cursor.fetchone()
    # 모든 상품 조회
    cursor.execute("SELECT * FROM product")
    all_products = cursor.fetchall()
    return render_template('dashboard.html', products=all_products, user=current_user)

# 프로필 페이지: bio 업데이트 가능
@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    db = get_db()
    cursor = db.cursor()
    if request.method == 'POST':
        bio = request.form.get('bio', '')
        cursor.execute("UPDATE user SET bio = ? WHERE id = ?", (bio, session['user_id']))
        db.commit()
        flash('프로필이 업데이트되었습니다.')
        return redirect(url_for('profile'))
    cursor.execute("SELECT * FROM user WHERE id = ?", (session['user_id'],))
    current_user = cursor.fetchone()
    return render_template('profile.html', user=current_user)

# 상품 등록
@app.route('/product/new', methods=['GET', 'POST'])
def new_product():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        f = request.files['file']
        f.save('static/uploads/' + secure_filename(f.filename))


        title = request.form['title']
        description = request.form['description']
        price = request.form['price']
        db = get_db()
        cursor = db.cursor()
        product_id = str(uuid.uuid4())
        cursor.execute(
            "INSERT INTO product (id, title, description, price, seller_id, decl, image) VALUES (?, ?, ?, ?, ?, 0, ?)",
            (product_id, title, description, price, session['user_id'], 'static/uploads/' + secure_filename(f.filename))
        )
        db.commit()
        flash('상품이 등록되었습니다.')
        return redirect(url_for('dashboard'))
    return render_template('new_product.html')


# 상품 상세보기
@app.route('/product/<product_id>')
def view_product(product_id):
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM product WHERE id = ?", (product_id,))
    product = cursor.fetchone()
    if not product:
        flash('상품을 찾을 수 없습니다.')
        return redirect(url_for('dashboard'))
    # 판매자 정보 조회
    cursor.execute("SELECT * FROM user WHERE id = ?", (product['seller_id'],))
    seller = cursor.fetchone()
    return render_template('view_product.html', product=product, seller=seller)

# 신고하기
@app.route('/report', methods=['GET', 'POST'])
def report():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        db = get_db()
        cursor = db.cursor()
        if request.form['select']:
            option = request.form['select']
            print(option)
            if option == "user":
                tar_user = request.form["target_id"]
                cursor.execute("SELECT id FROM user WHERE username = ?", (tar_user, ))
                user = cursor.fetchone()
                if not user:
                    flash("존재하지 않는 사용자 입니다.")
                    return redirect(url_for("report"))
                cursor.execute("UPDATE user SET decl=1 WHERE username=?", (tar_user, ))
                db.commit()
                target_id = tar_user

            if option == "product":
                tar_product = request.form['target_id']
                cursor.execute("SELECT seller_id FROM product WHERE title = ?", (tar_product, ))
                product = cursor.fetchone()
                print(product)
                if not product:
                    flash("존재하지 않는 상품 입니다.")
                    return redirect(url_for("report"))
                cursor.execute("UPDATE product SET decl=decl+1 WHERE seller_id=? and title=?", (str(product['seller_id']), tar_product))
                db.commit()
                target_id = tar_product

            if not (option == 'user' or option == 'product'):
                flash("대상이 올바르지 않습니다.")
                return redirect(url_for("report"))


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
    return render_template('report.html')



@app.route('/admin', methods=['GET', 'POST'])
def admin():
    
    query='''SELECT u.id AS user_id, u.username, u.password, u.privilege, u.status, u.decl AS user_decl, u.bio,p.id AS product_id, p.title, p.description, p.price, p.seller_id, p.decl AS product_decl, p.image,r.id AS report_id, r.reason AS report_reason FROM user u LEFT JOIN product p ON u.id = p.seller_id LEFT JOIN report r ON p.id = r.target_id WHERE u.username LIKE ? OR p.title LIKE ?;
'''

    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM user")
    all_user = cursor.fetchall()
    cursor.execute("SELECT * FROM product") 
    all_content = cursor.fetchall()
    cursor.execute("SELECT * FROM report")
    all_report = cursor.fetchall()
    if request.method == "POST":
        if(request.form['search_user']):
            search = request.form['search_user']
            cursor.execute(query, (search, search))
            rows = cursor.fetchall()
            if(rows):
                    result = []
                    for row in rows:
                        result.append({
                            'user_id': row[0],
                            'username': row[1],
                            'password': row[2],
                            'privilege': row[3],
                            'status': row[4],
                            'user_decl': row[5],
                            'bio': row[6],
                            'product_id': row[7],
                            'title': row[8],
                            'description': row[9],
                            'price': row[10],
                            'seller_id': row[11],
                            'product_decl': row[12],
                            'image': row[13],
                            'report_id': row[14],
                            'report_reason': row[15]
                        })
                    print(result)

                    return render_template("admin.html", row=rows) 
        
 
    return render_template('admin.html',users=all_user, contents=all_content, reports=all_report)



@app.route('/admin_test', methods=['GET', 'POST'])
def admin_test():
    
    query='''SELECT u.id AS user_id, u.username, u.password, u.privilege, u.status, u.decl AS user_decl, u.bio,p.id AS product_id, p.title, p.description, p.price, p.seller_id, p.decl AS product_decl, p.image,r.id AS report_id, r.reason AS report_reason FROM user u LEFT JOIN product p ON u.id = p.seller_id LEFT JOIN report r ON p.id = r.target_id WHERE u.username LIKE ? OR p.title LIKE ?;
'''

    db = get_db()
    cursor = db.cursor()
    if(request.args.get('query', '')):
        search = request.args.get('query')
        print(search)
        cursor.execute(query, (search, search))
        rows = cursor.fetchall()
        if '' not in rows:
                result = []
                for row in rows:
                    result.append({
                        'user_id': row[0],
                        'username': row[1],
                        'password': row[2],
                        'privilege': row[3],
                        'status': row[4],
                        'user_decl': row[5],
                        'bio': row[6],
                        'product_id': row[7],
                        'title': row[8],
                        'description': row[9],
                        'price': row[10],
                        'seller_id': row[11],
                        'product_decl': row[12],
                        'image': row[13],
                        'report_id': row[14],
                        'report_reason': row[15]
                    })
                print(result)
                return jsonify({'data': result})
        else:
            print("asdasdasdadasd")
            return render_template("admin_test.html")
     
    return render_template("admin_test.html")



@app.route("/user_delete", methods=["POST"])
def delete_user():
    if request.method == "POST":
        del_target = request.form['del']
        db = get_db()
        cursor = db.cursor()
        cursor.execute("DELETE FROM user WHERE id = ?", (del_target, ))
        db.commit()
        print(f"delete user : {del_target}")
        return redirect(url_for("admin"))


@app.route("/content_delete", methods=["POST"])
def delete_content():
    if(request.method=="POST"):
        del_content = request.form['pro_id']
        db = get_db()
        cursor = db.cursor()
        cursor.execute("DELETE FROM product WHERE id = ?", (del_content, ))
        db.commit()
        print(f"delete content : {del_content}")
        return redirect(url_for("admin"))

@app.route("/user_freezing", methods=["GET"])
def user_freezing():
    if(request.method=="GET"):
        user = request.args.get('sleep')
        db = get_db()
        cursor = db.cursor()
        cursor.execute("UPDATE user SET status=0 WHERE id = ?", (user, ))
        db.commit()
        print(f"user freezing : {user}")
        return redirect(url_for("admin"))


@app.route("/user_wakeup", methods=["GET"])
def user_wakeup():
    if(request.method=="GET"):
        user = request.args.get("wakeup")
        db=get_db()
        cursor = db.cursor()
        cursor.execute("UPDATE user SET status=1 WHERE id = ?", (user, ))
        db.commit()
        print(f"wake up : {user}")
        return redirect(url_for("admin"))

@app.route("/report_delete", methods=["POST"])
def report_delete():
    if request.method == "POST":
        del_report = request.form['del_report']
        db = get_db()
        cursor = db.cursor()
        cursor.execute("DELETE FROM report WHERE id = ?", (del_report, ))
        db.commit()
        return redirect(url_for("admin"))

@app.route("/profile/change_password", methods=["POST"])
def change_password():
    if request.method == "POST":
        new_pw = request.form['new_password']
        db = get_db()
        cursor = db.cursor()
        cursor.execute("UPDATE user SET password=? WHERE id = ?", (new_pw, session['user_id']))
        db.commit()
        flash("password change success!!")
        return redirect(url_for('profile'))

    



# 실시간 채팅: 클라이언트가 메시지를 보내면 전체 브로드캐스트
@socketio.on('send_message')
def handle_send_message_event(data):
    print(data)
    data['message_id'] = str(uuid.uuid4())
    send(data, broadcast=True)


@socketio.on("join", namespace="/chat")
def join_chat(msg):
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT username FROM user WHERE id = ?", (session['user_id'], ))
    user = cursor.fetchone()
    room = session.get('room')
    join_room(room)
    emit("status", {'messages' : user['username'] + " 님이 입장하셨습니다."},room=room) 



@socketio.on("chating", namespace="/chat")
def chating(msg):
    print(msg)
    room = session.get('room')
    emit("message", msg, room=room)


if __name__ == '__main__':
    init_db()  
    socketio.run(app, debug=True)
