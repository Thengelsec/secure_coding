import sqlite3
import uuid
from flask import Flask, render_template, request, redirect, url_for, session, flash, g
from flask_socketio import SocketIO, send

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret!'
DATABASE = 'market.db'
socketio = SocketIO(app)

# 데이터베이스 연결 관리: 요청마다 연결 생성 후 사용, 종료 시 close
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
                bio TEXT,
                cash INTEGER DEFAULT 0,
                ban INTEGER DEFAULT 0,
                is_admin INTEGER DEFAULT 0
            )
        """)
        # 상품 테이블 생성
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS product (
                id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                description TEXT NOT NULL,
                price TEXT NOT NULL,
                seller_id TEXT NOT NULL
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

# 전체 페이지 user 정보 관리
@app.before_request
def load_user():
    g.user = None
    if 'user_id' in session:
        db = get_db()
        cursor = db.cursor()
        cursor.execute("""
            SELECT id, username, bio, cash, ban, is_admin
            FROM user WHERE id = ?
        """, (session['user_id'],))
        g.user = cursor.fetchone()

# 템플릿 user 자동 사용
@app.context_processor
def inject_user():
    return dict(user=g.user)

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
        cursor.execute("INSERT INTO user (id, username, password) VALUES (?, ?, ?)",
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
            if user['ban'] == 1:
                flash('정지된 계정입니다.')
                return redirect(url_for('login'))
            session['user_id'] = user['id']
            flash('로그인 성공!')
            return redirect(url_for('dashboard'))
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
    db = get_db()
    cursor = db.cursor()
    # 현재 사용자 조회
    cursor.execute("SELECT * FROM user WHERE id = ?", (session['user_id'],))
    current_user = cursor.fetchone()

    # 검색기능
    keyword = request.args.get('word', '').strip()
    if keyword:
        # 키워드를 포함한 상품 제목, 설명, 가격을 모두 검색
        like = f'%{keyword}%'
        cursor.execute("""
            SELECT product.*, user.username 
            FROM product
            JOIN user ON product.seller_id = user.id
            WHERE title LIKE ? 
                OR description LIKE ? 
                OR price LIKE ?
                OR user.username LIKE ?
        """, (like, like, like, like))
    else:
        cursor.execute("SELECT * FROM product")  # 키워드 없으면 전체 조회

    all_products = cursor.fetchall()

    return render_template(
        'dashboard.html',
        products=all_products,  # 검색 결과 전달
        keyword=keyword  # 템플릿에서 검색어 재사용
    )

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
    return render_template('profile.html')

# 프로필 뷰어 페이지
@app.route('/user/<user_id>')
def view_user_profile(user_id):
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM user WHERE id = ?", (user_id,))
    user_profile = cursor.fetchone()

    if not user_profile:
        flash("사용자를 찾을 수 없습니다.")
        return redirect(url_for('dashboard'))

    return render_template('view_profile.html', target_user=user_profile)

# 상품 등록
@app.route('/product/new', methods=['GET', 'POST'])
def new_product():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        price = request.form['price']
        db = get_db()
        cursor = db.cursor()
        product_id = str(uuid.uuid4())
        cursor.execute(
            "INSERT INTO product (id, title, description, price, seller_id) VALUES (?, ?, ?, ?, ?)",
            (product_id, title, description, price, session['user_id'])
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

    # 관리자 신고 목록 조회
    reports = []
    if g.user and g.user['is_admin'] == 1:
        cursor.execute("""
            SELECT report.id, report.reason, report.reporter_id, user.username 
            FROM report
            JOIN user ON report.reporter_id = user.id
            WHERE report.target_id = ?
        """, (product_id,))
        reports = cursor.fetchall()

    return render_template(
        'view_product.html', 
        product=product, 
        seller=seller,
        reports=reports
    )

# 포인트 충전하기
@app.route('/charge', methods=['GET', 'POST'])
def charge():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    db = get_db()
    cursor = db.cursor()

    if request.method == 'POST':
        amount = int(request.form['amount'])
        cursor.execute("UPDATE user SET cash = cash + ? WHERE id = ?", (amount, session['user_id']))
        db.commit()
        flash(f'{amount}원 충전되었습니다.')
        return redirect(url_for('dashboard'))

    cursor.execute("SELECT * FROM user WHERE id = ?", (session['user_id'],))
    current_user = cursor.fetchone()

    return render_template('charge.html')

# 테스트용: 로그인한 사용자의 cash를 0으로 초기화 (나중에 삭제)#################
@app.route('/reset_cash')
def reset_cash():  # test
    if 'user_id' not in session:
        return redirect(url_for('login'))

    db = get_db()
    cursor = db.cursor()
    cursor.execute("UPDATE user SET cash = 0 WHERE id = ?", (session['user_id'],))
    db.commit()
    flash("보유 금액이 0원으로 초기화되었습니다. (테스트용 기능)")
    return redirect(url_for('dashboard'))

# 신고하기
@app.route('/report', methods=['GET', 'POST'])
def report():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        target_id = request.form['target_id']
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

# 실시간 채팅: 클라이언트가 메시지를 보내면 전체 브로드캐스트
@socketio.on('send_message')
def handle_send_message_event(data):
    data['message_id'] = str(uuid.uuid4())
    send(data, broadcast=True)

# 관리자 페이지
@app.route('/admin')
def admin_page():
    if not g.user or g.user['is_admin'] != 1:
        abort(403)

    db = get_db()
    cursor = db.cursor()

    keyword = request.args.get('q', '').strip()
    results = []

    if keyword:
        like = f"%{keyword}%"
        # 사용자 검색
        cursor.execute("SELECT id, username FROM user WHERE username LIKE ?", (like,))
        for u in cursor.fetchall():
            results.append({'type': 'User', 'id': u['id'], 'label': u['username']})
        # 상품 검색
        cursor.execute("SELECT id, title FROM product WHERE title LIKE ?", (like,))
        for p in cursor.fetchall():
            results.append({'type': 'Product', 'id': p['id'], 'label': p['title']})
    else:
        # 검색어 없으면 전체 목록
        cursor.execute("SELECT id, username FROM user")
        for u in cursor.fetchall():
            results.append({'type': 'User', 'id': u['id'], 'label': u['username']})
        cursor.execute("SELECT id, title FROM product")
        for p in cursor.fetchall():
            results.append({'type': 'Product', 'id': p['id'], 'label': p['title']})


    cursor.execute("""
        SELECT report.target_id, product.title, COUNT(*) AS report_count
        FROM report
        JOIN product ON report.target_id = product.id
        GROUP BY report.target_id
    """)
    report_summary = cursor.fetchall()

    return render_template(
        "admin.html",
        keyword=keyword,
        results=results,
        report_summary=report_summary
    )

# 관리자/본인 용 상품 페이지 삭제
@app.route('/admin/delete_product/<product_id>', methods=['POST'])
def delete_product(product_id):
    if not g.user:
        abort(403)

    db = get_db()
    cursor = db.cursor()

    # 관리자이거나 해당 상품의 게시자만 삭제 가능
    cursor.execute("SELECT seller_id FROM product WHERE id = ?", (product_id,))
    product = cursor.fetchone()
    if not product:
        flash("상품이 존재하지 않습니다.")
        return redirect(url_for('dashboard'))

    if g.user['is_admin'] != 1 and g.user['id'] != product['seller_id']:
        abort(403)

    cursor.execute("DELETE FROM report WHERE target_id = ?", (product_id,))
    cursor.execute("DELETE FROM product WHERE id = ?", (product_id,))
    db.commit()
    flash("상품 및 신고 내역이 삭제되었습니다.")
    return redirect(url_for('dashboard'))

# 관리자용 신고 삭제
@app.route('/admin/delete_report/<report_id>', methods=['POST'])
def delete_report(report_id):
    if not g.user or g.user['is_admin'] != 1:
        abort(403)
    db = get_db()
    cursor = db.cursor()
    cursor.execute("DELETE FROM report WHERE id = ?", (report_id,))
    db.commit()
    flash("신고가 삭제되었습니다.")
    return redirect(request.referrer or url_for('admin_page'))

# 관리자용 사용자 정지
@app.route('/admin/ban_user/<user_id>', methods=['POST'])
def ban_user(user_id):
    if not g.user or g.user['is_admin'] != 1:
        abort(403)

    if user_id == g.user['id']:
        flash("자기 자신은 정지할 수 없습니다.")
        return redirect(url_for('admin_page'))

    db = get_db()
    cursor = db.cursor()
    cursor.execute("UPDATE user SET ban = 1 WHERE id = ?", (user_id,))
    db.commit()
    flash("사용자가 정지되었습니다.")
    return redirect(url_for('view_user_profile', user_id=user_id))

# 관리자용 사용자 정지 해제
@app.route('/admin/unban_user/<user_id>', methods=['POST'])
def unban_user(user_id):
    if not g.user or g.user['is_admin'] != 1:
        abort(403)
    db = get_db()
    cursor = db.cursor()
    cursor.execute("UPDATE user SET ban = 0 WHERE id = ?", (user_id,))
    db.commit()
    flash("사용자 정지가 해제되었습니다.")
    return redirect(request.referrer or url_for('admin_page'))

# 테스트용 관리자 변경 나중에 삭제###########################################
@app.route('/make_admin')
def make_admin():
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT is_admin FROM user WHERE username = 'admin'")
    user = cursor.fetchone()

    if not user:
        return "admin 계정을 찾을 수 없습니다."

    new_status = 0 if user['is_admin'] == 1 else 1
    cursor.execute("UPDATE user SET is_admin = ? WHERE username = 'admin'", (new_status,))
    db.commit()

    status = "관리자 권한 부여됨 ✅" if new_status == 1 else "일반 사용자로 전환됨 ⚠️"
    return f"admin 계정: {status}"

# 포인트 , 표기 필터
@app.template_filter('comma')
def comma_format(value):
    try:
        return f"{int(value):,}"
    except (ValueError, TypeError):
        return value

if __name__ == '__main__':
    init_db()  # 앱 컨텍스트 내에서 테이블 생성
    socketio.run(app, debug=True)
