import sqlite3
import uuid
from flask import Flask, render_template, request, redirect, url_for, session, flash, g, abort
from flask_socketio import SocketIO, send, join_room, leave_room, emit
from datetime import datetime

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
                price INTEGER NOT NULL,
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

        # 구매기록 테이블 생성
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS purchase (
                id TEXT PRIMARY KEY,
                buyer_id TEXT NOT NULL,
                product_id TEXT NOT NULL,
                product_title TEXT NOT NULL,
                product_price TEXT NOT NULL,
                seller_id TEXT NOT NULL,
                purchased_at TEXT NOT NULL
            )
        """)

        # 채팅방 테이블
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS chat_room (
                id TEXT PRIMARY KEY,
                buyer_id TEXT NOT NULL,
                seller_id TEXT NOT NULL,
                product_id TEXT NOT NULL
            )
        """)

        # 채팅 메시지 테이블
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS chat_message (
                id TEXT PRIMARY KEY,
                room_id TEXT NOT NULL,
                sender_id TEXT NOT NULL,
                message TEXT NOT NULL,
                sent_at TEXT NOT NULL
            )
        """)

        db.commit()

# 로그인 시에만 접근 가능
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
    elif request.endpoint not in ('index', 'login', 'register', 'static'):
        return redirect(url_for('login'))

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
    db = get_db()
    cursor = db.cursor()

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
    
    cursor.execute("""
        SELECT * FROM purchase
        WHERE buyer_id = ?
        ORDER BY purchased_at DESC
    """, (session['user_id'],))
    purchases = cursor.fetchall()

    cursor.execute("""
        SELECT * FROM purchase
        WHERE seller_id = ?
        ORDER BY purchased_at DESC
    """, (session['user_id'],))
    sales = cursor.fetchall()

    return render_template(
        'profile.html',
        current_user=current_user,
        purchases=purchases,
        sales=sales
    )

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
    
    received_reports = []
    if g.user and g.user['is_admin'] == 1:
        cursor.execute("""
            SELECT 
                report.id AS report_id,
                report.reason, 
                reporter.username AS reporter_name
            FROM report
            JOIN user AS reporter ON report.reporter_id = reporter.id
            WHERE report.target_id = ?
        """, (user_id,))
        received_reports = cursor.fetchall()

    return render_template(
        'view_profile.html', 
        target_user=user_profile,
        received_reports=received_reports
    )

# 상품 등록
@app.route('/product/new', methods=['GET', 'POST'])
def new_product():
    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        price = int(request.form['price'])
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

    db = get_db()
    cursor = db.cursor()

    if request.method == 'POST':
        try:
            amount = int(request.form['amount'])
            if amount <= 0 or amount % 10000 != 0:
                flash("충전 금액은 1원 이상이어야 합니다.")
                return redirect(url_for('charge'))
        except ValueError:
            flash("유효한 숫자를 입력해주세요.")
            return redirect(url_for('charge'))

        cursor.execute("UPDATE user SET cash = cash + ? WHERE id = ?", (amount, session['user_id']))
        db.commit()
        flash(f'{amount}원 충전되었습니다.')
        return redirect(url_for('dashboard'))

    cursor.execute("SELECT * FROM user WHERE id = ?", (session['user_id'],))
    current_user = cursor.fetchone()

    return render_template('charge.html')

# 상품 구매하기
@app.route('/buy/<product_id>', methods=['POST'])
def buy_product(product_id):

    db = get_db()
    cursor = db.cursor()

    # 상품 정보 조회
    cursor.execute("SELECT * FROM product WHERE id = ?", (product_id,))
    product = cursor.fetchone()

    if not product:
        flash("상품을 찾을 수 없습니다.")
        return redirect(url_for('dashboard'))

    # 자기 자신의 상품은 구매 불가
    if product['seller_id'] == session['user_id']:
        flash("자신의 상품은 구매할 수 없습니다.")
        return redirect(url_for('view_product', product_id=product_id))

    # 구매자 정보 조회
    cursor.execute("SELECT cash FROM user WHERE id = ?", (session['user_id'],))
    buyer = cursor.fetchone()

    if not buyer:
        flash("사용자 정보를 찾을 수 없습니다.")
        return redirect(url_for('dashboard'))

    # 잔액 확인
    price = int(product['price'])
    if buyer['cash'] < price:
        flash("보유 금액이 부족합니다.")
        return redirect(url_for('view_product', product_id=product_id))

    # 거래 처리
    new_id = str(uuid.uuid4())
    cursor.execute("""
    INSERT INTO purchase (
        id, buyer_id, product_id,
        product_title, product_price,
        seller_id, purchased_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (
        new_id,
        session['user_id'],
        product['id'],
        product['title'],
        product['price'],
        product['seller_id'],
        datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    ))

    # 구매자 금액 차감
    cursor.execute("""
        UPDATE user SET cash = cash - ? WHERE id = ?
        """, 
        (price, session['user_id'])
    )

    # 판매자 금액 증가
    cursor.execute("""
        UPDATE user SET cash = cash + ? WHERE id = ?
        """, (price, product['seller_id'])
    )

    cursor.execute("""
        DELETE FROM product WHERE id = ?
        """, 
        (product_id,)
    )

    db.commit()
    flash("상품이 성공적으로 구매되었습니다.")
    return redirect(url_for('dashboard'))

# 테스트용: 로그인한 사용자의 cash를 0으로 초기화 (나중에 삭제)#################
@app.route('/reset_cash')
def reset_cash():  # test

    db = get_db()
    cursor = db.cursor()
    cursor.execute("UPDATE user SET cash = 0 WHERE id = ?", (session['user_id'],))
    db.commit()
    flash("보유 금액이 0원으로 초기화되었습니다. (테스트용 기능)")
    return redirect(url_for('dashboard'))

# 신고하기
@app.route('/report', methods=['GET', 'POST'])
def report():

    db = get_db()
    cursor = db.cursor()

    if request.method == 'POST':
        target_input = request.form['target_id'].strip()
        reason = request.form['reason']
        report_id = str(uuid.uuid4())
        target_id = None

        # 1. 상품 ID로 조회
        cursor.execute("SELECT id FROM product WHERE id = ?", (target_input,))
        product = cursor.fetchone()
        if product:
            target_id = product['id']
        else:
            # 2. 사용자 이름으로 조회
            cursor.execute("SELECT id FROM user WHERE username = ?", (target_input,))
            user = cursor.fetchone()
            if user:
                target_id = user['id']

        if not target_id:
            flash("해당 사용자명 또는 상품ID가 존재하지 않습니다.")
            return redirect(url_for('report'))

        # 3. 기존 신고 여부
        cursor.execute("SELECT id FROM report WHERE reporter_id = ? AND target_id = ?", (session['user_id'], target_id))
        existing = cursor.fetchone()

        if existing and request.form.get('confirm') != '1':
            return render_template(
                'report.html',
                target_id=target_input,
                reason=reason,
                existing=True
            )

        if existing:
            cursor.execute("UPDATE report SET reason = ? WHERE id = ?", (reason, existing['id']))
            flash("기존 신고 내용이 수정되었습니다.")
        else:
            cursor.execute("INSERT INTO report (id, reporter_id, target_id, reason) VALUES (?, ?, ?, ?)",
                           (report_id, session['user_id'], target_id, reason))
            flash("신고가 접수되었습니다.")

        db.commit()
        return redirect(url_for('dashboard'))

    return render_template('report.html')

# 실시간 채팅: 클라이언트가 메시지를 보내면 전체 브로드캐스트
@socketio.on('send_message')
def handle_send_message_event(data):
    data['message_id'] = str(uuid.uuid4())
    send(data, broadcast=True)

# 채팅방 입장
@socketio.on('join_room')
def on_join(data):
    room = data.get('room')
    if room:
        join_room(room)
        print(f"[채팅방 입장] room: {room}")

# 1ㄷ1 채팅 기능
@socketio.on('send_private')
def on_private_message(data):
    room = data.get('room')
    sender_id = data.get('sender_id')
    message = data.get('message')
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    if not room or not sender_id or not message:
        print("[오류] 필수 값 누락:", data)
        return

    db = get_db()
    cursor = db.cursor()
    cursor.execute("""
        INSERT INTO chat_message (id, room_id, sender_id, message, sent_at)
        VALUES (?, ?, ?, ?, ?)
    """, (str(uuid.uuid4()), room, sender_id, message, timestamp))
    db.commit()

    emit('receive_message', {
        'sender_id': sender_id,
        'message': message,
        'sent_at': timestamp
    }, to=room)

# 채팅방
@app.route('/chat/<room_id>', endpoint='chat_room')
def chat_room(room_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    db = get_db()
    cursor = db.cursor()

    cursor.execute("SELECT * FROM chat_room WHERE id = ?", (room_id,))
    room = cursor.fetchone()

    if not room or session['user_id'] not in (room['buyer_id'], room['seller_id']):
        abort(403)

    cursor.execute("""
        SELECT sender_id, message, sent_at FROM chat_message
        WHERE room_id = ?
        ORDER BY sent_at ASC
    """, (room_id,))
    messages = cursor.fetchall()

    return render_template(
        "chat_room.html",
        room=room,
        user_id=session['user_id'],
        messages=messages
    )

# 상세페이지 채팅
@app.route('/chat/start/<product_id>', endpoint='start_chat')
def start_chat(product_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    db = get_db()
    cursor = db.cursor()

    cursor.execute("SELECT seller_id FROM product WHERE id = ?", (product_id,))
    product = cursor.fetchone()
    if not product:
        flash("상품을 찾을 수 없습니다.")
        return redirect(url_for('dashboard'))

    buyer_id = session['user_id']
    seller_id = product['seller_id']

    if buyer_id == seller_id:
        flash("자신과는 채팅할 수 없습니다.")
        return redirect(url_for('view_product', product_id=product_id))

    cursor.execute("""
        SELECT id FROM chat_room
        WHERE buyer_id = ? AND seller_id = ? AND product_id = ?
    """, (buyer_id, seller_id, product_id))
    room = cursor.fetchone()

    if room:
        room_id = room['id']
    else:
        room_id = str(uuid.uuid4())
        cursor.execute("""
            INSERT INTO chat_room (id, buyer_id, seller_id, product_id)
            VALUES (?, ?, ?, ?)
        """, (room_id, buyer_id, seller_id, product_id))
        db.commit()

    return redirect(url_for('chat_room', room_id=room_id))

# 판매자 채팅
@app.route('/chat/list')
def chat_list():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']
    db = get_db()
    cursor = db.cursor()

    cursor.execute("""
        SELECT c.id, p.title AS product_title,
               CASE
                 WHEN c.buyer_id = ? THEN c.seller_id
                 ELSE c.buyer_id
               END AS other_user_id
        FROM chat_room c
        JOIN product p ON c.product_id = p.id
        WHERE c.seller_id = ? OR c.buyer_id = ?
    """, (user_id, user_id, user_id))

    chat_rooms = cursor.fetchall()
    chat_rooms_fixed = []

    for room in chat_rooms:
        cursor.execute("SELECT username FROM user WHERE id = ?", (room['other_user_id'],))
        user_info = cursor.fetchone()
        chat_rooms_fixed.append({
            'id': room['id'],
            'product_title': room['product_title'],
            'other_username': user_info['username'] if user_info else '알 수 없음'
        })

    return render_template(
        "seller_chat_list.html", 
        chat_rooms=chat_rooms_fixed)

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
        SELECT 
            report.target_id,
            COALESCE(product.title, user.username) AS title,
            CASE
                WHEN product.title IS NOT NULL THEN '상품'
                WHEN user.username IS NOT NULL THEN '사용자'
                ELSE '알 수 없음'
            END AS target_type,
            COUNT(*) AS report_count
        FROM report
        LEFT JOIN product ON report.target_id = product.id
        LEFT JOIN user ON report.target_id = user.id
        GROUP BY report.target_id
    """)
    report_summary = cursor.fetchall()

    cursor.execute("""
        SELECT p.id, u1.username AS buyer, 
        u2.username AS seller, p.product_title, 
        p.product_price, p.purchased_at
        FROM purchase p
        JOIN user u1 ON p.buyer_id = u1.id
        JOIN user u2 ON p.seller_id = u2.id
        ORDER BY p.purchased_at DESC
    """)
    purchase_history = cursor.fetchall()

    purchase_keyword = request.args.get('purchase_q', '').strip()
    purchase_query = """
        SELECT purchase.*, buyer.username AS buyer_name, seller.username AS seller_name
        FROM purchase
        JOIN user AS buyer ON purchase.buyer_id = buyer.id
        JOIN user AS seller ON purchase.seller_id = seller.id
    """
    params = ()
    if purchase_keyword:
        purchase_query += """
            WHERE product_title LIKE ? OR buyer.username LIKE ? OR seller.username LIKE ?
        """
        keyword_like = f"%{purchase_keyword}%"
        params = (keyword_like, keyword_like, keyword_like)

    purchase_query += " ORDER BY purchased_at DESC"
    cursor.execute(purchase_query, params)
    purchases = cursor.fetchall()

    return render_template(
        "admin.html",
        keyword=keyword,
        results=results,
        report_summary=report_summary,
        purchase_history=purchase_history,
        purchase_keyword=purchase_keyword
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

# 관리자용 거래내역 삭제
@app.route('/admin/delete_purchase/<purchase_id>', methods=['POST'])
def delete_purchase(purchase_id):
    if not g.user or g.user['is_admin'] != 1:
        abort(403)

    db = get_db()
    cursor = db.cursor()
    cursor.execute("DELETE FROM purchase WHERE id = ?", (purchase_id,))
    db.commit()
    flash("거래 기록이 삭제되었습니다.")
    return redirect(url_for('admin_page'))

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
