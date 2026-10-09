
import os
import sqlite3
import secrets
import json
from datetime import datetime, timezone
from functools import wraps

from flask import (
    Flask, g, render_template, request, redirect,
    url_for, session, flash, abort
)
from werkzeug.security import generate_password_hash, check_password_hash

APP_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.environ.get(
    "DB_PATH", os.path.join(APP_DIR, "cpps.sqlite3")
)

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE", "0") == "1",
    MAX_CONTENT_LENGTH=2 * 1024 * 1024
)


def now():
    return datetime.now(timezone.utc).isoformat()


def db():
    if "db" not in g:
        os.makedirs(os.path.dirname(DB_PATH) or ".", exist_ok=True)
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


@app.teardown_appcontext
def close_db(_=None):
    conn = g.pop("db", None)
    if conn is not None:
        conn.close()


def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA foreign_keys = ON")

    conn.executescript("""
    CREATE TABLE IF NOT EXISTS users(
      id INTEGER PRIMARY KEY,
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'cadet',
      created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS tests(
      id INTEGER PRIMARY KEY,
      title TEXT NOT NULL,
      description TEXT DEFAULT '',
      duration_minutes INTEGER NOT NULL DEFAULT 20,
      pass_percent INTEGER NOT NULL DEFAULT 70,
      max_attempts INTEGER NOT NULL DEFAULT 2,
      published INTEGER NOT NULL DEFAULT 0,
      created_by INTEGER,
      created_at TEXT NOT NULL,
      FOREIGN KEY(created_by) REFERENCES users(id)
    );

    CREATE TABLE IF NOT EXISTS questions(
      id INTEGER PRIMARY KEY,
      test_id INTEGER NOT NULL,
      prompt TEXT NOT NULL,
      a TEXT NOT NULL,
      b TEXT NOT NULL,
      c TEXT NOT NULL,
      d TEXT NOT NULL,
      correct TEXT NOT NULL CHECK(correct IN ('A','B','C','D')),
      question_type TEXT NOT NULL DEFAULT 'single',
      correct_answers TEXT NOT NULL DEFAULT '',
      FOREIGN KEY(test_id) REFERENCES tests(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS attempts(
      id INTEGER PRIMARY KEY,
      user_id INTEGER NOT NULL,
      test_id INTEGER NOT NULL,
      started_at TEXT NOT NULL,
      finished_at TEXT,
      score INTEGER,
      total INTEGER,
      passed INTEGER,
      answers_json TEXT DEFAULT '{}',
      FOREIGN KEY(user_id) REFERENCES users(id),
      FOREIGN KEY(test_id) REFERENCES tests(id)
    );

    CREATE TABLE IF NOT EXISTS internships(
      id INTEGER PRIMARY KEY,
      title TEXT NOT NULL,
      details TEXT NOT NULL DEFAULT '',
      status TEXT NOT NULL DEFAULT 'active',
      created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS internship_assignments(
      id INTEGER PRIMARY KEY,
      internship_id INTEGER NOT NULL,
      user_id INTEGER NOT NULL,
      status TEXT NOT NULL DEFAULT 'assigned',
      notes TEXT DEFAULT '',
      assigned_at TEXT NOT NULL,
      UNIQUE(internship_id,user_id),
      FOREIGN KEY(internship_id) REFERENCES internships(id) ON DELETE CASCADE,
      FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
    );
    """)

    # Миграция существующей базы без удаления старых вопросов.
    columns = {
        row[1]
        for row in conn.execute("PRAGMA table_info(questions)").fetchall()
    }

    if "question_type" not in columns:
        conn.execute("""
            ALTER TABLE questions
            ADD COLUMN question_type TEXT NOT NULL DEFAULT 'single'
        """)

    if "correct_answers" not in columns:
        conn.execute("""
            ALTER TABLE questions
            ADD COLUMN correct_answers TEXT NOT NULL DEFAULT ''
        """)

    old_questions = conn.execute("""
        SELECT id, correct, correct_answers
        FROM questions
        WHERE correct_answers IS NULL OR correct_answers = ''
    """).fetchall()

    for qid, correct, _ in old_questions:
        conn.execute(
            "UPDATE questions SET correct_answers=? WHERE id=?",
            (json.dumps([correct]), qid)
        )

    # Создание администратора через Environment Variables,
    # если администратора в базе ещё нет.
    admin_name = os.environ.get("ADMIN_USERNAME", "admin").strip() or "admin"
    admin_password = os.environ.get("ADMIN_PASSWORD", "")

    existing_admin = conn.execute(
        "SELECT id FROM users WHERE role='admin' LIMIT 1"
    ).fetchone()

    if not existing_admin and admin_password:
        conn.execute("""
            INSERT OR IGNORE INTO users
            (username, password_hash, role, created_at)
            VALUES (?, ?, ?, ?)
        """, (
            admin_name,
            generate_password_hash(admin_password),
            "admin",
            now()
        ))

    conn.commit()
    conn.close()


init_db()


def csrf_token():
    if "_csrf" not in session:
        session["_csrf"] = secrets.token_urlsafe(24)
    return session["_csrf"]


app.jinja_env.globals["csrf_token"] = csrf_token


@app.before_request
def protect_posts():
    if request.method == "POST":
        token = request.form.get("_csrf", "")
        if not token or not secrets.compare_digest(
            token, session.get("_csrf", "")
        ):
            abort(400, "Сессия формы истекла. Обновите страницу и повторите действие.")


def current_user():
    uid = session.get("user_id")
    if not uid:
        return None

    return db().execute(
        "SELECT id,username,role,created_at FROM users WHERE id=?",
        (uid,)
    ).fetchone()


@app.context_processor
def inject_user():
    return {"current_user": current_user()}


def login_required(fn):
    @wraps(fn)
    def wrapped(*args, **kwargs):
        if not current_user():
            flash("Сначала войдите в аккаунт.", "warning")
            return redirect(url_for("login", next=request.path))
        return fn(*args, **kwargs)
    return wrapped


def admin_required(fn):
    @wraps(fn)
    def wrapped(*args, **kwargs):
        u = current_user()

        if not u:
            flash("Войдите в аккаунт администратора.", "warning")
            return redirect(url_for("login"))

        if u["role"] != "admin":
            abort(403)

        return fn(*args, **kwargs)
    return wrapped


def safe_int(value, default, low, high):
    try:
        n = int(value)
    except (TypeError, ValueError):
        return default
    return max(low, min(high, n))


def correct_list_for_question(q):
    try:
        answers = json.loads(q["correct_answers"] or "[]")
    except (ValueError, TypeError):
        answers = []

    if not isinstance(answers, list):
        answers = []

    answers = [
        a for a in answers
        if a in ("A", "B", "C", "D")
    ]

    if not answers:
        answers = [q["correct"]]

    return sorted(set(answers))


@app.route("/")
def index():
    tests = db().execute("""
        SELECT t.*,
        (SELECT COUNT(*) FROM questions q WHERE q.test_id=t.id) qcount
        FROM tests t
        WHERE t.published=1
        ORDER BY t.created_at DESC
        LIMIT 8
    """).fetchall()

    internships = db().execute("""
        SELECT * FROM internships
        WHERE status='active'
        ORDER BY id DESC LIMIT 4
    """).fetchall()

    return render_template(
        "index.html",
        tests=tests,
        internships=internships
    )


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if (
            len(username) < 3
            or len(username) > 32
            or not username.replace("_", "").replace("-", "").isalnum()
        ):
            flash(
                "Никнейм: 3–32 символа, только буквы, цифры, _ или -.",
                "danger"
            )
        elif len(password) < 8:
            flash("Пароль должен содержать минимум 8 символов.", "danger")
        else:
            try:
                db().execute("""
                    INSERT INTO users(username,password_hash,role,created_at)
                    VALUES(?,?,?,?)
                """, (
                    username,
                    generate_password_hash(password),
                    "cadet",
                    now()
                ))
                db().commit()
                flash("Аккаунт создан. Теперь войдите.", "success")
                return redirect(url_for("login"))
            except sqlite3.IntegrityError:
                flash("Этот никнейм уже занят.", "danger")

    return render_template("auth.html", mode="register")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        user = db().execute(
            "SELECT * FROM users WHERE username=?",
            (username,)
        ).fetchone()

        if user and check_password_hash(user["password_hash"], password):
            session.clear()
            session["user_id"] = user["id"]
            csrf_token()

            next_url = request.args.get("next", "")
            if next_url.startswith("/") and not next_url.startswith("//"):
                return redirect(next_url)

            return redirect(url_for("dashboard"))

        flash("Неверный никнейм или пароль.", "danger")

    return render_template("auth.html", mode="login")


@app.route("/logout", methods=["POST"])
@login_required
def logout():
    session.clear()
    flash("Вы вышли из аккаунта.", "success")
    return redirect(url_for("index"))


@app.route("/dashboard")
@login_required
def dashboard():
    u = current_user()

    attempts = db().execute("""
        SELECT a.*,t.title
        FROM attempts a JOIN tests t ON t.id=a.test_id
        WHERE a.user_id=?
        ORDER BY a.id DESC LIMIT 10
    """, (u["id"],)).fetchall()

    assignments = db().execute("""
        SELECT ia.*,i.title,i.details
        FROM internship_assignments ia
        JOIN internships i ON i.id=ia.internship_id
        WHERE ia.user_id=?
        ORDER BY ia.id DESC
    """, (u["id"],)).fetchall()

    return render_template(
        "dashboard.html",
        attempts=attempts,
        assignments=assignments
    )


@app.route("/tests")
def tests_list():
    tests = db().execute("""
        SELECT t.*,
        (SELECT COUNT(*) FROM questions q WHERE q.test_id=t.id) qcount
        FROM tests t WHERE t.published=1
        ORDER BY t.id DESC
    """).fetchall()

    return render_template("tests.html", tests=tests)


@app.route("/test/<int:test_id>", methods=["GET", "POST"])
@login_required
def take_test(test_id):
    conn = db()

    test = conn.execute(
        "SELECT * FROM tests WHERE id=? AND published=1",
        (test_id,)
    ).fetchone()

    if not test:
        abort(404)

    user = current_user()

    used = conn.execute("""
        SELECT COUNT(*) n FROM attempts
        WHERE user_id=? AND test_id=? AND finished_at IS NOT NULL
    """, (user["id"], test_id)).fetchone()["n"]

    if request.method == "GET":
        if used >= test["max_attempts"]:
            flash("Лимит попыток для этого экзамена исчерпан.", "warning")
            return redirect(url_for("tests_list"))

        questions = conn.execute("""
            SELECT id,prompt,a,b,c,d,question_type
            FROM questions
            WHERE test_id=?
            ORDER BY id
        """, (test_id,)).fetchall()

        if not questions:
            flash("В этом тесте пока нет вопросов.", "warning")
            return redirect(url_for("tests_list"))

        cur = conn.execute("""
            INSERT INTO attempts(user_id,test_id,started_at)
            VALUES(?,?,?)
        """, (user["id"], test_id, now()))

        conn.commit()

        return render_template(
            "take_test.html",
            test=test,
            questions=questions,
            attempt_id=cur.lastrowid
        )

    attempt_id = safe_int(
        request.form.get("attempt_id"), 0, 1, 2**31 - 1
    )

    attempt = conn.execute("""
        SELECT * FROM attempts
        WHERE id=? AND user_id=? AND test_id=? AND finished_at IS NULL
    """, (attempt_id, user["id"], test_id)).fetchone()

    if not attempt:
        abort(400, "Попытка уже завершена или не найдена.")

    started = datetime.fromisoformat(attempt["started_at"])
    elapsed = (datetime.now(timezone.utc) - started).total_seconds()

    questions = conn.execute(
        "SELECT * FROM questions WHERE test_id=? ORDER BY id",
        (test_id,)
    ).fetchall()

    answers = {}
    score = 0

    for q in questions:
        selected = request.form.getlist(f"q_{q['id']}")
        selected = sorted(set(
            a for a in selected
            if a in ("A", "B", "C", "D")
        ))

        if selected:
            answers[str(q["id"])] = selected

        expected = correct_list_for_question(q)

        if selected == expected:
            score += 1

    total = len(questions)
    percent = round(score * 100 / total) if total else 0

    in_time = elapsed <= test["duration_minutes"] * 60 + 10
    passed = int(percent >= test["pass_percent"] and in_time)

    if not in_time:
        flash(
            "Время вышло. Результат сохранён, но экзамен не засчитан.",
            "warning"
        )

    conn.execute("""
        UPDATE attempts
        SET finished_at=?,score=?,total=?,passed=?,answers_json=?
        WHERE id=?
    """, (
        now(),
        score,
        total,
        passed,
        json.dumps(answers),
        attempt["id"]
    ))

    conn.commit()

    return redirect(url_for("attempt_result", attempt_id=attempt["id"]))


@app.route("/result/<int:attempt_id>")
@login_required
def attempt_result(attempt_id):
    u = current_user()

    attempt = db().execute("""
        SELECT a.*,t.title,t.pass_percent
        FROM attempts a JOIN tests t ON t.id=a.test_id
        WHERE a.id=?
    """, (attempt_id,)).fetchone()

    if not attempt:
        abort(404)

    if u["role"] != "admin" and attempt["user_id"] != u["id"]:
        abort(403)

    return render_template("result.html", attempt=attempt)


@app.route("/admin")
@admin_required
def admin():
    conn = db()

    stats = {
        "users": conn.execute(
            "SELECT COUNT(*) n FROM users WHERE role!='admin'"
        ).fetchone()["n"],
        "tests": conn.execute(
            "SELECT COUNT(*) n FROM tests"
        ).fetchone()["n"],
        "attempts": conn.execute("""
            SELECT COUNT(*) n FROM attempts
            WHERE finished_at IS NOT NULL
        """).fetchone()["n"],
        "passrate": conn.execute("""
            SELECT ROUND(100.0*SUM(passed)/NULLIF(COUNT(*),0)) n
            FROM attempts WHERE finished_at IS NOT NULL
        """).fetchone()["n"] or 0
    }

    tests = conn.execute("""
        SELECT t.*,
        (SELECT COUNT(*) FROM questions q WHERE q.test_id=t.id) qcount
        FROM tests t ORDER BY t.id DESC
    """).fetchall()

    users = conn.execute("""
        SELECT id,username,role,created_at FROM users ORDER BY id DESC
    """).fetchall()

    attempts = conn.execute("""
        SELECT a.*,u.username,t.title
        FROM attempts a
        JOIN users u ON u.id=a.user_id
        JOIN tests t ON t.id=a.test_id
        WHERE a.finished_at IS NOT NULL
        ORDER BY a.id DESC LIMIT 100
    """).fetchall()

    internships = conn.execute(
        "SELECT * FROM internships ORDER BY id DESC"
    ).fetchall()

    return render_template(
        "admin.html",
        stats=stats,
        tests=tests,
        users=users,
        attempts=attempts,
        internships=internships
    )


@app.route("/admin/test/new", methods=["POST"])
@admin_required
def create_test():
    title = request.form.get("title", "").strip()

    if not title:
        flash("Укажите название экзамена.", "danger")
        return redirect(url_for("admin"))

    cur = db().execute("""
        INSERT INTO tests(
            title,description,duration_minutes,pass_percent,
            max_attempts,published,created_by,created_at
        )
        VALUES(?,?,?,?,?,?,?,?)
    """, (
        title,
        request.form.get("description", "").strip(),
        safe_int(request.form.get("duration"), 20, 1, 180),
        safe_int(request.form.get("pass_percent"), 70, 1, 100),
        safe_int(request.form.get("max_attempts"), 2, 1, 20),
        1 if request.form.get("published") == "on" else 0,
        current_user()["id"],
        now()
    ))

    db().commit()
    flash("Экзамен создан. Теперь добавьте вопросы.", "success")
    return redirect(url_for("edit_test", test_id=cur.lastrowid))


@app.route("/admin/test/<int:test_id>", methods=["GET", "POST"])
@admin_required
def edit_test(test_id):
    conn = db()

    test = conn.execute(
        "SELECT * FROM tests WHERE id=?",
        (test_id,)
    ).fetchone()

    if not test:
        abort(404)

    if request.method == "POST":
        prompt = request.form.get("prompt", "").strip()

        options = [
            request.form.get(k, "").strip()
            for k in ("a", "b", "c", "d")
        ]

        question_type = request.form.get("question_type", "single")

        correct_list = request.form.getlist("correct")
        correct_list = sorted(set(
            a for a in correct_list
            if a in ("A", "B", "C", "D")
        ))

        if question_type not in ("single", "multiple"):
            question_type = "single"

        valid = (
            bool(prompt)
            and all(options)
            and bool(correct_list)
            and (
                question_type == "multiple"
                or len(correct_list) == 1
            )
        )

        if not valid:
            flash(
                "Заполните вопрос, все четыре ответа и отметьте правильные варианты.",
                "danger"
            )
        else:
            conn.execute("""
                INSERT INTO questions(
                    test_id,prompt,a,b,c,d,correct,
                    question_type,correct_answers
                )
                VALUES(?,?,?,?,?,?,?,?,?)
            """, (
                test_id,
                prompt,
                *options,
                correct_list[0],
                question_type,
                json.dumps(correct_list)
            ))

            conn.commit()
            flash("Вопрос добавлен.", "success")

        return redirect(url_for("edit_test", test_id=test_id))

    questions = conn.execute("""
        SELECT * FROM questions WHERE test_id=? ORDER BY id
    """, (test_id,)).fetchall()

    return render_template(
        "edit_test.html",
        test=test,
        questions=questions
    )


@app.route("/admin/test/<int:test_id>/settings", methods=["POST"])
@admin_required
def test_settings(test_id):
    db().execute("""
        UPDATE tests
        SET title=?,description=?,duration_minutes=?,
            pass_percent=?,max_attempts=?,published=?
        WHERE id=?
    """, (
        request.form.get("title", "").strip() or "Экзамен",
        request.form.get("description", "").strip(),
        safe_int(request.form.get("duration"), 20, 1, 180),
        safe_int(request.form.get("pass_percent"), 70, 1, 100),
        safe_int(request.form.get("max_attempts"), 2, 1, 20),
        1 if request.form.get("published") == "on" else 0,
        test_id
    ))

    db().commit()
    flash("Настройки сохранены.", "success")
    return redirect(url_for("edit_test", test_id=test_id))


@app.route("/admin/question/<int:question_id>/delete", methods=["POST"])
@admin_required
def delete_question(question_id):
    q = db().execute(
        "SELECT test_id FROM questions WHERE id=?",
        (question_id,)
    ).fetchone()

    if q:
        db().execute(
            "DELETE FROM questions WHERE id=?",
            (question_id,)
        )
        db().commit()
        flash("Вопрос удалён.", "success")
        return redirect(url_for("edit_test", test_id=q["test_id"]))

    abort(404)


@app.route("/admin/test/<int:test_id>/delete", methods=["POST"])
@admin_required
def delete_test(test_id):
    db().execute("DELETE FROM questions WHERE test_id=?", (test_id,))
    db().execute("DELETE FROM attempts WHERE test_id=?", (test_id,))
    db().execute("DELETE FROM tests WHERE id=?", (test_id,))
    db().commit()

    flash("Экзамен и связанные результаты удалены.", "success")
    return redirect(url_for("admin"))


@app.route("/admin/user/<int:user_id>/role", methods=["POST"])
@admin_required
def change_role(user_id):
    role = request.form.get("role")

    if role in ("cadet", "teacher", "admin") and user_id != current_user()["id"]:
        db().execute(
            "UPDATE users SET role=? WHERE id=?",
            (role, user_id)
        )
        db().commit()
        flash("Роль пользователя обновлена.", "success")

    return redirect(url_for("admin"))


@app.route("/admin/internship/new", methods=["POST"])
@admin_required
def create_internship():
    title = request.form.get("title", "").strip()
    details = request.form.get("details", "").strip()

    if title and details:
        db().execute("""
            INSERT INTO internships(title,details,status,created_at)
            VALUES(?,?,?,?)
        """, (title, details, "active", now()))
        db().commit()
        flash("Стажировка создана.", "success")
    else:
        flash("Заполните название и описание стажировки.", "danger")

    return redirect(url_for("admin"))


@app.route("/admin/internship/<int:internship_id>/assign", methods=["POST"])
@admin_required
def assign_internship(internship_id):
    username = request.form.get("username", "").strip()

    user = db().execute(
        "SELECT id FROM users WHERE username=?",
        (username,)
    ).fetchone()

    if not user:
        flash("Курсант с таким никнеймом не найден.", "danger")
    else:
        try:
            db().execute("""
                INSERT INTO internship_assignments(
                    internship_id,user_id,status,assigned_at
                )
                VALUES(?,?,?,?)
            """, (internship_id, user["id"], "assigned", now()))
            db().commit()
            flash("Стажировка назначена.", "success")
        except sqlite3.IntegrityError:
            flash("Эта стажировка уже назначена курсанту.", "warning")

    return redirect(url_for("admin"))


@app.route("/admin/assignment/<int:assignment_id>/status", methods=["POST"])
@admin_required
def assignment_status(assignment_id):
    status = request.form.get("status")

    if status in ("assigned", "in_progress", "completed"):
        db().execute(
            "UPDATE internship_assignments SET status=? WHERE id=?",
            (status, assignment_id)
        )
        db().commit()

    return redirect(url_for("admin"))


@app.errorhandler(403)
def forbidden(_):
    return render_template(
        "error.html",
        code=403,
        message="Недостаточно прав для просмотра этой страницы."
    ), 403


@app.errorhandler(404)
def not_found(_):
    return render_template(
        "error.html",
        code=404,
        message="Страница не найдена."
    ), 404


@app.errorhandler(400)
def bad_request(e):
    return render_template(
        "error.html",
        code=400,
        message=getattr(e, "description", "Некорректный запрос.")
    ), 400


if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 5000)),
        debug=False
    )
