import os
# pk_7311a316d99442c282272e76230e81f3
from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Custom filter``
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    list2 = []
    list1 = db.execute("SELECT DISTINCT(symbol) FROM transactions WHERE id = ?", session["user_id"])
    for dic in list1:
        list = lookup(dic["symbol"])
        rows = db.execute("SELECT totalShares FROM transactions WHERE symbol = ? AND id = ?", dic["symbol"], session["user_id"])
        totalShares = rows[0]["totalShares"]
        list["shares"] = totalShares
        total_price = totalShares * list["price"]
        list["total"] = "{:.2f}".format(total_price)
        list2.append(list)
    rows1 = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])
    sum1 = rows1[0]["cash"]
    total = sum1
    for i in list2:
        total += float(i["total"])
    total = "{:.2f}".format(total)
    sum1 = "{:.2f}".format(sum1)
    return render_template("index.html", list2 = list2, sum1 = sum1, total = total)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "GET":
        return render_template("buy.html")
    list = lookup(request.form.get("symbol"))
    rows = db.execute("SELECT * FROM users WHERE id = ?", session["user_id"])
    cash = float(rows[0]["cash"])
    username = rows[0]["username"]
    shares = request.form.get("shares")
    id = session["user_id"]
    cost = float(shares) * list["price"];
    if(cost > cash):
        return apology("Insufficient money")
    db.execute("UPDATE users SET cash = ? WHERE id = ?", cash - cost, id)
    db.execute("INSERT INTO transactions (id,username, price, symbol, time, shares,state) VALUES(?, ?, ? , ?, DATETIME('now','localtime'), ?, ?)",id, username, list["price"], list["symbol"], shares, "BUY")
    rows = db.execute("SELECT SUM(shares) FROM transactions WHERE symbol = ? AND id = ?", list["symbol"], id)
    db.execute("UPDATE transactions SET totalShares = ? WHERE symbol = ? AND id = ?", rows[0]["SUM(shares)"], list["symbol"], id)
    return redirect("/")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    list = db.execute("SELECT * FROM transactions WHERE id = ?", session["user_id"])
    return render_template("history.html", list=list)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""
    if request.method == "GET":
        return render_template("quote.html")
    symbol = request.form.get("symbol")
    list = lookup(symbol)
    return render_template("quoted.html", list=list)


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "POST":
        name = request.form.get("username")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")
        # Ensure username was submitted
        if not name:
            return apology("must provide username", 403)
        # Ensure username is valid
        rows = db.execute("SELECT username FROM users")
        for dic in rows:
            if name == dic["username"]:
                return apology("username already exists", 403)
        # Ensure password was submitted
        if not password:
            return apology("must provide password", 403)
        # Ensure passwords match
        if password != confirmation:
            return apology("passwords do not match", 403)
        hash_value = generate_password_hash(password,method='pbkdf2:sha256', salt_length=8)
        db.execute("INSERT INTO users (username, hash) VALUES(?, ?)", name, hash_value)
        return redirect("/")
    return render_template("register.html")

@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    list1 = db.execute("SELECT DISTINCT(symbol) FROM transactions WHERE id = ?", session["user_id"])
    if request.method == "POST":
        id = session["user_id"]
        symbol = request.form.get("symbol")
        list = lookup(symbol)
        rows = db.execute("SELECT SUM(shares) FROM transactions WHERE symbol = ? AND id = ?", symbol, id)
        current_shares = rows[0]["SUM(shares)"]
        shares = request.form.get("shares")
        rows = db.execute("SELECT username FROM users WHERE id = ?", id)
        username = rows[0]["username"]
        if not symbol:
            return apology("symbol missing")
        elif int(shares) > current_shares or int(shares) <= 0:
            return apology("Invalid number of shares")
        elif not any(dic["symbol"] == symbol for dic in list1):
            return apology("Invalid symbol")
        refund = float(request.form.get("shares")) * list["price"]
        db.execute("UPDATE users SET cash = cash + ? WHERE id = ?", refund, id)
        db.execute("UPDATE transactions SET totalShares = totalShares - ? WHERE symbol = ? AND id = ?", shares, symbol, id)
        db.execute("INSERT INTO transactions (id,username, price, symbol, time, shares) VALUES(?, ?, ? , ?, DATETIME('now','localtime'), ?, ?)",id, username, list["price"], symbol, shares)
        return redirect("/")
    else:
        return render_template("query.html", list=list)
