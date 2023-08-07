import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")


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
    userID = session["user_id"]
    symbols = db.execute("SELECT DISTINCT symbol FROM transactions WHERE user_id = ?", userID)
    credit = []
    rows = db.execute("SELECT cash from users WHERE id = ?", userID )
    current_cash = rows[0]["cash"]
    total = current_cash
    for symbol in symbols:

        shares_bought = db.execute("SELECT SUM(shares) AS sum FROM transactions WHERE user_id = :userID AND symbol = :symbol AND type = 'buy'", userID = userID, symbol = symbol['symbol'])
        shares_sold = db.execute("SELECT SUM(shares) AS sum FROM transactions WHERE user_id = :userID AND symbol = :symbol AND type = 'sell'", userID = userID, symbol = symbol['symbol'])
        if shares_sold[0]['sum'] is None:
            shares_sold[0]['sum'] = 0
        net_shares = shares_bought[0]['sum'] - shares_sold[0]['sum']

        if not net_shares == 0:
            credit.append({"symbol": symbol["symbol"], "name" : lookup(symbol["symbol"])['name'] , "shares" : net_shares , "price" : lookup(symbol["symbol"])['price'] })
    for credits in credit:
        total = total + (credits['price'] * credits['shares'])

    return render_template("index.html" , current_cash = current_cash, credit = credit , total = total)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    userID = session["user_id"]

    if request.method == "POST":
        symbol = request.form.get("symbol")
        if not lookup(symbol):
            return apology("There is no such symbol")
        if not request.form.get("shares") or  not request.form.get("shares").isnumeric():
            return apology("How many shares?", 400)
        else:
            price = lookup(symbol)["price"]
            stock = lookup(symbol)["name"]

            shares = int(request.form.get("shares"))
            rows = db.execute("SELECT cash from users WHERE id = ?", userID )
            current_cash = rows[0]["cash"]
            if current_cash - (shares * price) < 0:
                return apology("You don't have enough cash")
            else:
                current_cash = current_cash - (shares * price)

                db.execute("UPDATE users SET cash= :current_cash WHERE id= :userID" , current_cash = current_cash, userID= userID)
                db.execute("INSERT INTO transactions (user_id, stock, symbol, price, shares, type) VALUES(?, ?, ?, ?, ?, ?)", userID, stock, symbol, price, shares, 'buy')

                flash(f"You've bought {shares} shares of {symbol}")

                return redirect("/")

    else:
        return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    transactions = db.execute("SELECT * FROM transactions WHERE user_id = ?;", session["user_id"])
    return render_template("history.html", transactions=transactions)


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
    if request.method == "POST":
        if not (query := lookup(request.form.get("symbol"))):
            return apology("This simbol doesn't exist ")

        return render_template("quote.html", query=query)
    else:
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")

        if not username:
            return apology("Please give us your username")

        if not password:
            return apology("Please give us your unique password")

        if not confirmation:
            return apology("Please confirm your password")

        check = db.execute("SELECT * FROM users WHERE username = ?;", username)

        if len(check) != 0:
           return apology(f"The username '{username}' is already taken. Try more unique username.")

        if password != confirmation:
            return apology("Make sure you passwords match")

        new_user = db.execute("INSERT INTO users (username, hash) VALUES (?, ?);", username, generate_password_hash(password))

        session["user_id"] = new_user

        flash("Congratulations! You are registered!")

        return redirect("/")
    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():

    """Sell shares of stock"""
    userID = session["user_id"]


    if request.method == "POST":

        symbol = request.form.get("symbol")

        shares_bought = db.execute("SELECT SUM(shares) AS sum FROM transactions WHERE user_id = :userID AND symbol = :symbol AND type = 'buy'", userID = userID, symbol = symbol)
        shares_sold = db.execute("SELECT SUM(shares) AS sum FROM transactions WHERE user_id = :userID AND symbol = :symbol AND type = 'sell'", userID = userID, symbol = symbol)

        if shares_sold[0]['sum'] is None:
            shares_sold[0]['sum'] = 0

        net_shares = shares_bought[0]['sum'] - shares_sold[0]['sum']

        shares_to_sell = int(request.form.get("shares"))

        if not symbol:
            return apology("There is no shuch symbol")
        elif shares_to_sell < 0 or (net_shares - shares_to_sell) < 0:
            return apology("We need a valid number")
        else:
            price = lookup(symbol)["price"]
            stock = lookup(symbol)["name"]

            margin = int(shares_to_sell) * price
            cash_list = db.execute("SELECT cash from users WHERE id = ?", userID )
            current_cash = cash_list[0]["cash"]
            current_cash = current_cash + margin

            db.execute("UPDATE users SET cash= :current_cash WHERE id= :userID" , current_cash = current_cash, userID= userID)
            db.execute("INSERT INTO transactions (user_id, stock, symbol, price, shares, type) VALUES(?, ?, ?, ?, ?, ?)", userID, stock, symbol, price, shares_to_sell, 'sell')

            flash("Congratulations! You've sold some shares!")

            return redirect("/")

    else:

        user_stocks = db.execute("SELECT DISTINCT symbol FROM transactions WHERE user_id = ?", userID )
        return render_template("sell.html", options = user_stocks)

@app.route("/depositmoney", methods=["GET", "POST"])
@login_required
def depositmoney():
    if request.method == "GET":
        return render_template("depositmoney.html")
    else:
        amount = request.form.get("amount")
        if amount == None:
            return apology("Please provide an input")
        else:
            assets= db.execute("SELECT cash FROM users WHERE id =:userid", userid=session["user_id"])
            deposit= db.execute("UPDATE users SET cash=:cash WHERE id:=userid", cash=float(assets[0]["cash"]) + float(amount), userid = session["user_id"])
            flash("You have successfully deposit money!")
            return redirect("/")