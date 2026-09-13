from flask import Flask, render_template, request, redirect, url_for, session
import mysql.connector

from config import (
    DB_CONFIG,
    MAIL_SERVER,
    MAIL_PORT,
    MAIL_USE_TLS,
    MAIL_USERNAME,
    MAIL_PASSWORD
)

from flask_mail import Mail, Message

import uuid
import secrets
import hashlib
import hmac

from datetime import datetime, timedelta

from werkzeug.security import (
    check_password_hash,
    generate_password_hash
)


app = Flask(__name__)


# ============================================================
# Flask Secret Key
# ============================================================

app.secret_key = "cableconnect-secret-key"


# ============================================================
# Email Configuration
# ============================================================

app.config["MAIL_SERVER"] = MAIL_SERVER
app.config["MAIL_PORT"] = MAIL_PORT
app.config["MAIL_USE_TLS"] = MAIL_USE_TLS
app.config["MAIL_USERNAME"] = MAIL_USERNAME
app.config["MAIL_PASSWORD"] = MAIL_PASSWORD

mail = Mail(app)


# ============================================================
# MySQL Database Connection
# ============================================================

def get_db_connection():

    return mysql.connector.connect(
        host=DB_CONFIG["host"],
        user=DB_CONFIG["user"],
        password=DB_CONFIG["password"],
        database=DB_CONFIG["database"]
    )


# ============================================================
# Operator Login
# ============================================================

@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        username = request.form["username"].strip()
        password = request.form["password"]

        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)

        query = """
        SELECT
            id,
            name,
            username,
            password_hash
        FROM operators
        WHERE username = %s
        """

        cursor.execute(
            query,
            (username,)
        )

        operator = cursor.fetchone()

        cursor.close()
        connection.close()

        # ----------------------------------------------------
        # Check Username and Password
        # ----------------------------------------------------

        if operator and check_password_hash(
            operator["password_hash"],
            password
        ):

            session["operator_id"] = operator["id"]
            session["operator_name"] = operator["name"]
            session["operator_username"] = operator["username"]

            return redirect(
                url_for("dashboard")
            )

        return render_template(
            "login.html",
            error_message="Invalid username or password."
        )

    return render_template(
        "login.html"
    )
# ============================================================
# Operator Registration
# ============================================================

@app.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "POST":

        name = request.form["name"].strip()
        username = request.form["username"].strip()
        email = request.form["email"].strip().lower()
        password = request.form["password"]
        confirm_password = request.form["confirm_password"]

        # Check password match
        if password != confirm_password:

            return render_template(
                "register.html",
                error_message="Passwords do not match."
            )

        # Check password length
        if len(password) < 8:

            return render_template(
                "register.html",
                error_message=(
                    "Password must contain at least 8 characters."
                )
            )

        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)

        # Check username or email already exists
        check_query = """
        SELECT id, username, email
        FROM operators
        WHERE username = %s
        OR email = %s
        """

        cursor.execute(
            check_query,
            (
                username,
                email
            )
        )

        existing_operator = cursor.fetchone()

        if existing_operator:

            cursor.close()
            connection.close()

            if existing_operator["username"] == username:

                message = "Username already exists."

            else:

                message = "Email already registered."

            return render_template(
                "register.html",
                error_message=message
            )

        # Securely hash password
        password_hash = generate_password_hash(
            password
        )

        # Insert new operator
        insert_query = """
        INSERT INTO operators
        (
            name,
            username,
            password_hash,
            email
        )
        VALUES (%s, %s, %s, %s)
        """

        cursor.execute(
            insert_query,
            (
                name,
                username,
                password_hash,
                email
            )
        )

        connection.commit()

        cursor.close()
        connection.close()

        return redirect(
            url_for("login")
        )

    return render_template(
        "register.html"
    )

# ============================================================
# Forgot Password
# ============================================================

@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():

    if request.method == "POST":

        email = request.form["email"].strip().lower()

        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)

        # ----------------------------------------------------
        # Find Operator By Email
        # ----------------------------------------------------

        query = """
        SELECT
            id,
            username,
            email
        FROM operators
        WHERE email = %s
        """

        cursor.execute(
            query,
            (email,)
        )

        operator = cursor.fetchone()

        # ----------------------------------------------------
        # Email Not Found
        # ----------------------------------------------------

        if operator is None:

            cursor.close()
            connection.close()

            return render_template(
                "forgot_password.html",
                success_message=(
                    "If an account exists with this email, "
                    "a password reset link has been generated."
                )
            )

        # ----------------------------------------------------
        # Generate Secure Random Token
        # ----------------------------------------------------

        reset_token = secrets.token_urlsafe(32)

        # ----------------------------------------------------
        # Hash Token Before Storing
        # ----------------------------------------------------

        reset_token_hash = hashlib.sha256(
            reset_token.encode()
        ).hexdigest()

        # ----------------------------------------------------
        # Token Expiry - 15 Minutes
        # ----------------------------------------------------

        reset_token_expires = (
            datetime.now() + timedelta(minutes=15)
        )

        # ----------------------------------------------------
        # Store Token Hash + Expiry
        # ----------------------------------------------------

        update_query = """
        UPDATE operators

        SET
            reset_token_hash = %s,
            reset_token_expires = %s

        WHERE id = %s
        """

        cursor.execute(
            update_query,
            (
                reset_token_hash,
                reset_token_expires,
                operator["id"]
            )
        )

        connection.commit()

        cursor.close()
        connection.close()

        # ----------------------------------------------------
        # Create Reset Link
        # ----------------------------------------------------

        reset_link = url_for(
            "reset_password",
            token=reset_token,
            _external=True
        )

        # ----------------------------------------------------
        # Send Password Reset Email
        # ----------------------------------------------------

        try:

            message = Message(
                subject="CableConnect - Password Reset",
                sender=MAIL_USERNAME,
                recipients=[operator["email"]]
            )

            message.body = f"""
Hello,

We received a request to reset your CableConnect password.

Click the link below to create a new password:

{reset_link}

This link will expire in 15 minutes.

If you did not request a password reset, you can safely ignore this email.

Regards,
CableConnect Team
"""

            mail.send(message)

        except Exception as error:

            print()
            print("=" * 70)
            print("EMAIL SENDING ERROR")
            print("=" * 70)
            print(error)
            print("=" * 70)
            print()

            return render_template(
                "forgot_password.html",
                error_message=(
                    "Unable to send the reset email. "
                    "Please try again later."
                )
            )

        # ----------------------------------------------------
        # Email Successfully Sent
        # ----------------------------------------------------

        return render_template(
            "forgot_password.html",
            success_message=(
                "A password reset link has been sent to "
                "your registered email address."
            )
        )

    return render_template(
        "forgot_password.html"
    )


# ============================================================
# Reset Password
# ============================================================

@app.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_password(token):

    # --------------------------------------------------------
    # Hash Token From URL
    # --------------------------------------------------------

    token_hash = hashlib.sha256(
        token.encode()
    ).hexdigest()

    connection = get_db_connection()
    cursor = connection.cursor(dictionary=True)

    # --------------------------------------------------------
    # Find Matching Token
    # --------------------------------------------------------

    query = """
    SELECT
        id,
        username,
        reset_token_hash,
        reset_token_expires
    FROM operators
    WHERE reset_token_hash = %s
    """

    cursor.execute(
        query,
        (token_hash,)
    )

    operator = cursor.fetchone()

    # --------------------------------------------------------
    # Token Not Found
    # --------------------------------------------------------

    if operator is None:

        cursor.close()
        connection.close()

        return render_template(
            "reset_password.html",
            error_message=(
                "Invalid or expired password reset link."
            )
        )

    # --------------------------------------------------------
    # Verify Token Hash
    # --------------------------------------------------------

    if not hmac.compare_digest(
        operator["reset_token_hash"],
        token_hash
    ):

        cursor.close()
        connection.close()

        return render_template(
            "reset_password.html",
            error_message=(
                "Invalid password reset link."
            )
        )

    # --------------------------------------------------------
    # Check Token Expiry
    # --------------------------------------------------------

    if (
        operator["reset_token_expires"] is None
        or
        datetime.now() > operator["reset_token_expires"]
    ):

        cursor.close()
        connection.close()

        return render_template(
            "reset_password.html",
            error_message=(
                "This password reset link has expired. "
                "Please request a new one."
            )
        )

    # ========================================================
    # POST - Save New Password
    # ========================================================

    if request.method == "POST":

        new_password = request.form["password"]
        confirm_password = request.form["confirm_password"]

        # ----------------------------------------------------
        # Check Password Length
        # ----------------------------------------------------

        if len(new_password) < 8:

            cursor.close()
            connection.close()

            return render_template(
                "reset_password.html",
                error_message=(
                    "Password must contain at least 8 characters."
                )
            )

        # ----------------------------------------------------
        # Confirm Password
        # ----------------------------------------------------

        if new_password != confirm_password:

            cursor.close()
            connection.close()

            return render_template(
                "reset_password.html",
                error_message=(
                    "Passwords do not match."
                )
            )

        # ----------------------------------------------------
        # Hash New Password
        # ----------------------------------------------------

        new_password_hash = generate_password_hash(
            new_password
        )

        # ----------------------------------------------------
        # Update Password
        # ----------------------------------------------------

        update_query = """
        UPDATE operators

        SET
            password_hash = %s,
            reset_token_hash = NULL,
            reset_token_expires = NULL

        WHERE id = %s
        """

        cursor.execute(
            update_query,
            (
                new_password_hash,
                operator["id"]
            )
        )

        connection.commit()

        cursor.close()
        connection.close()

        # ----------------------------------------------------
        # Password Successfully Changed
        # ----------------------------------------------------

        return render_template(
            "reset_password.html",
            success_message=(
                "Your password has been changed successfully. "
                "You can now login with your new password."
            )
        )

    # ========================================================
    # GET - Show Reset Password Page
    # ========================================================

    cursor.close()
    connection.close()

    return render_template(
        "reset_password.html"
    )


# ============================================================
# Logout
# ============================================================

@app.route("/logout")
def logout():

    session.clear()

    return redirect(
        url_for("login")
    )


# ============================================================
# Home
# ============================================================

@app.route("/")
def home():

    if "operator_id" not in session:

        return redirect(
            url_for("login")
        )

    return redirect(
        url_for("dashboard")
    )


# ============================================================
# Add Customer
# ============================================================

@app.route("/add-customer", methods=["GET", "POST"])
def add_customer():

    if "operator_id" not in session:

        return redirect(
            url_for("login")
        )

    if request.method == "POST":

        name = request.form["name"]
        mobile = request.form["mobile"]
        address = request.form["address"]
        monthly_amount = request.form["monthly_amount"]
        connection_start_date = request.form["connection_start_date"]
        stb_number = request.form["stb_number"]

        operator_id = session["operator_id"]

        connection = get_db_connection()
        cursor = connection.cursor()

        try:

            # ------------------------------------------------
            # Insert Customer
            # ------------------------------------------------

            customer_query = """
            INSERT INTO customers
            (
                operator_id,
                name,
                mobile,
                address,
                monthly_amount,
                connection_start_date
            )
            VALUES (%s, %s, %s, %s, %s, %s)
            """

            customer_values = (
                operator_id,
                name,
                mobile,
                address,
                monthly_amount,
                connection_start_date
            )

            cursor.execute(
                customer_query,
                customer_values
            )

            customer_id = cursor.lastrowid

            # ------------------------------------------------
            # Insert STB
            # ------------------------------------------------

            stb_query = """
            INSERT INTO stbs
            (
                customer_id,
                stb_number,
                installation_date
            )
            VALUES (%s, %s, %s)
            """

            stb_values = (
                customer_id,
                stb_number,
                connection_start_date
            )

            cursor.execute(
                stb_query,
                stb_values
            )

            connection.commit()

        except mysql.connector.Error as error:

            connection.rollback()

            cursor.close()
            connection.close()

            return f"""
            <h2>Error while adding customer</h2>
            <p>{error}</p>
            <br>
            <a href="/add-customer">Go Back</a>
            """

        cursor.close()
        connection.close()

        return redirect(
            url_for("customers")
        )

    return render_template(
        "add_customer.html"
    )


# ============================================================
# View Customers
# ============================================================

@app.route("/customers")
def customers():

    if "operator_id" not in session:

        return redirect(
            url_for("login")
        )

    connection = get_db_connection()
    cursor = connection.cursor(dictionary=True)

    query = """
    SELECT
        customers.id,
        customers.name,
        customers.mobile,
        customers.address,
        stbs.stb_number,
        customers.monthly_amount,
        customers.connection_start_date,

        CASE
            WHEN EXISTS (
                SELECT 1
                FROM payments
                WHERE payments.customer_id = customers.id
                AND payments.billing_month = MONTH(CURDATE())
                AND payments.billing_year = YEAR(CURDATE())
                AND payments.status = 'Paid'
            )
            THEN 'Active'
            ELSE 'Inactive'
        END AS monthly_status

    FROM customers

    JOIN stbs
        ON customers.id = stbs.customer_id

    WHERE customers.operator_id = %s

    ORDER BY customers.id DESC
    """

    cursor.execute(
        query,
        (session["operator_id"],)
    )

    customer_list = cursor.fetchall()

    cursor.close()
    connection.close()

    return render_template(
        "customers.html",
        customers=customer_list
    )


# ============================================================
# View STBs
# ============================================================

@app.route("/stbs")
def stbs():

    if "operator_id" not in session:

        return redirect(
            url_for("login")
        )

    connection = get_db_connection()
    cursor = connection.cursor(dictionary=True)

    query = """
    SELECT
        stbs.id,
        customers.id AS customer_id,
        customers.name AS customer_name,
        customers.mobile,
        stbs.stb_number,
        stbs.status,
        stbs.installation_date

    FROM stbs

    JOIN customers
        ON stbs.customer_id = customers.id

    WHERE customers.operator_id = %s

    ORDER BY stbs.id DESC
    """

    cursor.execute(
        query,
        (session["operator_id"],)
    )

    stb_list = cursor.fetchall()

    cursor.close()
    connection.close()

    return render_template(
        "stb.html",
        stbs=stb_list
    )


# ============================================================
# Add TV Recharge
# ============================================================

@app.route("/add-recharge", methods=["GET", "POST"])
def add_recharge():

    if "operator_id" not in session:

        return redirect(
            url_for("login")
        )

    connection = get_db_connection()
    cursor = connection.cursor(dictionary=True)

    if request.method == "POST":

        customer_id = request.form["customer_id"]
        amount = request.form["amount"]
        recharge_date = request.form["recharge_date"]
        expiry_date = request.form["expiry_date"]

        # ----------------------------------------------------
        # Verify Customer Belongs To Operator
        # ----------------------------------------------------

        customer_check_query = """
        SELECT id
        FROM customers
        WHERE id = %s
        AND operator_id = %s
        """

        cursor.execute(
            customer_check_query,
            (
                customer_id,
                session["operator_id"]
            )
        )

        customer_exists = cursor.fetchone()

        if customer_exists is None:

            cursor.close()
            connection.close()

            return "Customer not found.", 404

        # ----------------------------------------------------
        # Get STB ID
        # ----------------------------------------------------

        stb_query = """
        SELECT id
        FROM stbs
        WHERE customer_id = %s
        """

        cursor.execute(
            stb_query,
            (customer_id,)
        )

        stb = cursor.fetchone()

        if stb is None:

            cursor.close()
            connection.close()

            return "No STB found for this customer.", 404

        stb_id = stb["id"]

        # ----------------------------------------------------
        # Insert Recharge
        # ----------------------------------------------------

        recharge_query = """
        INSERT INTO recharges
        (
            customer_id,
            stb_id,
            amount,
            recharge_date,
            expiry_date
        )
        VALUES (%s, %s, %s, %s, %s)
        """

        recharge_values = (
            customer_id,
            stb_id,
            amount,
            recharge_date,
            expiry_date
        )

        cursor.execute(
            recharge_query,
            recharge_values
        )

        connection.commit()

        cursor.close()
        connection.close()

        return redirect(
            url_for("recharges")
        )

    # --------------------------------------------------------
    # Get Customers + STB Details
    # --------------------------------------------------------

    customer_query = """
    SELECT
        customers.id,
        customers.name,
        customers.mobile,
        customers.monthly_amount,

        stbs.id AS stb_id,
        stbs.stb_number

    FROM customers

    JOIN stbs
        ON customers.id = stbs.customer_id

    WHERE customers.operator_id = %s

    ORDER BY customers.name
    """

    cursor.execute(
        customer_query,
        (session["operator_id"],)
    )

    customer_list = cursor.fetchall()

    selected_customer = request.args.get(
        "customer_id"
    )

    cursor.close()
    connection.close()

    return render_template(
        "add_recharge.html",
        customers=customer_list,
        selected_customer=selected_customer
    )


# ============================================================
# Recharge History
# ============================================================

@app.route("/recharges")
def recharges():

    if "operator_id" not in session:

        return redirect(
            url_for("login")
        )

    connection = get_db_connection()
    cursor = connection.cursor(dictionary=True)

    query = """
    SELECT
        recharges.id,
        customers.name AS customer_name,
        customers.mobile,
        stbs.stb_number,
        recharges.amount,
        recharges.recharge_date,
        recharges.expiry_date,
        recharges.status

    FROM recharges

    JOIN customers
        ON recharges.customer_id = customers.id

    JOIN stbs
        ON recharges.stb_id = stbs.id

    WHERE customers.operator_id = %s

    ORDER BY recharges.id DESC
    """

    cursor.execute(
        query,
        (session["operator_id"],)
    )

    recharge_list = cursor.fetchall()

    cursor.close()
    connection.close()

    return render_template(
        "recharges.html",
        recharges=recharge_list
    )


# ============================================================
# Delete Payment
# ============================================================

@app.route(
    "/delete-payment/<int:payment_id>",
    methods=["POST"]
)
def delete_payment(payment_id):

    if "operator_id" not in session:

        return redirect(
            url_for("login")
        )

    connection = get_db_connection()
    cursor = connection.cursor()

    delete_query = """
    DELETE payments
    FROM payments

    JOIN customers
        ON payments.customer_id = customers.id

    WHERE payments.id = %s
    AND customers.operator_id = %s
    """

    cursor.execute(
        delete_query,
        (
            payment_id,
            session["operator_id"]
        )
    )

    connection.commit()

    cursor.close()
    connection.close()

    return redirect(
        url_for("payments")
    )


# ============================================================
# Add Monthly Payment
# ============================================================

@app.route("/add-payment", methods=["GET", "POST"])
def add_payment():

    if "operator_id" not in session:

        return redirect(
            url_for("login")
        )

    connection = get_db_connection()
    cursor = connection.cursor(dictionary=True)

    if request.method == "POST":

        customer_id = request.form["customer_id"]
        amount = request.form["amount"]
        payment_date = request.form["payment_date"]
        billing_month = request.form["billing_month"]
        billing_year = request.form["billing_year"]

        # ----------------------------------------------------
        # Verify Customer Belongs To Operator
        # ----------------------------------------------------

        customer_check_query = """
        SELECT id
        FROM customers
        WHERE id = %s
        AND operator_id = %s
        """

        cursor.execute(
            customer_check_query,
            (
                customer_id,
                session["operator_id"]
            )
        )

        customer_exists = cursor.fetchone()

        if customer_exists is None:

            cursor.close()
            connection.close()

            return "Customer not found.", 404

        # ----------------------------------------------------
        # Check Duplicate Payment
        # ----------------------------------------------------

        duplicate_query = """
        SELECT
            id,
            receipt_number

        FROM payments

        WHERE customer_id = %s

        AND billing_month = %s

        AND billing_year = %s

        AND status = 'Paid'
        """

        cursor.execute(
            duplicate_query,
            (
                customer_id,
                billing_month,
                billing_year
            )
        )

        existing_payment = cursor.fetchone()

        if existing_payment:

            customer_query = """
            SELECT
                id,
                name,
                mobile,
                monthly_amount

            FROM customers

            WHERE operator_id = %s

            ORDER BY name
            """

            cursor.execute(
                customer_query,
                (session["operator_id"],)
            )

            customer_list = cursor.fetchall()

            cursor.close()
            connection.close()

            return render_template(
                "add_payment.html",
                customers=customer_list,
                selected_customer=customer_id,
                error_message=(
                    "Payment already recorded for this customer "
                    "for the selected month and year."
                )
            )

        # ----------------------------------------------------
        # Generate Receipt Number
        # ----------------------------------------------------

        receipt_number = (
            "RCPT-" +
            uuid.uuid4().hex[:8].upper()
        )

        # ----------------------------------------------------
        # Insert Payment
        # ----------------------------------------------------

        payment_query = """
        INSERT INTO payments
        (
            customer_id,
            amount,
            payment_date,
            billing_month,
            billing_year,
            status,
            receipt_number
        )
        VALUES (%s, %s, %s, %s, %s, %s, %s)
        """

        payment_values = (
            customer_id,
            amount,
            payment_date,
            billing_month,
            billing_year,
            "Paid",
            receipt_number
        )

        try:

            cursor.execute(
                payment_query,
                payment_values
            )

            connection.commit()

        except mysql.connector.IntegrityError:

            connection.rollback()

            customer_query = """
            SELECT
                id,
                name,
                mobile,
                monthly_amount

            FROM customers

            WHERE operator_id = %s

            ORDER BY name
            """

            cursor.execute(
                customer_query,
                (session["operator_id"],)
            )

            customer_list = cursor.fetchall()

            cursor.close()
            connection.close()

            return render_template(
                "add_payment.html",
                customers=customer_list,
                selected_customer=customer_id,
                error_message=(
                    "Payment already recorded for this customer "
                    "for the selected month and year."
                )
            )

        cursor.close()
        connection.close()

        return redirect(
            url_for("payments")
        )

    # --------------------------------------------------------
    # Get Customers
    # --------------------------------------------------------

    customer_query = """
    SELECT
        id,
        name,
        mobile,
        monthly_amount

    FROM customers

    WHERE operator_id = %s

    ORDER BY name
    """

    cursor.execute(
        customer_query,
        (session["operator_id"],)
    )

    customer_list = cursor.fetchall()

    selected_customer = request.args.get(
        "customer_id"
    )

    cursor.close()
    connection.close()

    return render_template(
        "add_payment.html",
        customers=customer_list,
        selected_customer=selected_customer
    )


# ============================================================
# Payment History
# ============================================================

@app.route("/payments")
def payments():

    if "operator_id" not in session:

        return redirect(
            url_for("login")
        )

    connection = get_db_connection()
    cursor = connection.cursor(dictionary=True)

    query = """
    SELECT
        payments.id,
        customers.name AS customer_name,
        customers.mobile,
        payments.amount,
        payments.payment_date,
        payments.billing_month,
        payments.billing_year,
        payments.status,
        payments.receipt_number

    FROM payments

    JOIN customers
        ON payments.customer_id = customers.id

    WHERE customers.operator_id = %s

    ORDER BY payments.id DESC
    """

    cursor.execute(
        query,
        (session["operator_id"],)
    )

    payment_list = cursor.fetchall()

    cursor.close()
    connection.close()

    return render_template(
        "payments.html",
        payments=payment_list
    )


# ============================================================
# Payment Receipt
# ============================================================

@app.route("/receipt/<int:payment_id>")
def payment_receipt(payment_id):

    if "operator_id" not in session:

        return redirect(
            url_for("login")
        )

    connection = get_db_connection()
    cursor = connection.cursor(dictionary=True)

    query = """
    SELECT
        payments.id,
        payments.amount,
        payments.payment_date,
        payments.billing_month,
        payments.billing_year,
        payments.status,
        payments.receipt_number,

        customers.name AS customer_name,
        customers.mobile,
        customers.address,
        customers.monthly_amount,

        stbs.stb_number

    FROM payments

    JOIN customers
        ON payments.customer_id = customers.id

    LEFT JOIN stbs
        ON customers.id = stbs.customer_id

    WHERE payments.id = %s

    AND customers.operator_id = %s
    """

    cursor.execute(
        query,
        (
            payment_id,
            session["operator_id"]
        )
    )

    payment = cursor.fetchone()

    cursor.close()
    connection.close()

    if payment is None:

        return "Payment not found.", 404

    return render_template(
        "receipt.html",
        payment=payment
    )


# ============================================================
# Customer Details
# ============================================================

@app.route("/customer/<int:customer_id>")
def customer_details(customer_id):

    if "operator_id" not in session:

        return redirect(
            url_for("login")
        )

    connection = get_db_connection()
    cursor = connection.cursor(dictionary=True)

    # --------------------------------------------------------
    # Customer + STB Details
    # --------------------------------------------------------

    customer_query = """
    SELECT
        customers.id,
        customers.name,
        customers.mobile,
        customers.address,
        customers.monthly_amount,
        customers.connection_start_date,
        customers.status,

        stbs.id AS stb_id,
        stbs.stb_number,
        stbs.status AS stb_status,
        stbs.installation_date

    FROM customers

    JOIN stbs
        ON customers.id = stbs.customer_id

    WHERE customers.id = %s

    AND customers.operator_id = %s
    """

    cursor.execute(
        customer_query,
        (
            customer_id,
            session["operator_id"]
        )
    )

    customer = cursor.fetchone()

    if customer is None:

        cursor.close()
        connection.close()

        return "Customer not found.", 404

    # --------------------------------------------------------
    # Payment History
    # --------------------------------------------------------

    payment_query = """
    SELECT
        id,
        amount,
        payment_date,
        billing_month,
        billing_year,
        status,
        receipt_number

    FROM payments

    WHERE customer_id = %s

    ORDER BY payment_date DESC, id DESC
    """

    cursor.execute(
        payment_query,
        (customer_id,)
    )

    payment_history = cursor.fetchall()

    # --------------------------------------------------------
    # Recharge History
    # --------------------------------------------------------

    recharge_query = """
    SELECT
        recharges.id,
        recharges.amount,
        recharges.recharge_date,
        recharges.expiry_date,
        recharges.status,
        stbs.stb_number

    FROM recharges

    JOIN stbs
        ON recharges.stb_id = stbs.id

    WHERE recharges.customer_id = %s

    ORDER BY recharges.recharge_date DESC, recharges.id DESC
    """

    cursor.execute(
        recharge_query,
        (customer_id,)
    )

    recharge_history = cursor.fetchall()

    cursor.close()
    connection.close()

    return render_template(
        "customer_details.html",
        customer=customer,
        payments=payment_history,
        recharges=recharge_history
    )


# ============================================================
# Dashboard
# ============================================================

@app.route("/dashboard")
def dashboard():

    if "operator_id" not in session:

        return redirect(
            url_for("login")
        )

    connection = get_db_connection()
    cursor = connection.cursor(dictionary=True)

    operator_id = session["operator_id"]

    # --------------------------------------------------------
    # Total Customers
    # --------------------------------------------------------

    cursor.execute("""
        SELECT COUNT(*) AS total_customers
        FROM customers
        WHERE operator_id = %s
    """, (operator_id,))

    total_customers = (
        cursor.fetchone()["total_customers"]
    )

    # --------------------------------------------------------
    # Active Customers - Current Month
    # --------------------------------------------------------

    cursor.execute("""
        SELECT COUNT(*) AS active_customers

        FROM customers c

        WHERE c.operator_id = %s

        AND EXISTS (

            SELECT 1

            FROM payments p

            WHERE p.customer_id = c.id

            AND p.billing_month = MONTH(CURDATE())

            AND p.billing_year = YEAR(CURDATE())

            AND p.status = 'Paid'
        )
    """, (operator_id,))

    active_connections = (
        cursor.fetchone()["active_customers"]
    )

    # --------------------------------------------------------
    # Pending Customers - Current Month
    # --------------------------------------------------------

    cursor.execute("""
        SELECT COUNT(*) AS inactive_customers

        FROM customers c

        WHERE c.operator_id = %s

        AND NOT EXISTS (

            SELECT 1

            FROM payments p

            WHERE p.customer_id = c.id

            AND p.billing_month = MONTH(CURDATE())

            AND p.billing_year = YEAR(CURDATE())

            AND p.status = 'Paid'
        )
    """, (operator_id,))

    pending_payments = (
        cursor.fetchone()["inactive_customers"]
    )

    # --------------------------------------------------------
    # Today's Collection
    # --------------------------------------------------------

    cursor.execute("""
        SELECT
            COALESCE(SUM(p.amount), 0)
            AS today_collection

        FROM payments p

        JOIN customers c
            ON p.customer_id = c.id

        WHERE c.operator_id = %s

        AND p.payment_date = CURDATE()

        AND p.status = 'Paid'
    """, (operator_id,))

    today_collection = (
        cursor.fetchone()["today_collection"]
    )

    # --------------------------------------------------------
    # Current Month Collection
    # --------------------------------------------------------

    cursor.execute("""
        SELECT
            COALESCE(SUM(p.amount), 0)
            AS monthly_collection

        FROM payments p

        JOIN customers c
            ON p.customer_id = c.id

        WHERE c.operator_id = %s

        AND p.billing_month = MONTH(CURDATE())

        AND p.billing_year = YEAR(CURDATE())

        AND p.status = 'Paid'
    """, (operator_id,))

    monthly_collection = (
        cursor.fetchone()["monthly_collection"]
    )

    # --------------------------------------------------------
    # Pending Customers List
    # --------------------------------------------------------

    cursor.execute("""
        SELECT
            c.id,
            c.name,
            c.mobile,
            c.monthly_amount

        FROM customers c

        WHERE c.operator_id = %s

        AND NOT EXISTS (

            SELECT 1

            FROM payments p

            WHERE p.customer_id = c.id

            AND p.billing_month = MONTH(CURDATE())

            AND p.billing_year = YEAR(CURDATE())

            AND p.status = 'Paid'
        )

        ORDER BY c.name

        LIMIT 10
    """, (operator_id,))

    pending_customers = cursor.fetchall()

    cursor.close()
    connection.close()

    return render_template(
        "dashboard.html",

        total_customers=total_customers,

        active_connections=active_connections,

        today_collection=today_collection,

        monthly_collection=monthly_collection,

        pending_payments=pending_payments,

        pending_customers=pending_customers
    )


# ============================================================
# Run Application
# ============================================================

if __name__ == "__main__":

    app.run(debug=True)