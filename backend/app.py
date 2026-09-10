from flask import Flask, render_template, request, redirect, url_for
import mysql.connector
from config import DB_CONFIG

app = Flask(__name__)


# -----------------------------
# MySQL Database Connection
# -----------------------------
def get_db_connection():
    return mysql.connector.connect(
        host=DB_CONFIG["host"],
        user=DB_CONFIG["user"],
        password=DB_CONFIG["password"],
        database=DB_CONFIG["database"]
    )


# -----------------------------
# Home
# -----------------------------
@app.route("/")
def home():
    return """
    <h1>CableConnect</h1>
    <p>Backend is running!</p>

    <a href="/add-customer">Add Customer</a>
    <br><br>

    <a href="/customers">View Customers</a>
    <br><br>

    <a href="/stbs">View STBs</a>
    <br><br>
    <a href="/add-recharge">Add TV Recharge</a>
    <br><br>
    <a href="/recharges">Recharge History</a>
    """


# -----------------------------
# Add Customer
# -----------------------------
@app.route("/add-customer", methods=["GET", "POST"])
def add_customer():

    if request.method == "POST":

        # Get customer details from form
        name = request.form["name"]
        mobile = request.form["mobile"]
        address = request.form["address"]
        monthly_amount = request.form["monthly_amount"]
        connection_start_date = request.form["connection_start_date"]
        stb_number = request.form["stb_number"]

        # For now, our first operator has ID = 1
        operator_id = 1

        # Connect to MySQL
        connection = get_db_connection()
        cursor = connection.cursor()

        # -----------------------------
        # Insert Customer
        # -----------------------------
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

        cursor.execute(customer_query, customer_values)

        # Get the ID of the newly created customer
        customer_id = cursor.lastrowid


        # -----------------------------
        # Insert STB
        # -----------------------------
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

        cursor.execute(stb_query, stb_values)


        # Save both records
        connection.commit()

        # Close connection
        cursor.close()
        connection.close()

        # Go to Customers page
        return redirect(url_for("customers"))

    return render_template("add_customer.html")


# -----------------------------
# View Customers
# -----------------------------
@app.route("/customers")
def customers():

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
        customers.status
    FROM customers
    JOIN stbs
    ON customers.id = stbs.customer_id
    ORDER BY customers.id DESC
    """

    cursor.execute(query)

    customer_list = cursor.fetchall()

    cursor.close()
    connection.close()

    return render_template(
        "customers.html",
        customers=customer_list
    )
# -----------------------------
# View STBs
# -----------------------------
@app.route("/stbs")
def stbs():

    connection = get_db_connection()
    cursor = connection.cursor(dictionary=True)

    query = """
    SELECT
        stbs.id,
        customers.name AS customer_name,
        customers.mobile,
        stbs.stb_number,
        stbs.status,
        stbs.installation_date
    FROM stbs
    JOIN customers
    ON stbs.customer_id = customers.id
    ORDER BY stbs.id DESC
    """

    cursor.execute(query)

    stb_list = cursor.fetchall()

    cursor.close()
    connection.close()

    return render_template(
        "stb.html",
        stbs=stb_list
    )
# -----------------------------
# Add TV Recharge
# -----------------------------
@app.route("/add-recharge", methods=["GET", "POST"])
def add_recharge():

    connection = get_db_connection()
    cursor = connection.cursor(dictionary=True)

    # -----------------------------
    # Save Recharge
    # -----------------------------
    if request.method == "POST":

        customer_id = request.form["customer_id"]
        amount = request.form["amount"]
        recharge_date = request.form["recharge_date"]
        expiry_date = request.form["expiry_date"]

        # Get STB ID for selected customer
        stb_query = """
        SELECT id
        FROM stbs
        WHERE customer_id = %s
        """

        cursor.execute(stb_query, (customer_id,))

        stb = cursor.fetchone()

        if stb is None:
            cursor.close()
            connection.close()

            return "No STB found for this customer."

        stb_id = stb["id"]

        # Insert recharge
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

        cursor.execute(recharge_query, recharge_values)

        connection.commit()

        cursor.close()
        connection.close()

        return redirect(url_for("recharges"))


    # -----------------------------
    # Get Customers for Form
    # -----------------------------
    customer_query = """
    SELECT
        customers.id,
        customers.name,
        stbs.stb_number
    FROM customers
    JOIN stbs
    ON customers.id = stbs.customer_id
    ORDER BY customers.name
    """

    cursor.execute(customer_query)

    customer_list = cursor.fetchall()

    cursor.close()
    connection.close()

    return render_template(
        "add_recharge.html",
        customers=customer_list
    )
# -----------------------------
# Run Application
# -----------------------------
if __name__ == "__main__":
    app.run(debug=True)