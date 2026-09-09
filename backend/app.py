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
    """


# -----------------------------
# Add Customer
# -----------------------------
@app.route("/add-customer", methods=["GET", "POST"])
def add_customer():

    if request.method == "POST":

        name = request.form["name"]
        mobile = request.form["mobile"]
        address = request.form["address"]
        monthly_amount = request.form["monthly_amount"]
        connection_start_date = request.form["connection_start_date"]

        # For now, our first operator has ID = 1
        operator_id = 1

        connection = get_db_connection()
        cursor = connection.cursor()

        query = """
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

        values = (
            operator_id,
            name,
            mobile,
            address,
            monthly_amount,
            connection_start_date
        )

        cursor.execute(query, values)
        connection.commit()

        cursor.close()
        connection.close()

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
        id,
        name,
        mobile,
        address,
        monthly_amount,
        connection_start_date,
        status
    FROM customers
    ORDER BY id DESC
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
# Run Application
# -----------------------------
if __name__ == "__main__":
    app.run(debug=True)