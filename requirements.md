# CableConnect - Version 1 Requirements

## 1. Project Purpose

CableConnect is a TV Set-Top Box recharge and monthly payment
management system for local cable operators.

The system helps the operator manage customers, set-top boxes,
recharges, monthly payments, and payment history in one place.

## 2. Operator

The operator (babai) can:

- Login to the system
- Add customers
- View customers
- Search customers
- Manage set-top boxes
- Record TV recharges
- Record monthly payments
- View paid and pending payments
- View payment history
- View collection summary on the dashboard

## 3. Customer Information

The system stores:

- Customer name
- Mobile number
- Address
- STB ID
- Monthly amount
- Connection start date
- Connection status

## 4. Customer Search

The operator can search customers using:

- Customer name
- Mobile number
- STB ID

## 5. Recharge Management

The operator can record:

- Customer
- STB ID
- Recharge amount
- Recharge date
- Expiry date

The actual provider recharge is performed through the
authorized provider portal unless an official integration
is available.

## 6. Payment Management

When a customer pays the monthly amount:

- Record payment
- Store payment amount
- Store payment date
- Mark payment as PAID
- Generate a receipt

If payment is not received by the due date:

- Mark payment as PENDING

## 7. Dashboard

The dashboard displays:

- Total customers
- Active connections
- Pending payments
- Today's collection
- Monthly collection

## 8. Payment History

The operator can view a customer's previous payments.

Example:

September - ₹250 - Paid
August    - ₹250 - Paid
July      - ₹250 - Paid
June      - ₹250 - Pending

## 9. Version 1 Database

The initial system contains:

- Operator
- Customer
- STB
- Recharge
- Payment

## 10. Version 1 Workflow

Add Customer
    ↓
Assign STB
    ↓
Record Recharge
    ↓
Customer Pays Monthly Amount
    ↓
Record Payment
    ↓
Paid / Pending
    ↓
View Dashboard
    ↓
View Payment History

## 11. Not Included in Version 1

The following features will be added later:

- Customer login
- Online payments
- Wi-Fi management
- Technician management
- Complaint management
- WhatsApp/SMS notifications
- Multiple operators
- AI/ML features
- Provider API integration