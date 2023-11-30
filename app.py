from flask import Flask,  request, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import africastalking
import stripe
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity

app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
db = SQLAlchemy(app)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'secret'
app.config['JWT_SECRET_KEY'] = 'secret'
jwt = JWTManager(app)

# import package

port = 5000

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(120), unique=True, nullable=False)
    phone_number = db.Column(db.String(120), unique=True, nullable=False)

    def __repr__(self):
        return '<User %r>' % self.username

    def set_password(self, password):
        self.password = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password, password)

    def save(self):
        db.session.add(self)
        db.session.commit()

#create the tables
with app.app_context():
    db.create_all()

@app.route('/register', methods=['POST'])
def register():
    try:
        data = request.get_json()
        print("Received data:", data)  # Add this line for debugging

        username = data.get('username')
        password = data.get('password')
        phone_number = data.get('phone_number')
        email = data.get('email')

        # Check if the user already exists
        user = User.query.filter_by(email=email).first()
        if user:
            return jsonify({'error': 'User already exists'}), 400
        
        # The phone number should be unique and start with +2547
        if not phone_number.startswith('+2547'):
            return jsonify({'error': 'Invalid phone number'}), 400

        # Create a new user
        user = User(username=username, password=password, phone_number=phone_number, email=email)
        user.set_password(password)
        user.save()

        access_token = create_access_token(identity=user.id)

        return jsonify({'message': 'User created successfully', 'access_token': access_token}), 201

    except Exception as e:
        print("Error:", e)  # Add this line for debugging
        return jsonify({'error': 'Internal Server Error'}), 500

# Initialize SDK
username = "kinyanjui-yurs"    # use 'sandbox' for development in the test environment
api_key = "4c106cbe8995bfaf30af4d9122efdb0dd2145fb92f82948ca2a78368120ed193"      # use your sandbox app API key for development in the test environment
africastalking.initialize(username, api_key)


# Initialize a service e.g. SMS
sms = africastalking.SMS

# Use the service synchronously
# response = sms.send("Hello Message!", ["+254790407966"])
# print(response)

# Or use it asynchronously
# def on_finish(error, response):
#     if error is not None:
#         raise error
#     print(response)

# sms.send("Hello Message!", ["+254790407966"], callback=on_finish)    


@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    user = User.query.filter_by(email=email).first()

    if user and user.check_password(password):
        access_token = create_access_token(identity=user.id)
        return jsonify({'message': 'Login successful', 'access_token': access_token}), 200
    else:
        return jsonify({'error': 'Invalid email or password'}), 401
    
@app.route('/logout', methods=['POST'])
@jwt_required()
def logout():
    return jsonify({'message': 'Logout successful'}), 200

#send sms to user once the payment is made through stripe
@app.route('/stripe-webhook', methods=['POST'])
def stripe_webhook():
    payload = request.get_data(as_text=True)
    sig_header = request.headers.get('Stripe-Signature')

    try:
        event = stripe.Webhook.construct_event(
            payload, sig_header, "sk_test_51OHuVXIxFAeUmU1SI7usNMA7dDjLD0YktsI10rgqn7L88Jm6yyLu5LIyssKyZP7mEZW3VPti5gMfbEqUR8ulieMS008QhBD9iJ"
        )
    except ValueError as e:
        print("invalid payload")        
        return jsonify({"error": "invalid payload"}), 400
    
    except stripe.error.SignatureVerificationError as e:
        print("Invalid signature")
        return jsonify({"error": "Invalid signature"}), 400
    
    # Handle the event
    if event['type'] == 'payment_intent.succeeded':
        # Extract relevant information from the event
        payment_intent = event['data']['object']  # contains a stripe.PaymentIntent

        # Get the user associated with the payment
        user_email = payment_intent['customer']
        user = User.query.filter_by(email=user_email).first()

        if user:
            # Send SMS to the user's phone number
            send_sms(user.phone_number, "Payment successful! Thank you for your purchase.")

    return '', 200 

def send_sms(phone_number, message):
    try:
        sms.send(message, [phone_number])
        print(f"SMS sent to {phone_number} successfully.")
    except Exception as e:
        print(f"Error sending SMS to {phone_number}: {str(e)}")

if __name__ == "__main__":
    #TODO: Call send message function
    
    app.run(debug=True, port=port)
