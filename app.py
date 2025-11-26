from fyers_apiv3 import fyersModel
from flask import Flask, request, render_template_string, jsonify, redirect, url_for, session
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import webbrowser
import pandas as pd
import os
import threading
import time
import json
import requests
import hashlib
from datetime import datetime

app = Flask(__name__)
app.secret_key = "sajid_secret_key_change_this"

# ===== m.Stock API Credentials =====
# Fixed API secret for all users
MSTOCK_API_SECRET = '<your_api_secret_here>'

# Text files for storing data
USERS_FILE = "users.txt"
CREDENTIALS_FILE = "user_credentials.txt"

# Initialize files
def init_files():
    if not os.path.exists(USERS_FILE):
        with open(USERS_FILE, 'w') as f:
            f.write("")
    if not os.path.exists(CREDENTIALS_FILE):
        with open(CREDENTIALS_FILE, 'w') as f:
            f.write("")

init_files()

# ---- User Management Functions ----
def save_user(username, password, email):
    with open(USERS_FILE, 'a') as f:
        hashed_pw = generate_password_hash(password)
        f.write(f"{username}|{hashed_pw}|{email}\n")

def get_user(username):
    if not os.path.exists(USERS_FILE):
        return None
    with open(USERS_FILE, 'r') as f:
        for line in f:
            if line.strip():
                parts = line.strip().split('|')
                if len(parts) >= 3 and parts[0] == username:
                    return {'username': parts[0], 'password': parts[1], 'email': parts[2]}
    return None

def verify_user(username, password):
    user = get_user(username)
    if user and check_password_hash(user['password'], password):
        return user
    return None

def save_user_credentials(username, client_id=None, secret_key=None, auth_code=None, mstock_api_key=None):
    credentials = {}
    if os.path.exists(CREDENTIALS_FILE):
        with open(CREDENTIALS_FILE, 'r') as f:
            for line in f:
                if line.strip():
                    parts = line.strip().split('|')
                    if len(parts) >= 5:
                        credentials[parts[0]] = {
                            'client_id': parts[1], 
                            'secret_key': parts[2], 
                            'auth_code': parts[3],
                            'mstock_api_key': parts[4]
                        }

    if username not in credentials:
        credentials[username] = {
            'client_id': '', 
            'secret_key': '', 
            'auth_code': '',
            'mstock_api_key': ''
        }

    if client_id:
        credentials[username]['client_id'] = client_id
    if secret_key:
        credentials[username]['secret_key'] = secret_key
    if auth_code:
        credentials[username]['auth_code'] = auth_code
    if mstock_api_key:
        credentials[username]['mstock_api_key'] = mstock_api_key

    with open(CREDENTIALS_FILE, 'w') as f:
        for user, creds in credentials.items():
            f.write(f"{user}|{creds['client_id']}|{creds['secret_key']}|{creds['auth_code']}|{creds['mstock_api_key']}\n")

def get_user_credentials(username):
    if not os.path.exists(CREDENTIALS_FILE):
        return None
    with open(CREDENTIALS_FILE, 'r') as f:
        for line in f:
            if line.strip():
                parts = line.strip().split('|')
                if len(parts) >= 5 and parts[0] == username:
                    return {
                        'client_id': parts[1], 
                        'secret_key': parts[2], 
                        'auth_code': parts[3],
                        'mstock_api_key': parts[4]
                    }
    return None

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            return redirect(url_for('login_page'))
        return f(*args, **kwargs)
    return decorated_function

# ---- User-specific sessions ----
user_sessions = {}

def get_user_session(username):
    if username not in user_sessions:
        user_sessions[username] = {
            'fyers': None,
            'atm_strike': None,
            'initial_data': None,
            'ce_atm_low': None,  # Track CE ATM low
            'pe_atm_low': None,  # Track PE ATM low
            'ce_threshold': 10,  # Default CE threshold
            'pe_threshold': 10,  # Default PE threshold
            'ce_target': 20,  # Default CE target
            'pe_target': 20,  # Default PE target
            'ce_trailing_stop': 5,  # Default CE trailing stop loss
            'pe_trailing_stop': 5,  # Default PE trailing stop loss
            'ce_trailing_target': 15,  # Default CE trailing target
            'pe_trailing_target': 15,  # Default PE trailing target
            'symbol_prefix': 'NSE:NIFTY25',
            'signals': [],
            'buy_orders': set(),  # Track buy orders placed
            'sell_orders': set(),  # Track sell orders placed
            'order_prices': {},  # Store entry prices for placed orders
            'trailing_stop_prices': {},  # Store trailing stop prices for each position
            'highest_prices': {},  # Store highest prices reached for each position
            'bot_running': False,
            'bot_thread': None,
            'redirect_uri': f'http://127.0.0.1:5000/callback/{username}',
            'mstock_access_token': None,
            'mstock_access_token_expiry': None,
            'mstock_refresh_token': None,
            'mstock_refresh_token_expiry': None
        }
    return user_sessions[username]

# ---- Fyers Functions ----
def init_fyers_for_user(username, client_id, secret_key, auth_code):
    user_sess = get_user_session(username)
    try:
        appSession = fyersModel.SessionModel(
            client_id=client_id,
            secret_key=secret_key,
            redirect_uri=user_sess['redirect_uri'],
            response_type="code",
            grant_type="authorization_code",
            state="sample"
        )
        appSession.set_token(auth_code)
        token_response = appSession.generate_token()
        access_token = token_response.get("access_token")
        if not access_token:
            print(f"❌ Failed to get access token for {username}")
            return False

        user_sess['fyers'] = fyersModel.FyersModel(
            client_id=client_id,
            token=access_token,
            is_async=False,
            log_path=""
        )
        print(f"✅ Fyers initialized for {username}")
        return True
    except Exception as e:
        print(f"❌ Failed to init Fyers for {username}:", e)
        return False

# ---- mStock Functions ----
def init_mstock_for_user(username, mstock_api_key, totp):
    user_sess = get_user_session(username)
    try:
        checksum = hashlib.sha256(f"{mstock_api_key}{totp}{MSTOCK_API_SECRET}".encode()).hexdigest()
        headers = {'X-Mirae-Version': '1', 'Content-Type': 'application/x-www-form-urlencoded'}
        data = {'api_key': mstock_api_key, 'totp': totp, 'checksum': checksum}
        
        response = requests.post(
            'https://api.mstock.trade/openapi/typea/session/verifytotp',
            headers=headers,
            data=data
        )
        resp_json = response.json()
        
        if resp_json.get("status") == "success":
            access_token = resp_json["data"]["access_token"]
            access_token_expiry = time.time() + resp_json["data"].get("expires_in", 3600)
            user_sess['mstock_access_token'] = access_token
            user_sess['mstock_access_token_expiry'] = access_token_expiry
            
            if "refresh_token" in resp_json["data"]:
                refresh_token = resp_json["data"]["refresh_token"]
                refresh_token_expiry = time.time() + resp_json["data"].get("refresh_token_expires_in", 86400)
                user_sess['mstock_refresh_token'] = refresh_token
                user_sess['mstock_refresh_token_expiry'] = refresh_token_expiry
            
            print(f"✅ mStock initialized for {username}")
            return True
        else:
            print(f"❌ Failed to init mStock for {username}: {resp_json.get('message', 'Unknown error')}")
            return False
    except Exception as e:
        print(f"❌ Failed to init mStock for {username}:", e)
        return False

def place_fyers_order(username, symbol, price, side):
    """Place order with Fyers broker"""
    user_sess = get_user_session(username)
    try:
        if user_sess['fyers'] is None:
            return {"status": "error", "message": "Fyers not initialized", "broker": "Fyers"}
        
        data = {
            "symbol": symbol,
            "qty": 600,
            "type": 2,
            "side": side,
            "productType": "INTRADAY",
            "limitPrice": price,
            "stopPrice": 0,
            "validity": "DAY",
            "disclosedQty": 0,
            "offlineOrder": False,
            "orderTag": "signalorder"
        }
        response = user_sess['fyers'].place_order(data=data)
        print(f"✅ Fyers order placed for {username}:", response)
        return {"status": "success", "response": response, "broker": "Fyers"}
    except Exception as e:
        print(f"❌ Fyers order error for {username}:", e)
        return {"status": "error", "message": str(e), "broker": "Fyers"}

def place_mstock_order(username, symbol, price, side):
    """Place order with mStock broker"""
    user_sess = get_user_session(username)
    creds = get_user_credentials(username)
    access_token = user_sess.get('mstock_access_token')
    
    if not access_token:
        return {"status": "error", "message": "mStock not authenticated", "broker": "mStock"}
    
    try:
        # Convert Fyers symbol format to mStock format if needed
        mstock_symbol = symbol
        if ":" in symbol:  # Convert NSE:NIFTY25-25000CE to NIFTY25N1124500CE format
            parts = symbol.split(":")
            if len(parts) > 1:
                mstock_symbol = parts[1].replace("-", "")
        
        # Convert side (1=BUY, -1=SELL) to transaction_type
        transaction_type = "BUY" if side == 1 else "SELL"
        
        # Prepare order data
        data = {
            'tradingsymbol': mstock_symbol,
            'exchange': 'NFO',  # Assuming NFO for options
            'transaction_type': transaction_type,  # BUY or SELL
            'order_type': 'LIMIT',  # MARKET, LIMIT, etc.
            'quantity': 600,
            'product': 'MIS',  # MIS for intraday
            'validity': 'DAY',
            'price': price,
            'variety': 'regular'  # Regular order
        }
        
        # Prepare headers
        headers = {
            'X-Mirae-Version': '1',
            'Authorization': f'token {creds["mstock_api_key"]}:{access_token}',
            'Content-Type': 'application/x-www-form-urlencoded',
        }
        
        # Make API request
        response = requests.post(
            f'https://api.mstock.trade/openapi/typea/orders/regular',
            headers=headers,
            data=data
        )
        
        resp_json = response.json()
        
        if resp_json.get("status") == "success":
            order_id = resp_json.get("data", {}).get("orderid")
            print(f"✅ mStock order placed for {username}: {order_id}")
            return {"status": "success", "order_id": order_id, "broker": "mStock"}
        else:
            error_message = resp_json.get("message", "Failed to place order")
            print(f"❌ mStock order failed for {username}: {error_message}")
            return {"status": "error", "message": error_message, "broker": "mStock"}
            
    except Exception as e:
        print(f"❌ mStock order error for {username}: {e}")
        return {"status": "error", "message": str(e), "broker": "mStock"}

def place_order(username, symbol, price, side):
    """Place order with both Fyers and mStock brokers"""
    fyers_response = place_fyers_order(username, symbol, price, side)
    mstock_response = place_mstock_order(username, symbol, price, side)
    
    return {
        "fyers": fyers_response,
        "mstock": mstock_response,
        "overall_status": "success" if (fyers_response.get("status") == "success" or mstock_response.get("status") == "success") else "error"
    }

def background_bot_worker(username):
    """Background bot worker that processes option chain and places orders on both brokers"""
    user_sess = get_user_session(username)
    print(f"🤖 Background bot started for {username}")

    while user_sess['bot_running']:
        if user_sess['fyers'] is None:
            time.sleep(5)
            continue

        try:
            data = {"symbol": "NSE:NIFTY50-INDEX", "strikecount": 10, "timestamp": ""}
            response = user_sess['fyers'].optionchain(data=data)

            if "data" not in response or "optionsChain" not in response["data"]:
                time.sleep(2)
                continue

            options_data = response["data"]["optionsChain"]
            if not options_data:
                time.sleep(2)
                continue

            df = pd.DataFrame(options_data)
            df_pivot = df.pivot_table(index="strike_price", columns="option_type", values="ltp", aggfunc="first").reset_index()
            df_pivot = df_pivot.rename(columns={"CE": "CE_LTP", "PE": "PE_LTP"})

            if user_sess['atm_strike'] is None:
                nifty_spot = response["data"].get("underlyingValue", df_pivot["strike_price"].iloc[len(df_pivot) // 2])
                user_sess['atm_strike'] = min(df_pivot["strike_price"], key=lambda x: abs(x - nifty_spot))
                user_sess['initial_data'] = df_pivot.to_dict(orient="records")
                user_sess['signals'].clear()
                user_sess['buy_orders'].clear()
                user_sess['sell_orders'].clear()
                user_sess['order_prices'].clear()
                user_sess['trailing_stop_prices'].clear()
                user_sess['highest_prices'].clear()

                # Initialize CE and PE ATM lows
                atm_row = df_pivot[df_pivot["strike_price"] == user_sess['atm_strike']]
                if not atm_row.empty:
                    user_sess['ce_atm_low'] = atm_row["CE_LTP"].values[0]
                    user_sess['pe_atm_low'] = atm_row["PE_LTP"].values[0]

            # Update CE and PE ATM lows if they're lower than current values
            atm_row = df_pivot[df_pivot["strike_price"] == user_sess['atm_strike']]
            if not atm_row.empty:
                current_ce = atm_row["CE_LTP"].values[0]
                current_pe = atm_row["PE_LTP"].values[0]

                if user_sess['ce_atm_low'] is None or current_ce < user_sess['ce_atm_low']:
                    user_sess['ce_atm_low'] = current_ce

                if user_sess['pe_atm_low'] is None or current_pe < user_sess['pe_atm_low']:
                    user_sess['pe_atm_low'] = current_pe

                # Check for CE signal: if current CE > CE low + CE threshold
                ce_signal_name = f"ATM_CE_{user_sess['atm_strike']}"
                if current_ce > user_sess['ce_atm_low'] + user_sess['ce_threshold']:
                    if ce_signal_name not in user_sess['buy_orders'] and ce_signal_name not in user_sess['sell_orders']:
                        user_sess['signals'].append(f"{user_sess['atm_strike']} {current_ce} ATM Strike CE")
                        response = place_order(username, f"{user_sess['symbol_prefix']}{user_sess['atm_strike']}CE", current_ce, side=1)
                        if response.get("overall_status") == "success":
                            user_sess['buy_orders'].add(ce_signal_name)
                            user_sess['order_prices'][ce_signal_name] = current_ce
                            # Initialize trailing stop loss for this position
                            user_sess['trailing_stop_prices'][ce_signal_name] = current_ce - user_sess['ce_trailing_stop']
                            user_sess['highest_prices'][ce_signal_name] = current_ce

                # Check for PE signal: if current PE > PE low + PE threshold
                pe_signal_name = f"ATM_PE_{user_sess['atm_strike']}"
                if current_pe > user_sess['pe_atm_low'] + user_sess['pe_threshold']:
                    if pe_signal_name not in user_sess['buy_orders'] and pe_signal_name not in user_sess['sell_orders']:
                        user_sess['signals'].append(f"{user_sess['atm_strike']} {current_pe} ATM Strike PE")
                        response = place_order(username, f"{user_sess['symbol_prefix']}{user_sess['atm_strike']}PE", current_pe, side=1)
                        if response.get("overall_status") == "success":
                            user_sess['buy_orders'].add(pe_signal_name)
                            user_sess['order_prices'][pe_signal_name] = current_pe
                            # Initialize trailing stop loss for this position
                            user_sess['trailing_stop_prices'][pe_signal_name] = current_pe - user_sess['pe_trailing_stop']
                            user_sess['highest_prices'][pe_signal_name] = current_pe

                # Check for trailing stop loss and target conditions
                for signal_name in list(user_sess['buy_orders']):
                    if signal_name.startswith("ATM_CE_"):
                        # Update highest price if current price is higher
                        if current_ce > user_sess['highest_prices'][signal_name]:
                            user_sess['highest_prices'][signal_name] = current_ce
                            # Update trailing stop loss
                            user_sess['trailing_stop_prices'][signal_name] = current_ce - user_sess['ce_trailing_stop']
                        
                        # Check if trailing stop loss is triggered
                        if current_ce <= user_sess['trailing_stop_prices'][signal_name]:
                            # Place sell order for CE
                            user_sess['signals'].append(f"SELL {user_sess['atm_strike']} {current_ce} ATM Strike CE - Trailing Stop Loss Triggered")
                            place_order(username, f"{user_sess['symbol_prefix']}{user_sess['atm_strike']}CE", current_ce, side=-1)
                            user_sess['buy_orders'].remove(signal_name)
                            user_sess['sell_orders'].add(signal_name)
                        
                        # Check if target is reached
                        entry_price = user_sess['order_prices'].get(signal_name, 0)
                        if entry_price > 0 and current_ce >= entry_price + user_sess['ce_target']:
                            # Place sell order for CE
                            user_sess['signals'].append(f"SELL {user_sess['atm_strike']} {current_ce} ATM Strike CE - Target Reached")
                            place_order(username, f"{user_sess['symbol_prefix']}{user_sess['atm_strike']}CE", current_ce, side=-1)
                            user_sess['buy_orders'].remove(signal_name)
                            user_sess['sell_orders'].add(signal_name)

                    elif signal_name.startswith("ATM_PE_"):
                        # Update highest price if current price is higher
                        if current_pe > user_sess['highest_prices'][signal_name]:
                            user_sess['highest_prices'][signal_name] = current_pe
                            # Update trailing stop loss
                            user_sess['trailing_stop_prices'][signal_name] = current_pe - user_sess['pe_trailing_stop']
                        
                        # Check if trailing stop loss is triggered
                        if current_pe <= user_sess['trailing_stop_prices'][signal_name]:
                            # Place sell order for PE
                            user_sess['signals'].append(f"SELL {user_sess['atm_strike']} {current_pe} ATM Strike PE - Trailing Stop Loss Triggered")
                            place_order(username, f"{user_sess['symbol_prefix']}{user_sess['atm_strike']}PE", current_pe, side=-1)
                            user_sess['buy_orders'].remove(signal_name)
                            user_sess['sell_orders'].add(signal_name)
                        
                        # Check if target is reached
                        entry_price = user_sess['order_prices'].get(signal_name, 0)
                        if entry_price > 0 and current_pe >= entry_price + user_sess['pe_target']:
                            # Place sell order for PE
                            user_sess['signals'].append(f"SELL {user_sess['atm_strike']} {current_pe} ATM Strike PE - Target Reached")
                            place_order(username, f"{user_sess['symbol_prefix']}{user_sess['atm_strike']}PE", current_pe, side=-1)
                            user_sess['buy_orders'].remove(signal_name)
                            user_sess['sell_orders'].add(signal_name)

        except Exception as e:
            print(f"❌ Background bot error for {username}: {e}")

        time.sleep(2)

    print(f"🤖 Background bot stopped for {username}")

# ---- Auth Routes ----
@app.route('/sp', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        email = request.form.get('email')

        if not username or not password or not email:
            return render_template_string(SIGNUP_TEMPLATE, error="All fields are required!")

        if get_user(username):
            return render_template_string(SIGNUP_TEMPLATE, error="Username already exists!")

        save_user(username, password, email)
        return redirect(url_for('login_page'))

    return render_template_string(SIGNUP_TEMPLATE)

@app.route('/login', methods=['GET', 'POST'])
def login_page():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        user = verify_user(username, password)

        if user:
            session['username'] = user['username']
            session['email'] = user['email']

            # Load saved credentials if available
            creds = get_user_credentials(username)
            if creds and creds['client_id'] and creds['secret_key'] and creds['auth_code']:
                init_fyers_for_user(username, creds['client_id'], creds['secret_key'], creds['auth_code'])

            return redirect(url_for('index'))
        else:
            return render_template_string(LOGIN_TEMPLATE, error="Invalid credentials!")

    return render_template_string(LOGIN_TEMPLATE)

@app.route('/logout')
def logout():
    username = session.get('username')
    if username and username in user_sessions:
        user_sessions[username]['bot_running'] = False
    session.clear()
    return redirect(url_for('login_page'))

# ---- Main App Routes ----
@app.route("/", methods=["GET", "POST"])
@login_required
def index():
    username = session['username']
    user_sess = get_user_session(username)
    creds = get_user_credentials(username)
    fyers_authenticated = user_sess['fyers'] is not None
    mstock_authenticated = user_sess.get('mstock_access_token') is not None

    if request.method == "POST":
        try:
            user_sess['ce_threshold'] = float(request.form.get("ce_threshold", 10))
        except (ValueError, TypeError):
            user_sess['ce_threshold'] = 10
        try:
            user_sess['pe_threshold'] = float(request.form.get("pe_threshold", 10))
        except (ValueError, TypeError):
            user_sess['pe_threshold'] = 10
        try:
            user_sess['ce_target'] = float(request.form.get("ce_target", 20))
        except (ValueError, TypeError):
            user_sess['ce_target'] = 20
        try:
            user_sess['pe_target'] = float(request.form.get("pe_target", 20))
        except (ValueError, TypeError):
            user_sess['pe_target'] = 20
        try:
            user_sess['ce_trailing_stop'] = float(request.form.get("ce_trailing_stop", 5))
        except (ValueError, TypeError):
            user_sess['ce_trailing_stop'] = 5
        try:
            user_sess['pe_trailing_stop'] = float(request.form.get("pe_trailing_stop", 5))
        except (ValueError, TypeError):
            user_sess['pe_trailing_stop'] = 5
        try:
            user_sess['ce_trailing_target'] = float(request.form.get("ce_trailing_target", 15))
        except (ValueError, TypeError):
            user_sess['ce_trailing_target'] = 15
        try:
            user_sess['pe_trailing_target'] = float(request.form.get("pe_trailing_target", 15))
        except (ValueError, TypeError):
            user_sess['pe_trailing_target'] = 15
        prefix = request.form.get("symbol_prefix")
        if prefix:
            user_sess['symbol_prefix'] = prefix.strip()

    return render_template_string(
        MAIN_TEMPLATE,
        ce_threshold=user_sess['ce_threshold'],
        pe_threshold=user_sess['pe_threshold'],
        ce_target=user_sess['ce_target'],
        pe_target=user_sess['pe_target'],
        ce_trailing_stop=user_sess['ce_trailing_stop'],
        pe_trailing_stop=user_sess['pe_trailing_stop'],
        ce_trailing_target=user_sess['ce_trailing_target'],
        pe_trailing_target=user_sess['pe_trailing_target'],
        symbol_prefix=user_sess['symbol_prefix'],
        bot_running=user_sess['bot_running'],
        username=username,
        fyers_authenticated=fyers_authenticated,
        mstock_authenticated=mstock_authenticated,
        client_id=creds['client_id'] if creds else "",
        mstock_api_key=creds['mstock_api_key'] if creds else ""
    )

@app.route("/setup_credentials", methods=["GET", "POST"])
@login_required
def setup_credentials():
    username = session['username']
    creds = get_user_credentials(username)

    if request.method == "POST":
        client_id = request.form.get("client_id")
        secret_key = request.form.get("secret_key")
        mstock_api_key = request.form.get("mstock_api_key")

        if client_id and secret_key and mstock_api_key:
            save_user_credentials(username, client_id=client_id, secret_key=secret_key, mstock_api_key=mstock_api_key)
            return redirect(url_for('index'))

    return render_template_string(CREDENTIALS_TEMPLATE,
                                   client_id=creds['client_id'] if creds else "",
                                   secret_key=creds['secret_key'] if creds else "",
                                   mstock_api_key=creds['mstock_api_key'] if creds else "")

@app.route("/fyers_login")
@login_required
def fyers_login():
    username = session['username']
    creds = get_user_credentials(username)
    user_sess = get_user_session(username)

    if not creds or not creds['client_id'] or not creds['secret_key']:
        return redirect(url_for('setup_credentials'))

    appSession = fyersModel.SessionModel(
        client_id=creds['client_id'],
        secret_key=creds['secret_key'],
        redirect_uri=user_sess['redirect_uri'],
        response_type="code",
        grant_type="authorization_code",
        state="sample"
    )

    login_url = appSession.generate_authcode()
    webbrowser.open(login_url, new=1)
    return redirect(login_url)

@app.route("/callback/<username>")
def callback(username):
    auth_code = request.args.get("auth_code")
    if auth_code:
        creds = get_user_credentials(username)
        if creds:
            save_user_credentials(username, auth_code=auth_code)
            if init_fyers_for_user(username, creds['client_id'], creds['secret_key'], auth_code):
                return "<h2>✅ Fyers Authentication Successful! You can return to the app 🚀</h2>"
    return "❌ Fyers Authentication failed. Please retry."

@app.route("/mstock_auth", methods=["GET", "POST"])
@login_required
def mstock_auth():
    username = session['username']
    user_sess = get_user_session(username)
    creds = get_user_credentials(username)
    access_token = user_sess.get('mstock_access_token')
    error = None

    if request.method == "POST" and not access_token:
        totp = request.form.get("totp", "").strip()
        if not totp:
            error = "OTP is required!"
        else:
            if not creds or not creds['mstock_api_key']:
                error = "mStock API key not configured. Please setup your credentials first."
            else:
                if init_mstock_for_user(username, creds['mstock_api_key'], totp):
                    return redirect(url_for('index'))
                else:
                    error = "Failed to authenticate with mStock. Please check your OTP and try again."

    return render_template_string(MSTOCK_AUTH_TEMPLATE, 
                                  access_token=access_token, 
                                  error=error, 
                                  mstock_api_key=creds['mstock_api_key'] if creds else "")

@app.route("/fetch")
@login_required
def fetch_option_chain():
    username = session['username']
    user_sess = get_user_session(username)

    if user_sess['fyers'] is None:
        return jsonify({"error": "⚠ Please setup Fyers credentials and login first!"})

    try:
        data = {"symbol": "NSE:NIFTY50-INDEX", "strikecount": 20, "timestamp": ""}
        response = user_sess['fyers'].optionchain(data=data)

        if "data" not in response or "optionsChain" not in response["data"]:
            return jsonify({"error": f"Invalid response from API"})

        options_data = response["data"]["optionsChain"]
        if not options_data:
            return jsonify({"error": "No options data found!"})

        df = pd.DataFrame(options_data)
        df_pivot = df.pivot_table(index="strike_price", columns="option_type", values="ltp", aggfunc="first").reset_index()
        df_pivot = df_pivot.rename(columns={"CE": "CE_LTP", "PE": "PE_LTP"})

        if user_sess['atm_strike'] is None:
            nifty_spot = response["data"].get("underlyingValue", df_pivot["strike_price"].iloc[len(df_pivot) // 2])
            user_sess['atm_strike'] = min(df_pivot["strike_price"], key=lambda x: abs(x - nifty_spot))
            user_sess['initial_data'] = df_pivot.to_dict(orient="records")
            user_sess['signals'].clear()
            user_sess['buy_orders'].clear()
            user_sess['sell_orders'].clear()
            user_sess['order_prices'].clear()
            user_sess['trailing_stop_prices'].clear()
            user_sess['highest_prices'].clear()

            # Initialize CE and PE ATM lows
            atm_row = df_pivot[df_pivot["strike_price"] == user_sess['atm_strike']]
            if not atm_row.empty:
                user_sess['ce_atm_low'] = atm_row["CE_LTP"].values[0]
                user_sess['pe_atm_low'] = atm_row["PE_LTP"].values[0]

        # Update CE and PE ATM lows if they're lower than current values
        atm_row = df_pivot[df_pivot["strike_price"] == user_sess['atm_strike']]
        if not atm_row.empty:
            current_ce = atm_row["CE_LTP"].values[0]
            current_pe = atm_row["PE_LTP"].values[0]

            if user_sess['ce_atm_low'] is None or current_ce < user_sess['ce_atm_low']:
                user_sess['ce_atm_low'] = current_ce

            if user_sess['pe_atm_low'] is None or current_pe < user_sess['pe_atm_low']:
                user_sess['pe_atm_low'] = current_pe

            # Check for CE signal: if current CE > CE low + CE threshold
            ce_signal_name = f"ATM_CE_{user_sess['atm_strike']}"
            if current_ce > user_sess['ce_atm_low'] + user_sess['ce_threshold']:
                if ce_signal_name not in user_sess['buy_orders'] and ce_signal_name not in user_sess['sell_orders']:
                    user_sess['signals'].append(f"{user_sess['atm_strike']} {current_ce} ATM Strike CE")
                    response = place_order(username, f"{user_sess['symbol_prefix']}{user_sess['atm_strike']}CE", current_ce, side=1)
                    if response.get("overall_status") == "success":
                        user_sess['buy_orders'].add(ce_signal_name)
                        user_sess['order_prices'][ce_signal_name] = current_ce
                        # Initialize trailing stop loss for this position
                        user_sess['trailing_stop_prices'][ce_signal_name] = current_ce - user_sess['ce_trailing_stop']
                        user_sess['highest_prices'][ce_signal_name] = current_ce

            # Check for PE signal: if current PE > PE low + PE threshold
            pe_signal_name = f"ATM_PE_{user_sess['atm_strike']}"
            if current_pe > user_sess['pe_atm_low'] + user_sess['pe_threshold']:
                if pe_signal_name not in user_sess['buy_orders'] and pe_signal_name not in user_sess['sell_orders']:
                    user_sess['signals'].append(f"{user_sess['atm_strike']} {current_pe} ATM Strike PE")
                    response = place_order(username, f"{user_sess['symbol_prefix']}{user_sess['atm_strike']}PE", current_pe, side=1)
                    if response.get("overall_status") == "success":
                        user_sess['buy_orders'].add(pe_signal_name)
                        user_sess['order_prices'][pe_signal_name] = current_pe
                        # Initialize trailing stop loss for this position
                        user_sess['trailing_stop_prices'][pe_signal_name] = current_pe - user_sess['pe_trailing_stop']
                        user_sess['highest_prices'][pe_signal_name] = current_pe

            # Check for trailing stop loss and target conditions
            for signal_name in list(user_sess['buy_orders']):
                if signal_name.startswith("ATM_CE_"):
                    # Update highest price if current price is higher
                    if current_ce > user_sess['highest_prices'][signal_name]:
                        user_sess['highest_prices'][signal_name] = current_ce
                        # Update trailing stop loss
                        user_sess['trailing_stop_prices'][signal_name] = current_ce - user_sess['ce_trailing_stop']
                    
                    # Check if trailing stop loss is triggered
                    if current_ce <= user_sess['trailing_stop_prices'][signal_name]:
                        # Place sell order for CE
                        user_sess['signals'].append(f"SELL {user_sess['atm_strike']} {current_ce} ATM Strike CE - Trailing Stop Loss Triggered")
                        place_order(username, f"{user_sess['symbol_prefix']}{user_sess['atm_strike']}CE", current_ce, side=-1)
                        user_sess['buy_orders'].remove(signal_name)
                        user_sess['sell_orders'].add(signal_name)
                    
                    # Check if target is reached
                    entry_price = user_sess['order_prices'].get(signal_name, 0)
                    if entry_price > 0 and current_ce >= entry_price + user_sess['ce_target']:
                        # Place sell order for CE
                        user_sess['signals'].append(f"SELL {user_sess['atm_strike']} {current_ce} ATM Strike CE - Target Reached")
                        place_order(username, f"{user_sess['symbol_prefix']}{user_sess['atm_strike']}CE", current_ce, side=-1)
                        user_sess['buy_orders'].remove(signal_name)
                        user_sess['sell_orders'].add(signal_name)

                elif signal_name.startswith("ATM_PE_"):
                    # Update highest price if current price is higher
                    if current_pe > user_sess['highest_prices'][signal_name]:
                        user_sess['highest_prices'][signal_name] = current_pe
                        # Update trailing stop loss
                        user_sess['trailing_stop_prices'][signal_name] = current_pe - user_sess['pe_trailing_stop']
                    
                    # Check if trailing stop loss is triggered
                    if current_pe <= user_sess['trailing_stop_prices'][signal_name]:
                        # Place sell order for PE
                        user_sess['signals'].append(f"SELL {user_sess['atm_strike']} {current_pe} ATM Strike PE - Trailing Stop Loss Triggered")
                        place_order(username, f"{user_sess['symbol_prefix']}{user_sess['atm_strike']}PE", current_pe, side=-1)
                        user_sess['buy_orders'].remove(signal_name)
                        user_sess['sell_orders'].add(signal_name)
                    
                    # Check if target is reached
                    entry_price = user_sess['order_prices'].get(signal_name, 0)
                    if entry_price > 0 and current_pe >= entry_price + user_sess['pe_target']:
                        # Place sell order for PE
                        user_sess['signals'].append(f"SELL {user_sess['atm_strike']} {current_pe} ATM Strike PE - Target Reached")
                        place_order(username, f"{user_sess['symbol_prefix']}{user_sess['atm_strike']}PE", current_pe, side=-1)
                        user_sess['buy_orders'].remove(signal_name)
                        user_sess['sell_orders'].add(signal_name)

        return df_pivot.to_json(orient="records")
    except Exception as e:
        return jsonify({"error": str(e)})

@app.route("/start_bot", methods=["POST"])
@login_required
def start_bot():
    username = session['username']
    user_sess = get_user_session(username)

    if user_sess['fyers'] is None:
        return jsonify({"error": "⚠️ Please login with Fyers first!"})

    if user_sess['bot_running']:
        return jsonify({"error": "⚠️ Bot is already running!"})

    user_sess['bot_running'] = True
    user_sess['bot_thread'] = threading.Thread(target=background_bot_worker, args=(username,), daemon=True)
    user_sess['bot_thread'].start()

    return jsonify({"message": "✅ Bot started! Running in background!"})

@app.route("/stop_bot", methods=["POST"])
@login_required
def stop_bot():
    username = session['username']
    user_sess = get_user_session(username)
    user_sess['bot_running'] = False
    return jsonify({"message": "✅ Bot stopped!"})

@app.route("/bot_status")
@login_required
def bot_status():
    username = session['username']
    user_sess = get_user_session(username)
    return jsonify({
        "running": user_sess['bot_running'],
        "signals": user_sess['signals'],
        "buy_orders": list(user_sess['buy_orders']),
        "sell_orders": list(user_sess['sell_orders']),
        "order_prices": user_sess['order_prices'],
        "trailing_stop_prices": user_sess['trailing_stop_prices'],
        "highest_prices": user_sess['highest_prices'],
        "ce_atm_low": user_sess['ce_atm_low'],
        "pe_atm_low": user_sess['pe_atm_low'],
        "ce_target": user_sess['ce_target'],
        "pe_target": user_sess['pe_target'],
        "ce_trailing_stop": user_sess['ce_trailing_stop'],
        "pe_trailing_stop": user_sess['pe_trailing_stop'],
        "ce_trailing_target": user_sess['ce_trailing_target'],
        "pe_trailing_target": user_sess['pe_trailing_target']
    })

@app.route("/reset", methods=["POST"])
@login_required
def reset_orders():
    username = session['username']
    user_sess = get_user_session(username)
    user_sess['buy_orders'].clear()
    user_sess['sell_orders'].clear()
    user_sess['signals'].clear()
    user_sess['order_prices'].clear()
    user_sess['trailing_stop_prices'].clear()
    user_sess['highest_prices'].clear()
    user_sess['atm_strike'] = None
    user_sess['initial_data'] = None
    user_sess['ce_atm_low'] = None
    user_sess['pe_atm_low'] = None
    return jsonify({"message": "✅ Reset successful!"})

# ---- HTML Templates ----
SIGNUP_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Sign Up</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: Arial, sans-serif; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
               display: flex; justify-content: center; align-items: center; min-height: 100vh; }
        .container { background: white; padding: 40px; border-radius: 10px; box-shadow: 0 10px 25px rgba(0,0,0,0.2); width: 400px; }
        h2 { color: #333; text-align: center; margin-bottom: 30px; }
        input { width: 100%; padding: 12px; margin: 10px 0; border: 1px solid #ddd; border-radius: 5px; }
        button { width: 100%; padding: 12px; background: #667eea; color: white; border: none; border-radius: 5px;
                 cursor: pointer; font-size: 16px; margin-top: 10px; }
        button:hover { background: #5568d3; }
        .error { color: red; text-align: center; margin-bottom: 10px; }
        .link { text-align: center; margin-top: 20px; }
        .link a { color: #667eea; text-decoration: none; }
    </style>
</head>
<body>
    <div class="container">
        <h2>📝 Sign Up</h2>
        {% if error %}<div class="error">{{ error }}</div>{% endif %}
        <form method="POST">
            <input type="text" name="username" placeholder="Username" required>
            <input type="email" name="email" placeholder="Email" required>
            <input type="password" name="password" placeholder="Password" minlength="6" required>
            <button type="submit">Create Account</button>
        </form>
    </div>
</body>
</html>
"""

LOGIN_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Login</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: Arial, sans-serif; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
               display: flex; justify-content: center; align-items: center; min-height: 100vh; }
        .container { background: white; padding: 40px; border-radius: 10px; box-shadow: 0 10px 25px rgba(0,0,0,0.2); width: 400px; }
        h2 { color: #333; text-align: center; margin-bottom: 30px; }
        input { width: 100%; padding: 12px; margin: 10px 0; border: 1px solid #ddd; border-radius: 5px; }
        button { width: 100%; padding: 12px; background: #667eea; color: white; border: none; border-radius: 5px;
                 cursor: pointer; font-size: 16px; margin-top: 10px; }
        button:hover { background: #5568d3; }
        .error { color: red; text-align: center; margin-bottom: 10px; }
        .link { text-align: center; margin-top: 20px; }
        .link a { color: #667eea; text-decoration: none; }
    </style>
</head>
<body>
    <div class="container">
        <h2>🔐 Login</h2>
        {% if error %}<div class="error">{{ error }}</div>{% endif %}
        <form method="POST">
            <input type="text" name="username" placeholder="Username" required>
            <input type="password" name="password" placeholder="Password" required>
            <button type="submit">Login</button>
        </form>
        <div class="link">Don't have an account? Call Mr Sajid Shaikh 9834370368</div>
    </div>
</body>
</html>
"""

CREDENTIALS_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Setup Credentials</title>
    <style>
        body { font-family: Arial, sans-serif; background: #f4f4f9; padding: 20px; }
        .container { max-width: 600px; margin: 50px auto; background: white; padding: 40px;
                     border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        h2 { color: #1a73e8; text-align: center; }
        input { width: 100%; padding: 12px; margin: 10px 0; border: 1px solid #ddd; border-radius: 5px; }
        button { width: 100%; padding: 12px; background: #1a73e8; color: white; border: none;
                 border-radius: 5px; cursor: pointer; font-size: 16px; margin-top: 10px; }
        .info { background: #e3f2fd; padding: 15px; border-radius: 5px; margin-bottom: 20px; }
        .section { margin-bottom: 25px; }
        .section h3 { color: #333; margin-bottom: 10px; }
    </style>
</head>
<body>
    <div class="container">
        <h2>🔑 Setup API Credentials</h2>
        
        <div class="section">
            <h3>Fyers API Credentials</h3>
            <div class="info"><strong>Note:</strong> Enter your Fyers API credentials.</div>
        </div>
        
        <div class="section">
            <h3>mStock API Credentials</h3>
            <div class="info"><strong>Note:</strong> Enter your mStock API Key.</div>
        </div>
        
        <form method="POST">
            <input type="text" name="client_id" placeholder="Fyers Client ID" value="{{ client_id }}" required>
            <input type="text" name="secret_key" placeholder="Fyers Secret Key" value="{{ secret_key }}" required>
            <input type="text" name="mstock_api_key" placeholder="mStock API Key" value="{{ mstock_api_key }}" required>
            <button type="submit">Save & Continue</button>
        </form>
    </div>
</body>
</html>
"""

MSTOCK_AUTH_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>m.Stock OTP Authentication</title>
    <style>
        body { font-family: Arial; max-width: 800px; margin: 0 auto; padding: 20px; background-color: #f5f5f5; }
        .container { background-color: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        h2, h3 { text-align: center; }
        .form-container { background-color: #f9f9f9; padding: 20px; border-radius: 8px; margin-bottom: 20px; }
        .form-group { margin-bottom: 15px; }
        label { display: block; margin-bottom: 5px; font-weight: bold; }
        input[type="text"], input[type="submit"] { width: 100%; padding: 12px; border-radius: 4px; font-size: 16px; }
        input[type="submit"] { background-color: #4CAF50; color: white; border: none; cursor: pointer; }
        input[type="submit"]:hover { background-color: #45a049; }
        .success { color: green; background-color: #dff0d8; padding: 15px; border-radius: 5px; margin-bottom: 20px; }
        .error { color: red; background-color: #f2dede; padding: 15px; border-radius: 5px; margin-bottom: 20px; }
        .token-info { background-color: #e9f7ef; padding: 15px; border-radius: 5px; margin-bottom: 20px; word-break: break-all; }
        .hidden { display: none; }
        .back-link { text-align: center; margin-top: 20px; }
        .back-link a { color: #667eea; text-decoration: none; }
        .api-key-info { background-color: #e3f2fd; padding: 10px; border-radius: 5px; margin-bottom: 20px; }
    </style>
</head>
<body>
    <div class="container">
        <h2>m.Stock API Authentication</h2>
        
        {% if mstock_api_key %}
            <div class="api-key-info">
                <strong>Using API Key:</strong> {{ mstock_api_key }}
            </div>
        {% else %}
            <div class="error">
                <strong>Error:</strong> mStock API key not configured. Please <a href="/setup_credentials">setup your credentials</a> first.
            </div>
        {% endif %}

        <div id="otp-section" class="form-container {% if access_token %}hidden{% endif %}">
            <h3>Enter OTP to Generate Session</h3>
            <form method="POST">
                <div class="form-group">
                    <label for="totp">OTP:</label>
                    <input type="text" id="totp" name="totp" required placeholder="Enter your OTP">
                </div>
                <input type="submit" value="Verify OTP">
            </form>
        </div>

        {% if access_token %}
            <div class="success">
                <h3>✅ Authentication Successful!</h3>
            </div>

            <div class="token-info">
                <p><strong>Access Token:</strong> {{ access_token }}</p>
            </div>

            <div class="form-container">
                <a href="/" style="text-decoration:none;">
                    <input type="button" value="Go to Dashboard" style="background:#007bff;color:white;cursor:pointer;">
                </a>
            </div>
        {% elif error %}
            <div class="error">
                <strong>Error:</strong> {{ error }}
            </div>
        {% endif %}

        <div class="back-link">
            <a href="/">← Back to Main Dashboard</a>
        </div>
    </div>
</body>
</html>
"""

MAIN_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
  <title>Sajid Shaikh's Bot - Dual Broker</title>
  <style>
    body { font-family: Arial, sans-serif; background: #f4f4f9; padding: 20px; }
    .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 15px 30px;
              display: flex; justify-content: space-between; align-items: center; border-radius: 8px; margin-bottom: 20px; }
    .logout-btn { padding: 8px 15px; background: rgba(255,255,255,0.2); color: white; text-decoration: none;
                  border-radius: 4px; border: 1px solid rgba(255,255,255,0.3); margin-left: 10px; }
    .cred-btn { padding: 8px 15px; background: #ff9800; color: white; text-decoration: none; border-radius: 4px; margin-left: 10px; }
    h2 { color: #1a73e8; }
    .bot-control { background: #fff; padding: 15px; margin: 20px 0; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
    .bot-status { display: inline-block; padding: 5px 10px; border-radius: 4px; font-weight: bold; margin-right: 10px; }
    .status-running { background: #4caf50; color: white; }
    .status-stopped { background: #f44336; color: white; }
    .status-authenticated { background: #2196f3; color: white; }
    .status-not-authenticated { background: #ff9800; color: white; }
    .broker-status { display: flex; gap: 10px; align-items: center; margin: 10px 0; }
    table { border-collapse: collapse; width: 70%; margin-top: 10px; }
    th, td { border: 1px solid #aaa; padding: 8px; text-align: center; }
    th { background-color: #1a73e8; color: white; }
    tr:nth-child(even) { background-color: #f2f2f2; }
    tr.atm { background-color: #ffeb3b; font-weight: bold; }
    tr.ceMinus300 { background-color: #90ee90; font-weight: bold; }
    tr.pePlus300 { background-color: #ffb6c1; font-weight: bold; }
    a { text-decoration: none; padding: 8px 12px; background: #4caf50; color: white; border-radius: 4px; }
    a:hover { background: #45a049; }
    button { padding: 8px 12px; color: white; border: none; border-radius: 4px; cursor: pointer; margin-right: 5px; }
    .btn-start { background-color: #4caf50; }
    .btn-start:hover { background-color: #45a049; }
    .btn-stop { background-color: #f44336; }
    .btn-stop:hover { background-color: #da190b; }
    .btn-reset { background-color: #1a73e8; }
    .btn-reset:hover { background-color: #155cb0; }
    #signals { margin-top: 15px; font-weight: bold; color: red; }
    #profits { margin-top: 8px; font-weight: bold; color: green; }
    #lows { margin-top: 8px; font-weight: bold; color: blue; }
    #targets { margin-top: 8px; font-weight: bold; color: purple; }
    #trailing { margin-top: 8px; font-weight: bold; color: #ff6600; }
    form { margin-top: 20px; }
    label { margin-right: 10px; }
    input[type="number"], input[type="text"] { padding: 5px; margin-right: 20px; }
    .form-group { margin-bottom: 10px; }
    .form-group label { display: inline-block; width: 150px; }
    .form-row { display: flex; flex-wrap: wrap; margin-bottom: 10px; }
    .form-col { flex: 1; min-width: 200px; margin-right: 10px; }
  </style>
  <script>
    var atmStrike = null;
    var initialLTP = {};
    var signals = [];
    var ceAtmLow = null;
    var peAtmLow = null;
    var ceTarget = {{ ce_target }};
    var peTarget = {{ pe_target }};
    var ceTrailingStop = {{ ce_trailing_stop }};
    var peTrailingStop = {{ pe_trailing_stop }};
    var ceTrailingTarget = {{ ce_trailing_target }};
    var peTrailingTarget = {{ pe_trailing_target }};
    var orderPrices = {};
    var trailingStopPrices = {};
    var highestPrices = {};
    var buyOrders = new Set();
    var sellOrders = new Set();

    async function startBackgroundBot(){
        let res = await fetch("/start_bot", {method: "POST"});
        let data = await res.json();
        alert(data.message || data.error);
        checkBotStatus();
    }

    async function stopBackgroundBot(){
        let res = await fetch("/stop_bot", {method: "POST"});
        let data = await res.json();
        alert(data.message);
        checkBotStatus();
    }

    async function checkBotStatus(){
        let res = await fetch("/bot_status");
        let data = await res.json();
        let statusDiv = document.getElementById("botStatus");
        if(data.running){
            statusDiv.innerHTML = '<span class="bot-status status-running">🤖 Bot Running (Background)</span>';
            document.getElementById("startBtn").disabled = true;
            document.getElementById("stopBtn").disabled = false;
        } else {
            statusDiv.innerHTML = '<span class="bot-status status-stopped">⏸️ Bot Stopped</span>';
            document.getElementById("startBtn").disabled = false;
            document.getElementById("stopBtn").disabled = true;
        }

        // Update lows display
        if(data.ce_atm_low !== null && data.pe_atm_low !== null){
            document.getElementById("lows").innerHTML = "CE ATM Low: " + data.ce_atm_low.toFixed(2) +
                                                      " | PE ATM Low: " + data.pe_atm_low.toFixed(2);
        }

        // Update targets display
        if(data.ce_target !== null && data.pe_target !== null){
            document.getElementById("targets").innerHTML = "CE Target: " + data.ce_target.toFixed(2) +
                                                         " | PE Target: " + data.pe_target.toFixed(2);
        }

        // Update trailing stop loss display
        if(data.ce_trailing_stop !== null && data.pe_trailing_stop !== null){
            document.getElementById("trailing").innerHTML = "CE Trailing Stop: " + data.ce_trailing_stop.toFixed(2) +
                                                          " | PE Trailing Stop: " + data.pe_trailing_stop.toFixed(2);
        }

        // Update order prices
        if(data.order_prices){
            orderPrices = data.order_prices;
        }

        // Update trailing stop prices
        if(data.trailing_stop_prices){
            trailingStopPrices = data.trailing_stop_prices;
        }

        // Update highest prices
        if(data.highest_prices){
            highestPrices = data.highest_prices;
        }

        // Update buy and sell orders
        if(data.buy_orders){
            buyOrders = new Set(data.buy_orders);
        }
        if(data.sell_orders){
            sellOrders = new Set(data.sell_orders);
        }
    }

    async function fetchChain(){
        let res = await fetch("/fetch");
        let data = await res.json();
        let tbl = document.getElementById("chain");
        tbl.innerHTML = "";
        let signalsDiv = document.getElementById("signals");
        let profitsDiv = document.getElementById("profits");
        let lowsDiv = document.getElementById("lows");
        let targetsDiv = document.getElementById("targets");
        let trailingDiv = document.getElementById("trailing");

        if(data.error){
            tbl.innerHTML = `<tr><td colspan="3">${data.error}</td></tr>`;
            signalsDiv.innerHTML = "";
            profitsDiv.innerHTML = "";
            lowsDiv.innerHTML = "";
            targetsDiv.innerHTML = "";
            trailingDiv.innerHTML = "";
            return;
        }

        if(atmStrike === null){
            atmStrike = data[Math.floor(data.length/2)].strike_price;
        }

        if(Object.keys(initialLTP).length === 0){
            data.forEach(r => {
                initialLTP[r.strike_price] = {CE: r.CE_LTP, PE: r.PE_LTP};
            });
        }

        let atmLive = data.find(r => r.strike_price === atmStrike);
        signals = [];

        let ce_threshold = parseFloat(document.getElementById("ce_threshold").value) || 10;
        let pe_threshold = parseFloat(document.getElementById("pe_threshold").value) || 10;
        ceTarget = parseFloat(document.getElementById("ce_target").value) || 20;
        peTarget = parseFloat(document.getElementById("pe_target").value) || 20;
        ceTrailingStop = parseFloat(document.getElementById("ce_trailing_stop").value) || 5;
        peTrailingStop = parseFloat(document.getElementById("pe_trailing_stop").value) || 5;
        ceTrailingTarget = parseFloat(document.getElementById("ce_trailing_target").value) || 15;
        peTrailingTarget = parseFloat(document.getElementById("pe_trailing_target").value) || 15;

        // Initialize CE and PE ATM lows if not set
        if(ceAtmLow === null && atmLive && atmLive.CE_LTP !== undefined){
            ceAtmLow = atmLive.CE_LTP;
        }
        if(peAtmLow === null && atmLive && atmLive.PE_LTP !== undefined){
            peAtmLow = atmLive.PE_LTP;
        }

        // Update CE and PE ATM lows if they're lower than current values
        if(atmLive && atmLive.CE_LTP !== undefined && atmLive.CE_LTP < ceAtmLow){
            ceAtmLow = atmLive.CE_LTP;
        }
        if(atmLive && atmLive.PE_LTP !== undefined && atmLive.PE_LTP < peAtmLow){
            peAtmLow = atmLive.PE_LTP;
        }

        // Check for CE signal: if current CE > CE low + CE threshold
        let ceSignalName = "ATM_CE_" + atmStrike;
        if(atmLive && atmLive.CE_LTP !== undefined && ceAtmLow !== null &&
           atmLive.CE_LTP > ceAtmLow + ce_threshold &&
           !buyOrders.has(ceSignalName) && !sellOrders.has(ceSignalName)){
            signals.push("ATM Strike CE");
        }

        // Check for PE signal: if current PE > PE low + PE threshold
        let peSignalName = "ATM_PE_" + atmStrike;
        if(atmLive && atmLive.PE_LTP !== undefined && peAtmLow !== null &&
           atmLive.PE_LTP > peAtmLow + pe_threshold &&
           !buyOrders.has(peSignalName) && !sellOrders.has(peSignalName)){
            signals.push("ATM Strike PE");
        }

        // Check for exit conditions based on targets
        let exitSignals = [];

        // Check for CE exit
        let ceOrderPrice = orderPrices["ATM_CE_" + atmStrike];
        if(ceOrderPrice && atmLive && atmLive.CE_LTP !== undefined &&
           atmLive.CE_LTP >= ceOrderPrice + ceTarget && buyOrders.has("ATM_CE_" + atmStrike)){
            exitSignals.push("SELL ATM Strike CE - Target Reached");
        }

        // Check for PE exit
        let peOrderPrice = orderPrices["ATM_PE_" + atmStrike];
        if(peOrderPrice && atmLive && atmLive.PE_LTP !== undefined &&
           atmLive.PE_LTP >= peOrderPrice + peTarget && buyOrders.has("ATM_PE_" + atmStrike)){
            exitSignals.push("SELL ATM Strike PE - Target Reached");
        }

        // Check for trailing stop loss exit
        let ceTrailingStopPrice = trailingStopPrices["ATM_CE_" + atmStrike];
        if(ceTrailingStopPrice && atmLive && atmLive.CE_LTP !== undefined &&
           atmLive.CE_LTP <= ceTrailingStopPrice && buyOrders.has("ATM_CE_" + atmStrike)){
            exitSignals.push("SELL ATM Strike CE - Trailing Stop Loss Triggered");
        }

        let peTrailingStopPrice = trailingStopPrices["ATM_PE_" + atmStrike];
        if(peTrailingStopPrice && atmLive && atmLive.PE_LTP !== undefined &&
           atmLive.PE_LTP <= peTrailingStopPrice && buyOrders.has("ATM_PE_" + atmStrike)){
            exitSignals.push("SELL ATM Strike PE - Trailing Stop Loss Triggered");
        }

        if(signals.length > 0 || exitSignals.length > 0){
            signalsDiv.innerHTML = "📢 Signals: " + signals.concat(exitSignals).join(", ");
        } else {
            signalsDiv.innerHTML = "No signals";
        }

        lowsDiv.innerHTML = "CE ATM Low: " + ceAtmLow.toFixed(2) +
                           " | PE ATM Low: " + peAtmLow.toFixed(2);

        targetsDiv.innerHTML = "CE Target: " + ceTarget.toFixed(2) +
                              " | PE Target: " + peTarget.toFixed(2);

        trailingDiv.innerHTML = "CE Trailing Stop: " + ceTrailingStop.toFixed(2) +
                               " | PE Trailing Stop: " + peTrailingStop.toFixed(2);

        let profitsOutput = "";
        signals.forEach(signal => {
            let strike = atmStrike;
            let initialLtp = null;
            let liveLtp = null;
            let profit = 0;

            if(signal === "ATM Strike CE") {
                initialLtp = ceAtmLow;
                liveLtp = atmLive.CE_LTP;
                profit = (liveLtp - initialLtp);
            } else if(signal === "ATM Strike PE") {
                initialLtp = peAtmLow;
                liveLtp = atmLive.PE_LTP;
                profit = (liveLtp - initialLtp);
            }
            let totalProfit = (profit * 75).toFixed(2);
            profitsOutput += `<b>${signal}</b> - Strike: ${strike} | Low LTP: ${initialLtp?.toFixed(2)} | Live LTP: ${liveLtp?.toFixed(2)} | Profit × 75 = ₹${totalProfit} <br>`;
        });

        // Calculate profit for exited positions
        exitSignals.forEach(signal => {
            if(signal.includes("CE")) {
                let entryPrice = orderPrices["ATM_CE_" + atmStrike];
                let exitPrice = atmLive.CE_LTP;
                let profit = (exitPrice - entryPrice) * 75;
                profitsOutput += `<b>${signal}</b> - Strike: ${atmStrike} | Entry: ${entryPrice?.toFixed(2)} | Exit: ${exitPrice?.toFixed(2)} | Profit × 75 = ₹${profit.toFixed(2)} <br>`;
            } else if(signal.includes("PE")) {
                let entryPrice = orderPrices["ATM_PE_" + atmStrike];
                let exitPrice = atmLive.PE_LTP;
                let profit = (exitPrice - entryPrice) * 75;
                profitsOutput += `<b>${signal}</b> - Strike: ${atmStrike} | Entry: ${entryPrice?.toFixed(2)} | Exit: ${exitPrice?.toFixed(2)} | Profit × 75 = ₹${profit.toFixed(2)} <br>`;
            }
        });

        let ceMinus300 = data.find(r => r.strike_price === atmStrike - 300);
        if(ceMinus300){
            let base = initialLTP[atmStrike - 300]?.CE;
            if(base){
                let gainPct = ((ceMinus300.CE_LTP - base) / base) * 100;
                let profit = (ceMinus300.CE_LTP - base) * 75;
                profitsOutput += `<b>CE -300</b> Profit: ₹${profit.toFixed(2)} (Gain: ${gainPct.toFixed(1)}%)<br>`;
            }
        }

        let pePlus300 = data.find(r => r.strike_price === atmStrike + 300);
        if(pePlus300){
            let base = initialLTP[atmStrike + 300]?.PE;
            if(base){
                let gainPct = ((pePlus300.PE_LTP - base) / base) * 100;
                let profit = (pePlus300.PE_LTP - base) * 75;
                profitsOutput += `<b>PE +300</b> Profit: ₹${profit.toFixed(2)} (Gain: ${gainPct.toFixed(1)}%)<br>`;
            }
        }

        profitsDiv.innerHTML = profitsOutput || "No profits to show.";

        data.forEach(row=>{
            let cls = "";
            let CE_display = row.CE_LTP;
            let PE_display = row.PE_LTP;

            if(row.strike_price === atmStrike){
                cls = "atm";
                CE_display = `${ceAtmLow?.toFixed(2)} / ${atmLive?.CE_LTP?.toFixed(2)}`;
                PE_display = `${peAtmLow?.toFixed(2)} / ${atmLive?.PE_LTP?.toFixed(2)}`;

                // Add target and trailing stop information to ATM row
                let ceEntryPrice = orderPrices["ATM_CE_" + atmStrike];
                let peEntryPrice = orderPrices["ATM_PE_" + atmStrike];
                let ceTrailingStopPrice = trailingStopPrices["ATM_CE_" + atmStrike];
                let peTrailingStopPrice = trailingStopPrices["ATM_PE_" + atmStrike];
                let ceHighestPrice = highestPrices["ATM_CE_" + atmStrike];
                let peHighestPrice = highestPrices["ATM_PE_" + atmStrike];

                if(ceEntryPrice) {
                    CE_display += ` (Entry: ${ceEntryPrice.toFixed(2)}, Target: ${(ceEntryPrice + ceTarget).toFixed(2)})`;
                    if(ceTrailingStopPrice) {
                        CE_display += ` (Trailing Stop: ${ceTrailingStopPrice.toFixed(2)})`;
                    }
                    if(ceHighestPrice) {
                        CE_display += ` (Highest: ${ceHighestPrice.toFixed(2)})`;
                    }
                }
                if(peEntryPrice) {
                    PE_display += ` (Entry: ${peEntryPrice.toFixed(2)}, Target: ${(peEntryPrice + peTarget).toFixed(2)})`;
                    if(peTrailingStopPrice) {
                        PE_display += ` (Trailing Stop: ${peTrailingStopPrice.toFixed(2)})`;
                    }
                    if(peHighestPrice) {
                        PE_display += ` (Highest: ${peHighestPrice.toFixed(2)})`;
                    }
                }
            }

            if(row.strike_price === atmStrike - 300){
                cls = "ceMinus300";
                let base = initialLTP[row.strike_price]?.CE;
                if(base){
                    let gainPct = ((row.CE_LTP - base) / base) * 100;
                    let steps = Math.floor(gainPct / 25);
                    CE_display = `${base} / ${row.CE_LTP} (${steps*25}% crossed)`;
                }
                let basePE = initialLTP[row.strike_price]?.PE;
                if(basePE){
                    PE_display = `${basePE} / ${row.PE_LTP}`;
                }
            }

            if(row.strike_price === atmStrike + 300){
                cls = "pePlus300";
                let base = initialLTP[row.strike_price]?.PE;
                if(base){
                    let gainPct = ((row.PE_LTP - base) / base) * 100;
                    let steps = Math.floor(gainPct / 25);
                    PE_display = `${base} / ${row.PE_LTP} (${steps*25}% crossed)`;
                }
                let baseCE = initialLTP[row.strike_price]?.CE;
                if(baseCE){
                    CE_display = `${baseCE} / ${row.CE_LTP}`;
                }
            }

            tbl.innerHTML += `<tr class="${cls}"><td>${row.strike_price}</td><td>${CE_display}</td><td>${PE_display}</td></tr>`;
        });
    }

    setInterval(fetchChain, 2000);
    setInterval(checkBotStatus, 3000);
    window.onload = function(){
        fetchChain();
        checkBotStatus();
    };

    async function resetOrders(){
        let res = await fetch("/reset", {method: "POST"});
        let data = await res.json();
        alert(data.message);
        atmStrike = null;
        initialLTP = {};
        ceAtmLow = null;
        peAtmLow = null;
        orderPrices = {};
        trailingStopPrices = {};
        highestPrices = {};
        buyOrders.clear();
        sellOrders.clear();
        return false;
    }
  </script>
</head>
<body>
  <div class="header">
    <h1>Sajid Shaikh's Bot : +91 9834370368 (Dual Broker)</h1>
    <div>
      <span>Welcome, <strong>{{ username }}</strong>!</span>
      <a href="/setup_credentials" class="cred-btn">⚙️ Credentials</a>
      <a href="/logout" class="logout-btn">Logout</a>
    </div>
  </div>

  <div class="bot-control">
    <div class="broker-status">
      <div>
        <strong>Fyers Status:</strong>
        {% if fyers_authenticated %}
          <span class="bot-status status-authenticated">✅ Authenticated</span>
        {% else %}
          <span class="bot-status status-not-authenticated">⚠️ Not Authenticated</span>
          <a href="/fyers_login" style="text-decoration:none; padding: 5px 10px; background: #2196f3; color: white; border-radius: 4px; margin-left: 10px;">Login with Fyers</a>
        {% endif %}
      </div>
      <div>
        <strong>mStock Status:</strong>
        {% if mstock_authenticated %}
          <span class="bot-status status-authenticated">✅ Authenticated</span>
        {% else %}
          <span class="bot-status status-not-authenticated">⚠️ Not Authenticated</span>
          <a href="/mstock_auth" style="text-decoration:none; padding: 5px 10px; background: #ff9800; color: white; border-radius: 4px; margin-left: 10px;">Authenticate with mStock</a>
        {% endif %}
      </div>
    </div>
    <div id="botStatus">
      <span class="bot-status status-stopped">⏸️ Bot Stopped</span>
    </div>
    <p style="margin: 10px 0; color: #666;">
      ℹ️ Bot uses Fyers for market data and places orders on both Fyers and mStock brokers
    </p>
    <button id="startBtn" class="btn-start" onclick="startBackgroundBot()">▶️ Start Background Bot</button>
    <button id="stopBtn" class="btn-stop" onclick="stopBackgroundBot()" disabled>⏸️ Stop Bot</button>
  </div>

  <form method="POST" action="/">
    <div class="form-row">
      <div class="form-col">
        <div class="form-group">
          <label>CE Threshold:</label>
          <input type="number" id="ce_threshold" name="ce_threshold" step="0.1" value="{{ ce_threshold }}" required>
        </div>
      </div>
      <div class="form-col">
        <div class="form-group">
          <label>PE Threshold:</label>
          <input type="number" id="pe_threshold" name="pe_threshold" step="0.1" value="{{ pe_threshold }}" required>
        </div>
      </div>
    </div>
    
    <div class="form-row">
      <div class="form-col">
        <div class="form-group">
          <label>CE Target:</label>
          <input type="number" id="ce_target" name="ce_target" step="0.1" value="{{ ce_target }}" required>
        </div>
      </div>
      <div class="form-col">
        <div class="form-group">
          <label>PE Target:</label>
          <input type="number" id="pe_target" name="pe_target" step="0.1" value="{{ pe_target }}" required>
        </div>
      </div>
    </div>
    
    <div class="form-row">
      <div class="form-col">
        <div class="form-group">
          <label>CE Trailing Stop:</label>
          <input type="number" id="ce_trailing_stop" name="ce_trailing_stop" step="0.1" value="{{ ce_trailing_stop }}" required>
        </div>
      </div>
      <div class="form-col">
        <div class="form-group">
          <label>PE Trailing Stop:</label>
          <input type="number" id="pe_trailing_stop" name="pe_trailing_stop" step="0.1" value="{{ pe_trailing_stop }}" required>
        </div>
      </div>
    </div>
    
    <div class="form-row">
      <div class="form-col">
        <div class="form-group">
          <label>CE Trailing Target:</label>
          <input type="number" id="ce_trailing_target" name="ce_trailing_target" step="0.1" value="{{ ce_trailing_target }}" required>
        </div>
      </div>
      <div class="form-col">
        <div class="form-group">
          <label>PE Trailing Target:</label>
          <input type="number" id="pe_trailing_target" name="pe_trailing_target" step="0.1" value="{{ pe_trailing_target }}" required>
        </div>
      </div>
    </div>
    
    <div class="form-row">
      <div class="form-col">
        <div class="form-group">
          <label>Symbol Prefix:</label>
          <input type="text" id="symbol_prefix" name="symbol_prefix" value="{{ symbol_prefix }}" required>
        </div>
      </div>
    </div>
    
    <button type="submit" class="btn-reset">Update Settings</button>
  </form>

  <form onsubmit="return resetOrders();">
    <button type="submit" class="btn-reset">🔄 Reset Orders</button>
  </form>

  <div id="signals"></div>
  <div id="lows"></div>
  <div id="targets"></div>
  <div id="trailing"></div>
  <div id="profits"></div>
  <h3>Option Chain (Data from Fyers)</h3>
  <table>
    <thead><tr><th>Strike</th><th>CE LTP / Live</th><th>PE LTP / Live</th></tr></thead>
    <tbody id="chain"></tbody>
  </table>
</body>
</html>
"""

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 3000))
    print("\n" + "="*60)
    print("🚀 Sajid Shaikh Algo Trading Bot - Dual Broker")
    print("="*60)
    print(f"📍 Server: http://127.0.0.1:{port}")
    print("📝 Users stored in: users.txt")
    print("🔑 Credentials stored in: user_credentials.txt")
    print("📊 Market Data: Fyers")
    print("🛒 Order Placement: Fyers + mStock")
    print("="*60 + "\n")
    app.run(host="0.0.0.0", port=port, debug=False, use_reloader=False)