import streamlit as st
import pickle
import re
import json
import os
import hashlib
from datetime import datetime
import base64
import bcrypt
from cryptography.fernet import Fernet
from PIL import Image
from PIL.ExifTags import TAGS

# --------- ALERT SOUND FUNCTION ----------
def play_alert_sound():
    with open("alert.mp3", "rb") as sound_file:
        sound_bytes = sound_file.read()
        b64 = base64.b64encode(sound_bytes).decode()
        md = f"""
        <audio autoplay>
        <source src="data:audio/mp3;base64,{b64}" type="audio/mp3">
        </audio>
        """
        st.markdown(md, unsafe_allow_html=True)

st.set_page_config(page_title="DefendAI", layout="wide")

def load_css(file_name):
    with open(file_name) as f:
        st.markdown(f"<style>{f.read()}</style>", unsafe_allow_html=True)

load_css("styles.css")

# --------- AUTH SESSION INIT ----------
if "logged_in" not in st.session_state:
    st.session_state.logged_in = False

if "username" not in st.session_state:
    st.session_state.username = ""

if "show_login" not in st.session_state:
    st.session_state.show_login = False

if "show_register" not in st.session_state:
    st.session_state.show_register = False

if "open_register" not in st.session_state:
    st.session_state.open_register = False    

# --------- DATABASE SETUP ----------
import sqlite3

# Create vault folder if not exists
if not os.path.exists("vault"):
    os.makedirs("vault")

# Connect to database
conn = sqlite3.connect("users.db", check_same_thread=False)
c = conn.cursor()

# Create users table
c.execute("""
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password_hash BLOB,
    encryption_key BLOB
)
""")

conn.commit()

# --------- LOGIN POPUP ----------
@st.dialog("🔐 Login")
def login_popup():

    login_user = st.text_input("User ID")
    login_pass = st.text_input("Password", type="password")

    if st.button("Login Now"):

        c.execute("SELECT password_hash, encryption_key FROM users WHERE username=?", (login_user,))
        result = c.fetchone()

        if result:
            stored_hash, key = result
            if bcrypt.checkpw(login_pass.encode(), stored_hash):
                st.session_state.logged_in = True
                st.session_state.username = login_user
                st.session_state.key = key
                st.success("Login Successful")
                st.rerun()
            else:
                st.error("Wrong Password")
        else:
            st.error("User Not Found")

    st.markdown("---")

    if st.button("Create Account"):
        st.session_state.open_register = True
        st.rerun()

# --------- REGISTER POPUP ----------       
@st.dialog("📝 Create Account")
def register_popup():

    new_user = st.text_input("Email / Phone")
    new_pass = st.text_input("Set Password", type="password")
    confirm_pass = st.text_input("Confirm Password", type="password")

    if st.button("Register Now"):

        if not new_user or not new_pass or not confirm_pass:
            st.warning("Fill all fields")
        elif new_pass != confirm_pass:
            st.error("Passwords do not match")
        else:
            hashed_pw = bcrypt.hashpw(new_pass.encode(), bcrypt.gensalt())
            key = Fernet.generate_key()

            try:
                c.execute("INSERT INTO users (username,password_hash,encryption_key) VALUES(?,?,?)",
                          (new_user, hashed_pw, key))
                conn.commit()
                os.makedirs(f"vault/{new_user}", exist_ok=True)

                st.success("Account Created Successfully")
                st.rerun()

            except:
                st.error("User already exists")

# --------- SIDEBAR AUTH ----------
with st.sidebar:
    st.markdown("## 🔐 Account")

    if not st.session_state.logged_in:
        if st.button("Login"):
            login_popup()
    else:
        st.success(f"Logged in as {st.session_state.username}")
        if st.button("Logout"):
            st.session_state.clear()
            st.rerun()

    st.markdown("---")
    
# ---------- OPEN REGISTER DIALOG ----------
if st.session_state.open_register:
    st.session_state.open_register = False
    register_popup()

# --------- LOAD MODEL ----------
model = pickle.load(open("model.pkl", "rb"))
vectorizer = pickle.load(open("vectorizer.pkl", "rb"))

# --------- SESSION STATE ----------
if "total" not in st.session_state:
    st.session_state.total = 0
    st.session_state.safe = 0
    st.session_state.suspicious = 0
    st.session_state.harmful = 0

 # --------- AUTH SESSION ----------
if "logged_in" not in st.session_state:
    st.session_state.logged_in = False

if "show_login" not in st.session_state:
    st.session_state.show_login = False

if "show_register" not in st.session_state:
    st.session_state.show_register = False   

# --------- BLOCKLIST ENGINE ----------
BLOCKLIST_FILE = "blocked_sources.json"

if not os.path.exists(BLOCKLIST_FILE):
    with open(BLOCKLIST_FILE, "w") as f:
        json.dump([], f)

def load_blocklist():
    with open(BLOCKLIST_FILE, "r") as f:
        return json.load(f)

def save_blocklist(data):
    with open(BLOCKLIST_FILE, "w") as f:
        json.dump(data, f, indent=4)

def hash_source(source):
    return hashlib.sha256(source.encode()).hexdigest()

# --------- SEMANTIC INTELLIGENCE ENGINE ----------
def semantic_analysis(text):
    text_lower = text.lower()
    indicators = []
    category_scores = {
        "Violence Risk": 0,
        "Financial Fraud Risk": 0,
        "Phishing Risk": 0,
        "Manipulation Risk": 0,
        "Spam Risk": 0
    }

    violence_keywords = {"kill":3, "attack":3, "bomb":3, "shoot":3, "harm":2}
    fraud_keywords = {"bank":3, "otp":3, "transfer":2, "money":2, "account":2, "upi":2}
    phishing_keywords = {"password":3, "login":3, "verify":2, "link":2}
    manipulation_keywords = {"urgent":3, "immediately":3, "now":2, "last chance":2}
    spam_keywords = {"free":2, "win":2, "offer":2, "prize":2, "subscribe":1}

    for word, weight in violence_keywords.items():
        if word in text_lower:
            category_scores["Violence Risk"] += weight
            indicators.append(f'Violence keyword "{word}" detected')

    for word, weight in fraud_keywords.items():
        if word in text_lower:
            category_scores["Financial Fraud Risk"] += weight
            indicators.append(f'Financial keyword "{word}" detected')

    for word, weight in phishing_keywords.items():
        if word in text_lower:
            category_scores["Phishing Risk"] += weight
            indicators.append(f'Phishing keyword "{word}" detected')

    for word, weight in manipulation_keywords.items():
        if word in text_lower:
            category_scores["Manipulation Risk"] += weight
            indicators.append(f'Urgency trigger "{word}" detected')

    for word, weight in spam_keywords.items():
        if word in text_lower:
            category_scores["Spam Risk"] += weight
            indicators.append(f'Spam keyword "{word}" detected')

    # Pattern detection
    if re.search(r"http[s]?://|www\.", text_lower):
        category_scores["Phishing Risk"] += 5
        indicators.append("URL pattern detected")

    if re.search(r"\b\d{4,}\b", text_lower):
        category_scores["Financial Fraud Risk"] += 4
        indicators.append("Numeric pattern (possible OTP/account) detected")

    if text.isupper():
        category_scores["Violence Risk"] += 3
        indicators.append("ALL CAPS aggression detected")

    if "!!" in text:
        category_scores["Manipulation Risk"] += 2
        indicators.append("Repeated exclamation marks detected")

    total_semantic_score = sum(category_scores.values())
    semantic_score = min(total_semantic_score * 5, 100)

    primary_category = max(category_scores, key=category_scores.get)

    return semantic_score, primary_category, indicators

# --------- MESSAGE TYPE POPUP FUNCTION ----------
def show_threat_popup(category):

    css_class = ""

    if category.lower() == "safe":
        css_class = "safe-text"
    elif category.lower() in ["phishing", "scam/fraud", "spoofing"]:
        css_class = "phishing-text"
    elif category.lower() in ["violence", "harassment", "theft"]:
        css_class = "violence-text"
    else:
        css_class = "phishing-text"

    st.markdown(f"""
    <div class="threat-popup-overlay">
        <div class="threat-popup-box">
            <div class="threat-popup-title {css_class}">
                {category.upper()} MESSAGE DETECTED
            </div>
        </div>
    </div>
    """, unsafe_allow_html=True)

# --------- HEADER ----------
st.markdown('<div class="main-title">🛡️ DEFENDAI- AI Based Threat Detection</div>', unsafe_allow_html=True)
st.markdown('<div class="sub-title">Intelligent Multi-Layer Risk Detection System</div>', unsafe_allow_html=True)
st.markdown("---")

# --------- INPUT SECTION ----------
with st.container():
    st.markdown("""
    <div class="neon-card">
        <div class="quote-box">
            Detect. <span class="defend-word">Defend.</span> Protect.
        </div>
    """, unsafe_allow_html=True)

    text = st.text_area("Enter text for AI Threat Analysis")
    source_input = st.text_input("Enter Source (Email / Phone / ID)")
    st.markdown("</div>", unsafe_allow_html=True)
    analyze = st.button("🚀 Analyze Threat")
    st.markdown('</div>', unsafe_allow_html=True)

# --------- ANALYSIS ----------
if analyze and text != "":
    blocked_sources = load_blocklist()

if source_input:
    source_hash = hash_source(source_input)
    if source_hash in blocked_sources:
        st.error("🚫 SOURCE IS BLOCKED. Communication prevented.")
        st.stop()
    text_vec = vectorizer.transform([text])
    prediction = model.predict(text_vec)[0]
    show_threat_popup(prediction)

    probability = model.predict_proba(text_vec).max()

    st.session_state.total += 1

    if prediction == "safe":
        st.session_state.safe += 1
    elif prediction == "suspicious":
        st.session_state.suspicious += 1
    else:
        st.session_state.harmful += 1

    risk_score = round(probability * 100)

    # --- Semantic Layer ---
    semantic_score, primary_category, indicators = semantic_analysis(text)

    # --- Composite Score (40% ML + 60% Semantic) ---
    composite_score = round((risk_score * 0.4) + (semantic_score * 0.6))

    if composite_score <= 40:
        threat_level = "🟢 LOW"
    elif composite_score <= 70:
        threat_level = "🟡 MODERATE"
    else:
        threat_level = "🔴 CRITICAL"

    st.markdown("---")

    # Original ML Result (UNCHANGED)
    if prediction == "safe":
        st.success(f"✅ SAFE CONTENT | Confidence: {risk_score}%")
    elif prediction == "suspicious":
        st.warning(f"⚠ SUSPICIOUS CONTENT | Confidence: {risk_score}%")
    else:
        st.error(f"🚨 HARMFUL CONTENT | Confidence: {risk_score}%")

    st.progress(risk_score / 100)

    # --------- NEW CONTROL ROOM SECTION ----------
    st.markdown("## 🧠 Semantic Intelligence")
    st.write(f"**Primary Threat Category:** {primary_category}")
    st.write(f"**Semantic Risk Score:** {semantic_score}")

    st.markdown("### 📋 Detected Indicators")
    if indicators:
        for item in indicators:
            st.write(f"- {item}")
    else:
        st.write("- No significant indicators detected")

    st.markdown("---")

    st.markdown("## ⚡ Composite Threat Matrix")
    st.write(f"**Composite Threat Score:** {composite_score}")
    st.write(f"**System Threat Level:** {threat_level}")

    st.markdown("---")

    st.markdown("## 🛡 Defence Protocol Suggestion")

    if threat_level == "🔴 CRITICAL":
        play_alert_sound()
        # 🤖 RUN PHASE AUTO CHAT RESPONSE
        if "chat_history" not in st.session_state:
            st.session_state.chat_history = []

        st.session_state.chat_history.append((
            "Bot",
            "🚨 CRITICAL THREAT DETECTED. Source has been automatically blocked. Immediate review required."
        ))

        # 🤖 RUN PHASE: Auto AI Response
        if "chat_history" in st.session_state:
            st.session_state.chat_history.append((
                "Bot",
                "🚨 CRITICAL THREAT DETECTED. Source has been blocked automatically. Immediate administrative review recommended."
            ))
        if st.button("🔎 View Blocked Sources"):
         st.experimental_rerun()
        if source_input:
            source_hash = hash_source(source_input)
            blocked_sources = load_blocklist()
            if source_hash not in blocked_sources:
                blocked_sources.append(source_hash)
                save_blocklist(blocked_sources)
        st.markdown("""
<div class="matrix-bg"></div>

<div class="block-popup-overlay fade-out">
    <div class="block-popup-box">
        <div class="shield-icon">🛡</div>
        <div class="block-popup-title">SOURCE BLOCKED</div>
        <div class="block-popup-text">
            The sender has been automatically added to the secure blocklist.<br>
            Future communications from this source are prevented.
        </div>
    </div>
</div>
""", unsafe_allow_html=True)
        st.write("- Immediately block communication")
        st.write("- Flag account for administrative review")
        st.write("- Enable enhanced identity verification")
    elif threat_level == "🟡 MODERATE":
        st.write("- Monitor activity closely")
        st.write("- Recommend enabling 2FA")
        st.write("- Verify sender identity")
    else:
        st.write("- No immediate action required")
        st.write("- Continue monitoring")

# --------- CYBER CHATBOT (CRAWL PHASE) ----------

st.markdown("---")
st.markdown("## 🤖 DefendAI Cyber Assistant")

# 🔐 RUN PHASE SECURITY: Require Login
if not st.session_state.logged_in:
    st.warning("🔒 Login required to access Cyber Assistant")
    st.stop()

if "chat_history" not in st.session_state:
    st.session_state.chat_history = []

user_query = st.text_input("Ask Cyber Assistant")

def basic_cyber_response(query):

    query_lower = query.lower()

    # 🛡 ADMIN-ONLY ADVANCED COMMAND (RUN PHASE)
    admin_users = ["7653070228", "admin"]

    if "shutdown system" in query_lower:
        if st.session_state.username not in admin_users:
            return "⛔ Unauthorized command. Admin privileges required."
        return "🚨 System lockdown protocol initiated."

    if "view blocklist" in query_lower:
        if st.session_state.username != "admin":
            return "⛔ Unauthorized command. Admin privileges required."
        blocked = load_blocklist()
        return f"Blocked Sources Count: {len(blocked)}"

    # -------- Existing Features --------
    if "analyze:" in query_lower:
        text_to_analyze = query_lower.replace("analyze:", "").strip()
        text_vec = vectorizer.transform([text_to_analyze])
        prediction = model.predict(text_vec)[0]
        probability = model.predict_proba(text_vec).max()
        return f"Threat Prediction: {prediction.upper()} | Confidence: {round(probability*100)}%" 
    
    elif "phishing" in query_lower:
        return "Phishing is a credential harvesting attack using deceptive communication."
    
    return "Ask me to analyze text using format: analyze: Cybersecurity is the practice of protecting internet-connected systems—including hardware, software, and data—from malicious digital attacks, unauthorized access, and damage."

if st.button("Send"):
    if user_query:
        response = basic_cyber_response(user_query)
        st.session_state.chat_history.append(("You", user_query))
        st.session_state.chat_history.append(("Bot", response))

for role, message in st.session_state.chat_history:
    st.write(f"**{role}:** {message}")

# --------- IMAGE AUTHENTICITY ANALYZER ----------

st.markdown("---")
st.markdown("## 🖼 AI Image Authenticity Analyzer")

uploaded_image = st.file_uploader("Upload an Image", type=["jpg", "jpeg", "png"])

def analyze_image_authenticity(image):
    result = {
        "has_exif": False,
        "camera_model": None,
        "risk_score": 0,
        "verdict": "Unknown"
    }
    try:
        exif_data = image._getexif()
        if exif_data:
            result["has_exif"] = True
            for tag, value in exif_data.items():
                decoded = TAGS.get(tag, tag)
                if decoded == "Model":
                    result["camera_model"] = value

    except:
        pass

    # Risk scoring logic
    if not result["has_exif"]:
        result["risk_score"] += 50

    if not result["camera_model"]:
        result["risk_score"] += 20

    width, height = image.size
    if width > 3000 or height > 3000:
        result["risk_score"] += 20

    if result["risk_score"] <= 30:
        result["verdict"] = "🟢 Likely Real (Camera Image)"
    elif result["risk_score"] <= 70:
        result["verdict"] = "🟡 Suspicious (Possible AI Generated)"
    else:
        result["verdict"] = "🔴 High Probability AI Generated"

    return result


if uploaded_image:
    img = Image.open(uploaded_image)
    st.image(img, caption="Uploaded Image", use_column_width=True)

    image_result = analyze_image_authenticity(img)

    st.markdown("### 🔍 Image Analysis Result")
    st.write("EXIF Metadata Present:", image_result["has_exif"])
    st.write("Camera Model:", image_result["camera_model"])
    st.write("Risk Score:", image_result["risk_score"])
    st.write("Final Verdict:", image_result["verdict"])

# --------- DASHBOARD ----------
st.markdown("---")
st.markdown('<div class="main-title" style="font-size:30px;">📊 LIVE ANALYTICS DASHBOARD</div>', unsafe_allow_html=True)

col1, col2, col3, col4 = st.columns(4)

with col1:
    st.markdown('<div class="metric-card">Total Checked<br><h2>'+str(st.session_state.total)+'</h2></div>', unsafe_allow_html=True)

with col2:
    st.markdown('<div class="metric-card">Safe<br><h2>'+str(st.session_state.safe)+'</h2></div>', unsafe_allow_html=True)

with col3:
    st.markdown('<div class="metric-card">Suspicious<br><h2>'+str(st.session_state.suspicious)+'</h2></div>', unsafe_allow_html=True)

with col4:
    st.markdown('<div class="metric-card">Harmful<br><h2>'+str(st.session_state.harmful)+'</h2></div>', unsafe_allow_html=True)

st.markdown("---")
st.markdown("## 🚫 Blocked Source Registry")
blocked_sources = load_blocklist()
st.write(f"Total Blocked Sources: {len(blocked_sources)}")

if blocked_sources:
    st.write("Hashed Blocked IDs (Privacy Protected):")
    for b in blocked_sources:
        st.write(b)
st.caption("🔒 Privacy Protected | Local AI Execution | No Data Stored")