import streamlit as st
import hashlib
import sqlite3
import joblib
import re
import unidecode
import string
import time

# Load the Logistic Regression model and vectorizer
log_model = joblib.load(logistic_regression_model.pkl)
vectorizer = joblib.load(r'C:\Users\USER\Documents\vscode\vectoriser.pkl')

# Initialize the SQLite database
conn = sqlite3.connect('users.db', check_same_thread=False)
c = conn.cursor()

# Create user and comment tables if they don't exist
def create_tables():
    c.execute('''CREATE TABLE IF NOT EXISTS users(
                    username TEXT, 
                    password TEXT, 
                    is_admin BOOLEAN, 
                    banned BOOLEAN DEFAULT 0, 
                    ban_timestamp REAL DEFAULT NULL,
                    inappropriate_count INTEGER DEFAULT 0)''')
    
    c.execute('CREATE TABLE IF NOT EXISTS comments(username TEXT, comment TEXT, sentiment TEXT, flagged BOOLEAN)')
    conn.commit()

# Add new user to database
def add_user(username, password, is_admin=False):
    c.execute('INSERT INTO users(username, password, is_admin, inappropriate_count) VALUES (?, ?, ?, ?)', (username, password, is_admin, 0))
    conn.commit()

# Authenticate user
def login_user(username, password):
    c.execute('SELECT * FROM users WHERE username = ? AND password = ?', (username, password))
    data = c.fetchone()
    return data

# Hashing passwords
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# Store user comments and flagged status
def add_comment(username, comment, sentiment, flagged):
    c.execute('INSERT INTO comments(username, comment, sentiment, flagged) VALUES (?, ?, ?, ?)', (username, comment, sentiment, flagged))
    conn.commit()

# Get all user comments in reverse order (newest first)
def get_all_comments():
    c.execute('SELECT username, comment, sentiment, flagged FROM comments ORDER BY rowid DESC')  # Display newest first
    return c.fetchall()

# Get unflagged comments only for users (normal users won't see flagged ones)
def get_unflagged_comments():
    c.execute('SELECT username, comment, sentiment, flagged FROM comments WHERE flagged = 0 ORDER BY rowid DESC')
    return c.fetchall()

# Increment inappropriate comment count for the user
def increment_inappropriate_count(username):
    c.execute('UPDATE users SET inappropriate_count = inappropriate_count + 1 WHERE username = ?', (username,))
    conn.commit()

# Reset inappropriate comment count
def reset_inappropriate_count(username):
    c.execute('UPDATE users SET inappropriate_count = 0 WHERE username = ?', (username,))
    conn.commit()

# Ban user for 1 minute
def ban_user(username):
    ban_time = time.time()  # Record the current time as the ban start time
    c.execute('UPDATE users SET banned = 1, ban_timestamp = ? WHERE username = ?', (ban_time, username))
    conn.commit()

# Unban a user
def unban_user(username):
    c.execute('UPDATE users SET banned = 0, ban_timestamp = NULL WHERE username = ?', (username,))
    conn.commit()


def is_user_banned(username):
    c.execute('SELECT banned, ban_timestamp FROM users WHERE username = ?', (username,))
    data = c.fetchone()
    
    if data and data[0]:  # Check if the user is banned
        ban_time = data[1]
        current_time = time.time()
        time_left = 60 - (current_time - ban_time)  # Calculate time left for the ban

        if time_left <= 0:
            unban_user(username)
            return False, 0  # Ban expired
        else:
            return True, time_left  # Still banned, return the time left
    return False, 0  # Not banned



# Get inappropriate count for user
def get_inappropriate_count(username):
    c.execute('SELECT inappropriate_count FROM users WHERE username = ?', (username,))
    return c.fetchone()[0]

# Initialize session state variables
if "login_status" not in st.session_state:
    st.session_state["login_status"] = False
    st.session_state["is_admin"] = False
    st.session_state["username"] = None

# Registration function with hardcoded admin account
def register():
    st.subheader("Create New Account")
    username = st.text_input("Username")
    password = st.text_input("Password", type='password')
    confirm_password = st.text_input("Confirm Password", type='password')

    if st.button("Register"):
        if password == confirm_password:
            hashed_password = hash_password(password)
            
            # Automatically set admin flag for a hardcoded admin account
            is_admin = False
            if username == "adminadmin" and password == "admin":
                is_admin = True
            
            add_user(username, hashed_password, is_admin=is_admin)
            st.success("Account created successfully!")
        else:
            st.error("Passwords do not match.")

# Login function
def login():
    st.subheader("Login to Your Account")
    username = st.text_input("Username")
    password = st.text_input("Password", type='password')

    if st.button("Login"):
        hashed_password = hash_password(password)
        result = login_user(username, hashed_password)

        if result:
            st.session_state["login_status"] = True
            st.session_state["username"] = username
            st.session_state["is_admin"] = result[2]
            st.success(f"Welcome {username}")
        else:
            st.error("Incorrect username or password.")

def logout():
    st.session_state["login_status"] = False
    st.session_state["is_admin"] = False
    st.session_state["username"] = None
    st.write("You have been logged out. Please login again.")
    # This will refresh the app without needing the rerun function


# # Admin Dashboard (if logged in as admin)
# def admin_dashboard():
#     st.subheader("Admin Dashboard")

#     # List all user comments (including flagged comments)
#     st.write("All User Comments (including inappropriate ones):")
#     comments = get_all_comments()

#     for comment in comments:
#         user, text, sentiment, flagged = comment
#         if flagged:
#             st.warning(f"Flagged Comment by {user}: {text} (Sentiment: {sentiment})")
#         else:
#             st.write(f"{user}: {text} (Sentiment: {sentiment})")


def admin_dashboard():
    st.subheader("Admin Dashboard")

    # List all user comments (including flagged comments) with sentiment for admin
    st.write("All User Comments (including inappropriate ones):")
    comments = get_all_comments()
    display_comments(comments, is_admin=True)  # Set is_admin=True for admin users




# Define preprocessing functions for sentiment analysis
def preprocess_text(text):
    text = clean_stopwords(text)
    text = clean_punctuations(text)
    text = clean_URLs(text)
    text = clean_numeric(text)
    text = remove_accents(text)
    text = normalize_spaces(text)
    return text

# Helper functions for text preprocessing
stopwordlist = ['a', 'about', 'above', 'after', 'again', 'ain', 'all', 'am', 'an', 'and', 'any', 'are', 'as', 'at', 'be', 'because', 'been', 'before', 'being', 'below', 'between', 'both', 'by', 'can', 'd', 'did', 'do', 'does', 'doing', 'down', 'during', 'each', 'few', 'for', 'from', 'further', 'had', 'has', 'have', 'having', 'he', 'her', 'here', 'hers', 'herself', 'him', 'himself', 'his', 'how', 'i', 'if', 'in', 'into', 'is', 'it', 'its', 'itself', 'just', 'll', 'm', 'ma', 'me', 'more', 'most', 'my', 'myself', 'now', 'o', 'of', 'on', 'once', 'only', 'or', 'other', 'our', 'ours', 'ourselves', 'out', 'own', 're', 's', 'same', 'she', 'should', 'so', 'some', 'such', 't', 'than', 'that', 'the', 'their', 'theirs', 'them', 'themselves', 'then', 'there', 'these', 'they', 'this', 'those', 'through', 'to', 'too', 'under', 'until', 'up', 've', 'very', 'was', 'we', 'were', 'what', 'when', 'where', 'which', 'while', 'who', 'whom', 'why', 'will', 'with', 'won', 'y', 'you', 'your', 'yours', 'yourself', 'yourselves']
STOPWORDS = set(stopwordlist)

def clean_stopwords(text):
    return " ".join([word for word in str(text).split() if word.lower() not in STOPWORDS])

def clean_punctuations(text):
    translator = str.maketrans('', '', string.punctuation)
    return text.translate(translator)

def clean_URLs(text):
    return re.sub(r"(www\.[^\s]+)|(http\S+)", "", text)

def clean_numeric(text):
    return re.sub(r'[0-9]+', '', text)

def remove_accents(text):
    return unidecode.unidecode(text)

def normalize_spaces(text):
    return re.sub(r'\s+', ' ', text).strip()

def post_comment():
    is_banned, time_left = is_user_banned(st.session_state["username"])

    if is_banned:
        st.error(f"You are banned from posting for {int(time_left)} seconds due to inappropriate behavior.")
        return

    comment = st.text_area("Write your comment:")
    
    if st.button("Post Comment"):
        if comment:
            # Preprocess and analyze sentiment
            clean_input = preprocess_text(comment)
            input_vectorized = vectorizer.transform([clean_input])
            prediction = log_model.predict(input_vectorized)

            # Assume model returns categories such as "other_cyberbullying", "religion", etc.
            inappropriate_categories = ["other_cyberbullying", "religion", "gender", "age", "ethnicity"]
            sentiment = prediction[0]

            if sentiment in inappropriate_categories:
                # Increment inappropriate comment count
                increment_inappropriate_count(st.session_state["username"])
                inappropriate_count = get_inappropriate_count(st.session_state["username"])

                st.error("Your comment has been flagged as inappropriate.")
                st.write("Please visit [this page](https://cyberbullying.org/) for more information on how to prevent cyberbullying.")
                add_comment(st.session_state["username"], comment, sentiment, flagged=True)

                # Ban the user if they have made 3 inappropriate comments
                if inappropriate_count >= 3:
                    st.error("You have been banned for 1 minute due to repeated inappropriate comments.")
                    ban_user(st.session_state["username"])  # Ban the user for 1 minute
                    reset_inappropriate_count(st.session_state["username"])  # Reset the inappropriate count
            else:
                add_comment(st.session_state["username"], comment, sentiment, flagged=False)
                st.success(f"Comment posted: {comment}")

# Function to display comments with or without sentiment based on user role
def display_comments(comments, is_admin=False):
    for comment in comments:
        user, text, sentiment, flagged = comment
        if is_admin:
            # Admin view with sentiment
            if flagged:
                st.markdown(f"<div style='border: 2px solid red; padding: 10px; margin: 10px 0;'><strong>{user}</strong>: {text} (Sentiment: {sentiment})</div>", unsafe_allow_html=True)
            else:
                st.markdown(f"<div style='border: 1px solid gray; padding: 10px; margin: 10px 0;'><strong>{user}</strong>: {text} (Sentiment: {sentiment})</div>", unsafe_allow_html=True)
        else:
            # Regular user view without sentiment
            if flagged:
                st.markdown(f"<div style='border: 2px solid red; padding: 10px; margin: 10px 0;'><strong>{user}</strong>: {text}</div>", unsafe_allow_html=True)
            else:
                st.markdown(f"<div style='border: 1px solid gray; padding: 10px; margin: 10px 0;'><strong>{user}</strong>: {text}</div>", unsafe_allow_html=True)



def main():
    # Initialize session state variables if they don't exist
    if "login_status" not in st.session_state:
        st.session_state["login_status"] = False
    if "is_admin" not in st.session_state:
        st.session_state["is_admin"] = False
    if "username" not in st.session_state:
        st.session_state["username"] = None

    st.title("Social Media App")

    if st.session_state["login_status"]:
        st.write(f"Logged in as {st.session_state['username']}")
        if st.session_state["is_admin"]:
            admin_dashboard()
        else:
            st.write("Post a new comment:")
            post_comment()

            # Display comments for normal users without sentiment
            st.write("Recent Comments:")
            comments = get_unflagged_comments()
            display_comments(comments, is_admin=False)  # Set is_admin=False for regular users
        
        if st.button("Logout"):
            logout()
    else:
        # Show login and registration options
        choice = st.selectbox("Login or Register", ["Login", "Register"])
        if choice == "Login":
            login()
        else:
            register()

if __name__ == "__main__":
    main()
