"""ARLO INSIGNE, SDEV300, LAB8"""
import re
import logging
import socket
from datetime import datetime as dt
from flask import Flask, request, flash, redirect, url_for, session, render_template
from passlib.hash import sha256_crypt

app = Flask(__name__)

app.secret_key = b'thisisasecretkey'

# Setting up python logger
hostname = socket.getfqdn()

# Configuring logging
logging.basicConfig(filename='logfile.txt',
                    format='%(asctime)s - '
                    '%(name)s - %(levelname)s - %(message)s', filemode='a')
logger = logging.getLogger()
logger.setLevel(logging.ERROR)

@app.route('/main')
def get_main_page():
    """Get main page of the website"""
    if session.get('logged_in'):
        return render_template('main_page.html', datetime = str(dt.now()))
    else:
        return redirect(url_for('login'))

@app.route('/fail')
def fail():
    """Get webpage where user is redirected when they fail login"""
    return render_template('fail.html')

@app.route('/shows')
def shows():
    """Get web page of shows"""
    if session.get('logged_in'):
        return render_template('shows.html')
    else:
        return redirect(url_for('login'))

@app.route('/contact')
def contact():
    """Get contact page"""
    if session.get('logged_in'):
        return render_template('contact_us.html')
    else:
        return redirect(url_for('login'))

@app.route('/artists')
def get_new_artists():
    """Get new artists page"""
    if session.get('logged_in'):
        return render_template('new_artists.html')
    else:
        return redirect(url_for('login'))

@app.route('/trending')
def get_trending_songs():
    """Get trending songs page"""
    if session.get('logged_in'):
        return render_template('trending_songs.html')
    else:
        return redirect(url_for('login'))

def checknotreg(username):
    """Check if user is already registered"""
    already_registered = True

    # Open credentials file and read content line by line
    for lines in open('credentials', "r", encoding="utf-8").readlines():
        creds = lines.split()

        # Verify if the supplied username matches what is in the file
        if sha256_crypt.verify(username, creds[0]):
            already_registered = False

    return already_registered

def complex_pass(password):
    """Check if password meets the complexity requirement"""

    # Use regex to detect 1 upper, 1 lower, 1 digit,
    # 1 symbol and at least 12 char password
    reg = "^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-z\d@$!#%*?&]{12,100}$"
    pattern = re.compile(reg)

    # Check if supplied password meets the reqs
    match = re.search(pattern, password)

    if match:
        return True
    else:
        return False

def check_common(password):
    """Check if the password is common based on provided file"""
    for lines in open('CommonPassword.txt', 'r', encoding="utf=8"):
        if lines.rstrip() == password:
            return True

@app.route('/register', methods=['GET','POST'])
def register():
    """Get registration page"""
    if request.method == "POST":

        # Get user input
        username = request.form["username"]
        password = request.form["password"]

        error = None
        not_reg = False
        pass_complex = True
        common_pass = False

        # Validation for blank field, registered user,
        # common passwords, and complex passwords
        if not username:
            error = "Username is required."
        elif not password:
            error = "Password is required."
        elif not checknotreg(username):
            not_reg = True
            error = "Username already registered. " \
                    "Please choose another username."
        elif check_common(password):
            common_pass = True
            error = "Your password contains words that are too common. " \
                    "Please provide another password."
        elif not complex_pass(password):
            pass_complex = False
            error = "You need to provide a complex password."
        hash_user = sha256_crypt.hash(username)
        hash_pass = sha256_crypt.hash(password)

        # Writing to the credentials text file if all user input is valid
        if error is None and not_reg is False and pass_complex is True and common_pass is False:
            with open('credentials', "a", encoding="utf-8") as f:
                f.writelines(hash_user + " " + hash_pass + "\n")
            return redirect(url_for("login"))
        flash(error)
        # Printing flash error message
        return render_template('error_message.html')
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Get login page"""
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        error = None
        if not username:
            error = "Username is required."
        elif not password:
            error = "Password is required"

        valid = False

        # Checking if the supplied username and password is in the txt file
        for lines in open("credentials", "r", encoding="utf-8").readlines():
            creds = lines.split()
            if (sha256_crypt.verify(username, creds[0])) \
                    and (sha256_crypt.verify(password, creds[1])):
                session['logged_in'] = True
                valid = True

        if error is None and valid is True:
            return redirect(url_for("get_main_page"))
        else:
            # Logging if the user fails to login: date, time, and client IP
            logging.error(f'{socket.gethostbyname(hostname)} - Login failed.')
            return redirect(url_for("fail"))

        flash(error)

        # Printing flash error message
        return render_template('error_message.html')

    return render_template('login.html')

@app.route('/logout', methods=['GET', 'POST'])
def logout():
    """Get logout page"""
    session.pop('logged_in', None)
    return render_template('logout.html')

@app.route('/change_password', methods=['GET', 'POST'])
def change_password():
    """Change current password"""

    if request.method == "POST":

        username = request.form["username"]
        new_password = request.form["new password"]

        error = None
        common_pass = False
        pass_complex = True

        # Input validation for blank fields
        if not username:
            error = "Username is required."
        elif not new_password:
            error = "Password is required"
        elif check_common(new_password):
            common_pass = True
            error = "Your password contains words that are too common. " \
                    "Please provide another password."
        elif not complex_pass(new_password):
            pass_complex = False
            error = "You need to provide a complex password."

        if error is None and pass_complex is True and common_pass is False:
        # Opening the current pw/un file and transfer contents to temp
        # file with pw modification for user
            with open('credentials', 'r', encoding='utf=8') as f, \
                    open('temp', 'w', encoding='utf=8') as g:
                lines = f.readlines()
                for x in range(len(lines)):
                    creds = lines[x].split()
                    if sha256_crypt.verify(username, creds[0]):
                        creds[1] = sha256_crypt.hash(new_password)
                    g.writelines(creds[0] + " " + creds[1] + "\n")
                f.close()
                g.close()

            # Overwrite current pw/un file with content of temp file
            with open('credentials', 'w', encoding="utf=8") as h, \
                    open('temp', 'r', encoding='utf=8') as i:
                for lines in i:
                    h.write(lines)
            session['logged_in'] = False
            return redirect(url_for("login"))
        flash(error)
        # Printing flash error message
        return render_template('error_message.html')
    return render_template('change_password.html')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)