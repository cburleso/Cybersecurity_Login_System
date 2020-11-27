import sqlite3
import hashlib
import os
from flask import (
    Flask,
    redirect,
    render_template,
    request,
    url_for,
    flash
)

app = Flask(__name__)
app.secret_key = 'cybersecurityiskool'


@app.route('/', methods=['GET', 'POST'])
def login():
    global attempts
    if request.method == 'POST':

        username = request.form['username']
        password = request.form['password']

        # get registered users
        users = query_users()

        if username not in users or not users:
            # username not found in database
            flash("Account Not Found. Need to Register?", "alert-danger")
            return render_template('login.html')
        else:
            try:
                if attempts[username] >= MAX_ATTEMPTS:
                    flash("Account Locked - Maximum Password Attempts Reached")
                    return render_template('login.html')
            except KeyError:
                attempts[username] = 0

            stored = query_password(username)
            if authenticate(stored, password):
                try:
                    attempts[username] = 0
                except KeyError:
                    attempts[username] = 0
                return render_template('profile.html', username=username)
            else:
                try:
                    attempts[username] = attempts[username] + 1
                except KeyError:
                    attempts[username] = 1

                if attempts[username] >= MAX_ATTEMPTS:
                    flash("Account Locked - Maximum Password Attempts Reached")
                    return render_template('login.html')
                else:
                    flash("Invalid Password - " + str(MAX_ATTEMPTS - attempts[username]) +
                          " Attempts Remaining")
                    return render_template('login.html')

    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    global attempts
    if request.method == 'POST':

        username = request.form['username']
        password = request.form['password']

        users = query_users()
        if username in users:
            flash('Account Already Registered')
            return redirect(url_for('login'))
        else:
            if validate_password(password):
                register_user(username, password, 'entry')
                attempts[username] = 0
                return render_template('profile.html', username=username)
            else:
                flash('Password must be between 8 and 25 characters, contain one uppercase letter, '
                      'one lowercase letter, one number, and one special character.')
                return redirect(url_for('login'))


def validate_password(password):
    min_char = 8
    max_char = 25
    specials = '! @ # $ % ^ & * ( ) _ + { } : " < > ? \ | [ ] ; \ , . / ` ~'
    specials = specials.split()
    valid = False
    for c in specials:
        if c in password:
            valid = True
            break
    if (any(x.isupper() for x in password) and any(x.islower() for x in password)
            and any(x.isdigit() for x in password) and valid and min_char <= len(password) <= max_char):
        return True
    else:
        return False


def create_db():
    try:
        conn = sqlite3.connect('user.db')
        c = conn.cursor()
        c.execute('''CREATE TABLE users
                    (
                    username text,
                    password text,
                    access_level text
                    )''')
        conn.commit()
        return True
    except BaseException:
        return False
    finally:
        if c is not None:
            c.close()
        if conn is not None:
            conn.close()


def register_user(username, password, access):
    hashed_password = hash_pw(password)
    print(hashed_password)
    data_to_insert = [(username, hashed_password, access)]
    try:
        conn = sqlite3.connect('user.db')
        c = conn.cursor()
        c.executemany("INSERT INTO users VALUES (?, ?, ?)", data_to_insert)
        conn.commit()
    except sqlite3.IntegrityError:
        print("Error. Tried to add duplicate account!")
    finally:
        if c is not None:
            c.close()
        if conn is not None:
            conn.close()


def authenticate(stored, plain_text, salt_length=None) -> bool:
    """
    Authenticate by comparing stored and new hashes.

    :param stored: str (salt + hash retrieved from database)
    :param plain_text: str (user-supplied password)
    :param salt_length: int
    :return: bool
    """
    salt_length = salt_length or 40  # set salt_length
    salt = stored[:salt_length]  # extract salt from stored value
    stored_hash = stored[salt_length:]  # extract hash from stored value
    hashable = salt + plain_text  # concatenate hash and plain text
    hashable = hashable.encode('utf-8')  # convert to bytes
    this_hash = hashlib.sha1(hashable).hexdigest()  # hash and digest
    return this_hash == stored_hash  # compare


def hash_pw(plain_text):
    # generate a salt value using urandom (using a seed of 60)
    salt_bytes = str(os.urandom(60))

    # initialize empty salt string to concatenate to
    salt = ''

    # for each character within the salt_bytes byte string, append the first 40
    for i in range(40):
        salt += salt_bytes[i]

    # concatenate the salt string and plain_text string
    salt_plain = salt + plain_text

    # encode the concatenated strings using utf-8
    hashable = salt_plain.encode('utf-8')

    # hash the result using SHA1 and hexdigest()
    this_hash = hashlib.sha1(hashable).hexdigest()  # hash w/ SHA-1 and hex digest

    return salt + this_hash  # prepend hash and return


def query_users():
    try:
        conn = sqlite3.connect('user.db')
        c = conn.cursor()
        users = []
        for user in c.execute("SELECT username FROM users"):
            users.append(user[0])
    except sqlite3.DatabaseError:
        print("Error. Could not retrieve data.")
    else:
        return users
    finally:
        if c is not None:
            c.close()
        if conn is not None:
            conn.close()


def query_password(username):
    try:
        conn = sqlite3.connect('user.db')
        c = conn.cursor()
        password = []
        for password in c.execute('SELECT password FROM users WHERE username=?', (username,)):
            password = password[0]
    except sqlite3.DatabaseError:
        print("Error. Could not retrieve data.")
    else:
        return password
    finally:
        if c is not None:
            c.close()
        if conn is not None:
            conn.close()


attempts = {}
MAX_ATTEMPTS = 3

#registered_users = query_users()
#for user in registered_users:
    #attempts[user] = 0

success = create_db()
#register_user('connor', 'topsecret', 'admin')
#register_user('vanessa', 'test', 'engineer')
#register_user('jon', 'jonnyboy', 'hr')
#print(query_users())


