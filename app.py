from flask import Flask, request, jsonify, g, make_response, redirect
from sqlite3 import connect as sqlConnect
from hashlib import sha256
from string import ascii_letters, digits
from random import choice
from operator import itemgetter
from dataclasses import dataclass

app = Flask(__name__)

sha = lambda e: sha256(e.encode('utf-8')).hexdigest()
randsec = lambda: ''.join([choice(ascii_letters + ascii_letters.upper() + digits) for x in range(32)])

@dataclass
class User:
    uid: int
    name: str
    access_level: int

class CursorClosable:
    def __init__(self, connection, doCommit):
        self.cursor = connection.cursor()
        self.connection = connection if doCommit else None
    def __enter__(self):
        return self.cursor
    def __exit__(self, type, value, traceback):
        self.cursor.close()
        if self.connection: self.connection.commit()

store = {}

def db():
    if not hasattr(g, 'db'): 
        g.db = sqlConnect("data.db")
    return g.db

def dbex():
    return CursorClosable(db(), True)

def dbq():
    return CursorClosable(db(), False)

@app.before_first_request
def init():
    with dbex() as c:
        c.execute("""
            create table if not exists userdata (
                uid integer primary key autoincrement,
                accesslevel integer,
                username text unique,
                salt text,
                hash text
            )
        """)
        c.execute("""
            create table if not exists blobdata (
                id integer primary key autoincrement,
                type text,
                content blob
            )
        """)


def loginUser(user):
    session = randsec()
    response = simpleAccept({"session": session})
    response.set_cookie("session", session)
    store[session] = user
    return response

def assertLoggedIn():
    if not request.headers.get("Authorization") or request.headers.get("Authorization") not in store: return simpleReject("Not logged in")
    return None

@app.route('/')
def index():
    print("INDEX!")
    if val := assertLoggedIn(): return val
    return jsonify({"Info": "Hello!"})


@app.route("/register", methods=["POST"])
def register():
    username, password = itemgetter('username', 'password')(request.json)
    with dbex() as cursor:
        try:
            salt = randsec()
            phash = sha(password + salt)
            cursor.execute("insert into userdata (accesslevel, username, salt, hash) values (?, ?, ?, ?) returning uid", (0, username, salt, phash))
            uid, = cursor.fetchone()
            return loginUser(User(uid, name, 0))
        except Exception as e:
            print(e)
            return simpleReject("User already exists")

@app.route("/login", methods=["POST"])
def login():
    username, password = itemgetter('username', 'password')(request.json)
    with dbq() as cursor:
        cursor.execute("select uid, salt, hash, accesslevel from userdata where username = ?", (username, ))
        row = cursor.fetchone()
        if not row:
            return simpleReject("No such user")
        uid, salt, phash, accesslevel = row
        if phash == sha(password + salt):
            return loginUser(User(uid, username, accesslevel))
        else:
            return simpleReject("Password incorrect")

def simpleAccept(reason={}):
    res = make_response(jsonify({
        "ok": True,
        **reason
    }))
    res.headers["Content-Type"] = "application/json"
    return res
def simpleReject(reason):
    res = make_response(jsonify({
        "ok": False,
        "reason": reason
    }))
    res.headers["Content-Type"] = "application/json"
    return res

def currentUser():
    return store[request.headers.get("Authorization")]

@app.route("/uploadFile", methods=["POST", "GET"])
def uploadImage():
    if request.method == "GET":
        # Test code:
        return """
<!Doctype html>
<html>
    <head>
        <title>Test</title>
    </head>
    <body>
        <form action="/uploadFile" method="POST" enctype="multipart/form-data">
            <input type="file" name="file" accept="image/*">
            <input type="submit" value="Yes">
        </form>
    </body>
</html>
        """
    content = request.files["file"].read()
    fileType = request.files["file"].content_type
    with dbex() as cursor:
        cursor.execute("insert into blobdata (content, type) values (?, ?) returning id", (content, fileType))
        fid, = cursor.fetchone()
        return jsonify({
            "ok": True,
            "id": fid
        })

@app.route("/blob/<id>")
def getImage(id):
    with dbq() as cursor:
        cursor.execute("select content, type from blobdata where id = ?", (id,))
        dbresp = cursor.fetchone()
        if not dbresp: return simpleReject("No such blob in the database")
        content, content_type = dbresp

        response = make_response(content)
        response.headers["Content-Type"] = content_type
        return response

@app.route("/me")
def userInfo():
    if val := assertLoggedIn(): return val
    user = currentUser()
    return simpleAccept({ "username": user.name, "accessLevel": user.access_level })

@app.after_request
def apply_caching(response):
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Headers"] = "*"
    return response

if __name__ == "__main__": app.run(debug=True, port=1234)
