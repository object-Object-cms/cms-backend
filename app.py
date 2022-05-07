from flask import Flask, request, jsonify, g, make_response, redirect
from sqlite3 import connect as sqlConnect
from hashlib import sha256
from string import ascii_letters, digits
from random import choice
import time
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

@dataclass
class Article:
    id: str
    title: str
    description: str
    bannerImage: str
    category: str
    publishDate: int

    content: str

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
        c.execute("""
            create table if not exists articles (
                id text primary key,
                authorID integer,
                title text,
                description text,
                bannerimage text,
                category text,
                publishdate integer,
                content text
            )
        """)
        c.execute("""
            create table if not exists comments (
                id integer primary key,
                authorID integer,
                content text
            )
        """)
        c.execute("""
            create table if not exists specialpages (
                name text primary key,
                content text
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
            cursor.execute("insert into userdata (accesslevel, username, salt, hash) values (?, ?, ?, ?)", (0, username, salt, phash))
            cursor.execute("select uid from userdata where username = ?", (username, ))
            uid, = cursor.fetchone()
            return loginUser(User(uid, username, 0))
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

@app.route("/create/blob", methods=["POST"])
def uploadImage():
    #needs multipart data with <input type="file" name="file">
    #Only moderator and above can upload files
    if val := assertLoggedIn(): return val
    user = currentUser()
    if user.access_level < 50:
        return simpleReject("Only moderator and above can upload files to the server.")    

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

@app.route("/list/blobs")
def listBlobs():
    with dbq() as cursor:
        cursor.execute('select id, type from blobdata')
        output = []
        for _id, _type in cursor.fetchall():
            output.append({"id": _id, "type": _type})
        return simpleAccept({ "blobs": output })

@app.route("/me")
def userInfo():
    if val := assertLoggedIn(): return val
    user = currentUser()
    return simpleAccept({ "username": user.name, "accessLevel": user.access_level })

@app.route("/create/article", methods=["POST"])
def createArticle():
    if val := assertLoggedIn(): return val
    user = currentUser()
    if user.access_level < 50:
        return simpleReject("Only moderator and above can create articles on the server.")

    try:
        title, description, bannerimage, category, content = itemgetter('title', 'description', 'bannerimage', 'category', 'content')(request.json)
    except:
        return simpleReject("Invalid data supplied")
    
    with dbq() as cursor:
        cursor.execute('select type from blobdata where id = ?', (bannerimage, ))
        resp = cursor.fetchone()
        if not resp:
            return simpleReject("No blob with id " + bannerimage)
        if not resp[0].startswith("image/"):
            return simpleReject(f"Blob of type {resp[0]} cannot be loaded as the banner image")
    
    with dbex() as cursor:
        cursor.execute("insert into articles (authorID, title, description, bannerimage, category, publishdate, content) values (?, ?, ?, ?, ?, ?, ?) returning id", (user.uid, title, description, bannerimage, category, int(time.time()), content))
        aid, = cursor.fetchone()
    return simpleAccept({ "ok": True, "id": aid })

@app.route("/article/<id>")
def getArticle(id):
    with dbq() as cursor:
        cursor.execute('select content from articles where id = ?', (id, ))
        content = cursor.fetchone()
        if not content:
            return simpleReject("No such article")
        return simpleAccept({ "content": content[0] })

@app.route("/list/articles")
def articleList():
    # Any user can get the list of articles - no login assertion required
    articles = []
    with dbq() as cursor:
        cursor.execute("select a.id, f.username, a.title, a.description, a.bannerimage, a.category, a.publishdate from articles a left join userdata f on f.uid = a.authorID")
        for id, uname, title, description, bannerImage, category, publishDate in cursor.fetchall():
            articles.append({
                "id": id,
                "title": title,
                "description": description,
                "bannerImage": bannerImage,
                "category": category,
                "publishDate": publishDate,
                "author": uname
            })
    return simpleAccept({ "articles": articles })

@app.route("/edit/article/<id>")
def editArticle(id, methods=["POST"]):
    if val := assertLoggedIn(): return val
    user = currentUser()
    if user.access_level < 50:
        return simpleReject("Only moderator and above can edit articles on the server.")

    try:
        description, content = itemgetter('description', 'content')(request.json)
        int(id)
    except:
        return simpleReject("Invalid data supplied")

    with dbex() as cursor:
        cursor.execute("update articles set content = ?, description = ?, authorID = ? where id = ?", (content, description, currentUser().uid, int(id)))
    
    return simpleAccept({ })


@app.route("/create/comment", methods=["POST"])
def createComment():
    if val := assertLoggedIn(): return val
    try:
        content = itemgetter('content')(request.json)
    except:
        return simpleReject("Invalid data supplied")
    with dbex() as cursor:
        cursor.execute("insert into comments (authorID, content) values (?, ?)", (currentUser().uid, content))
    return simpleAccept({ "ok": True })

@app.route("/comments")
def listComments():
    with dbq() as cursor:
        cursor.execute('select u.username, c.content from comments c left join userdata u on u.uid = c.authorID')
        output = []
        for uname, content in cursor.fetchall():
            output.append({"username": uname, "content": content})
    return simpleAccept({ "comments": output })

@app.route("/create/core/<name>", methods=["POST"])
def createCorePage(name):
    if val := assertLoggedIn(): return val
    user = currentUser()
    if user.access_level < 100:
        return simpleReject("Only administrators can create core pages on the server.")
    if name not in [ "HOME" ]:
        return simpleReject("Invalid core page name.")
    try:
        content, = itemgetter('content')(reqiest.json)
    except:
        return simpleReject("Invalid data supplied")
    with dbex() as cursor:
        cursor.execute("insert into specialpages ( content ) values (?)", (content, ))
    return simpleAccept({ })

@app.route("/core/<name>")
def getCorePage(name):
    with dbq() as cursor:
        cursor.execute("select content from specialpages where name = ?", (name, ))
        content = cursor.fetchone()
        if not content:
            return simpleReject("No core page with name " + name)
        return simpleAccept({ "content": content[0] })

@app.route("/edit/core/<name>", methods=["POST"])
def editCorePage(name):
    if val := assertLoggedIn(): return val
    user = currentUser()
    if user.access_level < 100:
        return simpleReject("Only administrators can edit core pages on the server.")
    try:
        content, = itemgetter('content')(request.json)
    except:
        return simpleReject("Invalid data supplied")

    with dbex() as cursor:
        cursor.execute("update articles set content = ? where name = ?", (content, name))
    
    return simpleAccept({ })


@app.after_request
def no_cors(response):
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Headers"] = "*"
    return response

if __name__ == "__main__": app.run(debug=True, port=1234, host="0.0.0.0")
