from flask import Flask, request, jsonify, g, make_response, redirect
from sqlite3 import connect as sqlConnect
from hashlib import sha256
from string import ascii_letters, digits
from random import choice
import time
from operator import itemgetter
from dataclasses import dataclass

app = Flask(__name__, static_url_path='/')

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
                showInGallery integer,
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
    return app.send_static_file('index.html')

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

@app.route("/change_password", methods=["POST"])
def change_password():
    if val := assertLoggedIn(): return val
    user = currentUser()

    try:
        new_password = itemgetter('password')(request.json)
    except:
        simpleReject("Invalid data supplied")

    salt = randsec()
    phash = sha(new_password + salt)

    with dbex() as cursor:
        cursor.execute("update userdata set salt=?, hash=? where uid=?", (salt, phash, user.uid))

    return simpleAccept({})

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
    showInGallery = request.form.get("showInGallery", "false") == "true"
    with dbex() as cursor:
        cursor.execute("insert into blobdata (content, type, showInGallery) values (?, ?, ?) returning id", (content, fileType, showInGallery))
        fid, = cursor.fetchone()
        return jsonify({
            "ok": True,
            "id": fid
        })

@app.route("/edit/blob/<bid>", methods=["POST"])
def editBlob(bid):
    if val := assertLoggedIn(): return val
    user = currentUser()
    if user.access_level < 50:
        return simpleReject("Only moderator and above can edit files on the server.")

    try:
        show_in_gallery = itemgetter('showInGallery')(request.json)
    except:
        return simpleReject("Invalid data supplied")

    with dbex() as cursor:
        cursor.execute("update blobdata set showInGallery=? where id = ?", (show_in_gallery, bid))

    return simpleAccept({ })

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
        cursor.execute('select id, type, showInGallery from blobdata')
        output = []
        for _id, _type, show_in_gallery in cursor.fetchall():
            output.append({"id": _id, "type": _type, "showInGallery": show_in_gallery})
        return simpleAccept({ "blobs": output })

@app.route("/gallery")
def getGallery():
    with dbq() as cursor:
        cursor.execute('select id, type, showInGallery from blobdata where showInGallery=TRUE')
        output = []
        for _id, _type, show_in_gallery in cursor.fetchall():
            output.append({"id": _id, "type": _type, "showInGallery": show_in_gallery})
        return simpleAccept({ "blobs": output })

@app.route("/me")
def userInfo():
    if val := assertLoggedIn(): return val
    user = currentUser()
    return simpleAccept({ "id": user.uid,  "username": user.name, "accessLevel": user.access_level })

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
        aid = randsec()
        cursor.execute("insert into articles (authorID, title, description, bannerimage, category, publishdate, content, id) values (?, ?, ?, ?, ?, ?, ?, ?)", (user.uid, title, description, bannerimage, category, int(time.time() * 1000), content, aid))
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

@app.route("/edit/article/<id>", methods=["POST"])
def editArticle(id):
    if val := assertLoggedIn(): return val
    user = currentUser()
    if user.access_level < 50:
        return simpleReject("Only moderator and above can edit articles on the server.")

    try:
        description, content = itemgetter('description', 'content')(request.json)
    except:
        return simpleReject("Invalid data supplied")

    with dbex() as cursor:
        cursor.execute("update articles set content = ?, description = ?, authorID = ? where id = ?", (content, description, currentUser().uid, id))

    return simpleAccept({ })

@app.route("/delete/article/<id>", methods=["POST"])
def deleteArticle(id):
    if val := assertLoggedIn(): return val
    user = currentUser()
    if user.access_level < 50:
        return simpleReject("Only moderator and above can delete articles on the server.")

    with dbex() as cursor:
        cursor.execute("delete from articles where id = ?", (id,))

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

@app.route("/delete/comment/<cid>", methods=["POST"])
def deleteComment(cid):
    if val := assertLoggedIn(): return val
    user = currentUser()

    with dbex() as cursor:
        if user.access_level < 50:
            cursor.execute("delete from comments where id = ? and authorID = ?", (cid, user.uid))
        else:
            cursor.execute("delete from comments where id = ?", (cid,))

    return simpleAccept({ })

@app.route("/comments")
def listComments():
    with dbq() as cursor:
        cursor.execute('select u.uid, u.username, c.id, c.content from comments c left join userdata u on u.uid = c.authorID')
        output = []
        for uid, uname, cid, content in cursor.fetchall():
            output.append({"id": cid, "author": {"id": uid, "username": uname}, "content": content})
    return simpleAccept({ "comments": output })

@app.route("/create/core/<name>", methods=["POST"])
def createCorePage(name):
    if val := assertLoggedIn(): return val
    user = currentUser()
    if user.access_level < 100:
        return simpleReject("Only administrators can create core pages on the server.")
    if name not in [ "HOME", "MENUBAR", "GLOBAL_THEME" ]:
        return simpleReject("Invalid core page name.")
    try:
        content = itemgetter('content')(request.json)
    except:
        return simpleReject("Invalid data supplied")
    with dbex() as cursor:
        cursor.execute("insert into specialpages (name, content) values (?, ?)", (name, content))
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
        content = itemgetter('content')(request.json)
    except:
        return simpleReject("Invalid data supplied")

    with dbex() as cursor:
        cursor.execute("update specialpages set content = ? where name = ?", (content, name))

    return simpleAccept({ })

@app.route("/list/users")
def listUsers():
    if val := assertLoggedIn(): return val
    user = currentUser()
    if user.access_level < 100:
        return simpleReject("Only administrators can list users on the server.")

    users = []
    with dbq() as cursor:
        cursor.execute("select uid, accesslevel, username from userdata")
        for uid, accesslevel, username in cursor.fetchall():
            users.append({
                "id": uid,
                "accessLevel": accesslevel,
                "username": username
            })
    return simpleAccept({ "users": users })

@app.route("/create/user", methods=["POST"])
def createUser():
    if val := assertLoggedIn(): return val
    user = currentUser()
    if user.access_level < 100:
        return simpleReject("Only administrators can create users on the server.")

    try:
        username, password, accesslevel = itemgetter('username', 'password', 'accessLevel')(request.json)
    except:
        return simpleReject("Invalid data supplied")

    with dbex() as cursor:
        try:
            salt = randsec()
            phash = sha(password + salt)
            cursor.execute("insert into userdata (accesslevel, username, salt, hash) values (?, ?, ?, ?)", (accesslevel, username, salt, phash))
            cursor.execute("select uid from userdata where username = ?", (username, ))
            uid, = cursor.fetchone()
            return simpleAccept({ "id": uid })
        except Exception as e:
            print(e)
            return simpleReject("User already exists")

@app.route("/edit/user/<int:uid>", methods=["POST"])
def editUser(uid):
    if val := assertLoggedIn(): return val
    user = currentUser()
    if user.access_level < 100:
        return simpleReject("Only administrators can edit users on the server.")

    try:
        username, accesslevel = itemgetter('username', 'accessLevel')(request.json)
    except:
        return simpleReject("Invalid data supplied")

    password = request.json['password'] if 'password' in request.json else None

    with dbex() as cursor:
        try:
            cursor.execute("update userdata set accesslevel=?, username=? where uid=?", (accesslevel, username, uid))
            if password != None:
                salt = randsec()
                phash = sha(password + salt)
                cursor.execute("update userdata set salt=?, hash=? where uid=?", (salt, phash, uid))

            for s in store.values():
                if s.uid == uid:
                    s.name = username
                    s.access_level = accesslevel

            return simpleAccept({ })
        except Exception as e:
            print(e)
            return simpleReject("Username already taken")

@app.route("/delete/user/<int:uid>", methods=["POST"])
def deleteUser(uid):
    if val := assertLoggedIn(): return val
    user = currentUser()
    if user.access_level < 100:
        return simpleReject("Only administrators can delete users on the server.")

    with dbex() as cursor:
        cursor.execute("delete from userdata where uid=?", (uid,))

    sessions_to_invalidate = []
    for s in store.items():
        if s[1].uid == uid:
            sessions_to_invalidate.append(s[0])
    [store.pop(s) for s in sessions_to_invalidate]

    return simpleAccept({ })

@app.after_request
def no_cors(response):
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Headers"] = "*"
    return response

if __name__ == "__main__": app.run(debug=True, port=1234, host="0.0.0.0")
