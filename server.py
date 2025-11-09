from flask import Flask, redirect
app = Flask(__name__)

@app.route("/helloworld")
def hello():
    return "Hello, world!"
@app.route("/hello")
def hello():
    # 302 — обычный временный редирект
    return redirect("https://www.youtube.com/watch?v=dQw4w9WgXcQ", code=302)