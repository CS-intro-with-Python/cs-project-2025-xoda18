from flask import Flask, redirect

app = Flask(__name__)

@app.route("/helloworld")
def helloworld():
    return "Hello, world!"

@app.route("/hello")
def hello_redirect():
    return redirect("https://www.youtube.com/watch?v=dQw4w9WgXcQ", code=302)
