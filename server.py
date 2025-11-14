from flask import Flask, redirect

app = Flask(__name__)


@app.route("/hi")
def hello_redirect():
    return redirect("https://www.youtube.com/watch?v=dQw4w9WgXcQ")


@app.route("/hello")
def hello():
    return "Hello, world!"


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
