from flask import Flask, redirect, url_for

app = Flask(__name__)



# Defining the home page of our site
@app.route("/")  # this sets the route to this page
def home():
	return "Hello! this is the main page <h1>HELLO</h1>"  # some basic inline html


@app.route("/<name>") #use { for post id}
def user(name):
    return f"Hello {name}!" #use { for post id}

@app.route("/admin")
def admin():
	return redirect(url_for("home"))

if __name__ == "__main__":
    app.run(debug = True)

