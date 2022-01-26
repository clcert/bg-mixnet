from flask import (
    flash,
    Flask,
    redirect,
    render_template,
    request,
    url_for
)
import os
from werkzeug.utils import secure_filename

from main import (
    mix as f_mix,
    verify as f_verify
)

UPLOAD_FOLDER = f"{os.getcwd()}/data"
ALLOWED_EXTENSIONS = {"json", "txt"}

app = Flask(__name__)
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.secret_key = b"example"

def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

def validate_files(file_dict):
    ret = True
    for key in file_dict.keys():
        if file_dict[key] and allowed_file(file_dict[key].filename):
            continue
        ret = False
    return ret

@app.route("/")
def index():
    return "Try /mix or /verify"

@app.route("/mix", methods=("GET", "POST"))
def mix():
    if request.method == "POST":
        m = int(request.form["m"])
        n = int(request.form["n"])
        election_file = request.files["election_file"]
        if election_file and allowed_file(election_file.filename):
            filename = secure_filename(election_file.filename)
            path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
            election_file.save(path)
            f_mix(m, n, "data/ciphers.json", "data/public_randoms.txt", "data/proof.txt", path)
            return redirect(url_for('index'))

    return render_template("mix.html")

@app.route("/verify", methods=("GET", "POST"))
def verify():
    if request.method == "POST":
        m = int(request.form["m"])
        n = int(request.form["n"])
        files = {}
        files["ciphers"] = request.files["ciphers_file"]
        files["publics"] = request.files["publics_file"]
        files["proof"] = request.files["proof_file"]
        if validate_files(files):
            paths = {}
            for key in files.keys(): 
                filename = secure_filename(files[key].filename)
                paths[key] = os.path.join(app.config["UPLOAD_FOLDER"], filename)
                files[key].save(paths[key])

            valid = f_verify(m, n, paths["ciphers"], paths["publics"], paths["proof"])
            if valid:
                flash("Validation successful")
            else:
                flash("Validation failed")
            redirect(url_for('index'))

    return render_template("verify.html")

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8080, debug=True)