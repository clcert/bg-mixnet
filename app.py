from flask import (
    flash,
    Flask,
    redirect,
    render_template,
    request,
    send_file,
    url_for
)
from os import makedirs
from os.path import (
    exists,
    join as p_join,
    realpath,
    split as p_split
)
from werkzeug.utils import secure_filename
from zipfile import ZipFile

from main import (
    mix as f_mix,
    verify as f_verify
)

UPLOAD_FOLDER = p_join(p_split(realpath(__file__))[0], "data")
ALLOWED_EXTENSIONS = {"json", "txt"}

app = Flask(__name__)
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.secret_key = b"example"

def check_upfolder():
    if not exists(UPLOAD_FOLDER):
        makedirs(UPLOAD_FOLDER)

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
        check_upfolder()
        m = int(request.form["m"])
        n = int(request.form["n"])
        election_file = request.files["election_file"]
        if election_file and allowed_file(election_file.filename):
            filename = secure_filename(election_file.filename)
            path = p_join(app.config["UPLOAD_FOLDER"], filename)
            election_file.save(path)
            outs = ["ciphers.json", "public_randoms.txt", "proof.txt"]
            for out in outs:
                out = p_join(app.config["UPLOAD_FOLDER"], out)
            f_mix(m, n, outs[0], outs[1], outs[2], path)

            res_path = p_join(app.config["UPLOAD_FOLDER"], "response.zip")
            zipObj = ZipFile(res_path, "w")
            for out in outs:
                zipObj.write(out)
            zipObj.close()
            return send_file(res_path, mimetype="application/zip")

    return render_template("mix.html")

#TODO: debug verification
@app.route("/verify", methods=("GET", "POST"))
def verify():
    if request.method == "POST":
        check_upfolder()
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
                paths[key] = p_join(app.config["UPLOAD_FOLDER"], filename)
                files[key].save(paths[key])

            data = {
                "valid": f_verify(m, n, paths["ciphers"], paths["publics"], paths["proof"]),
                "show": True
            }
            return render_template("verify.html", data=data)

    data = {"valid": False, "show": False}
    return render_template("verify.html", data=data)

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8080, debug=True)