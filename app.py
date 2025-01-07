
from flask import Flask, render_template, request ,send_file, jsonify, session, make_response, abort
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user,current_user
from flask_cors import CORS
import jwt
import datetime
import secrets
from flask_limiter import Limiter
import stripe
import re
import base64
import os
import hashlib
from pymongo import MongoClient
from bson import ObjectId


# ------------環境変数予定------------

# 数か月に1回JWT_SECRET変更必須
# ここ環境変数
IS_LOCAL_DEBUG = False
IS_SECURE = not IS_LOCAL_DEBUG
APP_SECRET = "54684b68a4b6s8t4b6s84ns+684n6sy&ymof(oyb7q@s_$%i=y=o7te0j4omohkxa38+'"

# ECDSAバージョン
JWT_ALGORITHM = "ES256"
JWT_PRIVATE_SECRET = '-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDpQ/H6V87PDyKu\nxmRmJpmPcAMqEkurSdXBzW8oPFKzxRG0YFhzYhmo8AH/0+8ESWV39UIrbvMD8NDE\nzCwcZu7SG85R9DrcQoFwhyxP1jA7LDUvr2hn8CDaUMz8STuJMpI0onX4mpQlhOd4\nz3pS/9G4ms9PaOxBtEYVdUXBrWsm1egUutQsd2RYo7PUlfwNdhSgf838mPsuhcv9\nsJ/sJVSruzwY/sgwmCSghfgEJzEbFiJSJkkgwndvvI1wEdzk7kCTvFprRwYqCyVO\nwhKzgX916e9+GXVowEWinaVJ4xFsttYR3823uy3TpUs2wITKGhoG1PLpDG6kkHqk\na+BsDCWnAgMBAAECggEAA8bPyKA2wpFWOHhJ7UjLs8jBM3jJIvRsBGFpe0A6xeI3\naxvrG5OSMOTYi3DaXBbL5e6TUy5cuzVvaTEnfskc9NmOu2u5djyuhex9AFcDQB2P\nnVPAMbVE88k+jpdT1AuLDzhR6sBtfmFY3O9BOyMdDtmVBRxkRJxIFDK/lsOLSkt5\n0zw2vNLgXvpN45Pth3uPjGDrLr83BDQDiNLg5QDjAsEabGw9eymuOBjAuvHHawpp\nRcrBROoHsumFj5o1zf82JS1kPRUWrWh5Wd+ZpipOXLzJ77V6ViKwzO2GK8CksQRP\niJ+EFwLXbRT7knU3uhi3EKsRQahN1e3yQC0q9adLoQKBgQD3GzUqLaRNCIJbHRf0\nD3gsvf841qc1H9ddajvb9LhwDhlkMSRFKioHxHU3+rNWsw17gq6he5Pmm7S6DvdK\neQRC2FlQarql4RL1VZqgnAs4LiB7WROIrIr4ko++4pswl/eL/LQ2EpJrRj1ss5Xy\nFj0lGtGaf8mqF13vjPizjmt6oQKBgQDxqTXWWmKxbOSQwocUbPsR8oBCcl793SkI\nfca7HyPdjt+2e85PiZ1gWR3cUzYwPAeqIDEtFHSWQeAd2RHeVMZsWpotC8uv0wGF\nXaCtkUYIB9PadOrWibIsWwYrQl8G2/walQEQbx457psI4gJNtEd6cF7wRq19p+kI\njHwwpgVDRwKBgQDTFjrkPPkNlSdGDiRYKJ7QGb3cIAHWL80Zz5Yy32puzpyCKjiB\nnPMqj3hSyaZJecsapxfmelpttLU9+2rkA1zQfWBOgd3PteUsDmR4rtQmucClngJB\nzqMolIqW1Z0cdbTRsJ2BU3wgh3ARW5fLpZO2DqLfCCqNUki8SgBp4k+OAQKBgD1S\nSL0J1n1bOmyZUBmYxeT5+h3iU8RreFwVPnaBImK4PIBbzjBUpUCrnG4qF1gKA4/h\n91iPFj6CnNI2INif/nHEU9cWZStKidpDteAVOwYSpmmKvYSPEE09E8WqY96jt8cv\nBEQdTjg5GdIZN6hsFK83EIA8Dw4Rq4ply6W0myVFAoGAEJuI3hjdhQZ9xHZN0BFO\nbqeqp496+eLNEla0nq99QBQu6gnpSV87Z3loZcX73yRLmRXlgyb1XCPOq3N6lpJE\nyz0BGY7c0aBwwPsaMSG5T3/a2wWlwVav7Q2P0loOXu2eXbwlE6ZcCoAFpNN4Q2/o\nqmtzql7jwqA//Lj+3w9pXxM=\n-----END PRIVATE KEY-----\n'
JWT_PUBLIC_SECRET = '-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA6UPx+lfOzw8irsZkZiaZ\nj3ADKhJLq0nVwc1vKDxSs8URtGBYc2IZqPAB/9PvBElld/VCK27zA/DQxMwsHGbu\n0hvOUfQ63EKBcIcsT9YwOyw1L69oZ/Ag2lDM/Ek7iTKSNKJ1+JqUJYTneM96Uv/R\nuJrPT2jsQbRGFXVFwa1rJtXoFLrULHdkWKOz1JX8DXYUoH/N/Jj7LoXL/bCf7CVU\nq7s8GP7IMJgkoIX4BCcxGxYiUiZJIMJ3b7yNcBHc5O5Ak7xaa0cGKgslTsISs4F/\ndenvfhl1aMBFop2lSeMRbLbWEd/Nt7st06VLNsCEyhoaBtTy6QxupJB6pGvgbAwl\npwIDAQAB\n-----END PUBLIC KEY-----\n'


JWT_EXPIRATION_SECONDS = 7*60*24  # 7日
SESSION_EXPIRATION_SECONDS = JWT_EXPIRATION_SECONDS
COOKIE_NAME = "testtoken"



app = Flask(__name__)
app.secret_key = APP_SECRET # クッキーデータの@login_required検証に使う
app.config['PERMANENT_SESSION_LIFETIME'] = datetime.timedelta(seconds=SESSION_EXPIRATION_SECONDS) # セッションの有効期限を30分に設定
app.config['SESSION_COOKIE_SECURE'] = IS_SECURE  # クッキーSecure
app.config['SESSION_COOKIE_HTTPONLY'] = True  # クッキーHttpOnly

# ローカルホストを許可する
CORS(app, resources={r"/api/*": {"origins": ["http://localhost:5000", "http://127.0.0.1:5000","https://tech0-tanimoto-fdev-check-esh5h8h8a5b7esgr.japanwest-01.azurewebsites.net"], "supports_credentials": True}})

# ------------flask_login設定------------

login_manager = LoginManager()
login_manager.init_app(app)

# flask_loginが持つユーザー情報テーブルのUserMixin　ただしここでは@login_required判定にしか使わないのでほぼ不要
class User(UserMixin):
    def __init__(self, usermail):
        self.id = usermail  # usermailをidとして設定
        # self.dummy1 = "一時的なデータとしてユーザーのどんなデータを追跡したいかをここに記載"
        # self.dummy2= "今回は@login_required判定にだけ使って、セッションデータ使わないのでここ不要"

# 複数の情報をセッションとして持つ場合（メモリ上の簡易参照DBのようなもの）
# class User(UserMixin):
#     def __init__(self, usermail, username=None, purchase_count=0, address=None):
#         self.id = usermail  # メールアドレスをIDとして設定
#         self.username = username  # ユーザー名
#         self.purchase_count = purchase_count  # 購入数
#         self.address = address  # 住所
#
#     ユーザー情報を表示するメソッド（オプション）
#     def __repr__(self):
#         return f"User({self.username}, {self.id}, {self.purchase_count}, {self.address})"
#
# 新しいユーザーの作成
# new_user = User(usermail="test@example.com", username="John Doe", purchase_count=5, address="123 Main St")
#
# ユーザー情報の確認
# print(new_user)  # 出力: User(John Doe, test@example.com, 5, 123 Main St)


# 仮のユーザーデータベース
users = {
    'user1': {'password': 'hashed_password_1'},
    'user2': {'password': 'hashed_password_2'},
    "your_usermail@sample.com":{"password":"あああ"}
}

# ここDBでチェックする部分
@login_manager.user_loader
def load_user(usermail):
    # ここ本番ではDB参照必須
    isExist = usermail in users

    if isExist:
        return User(usermail=usermail) # あれば読み込み、なければ新規作成
    return None

# token検査
def check_token(token):
    # トークンのデコード
    data = jwt.decode(token, JWT_PUBLIC_SECRET, algorithms=[JWT_ALGORITHM]) # クッキーに登録した部分の"sub"の値が復元される
    return load_user(data['sub']) # subはsubjectの略

# ------------flask_limiter設定------------

# nginx対策 falsk_limiter用関数
def get_ip():
    # X-Forwarded-Forヘッダーを確認し、クライアントのIPアドレスを取得
    if request.headers.getlist("X-Forwarded-For"):
        return request.headers.getlist("X-Forwarded-For")[0]
    else:
        return request.remote_addr
    
# 一般的関数
def get_ip_req(request):
    # X-Forwarded-Forヘッダーを確認し、クライアントのIPアドレスを取得
    if request.headers.getlist("X-Forwarded-For"):
        return request.headers.getlist("X-Forwarded-For")[0]
    else:
        return request.remote_addr

# IPアドレスに基づいてリクエストを制限
limiter = Limiter(
    key_func=get_ip,  # カスタムのIP取得関数を指定
    app=app,
    default_limits=[],
    # default_limits=["100 per day", "20 per hour"],  # 1日100回、1時間20回の制限
    # storage_uri="redis://localhost:6379"  # Redisをストレージとして指定
    # Redis
    # storage_uri="redis://localhost:6379",
    # Redis cluster
    # storage_uri="redis+cluster://localhost:7000,localhost:7001,localhost:70002",
    # Memcached
    # storage_uri="memcached://localhost:11211",
    # Memcached Cluster
    # storage_uri="memcached://localhost:11211,localhost:11212,localhost:11213",
    # MongoDB
    # storage_uri="mongodb://localhost:27017",
    # Etcd
    # storage_uri="etcd://localhost:2379",
    # strategy="fixed-window", # or "moving-window"
    # default_limit_expiry=60,  # 機能消えてる
    # default_limits_deduct_when=lambda response: response.status_code != 200  # 200以外のステータスコードのみカウント
)
# limiter.reset() で削除可能
# limiter.reset(ip)  # IPアドレスに基づいてリセット※200番と組み合わせて使うとよい ただし機能なくなった
# @limiter.limit("5 per minute") # 個別に設定可能
# [count] [per|/] [n (optional)] [second|minute|hour|day|month|year][s]

# アクセス過多429を上書き
# パスワード間違えと同じ返答をしてアクセス者にヒントを与えない
@app.errorhandler(429)
def ratelimit_handler(e):
    return make_response(
            jsonify({'message': 'Invalid credentials'})
            , 401
    )


# ------------ここからコード------------


# app = Flask(__name__)
app = Flask(__name__, static_folder='templates/static', template_folder='templates')
# app = Flask(__name__, static_folder='templates')

# getのときの処理
@app.route('/', methods=['GET'])
def get():
	# return render_template('index.html')
	return send_file('templates/index.html')


# ログインAPI
@app.route('/api/login', methods=['POST'])
@limiter.limit("5 per minute") # 1分間に5回までアクセス可能
def login():
    # リクエストのContent-Typeがform-dataまたはapplication/x-www-form-urlencodedかをチェック
    # htmlのformからその送信は2つに絞られる
    if request.content_type in ['application/x-www-form-urlencoded', 'multipart/form-data']:
        return jsonify({'message': 'Invalid credentials'}), 401
    data = request.json
    usermail = data.get('usermail')
    password = data.get('password')

    # ここからDB参照必須
    if usermail in users and users[usermail]['password'] == password:
        user = User(usermail=usermail) # セッション用クッキーのためにデータ作成
        login_user(user, remember=True) # flask_loginの@login_requiredに使うクッキーをセット　Trueでブラウザ閉じてもセッション消えない永久設定
        expiration = datetime.datetime.now() + datetime.timedelta(seconds=JWT_EXPIRATION_SECONDS)
        token = jwt.encode({'sub': usermail, 'exp': expiration}, JWT_PRIVATE_SECRET, algorithm=JWT_ALGORITHM) # subは誰でも見れる部分
        # クッキーにJWTトークンを保存
        response = make_response(jsonify({'message': 'Login successful'}))
        response.set_cookie(COOKIE_NAME, token, httponly=True, secure=IS_SECURE)  # ローカル環境ではsecure=False、本番環境ではTrueにする
        return response
    else:
        return jsonify({'message': 'Invalid credentials'}), 401

# 認証されたユーザーの情報取得API
@app.route('/api/profile', methods=['GET'])
@login_required
def profile():
    token = request.cookies.get(COOKIE_NAME)  # クッキーからトークンを取得
    if not token:
        return jsonify({'message': 'Token is missing!'}), 401
    
    try:
        user = check_token(token)
        if user is not None:
            # print(current_user.id) # セッション情報 class User(UserMixin)
            if current_user.id != user.id:
                jsonify({'message': 'Not authorized!'}), 403

            return jsonify({'usermail': user.id})
    except jwt.ExpiredSignatureError:
        return jsonify({'message': 'Token has expired!'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'message': 'Invalid token!'}), 401

    return jsonify({'message': 'Not authorized!'}), 403

# JWTトークンを使って保護されたルート
@app.route('/api/protected', methods=['GET'])
@login_required
def protected():
    
    token = request.cookies.get(COOKIE_NAME)  # クッキーからトークンを取得
    if not token:
        return jsonify({'message': 'Token is missing!'}), 401

    try:
        user = check_token(token)
        if user is not None:
            # print(current_user.id) # セッション情報 class User(UserMixin)
            if current_user.id != user.id:
                jsonify({'message': 'Not authorized!'}), 403
            return jsonify({'message': f'Hello, {user.id}'})
    except jwt.ExpiredSignatureError:
        return jsonify({'message': 'Token has expired!'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'message': 'Invalid token!'}), 401

    return jsonify({'message': 'Not authorized!'}), 403

# ログアウトAPI（クッキーの削除）
@app.route('/api/logout', methods=['POST'])
@login_required
def logout():
    logout_user() # flask_loginの@login_requiredに使うクッキーを削除
    response = make_response(jsonify({'message': 'Logged out'}))
    response.delete_cookie(COOKIE_NAME)  # クッキーを削除
    return response

if __name__ == '__main__':
    app.run(debug=IS_LOCAL_DEBUG)
