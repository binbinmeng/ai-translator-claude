# app.py
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, send_file, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import os
import uuid
from datetime import datetime
import mimetypes

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///pdf_manager.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# 确保上传目录存在
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

db = SQLAlchemy(app)

# 数据库模型
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    pdfs = db.relationship('PDFFile', backref='owner', lazy=True, cascade='all, delete-orphan')

class PDFFile(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    original_filename = db.Column(db.String(255), nullable=False)
    file_size = db.Column(db.Integer, nullable=False)
    upload_date = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

# 路由
@app.route('/')
def index():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user = User.query.get(session['user_id'])
    pdfs = PDFFile.query.filter_by(user_id=session['user_id']).order_by(PDFFile.upload_date.desc()).all()
    return render_template('index.html', user=user, pdfs=pdfs)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        
        if User.query.filter_by(username=username).first():
            flash('用户名已存在')
            return render_template('register.html')
        
        if User.query.filter_by(email=email).first():
            flash('邮箱已被注册')
            return render_template('register.html')
        
        user = User(
            username=username,
            email=email,
            password_hash=generate_password_hash(password)
        )
        db.session.add(user)
        db.session.commit()
        
        flash('注册成功！请登录')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.password_hash, password):
            session['user_id'] = user.id
            flash('登录成功！')
            return redirect(url_for('index'))
        else:
            flash('用户名或密码错误')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('已退出登录')
    return redirect(url_for('login'))

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'user_id' not in session:
        return jsonify({'error': '未登录'}), 401
    
    if 'file' not in request.files:
        return jsonify({'error': '没有选择文件'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': '没有选择文件'}), 400
    
    if not file.filename.lower().endswith('.pdf'):
        return jsonify({'error': '只支持PDF文件'}), 400
    
    # 生成唯一文件名
    filename = str(uuid.uuid4()) + '.pdf'
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    
    try:
        file.save(filepath)
        file_size = os.path.getsize(filepath)
        
        # 保存到数据库
        pdf_file = PDFFile(
            filename=filename,
            original_filename=file.filename,
            file_size=file_size,
            user_id=session['user_id']
        )
        db.session.add(pdf_file)
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': '上传成功',
            'file_id': pdf_file.id,
            'filename': pdf_file.original_filename
        })
    
    except Exception as e:
        return jsonify({'error': f'上传失败: {str(e)}'}), 500

@app.route('/delete/<int:file_id>', methods=['DELETE'])
def delete_file(file_id):
    if 'user_id' not in session:
        return jsonify({'error': '未登录'}), 401
    
    pdf_file = PDFFile.query.filter_by(id=file_id, user_id=session['user_id']).first()
    if not pdf_file:
        return jsonify({'error': '文件不存在'}), 404
    
    try:
        # 删除物理文件
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], pdf_file.filename)
        if os.path.exists(filepath):
            os.remove(filepath)
        
        # 从数据库删除记录
        db.session.delete(pdf_file)
        db.session.commit()
        
        return jsonify({'success': True, 'message': '删除成功'})
    
    except Exception as e:
        return jsonify({'error': f'删除失败: {str(e)}'}), 500

@app.route('/download/<int:file_id>')
def download_file(file_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    pdf_file = PDFFile.query.filter_by(id=file_id, user_id=session['user_id']).first()
    if not pdf_file:
        flash('文件不存在')
        return redirect(url_for('index'))
    
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], pdf_file.filename)
    if not os.path.exists(filepath):
        flash('文件不存在')
        return redirect(url_for('index'))
    
    return send_file(filepath, as_attachment=True, download_name=pdf_file.original_filename)

@app.route('/preview/<int:file_id>')
def preview_file(file_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    pdf_file = PDFFile.query.filter_by(id=file_id, user_id=session['user_id']).first()
    if not pdf_file:
        return "文件不存在", 404
    
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], pdf_file.filename)
    if not os.path.exists(filepath):
        return "文件不存在", 404
    
    return send_file(filepath, mimetype='application/pdf')

def format_file_size(size_bytes):
    if size_bytes == 0:
        return "0B"
    size_names = ["B", "KB", "MB", "GB"]
    i = 0
    while size_bytes >= 1024 and i < len(size_names) - 1:
        size_bytes /= 1024.0
        i += 1
    return f"{size_bytes:.1f}{size_names[i]}"

# 添加模板过滤器
app.jinja_env.filters['format_file_size'] = format_file_size

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)