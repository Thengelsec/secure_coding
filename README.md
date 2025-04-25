# Secondhand Shopping Platform by secure_codding

## 🔧 Environment Setup

1. Install system-level dependency
```
git clone https://github.com/Thengelsec/secure_coding.git
sudo apt update
sudo apt install openssl
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes
```

2. Install Python packages
```
pip install -r requirements.txt
conda env create -f enviroments.yaml
```

## 🔄 Run Server Process
Need conda activate
```
python app.py
```