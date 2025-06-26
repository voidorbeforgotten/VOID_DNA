import sys, os, json, hashlib, uuid, threading, time, random, hmac, socket
from datetime import datetime, timezone
from PyQt5.QtWidgets import (
    QApplication, QWidget, QLabel, QPushButton, QVBoxLayout, QHBoxLayout,
    QTextEdit, QLineEdit, QMessageBox, QInputDialog, QListWidget, QGraphicsDropShadowEffect,
    QDialog, QDialogButtonBox, QDoubleSpinBox, QFormLayout, QSizePolicy, QTabWidget, QListWidgetItem, QFileDialog
)
from PyQt5.QtCore import Qt, pyqtSignal, QObject, QTimer, QThread
from PyQt5.QtGui import QFont, QColor, QPalette, QPixmap
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from mnemonic import Mnemonic
import base64
import secrets

# CONFIG
C={'W':'voidchain.blob','S':b"voidchain-secret-key",'P':4444,'I':10,'T':60,
'NP':QColor(180,0,255),'NC':QColor(0,255,200),'NPk':QColor(200,200,255),
'NB':QColor(50,200,255),'BG':QColor(0,255,200),'TC':QColor(200,200,255),
'FM':QFont("Consolas",11),'FT':QFont("Consolas",14,QFont.Bold),'BR':5.0,
'SD':4,'BD':7,'APR':0.25,'FTR':0.001}

VOID_PREFIX = "$VOID:vOI"
FTW_PREFIX = "$FTW:fTW:"
BLOB_MAGIC = b"VOIDCHAINv1"
PBKDF2_ITER = 200_000
SALT_SIZE = 16
NONCE_SIZE = 12

def hb(b): return hashlib.sha256(json.dumps(b,sort_keys=True).encode()).hexdigest()
def gb(s): return {'i':0,'t':str(datetime.now(timezone.utc)),'n':s,'q':"Void genesis","tx":[],'p':'0','o':0,'h':hb({'i':0,'t':str(datetime.now(timezone.utc)),'n':s,'q':"Void genesis","tx":[],'p':'0','o':0})}
def gm(): return ' '.join(random.choices(["void","chain","node","block","mine","coin","wallet","hash","seed","token","byte","crypto","ledger","peer","sync"],k=12))
def gv(): return VOID_PREFIX + uuid.uuid4().hex[:24]
def gf(): return FTW_PREFIX + uuid.uuid4().hex[:24]
def va(a): return a.startswith(VOID_PREFIX) and len(a) == 33
def fa(a): return a.startswith(FTW_PREFIX) and len(a) == 33
def ss(w,n,t): return hmac.new(C['S'],f"{w}:{n}:{t}".encode(),hashlib.sha256).hexdigest()

def derive_key(password: str, mnemonic: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=PBKDF2_ITER,
    )
    return kdf.derive((password + mnemonic).encode())

def encrypt_blob(data: dict, password: str, mnemonic: str) -> bytes:
    salt = secrets.token_bytes(SALT_SIZE)
    key = derive_key(password, mnemonic, salt)
    aesgcm = AESGCM(key)
    nonce = secrets.token_bytes(NONCE_SIZE)
    plaintext = json.dumps(data).encode()
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    blob = BLOB_MAGIC + salt + nonce + ciphertext
    return blob

def decrypt_blob(blob: bytes, password: str, mnemonic: str) -> dict:
    if not blob.startswith(BLOB_MAGIC):
        raise ValueError("Invalid blob format")
    salt = blob[len(BLOB_MAGIC):len(BLOB_MAGIC)+SALT_SIZE]
    nonce = blob[len(BLOB_MAGIC)+SALT_SIZE:len(BLOB_MAGIC)+SALT_SIZE+NONCE_SIZE]
    ciphertext = blob[len(BLOB_MAGIC)+SALT_SIZE+NONCE_SIZE:]
    key = derive_key(password, mnemonic, salt)
    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    return json.loads(plaintext.decode())

def mnemonic_to_seed(mnemonic: str) -> str:
    mnemo = Mnemonic("english")
    return mnemo.to_seed(mnemonic, passphrase="").hex()

def create_new_wallet(password: str) -> (dict, str):
    mnemonic = gm()
    seed = mnemonic_to_seed(mnemonic)
    wallet = {
        'n':str(uuid.uuid4()),
        'm':mnemonic,
        'va':gv(),
        'fa':gf(),
        'b':0.0,
        'c':[],
        'tx':[],
        'pw':None,  # Never store password
        'ps':0.0,
        'pt':[],
        'st':0.0,
        'stt':0,
        'ftw':0.0
    }
    wallet['c'].append(gb(wallet['n']))
    return wallet, mnemonic

def lw():
    if os.path.exists(C['W']):
        for _ in range(3):
            dlg = QDialog()
            dlg.setWindowTitle("Unlock Wallet")
            layout = QVBoxLayout(dlg)
            pw_input = QLineEdit()
            pw_input.setEchoMode(QLineEdit.Password)
            layout.addWidget(QLabel("Enter wallet password:"))
            layout.addWidget(pw_input)
            mnemonic_input = QLineEdit()
            layout.addWidget(QLabel("Enter your 12-word mnemonic:"))
            layout.addWidget(mnemonic_input)
            btns = QDialogButtonBox()
            unlock_btn = btns.addButton("Unlock Wallet", QDialogButtonBox.AcceptRole)
            create_btn = btns.addButton("Create New Wallet", QDialogButtonBox.ActionRole)
            cancel_btn = btns.addButton(QDialogButtonBox.Cancel)
            layout.addWidget(btns)
            result = {}
            def unlock():
                result['pw'] = pw_input.text()
                result['mn'] = mnemonic_input.text()
                dlg.accept()
            def create():
                result['create'] = True
                dlg.accept()
            unlock_btn.clicked.connect(unlock)
            create_btn.clicked.connect(create)
            cancel_btn.clicked.connect(dlg.reject)
            if dlg.exec() != QDialog.Accepted:
                QMessageBox.critical(None,"Access Denied","Cancelled.")
                sys.exit()
            if result.get('create'):
                break
            p = result.get('pw', '')
            m = result.get('mn', '')
            try:
                with open(C['W'],'rb') as f: blob = f.read()
                w = decrypt_blob(blob, p, m)
                return w, p, m
            except Exception as e:
                QMessageBox.warning(None,"Error",f"Failed to unlock wallet: {e}")
        # If user chose create or failed unlocks
        if not result.get('create'):
            QMessageBox.critical(None,"Access Denied","Too many failed attempts.")
            sys.exit()
    # Create new wallet
    m = gm()
    p,ok = QInputDialog.getText(None,"New Wallet",f"Create a wallet password:\nRecovery phrase:\n{m}\nCopy it safely.",QLineEdit.Password)
    if not ok:
        QMessageBox.critical(None,"Cancelled","Wallet creation cancelled.")
        sys.exit()
    w, _ = create_new_wallet(p)
    blob = encrypt_blob(w, p, m)
    with open(C['W'],'wb') as f: f.write(blob)
    QMessageBox.information(None,"Mnemonic Phrase",f"Your 12-word mnemonic:\n{m}\n\nWrite this down and keep it safe! It is the ONLY way to recover your wallet.")
    return w, p, m

def sw(w, password, mnemonic):
    blob = encrypt_blob(w, password, mnemonic)
    with open(C['W'],'wb') as f: f.write(blob)
    if w['st'] > 0 and w.get('stt',0) == 0: w['stt'] = int(time.time())

def ab(w,b,password,mnemonic):
    b['h'] = hb(b)
    w['c'].append(b)
    w['tx'] = []
    w['ps'] = 0.0
    w['pt'] = [tx for tx in w['pt'] if tx.get('id',None) not in [tx.get('id',None) for tx in b['tx']]]
    sw(w, password, mnemonic)

def ms(w, n, password, mnemonic):
    r = random.uniform(5e-8, 2e-7)
    w['ps'] = w.get('ps', 0.0) + r
    if 'sharepool' not in w:
        w['sharepool'] = []
    t = time.time()
    s = ss(w['va'], n, t)
    w['sharepool'].append({"w": w['va'], "n": n, "t": t, "s": s, "r": r})
    sw(w, password, mnemonic)

def cb(w):
    b=w.get("b",0.0)
    ftw = w.get("ftw", 0.0)
    for bl in w['c']:
        for tx in bl.get('tx',[]):
            if tx.get('to') == w['va']: b += tx['a']
            if tx.get('fr') == w['va']: b -= tx['a']
            if 'tf' in tx and tx['tf'] == w['fa']: ftw += tx.get('fa',0)
            if 'ff' in tx and tx['ff'] == w['fa']: ftw -= tx.get('fa',0)
    w['ftw'] = ftw
    return b

def uft(w):
    if w['st'] > 0:
        staked_time = time.time() - w.get('stt',time.time())
        staked_days = staked_time/(60*60*24)
        return staked_days * w['st'] * C['FTR']
    return 0

class LiveChainTab(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.layout = QVBoxLayout(self)
        self.setLayout(self.layout)
        self.title = QLabel("Live Chain Activity")
        self.title.setFont(C['FT'])
        self.title.setAlignment(Qt.AlignCenter)
        self.layout.addWidget(self.title)
        self.list = QListWidget()
        self.list.setStyleSheet("font-family: Consolas; font-size: 13px; background: #111122; color: #bbddff;")
        self.layout.addWidget(self.list)
        self.setMinimumHeight(400)
        self.setMinimumWidth(700)

    def add_event(self, msg):
        item = QListWidgetItem(msg)
        self.list.addItem(item)
        self.list.scrollToBottom()

class MS(QObject):
    u=pyqtSignal(int,int)  # nonce, hashrate

    m=pyqtSignal()

class MT(QThread):
    mined_block = pyqtSignal(str)
    hashrate_update = pyqtSignal(int, int)
    def __init__(self, w, si, live_tab, net, hr_callback, password, mnemonic):
        super().__init__()
        self.w = w
        self.si = si
        self.r = True
        self.live_tab = live_tab
        self.net = net
        self.hr_callback = hr_callback
        self.hash_attempts = 0
        self.hashrate = 0
        self.password = password
        self.mnemonic = mnemonic
        self.mined_block.connect(self.live_tab.add_event)
        self.hashrate_update.connect(self.hr_callback)
    def run(self):
        sp = '0' * C['SD']
        bp = '0' * C['BD']
        self.hash_attempts = 0
        self.hashrate = 0
        start_time = time.time()
        while self.r:
            lb = self.w['c'][-1]
            i = lb['i'] + 1  # FIX: use block index, not hash
            ph = lb['h']
            n = 0
            while self.r:
                b = {'i': i, 't': str(datetime.now(timezone.utc)), 'n': self.w['n'], 'tx': self.w.get('pt', []), 'p': ph, 'o': n}
                bh = hb(b)
                self.hash_attempts += 1
                elapsed = time.time() - start_time
                if elapsed > 0:
                    self.hashrate = int(self.hash_attempts / elapsed)
                if self.hash_attempts % 1000 == 0:
                    self.hashrate_update.emit(self.hash_attempts, self.hashrate)
                if bh.startswith(bp):
                    b['h'] = bh
                    self.w['b'] += C['BR'] + self.w.get('ps', 0.0)
                    self.w['ps'] = 0.0
                    ab(self.w, b, self.password, self.mnemonic)
                    msg = f"[{b['t']}] Block MINED by {b['n'][:8]}... | Hash: {b['h'][:10]}..."
                    self.mined_block.emit(msg)
                    self.net.broadcast_event(msg)
                    self.si.m.emit()
                    self.hashrate_update.emit(self.hash_attempts, self.hashrate)
                    break
                elif bh.startswith(sp):
                    ms(self.w, n, self.password, self.mnemonic)
                n += 1
    def stop(self):
        self.r = False

class NT(threading.Thread):
    def __init__(s,w,live_tab):
        super().__init__(daemon=True)
        s.w=w
        s.r=True
        s.p={}
        s.so=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
        s.so.setsockopt(socket.SOL_SOCKET,socket.SO_BROADCAST,1)
        s.so.bind(("",C['P']))
        s.live_tab = live_tab
        s.global_contracts = {}  # {contract_id: contract_dict}
        s.global_nfts = {}       # {nft_id: nft_dict}
    def run(s):
        lb=0
        while s.r:
            if time.time()-lb > C['I']:
                # Broadcast wallet summary and contracts/NFTs
                msg = {"n":s.w['n'],"va":s.w['va'],"fa":s.w['fa'],"b":cb(s.w),"ftw":s.w.get('ftw',0.0),"t":time.time()}
                # Add contracts/NFTs to broadcast
                msg['contracts'] = s.w.get('contracts', [])
                s.so.sendto(json.dumps(msg).encode(),('<broadcast>',C['P']))
                lb=time.time()
            try:
                s.so.settimeout(1.0)
                d,a=s.so.recvfrom(65536)
                p=json.loads(d.decode())
                if "event" in p:
                    s.live_tab.add_event(p["event"])
                if "n" in p and "va" in p:
                    s.p[p["n"]]={"va":p["va"],"fa":p.get("fa","N/A"),"b":p["b"],"ftw":p.get("ftw",0.0),"l":time.time()}
                # --- Global contracts/NFTs sync ---
                for c in p.get('contracts', []):
                    s.global_contracts[c['id']] = c
                    for nft in c.get('nfts', []):
                        s.global_nfts[nft['id']] = nft
            except:
                pass
    def broadcast_event(s, msg):
        s.so.sendto(json.dumps({"event": msg}).encode(),('<broadcast>',C['P']))
    def gp(s):
        return {n:p for n,p in s.p.items() if time.time()-p["l"] < C['T']}
    def stop(s):
        s.r=False
    def get_global_contracts(s):
        return list(s.global_contracts.values())
    def get_global_nfts(s):
        return list(s.global_nfts.values())

class AmountInputDialog(QDialog):
    def __init__(self, parent=None, title="", label="", minimum=0.01, maximum=1000.0):
        super().__init__(parent)
        self.setWindowTitle(title)
        self.value = None
        layout = QFormLayout(self)
        self.spin = QDoubleSpinBox()
        self.spin.setDecimals(8)
        self.spin.setMinimum(minimum)
        self.spin.setMaximum(maximum)
        self.spin.setSingleStep(0.01)
        self.spin.setValue(minimum)
        layout.addRow(label, self.spin)
        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)
    def getValue(self):
        return self.spin.value()

def ne(w,c=C['NP']):
    g=QGraphicsDropShadowEffect()
    g.setOffset(0)
    g.setBlurRadius(20)
    g.setColor(c)
    w.setGraphicsEffect(g)

class VW(QWidget):
    def __init__(s):
        super().__init__()
        s.setWindowTitle("VoidChain Wallet")
        s.setGeometry(200,200,900,900)
        s.w, s.password, s.mnemonic = lw()
        s.live_tab = LiveChainTab()
        s.n=NT(s.w, s.live_tab)
        s.n.start()
        s.mt=None
        s.s=MS()
        s.s.m.connect(s.ud)
        s.s.u.connect(lambda n,h: None)
        s.hashrate = 0
        s.hash_attempts = 0
        s.ui()

    def ui(s):
        p=QPalette()
        p.setColor(QPalette.Window,C['BG'])
        p.setColor(QPalette.WindowText,C['TC'])
        s.setPalette(p)
        s.setFont(C['FM'])
        s.setStyleSheet(
            "QWidget{background-color:#0f0f1e;color:#ccddff}"
            "QLabel{font-family:Consolas;font-weight:bold;color:#bbddff}"
            "QLineEdit,QTextEdit{background-color:#111122;color:#ddffee;border:1px solid #4444ff;border-radius:5px}"
            "QPushButton{background-color:#6000ff;color:white;border-radius:10px;padding:8px 18px;font-weight:bold}"
            "QPushButton:hover{background-color:#7f00ff}"
            "QListWidget{background-color:#111122;border:1px solid #4444ff;color:#66ffff;font-family:Consolas}"
        )
        s.tabs = QTabWidget()
        # --- Retro/primary color tabs, but NOT for Wallet tab ---
        s.tabs.setStyleSheet('''
            QTabBar::tab { min-width: 180px; min-height: 32px; font-size: 15px; font-family: Consolas; font-weight: bold; border-radius: 8px; margin: 2px; }
            QTabBar::tab:selected { border: 2px solid #fff; }
            QTabBar::tab:!selected { border: 1px solid #888; }
            QTabBar::tab:nth-child(2) { background: #ffe600; color: #222; } /* Live Chain - yellow */
            QTabBar::tab:nth-child(3) { background: #ff2a2a; color: #fff; } /* Contracts & NFTs - red */
            QTabBar::tab:nth-child(4) { background: #00e676; color: #222; } /* Global Contracts & NFTs - green */
        ''')
        # Main wallet tab
        wallet_tab = QWidget()
        l = QVBoxLayout(wallet_tab)
        vl=QHBoxLayout()
        s.val=QLabel(s.w['va'])
        s.val.setFont(C['FT'])
        ne(s.val)
        vl.addWidget(QLabel("VOID Address:"))
        vl.addWidget(s.val)
        s.vab=QPushButton("📋 Copy VOID Address")
        s.vab.clicked.connect(lambda:s.cac(s.w['va'],"VOID"))
        ne(s.vab)
        vl.addWidget(s.vab)
        l.addLayout(vl)
        fl=QHBoxLayout()
        s.fal=QLabel(s.w.get('fa', gf()))
        s.fal.setFont(C['FT'])
        ne(s.fal,C['NC'])
        fl.addWidget(QLabel("FTW Address:"))
        fl.addWidget(s.fal)
        s.fab=QPushButton("📋 Copy FTW Address")
        s.fab.clicked.connect(lambda:s.cac(s.w['fa'],"FTW"))
        ne(s.fab,C['NC'])
        fl.addWidget(s.fab)
        l.addLayout(fl)
        s.ml=QLabel(s.w['m'])
        s.ml.setWordWrap(True)
        ne(s.ml,C['NC'])
        l.addWidget(QLabel("Recovery Phrase:"))
        l.addWidget(s.ml)
        s.bl=QLabel()
        s.cl=QLabel()
        s.sl=QLabel()
        s.ftl=QLabel()
        s.st=QLabel()
        s.pending_shares_label = QLabel()
        s.hashrate_label = QLabel("Hashrate: 0 H/s")
        s.hashattempts_label = QLabel("Hash Attempts: 0")
        for lb in [s.bl,s.cl,s.sl,s.ftl,s.st,s.pending_shares_label,s.hashrate_label,s.hashattempts_label]:
            ne(lb,C['NPk'])
            l.addWidget(lb)
        ml=QHBoxLayout()
        ml.addStretch()
        s.mb=QPushButton("⛏️ Start Mining")
        s.mb.setFixedWidth(150)
        s.mb.setSizePolicy(QSizePolicy.Fixed,QSizePolicy.Fixed)
        s.mb.clicked.connect(s.tm)
        ne(s.mb)
        ml.addWidget(s.mb)
        ml.addStretch()
        l.addLayout(ml)
        sb=QHBoxLayout()
        s.sab=QPushButton("💰 Stake VOID")
        s.sab.clicked.connect(s.stk)
        ne(s.sab,C['NC'])
        sb.addWidget(s.sab)
        s.usb=QPushButton("💸 Unstake VOID")
        s.usb.clicked.connect(s.ust)
        ne(s.usb,C['NP'])
        sb.addWidget(s.usb)
        s.cfb=QPushButton("✨ Claim FTW")
        s.cfb.clicked.connect(s.cf)
        ne(s.cfb,C['NB'])
        sb.addWidget(s.cfb)
        l.addLayout(sb)
        l.addWidget(QLabel("Send VOID:"))
        s.sai=QLineEdit()
        s.sai.setPlaceholderText("VOID Recipient Address")
        l.addWidget(s.sai)
        s.sami=QLineEdit()
        s.sami.setPlaceholderText("Amount to Send (VOID)")
        l.addWidget(s.sami)
        s.sb=QPushButton("🚀 Send VOID")
        s.sb.clicked.connect(s.stx)
        ne(s.sb)
        l.addWidget(s.sb)
        l.addWidget(QLabel("Send FTW:"))
        s.sfta=QLineEdit()
        s.sfta.setPlaceholderText("FTW Recipient Address")
        l.addWidget(s.sfta)
        s.sfti=QLineEdit()
        s.sfti.setPlaceholderText("Amount to Send (FTW)")
        l.addWidget(s.sfti)
        s.sftb=QPushButton("🌟 Send FTW")
        s.sftb.clicked.connect(s.sft)
        ne(s.sftb,C['NC'])
        l.addWidget(s.sftb)
        l.addWidget(QLabel("Active Peers:"))
        s.pl=QListWidget()
        s.pl.setFixedHeight(120)
        l.addWidget(s.pl)
        l.addWidget(QLabel("Latest Block:"))
        s.bi=QTextEdit()
        s.bi.setReadOnly(True)
        s.bi.setFixedHeight(150)
        l.addWidget(s.bi)
        wallet_tab.setLayout(l)
        s.tabs.addTab(wallet_tab, "Wallet")
        # Live Chain tab
        s.tabs.addTab(s.live_tab, "Live Chain")
        # --- Add global contracts/NFTs tab ---
        s.global_contracts_tab = GlobalContractsNFTsTab(s.n, lambda: s.w.get('ftw', 0.0))
        s.tabs.addTab(s.global_contracts_tab, "Global Contracts & NFTs")
        # --- Set tab content background color on change ---
        def set_tab_bg(idx):
            # Wallet tab (idx 0): original style
            if idx == 0:
                s.tabs.currentWidget().setStyleSheet("")
            else:
                colors = [None, "#ffe600", "#ff2a2a", "#00e676"]
                text_colors = [None, "#222", "#fff", "#222"]
                if idx < len(colors) and colors[idx]:
                    s.tabs.currentWidget().setStyleSheet(f"background: {colors[idx]}; color: {text_colors[idx]}; border-radius: 12px; font-family: Consolas; font-size: 15px;")
        s.tabs.currentChanged.connect(set_tab_bg)
        set_tab_bg(0)
        main_layout = QVBoxLayout(s)
        main_layout.addWidget(s.tabs)
        s.ui_timer = QTimer()
        s.ui_timer.timeout.connect(s.ud)
        s.ui_timer.start(3000)
        s.ud()

    def update_hashrate(self, attempts, hashrate):
        self.hashrate_label.setText(f"Hashrate: {hashrate} H/s")
        self.hashattempts_label.setText(f"Hash Attempts: {attempts}")

    def ud(self):
        w = self.w
        self.bl.setText(f"VOID Balance: {cb(w):.8f}")
        self.cl.setText(f"Coins Mined: {len(w.get('c',[]))}")
        self.sl.setText(f"Stake Amount: {w.get('st',0.0):.8f} VOID")
        self.ftl.setText(f"FTW Balance: {w.get('ftw',0.0):.8f}")
        self.st.setText(f"FTW Pending (via staking): {uft(w):.8f}")
        self.pending_shares_label.setText(f"Pending Mining Shares (VOID): {w.get('ps',0.0):.8f}")
        self.hashrate_label.setText(f"Hashrate: {getattr(self, 'hashrate', 0)} H/s")
        self.hashattempts_label.setText(f"Hash Attempts: {getattr(self, 'hash_attempts', 0)}")
        peers = self.n.gp()
        self.pl.clear()
        for k,v in peers.items():
            self.pl.addItem(f"{v['va']} (VOID: {v['b']:.8f}) | {v['fa']} (FTW: {v['ftw']:.8f})")
        if w.get('c'):
            lb = w['c'][-1]
            self.bi.setText(json.dumps(lb, indent=2))
        else:
            self.bi.setText("No blocks mined yet.")
        if self.mt and self.mt.isRunning():
            self.mb.setText("⛔ Stop Mining")
        else:
            self.mb.setText("⛏️ Start Mining")
        # --- Contracts & NFTs tab unlock logic moved here ---
        if not hasattr(self, '_contracts_nfts_tab_added'):
            self._contracts_nfts_tab_added = False
        if w.get('ftw', 0.0) >= 0.00001 and not self._contracts_nfts_tab_added:
            self.contracts_nfts_tab = ContractsNFTsTab(self.w, self.live_tab, self.ud)
            self.tabs.addTab(self.contracts_nfts_tab, "Contracts & NFTs")
            self._contracts_nfts_tab_added = True
        elif w.get('ftw', 0.0) < 0.00001 and getattr(self, '_contracts_nfts_tab_added', False):
            idx = self.tabs.indexOf(self.contracts_nfts_tab)
            if idx != -1:
                self.tabs.removeTab(idx)
            self._contracts_nfts_tab_added = False

    def tm(self):
        if self.mt and self.mt.isRunning():
            self.mt.stop()
            self.mt.wait()
            self.mt = None
            self.ud()
        else:
            self.mt = MT(self.w, self.s, self.live_tab, self.n, self.update_hashrate, self.password, self.mnemonic)
            self.mt.start()

    def cac(self,a,t):
        QApplication.clipboard().setText(a)
        QMessageBox.information(self,f"{t} Address Copied",f"{t} address copied to clipboard:\n{a}")

    def stk(self):
        max_stake = self.w.get('b',0.0)
        d = AmountInputDialog(self,"Stake VOID","Amount to Stake (max {:.8f}):".format(max_stake),0.01,max_stake)
        if d.exec() == QDialog.Accepted:
            amt = d.getValue()
            if amt <= 0 or amt > max_stake:
                QMessageBox.warning(self,"Invalid Amount","Enter a valid amount less or equal to your balance.")
                return
            self.w['b'] -= amt
            self.w['st'] += amt
            if self.w.get('stt',0) == 0:
                self.w['stt'] = int(time.time())
            sw(self.w, self.password, self.mnemonic)
            self.ud()
            msg = f"[{datetime.now(timezone.utc)}] {self.w['va'][:8]}... STAKED {amt:.8f} VOID"
            self.live_tab.add_event(msg)
            self.n.broadcast_event(msg)

    def ust(self):
        max_unstake = self.w.get('st',0.0)
        d = AmountInputDialog(self,"Unstake VOID","Amount to Unstake (max {:.8f}):".format(max_unstake),0.01,max_unstake)
        if d.exec() == QDialog.Accepted:
            amt = d.getValue()
            if amt <= 0 or amt > max_unstake:
                QMessageBox.warning(self,"Invalid Amount","Enter a valid amount less or equal to your staked amount.")
                return
            pending_ftw = uft(self.w)
            self.w['b'] += amt
            self.w['ftw'] += pending_ftw
            self.w['st'] -= amt
            if self.w['st'] <= 0:
                self.w['stt'] = 0
            else:
                self.w['stt'] = int(time.time())
            sw(self.w, self.password, self.mnemonic)
            self.ud()
            msg = f"[{datetime.now(timezone.utc)}] {self.w['va'][:8]}... UNSTAKED {amt:.8f} VOID, CLAIMED {pending_ftw:.8f} FTW"
            self.live_tab.add_event(msg)
            self.n.broadcast_event(msg)
            QMessageBox.information(self,"Unstaked",f"Unstaked {amt:.8f} VOID\nAdded {pending_ftw:.8f} FTW rewards")

    def cf(self):
        p = uft(self.w)
        if p <= 0:
            QMessageBox.information(self,"No Rewards","No FTW rewards to claim currently.")
            return
        self.w['ftw'] += p
        self.w['stt'] = int(time.time())
        sw(self.w, self.password, self.mnemonic)
        self.ud()
        msg = f"[{datetime.now(timezone.utc)}] {self.w['fa'][:8]}... CLAIMED {p:.8f} FTW"
        self.live_tab.add_event(msg)
        self.n.broadcast_event(msg)
        QMessageBox.information(self,"Claimed",f"Claimed {p:.8f} FTW tokens")

    def stx(self):
        to = self.sai.text().strip()
        try:
            amt = float(self.sami.text().strip())
        except:
            QMessageBox.warning(self,"Invalid Input","Please enter a valid VOID amount.")
            return
        if not va(to):
            QMessageBox.warning(self,"Invalid Address","Please enter a valid VOID address.")
            return
        if amt <= 0 or amt > self.w.get('b',0.0):
            QMessageBox.warning(self,"Invalid Amount","You do not have enough VOID to send.")
            return
        tx = {'fr':self.w['va'],'to':to,'a':amt,'t':str(datetime.now(timezone.utc))}
        self.w['tx'].append(tx)
        self.w['b'] -= amt
        sw(self.w, self.password, self.mnemonic)
        self.ud()
        msg = f"[{datetime.now(timezone.utc)}] {self.w['va'][:8]}... SENT {amt:.8f} VOID to {to[:8]}..."
        self.live_tab.add_event(msg)
        self.n.broadcast_event(msg)
        QMessageBox.information(self,"Sent","Sent {:.8f} VOID to {}".format(amt,to))

    def sft(self):
        to = self.sfta.text().strip()
        try:
            amt = float(self.sfti.text().strip())
        except:
            QMessageBox.warning(self,"Invalid Input","Please enter a valid FTW amount.")
            return
        if not fa(to):
            QMessageBox.warning(self,"Invalid Address","Please enter a valid FTW address.")
            return
        if amt <= 0 or amt > self.w.get('ftw',0.0):
            QMessageBox.warning(self,"Invalid Amount","You do not have enough FTW to send.")
            return
        tx = {'ff':self.w['fa'],'tf':to,'fa':amt,'t':str(datetime.now(timezone.utc))}
        self.w['tx'].append(tx)
        self.w['ftw'] -= amt
        sw(self.w, self.password, self.mnemonic)
        self.ud()
        msg = f"[{datetime.now(timezone.utc)}] {self.w['fa'][:8]}... SENT {amt:.8f} FTW to {to[:8]}..."
        self.live_tab.add_event(msg)
        self.n.broadcast_event(msg)
        QMessageBox.information(self,"Sent","Sent {:.8f} FTW to {}".format(amt,to))

class ContractsNFTsTab(QWidget):
    def __init__(self, wallet, live_tab, update_wallet_callback):
        super().__init__()
        self.wallet = wallet
        self.live_tab = live_tab
        self.update_wallet_callback = update_wallet_callback
        layout = QVBoxLayout(self)
        info = QLabel("Create and deploy smart contracts or NFTs. Each deployment costs 0.00001 FTW.")
        layout.addWidget(info)
        self.editor = QTextEdit()
        self.editor.setPlaceholderText("Enter contract code or NFT description here...")
        layout.addWidget(self.editor)
        self.img_btn = QPushButton("Attach Image/GIF for NFT (optional)")
        self.img_btn.clicked.connect(self.select_image)
        layout.addWidget(self.img_btn)
        self.selected_img_b64 = None
        deploy_row = QHBoxLayout()
        self.deploy_contract_btn = QPushButton("Deploy Contract")
        self.deploy_contract_btn.clicked.connect(self.deploy_contract)
        deploy_row.addWidget(self.deploy_contract_btn)
        self.deploy_nft_btn = QPushButton("Deploy NFT")
        self.deploy_nft_btn.clicked.connect(self.deploy_nft)
        deploy_row.addWidget(self.deploy_nft_btn)
        layout.addLayout(deploy_row)
        self.contracts_list = QListWidget()
        layout.addWidget(QLabel("My Deployed Contracts & NFTs:"))
        layout.addWidget(self.contracts_list)
        self.contracts_list.itemDoubleClicked.connect(self.view_item)
        self.refresh_list()

    def select_image(self):
        path, _ = QFileDialog.getOpenFileName(self, "Select Image/GIF", "", "Images (*.png *.jpg *.jpeg *.gif)")
        if path:
            with open(path, "rb") as f:
                self.selected_img_b64 = base64.b64encode(f.read()).decode()
            QMessageBox.information(self, "Image Selected", "Image/GIF attached for NFT.")

    def deploy_contract(self):
        if self.wallet.get('ftw', 0.0) < 0.00001:
            QMessageBox.warning(self, "Insufficient FTW", "You need at least 0.00001 FTW to deploy a contract.")
            return
        code = self.editor.toPlainText().strip()
        if not code:
            QMessageBox.warning(self, "No Code", "Please enter contract code.")
            return
        # --- Validate code is a valid Python class ---
        try:
            local_vars = {}
            exec(code, {}, local_vars)
            contract_class = None
            for v in local_vars.values():
                if isinstance(v, type):
                    contract_class = v
                    break
            if not contract_class:
                raise ValueError("No class definition found in contract code.")
        except Exception as e:
            QMessageBox.critical(self, "Invalid Contract Code", f"Contract code must be a valid Python class.\nError: {e}")
            return
        name, ok = QInputDialog.getText(self, "Contract Name", "Enter contract name:")
        if not ok or not name.strip():
            return
        public, ok2 = QInputDialog.getItem(self, "Contract Visibility", "Allow public to interact?", ["Yes (Public)", "No (Private)"], 0, False)
        if not ok2:
            return
        is_public = public.startswith("Yes")
        contract = {
            'id': str(uuid.uuid4()),
            'name': name.strip(),
            'owner': self.wallet['fa'],
            'timestamp': str(datetime.now(timezone.utc)),
            'type': 'contract',
            'code': code,
            'nfts': [],
            'public': is_public
        }
        self.wallet.setdefault('contracts', []).append(contract)
        self.wallet['ftw'] -= 0.00001
        sw(self.wallet, self.wallet.get('password', ''), self.wallet.get('mnemonic', ''))
        self.update_wallet_callback()
        self.live_tab.add_event(f"[CONTRACT] {contract['name']} deployed by {contract['owner'][:8]}... at {contract['timestamp']}")
        QMessageBox.information(self, "Deployed", f"Contract '{name}' deployed! 0.00001 FTW used as gas.")
        self.refresh_list()

    def deploy_nft(self):
        if self.wallet.get('ftw', 0.0) < 0.00001:
            QMessageBox.warning(self, "Insufficient FTW", "You need at least 0.00001 FTW to deploy an NFT.")
            return
        desc = self.editor.toPlainText().strip()
        if not desc:
            QMessageBox.warning(self, "No Description", "Please enter NFT description.")
            return
        name, ok = QInputDialog.getText(self, "NFT Name", "Enter NFT name:")
        if not ok or not name.strip():
            return
        nft = {
            'id': str(uuid.uuid4()),
            'name': name.strip(),
            'owner': self.wallet['fa'],
            'timestamp': str(datetime.now(timezone.utc)),
            'desc': desc,
            'img_b64': self.selected_img_b64,
        }
        # Store NFT in a dummy contract for on-chain visibility
        if 'contracts' not in self.wallet or not self.wallet['contracts']:
            dummy = {
                'id': str(uuid.uuid4()),
                'name': 'NFT Dummy',
                'owner': self.wallet['fa'],
                'timestamp': str(datetime.now(timezone.utc)),
                'type': 'contract',
                'code': '',
                'nfts': [],
            }
            self.wallet.setdefault('contracts', []).append(dummy)
        self.wallet['contracts'][0].setdefault('nfts', []).append(nft)
        self.wallet['ftw'] -= 0.00001
        sw(self.wallet, self.wallet.get('password', ''), self.wallet.get('mnemonic', ''))
        self.update_wallet_callback()
        self.live_tab.add_event(f"[NFT] {nft['name']} deployed by {nft['owner'][:8]}... at {nft['timestamp']}")
        QMessageBox.information(self, "Deployed", f"NFT '{name}' deployed! 0.00001 FTW used as gas.")
        self.refresh_list()
        self.selected_img_b64 = None

    def refresh_list(self):
        self.contracts_list.clear()
        self._item_id_map = []  # Track (type, id) for each row
        for c in self.wallet.get('contracts', []):
            self.contracts_list.addItem(f"[CONTRACT] {c['name']} | {c['id']} | {c['timestamp']}")
            self._item_id_map.append(('contract', c['id']))
            for nft in c.get('nfts', []):
                self.contracts_list.addItem(f"[NFT] {nft.get('name', 'Unnamed')} | {nft.get('id', '')}")
                self._item_id_map.append(('nft', nft.get('id', '')))

    def view_item(self, item):
        idx = self.contracts_list.row(item)
        if not hasattr(self, '_item_id_map') or idx >= len(self._item_id_map):
            QMessageBox.warning(self, "Error", "Could not find the selected item.")
            return
        typ, obj_id = self._item_id_map[idx]
        if typ == 'contract':
            contract = next((c for c in self.wallet.get('contracts', []) if c['id'] == obj_id), None)
            if not contract:
                QMessageBox.warning(self, "Error", "Contract not found.")
                return
            dlg = QDialog(self)
            dlg.setWindowTitle(f"Contract: {contract['name']}")
            layout = QVBoxLayout(dlg)
            code_view = QTextEdit()
            code_view.setPlainText(contract.get('code', ''))
            code_view.setReadOnly(True)
            layout.addWidget(QLabel(f"Owner: {contract['owner']}"))
            layout.addWidget(QLabel(f"Timestamp: {contract['timestamp']}"))
            layout.addWidget(code_view)
            try:
                import time, inspect
                local_vars = {}
                exec(contract.get('code', ''), {"time": time}, local_vars)
                contract_class = None
                for v in local_vars.values():
                    if isinstance(v, type):
                        contract_class = v
                        break
                if not contract_class:
                    layout.addWidget(QLabel("[This contract does not define a valid Python class. Interaction unavailable.]") )
                else:
                    # --- PATCH: Restore state from contract dict ---
                    state = contract.get('state', {})
                    contract_obj = contract_class()
                    for k, v in state.items():
                        setattr(contract_obj, k, v)
                    methods = [m for m in dir(contract_obj) if callable(getattr(contract_obj, m)) and not m.startswith("__")]
                    for m in methods:
                        method = getattr(contract_obj, m)
                        sig = inspect.signature(method)
                        btn = QPushButton(f"Call: {m}{sig}")
                        def make_call(meth, sig, mname):
                            def call():
                                params = []
                                for pname, param in list(sig.parameters.items()):
                                    if pname == 'self':
                                        continue
                                    val, ok = QInputDialog.getText(dlg, f"Input for {mname}", f"Enter value for {pname} ({param.annotation}):")
                                    if not ok:
                                        return
                                    params.append(val)
                                try:
                                    result = meth(*params)
                                    # --- PATCH: Save state back to contract dict ---
                                    contract['state'] = {k: getattr(contract_obj, k) for k in dir(contract_obj) if not k.startswith('__') and not callable(getattr(contract_obj, k))}
                                    # --- FIX: Route contract action dict(s) to handle_contract_action for the current user's wallet ---
                                    if isinstance(result, dict) and 'action' in result:
                                        parent = self.parentWidget()
                                        while parent and not hasattr(parent, 'w'):
                                            parent = parent.parentWidget() if hasattr(parent, 'parentWidget') else None
                                        wallet = getattr(parent, 'w', None)
                                        live_tab = getattr(parent, 'live_tab', None)
                                        if wallet:
                                            handle_contract_action(wallet, result, live_tab)
                                            QMessageBox.information(dlg, "Contract Action", f"Action executed: {result}")
                                        else:
                                            QMessageBox.information(dlg, "Contract Action", f"Action: {result}")
                                    elif isinstance(result, list) and all(isinstance(x, dict) and 'action' in x for x in result):
                                        parent = self.parentWidget()
                                        while parent and not hasattr(parent, 'w'):
                                            parent = parent.parentWidget() if hasattr(parent, 'parentWidget') else None
                                        wallet = getattr(parent, 'w', None)
                                        live_tab = getattr(parent, 'live_tab', None)
                                        if wallet:
                                            handle_contract_action(wallet, result, live_tab)
                                            QMessageBox.information(dlg, "Contract Actions", f"Batch actions executed: {result}")
                                        else:
                                            QMessageBox.information(dlg, "Contract Actions", f"Batch actions: {result}")
                                    else:
                                        QMessageBox.information(dlg, "Contract Call", f"Result: {result}")
                                except Exception as e:
                                    QMessageBox.warning(dlg, "Error", f"Error calling method: {e}")
                            return call
                        btn.clicked.connect(make_call(method, sig, m))
                        layout.addWidget(btn)
            except Exception as e:
                layout.addWidget(QLabel(f"[This contract's code is invalid or contains syntax errors. Interaction unavailable. Error: {e}]") )
            if contract['owner'] == self.wallet['fa']:
                send_btn = QPushButton("Send Contract to FTW Address")
                def send_contract():
                    addr, ok = QInputDialog.getText(self, "Send Contract", "Enter recipient FTW address:")
                    if ok and addr.strip():
                        self.wallet['contracts'].remove(contract)
                        sw(self.wallet, self.wallet.get('password', ''), self.wallet.get('mnemonic', ''))
                        self.live_tab.add_event(f"[SEND] Contract '{contract['name']}' sent to {addr.strip()} at {datetime.now(timezone.utc)}")
                        QMessageBox.information(self, "Sent", f"Contract sent to {addr.strip()}.")
                        self.refresh_list()
                        dlg.accept()
                send_btn.clicked.connect(send_contract)
                layout.addWidget(send_btn)
            dlg.setLayout(layout)
            dlg.exec_()
        elif typ == 'nft':
            nft = None
            parent_contract = None
            for c in self.wallet.get('contracts', []):
                for n in c.get('nfts', []):
                    if n.get('id', '') == obj_id:
                        nft = n
                        parent_contract = c
                        break
                if nft:
                    break
            if not nft:
                QMessageBox.warning(self, "Error", "NFT not found.")
                return
            dlg = QDialog(self)
            dlg.setWindowTitle(f"NFT: {nft.get('name', '')}")
            layout = QVBoxLayout(dlg)
            if nft.get('img_b64'):
                img_data = base64.b64decode(nft['img_b64'])
                pixmap = QPixmap()
                pixmap.loadFromData(img_data)
                lbl = QLabel()
                lbl.setPixmap(pixmap.scaled(256,256,Qt.KeepAspectRatio))
                layout.addWidget(lbl)
            layout.addWidget(QLabel(f"Owner: {nft.get('owner','')}"))
            layout.addWidget(QLabel(f"Timestamp: {nft.get('timestamp','')}"))
            layout.addWidget(QLabel(f"Description: {nft.get('desc','')}"))
            if nft.get('owner','') == self.wallet['fa']:
                send_btn = QPushButton("Send NFT to FTW Address")
                def send_nft():
                    addr, ok = QInputDialog.getText(self, "Send NFT", "Enter recipient FTW address:")
                    if ok and addr.strip():
                        parent_contract['nfts'].remove(nft)
                        sw(self.wallet, self.wallet.get('password', ''), self.wallet.get('mnemonic', ''))
                        self.live_tab.add_event(f"[SEND] NFT '{nft.get('name','')}' sent to {addr.strip()} at {datetime.now(timezone.utc)}")
                        QMessageBox.information(self, "Sent", f"NFT sent to {addr.strip()}.")
                        self.refresh_list()
                        dlg.accept()
                send_btn.clicked.connect(send_nft)
                layout.addWidget(send_btn)
            dlg.setLayout(layout)
            dlg.exec_()

class GlobalContractsNFTsTab(QWidget):
    def __init__(self, network, get_ftw_balance):
        super().__init__()
        self.network = network
        self.get_ftw_balance = get_ftw_balance
        layout = QVBoxLayout(self)
        layout.addWidget(QLabel("All Contracts & NFTs on the Chain (Global Registry):"))
        self.list = QListWidget()
        layout.addWidget(self.list)
        self.refresh_btn = QPushButton("Refresh Global List")
        self.refresh_btn.clicked.connect(self.refresh_list)
        layout.addWidget(self.refresh_btn)
        self.refresh_list()
        self.list.itemDoubleClicked.connect(self.view_item)
        # --- Auto-refresh global list every 3 seconds ---
        self.refresh_timer = QTimer(self)
        self.refresh_timer.timeout.connect(self.refresh_list)
        self.refresh_timer.start(3000)

    def refresh_list(self):
        self.list.clear()
        self._item_id_map = []
        for c in self.network.get_global_contracts():
            pub = c.get('public', True)
            pubstr = '[PUBLIC]' if pub else '[PRIVATE]'
            self.list.addItem(f"[CONTRACT]{pubstr} {c['name']} | {c['id']} | {c['timestamp']}")
            self._item_id_map.append(('contract', c['id']))
            for nft in c.get('nfts', []):
                self.list.addItem(f"[NFT] {nft.get('name', 'Unnamed')} | {nft.get('id', '')}")
                self._item_id_map.append(('nft', nft.get('id', '')))

    def view_item(self, item):
        idx = self.list.row(item)
        if not hasattr(self, '_item_id_map') or idx >= len(self._item_id_map):
            QMessageBox.warning(self, "Error", "Could not find the selected item.")
            return
        typ, obj_id = self._item_id_map[idx]
        if typ == 'contract':
            contract = self.network.global_contracts.get(obj_id)
            if not contract:
                QMessageBox.warning(self, "Error", "Contract not found.")
                return
            dlg = QDialog(self)
            dlg.setWindowTitle(f"Contract: {contract['name']} (Global)")
            layout = QVBoxLayout(dlg)
            code_view = QTextEdit()
            code_view.setPlainText(contract.get('code', ''))
            code_view.setReadOnly(True)
            layout.addWidget(QLabel(f"Owner: {contract['owner']}"))
            layout.addWidget(QLabel(f"Timestamp: {contract['timestamp']}"))
            layout.addWidget(code_view)
            can_interact = False
            if contract.get('public', True) and self.get_ftw_balance() >= 0.00001:
                can_interact = True
            elif not contract.get('public', True):
                parent = self.parentWidget()
                while parent and not hasattr(parent, 'w'):
                    parent = parent.parentWidget() if hasattr(parent, 'parentWidget') else None
                if parent and contract.get('owner', None) == getattr(parent, 'w', {}).get('fa', None):
                    can_interact = True
            if can_interact:
                try:
                    import time, inspect
                    local_vars = {}
                    exec(contract.get('code', ''), {"time": time}, local_vars)
                    contract_class = None
                    for v in local_vars.values():
                        if isinstance(v, type):
                            contract_class = v
                            break
                    if not contract_class:
                        layout.addWidget(QLabel("[This contract does not define a valid Python class. Interaction unavailable.]") )
                    else:
                        # --- PATCH: Restore state from contract dict ---
                        state = contract.get('state', {})
                        contract_obj = contract_class()
                        for k, v in state.items():
                            setattr(contract_obj, k, v)
                        methods = [m for m in dir(contract_obj) if callable(getattr(contract_obj, m)) and not m.startswith("__")]
                        for m in methods:
                            method = getattr(contract_obj, m)
                            sig = inspect.signature(method)
                            btn = QPushButton(f"Call: {m}{sig}")
                            def make_call(meth, sig, mname):
                                def call():
                                    params = []
                                    for pname, param in list(sig.parameters.items()):
                                        if pname == 'self':
                                            continue
                                        val, ok = QInputDialog.getText(dlg, f"Input for {mname}", f"Enter value for {pname} ({param.annotation}):")
                                        if not ok:
                                            return
                                        params.append(val)
                                    try:
                                        result = meth(*params)
                                        # --- PATCH: Save state back to contract dict ---
                                        contract['state'] = {k: getattr(contract_obj, k) for k in dir(contract_obj) if not k.startswith('__') and not callable(getattr(contract_obj, k))}
                                        if isinstance(result, dict) and 'action' in result:
                                            parent = self.parentWidget()
                                            while parent and not hasattr(parent, 'w'):
                                                parent = parent.parentWidget() if hasattr(parent, 'parentWidget') else None
                                            wallet = getattr(parent, 'w', None)
                                            live_tab = getattr(parent, 'live_tab', None)
                                            if wallet:
                                                handle_contract_action(wallet, result, live_tab)
                                                QMessageBox.information(dlg, "Contract Action", f"Action executed: {result}")
                                            else:
                                                QMessageBox.information(dlg, "Contract Action", f"Action: {result}")
                                        elif isinstance(result, list) and all(isinstance(x, dict) and 'action' in x for x in result):
                                            parent = self.parentWidget()
                                            while parent and not hasattr(parent, 'w'):
                                                parent = parent.parentWidget() if hasattr(parent, 'parentWidget') else None
                                            wallet = getattr(parent, 'w', None)
                                            live_tab = getattr(parent, 'live_tab', None)
                                            if wallet:
                                                handle_contract_action(wallet, result, live_tab)
                                                QMessageBox.information(dlg, "Contract Actions", f"Batch actions executed: {result}")
                                            else:
                                                QMessageBox.information(dlg, "Contract Actions", f"Batch actions: {result}")
                                        else:
                                            QMessageBox.information(dlg, "Contract Call", f"Result: {result}")
                                    except Exception as e:
                                        QMessageBox.warning(dlg, "Error", f"Error calling method: {e}")
                                return call
                            btn.clicked.connect(make_call(method, sig, m))
                            layout.addWidget(btn)
                except Exception as e:
                    layout.addWidget(QLabel(f"[This contract's code is invalid or contains syntax errors. Interaction unavailable. Error: {e}]") )
            else:
                if contract.get('public', True):
                    if self.get_ftw_balance() < 0.00001:
                        layout.addWidget(QLabel("You need at least 0.00001 FTW to interact with public contracts."))
                    else:
                        layout.addWidget(QLabel("[This contract does not define a valid Python class. Interaction unavailable.]") )
                else:
                    layout.addWidget(QLabel("This contract is private. Only the owner can interact."))
            dlg.setLayout(layout)
            dlg.exec_()
        elif typ == 'nft':
            nft = self.network.global_nfts.get(obj_id)
            if not nft:
                QMessageBox.warning(self, "Error", "NFT not found.")
                return
            dlg = QDialog(self)
            dlg.setWindowTitle(f"NFT: {nft.get('name', '')} (Global)")
            layout = QVBoxLayout(dlg)
            if nft.get('img_b64'):
                img_data = base64.b64decode(nft['img_b64'])
                pixmap = QPixmap()
                pixmap.loadFromData(img_data)
                lbl = QLabel()
                lbl.setPixmap(pixmap.scaled(256,256,Qt.KeepAspectRatio))
                layout.addWidget(lbl)
            layout.addWidget(QLabel(f"Owner: {nft.get('owner','')}"))
            layout.addWidget(QLabel(f"Timestamp: {nft.get('timestamp','')}"))
            layout.addWidget(QLabel(f"Description: {nft.get('desc','')}"))
            dlg.setLayout(layout)
            dlg.exec_()

# --- FTWFaucet Contract ---
class FTWFaucet:
    """
    VoidChain FTW Faucet Contract
    - Users can claim 0.05 FTW every 24 hours by calling drip(address)
    - info() returns instructions
    """
    def __init__(self):
        self.last_claims = {}  # {address: timestamp}
    def info(self):
        return "This is the official FTW Faucet. Call drip(your_ftw_address) to claim 0.05 FTW every 24h."
    def drip(self, address):
        now = int(time.time())
        last = self.last_claims.get(address, 0)
        if now - last < 86400:
            return f"You must wait {int((86400 - (now - last))/3600)}h before claiming again."
        self.last_claims[address] = now
        return {"action": "send_ftw", "to": address, "amount": 0.05, "msg": "Faucet claim successful!"}

# --- Contract Action Handler ---
def handle_contract_action(wallet, action_dict, live_tab=None):
    """
    Handles contract actions that affect wallet state, such as FTW payouts, NFT minting, VOID transfers, burning, and staking boosts.
    Supports batch actions (list of actions).
    """
    # Batch: if action_dict is a list, process each
    if isinstance(action_dict, list):
        for act in action_dict:
            handle_contract_action(wallet, act, live_tab)
        return
    action = action_dict.get("action")
    # FTW payout
    if action == "send_ftw":
        amt = float(action_dict.get("amount", 0))
        to = action_dict.get("to")
        if to == wallet.get("fa"):
            wallet["ftw"] = wallet.get("ftw", 0.0) + amt
            wallet.setdefault("tx", []).append({
                "ff": action_dict.get("from", "faucet"),
                "tf": to,
                "fa": amt,
                "t": str(datetime.now(timezone.utc)),
                "note": action_dict.get("msg", "FTW payout")
            })
            sw(wallet, wallet.get("password", ""), wallet.get("mnemonic", ""))
            if live_tab:
                live_tab.add_event(f"[FTW] {amt} FTW sent to {to[:8]}... at {datetime.now(timezone.utc)}")
    # VOID payout
    elif action == "send_void":
        amt = float(action_dict.get("amount", 0))
        to = action_dict.get("to")
        if to == wallet.get("va"):
            wallet["b"] = wallet.get("b", 0.0) + amt
            wallet.setdefault("tx", []).append({
                "fr": action_dict.get("from", "contract"),
                "to": to,
                "a": amt,
                "t": str(datetime.now(timezone.utc)),
                "note": action_dict.get("msg", "VOID payout")
            })
            sw(wallet, wallet.get("password", ""), wallet.get("mnemonic", ""))
            if live_tab:
                live_tab.add_event(f"[VOID] {amt} VOID sent to {to[:8]}... at {datetime.now(timezone.utc)}")
    # NFT minting (advanced: add to contracts[0]['nfts'] and wallet['nfts'])
    elif action == "mint_nft":
        nft = action_dict.get("nft")
        to = action_dict.get("to")
        if to == wallet.get("fa"):
            # Add to wallet['nfts'] (for legacy support)
            wallet.setdefault("nfts", []).append(nft)
            # Add to contracts[0]['nfts'] for on-chain visibility
            if 'contracts' not in wallet or not wallet['contracts']:
                dummy = {
                    'id': str(uuid.uuid4()),
                    'name': 'NFT Dummy',
                    'owner': wallet['fa'],
                    'timestamp': str(datetime.now(timezone.utc)),
                    'type': 'contract',
                    'code': '',
                    'nfts': [],
                }
                wallet.setdefault('contracts', []).append(dummy)
            wallet['contracts'][0].setdefault('nfts', []).append(nft)
            # Deduct FTW for minting if specified
            if action_dict.get('deduct_ftw', True):
                wallet['ftw'] = wallet.get('ftw', 0.0) - 0.00001
            sw(wallet, wallet.get("password", ""), wallet.get("mnemonic", ""))
            if live_tab:
                live_tab.add_event(f"[NFT] {nft.get('name', nft.get('id', ''))} minted for {to[:8]} at {datetime.now(timezone.utc)}")
    # NFT transfer (remove from one wallet, add to another)
    elif action == "transfer_nft":
        nft_id = action_dict.get("nft_id")
        to = action_dict.get("to")
        # Remove from wallet's contracts
        found = False
        for c in wallet.get('contracts', []):
            nfts = c.get('nfts', [])
            for nft in nfts:
                if nft.get('id') == nft_id and nft.get('owner') == wallet.get('fa'):
                    nft['owner'] = to
                    found = True
                    break
            if found:
                break
        if found:
            sw(wallet, wallet.get("password", ""), wallet.get("mnemonic", ""))
            if live_tab:
                live_tab.add_event(f"[NFT] {nft_id} transferred to {to[:8]} at {datetime.now(timezone.utc)}")
    # FTW burning
    elif action == "burn_ftw":
        amt = float(action_dict.get("amount", 0))
        if wallet.get("ftw", 0.0) >= amt:
            wallet["ftw"] -= amt
            wallet.setdefault("tx", []).append({
                "ff": wallet.get("fa"),
                "tf": "burn",
                "fa": amt,
                "t": str(datetime.now(timezone.utc)),
                "note": action_dict.get("msg", "FTW burned")
            })
            sw(wallet, wallet.get("password", ""), wallet.get("mnemonic", ""))
            if live_tab:
                live_tab.add_event(f"[BURN] {amt} FTW burned at {datetime.now(timezone.utc)}")
    # Staking boost (for special NFT holders)
    elif action == "boost_staking":
        wallet["staking_boost"] = True
        sw(wallet, wallet.get("password", ""), wallet.get("mnemonic", ""))
        if live_tab:
            live_tab.add_event(f"[BOOST] Staking boost unlocked at {datetime.now(timezone.utc)}")
    # Custom token minting (for SimpleToken, etc.)
    elif action == "mint_token":
        token = action_dict.get("token", "custom")
        amt = float(action_dict.get("amount", 0))
        to = action_dict.get("to")
        if to == wallet.get("fa"):
            wallet.setdefault("tokens", {}).setdefault(token, 0.0)
            wallet["tokens"][token] += amt
            sw(wallet, wallet.get("password", ""), wallet.get("mnemonic", ""))
            if live_tab:
                live_tab.add_event(f"[TOKEN] {amt} {token} minted for {to[:8]}")
    # Custom token transfer
    elif action == "transfer_token":
        token = action_dict.get("token", "custom")
        amt = float(action_dict.get("amount", 0))
        to = action_dict.get("to")
        if wallet.setdefault("tokens", {}).get(token, 0.0) >= amt:
            wallet["tokens"][token] -= amt
            # No recipient wallet update here (handled on their side)
            sw(wallet, wallet.get("password", ""), wallet.get("mnemonic", ""))
            if live_tab:
                live_tab.add_event(f"[TOKEN] {amt} {token} sent to {to[:8]}")
    # Add more action types as needed
    # Example: lottery payout, batch NFT mint, NFT burn, etc.
    elif action == "mint_nfts":
        # Batch NFT minting (list of NFTs)
        nfts = action_dict.get("nfts", [])
        to = action_dict.get("to")
        if to == wallet.get("fa"):
            wallet.setdefault("nfts", []).extend(nfts)
            if 'contracts' not in wallet or not wallet['contracts']:
                dummy = {
                    'id': str(uuid.uuid4()),
                    'name': 'NFT Dummy',
                    'owner': wallet['fa'],
                    'timestamp': str(datetime.now(timezone.utc)),
                    'type': 'contract',
                    'code': '',
                    'nfts': [],
                }
                wallet.setdefault('contracts', []).append(dummy)
            wallet['contracts'][0].setdefault('nfts', []).extend(nfts)
            if action_dict.get('deduct_ftw', True):
                wallet['ftw'] = wallet.get('ftw', 0.0) - 0.00001 * len(nfts)
            sw(wallet, wallet.get("password", ""), wallet.get("mnemonic", ""))
            if live_tab:
                live_tab.add_event(f"[NFT] {len(nfts)} NFTs minted for {to[:8]} at {datetime.now(timezone.utc)}")
    elif action == "burn_nft":
        nft_id = action_dict.get("nft_id")
        found = False
        for c in wallet.get('contracts', []):
            nfts = c.get('nfts', [])
            for nft in nfts:
                if nft.get('id') == nft_id and nft.get('owner') == wallet.get('fa'):
                    nfts.remove(nft)
                    found = True
                    break
            if found:
                break
        if found:
            sw(wallet, wallet.get("password", ""), wallet.get("mnemonic", ""))
            if live_tab:
                live_tab.add_event(f"[NFT] {nft_id} burned at {datetime.now(timezone.utc)}")
    elif action == "lottery_payout":
        # Example: lottery payout to a list of winners
        winners = action_dict.get("winners", [])
        amount = float(action_dict.get("amount", 0))
        for winner in winners:
            if winner == wallet.get("fa"):
                wallet["ftw"] = wallet.get("ftw", 0.0) + amount
                wallet.setdefault("tx", []).append({
                    "ff": action_dict.get("from", "lottery"),
                    "tf": winner,
                    "fa": amount,
                    "t": str(datetime.now(timezone.utc)),
                    "note": action_dict.get("msg", "Lottery payout")
                })
                sw(wallet, wallet.get("password", ""), wallet.get("mnemonic", ""))
                if live_tab:
                    live_tab.add_event(f"[LOTTERY] {amount} FTW won by {winner[:8]} at {datetime.now(timezone.utc)}")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    win = VW()
    win.show()
    sys.exit(app.exec_())
