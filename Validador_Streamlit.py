# Validador_Streamlit.py
# =========================
# Validador de Etiquetas - Streamlit + SQLite
# UI FedEx + CRUD usuários + Export CSV + Suporte a Bipador (Modo Scan 2 bipagens)
# Versão para Cloud (Git/Streamlit/ngrok): DB em ./data/dados_label.db
# =========================
import sys
import os
import re
from pathlib import Path
from datetime import datetime, date
import sqlite3
import csv
import io
import secrets
import hashlib
import base64

import streamlit as st
from streamlit.components.v1 import html

# ===== CONFIG INICIAL =====
st.set_page_config(page_title="Validador de Etiquetas", page_icon="📦", layout="wide")

# ====== CSS ======
CUSTOM_CSS = """
<style>
[data-testid="stAppViewContainer"] > .main { background: linear-gradient(180deg, #ffffff 0%, #f7f7fb 70%); }
.header-box { background:#fff; border:1px solid #ececf1; box-shadow:0 6px 16px rgba(0,0,0,0.04); border-radius:18px; padding:14px 18px; margin-bottom:16px; }
.header-title { font-size:24px; font-weight:700; margin:4px 0 0 0; }
.header-sub { color:#666; margin-top:2px; }
.card { background:#fff; border:1px solid #ececf1; box-shadow:0 6px 16px rgba(0,0,0,0.06); border-radius:16px; padding:18px 18px; margin-top:10px; }
.stButton > button[kind="primary"]{ background:#4D148C; border-color:#4D148C; color:#fff; border-radius:12px; padding:0.6rem 1rem; font-weight:600; }
.stButton > button[kind="primary"]:hover{ background:#3B0F6A; border-color:#3B0F6A; }
input, textarea, select { border-radius:10px !important; }
.user-row { padding:10px; border:1px solid #efefef; border-radius:12px; background:#fff; margin-bottom:10px; }
.sidebar-top { font-weight:700; margin-top:4px; margin-bottom:10px; }
</style>
"""
st.markdown(CUSTOM_CSS, unsafe_allow_html=True)

# ========= RECURSOS / CAMINHOS =========
def resource_path(rel_path: str) -> str:
    if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
        base = sys._MEIPASS  # type: ignore[attr-defined]
    else:
        base = os.path.dirname(__file__)
    return os.path.join(base, rel_path)

# — Cloud: DB sempre em ./data
DATA_DIR = Path(__file__).parent / "data"
DATA_DIR.mkdir(parents=True, exist_ok=True)
DB_PATH = DATA_DIR / "dados_label.db"

LOGO_PATH = Path(resource_path("LogoFedex.png"))
NOK_SOUND = Path(resource_path("nok.wav"))

# diagnóstico útil
st.caption(f"📄 Banco de dados: `{DB_PATH}`")
if not os.access(DATA_DIR, os.W_OK):
    st.error(f"❌ Sem permissão de escrita na pasta: {DATA_DIR}")
if DB_PATH.exists() and not os.access(DB_PATH, os.W_OK):
    st.error(f"❌ Sem permissão de escrita no arquivo .db: {DB_PATH}")

# ===== PARÂMETROS =====
FLUSH_INTERVAL = 400
CODE_LEN = 10
MIN_CODE_LEN = 10

# ====== Senhas (hash + salt) ======
def make_hash(password: str, salt_hex: str | None = None) -> tuple[str, str]:
    if not salt_hex:
        salt_hex = secrets.token_hex(16)
    digest = hashlib.sha256(bytes.fromhex(salt_hex) + password.encode("utf-8")).hexdigest()
    return salt_hex, digest

def verify_password(password: str, salt_hex: str, hash_hex: str) -> bool:
    return make_hash(password, salt_hex)[1] == hash_hex

# ====== Banco de Dados ======
class DatabaseManager:
    def __init__(self, db_path: Path, flush_interval: int = FLUSH_INTERVAL):
        self.db_path = Path(db_path)
        self.flush_interval = flush_interval
        self.counter = 0
        self._connect()

    def _connect(self):
        self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self.conn.execute("PRAGMA journal_mode=WAL;")
        self.conn.execute("PRAGMA synchronous=NORMAL;")
        self.conn.execute("PRAGMA busy_timeout=3000;")

        # Criação inicial (se não existir)
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS registros (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                data_hora TEXT NOT NULL,
                usuario TEXT NOT NULL,
                tipo_tela TEXT NOT NULL,
                transporte TEXT NOT NULL,
                pedido TEXT NOT NULL,
                divergencia INTEGER NOT NULL,
                supervisor_liberou TEXT,
                motivo_divergencia TEXT
            );
        """)
        self.conn.execute("CREATE INDEX IF NOT EXISTS idx_tp_tppd ON registros(tipo_tela, transporte, pedido);")

        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS usuarios (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                uid TEXT NOT NULL UNIQUE,
                nome TEXT,
                role TEXT NOT NULL CHECK(role IN ('user','supervisor','admin')),
                salt_hex TEXT NOT NULL,
                hash_hex TEXT NOT NULL,
                ativo INTEGER NOT NULL DEFAULT 1,
                criado_em TEXT NOT NULL
            );
        """)

        # 🔧 MIGRAÇÃO DE SCHEMA
        self._ensure_schema()
        self.conn.commit()

    def _ensure_schema(self):
        """Garante que as tabelas tenham as colunas esperadas; cria colunas que faltarem."""
        # registros
        cur = self.conn.execute("PRAGMA table_info(registros);")
        cols = {r[1] for r in cur.fetchall()}  # nomes

        if "divergencia" not in cols:
            self.conn.execute("ALTER TABLE registros ADD COLUMN divergencia INTEGER NOT NULL DEFAULT 0;")
        if "supervisor_liberou" not in cols:
            self.conn.execute("ALTER TABLE registros ADD COLUMN supervisor_liberou TEXT DEFAULT '';")
        if "motivo_divergencia" not in cols:
            self.conn.execute("ALTER TABLE registros ADD COLUMN motivo_divergencia TEXT DEFAULT '';")

        self.conn.execute("CREATE INDEX IF NOT EXISTS idx_tp_tppd ON registros(tipo_tela, transporte, pedido);")

        # usuarios
        cur = self.conn.execute("PRAGMA table_info(usuarios);")
        ucols = {r[1] for r in cur.fetchall()}
        required = {"uid", "role", "salt_hex", "hash_hex", "ativo", "criado_em"}
        if not required.issubset(ucols):
            st.warning("⚠️ Schema inesperado em 'usuarios'. Verifique o DB existente.")

    # usuários
    def existe_admin(self) -> bool:
        cur = self.conn.execute("SELECT 1 FROM usuarios WHERE role='admin' AND ativo=1 LIMIT 1;")
        return cur.fetchone() is not None

    def criar_usuario(self, uid: str, nome: str, role: str, senha: str, ativo: int = 1):
        salt, h = make_hash(senha)
        self.conn.execute("""
            INSERT INTO usuarios(uid, nome, role, salt_hex, hash_hex, ativo, criado_em)
            VALUES (?,?,?,?,?,?,?)
        """, (uid.strip(), (nome or uid).strip(), role, salt, h, int(ativo),
              datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
        self.conn.commit()

    def atualizar_usuario(self, user_id: int, nome: str, role: str, ativo: int):
        self.conn.execute("""
            UPDATE usuarios SET nome=?, role=?, ativo=? WHERE id=?
        """, ((nome or "").strip(), role, int(ativo), user_id))
        self.conn.commit()

    def resetar_senha(self, user_id: int, nova_senha: str):
        salt, h = make_hash(nova_senha)
        self.conn.execute("""
            UPDATE usuarios SET salt_hex=?, hash_hex=? WHERE id=?
        """, (salt, h, user_id))
        self.conn.commit()

    def remover_usuario(self, user_id: int):
        self.conn.execute("DELETE FROM usuarios WHERE id=?", (user_id,))
        self.conn.commit()

    def autenticar(self, uid: str, senha: str):
        cur = self.conn.execute("""
            SELECT id, uid, nome, role, salt_hex, hash_hex, ativo FROM usuarios WHERE uid=?
        """, (uid.strip(),))
        row = cur.fetchone()
        if not row:
            return None
        user = dict(zip(["id","uid","nome","role","salt_hex","hash_hex","ativo"], row))
        if not user["ativo"]:
            return None
        if verify_password(senha, user["salt_hex"], user["hash_hex"]):
            return {k: user[k] for k in ("id","uid","nome","role","ativo")}
        return None

    # registros
    def append_row(self, row: dict):
        try:
            self.conn.execute("""
                INSERT INTO registros
                (data_hora, usuario, tipo_tela, transporte, pedido, divergencia, supervisor_liberou, motivo_divergencia)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                row["data_hora"],
                row["usuario"],
                row["tipo_tela"],
                row["transporte"][:10],
                row["pedido"][:10],
                1 if row.get("divergencia") else 0,
                row.get("supervisor_liberou", "") or "",
                row.get("motivo_divergencia", "") or ""
            ))
            self.counter += 1
            if self.counter >= self.flush_interval:
                self.save()
                self.counter = 0
        except sqlite3.Error as e:
            import traceback
            st.error(f"Erro ao inserir na tabela 'registros': {e}")
            st.caption("Dica: era um DB antigo? A migração '_ensure_schema' já tenta corrigir; se persistir, considere apagar ./data/dados_label.db.")
            st.text("Traceback:\n" + traceback.format_exc())
            st.stop()

    def save(self):
        self.conn.commit()

    def close(self):
        self.conn.commit()
        self.conn.close()

    def existe_registro(self, transporte: str, pedido: str, tipo_tela: str) -> bool:
        cur = self.conn.execute("""
            SELECT 1 FROM registros
            WHERE tipo_tela = ? AND transporte = ? AND pedido = ?
            LIMIT 1
        """, (tipo_tela, transporte[:10], pedido[:10]))
        return cur.fetchone() is not None

    def query_export(self, dt_ini: date, dt_fim: date, tipo_tela: str|None, apenas_div: bool):
        start = f"{dt_ini.strftime('%Y-%m-%d')} 00:00:00"
        end   = f"{dt_fim.strftime('%Y-%m-%d')} 23:59:59"
        base = """
            SELECT data_hora, usuario, tipo_tela, transporte, pedido,
                   divergencia, supervisor_liberou, motivo_divergencia
              FROM registros
             WHERE data_hora BETWEEN ? AND ?
        """
        params = [start, end]
        if tipo_tela and tipo_tela != "TODAS":
            base += " AND tipo_tela = ?"
            params.append(tipo_tela)
        if apenas_div:
            base += " AND divergencia = 1"
        base += " ORDER BY data_hora ASC"
        cur = self.conn.execute(base, tuple(params))
        cols = [d[0] for d in cur.description]
        rows = cur.fetchall()
        return cols, rows

# --------- estado global ---------
if "db" not in st.session_state:
    st.session_state.db = DatabaseManager(DB_PATH)

st.session_state.setdefault("user", None)          # dict: id, uid, nome, role, ativo
st.session_state.setdefault("page", "login")       # login | leitura | varios | exportar | cadastros
st.session_state.setdefault("ult_leitura", "-")
st.session_state.setdefault("volumes", [])
st.session_state.setdefault("vol_count", 0)

# ====== Helpers: bipador ======
def sanitize_code(code: str, max_len: int = 10) -> str:
    code = re.sub(r'[^0-9A-Za-z]', '', code or '')
    return code[:max_len]

def focus_input_by_label(label_text: str):
    html(f"""
    <script>
    const inputs = parent.document.querySelectorAll('input');
    const el = Array.from(inputs).find(x => (x.getAttribute('aria-label')||'').includes("{label_text}"));
    if (el) {{ el.focus(); el.select(); }}
    </script>
    """, height=0)

def _sound_data_url(path: Path) -> str | None:
    if not path or not path.exists(): return None
    mime = "audio/wav" if path.suffix.lower() == ".wav" else "audio/mpeg"
    b64 = base64.b64encode(path.read_bytes()).decode("ascii")
    return f"data:{mime};base64,{b64}"

# cache som (se existir)
if "SND_NOK" not in st.session_state:
    st.session_state["SND_NOK"] = _sound_data_url(NOK_SOUND)

def play_sound(data_url_key: str):
    data_url = st.session_state.get(data_url_key)
    if not data_url: return
    html(f'<audio autoplay style="display:none"><source src="{data_url}"></audio>', height=0)

# ====== Registro ======
def registrar_dado(usuario: str, tela_origem: str, transporte: str, pedido: str,
                   divergencia: bool = False, supervisor_liberou: str = "", motivo_divergencia: str = ""):
    row = {
        "data_hora": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "usuario": usuario,
        "tipo_tela": tela_origem,
        "transporte": transporte[:10],
        "pedido": pedido[:10],
        "divergencia": divergencia,
        "supervisor_liberou": supervisor_liberou,
        "motivo_divergencia": motivo_divergencia
    }
    st.session_state.db.append_row(row)

def verificar_registro_existente(transporte: str, pedido: str, tipo_tela: str = "LEITURA") -> bool:
    return st.session_state.db.existe_registro(transporte, pedido, tipo_tela)

# ====== Gate inicial: primeiro admin ======
def setup_admin_gate():
    if st.session_state.db.existe_admin():
        return False
    st.info("👋 Bem-vindo! Antes de começar, crie o **primeiro administrador**.")
    with st.container():
        with st.form("criar_admin", clear_on_submit=False):
            uid = st.text_input("Login (uid) do Admin *")
            nome = st.text_input("Nome (opcional)")
            senha1 = st.text_input("Senha *", type="password")
            senha2 = st.text_input("Confirmar senha *", type="password")
            if st.form_submit_button("Criar Admin", use_container_width=True):
                if not uid or not senha1:
                    st.error("Informe login e senha.")
                elif senha1 != senha2:
                    st.error("As senhas não conferem.")
                else:
                    try:
                        st.session_state.db.criar_usuario(uid, nome or uid, "admin", senha1, ativo=1)
                        st.success("Administrador criado. Faça login.")
                        st.rerun()
                    except sqlite3.IntegrityError:
                        st.error("Login já existe.")
    return True

# ====== Divergência (dialog) ======
@st.dialog("⚠️ Etiqueta Divergente")
def dialog_divergencia(transporte: str, pedido: str, origem: str):
    play_sound("SND_NOK")
    st.markdown(f"**Transporte:** `{transporte}`  |  **Pedido:** `{pedido}`")
    sid = st.text_input("Login Supervisor/Admin")
    spw = st.text_input("Senha", type="password")
    motivo = st.text_input("Motivo da Divergência")

    colA, colB = st.columns(2)
    with colA:
        cancelar = st.button("Cancelar", type="secondary")
    with colB:
        concluir = st.button("Validar e Concluir", type="primary")

    if cancelar:
        st.rerun()

    if concluir:
        auth = st.session_state.db.autenticar(sid, spw)
        if auth and auth["role"] in ("supervisor", "admin"):
            if not motivo.strip():
                st.warning("Informe o motivo da divergência.")
                st.stop()
            registrar_dado(
                usuario=st.session_state.user["uid"],
                tela_origem=origem,
                transporte=transporte,
                pedido=pedido,
                divergencia=True,
                supervisor_liberou=sid,
                motivo_divergencia=motivo.strip()
            )
            if origem == "VARIOS":
                st.session_state.vol_count += 1
                st.session_state.volumes.append({
                    "n": st.session_state.vol_count,
                    "transporte": transporte,
                    "pedido": pedido,
                    "divergente": True
                })
            st.success("Divergência liberada com sucesso!")
            st.rerun()
        else:
            st.error("Credenciais inválidas ou papel insuficiente (precisa ser supervisor/admin).")

# ====== HEADER ======
def render_header():
    with st.container():
        col_logo, col_title = st.columns([1, 5])
        with col_logo:
            if Path(LOGO_PATH).exists():
                st.image(str(LOGO_PATH), width=140)
        with col_title:
            st.markdown('<div class="header-box">', unsafe_allow_html=True)
            st.markdown('<div class="header-title">Validador de Etiquetas</div>', unsafe_allow_html=True)
            st.markdown('<div class="header-sub">FedEx • Expedição Vivo Telefônica — Registro de Leituras e Divergências</div>', unsafe_allow_html=True)
            st.markdown('</div>', unsafe_allow_html=True)

# ====== TELAS ======
def form_leitura(scan_mode: bool):
    t_key, p_key = "scan_t", "scan_p"
    with st.form("form_leitura", clear_on_submit=False):
        c1, c2, c3 = st.columns([1,1,1])
        with c1:
            st.text_input("Transporte (máx 10)", key=t_key, max_chars=CODE_LEN, placeholder="Bipe Transporte")
        with c2:
            st.text_input("Pedido (máx 10)", key=p_key, max_chars=CODE_LEN, placeholder="Bipe Pedido")
        with c3:
            st.write("")
            submit = st.form_submit_button("Registrar", use_container_width=True)

    trans = (st.session_state.get(t_key, "") or "").strip()
    ped   = (st.session_state.get(p_key, "") or "").strip()

    if scan_mode:
        t_san = sanitize_code(trans, MIN_CODE_LEN)
        p_san = sanitize_code(ped,   MIN_CODE_LEN)
        if not t_san:
            focus_input_by_label("Transporte (máx 10)")
        elif len(t_san) >= MIN_CODE_LEN and not p_san:
            focus_input_by_label("Pedido (máx 10)")
        else:
            focus_input_by_label("Pedido (máx 10)")
    else:
        focus_input_by_label("Transporte (máx 10)")

    return submit, trans, ped

def tela_leitura(scan_mode: bool):
    render_header()
    st.markdown("#### 📥 Leitura (Simples)")
    st.caption("No Modo Scan, bipar **Transporte** e depois **Pedido**. Se T ≠ P ou duplicado, exige liberação.")
    st.markdown('<div class="card">', unsafe_allow_html=True)

    submit, t_raw, p_raw = form_leitura(scan_mode)

    colA, colB, colC = st.columns([2,1,1])
    with colA:
        st.markdown(f"**Última leitura:** {st.session_state.ult_leitura}")
    with colB:
        if st.button("Vários Volumes", use_container_width=True):
            st.session_state.page = "varios"; st.rerun()
    with colC:
        if st.button("Exportar CSV", use_container_width=True):
            st.session_state.page = "exportar"; st.rerun()

    st.markdown('</div>', unsafe_allow_html=True)

    if submit:
        t = sanitize_code(t_raw, CODE_LEN)
        p = sanitize_code(p_raw, CODE_LEN)

        if not t and not p:
            focus_input_by_label("Transporte (máx 10)"); return
        if t and not p:
            focus_input_by_label("Pedido (máx 10)"); return
        if not t and p:
            focus_input_by_label("Transporte (máx 10)"); return

        if t != p or verificar_registro_existente(t, p, "LEITURA"):
            play_sound("SND_NOK")
            dialog_divergencia(t, p, "LEITURA")
            return

        # OK → grava e limpa (reset explícito + rerun)
        registrar_dado(st.session_state.user["uid"], "LEITURA", t, p)
        st.session_state.ult_leitura = f"T:{t}  P:{p}"
        st.success(f"Registrado com sucesso: T:{t} P:{p}")

        st.session_state["scan_t"] = ""
        st.session_state["scan_p"] = ""
        st.rerun()

def form_varios():
    with st.form("form_varios", clear_on_submit=False):
        c1, c2, c3 = st.columns([1,1,1])
        with c1:
            trans = st.text_input("Transporte (máx 10)", key="varios_t", max_chars=CODE_LEN, placeholder="Bipe Transporte")
        with c2:
            ped = st.text_input("Pedido (máx 10)", key="varios_p", max_chars=CODE_LEN, placeholder="Bipe Pedido")
        with c3:
            st.write("")
            submit = st.form_submit_button("Adicionar/Registrar", use_container_width=True)
    return submit, trans.strip(), ped.strip()

def tela_varios():
    render_header()
    st.markdown("#### 📦 Leitura (Vários Volumes)")
    st.caption("Exige supervisor/admin somente quando T ≠ P. T = P registra direto e adiciona à lista.")
    st.markdown('<div class="card">', unsafe_allow_html=True)

    submit, t, p = form_varios()

    box = st.container()
    with box:
        if len(st.session_state.volumes) == 0:
            st.info("Nenhum volume registrado ainda.")
        else:
            for item in st.session_state.volumes[-200:]:
                tag = " [DIVERGENTE]" if item.get("divergente") else ""
                style = ":red[" if item.get("divergente") else ""
                close = "]" if item.get("divergente") else ""
                st.markdown(f"{style}{item['n']} - T:{item['transporte']}  P:{item['pedido']}{tag}{close}")

    col1, col2, col3 = st.columns([1,1,1])
    with col1:
        if st.button("Leitura Simples", use_container_width=True):
            st.session_state.page = "leitura"; st.rerun()
    with col2:
        if st.button("Zerar Lista (UI)", use_container_width=True, type="secondary"):
            st.session_state.volumes = []; st.session_state.vol_count = 0; st.rerun()
    with col3:
        if st.button("Exportar CSV", use_container_width=True):
            st.session_state.page = "exportar"; st.rerun()

    st.markdown('</div>', unsafe_allow_html=True)

    if submit:
        t = sanitize_code(t, 10)
        p = sanitize_code(p, 10)
        if not t or not p:
            st.warning("Leitura inválida."); focus_input_by_label("Transporte (máx 10)"); return
        if t != p:
            play_sound("SND_NOK")
            dialog_divergencia(t, p, "VARIOS"); return

        registrar_dado(st.session_state.user["uid"], "VARIOS", t, p)
        st.session_state.vol_count += 1
        st.session_state.volumes.append({"n": st.session_state.vol_count, "transporte": t, "pedido": p, "divergente": False})
        st.success(f"Registrado com sucesso: T:{t} P:{p}")

        # limpar e reiniciar para próximos bipes
        st.session_state["varios_t"] = ""
        st.session_state["varios_p"] = ""
        st.rerun()

    focus_input_by_label("Transporte (máx 10)")

# ---------- EXPORTAÇÃO CSV ----------
def tela_exportar():
    render_header()
    st.markdown("#### 📤 Exportar leituras para CSV")
    st.markdown('<div class="card">', unsafe_allow_html=True)

    col1, col2, col3, col4 = st.columns([1,1,1,1])
    today = date.today()
    with col1:
        dt_ini = st.date_input("Data inicial", value=today.replace(day=1))
    with col2:
        dt_fim = st.date_input("Data final", value=today)
    with col3:
        tipo = st.selectbox("Tipo de Tela", ["TODAS", "LEITURA", "VARIOS"])
    with col4:
        apenas_div = st.checkbox("Apenas divergências", value=False)

    cols, rows = st.session_state.db.query_export(dt_ini, dt_fim, tipo, apenas_div)
    st.write(f"Registros encontrados: **{len(rows)}**")

    if rows:
        buffer = io.StringIO()
        writer = csv.writer(buffer, lineterminator="\n")
        writer.writerow(cols)
        writer.writerows(rows)
        csv_bytes = buffer.getvalue().encode("utf-8-sig")

        fname = f"leituras_{dt_ini.strftime('%Y%m%d')}_{dt_fim.strftime('%Y%m%d')}"
        if tipo != "TODAS": fname += f"_{tipo.lower()}"
        if apenas_div: fname += "_divergencias"
        fname += ".csv"

        st.download_button("⬇️ Baixar CSV", data=csv_bytes, file_name=fname, mime="text/csv", use_container_width=True)

    st.markdown('</div>', unsafe_allow_html=True)

# ---------- CADASTROS (apenas admin) ----------
def tela_cadastros():
    render_header()
    st.markdown("#### 👥 Cadastros de Usuários / Supervisores / Admin")
    if not (st.session_state.user and st.session_state.user["role"] == "admin"):
        st.error("Acesso restrito a administradores."); return

    st.markdown('<div class="card">', unsafe_allow_html=True)
    st.markdown("**➕ Novo usuário**")
    with st.form("novo_user"):
        c1, c2, c3, c4 = st.columns([1,1,1,1])
        with c1: uid = st.text_input("Login (uid) *")
        with c2: nome = st.text_input("Nome")
        with c3: role = st.selectbox("Papel *", ["user","supervisor","admin"])
        with c4: ativo = st.checkbox("Ativo", value=True)
        c5, c6, _ = st.columns([1,1,2])
        with c5: senha1 = st.text_input("Senha *", type="password")
        with c6: senha2 = st.text_input("Confirmar senha *", type="password")
        ok = st.form_submit_button("Salvar cadastro", use_container_width=True)
    if ok:
        if not uid or not senha1:
            st.error("Preencha login e senha.")
        elif senha1 != senha2:
            st.error("As senhas não conferem.")
        else:
            try:
                st.session_state.db.criar_usuario(uid, nome or uid, role, senha1, ativo=int(ativo))
                st.success("Usuário criado!")
            except sqlite3.IntegrityError:
                st.error("Login já existe.")
    st.markdown('</div>', unsafe_allow_html=True)

    st.markdown('<div class="card">', unsafe_allow_html=True)
    busca = st.text_input("🔎 Buscar por login/nome", placeholder="ex.: gabriel, supervisor, etc.")
    cols, rows = st.session_state.db.listar_usuarios(busca)

    if not rows:
        st.info("Nenhum usuário encontrado.")
    else:
        for rec in rows:
            rec = dict(zip(cols, rec))
            with st.container():
                st.markdown(f"""
                <div class="user-row">
                    <b>Login:</b> {rec['uid']} &nbsp;|&nbsp;
                    <b>Nome:</b> {rec['nome'] or '-'} &nbsp;|&nbsp;
                    <b>Papel:</b> {rec['role']} &nbsp;|&nbsp;
                    <b>Ativo:</b> {"✅" if rec['ativo'] else "❌"} &nbsp;|&nbsp;
                    <b>Criado em:</b> {rec['criado_em']}
                </div>
                """, unsafe_allow_html=True)
                with st.popover("Ações", use_container_width=True):
                    novo_nome = st.text_input("Nome", value=rec["nome"] or "", key=f"nome_{rec['id']}")
                    novo_role = st.selectbox("Papel", ["user","supervisor","admin"],
                                             index=["user","supervisor","admin"].index(rec["role"]),
                                             key=f"role_{rec['id']}")
                    novo_ativo = st.checkbox("Ativo", value=bool(rec["ativo"]), key=f"ativo_{rec['id']}")
                    cols_btn = st.columns(3)
                    if cols_btn[0].button("Salvar alterações", key=f"salvar_{rec['id']}", type="primary"):
                        st.session_state.db.atualizar_usuario(rec["id"], novo_nome, novo_role, int(novo_ativo))
                        st.success("Alterações salvas."); st.rerun()
                    nova_senha1 = cols_btn[1].text_input("Nova senha", type="password", key=f"ns1_{rec['id']}")
                    nova_senha2 = cols_btn[2].text_input("Confirmar", type="password", key=f"ns2_{rec['id']}")
                    c2 = st.columns(2)
                    if c2[0].button("Resetar senha", key=f"reset_{rec['id']}", type="secondary"):
                        if nova_senha1 and nova_senha1 == nova_senha2:
                            st.session_state.db.resetar_senha(rec["id"], nova_senha1)
                            st.success("Senha redefinida."); st.rerun()
                        else:
                            st.error("Preencha e confirme a nova senha corretamente.")
                    if c2[1].button("Remover usuário", key=f"del_{rec['id']}", type="secondary"):
                        st.session_state.db.remover_usuario(rec["id"])
                        st.success("Usuário removido."); st.rerun()
    st.markdown('</div>', unsafe_allow_html=True)

def tela_login():
    render_header()
    if setup_admin_gate():
        return

    st.markdown("### 🔐 Login")
    with st.form("login_form"):
        c1, c2 = st.columns([1,1])
        with c1:
            uid = st.text_input("Login (uid)")
        with c2:
            pwd = st.text_input("Senha", type="password")
        ok = st.form_submit_button("Entrar", use_container_width=True)

    if ok:
        auth = st.session_state.db.autenticar(uid, pwd)
        if auth:
            st.session_state.user = auth
            st.success(f"Bem-vindo, {auth['uid']}!")
            st.session_state.page = "leitura"
            st.rerun()
        else:
            st.error("Login ou senha inválidos, ou usuário inativo.")

# ====== SIDEBAR ======
def sidebar_nav():
    with st.sidebar:
        if Path(LOGO_PATH).exists():
            st.image(str(LOGO_PATH), width=140)
        st.markdown('<div class="sidebar-top">FedEx • Validador</div>', unsafe_allow_html=True)

        st.session_state["scan_mode"] = st.toggle(
            "Modo Scan (2 bipagens: Transporte e Pedido)",
            value=st.session_state.get("scan_mode", True)
        )
        st.caption("No Modo Scan, bipar T e depois P; Enter no P envia.")

        if st.session_state.user:
            st.success(f"👤 {st.session_state.user['uid']} ({st.session_state.user['role']})")
            options = ["Leitura", "Vários Volumes", "Exportar CSV"]
            if st.session_state.user["role"] == "admin":
                options.append("Cadastros")
            sel = st.radio(
                "Navegação", options,
                index=options.index(
                    "Cadastros" if st.session_state.page=="cadastros" else
                    "Exportar CSV" if st.session_state.page=="exportar" else
                    "Vários Volumes" if st.session_state.page=="varios" else
                    "Leitura"
                ),
                label_visibility="collapsed"
            )

            st.session_state.page = (
                "leitura" if sel=="Leitura" else
                "varios" if sel=="Vários Volumes" else
                "exportar" if sel=="Exportar CSV" else
                "cadastros"
            )

            st.divider()
            if st.button("Sair"):
                st.session_state.db.save()
                st.session_state.user = None
                st.session_state.page = "login"
                st.rerun()
        else:
            st.info("Faça login para acessar o sistema.")

# ====== ROUTER ======
def require_login():
    if not st.session_state.user:
        st.session_state.page = "login"; st.rerun()

# Render sidebar sempre
sidebar_nav()

# Navegação
page = st.session_state.page
if page == "login":
    tela_login()
elif page == "leitura":
    require_login(); tela_leitura(st.session_state.get("scan_mode", True))
elif page == "varios":
    require_login(); tela_varios()
elif page == "exportar":
    require_login(); tela_exportar()
elif page == "cadastros":
    require_login(); tela_cadastros()

# Rodapé + commit manual
st.markdown("---")
c1, c2 = st.columns([1,3])
with c1:
    if st.button("💾 Salvar agora"):
        st.session_state.db.save(); st.success("Commit realizado.")
with c2:
    st.caption("Desenvolvido: Gabriel da Silva Lopes • FedEx • Streamlit + SQLite")