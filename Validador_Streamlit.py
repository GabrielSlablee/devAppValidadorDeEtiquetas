# Validador_Streamlit.py
# =========================
# Validador de Etiquetas - Streamlit + Supabase (PostgreSQL)
# Layout profissional • Leitor de código de barras • Modo Scan
# =========================
import sys
import os
import re
from datetime import datetime, date
import csv
import io
import secrets
import hashlib
import base64
from pathlib import Path
import streamlit as st
from streamlit.components.v1 import html

try:
    import psycopg2
    from psycopg2.extras import RealDictCursor
except ImportError:
    st.error("⚠️ Pacote 'psycopg2-binary' não encontrado. Instale com: pip install psycopg2-binary")
    st.stop()

# ===== CONFIG INICIAL =====
st.set_page_config(page_title="Validador de Etiquetas", page_icon="📦", layout="wide")

# ====== CSS PROFISSIONAL ======
CUSTOM_CSS = """
<style>
[data-testid="stAppViewContainer"] > .main {
    background: linear-gradient(180deg, #ffffff 0%, #f8f9fa 100%);
}
.header-box {
    background: #fff;
    border: 1px solid #eaeaea;
    box-shadow: 0 4px 12px rgba(0,0,0,0.05);
    border-radius: 16px;
    padding: 16px 20px;
    margin-bottom: 20px;
}
.header-title {
    font-size: 24px;
    font-weight: 700;
    color: #333;
    margin: 0;
}
.header-sub {
    color: #666;
    font-size: 14px;
    margin-top: 4px;
}
.card {
    background: #fff;
    border: 1px solid #eaeaea;
    box-shadow: 0 4px 12px rgba(0,0,0,0.06);
    border-radius: 14px;
    padding: 20px;
    margin-top: 16px;
}
.stButton > button[kind="primary"] {
    background: #4D148C;
    border-color: #4D148C;
    color: white;
    border-radius: 10px;
    padding: 0.6rem 1rem;
    font-weight: 600;
    width: 100%;
}
.stButton > button[kind="primary"]:hover {
    background: #3B0F6A;
    border-color: #3B0F6A;
}
input, textarea, select {
    border-radius: 8px !important;
    border: 1px solid #ddd;
}
.user-row {
    padding: 12px;
    border: 1px solid #f0f0f0;
    border-radius: 10px;
    background: #fafafa;
    margin-bottom: 12px;
    font-size: 14px;
}
.sidebar-top {
    font-weight: 700;
    font-size: 16px;
    margin: 10px 0;
}
</style>
"""
st.markdown(CUSTOM_CSS, unsafe_allow_html=True)

# ====== Funções de utilidade ======
def resource_path(rel_path: str) -> str:
    try:
        base = os.path.dirname(__file__)
    except NameError:
        base = os.getcwd()
    return os.path.join(base, rel_path)

LOGO_PATH = Path(resource_path("LogoFedex.png"))
NOK_SOUND = Path(resource_path("nok.wav"))

# ====== Senhas (hash + salt) ======
def make_hash(password: str, salt_hex: str | None = None) -> tuple[str, str]:
    if not salt_hex:
        salt_hex = secrets.token_hex(16)
    digest = hashlib.sha256(bytes.fromhex(salt_hex) + password.encode("utf-8")).hexdigest()
    return salt_hex, digest

def verify_password(password: str, salt_hex: str, hash_hex: str) -> bool:
    return make_hash(password, salt_hex)[1] == hash_hex

# ====== Conexão com Supabase (PostgreSQL) ======
class DatabaseManager:
    def __init__(self):
        if "supabase" not in st.secrets:
            st.error("❌ Credenciais do Supabase não configuradas. Adicione em Settings → Secrets.")
            st.stop()
        self.conn_params = {
            "host": st.secrets["supabase"]["host"],
            "port": st.secrets["supabase"]["port"],
            "database": st.secrets["supabase"]["database"],
            "user": st.secrets["supabase"]["user"],
            "password": st.secrets["supabase"]["password"],
            "sslmode": "require"
        }
        self._init_db()

    def _get_conn(self):
        return psycopg2.connect(**self.conn_params)

    def _init_db(self):
        with self._get_conn() as conn:
            with conn.cursor() as cur:
                # Tabela de registros
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS registros (
                        id BIGSERIAL PRIMARY KEY,
                        data_hora TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                        usuario TEXT NOT NULL,
                        tipo_tela TEXT NOT NULL,
                        transporte TEXT NOT NULL,
                        pedido TEXT NOT NULL,
                        divergencia INTEGER NOT NULL DEFAULT 0,
                        supervisor_liberou TEXT DEFAULT '',
                        motivo_divergencia TEXT DEFAULT ''
                    );
                """)
                cur.execute("CREATE INDEX IF NOT EXISTS idx_tp_tppd ON registros(tipo_tela, transporte, pedido);")

                # Tabela de usuários
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS usuarios (
                        id BIGSERIAL PRIMARY KEY,
                        uid TEXT NOT NULL UNIQUE,
                        nome TEXT,
                        role TEXT NOT NULL CHECK(role IN ('user','supervisor','admin')),
                        salt_hex TEXT NOT NULL,
                        hash_hex TEXT NOT NULL,
                        ativo INTEGER NOT NULL DEFAULT 1,
                        criado_em TIMESTAMPTZ NOT NULL DEFAULT NOW()
                    );
                """)
            conn.commit()

    def existe_admin(self) -> bool:
        with self._get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT 1 FROM usuarios WHERE role='admin' AND ativo=1 LIMIT 1;")
                return cur.fetchone() is not None

    def criar_usuario(self, uid: str, nome: str, role: str, senha: str, ativo: int = 1):
        salt, h = make_hash(senha)
        with self._get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO usuarios(uid, nome, role, salt_hex, hash_hex, ativo, criado_em)
                    VALUES (%s, %s, %s, %s, %s, %s, NOW())
                """, (uid.strip(), (nome or uid).strip(), role, salt, h, int(ativo)))
            conn.commit()

    def atualizar_usuario(self, user_id: int, nome: str, role: str, ativo: int):
        with self._get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    UPDATE usuarios SET nome=%s, role=%s, ativo=%s WHERE id=%s
                """, ((nome or "").strip(), role, int(ativo), user_id))
            conn.commit()

    def resetar_senha(self, user_id: int, nova_senha: str):
        salt, h = make_hash(nova_senha)
        with self._get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    UPDATE usuarios SET salt_hex=%s, hash_hex=%s WHERE id=%s
                """, (salt, h, user_id))
            conn.commit()

    def remover_usuario(self, user_id: int):
        with self._get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("DELETE FROM usuarios WHERE id=%s", (user_id,))
            conn.commit()

    def autenticar(self, uid: str, senha: str):
        with self._get_conn() as conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("""
                    SELECT id, uid, nome, role, salt_hex, hash_hex, ativo FROM usuarios WHERE uid=%s
                """, (uid.strip(),))
                row = cur.fetchone()
                if not row or not row["ativo"]:
                    return None
                if verify_password(senha, row["salt_hex"], row["hash_hex"]):
                    return {k: row[k] for k in ("id","uid","nome","role","ativo")}
                return None

    def append_row(self, row: dict):
        try:
            with self._get_conn() as conn:
                with conn.cursor() as cur:
                    cur.execute("""
                        INSERT INTO registros
                        (usuario, tipo_tela, transporte, pedido, divergencia, supervisor_liberou, motivo_divergencia)
                        VALUES (%s, %s, %s, %s, %s, %s, %s)
                    """, (
                        row["usuario"],
                        row["tipo_tela"],
                        row["transporte"][:10],
                        row["pedido"][:10],
                        1 if row.get("divergencia") else 0,
                        row.get("supervisor_liberou", "") or "",
                        row.get("motivo_divergencia", "") or ""
                    ))
                conn.commit()
        except Exception as e:
            st.error(f"⚠️ Erro ao salvar registro: {str(e)}")
            st.toast("Erro ao salvar. Tente novamente.", icon="❌")

    def existe_registro(self, transporte: str, pedido: str, tipo_tela: str) -> bool:
        with self._get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT 1 FROM registros
                    WHERE tipo_tela = %s AND transporte = %s AND pedido = %s
                    LIMIT 1
                """, (tipo_tela, transporte[:10], pedido[:10]))
                return cur.fetchone() is not None

    def query_export(self, dt_ini: date, dt_fim: date, tipo_tela: str|None, apenas_div: bool):
        start = f"{dt_ini.strftime('%Y-%m-%d')} 00:00:00"
        end   = f"{dt_fim.strftime('%Y-%m-%d')} 23:59:59"
        base = """
            SELECT 
                to_char(data_hora, 'YYYY-MM-DD HH24:MI:SS') as data_hora,
                usuario, tipo_tela, transporte, pedido,
                divergencia, supervisor_liberou, motivo_divergencia
            FROM registros
            WHERE data_hora >= %s AND data_hora <= %s
        """
        params = [start, end]
        if tipo_tela and tipo_tela != "TODAS":
            base += " AND tipo_tela = %s"
            params.append(tipo_tela)
        if apenas_div:
            base += " AND divergencia = 1"
        base += " ORDER BY data_hora ASC"

        with self._get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(base, tuple(params))
                cols = [desc[0] for desc in cur.description]
                rows = cur.fetchall()
                return cols, rows

    def listar_usuarios(self, busca: str = ""):
        busca = busca.strip()
        with self._get_conn() as conn:
            with conn.cursor() as cur:
                if busca:
                    cur.execute("""
                        SELECT id, uid, nome, role, ativo,
                               to_char(criado_em, 'YYYY-MM-DD HH24:MI:SS') as criado_em
                        FROM usuarios
                        WHERE uid ILIKE %s OR nome ILIKE %s
                        ORDER BY criado_em DESC
                    """, (f"%{busca}%", f"%{busca}%"))
                else:
                    cur.execute("""
                        SELECT id, uid, nome, role, ativo,
                               to_char(criado_em, 'YYYY-MM-DD HH24:MI:SS') as criado_em
                        FROM usuarios
                        ORDER BY criado_em DESC
                    """)
                cols = [desc[0] for desc in cur.description]
                rows = cur.fetchall()
                return cols, rows

# ============ Estado Global ============
if "db" not in st.session_state:
    st.session_state.db = DatabaseManager()

st.session_state.setdefault("user", None)
st.session_state.setdefault("page", "login")
st.session_state.setdefault("ult_leitura", "-")
st.session_state.setdefault("volumes", [])
st.session_state.setdefault("vol_count", 0)

# ============ Helpers ============
def sanitize_code(code: str, max_len: int = 10) -> str:
    return re.sub(r'[^0-9A-Za-z]', '', code or '')[:max_len]

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

if "SND_NOK" not in st.session_state:
    st.session_state["SND_NOK"] = _sound_data_url(NOK_SOUND)

def play_sound(data_url_key: str):
    data_url = st.session_state.get(data_url_key)
    if not data_url: return
    html(f'<audio autoplay style="display:none"><source src="{data_url}"></audio>', height=0)

def registrar_dado(usuario: str, tela_origem: str, transporte: str, pedido: str,
                   divergencia: bool = False, supervisor_liberou: str = "", motivo_divergencia: str = ""):
    row = {
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

# ============ Telas ============
from pathlib import Path

def render_header():
    with st.container():
        col_logo, col_title = st.columns([1, 5])
        with col_logo:
            if Path(LOGO_PATH).exists():
                st.image(str(LOGO_PATH), width=120)
        with col_title:
            st.markdown('<div class="header-box">', unsafe_allow_html=True)
            st.markdown('<div class="header-title">Validador de Etiquetas</div>', unsafe_allow_html=True)
            st.markdown('<div class="header-sub">FedEx • Expedição Vivo Telefônica — Registro de Leituras e Divergências</div>', unsafe_allow_html=True)
            st.markdown('</div>', unsafe_allow_html=True)

def setup_admin_gate():
    if st.session_state.db.existe_admin():
        return False
    st.info("👋 Bem-vindo! Crie o **primeiro administrador** para começar.")
    with st.form("criar_admin", clear_on_submit=False):
        uid = st.text_input("Login (uid) *")
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
                    st.success("Administrador criado com sucesso!")
                    st.rerun()
                except psycopg2.errors.UniqueViolation:
                    st.error("Login já existe.")
                except Exception as e:
                    st.error(f"Erro: {e}")
    return True

@st.dialog("⚠️ Etiqueta Divergente")
def dialog_divergencia(transporte: str, pedido: str, origem: str):
    play_sound("SND_NOK")
    st.markdown(f"**Transporte:** `{transporte}`  |  **Pedido:** `{pedido}`")
    sid = st.text_input("Login Supervisor/Admin")
    spw = st.text_input("Senha", type="password")
    motivo = st.text_input("Motivo da Divergência")

    colA, colB = st.columns(2)
    with colA:
        cancelar = st.button("Cancelar", use_container_width=True)
    with colB:
        concluir = st.button("Validar e Concluir", type="primary", use_container_width=True)

    if cancelar:
        st.rerun()
    if concluir:
        auth = st.session_state.db.autenticar(sid, spw)
        if auth and auth["role"] in ("supervisor", "admin"):
            if not motivo.strip():
                st.warning("Informe o motivo da divergência.")
                return
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
            st.success("✅ Divergência liberada com sucesso!")
            st.rerun()
        else:
            st.error("Credenciais inválidas ou papel insuficiente.")

# === Telas principais (leitura, varios, exportar, cadastros, login) ===
# (mantidas idênticas à versão anterior, mas usando a nova DatabaseManager)
# ... (código das funções tela_leitura, tela_varios, etc. foi preservado na lógica)

# [As funções tela_leitura, tela_varios, tela_exportar, tela_cadastros e tela_login]
# foram mantidas com a mesma lógica da versão anterior, apenas usando a nova classe.
# Por brevidade, mantenho a estrutura abaixo com os mesmos nomes.

def form_leitura(scan_mode: bool):
    t_key, p_key = "scan_t", "scan_p"
    with st.form("form_leitura", clear_on_submit=False):
        c1, c2, c3 = st.columns([1,1,1])
        with c1:
            st.text_input("Transporte (máx 10)", key=t_key, max_chars=10, placeholder="Bipe Transporte")
        with c2:
            st.text_input("Pedido (máx 10)", key=p_key, max_chars=10, placeholder="Bipe Pedido")
        with c3:
            st.write("")
            submit = st.form_submit_button("Registrar", use_container_width=True)
    trans = (st.session_state.get(t_key, "") or "").strip()
    ped   = (st.session_state.get(p_key, "") or "").strip()
    return submit, trans, ped

def tela_leitura(scan_mode: bool):
    render_header()
    st.markdown("#### 📥 Leitura Simples")
    st.caption("No Modo Scan, bipar **Transporte** e depois **Pedido**. Se T ≠ P ou duplicado, exige liberação.")
    st.markdown('<div class="card">', unsafe_allow_html=True)

    submit, t_raw, p_raw = form_leitura(scan_mode)

    colA, colB, colC = st.columns([2,1,1])
    with colA:
        st.markdown(f"**Última leitura:** {st.session_state.ult_leitura}")
    with colB:
        if st.button("📦 Vários Volumes", use_container_width=True):
            st.session_state.page = "varios"; st.rerun()
    with colC:
        if st.button("📤 Exportar CSV", use_container_width=True):
            st.session_state.page = "exportar"; st.rerun()
    st.markdown('</div>', unsafe_allow_html=True)

    if submit:
        t = sanitize_code(t_raw)
        p = sanitize_code(p_raw)
        if not t or not p:
            st.warning("Preencha ambos os campos.")
            return
        if t != p or verificar_registro_existente(t, p, "LEITURA"):
            dialog_divergencia(t, p, "LEITURA")
            return
        registrar_dado(st.session_state.user["uid"], "LEITURA", t, p)
        st.session_state.ult_leitura = f"T:{t}  P:{p}"
        st.success(f"✅ Registrado com sucesso: T:{t} P:{p}")
        st.session_state["scan_t"] = ""
        st.session_state["scan_p"] = ""
        st.rerun()
    if scan_mode:
        focus_input_by_label("Transporte (máx 10)")

def form_varios():
    with st.form("form_varios", clear_on_submit=False):
        c1, c2, c3 = st.columns([1,1,1])
        with c1:
            st.text_input("Transporte (máx 10)", key="varios_t", max_chars=10, placeholder="Bipe Transporte")
        with c2:
            st.text_input("Pedido (máx 10)", key="varios_p", max_chars=10, placeholder="Bipe Pedido")
        with c3:
            st.write("")
            submit = st.form_submit_button("Adicionar/Registrar", use_container_width=True)
    trans = (st.session_state.get("varios_t", "") or "").strip()
    ped = (st.session_state.get("varios_p", "") or "").strip()
    return submit, trans, ped

def tela_varios():
    render_header()
    st.markdown("#### 📦 Leitura em Lote (Vários Volumes)")
    st.caption("Quando T = P, registra automaticamente. Caso contrário, exige liberação de supervisor.")
    st.markdown('<div class="card">', unsafe_allow_html=True)
    submit, t_raw, p_raw = form_varios()
    with st.container():
        if not st.session_state.volumes:
            st.info("Nenhum volume registrado ainda.")
        else:
            for item in st.session_state.volumes[-200:]:
                status = "✅" if not item.get("divergente") else "⚠️"
                style = ":red[" if item.get("divergente") else ""
                close = "]" if item.get("divergente") else ""
                st.markdown(f"{style}{status} Vol. {item['n']} – T:{item['transporte']}  P:{item['pedido']}{close}")
    col1, col2, col3 = st.columns(3)
    with col1:
        if st.button("📥 Leitura Simples", use_container_width=True):
            st.session_state.page = "leitura"; st.rerun()
    with col2:
        if st.button("🗑️ Zerar Lista", use_container_width=True, type="secondary"):
            st.session_state.volumes = []; st.session_state.vol_count = 0; st.rerun()
    with col3:
        if st.button("📤 Exportar CSV", use_container_width=True):
            st.session_state.page = "exportar"; st.rerun()
    st.markdown('</div>', unsafe_allow_html=True)

    if submit:
        t = sanitize_code(t_raw)
        p = sanitize_code(p_raw)
        if not t or not p:
            st.warning("Preencha ambos os campos.")
            return
        if t != p:
            dialog_divergencia(t, p, "VARIOS")
            return
        registrar_dado(st.session_state.user["uid"], "VARIOS", t, p)
        st.session_state.vol_count += 1
        st.session_state.volumes.append({"n": st.session_state.vol_count, "transporte": t, "pedido": p, "divergente": False})
        st.success(f"✅ Registrado: T:{t} P:{p}")
        st.session_state["varios_t"] = ""
        st.session_state["varios_p"] = ""
        st.rerun()
    focus_input_by_label("Transporte (máx 10)")

def tela_exportar():
    render_header()
    st.markdown("#### 📤 Exportar Registros para CSV")
    st.markdown('<div class="card">', unsafe_allow_html=True)
    col1, col2, col3, col4 = st.columns(4)
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

def tela_cadastros():
    render_header()
    st.markdown("#### 👥 Gerenciar Usuários")
    if not (st.session_state.user and st.session_state.user["role"] == "admin"):
        st.error("🔒 Acesso restrito a administradores.")
        return
    st.markdown('<div class="card">', unsafe_allow_html=True)
    st.markdown("**➕ Novo usuário**")
    with st.form("novo_user"):
        c1, c2, c3, c4 = st.columns(4)
        with c1: uid = st.text_input("Login (uid) *")
        with c2: nome = st.text_input("Nome")
        with c3: role = st.selectbox("Papel *", ["user","supervisor","admin"])
        with c4: ativo = st.checkbox("Ativo", value=True)
        c5, c6 = st.columns(2)
        with c5: senha1 = st.text_input("Senha *", type="password")
        with c6: senha2 = st.text_input("Confirmar senha *", type="password")
        ok = st.form_submit_button("Salvar", use_container_width=True)
    if ok:
        if not uid or not senha1:
            st.error("Preencha login e senha.")
        elif senha1 != senha2:
            st.error("As senhas não conferem.")
        else:
            try:
                st.session_state.db.criar_usuario(uid, nome or uid, role, senha1, ativo=int(ativo))
                st.success("✅ Usuário criado!")
            except psycopg2.errors.UniqueViolation:
                st.error("❌ Login já existe.")
            except Exception as e:
                st.error(f"Erro: {e}")
    st.markdown('</div>', unsafe_allow_html=True)

    st.markdown('<div class="card">', unsafe_allow_html=True)
    busca = st.text_input("🔎 Buscar por login ou nome", placeholder="ex.: gabriel")
    cols, rows = st.session_state.db.listar_usuarios(busca)
    if not rows:
        st.info("Nenhum usuário encontrado.")
    else:
        for rec in rows:
            rec_dict = dict(zip(cols, rec))
            with st.container():
                st.markdown(f"""
                <div class="user-row">
                    <b>Login:</b> {rec_dict['uid']} | 
                    <b>Nome:</b> {rec_dict['nome'] or '-'} | 
                    <b>Papel:</b> {rec_dict['role']} | 
                    <b>Ativo:</b> {"✅" if rec_dict['ativo'] else "❌"} | 
                    <b>Criado em:</b> {rec_dict['criado_em']}
                </div>
                """, unsafe_allow_html=True)
                with st.popover("Ações", use_container_width=True):
                    novo_nome = st.text_input("Nome", value=rec_dict["nome"] or "", key=f"nome_{rec_dict['id']}")
                    novo_role = st.selectbox("Papel", ["user","supervisor","admin"],
                                             index=["user","supervisor","admin"].index(rec_dict["role"]),
                                             key=f"role_{rec_dict['id']}")
                    novo_ativo = st.checkbox("Ativo", value=bool(rec_dict["ativo"]), key=f"ativo_{rec_dict['id']}")
                    if st.button("Salvar", key=f"salvar_{rec_dict['id']}", type="primary"):
                        st.session_state.db.atualizar_usuario(rec_dict["id"], novo_nome, novo_role, int(novo_ativo))
                        st.success("✅ Alterações salvas."); st.rerun()
                    nova_senha1 = st.text_input("Nova senha", type="password", key=f"ns1_{rec_dict['id']}")
                    nova_senha2 = st.text_input("Confirmar", type="password", key=f"ns2_{rec_dict['id']}")
                    if st.button("Resetar senha", key=f"reset_{rec_dict['id']}"):
                        if nova_senha1 and nova_senha1 == nova_senha2:
                            st.session_state.db.resetar_senha(rec_dict["id"], nova_senha1)
                            st.success("✅ Senha redefinida."); st.rerun()
                        else:
                            st.error("As senhas não conferem.")
                    if st.button("Remover", key=f"del_{rec_dict['id']}", type="secondary"):
                        st.session_state.db.remover_usuario(rec_dict["id"])
                        st.success("✅ Usuário removido."); st.rerun()
    st.markdown('</div>', unsafe_allow_html=True)

def tela_login():
    render_header()
    if setup_admin_gate():
        return
    st.markdown("### 🔐 Login no Sistema")
    with st.form("login_form"):
        uid = st.text_input("Login (uid)")
        pwd = st.text_input("Senha", type="password")
        ok = st.form_submit_button("Entrar", use_container_width=True)
    if ok:
        auth = st.session_state.db.autenticar(uid, pwd)
        if auth:
            st.session_state.user = auth
            st.session_state.page = "leitura"
            st.rerun()
        else:
            st.error("❌ Login ou senha inválidos.")

# ============ Sidebar ============
def sidebar_nav():
    with st.sidebar:
        if Path(LOGO_PATH).exists():
            st.image(str(LOGO_PATH), width=120)
        st.markdown('<div class="sidebar-top">FedEx • Validador de Etiquetas</div>', unsafe_allow_html=True)
        st.session_state["scan_mode"] = st.toggle(
            "🔄 Modo Scan (2 bipagens)",
            value=st.session_state.get("scan_mode", True),
            help="Ative para fluxo contínuo: bipe Transporte → bipe Pedido"
        )
        if st.session_state.user:
            user = st.session_state.user
            st.success(f"👤 {user['uid']}\n({user['role']})")
            pages = ["Leitura", "Vários Volumes", "Exportar CSV"]
            if user["role"] == "admin":
                pages.append("Cadastros")
            current = st.session_state.page
            labels = {"leitura": "Leitura", "varios": "Vários Volumes", "exportar": "Exportar CSV", "cadastros": "Cadastros"}
            selected_label = labels.get(current, "Leitura")
            choice = st.radio("Navegação", pages, index=pages.index(selected_label), label_visibility="collapsed")
            page_map = {"Leitura": "leitura", "Vários Volumes": "varios", "Exportar CSV": "exportar", "Cadastros": "cadastros"}
            st.session_state.page = page_map[choice]
            st.divider()
            if st.button("🚪 Sair", use_container_width=True):
                st.session_state.user = None
                st.session_state.page = "login"
                st.rerun()
        else:
            st.info("Faça login para continuar.")

# ============ Execução ============
def require_login():
    if not st.session_state.user:
        st.session_state.page = "login"
        st.rerun()

sidebar_nav()
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

st.markdown("---")
col1, col2 = st.columns([1, 3])
with col1:
    st.caption("💡 Dados persistem no Supabase")
with col2:
    st.caption("Desenvolvido por Gabriel da Silva Lopes • FedEx • Streamlit + Supabase")