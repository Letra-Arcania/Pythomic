r"""
Pythomic — rede social estilo Instagram feita em Python puro (ReactPy + Flask).
================================================================================

Versão SINGLE-FILE: banco de dados, uploads validados e interface vivem neste
único arquivo, organizados por seções numeradas.

Como executar
-------------
1. (Opcional, recomendado) Crie e ative um ambiente virtual (venv):

       python -m venv .venv
       # Windows:      .venv\Scripts\activate
       # Linux/macOS:  source .venv/bin/activate

2. Instale as dependências:

       pip install -r requirements.txt
       (ou, manualmente: pip install reactpy "reactpy[flask]" flask cryptography)

3. Inicie o servidor:

       python pythomic.py

4. Abra no navegador:

       http://localhost:5000

Segredo mestre (opcional)
-------------------------
A criptografia dos campos sensíveis (nome, email e texto dos posts) deriva de
um segredo mestre. Você pode defini-lo com a variável de ambiente
PYTHOMIC_SECRET. Se ela não existir, um segredo aleatório é gerado com
secrets.token_urlsafe(32) e salvo no arquivo ".pythomic_secret" (permissão
0600) ao lado deste script; nas próximas execuções o valor é recarregado
de lá. Guarde esse segredo: sem ele, os dados já criptografados no banco
NÃO podem mais ser descriptografados.

Observação: se o pacote opcional "cryptography" não estiver instalado, o app
AINDA FUNCIONA, porém grava os campos apenas em base64 (ofuscação — isso NÃO
é criptografia de verdade) e imprime um aviso alto e claro uma única vez.

Extra: a variável de ambiente PYTHOMIC_DEBUG=1 habilita o modo debug do Flask
(uso exclusivo em desenvolvimento — o debugger interativo do Werkzeug nunca
deve ficar exposto em produção).
"""

import base64
import hashlib
import hmac
import os
import secrets
import sqlite3
import threading
import time
import uuid
from contextlib import contextmanager

from flask import Flask
from reactpy import component, event, html, svg, use_state
from reactpy.backend.flask import configure

# O pacote "cryptography" é opcional: sem ele o app roda em modo de
# contingência (campos gravados em base64). Veja a seção de segurança.
try:
    from cryptography.fernet import Fernet
    _CRYPTO_OK = True
except ImportError:  # ambiente sem o pacote opcional
    _CRYPTO_OK = False


# ==================== 2. CONFIGURAÇÃO E SEGREDOS ====================

_BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_NAME = os.path.join(_BASE_DIR, "database.db")
UPLOAD_DIR = os.path.join(_BASE_DIR, "uploads")
SECRET_FILE = os.path.join(_BASE_DIR, ".pythomic_secret")

# --- Parâmetros de segurança ---
PBKDF2_ITERATIONS = 600_000            # hash de senha (recomendação atual p/ SHA-256)
FIELD_KEY_ITERATIONS = 200_000         # derivação das chaves de campo (Fernet/HMAC)
MAX_FILE_SIZE = 10 * 1024 * 1024       # 10 MB por upload
MAX_CONTENT_LENGTH = 12 * 1024 * 1024  # limite do corpo HTTP aceito pelo Flask
MAX_POST_LENGTH = 500                  # tamanho máximo do texto do post

# --- Rate limiting (limites em memória; veja a classe RateLimiter) ---
LOGIN_MAX_ATTEMPTS = 5
LOGIN_WINDOW = 15 * 60                 # 15 minutos
REGISTER_MAX_PER_HOUR = 30
REGISTER_WINDOW = 60 * 60              # 1 hora

# Avatar padrão embutido (SVG em data URI — nada é enviado a servidores externos)
DEFAULT_AVATAR = (
    "data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' "
    "fill='%23dbdbdb'><path d='M12 12c2.21 0 4-1.79 4-4s-1.79-4-4-4-4 1.79-4 4 1.79 4 4 4z"
    "m0 2c-2.67 0-8 1.34-8 4v2h16v-2c0-2.66-5.33-4-8-4z'/></svg>"
)


def _load_master_secret() -> str:
    """Obtém o segredo mestre usado para derivar as chaves de criptografia.

    Prioridade:
      1. Variável de ambiente PYTHOMIC_SECRET;
      2. Arquivo ".pythomic_secret" — criado na primeira execução com
         permissão 0600 caso não exista, e recarregado nas seguintes.
    """
    segredo = os.environ.get("PYTHOMIC_SECRET", "").strip()
    if segredo:
        return segredo
    if os.path.exists(SECRET_FILE):
        with open(SECRET_FILE, "r", encoding="utf-8") as arquivo:
            segredo = arquivo.read().strip()
        if segredo:
            return segredo
    # Primeira execução sem PYTHOMIC_SECRET: gera e persiste com permissão 0600.
    segredo = secrets.token_urlsafe(32)
    try:
        descritor = os.open(SECRET_FILE, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descritor, "w", encoding="utf-8") as arquivo:
            arquivo.write(segredo)
    except FileExistsError:
        # Outro processo criou o arquivo simultaneamente: apenas reutilize.
        with open(SECRET_FILE, "r", encoding="utf-8") as arquivo:
            return arquivo.read().strip()
    try:
        # Reforça a permissão (alguns sistemas ignoram o modo do os.open).
        os.chmod(SECRET_FILE, 0o600)
    except OSError:
        pass
    return segredo


MASTER_SECRET = _load_master_secret()


# ==================== 3. UTILITÁRIOS DE SEGURANÇA ====================
# Hash de senha (PBKDF2), criptografia de campos (Fernet), HMAC de busca
# (name_hash/email_hash) e limitador de tentativas (rate limit).

_CRYPTO_WARNED = False


def _warn_insecure_fallback() -> None:
    """Aviso alto e claro (exibido uma única vez) sobre o modo sem criptografia."""
    global _CRYPTO_WARNED
    if _CRYPTO_WARNED:
        return
    _CRYPTO_WARNED = True
    print("=" * 70)
    print("[Pythomic] AVISO DE SEGURANÇA: o pacote 'cryptography' não está instalado.")
    print("[Pythomic] Os campos sensíveis serão gravados APENAS em base64")
    print("[Pythomic] (ofuscação — NÃO é criptografia de verdade!).")
    print("[Pythomic] Instale com: pip install cryptography")
    print("=" * 70)


def _derive_field_key() -> bytes:
    """Deriva a chave Fernet do segredo mestre.

    Derivação exigida pelo projeto: base64.urlsafe_b64encode(PBKDF2-HMAC-SHA256
    (segredo, info b"pythomic-field-enc-v1", 200.000 iterações)).
    """
    return base64.urlsafe_b64encode(
        hashlib.pbkdf2_hmac(
            "sha256",
            MASTER_SECRET.encode("utf-8"),
            b"pythomic-field-enc-v1",
            FIELD_KEY_ITERATIONS,
        )
    )


def _derive_lookup_key() -> bytes:
    """Deriva a chave HMAC dos hashes de busca (name_hash / email_hash).

    Usa uma info string DIFERENTE da chave de criptografia (separação de
    domínios): comprometer uma chave não compromete a outra.
    """
    return hashlib.pbkdf2_hmac(
        "sha256",
        MASTER_SECRET.encode("utf-8"),
        b"pythomic-lookup-hmac-v1",
        FIELD_KEY_ITERATIONS,
    )


_FERNET = Fernet(_derive_field_key()) if _CRYPTO_OK else None
_LOOKUP_KEY = _derive_lookup_key()


def encrypt_field(value) -> str:
    """Criptografa um campo sensível (nome, email, texto do post) para o banco.

    Com 'cryptography': Fernet (AES-128-CBC + HMAC-SHA256, autenticado).
    Sem o pacote: prefixo "b64:" + base64 — apenas ofuscação (veja o aviso
    emitido uma vez em _warn_insecure_fallback).
    """
    if value is None:
        return ""
    dados = str(value).encode("utf-8")
    if _FERNET is not None:
        return _FERNET.encrypt(dados).decode("ascii")
    _warn_insecure_fallback()
    return "b64:" + base64.b64encode(dados).decode("ascii")


def decrypt_field(value) -> str:
    """Descriptografa um campo gravado por encrypt_field.

    Aceita valores gravados no modo de contingência ("b64:...") mesmo que o
    'cryptography' já esteja instalado — assim nenhum dado antigo é perdido.
    """
    if not value:
        return ""
    if value.startswith("b64:"):
        try:
            return base64.b64decode(value[4:].encode("ascii")).decode("utf-8")
        except (ValueError, TypeError):
            return ""
    if _FERNET is not None:
        try:
            return _FERNET.decrypt(value.encode("ascii")).decode("utf-8")
        except Exception:
            # Token inválido: o segredo mestre mudou desde a gravação.
            return ""
    return value


def lookup_hash(value) -> str:
    """HMAC-SHA256 determinístico do valor normalizado (para busca/unicidade).

    Guardamos name_hash/email_hash para permitir colunas UNIQUE e consultas
    por igualdade SEM armazenar o dado em texto puro no banco.
    """
    normalizado = (value or "").strip().lower()
    return hmac.new(_LOOKUP_KEY, normalizado.encode("utf-8"), hashlib.sha256).hexdigest()


def hash_password(password: str) -> str:
    """Gera o hash da senha no formato pbkdf2$iterações$salt$hash.

    PBKDF2-HMAC-SHA256 com 600.000 iterações e salt aleatório de 16 bytes.
    """
    salt = secrets.token_hex(16)  # 16 bytes aleatórios (32 caracteres hex)
    digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt.encode("ascii"), PBKDF2_ITERATIONS
    )
    return f"pbkdf2${PBKDF2_ITERATIONS}${salt}${digest.hex()}"


def verify_password(password: str, stored: str) -> bool:
    """Verifica a senha com comparação em tempo constante (hmac.compare_digest)."""
    try:
        algo, iteracoes, salt, digest = (stored or "").split("$", 3)
    except ValueError:
        return False
    if algo != "pbkdf2":
        return False
    try:
        iteracoes = int(iteracoes)
    except ValueError:
        return False
    esperado = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt.encode("ascii"), iteracoes
    ).hex()
    return hmac.compare_digest(esperado, digest)


def password_policy_error(password: str):
    """Valida a política de senha. Retorna None se válida, ou a mensagem de erro.

    Política: mínimo de 8 caracteres, com pelo menos uma letra e um número.
    Aplicada no cadastro E na troca de senha (a UI também valida, mas a regra
    vale no servidor como defesa adicional).
    """
    senha = password or ""
    if len(senha) < 8:
        return "A senha deve ter pelo menos 8 caracteres."
    if not any(letra.isalpha() for letra in senha):
        return "A senha deve conter pelo menos uma letra."
    if not any(letra.isdigit() for letra in senha):
        return "A senha deve conter pelo menos um número."
    return None


class RateLimiter:
    """Limitador de tentativas em memória, thread-safe (threading.Lock + dict).

    NOTA IMPORTANTE: os componentes ReactPy executam no SERVIDOR — dentro de
    um componente não existe contexto de requisição HTTP acessível (sem IP,
    sem sessão). Por isso o limite de login é chaveado pelo email informado
    ("login:<email>") e o limite de cadastro usa um contador global
    ("register:global").
    """

    def __init__(self):
        self._lock = threading.Lock()
        self._eventos = {}  # chave -> lista de timestamps dentro da janela

    def _podar(self, chave, janela, agora):
        vivos = [quando for quando in self._eventos.get(chave, []) if agora - quando < janela]
        if vivos:
            self._eventos[chave] = vivos
        else:
            self._eventos.pop(chave, None)
        return vivos

    def hit(self, chave, limite, janela):
        """Registra uma tentativa. Retorna (permitido, segundos_para_liberar)."""
        agora = time.time()
        with self._lock:
            eventos = self._podar(chave, janela, agora)
            if len(eventos) >= limite:
                return False, max(1, int(janela - (agora - eventos[0])))
            eventos.append(agora)
            self._eventos[chave] = eventos
            return True, 0

    def reset(self, chave):
        """Limpa o histórico da chave (ex.: após um login bem-sucedido)."""
        with self._lock:
            self._eventos.pop(chave, None)


rate_limiter = RateLimiter()


# ==================== 4. BANCO DE DADOS (SQLITE) ====================


@contextmanager
def _conn():
    """Conexão SQLite endurecida: WAL, foreign_keys e busy_timeout.

    Todas as consultas do projeto usam parâmetros (?) — nunca formatação de
    strings — para eliminar risco de SQL Injection.
    """
    conn = sqlite3.connect(DB_NAME, timeout=5.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA busy_timeout = 5000")
    conn.execute("PRAGMA journal_mode = WAL")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db():
    """Cria o schema (idempotente) e os índices usados pelo feed."""
    with _conn() as conn:
        conn.execute(
            """CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name_hash TEXT UNIQUE NOT NULL,
                name_enc TEXT,
                email_hash TEXT UNIQUE NOT NULL,
                email_enc TEXT,
                password TEXT NOT NULL,
                profile_pic TEXT,
                created_at INTEGER NOT NULL)"""
        )
        conn.execute(
            """CREATE TABLE IF NOT EXISTS posts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                text_enc TEXT,
                media TEXT,
                created_at INTEGER NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE)"""
        )
        conn.execute(
            """CREATE TABLE IF NOT EXISTS followers (
                follower_id INTEGER NOT NULL,
                following_id INTEGER NOT NULL,
                PRIMARY KEY (follower_id, following_id))"""
        )
        conn.execute(
            """CREATE TABLE IF NOT EXISTS likes (
                user_id INTEGER NOT NULL,
                post_id INTEGER NOT NULL,
                PRIMARY KEY (user_id, post_id))"""
        )
        conn.execute(
            """CREATE TABLE IF NOT EXISTS post_views (
                post_id INTEGER NOT NULL,
                user_id INTEGER NOT NULL,
                viewed_at INTEGER NOT NULL,
                PRIMARY KEY (post_id, user_id),
                FOREIGN KEY (post_id) REFERENCES posts(id) ON DELETE CASCADE,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE)""")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_posts_user ON posts(user_id)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_posts_created ON posts(created_at)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_likes_post ON likes(post_id)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_followers_target ON followers(following_id)")


def safe_user(row):
    """Converte a linha do usuário em um dicionário SEGURO para a interface.

    CORREÇÃO DE SEGURANÇA: a versão original fazia `set_user(dict(user))`,
    o que enviava o HASH DA SENHA para o navegador junto com os demais campos
    (qualquer pessoa inspecionando os dados do WebSocket via o hash). Aqui
    devolvemos somente o que a UI precisa exibir — o hash da senha e as
    colunas internas NUNCA saem do servidor.
    """
    if row is None:
        return None
    return {
        "id": row["id"],
        "name": decrypt_field(row["name_enc"]) or "Usuário",
        "email": decrypt_field(row["email_enc"]),
        "profile_pic": row["profile_pic"] or DEFAULT_AVATAR,
        "created": row["created_at"],
    }


def register_user(name, email, password):
    """Cadastra um usuário. Retorna o novo id ou None (inválido/duplicado).

    A unicidade é garantida pelas colunas name_hash/email_hash (HMAC-SHA256),
    nunca pelo texto puro — que nem chega a ficar armazenado sem criptografia.
    """
    name = (name or "").strip()
    email = (email or "").strip().lower()
    if not name or not email or not password:
        return None
    if password_policy_error(password):  # defesa extra: a UI também valida
        return None
    try:
        with _conn() as conn:
            cur = conn.execute(
                "INSERT INTO users (name_hash, name_enc, email_hash, email_enc,"
                " password, profile_pic, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    lookup_hash(name),
                    encrypt_field(name),
                    lookup_hash(email),
                    encrypt_field(email),
                    hash_password(password),
                    DEFAULT_AVATAR,
                    int(time.time()),
                ),
            )
            return cur.lastrowid
    except sqlite3.IntegrityError:
        # Violação de UNIQUE em name_hash/email_hash: já cadastrado.
        return None


def login_user(email, password):
    """Autentica buscando por email_hash. Retorna a linha completa ou None.

    ATENÇÃO: a linha inclui o hash da senha — use sempre safe_user() antes
    de enviar qualquer dado de usuário para a interface.
    """
    if not (email or "").strip():
        return None
    email_hash = lookup_hash(email)
    with _conn() as conn:
        row = conn.execute("SELECT * FROM users WHERE email_hash = ?", (email_hash,)).fetchone()
    if row and verify_password(password or "", row["password"]):
        return row
    return None


def get_user_by_id(user_id):
    with _conn() as conn:
        return conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()


def update_password(user_id, new_password):
    with _conn() as conn:
        conn.execute(
            "UPDATE users SET password = ? WHERE id = ?",
            (hash_password(new_password), user_id),
        )


def get_user_stats(user_id):
    """Estatísticas do usuário: seguidores, seguindo, posts e views acumuladas.

    As views somam TODAS as visualizações únicas recebidas pelos posts do
    usuário (uma por usuário por post — veja a tabela post_views).
    """
    with _conn() as conn:
        seguidores = conn.execute(
            "SELECT COUNT(*) AS total FROM followers WHERE following_id = ?", (user_id,)
        ).fetchone()["total"]
        seguindo = conn.execute(
            "SELECT COUNT(*) AS total FROM followers WHERE follower_id = ?", (user_id,)
        ).fetchone()["total"]
        posts = conn.execute(
            "SELECT COUNT(*) AS total FROM posts WHERE user_id = ?", (user_id,)
        ).fetchone()["total"]
        views = conn.execute(
            "SELECT COUNT(*) AS total FROM post_views v JOIN posts p ON p.id = v.post_id"
            " WHERE p.user_id = ?",
            (user_id,),
        ).fetchone()["total"]
    return {"followers": seguidores, "following": seguindo, "posts": posts, "views": views}


def is_following(follower_id, following_id) -> bool:
    """Verifica se follower_id já segue following_id (consulta indexada)."""
    with _conn() as conn:
        row = conn.execute(
            "SELECT 1 FROM followers WHERE follower_id = ? AND following_id = ?",
            (follower_id, following_id),
        ).fetchone()
    return row is not None


def update_profile_pic(user_id, pic_path) -> None:
    """Grava o novo caminho da foto de perfil (arquivo servido por /uploads)."""
    with _conn() as conn:
        conn.execute("UPDATE users SET profile_pic = ? WHERE id = ?", (pic_path, user_id))


def toggle_follow(follower_id, following_id):
    """Segue/deixa de seguir. Retorna True se passou a seguir, False se parou."""
    with _conn() as conn:
        cur = conn.execute(
            "DELETE FROM followers WHERE follower_id = ? AND following_id = ?",
            (follower_id, following_id),
        )
        if cur.rowcount:
            return False
        conn.execute(
            "INSERT OR IGNORE INTO followers (follower_id, following_id) VALUES (?, ?)",
            (follower_id, following_id),
        )
        return True


def create_post(user_id, text, media_path=None):
    """Cria um post: texto criptografado (text_enc) + timestamp de criação."""
    with _conn() as conn:
        conn.execute(
            "INSERT INTO posts (user_id, text_enc, media, created_at) VALUES (?, ?, ?, ?)",
            (user_id, encrypt_field((text or "").strip()), media_path, int(time.time())),
        )


def toggle_like(user_id, post_id):
    """Curti/descurti. Retorna True se passou a curtir, False se parou."""
    with _conn() as conn:
        cur = conn.execute(
            "DELETE FROM likes WHERE user_id = ? AND post_id = ?", (user_id, post_id)
        )
        if cur.rowcount:
            return False
        conn.execute(
            "INSERT OR IGNORE INTO likes (user_id, post_id) VALUES (?, ?)", (user_id, post_id)
        )
        return True


def relative_time(created_at) -> str:
    """Timestamp -> tempo relativo em pt-BR: agora / há X min / há X h / há X d."""
    if not created_at:
        return ""
    delta = int(time.time() - float(created_at))
    if delta < 60:
        return "agora"
    if delta < 3600:
        return f"há {delta // 60} min"
    if delta < 86400:
        return f"há {delta // 3600} h"
    return f"há {delta // 86400} d"


def get_all_posts(current_user_id):
    """Feed completo em UMA consulta (sem N+1) + descriptografia após a busca.

    Os campos protegidos (text_enc, name_enc) só são descriptografados aqui,
    na memória do servidor, já no formato pronto para a interface.
    """
    with _conn() as conn:
        # Contagem de views: registra a visualização ÚNICA deste usuário para
        # cada post de OUTRAS pessoas presente no feed. O INSERT OR IGNORE
        # garante uma view por usuário por post — atualizar o feed não infla
        # o contador (e o próprio autor não contabiliza view nele mesmo).
        conn.execute(
            "INSERT OR IGNORE INTO post_views (post_id, user_id, viewed_at) "
            "SELECT p.id, ?, ? FROM posts p WHERE p.user_id != ?",
            (current_user_id, int(time.time()), current_user_id),
        )
        rows = conn.execute(
            """
            SELECT
                p.id, p.user_id, p.text_enc, p.media, p.created_at,
                u.name_enc, u.profile_pic,
                (SELECT COUNT(*) FROM likes WHERE post_id = p.id)                                 AS likes_count,
                EXISTS (SELECT 1 FROM likes WHERE post_id = p.id AND user_id = ?)                 AS is_liked,
                EXISTS (SELECT 1 FROM followers WHERE follower_id = ? AND following_id = p.user_id) AS is_following,
                (SELECT COUNT(*) FROM followers WHERE following_id = p.user_id)                   AS followers_count,
                (SELECT COUNT(*) FROM post_views WHERE post_id = p.id)                            AS views_count
            FROM posts p
            JOIN users u ON u.id = p.user_id
            ORDER BY p.id DESC
            """,
            (current_user_id, current_user_id),
        ).fetchall()
    feed = []
    for r in rows:
        feed.append(
            {
                "id": r["id"],
                "user_id": r["user_id"],
                "name": decrypt_field(r["name_enc"]) or "Usuário",
                "profile_pic": r["profile_pic"] or DEFAULT_AVATAR,
                "text": decrypt_field(r["text_enc"]),
                "media": r["media"],
                "time_label": relative_time(r["created_at"]),
                "likes_count": r["likes_count"],
                "is_liked": bool(r["is_liked"]),
                "is_following": bool(r["is_following"]),
                "followers_count": r["followers_count"],
                "views_count": r["views_count"],
            }
        )
    return feed


# ==================== 5. UPLOADS VALIDADOS ====================


class UploadError(Exception):
    """Erro de validação de upload com mensagem amigável em pt-BR."""


# Tipos permitidos e suas extensões (whitelist MIME)
ALLOWED_MIME = {
    "image/jpeg": ".jpg",
    "image/png": ".png",
    "image/gif": ".gif",
    "image/webp": ".webp",
    "video/mp4": ".mp4",
}


def _magic_mime(data: bytes):
    """Identifica o tipo REAL do arquivo pelos magic bytes (assinatura).

    JPEG: FF D8 FF | PNG: 89 50 4E 47 | GIF: "GIF8"
    WEBP: "RIFF" nos bytes 0-4 e "WEBP" nos bytes 8-12
    MP4:  "ftyp" nos bytes 4-8
    """
    if data[:3] == b"\xff\xd8\xff":
        return "image/jpeg"
    if data[:4] == b"\x89\x50\x4e\x47":
        return "image/png"
    if data[:4] == b"GIF8":
        return "image/gif"
    if data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return "image/webp"
    if data[4:8] == b"ftyp":
        return "video/mp4"
    return None


def save_media(base64_data, filename_prefix, images_only=False) -> str:
    """Valida e grava a mídia enviada (data URL em base64).

    Validações: tipo declarado x magic bytes, tamanho máximo (10 MB) e
    decodificação base64 estrita. O arquivo é salvo com nome aleatório
    (uuid4) para evitar colisões e caminhos previsíveis.
    Com images_only=True (foto de perfil), vídeos são rejeitados.
    Retorna o caminho público "/uploads/<arquivo>".
    """
    if not base64_data:
        raise UploadError("Nenhum arquivo recebido.")

    header, encoded = "", base64_data
    if "," in base64_data:
        header, encoded = base64_data.split(",", 1)
    declarado = ""
    if header.startswith("data:"):
        declarado = header[5:].split(";", 1)[0].lower()

    try:
        data = base64.b64decode(encoded, validate=True)
    except (ValueError, TypeError):
        raise UploadError("Arquivo corrompido ou inválido.")

    if not data:
        raise UploadError("Arquivo vazio.")
    if len(data) > MAX_FILE_SIZE:
        raise UploadError("Arquivo muito grande (máximo: 10 MB).")

    real = _magic_mime(data)
    if real is None:
        raise UploadError("Tipo de arquivo não permitido (use JPG, PNG, GIF, WEBP ou MP4).")
    if images_only and not real.startswith("image/"):
        raise UploadError("A foto de perfil deve ser uma imagem (JPG, PNG, GIF ou WEBP).")
    if declarado and declarado != real:
        # O navegador declarou um tipo, mas a assinatura do arquivo é outra:
        # indício clássico de arquivo disfarçado — rejeite.
        raise UploadError("O conteúdo do arquivo não corresponde ao tipo declarado.")

    ext = ALLOWED_MIME[real]
    filename = f"{filename_prefix}_{uuid.uuid4().hex}{ext}"
    os.makedirs(UPLOAD_DIR, exist_ok=True)
    path = os.path.join(UPLOAD_DIR, filename)
    with open(path, "wb") as f:
        f.write(data)
    return f"/uploads/{filename}"


# ==================== 6. APLICAÇÃO FLASK ====================

# A pasta de uploads continua sendo servida estaticamente pelo Flask.
app = Flask(__name__, static_folder=UPLOAD_DIR, static_url_path="/uploads")

# Endurecimento básico do Flask.
app.config["MAX_CONTENT_LENGTH"] = MAX_CONTENT_LENGTH  # rejeita corpos > 12 MB
app.config["SESSION_COOKIE_HTTPONLY"] = True           # JS não lê cookies
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"          # mitiga CSRF básico


@app.after_request
def _add_security_headers(response):
    """Cabeçalhos de segurança aplicados a TODAS as respostas."""
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    return response


# Garante schema do banco e pasta de uploads antes de servir qualquer rota.
init_db()
os.makedirs(UPLOAD_DIR, exist_ok=True)


# ==================== 7. INTERFACE REACTPY ====================
#
# Arquitetura: os componentes ReactPy rodam no servidor e enviam apenas a
# árvore de VDOM + eventos ao navegador. Tema claro/escuro é 100% controlado
# por variáveis CSS ([data-theme="dark"] no <html>), com persistência em
# localStorage via pequenos scripts injetados.

# --- CSS global (mobile-first) injetado uma única vez pelo componente App ---
GLOBAL_CSS = """
:root {
    --bg: #fafafa;
    --card: #ffffff;
    --text: #111111;
    --muted: #8e8e8e;
    --border: #dbdbdb;
    --input-bg: #fafafa;
    --brand: #0095f6;
    --danger: #ed4956;
    --shadow: 0 6px 24px rgba(0, 0, 0, 0.08);
}
html[data-theme="dark"] {
    --bg: #000000;
    --card: #0a0a0a;
    --text: #f5f5f5;
    --muted: #a8a8a8;
    --border: #333333;
    --input-bg: #1e1e1e;
    --shadow: 0 6px 24px rgba(0, 0, 0, 0.6);
}
*, *::before, *::after { box-sizing: border-box; }
body {
    margin: 0;
    background: var(--bg);
    color: var(--text);
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto,
        Helvetica, Arial, sans-serif;
    transition: background 0.3s ease, color 0.3s ease;
}
button, input, textarea { font-family: inherit; }
a { color: var(--brand); }
::-webkit-scrollbar { width: 10px; height: 10px; }
::-webkit-scrollbar-track { background: transparent; }
::-webkit-scrollbar-thumb { background: var(--border); border-radius: 8px; }
::-webkit-scrollbar-thumb:hover { background: var(--muted); }

/* ---- Identidade: logo com gradiente no estilo Instagram ---- */
.py-logo {
    font-family: "Brush Script MT", "Segoe Script", "Lucida Handwriting", cursive;
    font-weight: bold;
    background: linear-gradient(45deg, #f58529, #dd2a7b, #8134af);
    -webkit-background-clip: text;
    background-clip: text;
    color: transparent;
    -webkit-text-fill-color: transparent;
    line-height: 1.15;
}

/* ---- Boas-vindas ---- */
.py-welcome {
    min-height: 100vh;
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    padding: 24px;
    text-align: center;
}
.py-hero-logo { font-size: 64px; margin: 0; }
.py-tagline { color: var(--muted); margin: 10px 0 34px; font-size: 16px; }
.py-cta { width: 100%; max-width: 320px; padding: 15px; font-size: 16px; }
.py-features {
    display: flex;
    flex-direction: column;
    gap: 10px;
    margin-top: 34px;
    width: 100%;
    max-width: 340px;
}
.py-feature {
    display: flex;
    align-items: center;
    gap: 12px;
    font-size: 13px;
    color: var(--muted);
    background: var(--card);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 12px 14px;
    text-align: left;
}
.py-feature svg { flex-shrink: 0; color: var(--brand); }

/* ---- Autenticação ---- */
.py-auth {
    min-height: 100vh;
    display: flex;
    flex-direction: column;
    justify-content: center;
    max-width: 400px;
    margin: 0 auto;
    padding: 24px;
}
.py-auth-logo { font-size: 46px; text-align: center; }
.py-auth-title { margin: 6px 0 18px; text-align: center; font-size: 18px; }
.py-hint { font-size: 12px; color: var(--muted); margin: 0 0 10px; text-align: center; }
.py-pwd-row { position: relative; }
.py-pwd-row .py-input { padding-right: 46px; }
.py-pwd-toggle { position: absolute; right: 8px; top: 6px; color: var(--muted); }

/* ---- Formulários ---- */
.py-input {
    width: 100%;
    padding: 12px;
    margin-bottom: 10px;
    border: 1px solid var(--border);
    border-radius: 10px;
    background: var(--input-bg);
    color: var(--text);
    font-size: 14px;
    outline: none;
    transition: border-color 0.2s ease, box-shadow 0.2s ease;
}
.py-input:focus {
    border-color: var(--brand);
    box-shadow: 0 0 0 3px rgba(0, 149, 246, 0.25);
}
.py-textarea { min-height: 90px; resize: vertical; line-height: 1.4; }
.py-file { padding: 9px; font-size: 13px; }
.py-error {
    color: var(--danger);
    background: rgba(237, 73, 86, 0.1);
    border: 1px solid rgba(237, 73, 86, 0.35);
    border-radius: 10px;
    padding: 10px 12px;
    font-size: 13px;
    margin: 4px 0 10px;
    text-align: center;
}
.py-success {
    color: #2e7d32;
    background: rgba(46, 125, 50, 0.1);
    border: 1px solid rgba(46, 125, 50, 0.35);
    border-radius: 10px;
    padding: 10px 12px;
    font-size: 13px;
    margin: 4px 0 10px;
    text-align: center;
}

/* ---- Botões ---- */
.py-btn {
    border: none;
    border-radius: 10px;
    padding: 12px 16px;
    font-weight: bold;
    font-size: 14px;
    cursor: pointer;
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 8px;
    transition: filter 0.15s ease, background 0.2s ease, color 0.2s ease,
        border-color 0.2s ease;
}
.py-btn:active { transform: scale(0.985); }
.py-btn:focus-visible { outline: 2px solid var(--brand); outline-offset: 2px; }
.py-btn-primary { background: var(--brand); color: #ffffff; width: 100%; }
.py-btn-primary:hover { filter: brightness(1.08); }
.py-btn-ghost { background: transparent; color: var(--brand); width: 100%; padding: 10px; margin-top: 6px; }
.py-btn-ghost:hover { color: var(--text); }
.py-btn-outline { background: transparent; border: 1px solid var(--border); color: var(--text); width: 100%; }
.py-btn-outline:hover { border-color: var(--brand); color: var(--brand); }
.py-btn-danger {
    background: transparent;
    border: 1px solid var(--danger);
    color: var(--danger);
    width: 100%;
    margin-top: 14px;
}
.py-btn-danger:hover { background: rgba(237, 73, 86, 0.08); }
.py-btn-follow {
    padding: 6px 16px;
    font-size: 13px;
    border-radius: 8px;
    border: none;
    font-weight: bold;
    cursor: pointer;
    background: var(--brand);
    color: #ffffff;
    transition: filter 0.15s ease;
    flex-shrink: 0;
}
.py-btn-follow:hover { filter: brightness(1.08); }
.py-btn-following { background: transparent; border: 1px solid var(--border); color: var(--text); filter: none; }
.py-btn-following:hover { border-color: var(--muted); }
.py-icon-btn {
    background: none;
    border: none;
    cursor: pointer;
    color: var(--text);
    display: inline-flex;
    align-items: center;
    justify-content: center;
    padding: 7px;
    border-radius: 8px;
    transition: background 0.15s ease;
}
.py-icon-btn:hover { background: rgba(0, 0, 0, 0.06); }
html[data-theme="dark"] .py-icon-btn:hover { background: rgba(255, 255, 255, 0.1); }

/* ---- Estrutura: cabeçalho, abas e barra lateral ---- */
.py-header {
    position: sticky;
    top: 0;
    z-index: 40;
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 10px 14px;
    background: var(--card);
    border-bottom: 1px solid var(--border);
}
.py-header-logo { font-size: 28px; }
.py-tabs {
    position: fixed;
    left: 0;
    right: 0;
    bottom: 0;
    z-index: 50;
    display: flex;
    background: var(--card);
    border-top: 1px solid var(--border);
}
.py-tab {
    flex: 1;
    background: none;
    border: none;
    padding: 10px 0 12px;
    color: var(--muted);
    cursor: pointer;
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 3px;
    font-size: 11px;
    transition: color 0.15s ease;
}
.py-tab:hover { color: var(--text); }
.py-sidebar {
    display: none;
    position: fixed;
    top: 0;
    left: 0;
    bottom: 0;
    width: 240px;
    background: var(--card);
    border-right: 1px solid var(--border);
    padding: 26px 16px;
    flex-direction: column;
    gap: 6px;
    z-index: 60;
}
.py-side-logo { font-size: 34px; margin: 0 6px 18px; }
.py-nav-btn {
    display: flex;
    align-items: center;
    gap: 12px;
    background: none;
    border: none;
    color: var(--text);
    font-size: 15px;
    font-weight: 600;
    padding: 12px;
    border-radius: 10px;
    cursor: pointer;
    text-align: left;
    width: 100%;
    transition: background 0.15s ease;
}
.py-nav-btn:hover { background: rgba(0, 0, 0, 0.06); }
html[data-theme="dark"] .py-nav-btn:hover { background: rgba(255, 255, 255, 0.08); }
.py-side-profile {
    margin-top: auto;
    display: flex;
    align-items: center;
    gap: 10px;
    border-top: 1px solid var(--border);
    padding-top: 14px;
    cursor: pointer;
}
.py-side-profile-name { font-weight: bold; font-size: 13px; color: var(--text); }
.py-side-profile-meta { font-size: 11px; color: var(--muted); }

/* ---- Feed ---- */
.py-main { max-width: 470px; margin: 0 auto; padding: 0 0 92px; }
.py-feed-top { padding: 14px 12px 0; }
.py-refresh {
    width: 100%;
    padding: 10px;
    border: 1px solid var(--border);
    background: transparent;
    color: var(--text);
    border-radius: 10px;
    cursor: pointer;
    font-weight: bold;
    font-size: 13px;
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 8px;
    transition: border-color 0.2s ease, color 0.2s ease;
}
.py-refresh:hover { border-color: var(--brand); color: var(--brand); }
.py-card {
    background: var(--card);
    border: 1px solid var(--border);
    border-radius: 14px;
    box-shadow: var(--shadow);
    overflow: hidden;
    margin: 20px 12px 0;
}
.py-post-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 10px 14px;
}
.py-post-user { display: flex; align-items: center; gap: 10px; min-width: 0; cursor: pointer; }
.py-avatar {
    width: 42px;
    height: 42px;
    border-radius: 50%;
    padding: 2px;
    background: linear-gradient(45deg, #f58529, #dd2a7b, #8134af);
    flex-shrink: 0;
}
.py-avatar img {
    width: 100%;
    height: 100%;
    border-radius: 50%;
    object-fit: cover;
    border: 2px solid var(--card);
    display: block;
    background: var(--input-bg);
}
.py-avatar-sm { width: 36px; height: 36px; }
.py-user-name {
    font-weight: bold;
    font-size: 14px;
    color: var(--text);
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
}
.py-user-meta { font-size: 12px; color: var(--muted); }
.py-media { width: 100%; display: block; max-height: 600px; object-fit: cover; background: #000; }
.py-post-actions { padding: 8px 10px 0; display: flex; align-items: center; gap: 6px; }
.py-like-btn {
    background: none;
    border: none;
    padding: 6px;
    cursor: pointer;
    display: flex;
    align-items: center;
    border-radius: 8px;
    color: var(--muted);
    transition: background 0.15s ease;
}
.py-like-btn:hover { background: rgba(0, 0, 0, 0.05); }
html[data-theme="dark"] .py-like-btn:hover { background: rgba(255, 255, 255, 0.08); }
.py-likes { font-weight: bold; font-size: 14px; color: var(--text); }
.py-caption {
    margin: 6px 14px 14px;
    font-size: 14px;
    line-height: 1.45;
    color: var(--text);
    word-wrap: break-word;
}
.py-caption strong { margin-right: 6px; }
@keyframes pythomic-pop {
    0% { transform: scale(1); }
    50% { transform: scale(1.35); }
    100% { transform: scale(1); }
}
.py-pop { display: inline-flex; animation: pythomic-pop 0.35s ease; }
.py-empty {
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 10px;
    padding: 70px 24px;
    text-align: center;
    color: var(--muted);
}
.py-empty svg { color: var(--border); }

/* ---- Modais ---- */
.py-overlay {
    position: fixed;
    inset: 0;
    background: rgba(0, 0, 0, 0.6);
    display: flex;
    align-items: center;
    justify-content: center;
    z-index: 100;
    padding: 16px;
}
.py-modal {
    background: var(--card);
    border: 1px solid var(--border);
    border-radius: 16px;
    padding: 22px;
    width: 100%;
    max-width: 400px;
    max-height: 88vh;
    overflow-y: auto;
    position: relative;
    box-shadow: var(--shadow);
}
.py-modal-close { position: absolute; top: 8px; right: 10px; }
.py-modal-title { margin: 2px 0 4px; text-align: center; }
.py-modal-sub { margin: 0 0 14px; text-align: center; color: var(--muted); font-size: 13px; }
.py-divider { border: none; border-top: 1px solid var(--border); margin: 16px 0; }
.py-section-title { margin: 14px 0 10px; font-size: 14px; }
.py-counter { font-size: 12px; color: var(--muted); text-align: right; margin: -4px 0 8px; }
.py-counter-full { color: var(--danger); }
.py-attached {
    display: flex;
    align-items: center;
    gap: 6px;
    font-size: 12px;
    color: #2e7d32;
    margin: 0 0 8px;
}
.py-attached svg { color: #2e7d32; }
.py-thumb {
    width: 64px;
    height: 64px;
    object-fit: cover;
    border-radius: 8px;
    border: 1px solid var(--border);
    display: block;
    margin-bottom: 8px;
}
.py-stats { display: flex; gap: 10px; justify-content: center; margin: 0 0 14px; flex-wrap: wrap; }
.py-stat {
    background: var(--input-bg);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 8px 14px;
    font-size: 13px;
    color: var(--muted);
}
.py-stat strong { color: var(--text); }

/* ---- Views, foto de perfil e modal de perfil ---- */
.py-views {
    margin-left: auto;
    display: inline-flex;
    align-items: center;
    gap: 5px;
    font-size: 13px;
    font-weight: 600;
    color: var(--muted);
}
.py-avatar-wrap { display: flex; justify-content: center; margin: 0 0 6px; }
.py-avatar-lg { width: 84px; height: 84px; }
.py-profile-row { display: flex; align-items: center; gap: 14px; margin: 4px 0 10px; }
.py-profile-row .py-avatar { width: 72px; height: 72px; }
.py-profile-info { min-width: 0; flex: 1; }
.py-profile-name {
    font-weight: bold;
    font-size: 17px;
    color: var(--text);
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
}
.py-profile-meta { font-size: 12px; color: var(--muted); }

/* ---- Desktop / tela na horizontal: barra lateral fixa à esquerda, abas
   escondidas. Além do corte clássico de 1024px, o modo paisagem
   (orientation: landscape) com pelo menos 740px de largura TAMBÉM ativa a
   barra lateral — assim a barra de abas do canto inferior some quando o
   monitor está na horizontal, sem deixar o usuário sem navegação. ---- */
@media (min-width: 1024px), (orientation: landscape) and (min-width: 740px) {
    .py-header { display: none; }
    .py-tabs { display: none; }
    .py-sidebar { display: flex; }
    .py-main {
        max-width: 470px;
        margin: 26px 0 60px calc(240px + (100% - 240px - 470px) / 2);
        padding: 0;
    }
}
"""

# --- Scripts injetados (padrão hidden-input + evento "input" do projeto) ---

# No primeiro carregamento, aplica o tema salvo no localStorage no <html>
# e avisa o servidor pelo input escondido py_theme_input (padrão do projeto).
THEME_BOOT_SCRIPT = """
(function () {
    var tema = 'light';
    try { tema = localStorage.getItem('pythomic_theme') || 'light'; } catch (err) { tema = 'light'; }
    if (tema !== 'dark') { tema = 'light'; }
    document.documentElement.dataset.theme = tema;
    setTimeout(function () {
        var input = document.getElementById('py_theme_input');
        if (!input) return;
        input.value = tema;
        input.dispatchEvent(new Event('input', { bubbles: true }));
    }, 0);
})();
"""


def _theme_sync_script(is_dark: bool) -> str:
    """Script que aplica e persiste o tema atual no <html> + localStorage.

    É remontado a cada mudança de tema (a key muda junto com o estado),
    executando novamente e gravando a escolha do usuário.
    """
    tema = "dark" if is_dark else "light"
    return (
        "(function () {\n"
        "    document.documentElement.dataset.theme = '" + tema + "';\n"
        "    try { localStorage.setItem('pythomic_theme', '" + tema + "'); } catch (err) {}\n"
        "})();"
    )


# Padrão do projeto mantido: o input de arquivo lê o arquivo como data URL
# (base64) e despeja num input escondido, cujo evento "input" chega ao
# servidor. Melhorias: valida o tamanho (10 MB) no cliente com mensagem
# em pt-BR antes de ler, e trata falhas de leitura. A função abaixo gera uma
# cópia do script para cada par de ids (mídia do post e foto de perfil).
def _make_upload_script(file_input_id: str, hidden_input_id: str) -> str:
    """Gera o script de upload para um par (input de arquivo, input escondido)."""
    return """
(function () {
    var fileInput = document.getElementById('FILE_INPUT_ID');
    if (!fileInput || fileInput.dataset.pyBound) return;
    fileInput.dataset.pyBound = '1';
    fileInput.addEventListener('change', function (e) {
        var file = e.target.files[0];
        if (!file) return;
        var LIMITE = 10 * 1024 * 1024;
        if (file.size > LIMITE) {
            alert('Arquivo muito grande. O tamanho máximo permitido é 10 MB.');
            e.target.value = '';
            return;
        }
        var reader = new FileReader();
        reader.onload = function (ev) {
            var hidden = document.getElementById('HIDDEN_INPUT_ID');
            if (!hidden) return;
            hidden.value = ev.target.result;
            hidden.dispatchEvent(new Event('input', { bubbles: true }));
        };
        reader.onerror = function () {
            alert('Não foi possível ler o arquivo. Tente novamente.');
        };
        reader.readAsDataURL(file);
    });
})();
""".replace("FILE_INPUT_ID", file_input_id).replace("HIDDEN_INPUT_ID", hidden_input_id)


# Upload de mídia dos posts (ids originais preservados).
FILE_UPLOAD_SCRIPT = _make_upload_script("py_file_input", "py_base64_input")

# Upload da foto de perfil (ids próprios, sem colidir com o modal de post).
AVATAR_UPLOAD_SCRIPT = _make_upload_script("py_avatar_file_input", "py_avatar_b64_input")


# --- Ícones em SVG inline (sem emojis na interface) ---

def _icon(size, *paths, fill="none", stroke="currentColor", stroke_width=2):
    """Monta um <svg> 24x24 com os caminhos informados (estilo stroke)."""
    return svg.svg(
        {
            "viewBox": "0 0 24 24",
            "width": f"{size}px",
            "height": f"{size}px",
            "fill": fill,
            "stroke": stroke,
            "strokeWidth": stroke_width,
            "strokeLinecap": "round",
            "strokeLinejoin": "round",
            "aria-hidden": "true",
        },
        *[svg.path({"d": d}) for d in paths],
    )


HEART_PATH = (
    "M20.84 4.61a5.5 5.5 0 0 0-7.78 0L12 5.67l-1.06-1.06a5.5 5.5 0 0 0-7.78 7.78"
    "l1.06 1.06L12 21.23l7.78-7.78 1.06-1.06a5.5 5.5 0 0 0 0-7.78z"
)
HOME_PATHS = ("M3 9l9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z", "M9 22V12h6v10")
PLUS_PATHS = ("M12 5v14", "M5 12h14")
MENU_PATHS = ("M3 6h18", "M3 12h18", "M3 18h18")
CLOSE_PATHS = ("M18 6L6 18", "M6 6l12 12")
MOON_PATHS = ("M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z",)
SUN_PATHS = (
    "M12 17a5 5 0 1 0 0-10 5 5 0 0 0 0 10z",
    "M12 1v2", "M12 21v2", "M4.22 4.22l1.42 1.42", "M18.36 18.36l1.42 1.42",
    "M1 12h2", "M21 12h2", "M4.22 19.78l1.42-1.42", "M18.36 5.64l1.42-1.42",
)
LOGOUT_PATHS = ("M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4", "M16 17l5-5-5-5", "M21 12H9")
REFRESH_PATHS = (
    "M23 4v6h-6", "M1 20v-6h6",
    "M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15",
)
CHECK_PATHS = ("M20 6L9 17l-5-5",)
EYE_PATHS = ("M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z", "M15 12a3 3 0 1 1-6 0 3 3 0 0 1 6 0z")
EYE_OFF_PATHS = (
    "M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94",
    "M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19",
    "M14.12 14.12a3 3 0 1 1-4.24-4.24",
    "M1 1l22 22",
)
SHIELD_PATHS = ("M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z",)
LOCK_PATHS = ("M7 11h10v10H7z", "M7 11V7a5 5 0 0 1 10 0v4")
DEVICES_PATHS = ("M2 4h14v10H2z", "M6 18h6", "M9 14v4", "M17 8h4v12h-4z", "M19 17h.01")
IMAGE_PATHS = (
    "M21 19V5a2 2 0 0 0-2-2H5a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2z",
    "M8.5 10a1.5 1.5 0 1 0 0-3 1.5 1.5 0 0 0 0 3z",
    "M21 15l-5-5L5 21",
)
CAMERA_PATHS = (
    "M23 19a2 2 0 0 1-2 2H3a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h4l2-3h6l2 3h4a2 2 0 0 1 2 2z",
    "M16 13a4 4 0 1 1-8 0 4 4 0 0 1 8 0z",
)


# Ícones são funções simples (sem hooks) — podem ser chamadas inline como
# filhos de outros elementos, sem custo de componente.
def HeartIcon(filled, size=26):
    """Coração do botão curtir: preenchido (vermelho) ou contorno."""
    if filled:
        return _icon(size, HEART_PATH, fill="#ed4956", stroke="none")
    return _icon(size, HEART_PATH)


def IconHome(size=22):
    return _icon(size, *HOME_PATHS)


def IconPlus(size=22):
    return _icon(size, *PLUS_PATHS)


def IconMenu(size=22):
    return _icon(size, *MENU_PATHS)


def IconClose(size=20):
    return _icon(size, *CLOSE_PATHS)


def IconMoon(size=22):
    return _icon(size, *MOON_PATHS)


def IconSun(size=22):
    return _icon(size, *SUN_PATHS)


def IconLogout(size=20):
    return _icon(size, *LOGOUT_PATHS)


def IconRefresh(size=16):
    return _icon(size, *REFRESH_PATHS)


def IconCheck(size=14):
    return _icon(size, *CHECK_PATHS)


def IconEye(size=20):
    return _icon(size, *EYE_PATHS)


def IconEyeOff(size=20):
    return _icon(size, *EYE_OFF_PATHS)


def IconShield(size=20):
    return _icon(size, *SHIELD_PATHS)


def IconLock(size=20):
    return _icon(size, *LOCK_PATHS)


def IconDevices(size=20):
    return _icon(size, *DEVICES_PATHS)


def IconImage(size=48):
    return _icon(size, *IMAGE_PATHS)


def IconCamera(size=20):
    return _icon(size, *CAMERA_PATHS)


# --- Telas ---


@component
def WelcomeScreen(set_page):
    """Tela inicial: hero com logo em gradiente, CTA e diferenciais de segurança."""
    return html.div(
        {"class": "py-welcome"},
        html.h1({"class": "py-logo py-hero-logo"}, "Pythomic"),
        html.p({"class": "py-tagline"}, "Conecte-se com o mundo Python."),
        html.button(
            {"class": "py-btn py-btn-primary py-cta", "on_click": lambda e: set_page("auth")},
            "Começar",
        ),
        html.div(
            {"class": "py-features"},
            html.div(
                {"class": "py-feature"},
                IconShield(20),
                html.span({}, "Criptografia de dados no servidor"),
            ),
            html.div(
                {"class": "py-feature"},
                IconLock(20),
                html.span({}, "Senhas protegidas com PBKDF2"),
            ),
            html.div(
                {"class": "py-feature"},
                IconDevices(20),
                html.span({}, "Responsivo para celular e PC"),
            ),
        ),
    )


@component
def AuthScreen(set_page, set_user):
    """Login e cadastro com validação em pt-BR e rate limiting."""
    is_login, set_is_login = use_state(True)
    name, set_name = use_state("")
    email, set_email = use_state("")
    pwd, set_pwd = use_state("")
    conf, set_conf = use_state("")
    error, set_error = use_state("")
    show_pwd, set_show_pwd = use_state(False)

    def toggle_mode(e):
        set_error("")
        set_is_login(not is_login)

    def handle_submit(e):
        set_error("")
        email_norm = email.strip().lower()

        if is_login:
            if not email_norm or not pwd:
                set_error("Informe email e senha.")
                return
            # Rate limit de login: 5 tentativas por 15 min por email
            # (veja a nota sobre chaves na classe RateLimiter).
            chave = f"login:{email_norm}"
            permitido, espera = rate_limiter.hit(chave, LOGIN_MAX_ATTEMPTS, LOGIN_WINDOW)
            if not permitido:
                minutos = max(1, espera // 60)
                set_error(f"Muitas tentativas. Tente novamente em {minutos} minuto(s).")
                return
            usuario = login_user(email_norm, pwd)
            if usuario:
                rate_limiter.reset(chave)  # sucesso limpa o histórico de falhas
                # safe_user() garante que o hash da senha NUNCA chega à interface.
                set_user(safe_user(usuario))
                set_page("home")
            else:
                set_error("Email ou senha inválidos.")
            return

        # --- Cadastro ---
        nome = name.strip()
        if not nome:
            set_error("Informe um nome de usuário.")
            return
        if len(nome) > 30:
            set_error("O nome de usuário deve ter no máximo 30 caracteres.")
            return
        if not email_norm or "@" not in email_norm or len(email_norm) > 120:
            set_error("Informe um email válido.")
            return
        erro_politica = password_policy_error(pwd)
        if erro_politica:
            set_error(erro_politica)
            return
        if pwd != conf:
            set_error("As senhas não conferem.")
            return
        # Rate limit global de cadastro: 30 por hora (sem request context).
        permitido, espera = rate_limiter.hit(
            "register:global", REGISTER_MAX_PER_HOUR, REGISTER_WINDOW
        )
        if not permitido:
            minutos = max(1, espera // 60)
            set_error(f"Muitos cadastros neste momento. Tente novamente em {minutos} minuto(s).")
            return
        uid = register_user(nome, email_norm, pwd)
        if uid:
            set_user(safe_user(get_user_by_id(uid)))
            set_page("home")
        else:
            set_error("Nome de usuário ou email já cadastrados.")

    tipo_senha = "text" if show_pwd else "password"

    return html.div(
        {"class": "py-auth"},
        html.div({"class": "py-logo py-auth-logo"}, "Pythomic"),
        html.h2({"class": "py-auth-title"}, "Entrar" if is_login else "Criar Conta"),
        html.div({"class": "py-error"}, error) if error else None,
        html.input(
            {
                "class": "py-input",
                "type": "text",
                "placeholder": "Nome de usuário",
                "value": name,
                "maxLength": 30,
                "on_change": lambda e: set_name(e["target"]["value"]),
            }
        ) if not is_login else None,
        html.input(
            {
                "class": "py-input",
                "type": "email",
                "placeholder": "Email",
                "value": email,
                "on_change": lambda e: set_email(e["target"]["value"]),
            }
        ),
        html.div(
            {"class": "py-pwd-row"},
            html.input(
                {
                    "class": "py-input",
                    "type": tipo_senha,
                    "placeholder": "Senha",
                    "value": pwd,
                    "on_change": lambda e: set_pwd(e["target"]["value"]),
                }
            ),
            html.button(
                {
                    "class": "py-icon-btn py-pwd-toggle",
                    "type": "button",
                    "on_click": lambda e: set_show_pwd(not show_pwd),
                    "title": "Ocultar senha" if show_pwd else "Mostrar senha",
                },
                IconEyeOff(20) if show_pwd else IconEye(20),
            ),
        ),
        html.input(
            {
                "class": "py-input",
                "type": tipo_senha,
                "placeholder": "Confirmar Senha",
                "value": conf,
                "on_change": lambda e: set_conf(e["target"]["value"]),
            }
        ) if not is_login else None,
        html.p(
            {"class": "py-hint"},
            "Mínimo de 8 caracteres, com pelo menos uma letra e um número.",
        ) if not is_login else None,
        html.button(
            {"class": "py-btn py-btn-primary", "on_click": handle_submit},
            "Entrar" if is_login else "Criar Conta",
        ),
        html.button({"class": "py-btn py-btn-ghost", "on_click": toggle_mode},
                    "Criar conta" if is_login else "Fazer Login"),
        html.button({"class": "py-btn py-btn-ghost", "on_click": lambda e: set_page("welcome")},
                    "Voltar"),
    )


@component
def PostCard(post, current_user, refresh, feed_version, on_open_profile):
    """Card de post do feed.

    Os estados de curtida guardam o id do post e a versão do feed: como os
    componentes são reconciliados por posição na lista, isso impede que a
    curtida de um post apareça em outro ao inserir/atualizar o feed — e
    ressincroniza os contadores quando o usuário clica em "Atualizar Feed".
    """
    like_state, set_like_state = use_state(None)
    if (
        like_state is None
        or like_state["post_id"] != post["id"]
        or like_state["feed_version"] != feed_version
    ):
        like_state = {
            "post_id": post["id"],
            "feed_version": feed_version,
            "liked": bool(post["is_liked"]),
            "count": post["likes_count"],
        }
    pop_key, set_pop_key = use_state(0)

    def handle_like(e):
        liked = toggle_like(current_user["id"], post["id"])
        set_like_state(
            {
                "post_id": post["id"],
                "feed_version": like_state["feed_version"],
                "liked": liked,
                "count": like_state["count"] + (1 if liked else -1),
            }
        )
        set_pop_key(lambda k: k + 1)  # remonta o coração e reanima o "pop"

    def handle_follow(e):
        toggle_follow(current_user["id"], post["user_id"])
        refresh()

    is_own_post = post["user_id"] == current_user["id"]

    media_element = None
    if post["media"]:
        if post["media"].lower().endswith((".mp4", ".webm")):
            media_element = html.video(
                {"src": post["media"], "controls": True, "preload": "metadata", "class": "py-media"}
            )
        else:
            media_element = html.img(
                {"src": post["media"], "alt": "Mídia do post", "class": "py-media"}
            )

    follow_btn = None
    if not is_own_post:
        follow_btn = html.button(
            {
                "class": "py-btn-follow py-btn-following" if post["is_following"] else "py-btn-follow",
                "on_click": handle_follow,
            },
            "Seguindo" if post["is_following"] else "Seguir",
        )

    user_meta = f"{post['followers_count']} seguidores"
    if post["time_label"]:
        user_meta += f" · {post['time_label']}"

    legenda = None
    if post["text"]:
        legenda = html.p(
            {"class": "py-caption"},
            html.strong({}, post["name"]),
            " " + post["text"],
        )

    return html.div(
        {"class": "py-card"},
        html.div(
            {"class": "py-post-header"},
            html.div(
                {
                    "class": "py-post-user",
                    "on_click": lambda e: on_open_profile(post["user_id"]),
                    "title": "Ver perfil",
                },
                html.div(
                    {"class": "py-avatar"},
                    html.img({"src": post["profile_pic"], "alt": post["name"]}),
                ),
                html.div(
                    {"style": {"minWidth": "0"}},
                    html.div({"class": "py-user-name"}, post["name"]),
                    html.div({"class": "py-user-meta"}, user_meta),
                ),
            ),
            follow_btn,
        ),
        media_element,
        html.div(
            {"class": "py-post-actions"},
            html.button(
                {"class": "py-like-btn", "on_click": handle_like, "title": "Curtir"},
                html.span({"class": "py-pop", "key": f"heart-{pop_key}"}, HeartIcon(like_state["liked"])),
            ),
            html.span({"class": "py-likes"}, str(like_state["count"])),
            html.span(
                {"class": "py-views", "title": "Visualizações"},
                IconEye(16),
                str(post["views_count"]),
            ),
        ),
        legenda,
    )


@component
def CreatePostModal(user, on_close, refresh):
    """Modal de criação de post: texto + mídia (padrão base64 do projeto)."""
    post_text, set_post_text = use_state("")
    file_data, set_file_data = use_state(None)
    upload_key, set_upload_key = use_state(0)
    post_error, set_post_error = use_state("")

    restantes = MAX_POST_LENGTH - len(post_text)

    def handle_publish(e):
        text = post_text.strip()
        if not text and not file_data:
            set_post_error("Escreva algo ou anexe uma mídia.")
            return
        media_path = None
        if file_data:
            try:
                media_path = save_media(file_data, f"post_{user['id']}_{int(time.time())}")
            except UploadError as err:
                set_post_error(str(err))
                return
        create_post(user["id"], text, media_path)
        set_post_text("")
        set_file_data(None)
        set_post_error("")
        set_upload_key(lambda k: k + 1)  # reseta o input de arquivo
        refresh()
        on_close(e)

    preview = None
    if file_data and file_data.startswith("data:image"):
        preview = html.img(
            {"src": file_data, "class": "py-thumb", "alt": "Pré-visualização da mídia"}
        )

    return html.div(
        {"class": "py-overlay", "on_click": on_close},
        html.div(
            {"class": "py-modal", "on_click": event(lambda e: None, stop_propagation=True)},
            html.button(
                {"class": "py-icon-btn py-modal-close", "on_click": on_close, "title": "Fechar"},
                IconClose(20),
            ),
            html.h3({"class": "py-modal-title"}, "Criar Post"),
            html.textarea(
                {
                    "class": "py-input py-textarea",
                    "placeholder": "Escreva um texto...",
                    "value": post_text,
                    "maxLength": MAX_POST_LENGTH,
                    "on_change": lambda e: set_post_text(e["target"]["value"]),
                }
            ),
            html.div(
                {"class": "py-counter" + ("" if restantes > 0 else " py-counter-full")},
                f"{restantes} caracteres restantes",
            ),
            html.input(
                {
                    "type": "file",
                    "id": "py_file_input",
                    "key": f"file-{upload_key}",
                    "class": "py-input py-file",
                    "accept": "image/jpeg,image/png,image/gif,image/webp,video/mp4",
                }
            ),
            html.input(
                {
                    "type": "hidden",
                    "id": "py_base64_input",
                    "key": f"hidden-{upload_key}",
                    "on_change": lambda e: set_file_data(e["target"]["value"]),
                }
            ),
            preview,
            html.p({"class": "py-attached"}, IconCheck(14), "Mídia anexada") if file_data else None,
            html.div({"class": "py-error"}, post_error) if post_error else None,
            html.button(
                {"class": "py-btn py-btn-primary", "on_click": handle_publish,
                 "style": {"marginBottom": "14px"}},
                "Publicar",
            ),
            # A key muda junto com upload_key: o script é remontado e religa
            # o listener no novo input de arquivo a cada reset.
            html.script({"key": f"upload-script-{upload_key}"}, FILE_UPLOAD_SCRIPT),
        ),
    )


@component
def MenuModal(user, set_user, is_dark, set_is_dark, on_close, refresh):
    """Menu do perfil: foto, estatísticas (+ views), senha, tema e logout."""
    stats = get_user_stats(user["id"])
    old_pwd, set_old_pwd = use_state("")
    new_pwd, set_new_pwd = use_state("")
    conf_pwd, set_conf_pwd = use_state("")
    pwd_msg, set_pwd_msg = use_state("")
    pwd_ok, set_pwd_ok = use_state(False)
    show_pwd, set_show_pwd = use_state(False)
    avatar_data, set_avatar_data = use_state(None)
    avatar_key, set_avatar_key = use_state(0)
    avatar_msg, set_avatar_msg = use_state("")
    avatar_ok, set_avatar_ok = use_state(False)

    def toggle_theme(e):
        # Troca o estado no servidor; o script de sincronização (keyed)
        # aplica o data-theme no <html> e grava no localStorage.
        set_is_dark(not is_dark)

    def change_avatar(e):
        """Troca a foto de perfil: valida (somente imagens), grava e atualiza a UI."""
        set_avatar_msg("")
        set_avatar_ok(False)
        if not avatar_data:
            set_avatar_msg("Escolha uma imagem primeiro.")
            return
        try:
            caminho = save_media(
                avatar_data, f"avatar_{user['id']}_{int(time.time())}", images_only=True
            )
        except UploadError as err:
            set_avatar_msg(str(err))
            return
        update_profile_pic(user["id"], caminho)
        # safe_user() de novo: a nova foto sai limpa para toda a interface.
        set_user(safe_user(get_user_by_id(user["id"])))
        set_avatar_data(None)
        set_avatar_key(lambda k: k + 1)  # reseta o input de arquivo
        set_avatar_ok(True)
        set_avatar_msg("Foto de perfil atualizada!")
        refresh()  # propaga a nova foto para os cards do feed

    def change_password(e):
        set_pwd_msg("")
        set_pwd_ok(False)
        # Mesma política do cadastro: 8+ caracteres, letra e número.
        erro_politica = password_policy_error(new_pwd)
        if erro_politica:
            set_pwd_msg(erro_politica)
            return
        if new_pwd != conf_pwd:
            set_pwd_msg("A nova senha e a confirmação não conferem.")
            return
        if not login_user(user["email"], old_pwd):
            set_pwd_msg("Senha atual incorreta.")
            return
        update_password(user["id"], new_pwd)
        set_pwd_ok(True)
        set_pwd_msg("Senha alterada com sucesso!")
        set_old_pwd("")
        set_new_pwd("")
        set_conf_pwd("")

    tipo_senha = "text" if show_pwd else "password"

    return html.div(
        {"class": "py-overlay", "on_click": on_close},
        html.div(
            {"class": "py-modal", "on_click": event(lambda e: None, stop_propagation=True)},
            html.button(
                {"class": "py-icon-btn py-modal-close", "on_click": on_close, "title": "Fechar"},
                IconClose(20),
            ),
            html.h3({"class": "py-modal-title"}, f"@{user['name']}"),
            html.div(
                {"class": "py-avatar-wrap"},
                html.div(
                    {"class": "py-avatar py-avatar-lg"},
                    html.img({"src": user["profile_pic"], "alt": user["name"]}),
                ),
            ),
            html.input(
                {
                    "type": "file",
                    "id": "py_avatar_file_input",
                    "key": f"avatar-file-{avatar_key}",
                    "class": "py-input py-file",
                    "accept": "image/jpeg,image/png,image/gif,image/webp",
                }
            ),
            html.input(
                {
                    "type": "hidden",
                    "id": "py_avatar_b64_input",
                    "key": f"avatar-hidden-{avatar_key}",
                    "on_change": lambda e: set_avatar_data(e["target"]["value"]),
                }
            ),
            html.img(
                {
                    "src": avatar_data,
                    "class": "py-thumb",
                    "alt": "Pré-visualização da nova foto",
                }
            ) if avatar_data and avatar_data.startswith("data:image") else None,
            html.button(
                {"class": "py-btn py-btn-primary", "on_click": change_avatar},
                IconCamera(18),
                "Salvar Nova Foto",
            ),
            html.div(
                {"class": "py-success" if avatar_ok else "py-error"}, avatar_msg
            ) if avatar_msg else None,
            html.div(
                {"class": "py-stats"},
                html.span(
                    {"class": "py-stat"},
                    html.strong({}, str(stats["followers"])),
                    " seguidores",
                ),
                html.span(
                    {"class": "py-stat"},
                    html.strong({}, str(stats["following"])),
                    " seguindo",
                ),
                html.span(
                    {"class": "py-stat"},
                    html.strong({}, str(stats["posts"])),
                    " posts",
                ),
                html.span(
                    {"class": "py-stat"},
                    html.strong({}, str(stats["views"])),
                    " views",
                ),
            ),
            html.hr({"class": "py-divider"}),
            html.h4({"class": "py-section-title"}, "Trocar Senha"),
            html.input(
                {
                    "class": "py-input",
                    "type": "password",
                    "placeholder": "Senha atual",
                    "value": old_pwd,
                    "on_change": lambda e: set_old_pwd(e["target"]["value"]),
                }
            ),
            html.div(
                {"class": "py-pwd-row"},
                html.input(
                    {
                        "class": "py-input",
                        "type": tipo_senha,
                        "placeholder": "Nova senha",
                        "value": new_pwd,
                        "on_change": lambda e: set_new_pwd(e["target"]["value"]),
                    }
                ),
                html.button(
                    {
                        "class": "py-icon-btn py-pwd-toggle",
                        "type": "button",
                        "on_click": lambda e: set_show_pwd(not show_pwd),
                        "title": "Ocultar senha" if show_pwd else "Mostrar senha",
                    },
                    IconEyeOff(20) if show_pwd else IconEye(20),
                ),
            ),
            html.input(
                {
                    "class": "py-input",
                    "type": tipo_senha,
                    "placeholder": "Confirmar nova senha",
                    "value": conf_pwd,
                    "on_change": lambda e: set_conf_pwd(e["target"]["value"]),
                }
            ),
            html.p(
                {"class": "py-hint"},
                "Mínimo de 8 caracteres, com pelo menos uma letra e um número.",
            ),
            html.button({"class": "py-btn py-btn-primary", "on_click": change_password},
                        "Alterar Senha"),
            html.div(
                {"class": "py-success" if pwd_ok else "py-error"},
                pwd_msg,
            ) if pwd_msg else None,
            html.hr({"class": "py-divider"}),
            html.button(
                {"class": "py-btn py-btn-outline", "on_click": toggle_theme},
                IconMoon(18) if not is_dark else IconSun(18),
                f"Trocar para {'Light Mode' if is_dark else 'Dark Mode'}",
            ),
            html.button(
                {"class": "py-btn py-btn-danger", "on_click": lambda e: set_user(None)},
                IconLogout(18),
                "Sair da Conta",
            ),
            # Religa o listener do input de arquivo da foto: a key muda junto
            # com avatar_key e o script é remontado a cada reset (mesmo padrão
            # do modal de criação de post).
            html.script({"key": f"avatar-script-{avatar_key}"}, AVATAR_UPLOAD_SCRIPT),
        ),
    )


@component
def ProfileModal(current_user, profile_id, on_close, refresh):
    """Perfil de um usuário: foto, estatísticas e botão Seguir ao lado.

    Abre ao clicar no perfil (avatar/nome) de qualquer card do feed. O botão
    Seguir/Seguindo fica AO LADO do perfil, como no Instagram; no próprio
    perfil ele não aparece — ficam só as estatísticas.
    """
    dados = safe_user(get_user_by_id(profile_id)) if profile_id else None
    stats = get_user_stats(profile_id) if profile_id else None
    seguindo, set_seguindo = use_state(
        is_following(current_user["id"], profile_id) if profile_id else False
    )
    seguidores, set_seguidores = use_state(stats["followers"] if stats else 0)

    def toggle_follow_click(e):
        agora_segue = toggle_follow(current_user["id"], profile_id)
        set_seguindo(agora_segue)
        set_seguidores(lambda n: n + (1 if agora_segue else -1))
        refresh()  # mantém os botões "Seguir" dos cards em sincronia

    if dados is None or stats is None:
        return html.div(
            {"class": "py-overlay", "on_click": on_close},
            html.div(
                {"class": "py-modal", "on_click": event(lambda e: None, stop_propagation=True)},
                html.button(
                    {"class": "py-icon-btn py-modal-close", "on_click": on_close,
                     "title": "Fechar"},
                    IconClose(20),
                ),
                html.p({"class": "py-modal-sub"}, "Perfil não encontrado."),
            ),
        )

    botao_seguir = None
    if dados["id"] != current_user["id"]:
        botao_seguir = html.button(
            {
                "class": "py-btn-follow py-btn-following" if seguindo else "py-btn-follow",
                "on_click": toggle_follow_click,
            },
            "Seguindo" if seguindo else "Seguir",
        )

    return html.div(
        {"class": "py-overlay", "on_click": on_close},
        html.div(
            {"class": "py-modal", "on_click": event(lambda e: None, stop_propagation=True)},
            html.button(
                {"class": "py-icon-btn py-modal-close", "on_click": on_close, "title": "Fechar"},
                IconClose(20),
            ),
            html.h3({"class": "py-modal-title"}, "Perfil"),
            html.div(
                {"class": "py-profile-row"},
                html.div(
                    {"class": "py-avatar"},
                    html.img({"src": dados["profile_pic"], "alt": dados["name"]}),
                ),
                html.div(
                    {"class": "py-profile-info"},
                    html.div({"class": "py-profile-name"}, dados["name"]),
                    html.div(
                        {"class": "py-profile-meta"},
                        "Membro desde "
                        + time.strftime("%d/%m/%Y", time.localtime(dados.get("created") or 0)),
                    ),
                ),
                botao_seguir,
            ),
            html.div(
                {"class": "py-stats"},
                html.span({"class": "py-stat"}, html.strong({}, str(stats["posts"])), " posts"),
                html.span(
                    {"class": "py-stat"}, html.strong({}, str(seguidores)), " seguidores"
                ),
                html.span(
                    {"class": "py-stat"}, html.strong({}, str(stats["following"])), " seguindo"
                ),
                html.span({"class": "py-stat"}, html.strong({}, str(stats["views"])), " views"),
            ),
        ),
    )


@component
def HomeScreen(user, set_user, is_dark, set_is_dark):
    """Feed + cabeçalho (mobile), barra lateral (desktop) e abas (mobile)."""
    is_menu_open, set_menu_open = use_state(False)
    is_create_open, set_create_open = use_state(False)
    profile_id, set_profile_id = use_state(None)
    posts, set_posts = use_state(get_all_posts(user["id"]))
    feed_version, set_feed_version = use_state(0)
    stats = get_user_stats(user["id"])

    def refresh_posts():
        set_posts(get_all_posts(user["id"]))
        set_feed_version(lambda v: v + 1)  # ressincroniza curtidas nos cards

    def open_profile(user_id):
        set_profile_id(user_id)

    def toggle_theme(e):
        set_is_dark(not is_dark)

    cabecalho = html.header(
        {"class": "py-header"},
        html.div({"class": "py-logo py-header-logo"}, "Pythomic"),
        html.div(
            {"style": {"display": "flex", "gap": "2px"}},
            html.button(
                {
                    "class": "py-icon-btn",
                    "on_click": lambda e: set_create_open(True),
                    "title": "Criar novo post",
                },
                IconPlus(22),
            ),
            html.button(
                {
                    "class": "py-icon-btn",
                    "on_click": toggle_theme,
                    "title": "Alternar tema claro/escuro",
                },
                IconMoon(22) if not is_dark else IconSun(22),
            ),
            html.button(
                {"class": "py-icon-btn", "on_click": lambda e: set_menu_open(True),
                 "title": "Abrir menu"},
                IconMenu(22),
            ),
        ),
    )

    barra_lateral = html.aside(
        {"class": "py-sidebar"},
        html.div({"class": "py-logo py-side-logo"}, "Pythomic"),
        html.button({"class": "py-nav-btn", "on_click": lambda e: refresh_posts()},
                    IconHome(22), "Início"),
        html.button({"class": "py-nav-btn", "on_click": lambda e: set_create_open(True)},
                    IconPlus(22), "Criar"),
        html.button({"class": "py-nav-btn", "on_click": toggle_theme},
                    IconMoon(22) if not is_dark else IconSun(22), "Tema"),
        html.button({"class": "py-nav-btn", "on_click": lambda e: set_user(None)},
                    IconLogout(20), "Sair"),
        html.div(
            {
                "class": "py-side-profile",
                "on_click": lambda e: set_menu_open(True),
                "title": "Abrir menu do perfil",
            },
            html.div(
                {"class": "py-avatar py-avatar-sm"},
                html.img({"src": user["profile_pic"], "alt": user["name"]}),
            ),
            html.div(
                {"style": {"minWidth": "0"}},
                html.div({"class": "py-side-profile-name"}, f"@{user['name']}"),
                html.div(
                    {"class": "py-side-profile-meta"},
                    f"{stats['followers']} seguidores · {stats['following']} seguindo",
                ),
            ),
        ),
    )

    abas = html.nav(
        {"class": "py-tabs"},
        html.button({"class": "py-tab", "on_click": lambda e: refresh_posts()},
                    IconHome(22), html.span({}, "Início")),
        html.button({"class": "py-tab", "on_click": lambda e: set_create_open(True)},
                    IconPlus(22), html.span({}, "Criar")),
        html.button({"class": "py-tab", "on_click": lambda e: set_menu_open(True)},
                    IconMenu(22), html.span({}, "Menu")),
    )

    return html.div(
        {"class": "py-shell"},
        barra_lateral,
        cabecalho,
        html.main(
            {"class": "py-main"},
            html.div(
                {"class": "py-feed-top"},
                html.button(
                    {"class": "py-refresh", "on_click": lambda e: refresh_posts()},
                    IconRefresh(16),
                    "Atualizar Feed",
                ),
            ),
            html.div(
                {"class": "py-empty"},
                IconImage(48),
                html.p(
                    {"style": {"margin": "0", "fontWeight": "bold", "color": "var(--text)"}},
                    "Seu feed está vazio",
                ),
                html.p(
                    {"style": {"margin": "0", "fontSize": "13px"}},
                    "Siga novas pessoas ou publique o primeiro post pelo botão Criar.",
                ),
            ) if not posts else None,
            *[PostCard(p, user, refresh_posts, feed_version, open_profile) for p in posts],
        ),
        abas,
        CreatePostModal(user, lambda e: set_create_open(False), refresh_posts)
        if is_create_open else None,
        MenuModal(user, set_user, is_dark, set_is_dark,
                  lambda e: set_menu_open(False), refresh_posts)
        if is_menu_open else None,
        ProfileModal(user, profile_id, lambda e: set_profile_id(None), refresh_posts)
        if profile_id else None,
    )


@component
def App():
    """Raiz da aplicação: roteamento simples, tema persistente e CSS global."""
    page, set_page = use_state("welcome")
    user, set_user = use_state(None)
    is_dark, set_is_dark = use_state(False)
    theme_ready, set_theme_ready = use_state(False)

    def handle_theme_input(e):
        """Recebe do script de boot o tema salvo no navegador (padrão hidden-input)."""
        valor = e["target"]["value"]
        set_is_dark(valor == "dark")
        set_theme_ready(True)  # libera o script de sincronização após o boot

    if page == "home" and user:
        tela = HomeScreen(user, set_user, is_dark, set_is_dark)
    elif page == "auth":
        tela = AuthScreen(set_page, set_user)
    else:
        tela = WelcomeScreen(set_page)

    return html.div(
        {"class": "py-shell"},
        html.style(GLOBAL_CSS),
        html.input(
            {"type": "hidden", "id": "py_theme_input", "on_change": handle_theme_input}
        ),
        # Boot: aplica o tema salvo no localStorage (roda uma vez na montagem).
        html.script({"key": "py-theme-boot"}, THEME_BOOT_SCRIPT),
        # Sincronização: só entra em cena depois do boot, para não sobrescrever
        # o tema persistido; a key muda a cada alternância e re-executa o script.
        html.script(
            {"key": f"py-theme-sync-{is_dark}"}, _theme_sync_script(is_dark)
        ) if theme_ready else None,
        tela,
    )


# Liga a interface ReactPy ao servidor Flask.
configure(app, App)


if __name__ == "__main__":
    # Debug desativado por padrão: o debugger interativo do Werkzeug permite
    # execução remota de código se exposto. Ative apenas em desenvolvimento
    # com a variável de ambiente PYTHOMIC_DEBUG=1.
    app.run(host="0.0.0.0", port=5000, debug=os.environ.get("PYTHOMIC_DEBUG") == "1")
