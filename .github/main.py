from fastapi import FastAPI, APIRouter, HTTPException, Depends, Header
from fastapi.responses import StreamingResponse
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import os
import re
import io
import asyncio
import ipaddress
import logging
import secrets
from pathlib import Path
from pydantic import BaseModel, Field, EmailStr
from typing import List, Optional, Literal, Dict
from datetime import datetime, timedelta, timezone, date
import uuid
import bcrypt
import jwt
import httpx
from html import escape
from html.parser import HTMLParser
from urllib.parse import urlparse

from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.lib import colors as rl_colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

# ------------------------ DB ------------------------
mongo_url = os.environ['MONGO_URL']
mongo_client = AsyncIOMotorClient(mongo_url)
db = mongo_client[os.environ['DB_NAME']]

# ------------------------ Constants ------------------------
JWT_SECRET = os.environ['JWT_SECRET']
JWT_ALG = "HS256"
EMAIL_BASE_URL = "https://integrations.emergentagent.com"
EMAIL_KEY = os.environ["EMERGENT_EMAIL_KEY"]
EMAIL_FROM_NAME = os.environ["EMAIL_FROM_NAME"]

BR_TZ = timezone(timedelta(hours=-3))

# ------------------------ App ------------------------
app = FastAPI()
api = APIRouter(prefix="/api")

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# ------------------------ Helpers ------------------------

def now_utc():
    return datetime.now(timezone.utc)

def hash_pw(pw: str) -> str:
    return bcrypt.hashpw(pw.encode(), bcrypt.gensalt()).decode()

def verify_pw(pw: str, h: str) -> bool:
    try:
        return bcrypt.checkpw(pw.encode(), h.encode())
    except Exception:
        return False

def make_token(sub: str) -> str:
    payload = {"sub": sub, "exp": now_utc() + timedelta(days=7)}
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALG)

async def get_admin(authorization: Optional[str] = Header(None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing token")
    token = authorization.split(" ", 1)[1]
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid token")
    admin = await db.admins.find_one({"username": payload["sub"]}, {"_id": 0, "password_hash": 0})
    if not admin:
        raise HTTPException(status_code=401, detail="Admin not found")
    return admin

# ------------------------ Email guardrails ------------------------
_SHORTENERS = ("bit.ly", "tinyurl.com", "t.co", "is.gd", "cutt.ly", "goo.gl", "rebrand.ly")
_CRED_ASK = ("reply with your password", "reply with the code", "send your password", "cvv",
             "send us your password", "enter your password below", "confirm your card number",
             "your full card number", "seed phrase", "recovery phrase", "verify your card",
             "social security number", "confirm your bank details")
_HOSTISH = re.compile(r"\b(?:https?://)?((?:[a-z0-9-]+\.)+[a-z]{2,})", re.I)

def _host_ok(host: str) -> bool:
    if not host or "xn--" in host:
        return False
    try:
        ipaddress.ip_address(host)
        return False
    except ValueError:
        pass
    return not any(host == s or host.endswith("." + s) for s in _SHORTENERS)

def _same_site(shown: str, real: str) -> bool:
    return shown == real or real.endswith("." + shown) or shown.endswith("." + real)

class _EmailScan(HTMLParser):
    def __init__(self):
        super().__init__()
        self.tags, self.urls, self.anchors = set(), [], []
        self._href, self._text = None, []
    def handle_starttag(self, tag, attrs):
        self.tags.add(tag.lower())
        self.urls += [v for k, v in attrs if k.lower() in ("href", "src") and v]
        if tag.lower() == "a":
            self._href = dict((k.lower(), v) for k, v in attrs).get("href")
            self._text = []
    def handle_data(self, data):
        if self._href is not None:
            self._text.append(data)
    def handle_endtag(self, tag):
        if tag.lower() == "a" and self._href is not None:
            self.anchors.append((self._href, "".join(self._text)))
            self._href, self._text = None, []

def _assert_safe_email(subject: str, html: str) -> None:
    scan = _EmailScan(); scan.feed(html)
    if scan.tags & {"form", "input", "textarea", "select"}:
        raise ValueError("No forms or input fields in email (G2)")
    body = f"{subject}\n{html}".lower()
    for p in _CRED_ASK:
        if p in body:
            raise ValueError(f"Email asks the recipient for credentials: {p!r} (G2)")
    for url in scan.urls:
        low = url.strip().lower()
        if low.startswith(("mailto:", "tel:", "cid:", "#")):
            continue
        if not low.startswith("https://"):
            raise ValueError(f"Email links/assets must be absolute https: {url!r} (G3)")
        host = urlparse(low).hostname or ""
        if not _host_ok(host) or urlparse(low).username is not None:
            raise ValueError(f"Shortened, numeric-host or credential-bearing URL: {url!r} (G3)")
    for href, text in scan.anchors:
        real = urlparse(href.strip().lower()).hostname or ""
        if not real:
            continue
        for m in _HOSTISH.finditer(text):
            if not _same_site(m.group(1).lower(), real):
                raise ValueError(f"Anchor text {m.group(1)!r} != real link host {real!r} (G3)")

async def send_email(*, to: str, subject: str, html: str) -> Optional[str]:
    _assert_safe_email(subject, html)
    payload = {"to": [to], "subject": subject, "html": html, "from_name": EMAIL_FROM_NAME}
    try:
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.post(
                f"{EMAIL_BASE_URL}/api/v1/email/send",
                headers={"X-Email-Key": EMAIL_KEY},
                json=payload,
            )
        resp.raise_for_status()
        return resp.json().get("id")
    except httpx.HTTPStatusError as e:
        logger.error(f"Email send failed: {e.response.status_code} {e.response.text}")
        raise HTTPException(status_code=502, detail="Falha ao enviar email")
    except Exception as e:
        logger.error(f"Email send error: {str(e)}")
        raise HTTPException(status_code=500, detail="Falha ao enviar email")

# ------------------------ Models ------------------------
class LoginReq(BaseModel):
    username: str
    password: str

class ChangePwReq(BaseModel):
    current_password: str
    new_password: str

class ForgotPwReq(BaseModel):
    username: str

class ResetPwReq(BaseModel):
    username: str
    code: str
    new_password: str

class EmployeeIn(BaseModel):
    matricula: str
    name: str
    cpf: Optional[str] = None
    role: Optional[str] = None
    pin: str
    weekly_hours: int = 40

class EmployeeUpdate(BaseModel):
    matricula: Optional[str] = None
    name: Optional[str] = None
    cpf: Optional[str] = None
    role: Optional[str] = None
    pin: Optional[str] = None
    weekly_hours: Optional[int] = None
    active: Optional[bool] = None

class MatriculaLookup(BaseModel):
    matricula: str

class PunchReq(BaseModel):
    employee_id: str
    pin: str

class PunchVerifyReq(BaseModel):
    employee_id: str
    pin: str

class CompanyIn(BaseModel):
    name: str
    cnpj: Optional[str] = None
    address: Optional[str] = None
    admin_email: Optional[str] = None
    expected_entry_time: Optional[str] = "08:00"  # HH:MM
    tolerance_minutes: Optional[int] = 10
    auto_send_biweekly: Optional[bool] = True

class ManualPunchReq(BaseModel):
    employee_id: str
    kind: Literal["entrada", "intervalo_saida", "intervalo_retorno", "saida"]
    shift_date: str  # YYYY-MM-DD (the shift/entrada day)
    time: str  # HH:MM (local BR time)
    note: Optional[str] = None

class AbsenceIn(BaseModel):
    employee_id: str
    date: str  # YYYY-MM-DD
    type: str = "atestado"  # atestado | folga | ferias | outro
    note: Optional[str] = None

class RemoveEmployeeReq(BaseModel):
    reason: str
    recipient_email: Optional[EmailStr] = None

class ReportReq(BaseModel):
    employee_id: Optional[str] = None  # None -> all employees (general)
    start_date: str  # YYYY-MM-DD
    end_date: str    # YYYY-MM-DD

class SendReportReq(ReportReq):
    email: EmailStr

# ------------------------ Startup ------------------------
@app.on_event("startup")
async def seed():
    # Admin default
    admin_existente = await db.admins.find_one({"username": "admin"})
    if admin_existente:
        await db.admins.update_one(
        {"username": "admin"},
        {"$set": {"password_hash": hash_pw("Adm1234")}}
        )
        logger.info("Senha do Administrador atualizada com sucesso para: Adm1234")
    else:
        await db.admins.insert_one({
            "id": str(uuid.uuid4()),
            "username": "admin",
            "password_hash": hash_pw("Adm1234"),
            "created_at": now_utc().isoformat(),
        })
        logger.info("novo administrador criado com sucesso: admin / Adm1234")

    # Company default
    if await db.company.count_documents({}) == 0:
        await db.company.insert_one({
            "id": "singleton",
            "name": "Minha Empresa Ltda",
            "cnpj": "",
            "address": "",
            "admin_email": "delivered@resend.dev",
            "expected_entry_time": "08:00",
            "tolerance_minutes": 10,
            "auto_send_biweekly": True,
        })
    else:
        # ensure new keys exist on legacy docs
        await db.company.update_one(
            {"id": "singleton"},
            {"$setOnInsert": {}, "$set": {}},
        )
        c = await db.company.find_one({"id": "singleton"}) or {}
        defaults = {"expected_entry_time": "08:00", "tolerance_minutes": 10, "auto_send_biweekly": True}
        missing = {k: v for k, v in defaults.items() if k not in c}
        if missing:
            await db.company.update_one({"id": "singleton"}, {"$set": missing})
    # Backfill matricula for legacy employees (auto-generate sequential)
    seq = 1
    async for emp in db.employees.find({"matricula": {"$in": [None, ""]}}, {"id": 1}):
        while await db.employees.find_one({"matricula": f"{seq:04d}"}):
            seq += 1
        await db.employees.update_one({"id": emp["id"]}, {"$set": {"matricula": f"{seq:04d}"}})
        seq += 1
    # Kick off auto-scheduler task
    asyncio.create_task(_scheduler_loop())

@app.on_event("shutdown")
async def shutdown_db_client():
    mongo_client.close()

# ------------------------ Auth ------------------------
@api.post("/auth/login")
async def login(req: LoginReq):
    admin = await db.admins.find_one({"username": req.username})
    if not admin or not verify_pw(req.password, admin["password_hash"]):
        raise HTTPException(status_code=401, detail="Credenciais invalidas")
    return {"token": make_token(admin["username"]), "username": admin["username"]}

@api.post("/auth/change-password")
async def change_password(req: ChangePwReq, admin=Depends(get_admin)):
    full = await db.admins.find_one({"username": admin["username"]})
    if not verify_pw(req.current_password, full["password_hash"]):
        raise HTTPException(status_code=400, detail="Senha atual incorreta")
    if len(req.new_password) < 6:
        raise HTTPException(status_code=400, detail="Nova senha muito curta")
    await db.admins.update_one({"username": admin["username"]}, {"$set": {"password_hash": hash_pw(req.new_password)}})
    return {"ok": True}

@api.post("/auth/forgot-password")
async def forgot_password(req: ForgotPwReq):
    admin = await db.admins.find_one({"username": req.username})
    if not admin:
        # Do not leak existence; still respond ok
        return {"ok": True}
    company = await db.company.find_one({"id": "singleton"}, {"_id": 0}) or {}
    to_email = company.get("admin_email") or "delivered@resend.dev"
    code = f"{secrets.randbelow(1000000):06d}"
    expires = now_utc() + timedelta(minutes=15)
    await db.pw_resets.update_one(
        {"username": req.username},
        {"$set": {"code": code, "expires_at": expires.isoformat(), "used": False}},
        upsert=True,
    )
    subject = f"Codigo de recuperacao - {EMAIL_FROM_NAME}"
    html = (
        f'<table role="presentation" width="100%"><tr><td style="padding:24px;'
        f'font-family:Arial,sans-serif;color:#0F172A">'
        f'<h2 style="color:#1D4ED8;margin:0 0 16px 0">{escape(EMAIL_FROM_NAME)}</h2>'
        f'<p>Ola,</p>'
        f'<p>Recebemos uma solicitacao para redefinir a senha do administrador '
        f'<strong>{escape(req.username)}</strong>.</p>'
        f'<p>Seu codigo de recuperacao (valido por 15 minutos):</p>'
        f'<p style="font-size:28px;font-weight:bold;letter-spacing:6px;'
        f'background:#DBEAFE;color:#1E40AF;padding:16px;text-align:center;'
        f'border-radius:8px">{escape(code)}</p>'
        f'<p>Se voce nao solicitou, ignore este email.</p>'
        f'<p style="font-size:12px;color:#64748B;margin-top:24px">'
        f'Enviado por {escape(EMAIL_FROM_NAME)}. Nunca compartilhe seu codigo com terceiros.'
        f'</p></td></tr></table>'
    )
    await send_email(to=to_email, subject=subject, html=html)
    return {"ok": True, "sent_to_hint": to_email[:3] + "***@" + to_email.split("@")[-1]}

@api.post("/auth/reset-password")
async def reset_password(req: ResetPwReq):
    rec = await db.pw_resets.find_one({"username": req.username}, {"_id": 0})
    if not rec or rec.get("used"):
        raise HTTPException(status_code=400, detail="Codigo invalido")
    if datetime.fromisoformat(rec["expires_at"]) < now_utc():
        raise HTTPException(status_code=400, detail="Codigo expirado")
    if rec["code"] != req.code:
        raise HTTPException(status_code=400, detail="Codigo invalido")
    if len(req.new_password) < 6:
        raise HTTPException(status_code=400, detail="Nova senha muito curta")
    await db.admins.update_one({"username": req.username}, {"$set": {"password_hash": hash_pw(req.new_password)}})
    await db.pw_resets.update_one({"username": req.username}, {"$set": {"used": True}})
    return {"ok": True}

# ------------------------ Company ------------------------
@api.get("/company")
async def get_company():
    c = await db.company.find_one({"id": "singleton"}, {"_id": 0})
    return c or {}

@api.put("/company")
async def update_company(req: CompanyIn, admin=Depends(get_admin)):
    await db.company.update_one({"id": "singleton"}, {"$set": req.dict()}, upsert=True)
    return await db.company.find_one({"id": "singleton"}, {"_id": 0})

# ------------------------ Employees ------------------------
@api.get("/employees")
async def list_employees(include_inactive: bool = False):
    q = {} if include_inactive else {"active": True}
    docs = await db.employees.find(q, {"_id": 0, "pin_hash": 0}).sort("name", 1).to_list(1000)
    return docs

@api.post("/employees")
async def create_employee(req: EmployeeIn, admin=Depends(get_admin)):
    if not req.pin.isdigit() or len(req.pin) < 4 or len(req.pin) > 8:
        raise HTTPException(status_code=400, detail="PIN deve ter 4-8 digitos")
    if not req.name.strip():
        raise HTTPException(status_code=400, detail="Nome obrigatorio")
    matricula = req.matricula.strip()
    if not matricula:
        raise HTTPException(status_code=400, detail="Matricula obrigatoria")
    if await db.employees.find_one({"matricula": matricula}):
        raise HTTPException(status_code=400, detail="Matricula ja cadastrada")
    eid = str(uuid.uuid4())
    doc = {
        "id": eid,
        "matricula": matricula,
        "name": req.name.strip(),
        "cpf": req.cpf or "",
        "role": req.role or "",
        "weekly_hours": req.weekly_hours,
        "pin_hash": hash_pw(req.pin),
        "active": True,
        "created_at": now_utc().isoformat(),
    }
    await db.employees.insert_one(doc)
    doc.pop("pin_hash", None)
    doc.pop("_id", None)
    return doc

@api.put("/employees/{eid}")
async def update_employee(eid: str, req: EmployeeUpdate, admin=Depends(get_admin)):
    upd = {k: v for k, v in req.dict().items() if v is not None and k != "pin"}
    if req.pin is not None:
        if not req.pin.isdigit() or len(req.pin) < 4 or len(req.pin) > 8:
            raise HTTPException(status_code=400, detail="PIN deve ter 4-8 digitos")
        upd["pin_hash"] = hash_pw(req.pin)
    if "matricula" in upd:
        upd["matricula"] = upd["matricula"].strip()
        if not upd["matricula"]:
            raise HTTPException(status_code=400, detail="Matricula invalida")
        existing = await db.employees.find_one({"matricula": upd["matricula"], "id": {"$ne": eid}})
        if existing:
            raise HTTPException(status_code=400, detail="Matricula ja cadastrada")
    if not upd:
        raise HTTPException(status_code=400, detail="Nada para atualizar")
    r = await db.employees.update_one({"id": eid}, {"$set": upd})
    if r.matched_count == 0:
        raise HTTPException(status_code=404, detail="Colaborador nao encontrado")
    return await db.employees.find_one({"id": eid}, {"_id": 0, "pin_hash": 0})

@api.delete("/employees/{eid}")
async def deactivate_employee(eid: str, admin=Depends(get_admin)):
    r = await db.employees.update_one({"id": eid}, {"$set": {"active": False}})
    if r.matched_count == 0:
        raise HTTPException(status_code=404, detail="Colaborador nao encontrado")
    return {"ok": True}

@api.post("/employees/{eid}/remove")
async def remove_employee(eid: str, req: RemoveEmployeeReq, admin=Depends(get_admin)):
    """Remove (deactivate) an employee with a justification and email notification.
    Employee data + reason is emailed to recipient_email (falls back to company admin_email).
    Punch history is preserved so past reports remain valid."""
    if not req.reason.strip():
        raise HTTPException(status_code=400, detail="Justificativa obrigatoria")
    emp = await db.employees.find_one({"id": eid}, {"_id": 0, "pin_hash": 0})
    if not emp:
        raise HTTPException(status_code=404, detail="Colaborador nao encontrado")
    company = await db.company.find_one({"id": "singleton"}, {"_id": 0}) or {}
    to_email = req.recipient_email or company.get("admin_email")
    if not to_email:
        raise HTTPException(status_code=400, detail="Nenhum email de destino configurado")

    subject = f"Remocao de colaborador - {emp['name']}"
    when = local_now().strftime("%d/%m/%Y %H:%M")
    html = (
        f'<table role="presentation" width="100%"><tr><td style="padding:24px;'
        f'font-family:Arial,sans-serif;color:#0F172A">'
        f'<h2 style="color:#1D4ED8;margin:0 0 8px 0">{escape(EMAIL_FROM_NAME)} - Remocao de colaborador</h2>'
        f'<p><b>Empresa:</b> {escape(company.get("name",""))}<br/>'
        f'<b>Data/Hora:</b> {escape(when)}<br/>'
        f'<b>Administrador:</b> {escape(admin["username"])}</p>'
        f'<h3 style="margin:16px 0 8px 0;color:#0F172A">Dados do colaborador</h3>'
        f'<table role="presentation" style="border-collapse:collapse;font-size:13px">'
        f'<tr><td style="padding:4px 12px 4px 0;color:#64748B">Matricula</td><td style="padding:4px 0"><b>{escape(emp.get("matricula",""))}</b></td></tr>'
        f'<tr><td style="padding:4px 12px 4px 0;color:#64748B">Nome</td><td style="padding:4px 0"><b>{escape(emp["name"])}</b></td></tr>'
        f'<tr><td style="padding:4px 12px 4px 0;color:#64748B">CPF</td><td style="padding:4px 0">{escape(emp.get("cpf",""))}</td></tr>'
        f'<tr><td style="padding:4px 12px 4px 0;color:#64748B">Cargo</td><td style="padding:4px 0">{escape(emp.get("role",""))}</td></tr>'
        f'<tr><td style="padding:4px 12px 4px 0;color:#64748B">Horas semanais</td><td style="padding:4px 0">{emp.get("weekly_hours","")}</td></tr>'
        f'<tr><td style="padding:4px 12px 4px 0;color:#64748B">Cadastrado em</td><td style="padding:4px 0">{escape(emp.get("created_at",""))}</td></tr>'
        f'</table>'
        f'<h3 style="margin:16px 0 8px 0;color:#0F172A">Justificativa</h3>'
        f'<p style="background:#FEF3C7;color:#92400E;padding:12px;border-radius:8px;'
        f'white-space:pre-wrap">{escape(req.reason)}</p>'
        f'<p style="font-size:12px;color:#64748B;margin-top:24px">'
        f'Registro de auditoria gerado por {escape(EMAIL_FROM_NAME)}. O historico de pontos '
        f'deste colaborador foi mantido para consulta em relatorios anteriores.'
        f'</p></td></tr></table>'
    )
    await send_email(to=to_email, subject=subject, html=html)
    await db.employees.update_one(
        {"id": eid},
        {"$set": {
            "active": False,
            "removed_at": now_utc().isoformat(),
            "removed_by": admin["username"],
            "remove_reason": req.reason.strip(),
            "remove_notified_to": to_email,
        }},
    )
    return {"ok": True, "sent_to": to_email}

@api.post("/employees/lookup")
async def employee_lookup(req: MatriculaLookup):
    """Public: given a matricula, return minimal employee info to proceed to PIN entry."""
    mat = req.matricula.strip()
    if not mat:
        raise HTTPException(status_code=400, detail="Informe a matricula")
    emp = await db.employees.find_one({"matricula": mat, "active": True}, {"_id": 0, "pin_hash": 0})
    if not emp:
        raise HTTPException(status_code=404, detail="Matricula nao encontrada")
    return {"id": emp["id"], "name": emp["name"], "matricula": emp["matricula"], "role": emp.get("role", "")}

# ------------------------ Punches ------------------------
def local_now():
    return datetime.now(BR_TZ)

def start_of_day(dt: datetime):
    return dt.replace(hour=0, minute=0, second=0, microsecond=0)

@api.post("/punches/verify-pin")
async def verify_pin(req: PunchVerifyReq):
    """Validate PIN before showing biometric prompt on device."""
    emp = await db.employees.find_one({"id": req.employee_id, "active": True})
    if not emp:
        raise HTTPException(status_code=404, detail="Colaborador nao encontrado")
    if not verify_pw(req.pin, emp["pin_hash"]):
        raise HTTPException(status_code=401, detail="PIN incorreto")
    # Compute next kind for UI preview
    shift_date, next_kind = await _resolve_next_punch(req.employee_id)
    return {"ok": True, "name": emp["name"], "next_kind": next_kind, "shift_date": shift_date}

_KIND_ORDER = ["entrada", "intervalo_saida", "intervalo_retorno", "saida"]

async def _resolve_next_punch(employee_id: str):
    """Return (shift_date, next_kind).
    Rule: cross-midnight — a punch after 00:00 still belongs to the shift whose
    "entrada" is the most recent one that has NOT yet been closed with "saida".
    If today already has all 4 punches OR no open shift exists, a new shift starts
    on today's local date with next_kind = "entrada".
    """
    today = local_now().date().isoformat()
    # Find the latest entrada punch for this employee (any date)
    latest_entrada = await db.punches.find_one(
        {"employee_id": employee_id, "kind": "entrada"},
        {"_id": 0},
        sort=[("timestamp", -1)],
    )
    if latest_entrada:
        shift_date = latest_entrada["local_date"]
        shift_kinds = await db.punches.find(
            {"employee_id": employee_id, "local_date": shift_date}, {"_id": 0, "kind": 1}
        ).to_list(20)
        kinds_set = {k["kind"] for k in shift_kinds}
        # If shift already has all 4 → new shift today
        if "saida" in kinds_set:
            # closed shift; if the closed shift is today, no more punches today
            if shift_date == today:
                return today, None  # nothing more to punch today
            return today, "entrada"
        # Determine next in order
        for k in _KIND_ORDER:
            if k not in kinds_set:
                return shift_date, k
    # No entrada ever → next is entrada today
    return today, "entrada"

@api.post("/punches")
async def create_punch(req: PunchReq):
    emp = await db.employees.find_one({"id": req.employee_id, "active": True})
    if not emp:
        raise HTTPException(status_code=404, detail="Colaborador nao encontrado")
    if not verify_pw(req.pin, emp["pin_hash"]):
        raise HTTPException(status_code=401, detail="PIN incorreto")
    shift_date, next_kind = await _resolve_next_punch(req.employee_id)
    if not next_kind:
        raise HTTPException(
            status_code=400,
            detail="Todas as marcacoes de hoje ja foram registradas para este colaborador",
        )
    # Guard: prevent duplicate in the same shift (should not happen given resolution, defense in depth)
    dup = await db.punches.find_one(
        {"employee_id": req.employee_id, "local_date": shift_date, "kind": next_kind}
    )
    if dup:
        raise HTTPException(status_code=400, detail=f"Marcacao '{next_kind}' ja registrada neste turno")
    doc = {
        "id": str(uuid.uuid4()),
        "employee_id": req.employee_id,
        "employee_name": emp["name"],
        "kind": next_kind,
        "timestamp": now_utc().isoformat(),
        "local_date": shift_date,  # tied to the shift (day of the entrada)
    }
    await db.punches.insert_one(doc)
    doc.pop("_id", None)
    return doc

@api.get("/punches/today")
async def punches_today(admin=Depends(get_admin)):
    today = local_now().date().isoformat()
    docs = await db.punches.find({"local_date": today}, {"_id": 0}).sort("timestamp", -1).to_list(1000)
    return docs

@api.get("/punches/employee/{eid}")
async def punches_employee(eid: str, start: str, end: str, admin=Depends(get_admin)):
    docs = await db.punches.find(
        {"employee_id": eid, "local_date": {"$gte": start, "$lte": end}}, {"_id": 0}
    ).sort("timestamp", 1).to_list(5000)
    return docs

@api.get("/punches/day/{eid}")
async def punches_day(eid: str, date: str):
    """Public 'day mirror': returns the 4 punches of a given shift for an employee.
    date = shift_date (YYYY-MM-DD)."""
    emp = await db.employees.find_one({"id": eid}, {"_id": 0, "pin_hash": 0})
    if not emp:
        raise HTTPException(status_code=404, detail="Colaborador nao encontrado")
    docs = await db.punches.find(
        {"employee_id": eid, "local_date": date}, {"_id": 0}
    ).sort("timestamp", 1).to_list(20)
    by_kind: Dict[str, dict] = {}
    for d in docs:
        by_kind[d["kind"]] = d
    return {"employee": {"id": emp["id"], "name": emp["name"], "matricula": emp.get("matricula", "")}, "date": date, "marks": by_kind}

@api.post("/punches/manual")
async def create_manual_punch(req: ManualPunchReq, admin=Depends(get_admin)):
    """Admin-only: register a punch on behalf of a collaborator who couldn't punch.
    Enforces unique kind per shift_date."""
    emp = await db.employees.find_one({"id": req.employee_id})
    if not emp:
        raise HTTPException(status_code=404, detail="Colaborador nao encontrado")
    # Validate time HH:MM
    try:
        hh, mm = req.time.split(":")
        h, m = int(hh), int(mm)
        assert 0 <= h < 24 and 0 <= m < 60
    except Exception:
        raise HTTPException(status_code=400, detail="Horario invalido (use HH:MM)")
    try:
        sd = date.fromisoformat(req.shift_date)
    except Exception:
        raise HTTPException(status_code=400, detail="Data invalida")
    # For intervalo/saida that occur after midnight, admin should still use the entrada's shift_date
    # We record the timestamp using the natural clock time; if the kind is not entrada AND the shift already has an entrada AND HH:MM < entrada HH:MM, treat as next day.
    day_punches = await db.punches.find({"employee_id": req.employee_id, "local_date": req.shift_date}, {"_id": 0}).to_list(20)
    if any(p["kind"] == req.kind for p in day_punches):
        raise HTTPException(status_code=400, detail=f"Marcacao '{req.kind}' ja registrada neste turno")
    # Determine actual date for timestamp (cross-midnight for later kinds)
    ts_date = sd
    entrada = next((p for p in day_punches if p["kind"] == "entrada"), None)
    if entrada and req.kind != "entrada":
        ent_local = parse_iso(entrada["timestamp"])
        cand_local = datetime(sd.year, sd.month, sd.day, h, m, tzinfo=BR_TZ)
        if cand_local < ent_local:
            ts_date = sd + timedelta(days=1)
    ts_local = datetime(ts_date.year, ts_date.month, ts_date.day, h, m, tzinfo=BR_TZ)
    ts_utc = ts_local.astimezone(timezone.utc)
    doc = {
        "id": str(uuid.uuid4()),
        "employee_id": req.employee_id,
        "employee_name": emp["name"],
        "kind": req.kind,
        "timestamp": ts_utc.isoformat(),
        "local_date": req.shift_date,
        "manual": True,
        "manual_by": admin["username"],
        "manual_note": req.note or "",
    }
    await db.punches.insert_one(doc)
    doc.pop("_id", None)
    return doc

@api.delete("/punches/{pid}")
async def delete_punch(pid: str, admin=Depends(get_admin)):
    r = await db.punches.delete_one({"id": pid})
    if r.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Marcacao nao encontrada")
    return {"ok": True}

# ------------------------ Absences ------------------------
@api.get("/absences")
async def list_absences(start: Optional[str] = None, end: Optional[str] = None, employee_id: Optional[str] = None, admin=Depends(get_admin)):
    q: Dict = {}
    if employee_id:
        q["employee_id"] = employee_id
    if start or end:
        q["date"] = {}
        if start:
            q["date"]["$gte"] = start
        if end:
            q["date"]["$lte"] = end
    docs = await db.absences.find(q, {"_id": 0}).sort("date", -1).to_list(1000)
    return docs

@api.post("/absences")
async def create_absence(req: AbsenceIn, admin=Depends(get_admin)):
    emp = await db.employees.find_one({"id": req.employee_id})
    if not emp:
        raise HTTPException(status_code=404, detail="Colaborador nao encontrado")
    try:
        date.fromisoformat(req.date)
    except Exception:
        raise HTTPException(status_code=400, detail="Data invalida")
    doc = {
        "id": str(uuid.uuid4()),
        "employee_id": req.employee_id,
        "employee_name": emp["name"],
        "date": req.date,
        "type": req.type,
        "note": req.note or "",
        "created_at": now_utc().isoformat(),
    }
    await db.absences.insert_one(doc)
    doc.pop("_id", None)
    return doc

@api.delete("/absences/{aid}")
async def delete_absence(aid: str, admin=Depends(get_admin)):
    r = await db.absences.delete_one({"id": aid})
    if r.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Ausencia nao encontrada")
    return {"ok": True}

# ------------------------ Report calculation ------------------------

def parse_iso(s: str) -> datetime:
    return datetime.fromisoformat(s.replace("Z", "+00:00")).astimezone(BR_TZ)

def compute_day(punches: List[dict]) -> dict:
    """From a day's punches (sorted), compute totals in minutes."""
    order = ["entrada", "intervalo_saida", "intervalo_retorno", "saida"]
    by_kind = {}
    for p in sorted(punches, key=lambda x: x["timestamp"]):
        by_kind[p["kind"]] = parse_iso(p["timestamp"])
    entrada = by_kind.get("entrada")
    isaida = by_kind.get("intervalo_saida")
    iretorno = by_kind.get("intervalo_retorno")
    saida = by_kind.get("saida")
    worked = 0
    if entrada and saida:
        total = (saida - entrada).total_seconds() / 60
        interval = 0
        if isaida and iretorno:
            interval = (iretorno - isaida).total_seconds() / 60
        worked = max(0, total - interval)
    return {
        "entrada": entrada.strftime("%H:%M") if entrada else "",
        "intervalo_saida": isaida.strftime("%H:%M") if isaida else "",
        "intervalo_retorno": iretorno.strftime("%H:%M") if iretorno else "",
        "saida": saida.strftime("%H:%M") if saida else "",
        "worked_min": int(worked),
    }

def overtime_split(worked_min: int, weekday: int) -> dict:
    """weekday: 0=Mon..6=Sun. Returns {'regular','ot50','ot100'} minutes.
    Rules requested: Mon-Fri 8h base, above = ot50 (extra). Saturday all extra (ot50). Sunday 100% (ot100)."""
    base = 8 * 60
    if weekday <= 4:  # Mon-Fri
        regular = min(worked_min, base)
        ot50 = max(0, worked_min - base)
        ot100 = 0
    elif weekday == 5:  # Sat
        regular = 0
        ot50 = worked_min
        ot100 = 0
    else:  # Sun
        regular = 0
        ot50 = 0
        ot100 = worked_min
    return {"regular": regular, "ot50": ot50, "ot100": ot100}

def fmt_hm(mins: int) -> str:
    h = mins // 60
    m = mins % 60
    return f"{h:02d}:{m:02d}"

async def build_report_data(employee_id: str, start_date: str, end_date: str):
    emp = await db.employees.find_one({"id": employee_id}, {"_id": 0, "pin_hash": 0})
    if not emp:
        raise HTTPException(status_code=404, detail="Colaborador nao encontrado")
    company = await db.company.find_one({"id": "singleton"}, {"_id": 0}) or {}
    punches = await db.punches.find(
        {"employee_id": employee_id, "local_date": {"$gte": start_date, "$lte": end_date}}, {"_id": 0}
    ).sort("timestamp", 1).to_list(5000)
    absences = await db.absences.find(
        {"employee_id": employee_id, "date": {"$gte": start_date, "$lte": end_date}}, {"_id": 0}
    ).to_list(1000)
    abs_by_date = {a["date"]: a for a in absences}
    # group by day
    days = {}
    for p in punches:
        days.setdefault(p["local_date"], []).append(p)
    # build day rows for every day in range
    sd = date.fromisoformat(start_date)
    ed = date.fromisoformat(end_date)
    rows = []
    tot = {"regular": 0, "ot50": 0, "ot100": 0, "worked": 0}
    weekday_names = ["Seg", "Ter", "Qua", "Qui", "Sex", "Sab", "Dom"]
    d = sd
    while d <= ed:
        iso = d.isoformat()
        day_p = days.get(iso, [])
        info = compute_day(day_p)
        split = overtime_split(info["worked_min"], d.weekday())
        absence = abs_by_date.get(iso)
        absence_type = ""
        # If no punches AND there's an absence AND it's a weekday, credit 8h regular
        if absence and info["worked_min"] == 0:
            absence_type = absence.get("type", "atestado")
            if d.weekday() <= 4:
                split = {"regular": 8 * 60, "ot50": 0, "ot100": 0}
        rows.append({
            "date": d.strftime("%d/%m/%Y"),
            "wd": weekday_names[d.weekday()],
            **info,
            "worked_hm": fmt_hm(info["worked_min"]),
            "regular_hm": fmt_hm(split["regular"]),
            "ot50_hm": fmt_hm(split["ot50"]),
            "ot100_hm": fmt_hm(split["ot100"]),
            "absence": absence_type,
        })
        tot["regular"] += split["regular"]
        tot["ot50"] += split["ot50"]
        tot["ot100"] += split["ot100"]
        tot["worked"] += info["worked_min"]
        d += timedelta(days=1)
    return {
        "company": company,
        "employee": emp,
        "start_date": start_date,
        "end_date": end_date,
        "rows": rows,
        "totals": {k: fmt_hm(v) for k, v in tot.items()},
    }

# ------------------------ PDF ------------------------

def render_pdf(data: dict) -> bytes:
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, leftMargin=1.5*cm, rightMargin=1.5*cm, topMargin=1.5*cm, bottomMargin=1.5*cm)
    styles = getSampleStyleSheet()
    h1 = ParagraphStyle("h1", parent=styles["Heading1"], fontSize=16, textColor=rl_colors.HexColor("#1D4ED8"))
    h2 = ParagraphStyle("h2", parent=styles["Heading2"], fontSize=12, textColor=rl_colors.HexColor("#0F172A"))
    normal = ParagraphStyle("n", parent=styles["Normal"], fontSize=9)
    small = ParagraphStyle("s", parent=styles["Normal"], fontSize=8, textColor=rl_colors.HexColor("#64748B"))

    story = []
    company = data["company"]
    emp = data["employee"]
    story.append(Paragraph("FOLHA DE PONTO QUINZENAL", h1))
    story.append(Spacer(1, 6))
    story.append(Paragraph(f"<b>Empresa:</b> {escape(company.get('name',''))}", normal))
    if company.get("cnpj"):
        story.append(Paragraph(f"<b>CNPJ:</b> {escape(company.get('cnpj',''))}", normal))
    if company.get("address"):
        story.append(Paragraph(f"<b>Endereco:</b> {escape(company.get('address',''))}", normal))
    story.append(Spacer(1, 8))
    story.append(Paragraph(f"<b>Colaborador:</b> {escape(emp['name'])}", normal))
    if emp.get("cpf"):
        story.append(Paragraph(f"<b>CPF:</b> {escape(emp['cpf'])}", normal))
    if emp.get("role"):
        story.append(Paragraph(f"<b>Cargo:</b> {escape(emp['role'])}", normal))
    story.append(Paragraph(f"<b>Periodo:</b> {data['start_date']} a {data['end_date']}", normal))
    story.append(Spacer(1, 10))

    header = ["Data", "Dia", "Entrada", "Int.Saida", "Int.Retorno", "Saida", "Trab.", "Normal", "HE 50%", "HE 100%"]
    table_data = [header]
    for r in data["rows"]:
        table_data.append([
            r["date"], r["wd"], r["entrada"], r["intervalo_saida"], r["intervalo_retorno"], r["saida"],
            r["worked_hm"], r["regular_hm"], r["ot50_hm"], r["ot100_hm"],
        ])
    t = Table(table_data, repeatRows=1, colWidths=[1.9*cm, 1.1*cm, 1.6*cm, 1.7*cm, 1.9*cm, 1.5*cm, 1.4*cm, 1.4*cm, 1.4*cm, 1.5*cm])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,0), rl_colors.HexColor("#1D4ED8")),
        ("TEXTCOLOR", (0,0), (-1,0), rl_colors.white),
        ("FONTSIZE", (0,0), (-1,-1), 8),
        ("ALIGN", (0,0), (-1,-1), "CENTER"),
        ("GRID", (0,0), (-1,-1), 0.3, rl_colors.HexColor("#CBD5E1")),
        ("ROWBACKGROUNDS", (0,1), (-1,-1), [rl_colors.white, rl_colors.HexColor("#F1F5F9")]),
    ]))
    story.append(t)
    story.append(Spacer(1, 12))

    tot = data["totals"]
    tot_table = Table([
        ["Total trabalhado", "Horas normais", "HE 50% (Seg-Sab)", "HE 100% (Dom/Feriado)"],
        [tot["worked"], tot["regular"], tot["ot50"], tot["ot100"]],
    ], colWidths=[4*cm, 4*cm, 4*cm, 4.5*cm])
    tot_table.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,0), rl_colors.HexColor("#DBEAFE")),
        ("TEXTCOLOR", (0,0), (-1,0), rl_colors.HexColor("#1E40AF")),
        ("FONTSIZE", (0,0), (-1,-1), 10),
        ("ALIGN", (0,0), (-1,-1), "CENTER"),
        ("GRID", (0,0), (-1,-1), 0.3, rl_colors.HexColor("#CBD5E1")),
        ("FONTNAME", (0,1), (-1,1), "Helvetica-Bold"),
    ]))
    story.append(tot_table)
    story.append(Spacer(1, 24))

    story.append(Paragraph("Regras: Seg-Sex 8h base (excedente = HE 50%). Sabado = HE 50%. Domingo = HE 100%.", small))
    story.append(Spacer(1, 30))

    sig = Table([
        ["_______________________________", "_______________________________", "_______________________________"],
        ["Colaborador", "Chefia Imediata", "Gerencia"],
    ], colWidths=[6*cm, 6*cm, 6*cm])
    sig.setStyle(TableStyle([
        ("ALIGN", (0,0), (-1,-1), "CENTER"),
        ("FONTSIZE", (0,0), (-1,-1), 9),
    ]))
    story.append(sig)

    doc.build(story)
    return buf.getvalue()

# ------------------------ Report endpoints ------------------------

async def _resolve_targets(employee_id: Optional[str]) -> List[dict]:
    if employee_id:
        emp = await db.employees.find_one({"id": employee_id}, {"_id": 0, "pin_hash": 0})
        if not emp:
            raise HTTPException(status_code=404, detail="Colaborador nao encontrado")
        return [emp]
    return await db.employees.find({"active": True}, {"_id": 0, "pin_hash": 0}).sort("name", 1).to_list(1000)

@api.post("/reports/data")
async def report_data(req: ReportReq, admin=Depends(get_admin)):
    """Return computed report data (JSON) for preview."""
    targets = await _resolve_targets(req.employee_id)
    out = []
    for e in targets:
        out.append(await build_report_data(e["id"], req.start_date, req.end_date))
    return {"reports": out}

@api.post("/reports/pdf")
async def report_pdf(req: ReportReq, admin=Depends(get_admin)):
    if not req.employee_id:
        raise HTTPException(status_code=400, detail="Selecione um colaborador para gerar o PDF")
    data = await build_report_data(req.employee_id, req.start_date, req.end_date)
    pdf = render_pdf(data)
    return StreamingResponse(
        io.BytesIO(pdf),
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename=folha-ponto.pdf"},
    )

@api.post("/reports/send")
async def report_send(req: SendReportReq, admin=Depends(get_admin)):
    """Generate PDF and email a summary. PDF attachment not supported by proxy; we send a summary + link/instructions."""
    targets = await _resolve_targets(req.employee_id)
    lines = []
    for e in targets:
        data = await build_report_data(e["id"], req.start_date, req.end_date)
        tot = data["totals"]
        lines.append(
            f"<tr><td style='padding:6px;border-bottom:1px solid #E2E8F0'>{escape(e['name'])}</td>"
            f"<td style='padding:6px;border-bottom:1px solid #E2E8F0;text-align:center'>{tot['worked']}</td>"
            f"<td style='padding:6px;border-bottom:1px solid #E2E8F0;text-align:center'>{tot['regular']}</td>"
            f"<td style='padding:6px;border-bottom:1px solid #E2E8F0;text-align:center'>{tot['ot50']}</td>"
            f"<td style='padding:6px;border-bottom:1px solid #E2E8F0;text-align:center'>{tot['ot100']}</td></tr>"
        )
    company = await db.company.find_one({"id": "singleton"}, {"_id": 0}) or {}
    html = (
        f'<table role="presentation" width="100%"><tr><td style="padding:24px;font-family:Arial,sans-serif;color:#0F172A">'
        f'<h2 style="color:#1D4ED8;margin:0 0 8px 0">{escape(EMAIL_FROM_NAME)} - Resumo de Folha de Ponto</h2>'
        f'<p><b>Empresa:</b> {escape(company.get("name",""))}<br/>'
        f'<b>Periodo:</b> {escape(req.start_date)} a {escape(req.end_date)}</p>'
        f'<table role="presentation" width="100%" style="border-collapse:collapse;font-size:13px">'
        f'<thead><tr style="background:#DBEAFE;color:#1E40AF">'
        f'<th style="padding:8px;text-align:left">Colaborador</th>'
        f'<th style="padding:8px">Trab.</th><th style="padding:8px">Normal</th>'
        f'<th style="padding:8px">HE 50%</th><th style="padding:8px">HE 100%</th></tr></thead>'
        f'<tbody>{"".join(lines)}</tbody></table>'
        f'<p style="margin-top:16px">O PDF completo pode ser baixado no aplicativo pela area de Relatorios.</p>'
        f'<p style="font-size:12px;color:#64748B;margin-top:24px">Enviado por {escape(EMAIL_FROM_NAME)}.</p>'
        f'</td></tr></table>'
    )
    subject = f"Folha de Ponto - {req.start_date} a {req.end_date}"
    await send_email(to=req.email, subject=subject, html=html)
    return {"ok": True}

def current_biweekly_range(today: Optional[date] = None):
    """Given a date, returns the biweekly closed on the day before OR on today.
    Rules: emitted on the 16th (covers 1..15) and on the last day (covers 16..last)."""
    today = today or local_now().date()
    y, m, d = today.year, today.month, today.day
    if d >= 16:
        return date(y, m, 1), date(y, m, 15)
    # first day of month: covers previous month 16..last
    prev_m = m - 1 if m > 1 else 12
    prev_y = y if m > 1 else y - 1
    last = (date(prev_y, prev_m % 12 + 1, 1) - timedelta(days=1)) if prev_m != 12 else date(prev_y, 12, 31)
    return date(prev_y, prev_m, 16), last

async def _auto_send_biweekly():
    """Send the just-closed biweekly report to admin_email. Uses today's context."""
    company = await db.company.find_one({"id": "singleton"}, {"_id": 0}) or {}
    if not company.get("auto_send_biweekly", True):
        return
    to_email = company.get("admin_email")
    if not to_email:
        return
    start, end = current_biweekly_range()
    employees = await db.employees.find({"active": True}, {"_id": 0, "pin_hash": 0}).sort("name", 1).to_list(1000)
    if not employees:
        return
    lines = []
    for e in employees:
        data = await build_report_data(e["id"], start.isoformat(), end.isoformat())
        tot = data["totals"]
        lines.append(
            f"<tr><td style='padding:6px;border-bottom:1px solid #E2E8F0'>{escape(e['name'])} ({escape(e.get('matricula',''))})</td>"
            f"<td style='padding:6px;border-bottom:1px solid #E2E8F0;text-align:center'>{tot['worked']}</td>"
            f"<td style='padding:6px;border-bottom:1px solid #E2E8F0;text-align:center'>{tot['regular']}</td>"
            f"<td style='padding:6px;border-bottom:1px solid #E2E8F0;text-align:center'>{tot['ot50']}</td>"
            f"<td style='padding:6px;border-bottom:1px solid #E2E8F0;text-align:center'>{tot['ot100']}</td></tr>"
        )
    html = (
        f'<table role="presentation" width="100%"><tr><td style="padding:24px;font-family:Arial,sans-serif;color:#0F172A">'
        f'<h2 style="color:#1D4ED8;margin:0 0 8px 0">{escape(EMAIL_FROM_NAME)} - Folha de Ponto Quinzenal</h2>'
        f'<p><b>Empresa:</b> {escape(company.get("name",""))}<br/>'
        f'<b>Periodo:</b> {start.isoformat()} a {end.isoformat()}</p>'
        f'<table role="presentation" width="100%" style="border-collapse:collapse;font-size:13px">'
        f'<thead><tr style="background:#DBEAFE;color:#1E40AF">'
        f'<th style="padding:8px;text-align:left">Colaborador</th>'
        f'<th style="padding:8px">Trab.</th><th style="padding:8px">Normal</th>'
        f'<th style="padding:8px">HE 50%</th><th style="padding:8px">HE 100%</th></tr></thead>'
        f'<tbody>{"".join(lines)}</tbody></table>'
        f'<p style="margin-top:16px">Baixe cada PDF individual no aplicativo em Relatorios.</p>'
        f'<p style="font-size:12px;color:#64748B;margin-top:24px">Enviado automaticamente por {escape(EMAIL_FROM_NAME)}.</p>'
        f'</td></tr></table>'
    )
    subject = f"Folha de Ponto Quinzenal - {start.isoformat()} a {end.isoformat()}"
    await send_email(to=to_email, subject=subject, html=html)
    await db.jobs_log.insert_one({
        "job": "auto_biweekly",
        "start": start.isoformat(),
        "end": end.isoformat(),
        "sent_to": to_email,
        "at": now_utc().isoformat(),
    })

@api.post("/reports/send-biweekly-now")
async def report_send_biweekly_now(admin=Depends(get_admin)):
    """Manual trigger: send the current biweekly summary to admin_email."""
    await _auto_send_biweekly()
    return {"ok": True}

async def _scheduler_loop():
    """Once a day at 23:00 local, if today is the 15th or the last day of the month,
    trigger the biweekly auto-send (covers 1-15 or 16-last)."""
    while True:
        try:
            now = local_now()
            target = now.replace(hour=23, minute=0, second=0, microsecond=0)
            if now >= target:
                target = target + timedelta(days=1)
            await asyncio.sleep(max(60, (target - now).total_seconds()))
            today = local_now().date()
            tomorrow = today + timedelta(days=1)
            is_last_day = tomorrow.day == 1
            if today.day == 15 or is_last_day:
                logger.info("Auto biweekly report triggered (%s)", today.isoformat())
                # Emitted "on the 16th and on the last day" per user: we send at 23:00 of 15th and last day so the file lands ready.
                # Adjust the range: at day 15 evening -> cover 1..15; last-day evening -> cover 16..last
                # current_biweekly_range() would return prev-half if called from 16, so we call while it's still 15 -> since day <= 15 branch, we override:
                y, m = today.year, today.month
                if today.day == 15:
                    start, end = date(y, m, 1), date(y, m, 15)
                else:
                    start, end = date(y, m, 16), today
                # Temporarily override by patching function inputs
                await _send_biweekly_with_range(start, end)
        except Exception as e:
            logger.error("Scheduler error: %s", e)

async def _send_biweekly_with_range(start: date, end: date):
    company = await db.company.find_one({"id": "singleton"}, {"_id": 0}) or {}
    if not company.get("auto_send_biweekly", True):
        return
    to_email = company.get("admin_email")
    if not to_email:
        return
    employees = await db.employees.find({"active": True}, {"_id": 0, "pin_hash": 0}).sort("name", 1).to_list(1000)
    if not employees:
        return
    lines = []
    for e in employees:
        data = await build_report_data(e["id"], start.isoformat(), end.isoformat())
        tot = data["totals"]
        lines.append(
            f"<tr><td style='padding:6px;border-bottom:1px solid #E2E8F0'>{escape(e['name'])} ({escape(e.get('matricula',''))})</td>"
            f"<td style='padding:6px;border-bottom:1px solid #E2E8F0;text-align:center'>{tot['worked']}</td>"
            f"<td style='padding:6px;border-bottom:1px solid #E2E8F0;text-align:center'>{tot['regular']}</td>"
            f"<td style='padding:6px;border-bottom:1px solid #E2E8F0;text-align:center'>{tot['ot50']}</td>"
            f"<td style='padding:6px;border-bottom:1px solid #E2E8F0;text-align:center'>{tot['ot100']}</td></tr>"
        )
    html = (
        f'<table role="presentation" width="100%"><tr><td style="padding:24px;font-family:Arial,sans-serif;color:#0F172A">'
        f'<h2 style="color:#1D4ED8;margin:0 0 8px 0">{escape(EMAIL_FROM_NAME)} - Folha de Ponto Quinzenal</h2>'
        f'<p><b>Empresa:</b> {escape(company.get("name",""))}<br/>'
        f'<b>Periodo:</b> {start.isoformat()} a {end.isoformat()}</p>'
        f'<table role="presentation" width="100%" style="border-collapse:collapse;font-size:13px">'
        f'<thead><tr style="background:#DBEAFE;color:#1E40AF">'
        f'<th style="padding:8px;text-align:left">Colaborador</th>'
        f'<th style="padding:8px">Trab.</th><th style="padding:8px">Normal</th>'
        f'<th style="padding:8px">HE 50%</th><th style="padding:8px">HE 100%</th></tr></thead>'
        f'<tbody>{"".join(lines)}</tbody></table>'
        f'<p style="font-size:12px;color:#64748B;margin-top:24px">Enviado automaticamente por {escape(EMAIL_FROM_NAME)}.</p>'
        f'</td></tr></table>'
    )
    subject = f"Folha de Ponto Quinzenal - {start.isoformat()} a {end.isoformat()}"
    await send_email(to=to_email, subject=subject, html=html)
    await db.jobs_log.insert_one({
        "job": "auto_biweekly",
        "start": start.isoformat(),
        "end": end.isoformat(),
        "sent_to": to_email,
        "at": now_utc().isoformat(),
    })

# ------------------------ Root ------------------------
@api.get("/")
async def root():
    return {"app": EMAIL_FROM_NAME, "status": "ok"}

# ------------------------ Wire up ------------------------
app.include_router(api)

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
app.mount("/static", StaticFiles(directory="dist"), name="static")
@app.get("/{full_path:path}")
async def serve_app(catchall: str = ""):
    return FileResponse("dist/index.html")