import os, json, time, hmac, hashlib, base64, sqlite3, uuid, urllib.request, urllib.parse
from fastapi import FastAPI, Depends, HTTPException, UploadFile, File, Form, Request
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

B = os.path.dirname(os.path.abspath(__file__))
SECRET = os.getenv("SECRET", "change-this-secret")
os.makedirs(B + "/uploads", exist_ok=True)
app = FastAPI(title="CivicAI")

def q(sql, a=(), one=False, w=False):
    c = sqlite3.connect(B + "/civicai.db"); c.row_factory = sqlite3.Row
    r = c.execute(sql, a); d = r.fetchone() if one else r.fetchall(); c.commit(); lid = r.lastrowid; c.close()
    if w: return lid
    return (dict(d) if d else None) if one else [dict(x) for x in d]

q("create table if not exists users(id integer primary key,name,email unique,phone,city,password_hash,role,created_at)")
q("""create table if not exists complaints(id integer primary key,user_id,photo_url,description,latitude,longitude,area,landmark,
created_at,ai_category,ai_subcategory,ai_urgency,ai_confidence,ai_reason,suggested_department,low_confidence,admin_category,
admin_urgency,assigned_department,override_reason,status,admin_notes,citizen_update,updated_at,resolved_photo_url)""")
try: q("alter table complaints add column resolved_photo_url")
except Exception: pass

def hp(p, s=None):
    s = s or os.urandom(8).hex()
    return s + ":" + hashlib.pbkdf2_hmac("sha256", p.encode(), s.encode(), 100000).hex()
def chk(p, h): return hmac.compare_digest(hp(p, h.split(":")[0]), h)
def sig(p): return hmac.new(SECRET.encode(), p.encode(), hashlib.sha256).hexdigest()
def tok(u):
    p = base64.urlsafe_b64encode(json.dumps({"id": u["id"], "exp": time.time() + 86400}).encode()).decode()
    return p + "." + sig(p)
def me(request: Request):
    try:
        p, s = request.headers["authorization"].split(" ")[1].split(".")
        assert hmac.compare_digest(s, sig(p))
        d = json.loads(base64.urlsafe_b64decode(p)); assert d["exp"] > time.time()
        u = q("select * from users where id=?", (d["id"],), True); assert u
        return u
    except Exception:
        raise HTTPException(401, "Please log in.")
def adm(u=Depends(me)):
    if u["role"] != "ADMIN": raise HTTPException(403, "Administrator privileges required.")
    return u

if not q("select 1 from users where role='ADMIN'", one=True):
    q("insert into users(name,email,password_hash,role,created_at) values(?,?,?,?,?)",
      ("Administrator", "admin@civicai.local", hp("Admin@123"), "ADMIN", time.ctime()))

class Reg(BaseModel): name: str; email: str; password: str; phone: str = ""; city: str = ""
class Log(BaseModel): email: str; password: str; admin: bool = False
class Dec(BaseModel):
    category: str | None = None; urgency: str | None = None; department: str | None = None; status: str | None = None
    admin_notes: str | None = None; citizen_update: str | None = None; override_reason: str | None = None

def pub(u): return {"name": u["name"], "role": u["role"], "email": u["email"], "city": u["city"]}

@app.post("/api/auth/register")
def register(r: Reg):
    if len(r.password) < 6: raise HTTPException(400, "Password must be at least 6 characters.")
    try:
        i = q("insert into users(name,email,phone,city,password_hash,role,created_at) values(?,?,?,?,?,'CITIZEN',?)",
              (r.name.strip(), r.email.lower().strip(), r.phone, r.city, hp(r.password), time.ctime()), w=True)
    except sqlite3.IntegrityError:
        raise HTTPException(400, "This email is already registered.")
    return {"token": tok({"id": i}), "user": pub(q("select * from users where id=?", (i,), True))}

def digits(s): return "".join(ch for ch in str(s or "") if ch.isdigit())[-10:]

@app.post("/api/auth/login")
def login(r: Log):
    # "email" field may hold an email address OR a phone number
    who = r.email.strip()
    cands = q("select * from users where email=?", (who.lower(),))
    if len(digits(who)) >= 7 and "@" not in who:
        cands += [x for x in q("select * from users where phone is not null and phone!=''") if digits(x["phone"]) == digits(who)]
    # a phone number can be shared by more than one account, so pick the one whose password matches
    u = next((x for x in cands if chk(r.password, x["password_hash"])), None)
    if not u: raise HTTPException(401, "Wrong email/phone or password.")
    if r.admin and u["role"] != "ADMIN": raise HTTPException(403, "Access denied: administrator privileges required.")
    return {"token": tok(u), "user": pub(u)}

# ---------- AI workflow ----------
CATS = {
 "Road / Pothole": ("Roads / Public Works", ["pothole", "road", "crack", "asphalt"]),
 "Drainage": ("Drainage Department", ["drain", "gutter"]),
 "Flooding / Waterlogging": ("Drainage Department", ["flood", "waterlog", "stagnant"]),
 "Waste": ("Waste Management", ["garbage", "trash", "waste", "dump", "litter"]),
 "Streetlight": ("Electrical / Streetlight Department", ["streetlight", "street light", "lamp"]),
 "Electricity": ("Electrical / Streetlight Department", ["wire", "electric", "pole", "transformer", "spark"]),
 "Water Supply": ("Water Supply Department", ["leak", "pipe", "water supply", "tap"]),
 "Sewage": ("Drainage Department", ["sewage", "sewer", "manhole"]),
 "Footpath": ("Roads / Public Works", ["footpath", "pavement", "sidewalk"]),
 "Traffic Infrastructure": ("Traffic / Public Works", ["signal", "traffic", "sign"]),
 "Trees / Vegetation": ("Parks & Horticulture", ["tree", "branch"]),
 "Public Property": ("Public Works", ["bench", "bridge", "building", "wall"]),
 "Other": ("Municipal Office", [])}
CRIT = ["open manhole", "exposed", "live wire", "fallen pole", "fallen tree", "spark", "overflow", "collapse", "blocked road", "accident"]
HIGH = ["large", "big", "huge", "water", "flood", "blocked", "broken", "leak", "danger", "school", "hospital", "main road"]

def rules(d):
    d = d.lower(); best = ("Other", 0)
    for c, (_, ks) in CATS.items():
        n = sum(k in d for k in ks)
        if n > best[1]: best = (c, n)
    u = "CRITICAL" if any(k in d for k in CRIT) else "HIGH" if any(k in d for k in HIGH) else "ROUTINE"
    return dict(category=best[0], subcategory=best[0], urgency=u, confidence=min(.9, .4 + .15 * best[1] + (.1 if len(d) > 60 else 0)),
                reason=f"Keyword-based estimate from the description only (no image model configured): {u.lower()} urgency.")

def watson(path, desc):
    key, pid, model = os.getenv("WATSONX_APIKEY"), os.getenv("WATSONX_PROJECT_ID"), os.getenv("WATSONX_MODEL")
    if not (key and pid and model): return None
    try:
        t = json.load(urllib.request.urlopen(urllib.request.Request("https://iam.cloud.ibm.com/identity/token",
            urllib.parse.urlencode({"grant_type": "urn:ibm:params:oauth:grant-type:apikey", "apikey": key}).encode(),
            {"Content-Type": "application/x-www-form-urlencoded"})))["access_token"]
        img = base64.b64encode(open(path, "rb").read()).decode()
        prompt = ("You analyse civic complaints. Describe only what is visible. Reply with JSON only: "
                  '{"category": one of %s, "subcategory": str, "urgency": "CRITICAL"|"HIGH"|"ROUTINE", "confidence": 0-1, "reason": str}. '
                  "Never advise citizens to touch hazards. Citizen description: %s") % (list(CATS), desc)
        body = {"model_id": model, "project_id": pid, "max_tokens": 500, "messages": [{"role": "user", "content": [
            {"type": "text", "text": prompt}, {"type": "image_url", "image_url": {"url": "data:image/jpeg;base64," + img}}]}]}
        r = json.load(urllib.request.urlopen(urllib.request.Request(
            os.getenv("WATSONX_URL", "https://us-south.ml.cloud.ibm.com") + "/ml/v1/text/chat?version=2024-10-10",
            json.dumps(body).encode(), {"Authorization": "Bearer " + t, "Content-Type": "application/json"}), timeout=60))
        s = r["choices"][0]["message"]["content"]
        return json.loads(s[s.index("{"): s.rindex("}") + 1])
    except Exception as e:
        print("watsonx failed, using fallback:", e); return None

def analyze(path, desc):
    r = watson(path, desc)
    if not (isinstance(r, dict) and r.get("category") in CATS and str(r.get("urgency", "")).upper() in ("CRITICAL", "HIGH", "ROUTINE")):
        r = rules(desc)
    r["urgency"] = r["urgency"].upper()
    try: r["confidence"] = max(0.0, min(1.0, float(r["confidence"])))
    except Exception: r["confidence"] = .4
    r["department"] = CATS[r["category"]][0]
    return r

# ---------- complaints ----------
@app.post("/api/complaints")
async def create(description: str = Form(...), latitude: float | None = Form(None), longitude: float | None = Form(None),
                 area: str = Form(""), landmark: str = Form(""), photo: UploadFile = File(...), u=Depends(me)):
    if len(description.strip()) < 10: raise HTTPException(400, "Describe the problem in at least 10 characters.")
    if latitude is None and not area.strip(): raise HTTPException(400, "Location is required: use GPS or type an area.")
    if not (photo.content_type or "").startswith("image/"): raise HTTPException(400, "The photo must be an image file.")
    ext = os.path.splitext(photo.filename or "")[1].lower()
    fn = uuid.uuid4().hex + (ext if ext in (".jpg", ".jpeg", ".png", ".webp", ".gif") else ".jpg")
    p = B + "/uploads/" + fn
    open(p, "wb").write(await photo.read())
    a = analyze(p, description); now = time.ctime()
    i = q("""insert into complaints(user_id,photo_url,description,latitude,longitude,area,landmark,created_at,ai_category,ai_subcategory,
ai_urgency,ai_confidence,ai_reason,suggested_department,low_confidence,status,updated_at) values(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
          (u["id"], "/uploads/" + fn, description.strip(), latitude, longitude, area.strip(), landmark.strip(), now, a["category"],
           a.get("subcategory", ""), a["urgency"], a["confidence"], a.get("reason", ""), a["department"], int(a["confidence"] < .6),
           "PENDING_REVIEW", now), w=True)
    return q("select * from complaints where id=?", (i,), True)

@app.get("/api/complaints/my")
def mine(u=Depends(me)): return q("select * from complaints where user_id=? order by id desc", (u["id"],))

@app.get("/api/complaints/{i}")
def one(i: int, u=Depends(me)):
    c = q("select * from complaints where id=?", (i,), True)
    if not c or (u["role"] != "ADMIN" and c["user_id"] != u["id"]): raise HTTPException(404, "Complaint not found.")
    if u["role"] != "ADMIN": c.pop("admin_notes")
    return c

@app.get("/api/admin/complaints")
def alist(category: str = "", urgency: str = "", status: str = "", area: str = "", department: str = "", search: str = "", u=Depends(adm)):
    s, a = "select * from complaints where 1=1", []
    for col, v in (("coalesce(admin_category,ai_category)", category), ("coalesce(admin_urgency,ai_urgency)", urgency),
                   ("status", status), ("coalesce(assigned_department,suggested_department)", department)):
        if v: s += f" and {col}=?"; a.append(v)
    if area: s += " and area like ?"; a.append(f"%{area}%")
    if search:
        s += " and (cast(id as text)=? or description like ? or landmark like ? or area like ?)"
        a += [search.lstrip("#"), *[f"%{search}%"] * 3]
    return q(s + " order by id desc", a)

@app.get("/api/admin/statistics")
def stats(u=Depends(adm)):
    g = lambda col: {r["k"] or "-": r["n"] for r in q(f"select {col} k,count(*) n from complaints group by k")}
    return {"total": q("select count(*) n from complaints", one=True)["n"], "urgency": g("coalesce(admin_urgency,ai_urgency)"),
            "category": g("coalesce(admin_category,ai_category)"), "status": g("status"), "area": g("area")}

@app.patch("/api/admin/complaints/{i}")
def decide(i: int, d: Dec, u=Depends(adm)):
    c = q("select * from complaints where id=?", (i,), True)
    if not c: raise HTTPException(404, "Complaint not found.")
    if d.status and d.status not in ("PENDING_REVIEW", "ASSIGNED", "IN_PROGRESS", "RESOLVED", "REJECTED"): raise HTTPException(400, "Invalid status.")
    if d.urgency and d.urgency not in ("CRITICAL", "HIGH", "ROUTINE"): raise HTTPException(400, "Invalid urgency.")
    if d.category and d.category not in CATS: raise HTTPException(400, "Invalid category.")
    if ((d.urgency and d.urgency != c["ai_urgency"]) or (d.category and d.category != c["ai_category"])) and not (d.override_reason or c["override_reason"]):
        raise HTTPException(400, "Give a reason when overriding the AI.")
    if d.status == "REJECTED" and not (d.admin_notes or c["admin_notes"]):
        raise HTTPException(400, "Give a reason when rejecting a complaint (e.g. wrong problem, duplicate, spam).")
    m = {"admin_category": d.category, "admin_urgency": d.urgency, "assigned_department": d.department, "status": d.status,
         "admin_notes": d.admin_notes, "citizen_update": d.citizen_update, "override_reason": d.override_reason}
    s = {k: v for k, v in m.items() if v is not None}
    if s: q("update complaints set " + ",".join(k + "=?" for k in s) + ",updated_at=? where id=?", (*s.values(), time.ctime(), i))
    return one(i, u)

@app.post("/api/admin/complaints/{i}/resolve")
async def resolve(i: int, notes: str = Form(""), photo: UploadFile = File(...), u=Depends(adm)):
    c = q("select * from complaints where id=?", (i,), True)
    if not c: raise HTTPException(404, "Complaint not found.")
    if not (photo.content_type or "").startswith("image/"): raise HTTPException(400, "The resolution photo must be an image file.")
    ext = os.path.splitext(photo.filename or "")[1].lower()
    fn = uuid.uuid4().hex + (ext if ext in (".jpg", ".jpeg", ".png", ".webp", ".gif") else ".jpg")
    open(B + "/uploads/" + fn, "wb").write(await photo.read())
    note = notes.strip()
    q("""update complaints set status='RESOLVED', resolved_photo_url=?, admin_notes=?, citizen_update=?, updated_at=? where id=?""",
      ("/uploads/" + fn, note or c["admin_notes"], note or c["citizen_update"] or "Your report has been resolved.", time.ctime(), i))
    return q("select * from complaints where id=?", (i,), True)

app.mount("/uploads", StaticFiles(directory=B + "/uploads"))
@app.get("/")
def home(): return FileResponse(B + "/static/index.html")
