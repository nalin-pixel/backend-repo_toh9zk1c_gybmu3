import os
from datetime import datetime, timedelta, timezone
from typing import Optional, List, Any, Dict

from fastapi import FastAPI, HTTPException, Depends, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel, Field, EmailStr
from jose import jwt, JWTError
from passlib.context import CryptContext
from bson import ObjectId

from database import db
from schemas import User as UserSchema, Store as StoreSchema, Rating as RatingSchema

# App and CORS
app = FastAPI(title="Ratings Platform API")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Auth setup
SECRET_KEY = os.getenv("SECRET_KEY", "supersecretkey")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 24 * 60

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")

# Helpers

def oid(obj: Any) -> str:
    return str(obj) if isinstance(obj, ObjectId) else str(ObjectId(obj))


def to_obj_id(id_str: str) -> ObjectId:
    try:
        return ObjectId(id_str)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid id")


def sanitize(doc: Dict) -> Dict:
    if not doc:
        return doc
    d = {**doc}
    if "_id" in d:
        d["id"] = str(d.pop("_id"))
    return d


def verify_password_policy(password: str) -> None:
    # 8-16 chars, at least one uppercase and one special char
    import re
    if not (8 <= len(password) <= 16):
        raise HTTPException(status_code=422, detail="Password must be 8-16 characters long")
    if not re.search(r"[A-Z]", password):
        raise HTTPException(status_code=422, detail="Password must include at least one uppercase letter")
    if not re.search(r"[^A-Za-z0-9]", password):
        raise HTTPException(status_code=422, detail="Password must include at least one special character")


def hash_password(password: str) -> str:
    verify_password_policy(password)
    return pwd_context.hash(password)


def verify_password(password: str, hashed: str) -> bool:
    return pwd_context.verify(password, hashed)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(status_code=401, detail="Could not validate credentials")
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: str = payload.get("sub")
        if user_id is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    user = db["user"].find_one({"_id": to_obj_id(user_id)})
    if not user:
        raise credentials_exception
    return sanitize(user)


def require_role(*roles: str):
    async def role_dep(current_user=Depends(get_current_user)):
        if current_user.get("role") not in roles:
            raise HTTPException(status_code=403, detail="Insufficient permissions")
        return current_user
    return role_dep

# Request/Response Models
class SignupRequest(BaseModel):
    name: str = Field(..., min_length=20, max_length=60)
    email: EmailStr
    address: str = Field(..., max_length=400)
    password: str

class LoginRequest(BaseModel):
    email: EmailStr
    password: str

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: Dict[str, Any]

class CreateUserRequest(BaseModel):
    name: str = Field(..., min_length=20, max_length=60)
    email: EmailStr
    address: str = Field(..., max_length=400)
    password: str
    role: str = Field(..., pattern="^(admin|user|owner)$")

class CreateStoreRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=120)
    email: EmailStr
    address: str = Field(..., max_length=400)
    owner_id: str

class UpdatePasswordRequest(BaseModel):
    old_password: Optional[str] = None
    new_password: str

class RateStoreRequest(BaseModel):
    score: int = Field(..., ge=1, le=5)

# Auth Routes
@app.post("/auth/signup", response_model=TokenResponse)
def signup(payload: SignupRequest):
    existing = db["user"].find_one({"email": payload.email})
    if existing:
        raise HTTPException(status_code=409, detail="Email already registered")
    user_doc = UserSchema(
        name=payload.name,
        email=payload.email,
        address=payload.address,
        password_hash=hash_password(payload.password),
        role="user",
    ).model_dump()
    res = db["user"].insert_one(user_doc)
    uid = str(res.inserted_id)
    token = create_access_token({"sub": uid})
    user_doc["_id"] = res.inserted_id
    return TokenResponse(access_token=token, user=sanitize(user_doc))

@app.post("/auth/login", response_model=TokenResponse)
def login(payload: LoginRequest):
    user = db["user"].find_one({"email": payload.email})
    if not user or not verify_password(payload.password, user.get("password_hash", "")):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    token = create_access_token({"sub": str(user["_id"])})
    return TokenResponse(access_token=token, user=sanitize(user))

@app.get("/me")
def me(current_user=Depends(get_current_user)):
    return current_user

@app.put("/auth/password")
def update_password(payload: UpdatePasswordRequest, current_user=Depends(get_current_user)):
    if current_user.get("role") in ("admin",) and payload.old_password is None:
        # admins may change without old password for themselves; for simplicity require old for all
        pass
    # verify old password
    user = db["user"].find_one({"_id": to_obj_id(current_user["id"])})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    # if old_password provided, verify
    if payload.old_password and not verify_password(payload.old_password, user.get("password_hash", "")):
        raise HTTPException(status_code=400, detail="Old password incorrect")
    new_hash = hash_password(payload.new_password)
    db["user"].update_one({"_id": user["_id"]}, {"$set": {"password_hash": new_hash, "updated_at": datetime.now(timezone.utc)}})
    return {"message": "Password updated"}

# Admin Routes
@app.post("/admin/users")
def admin_create_user(payload: CreateUserRequest, admin=Depends(require_role("admin"))):
    if db["user"].find_one({"email": payload.email}):
        raise HTTPException(status_code=409, detail="Email already exists")
    user_doc = UserSchema(
        name=payload.name,
        email=payload.email,
        address=payload.address,
        password_hash=hash_password(payload.password),
        role=payload.role,
    ).model_dump()
    res = db["user"].insert_one(user_doc)
    user_doc["_id"] = res.inserted_id
    return sanitize(user_doc)

@app.post("/admin/stores")
def admin_create_store(payload: CreateStoreRequest, admin=Depends(require_role("admin"))):
    owner = db["user"].find_one({"_id": to_obj_id(payload.owner_id)})
    if not owner or owner.get("role") != "owner":
        raise HTTPException(status_code=400, detail="owner_id must be a valid Store Owner")
    store_doc = StoreSchema(owner_id=payload.owner_id, name=payload.name, email=payload.email, address=payload.address).model_dump()
    res = db["store"].insert_one(store_doc)
    store_doc["_id"] = res.inserted_id
    return sanitize(store_doc)

@app.get("/admin/dashboard")
def admin_dashboard(admin=Depends(require_role("admin"))):
    total_users = db["user"].count_documents({})
    total_stores = db["store"].count_documents({})
    total_ratings = db["rating"].count_documents({})
    return {"total_users": total_users, "total_stores": total_stores, "total_ratings": total_ratings}

@app.get("/admin/users")
def admin_list_users(
    name: Optional[str] = None,
    email: Optional[str] = None,
    address: Optional[str] = None,
    role: Optional[str] = None,
    sort_by: Optional[str] = Query("name"),
    order: Optional[str] = Query("asc"),
    admin=Depends(require_role("admin")),
):
    q: Dict[str, Any] = {}
    if name:
        q["name"] = {"$regex": name, "$options": "i"}
    if email:
        q["email"] = {"$regex": email, "$options": "i"}
    if address:
        q["address"] = {"$regex": address, "$options": "i"}
    if role:
        q["role"] = role
    sort_dir = 1 if order == "asc" else -1
    cursor = db["user"].find(q).sort([(sort_by, sort_dir)])
    users = [sanitize(u) for u in cursor]
    return users

@app.get("/admin/stores")
def admin_list_stores(
    name: Optional[str] = None,
    email: Optional[str] = None,
    address: Optional[str] = None,
    sort_by: Optional[str] = Query("name"),
    order: Optional[str] = Query("asc"),
    admin=Depends(require_role("admin")),
):
    q: Dict[str, Any] = {}
    if name:
        q["name"] = {"$regex": name, "$options": "i"}
    if email:
        q["email"] = {"$regex": email, "$options": "i"}
    if address:
        q["address"] = {"$regex": address, "$options": "i"}
    sort_dir = 1 if order == "asc" else -1
    stores = [sanitize(s) for s in db["store"].find(q).sort([(sort_by, sort_dir)])]
    # attach rating average
    for s in stores:
        avg = list(db["rating"].aggregate([
            {"$match": {"store_id": s["id"]}},
            {"$group": {"_id": "$store_id", "avg": {"$avg": "$score"}, "count": {"$sum": 1}}}
        ]))
        s["average_rating"] = round(avg[0]["avg"], 2) if avg else None
        s["rating_count"] = avg[0]["count"] if avg else 0
    return stores

# Stores and Ratings for Users
@app.get("/stores")
def list_stores(
    name: Optional[str] = None,
    address: Optional[str] = None,
    sort_by: Optional[str] = Query("name"),
    order: Optional[str] = Query("asc"),
    current_user=Depends(get_current_user),
):
    q: Dict[str, Any] = {}
    if name:
        q["name"] = {"$regex": name, "$options": "i"}
    if address:
        q["address"] = {"$regex": address, "$options": "i"}
    sort_dir = 1 if order == "asc" else -1
    stores = [sanitize(s) for s in db["store"].find(q).sort([(sort_by, sort_dir)])]
    # attach overall rating and user's rating
    for s in stores:
        pipe = [
            {"$match": {"store_id": s["id"]}},
            {"$group": {"_id": "$store_id", "avg": {"$avg": "$score"}}},
        ]
        agg = list(db["rating"].aggregate(pipe))
        s["overall_rating"] = round(agg[0]["avg"], 2) if agg else None
        r = db["rating"].find_one({"store_id": s["id"], "user_id": current_user["id"]})
        s["my_rating"] = r["score"] if r else None
    return stores

@app.post("/stores/{store_id}/rating")
def rate_store(store_id: str, payload: RateStoreRequest, current_user=Depends(get_current_user)):
    # ensure store exists
    st = db["store"].find_one({"_id": to_obj_id(store_id)})
    if not st:
        raise HTTPException(status_code=404, detail="Store not found")
    existing = db["rating"].find_one({"store_id": store_id, "user_id": current_user["id"]})
    if existing:
        db["rating"].update_one({"_id": existing["_id"]}, {"$set": {"score": payload.score, "updated_at": datetime.now(timezone.utc)}})
    else:
        doc = RatingSchema(user_id=current_user["id"], store_id=store_id, score=payload.score).model_dump()
        db["rating"].insert_one(doc)
    return {"message": "Rating saved"}

# Owner routes
@app.get("/owner/dashboard")
def owner_dashboard(current_owner=Depends(require_role("owner"))):
    stores = list(db["store"].find({"owner_id": current_owner["id"]}))
    result = []
    for st in stores:
        s = sanitize(st)
        ratings = list(db["rating"].find({"store_id": s["id"]}))
        user_map = {u["_id"]: u for u in db["user"].find({"_id": {"$in": [to_obj_id(r["user_id"]) for r in ratings]}})} if ratings else {}
        raters = [
            {
                "user_name": user_map.get(to_obj_id(r["user_id"]))["name"] if user_map else "",
                "user_email": user_map.get(to_obj_id(r["user_id"]))["email"] if user_map else "",
                "score": r["score"],
            }
            for r in ratings
        ]
        avg = round(sum([r["score"] for r in ratings]) / len(ratings), 2) if ratings else None
        result.append({"store": s, "average_rating": avg, "ratings": raters})
    return result

# Bootstrap route for demo
@app.post("/init/bootstrap")
def bootstrap_admin():
    """Create a default admin if none exists (email: admin@example.com, password: Admin@123)."""
    if db["user"].count_documents({"role": "admin"}) > 0:
        raise HTTPException(status_code=400, detail="Admin already exists")
    user_doc = UserSchema(
        name="Default Administrator User Name",
        email="admin@example.com",
        address="Admin Address",
        password_hash=hash_password("Admin@123"),
        role="admin",
    ).model_dump()
    res = db["user"].insert_one(user_doc)
    return {"message": "Admin created", "email": "admin@example.com", "password": "Admin@123"}

# Utility endpoints
@app.get("/")
def root():
    return {"message": "Ratings Platform API running"}

@app.get("/test")
def test_database():
    try:
        collections = db.list_collection_names() if db else []
        return {"backend": "ok", "database": "ok" if db else "missing", "collections": collections}
    except Exception as e:
        return {"backend": "ok", "database": f"error: {e}"}
