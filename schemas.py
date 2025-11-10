"""
Database Schemas for the Rating Platform

MongoDB collections are defined below using Pydantic models. Each class name is
converted to lowercase for the collection name (User -> "user").

We will use these collections:
- user: system users (admin, normal, owner)
- store: registered stores
- rating: user ratings for stores
- session: auth sessions (JWT-less helper if needed)
"""

from pydantic import BaseModel, Field, EmailStr
from typing import Optional, Literal

Role = Literal["admin", "user", "owner"]

class User(BaseModel):
    name: str = Field(..., min_length=20, max_length=60)
    email: EmailStr
    address: str = Field(..., max_length=400)
    password_hash: str = Field(..., description="BCrypt hash of password")
    role: Role = Field("user")

class Store(BaseModel):
    owner_id: str = Field(..., description="Reference to user _id (owner)")
    name: str = Field(..., min_length=1, max_length=120)
    email: EmailStr
    address: str = Field(..., max_length=400)

class Rating(BaseModel):
    user_id: str = Field(...)
    store_id: str = Field(...)
    score: int = Field(..., ge=1, le=5)

class Session(BaseModel):
    user_id: str
    token: str
