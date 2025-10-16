from fastapi import FastAPI, APIRouter, HTTPException, Depends, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import os
import logging
from pathlib import Path
from pydantic import BaseModel, Field, ConfigDict, EmailStr
from typing import List, Optional
import uuid
from datetime import datetime, timezone, timedelta
from passlib.context import CryptContext
import jwt

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

# MongoDB connection
mongo_url = os.environ['MONGO_URL']
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ['DB_NAME']]

# Security
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
SECRET_KEY = os.environ.get('SECRET_KEY', 'your-secret-key-change-in-production')
ALGORITHM = "HS256"
security = HTTPBearer()

# Create the main app
app = FastAPI()
api_router = APIRouter(prefix="/api")

# ==================== MODELS ====================

class UserRegister(BaseModel):
    email: EmailStr
    password: str
    name: str

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class User(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    email: str
    name: str
    role: str = "customer"  # customer or admin
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class MenuItem(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    description: str
    category: str
    base_price: float
    image_url: str
    sizes: List[dict]  # [{"name": "Small", "price": 3.5}, ...]
    customizations: List[str]  # ["Whole Milk", "Almond Milk", ...]

class CartItem(BaseModel):
    menu_item_id: str
    name: str
    size: str
    customizations: List[str]
    price: float
    quantity: int

class OrderCreate(BaseModel):
    user_id: str
    items: List[CartItem]
    total: float
    delivery_address: str
    phone: str

class Order(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    user_id: str
    items: List[dict]
    total: float
    status: str = "pending"  # pending, preparing, ready, delivered, cancelled
    delivery_address: str
    phone: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class OrderStatusUpdate(BaseModel):
    status: str

class StoreInfo(BaseModel):
    model_config = ConfigDict(extra="ignore")
    address: str
    city: str
    phone: str
    email: str
    hours: dict
    map_url: str

# ==================== HELPER FUNCTIONS ====================

def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def create_token(data: dict) -> str:
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(days=7)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    try:
        token = credentials.credentials
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id = payload.get("user_id")
        if user_id is None:
            raise HTTPException(status_code=401, detail="Invalid token")
        
        user = await db.users.find_one({"id": user_id}, {"_id": 0})
        if user is None:
            raise HTTPException(status_code=401, detail="User not found")
        return user
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token")

# ==================== AUTH ROUTES ====================

@api_router.post("/auth/register")
async def register(user_data: UserRegister):
    # Check if user exists
    existing_user = await db.users.find_one({"email": user_data.email})
    if existing_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    # Create user
    user = User(
        email=user_data.email,
        name=user_data.name,
        role="customer"
    )
    
    user_dict = user.model_dump()
    user_dict['created_at'] = user_dict['created_at'].isoformat()
    user_dict['password_hash'] = hash_password(user_data.password)
    
    await db.users.insert_one(user_dict)
    
    # Create token
    token = create_token({"user_id": user.id, "email": user.email, "role": user.role})
    
    return {
        "token": token,
        "user": {
            "id": user.id,
            "email": user.email,
            "name": user.name,
            "role": user.role
        }
    }

@api_router.post("/auth/login")
async def login(credentials: UserLogin):
    user = await db.users.find_one({"email": credentials.email}, {"_id": 0})
    if not user:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    if not verify_password(credentials.password, user['password_hash']):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    token = create_token({"user_id": user['id'], "email": user['email'], "role": user['role']})
    
    return {
        "token": token,
        "user": {
            "id": user['id'],
            "email": user['email'],
            "name": user['name'],
            "role": user['role']
        }
    }

@api_router.get("/auth/me")
async def get_me(current_user: dict = Depends(get_current_user)):
    return {
        "id": current_user['id'],
        "email": current_user['email'],
        "name": current_user['name'],
        "role": current_user['role']
    }

# ==================== MENU ROUTES ====================

@api_router.get("/menu/items")
async def get_menu_items():
    items = await db.menu_items.find({}, {"_id": 0}).to_list(1000)
    return items

@api_router.post("/menu/items")
async def create_menu_item(item: MenuItem, current_user: dict = Depends(get_current_user)):
    if current_user['role'] != 'admin':
        raise HTTPException(status_code=403, detail="Admin access required")
    
    item_dict = item.model_dump()
    await db.menu_items.insert_one(item_dict)
    return item_dict

# ==================== ORDER ROUTES ====================

@api_router.post("/orders")
async def create_order(order_data: OrderCreate, current_user: dict = Depends(get_current_user)):
    order = Order(
        user_id=current_user['id'],
        items=[item.model_dump() for item in order_data.items],
        total=order_data.total,
        delivery_address=order_data.delivery_address,
        phone=order_data.phone,
        status="pending"
    )
    
    order_dict = order.model_dump()
    order_dict['created_at'] = order_dict['created_at'].isoformat()
    order_dict['updated_at'] = order_dict['updated_at'].isoformat()
    
    await db.orders.insert_one(order_dict.copy())
    
    # Return the dict without _id
    return {
        "id": order.id,
        "user_id": order.user_id,
        "items": order_dict['items'],
        "total": order.total,
        "status": order.status,
        "delivery_address": order.delivery_address,
        "phone": order.phone,
        "created_at": order_dict['created_at'],
        "updated_at": order_dict['updated_at']
    }

@api_router.get("/orders/user")
async def get_user_orders(current_user: dict = Depends(get_current_user)):
    orders = await db.orders.find({"user_id": current_user['id']}, {"_id": 0}).sort("created_at", -1).to_list(1000)
    
    for order in orders:
        if isinstance(order.get('created_at'), str):
            order['created_at'] = datetime.fromisoformat(order['created_at'])
        if isinstance(order.get('updated_at'), str):
            order['updated_at'] = datetime.fromisoformat(order['updated_at'])
    
    return orders

@api_router.get("/orders/all")
async def get_all_orders(current_user: dict = Depends(get_current_user)):
    if current_user['role'] != 'admin':
        raise HTTPException(status_code=403, detail="Admin access required")
    
    orders = await db.orders.find({}, {"_id": 0}).sort("created_at", -1).to_list(1000)
    
    for order in orders:
        if isinstance(order.get('created_at'), str):
            order['created_at'] = datetime.fromisoformat(order['created_at'])
        if isinstance(order.get('updated_at'), str):
            order['updated_at'] = datetime.fromisoformat(order['updated_at'])
    
    return orders

@api_router.patch("/orders/{order_id}/status")
async def update_order_status(order_id: str, status_update: OrderStatusUpdate, current_user: dict = Depends(get_current_user)):
    if current_user['role'] != 'admin':
        raise HTTPException(status_code=403, detail="Admin access required")
    
    result = await db.orders.update_one(
        {"id": order_id},
        {"$set": {
            "status": status_update.status,
            "updated_at": datetime.now(timezone.utc).isoformat()
        }}
    )
    
    if result.modified_count == 0:
        raise HTTPException(status_code=404, detail="Order not found")
    
    return {"message": "Order status updated"}

@api_router.get("/orders/{order_id}")
async def get_order(order_id: str, current_user: dict = Depends(get_current_user)):
    order = await db.orders.find_one({"id": order_id}, {"_id": 0})
    
    if not order:
        raise HTTPException(status_code=404, detail="Order not found")
    
    if current_user['role'] != 'admin' and order['user_id'] != current_user['id']:
        raise HTTPException(status_code=403, detail="Access denied")
    
    if isinstance(order.get('created_at'), str):
        order['created_at'] = datetime.fromisoformat(order['created_at'])
    if isinstance(order.get('updated_at'), str):
        order['updated_at'] = datetime.fromisoformat(order['updated_at'])
    
    return order

# ==================== STORE INFO ROUTES ====================

@api_router.get("/store/info")
async def get_store_info():
    store = await db.store_info.find_one({}, {"_id": 0})
    if not store:
        # Return default store info
        return {
            "address": "123 Coffee Street",
            "city": "New York, NY 10001",
            "phone": "+1 (555) 123-4567",
            "email": "hello@coffeeshop.com",
            "hours": {
                "monday": "7:00 AM - 8:00 PM",
                "tuesday": "7:00 AM - 8:00 PM",
                "wednesday": "7:00 AM - 8:00 PM",
                "thursday": "7:00 AM - 8:00 PM",
                "friday": "7:00 AM - 9:00 PM",
                "saturday": "8:00 AM - 9:00 PM",
                "sunday": "8:00 AM - 7:00 PM"
            },
            "map_url": "https://www.google.com/maps/embed?pb=!1m18!1m12!1m3!1d3024.2219901290355!2d-74.00369368400567!3d40.71312937933017!2m3!1f0!2f0!3f0!3m2!1i1024!2i768!4f13.1!3m3!1m2!1s0x89c25a316f6d7ad7%3A0x9e3c2f7c0f3f3f3f!2sNew%20York%2C%20NY!5e0!3m2!1sen!2sus!4v1234567890123!5m2!1sen!2sus"
        }
    return store

# ==================== INITIALIZE DATA ====================

@api_router.post("/init-data")
async def initialize_data():
    # Check if data already exists
    existing_items = await db.menu_items.count_documents({})
    if existing_items > 0:
        return {"message": "Data already initialized"}
    
    # Initialize menu items
    menu_items = [
        {
            "id": str(uuid.uuid4()),
            "name": "Classic Espresso",
            "description": "Rich and bold espresso shot, perfect for a quick energy boost",
            "category": "Espresso",
            "base_price": 3.5,
            "image_url": "https://images.unsplash.com/photo-1461023058943-07fcbe16d735?crop=entropy&cs=srgb&fm=jpg&ixid=M3w3NTY2Njl8MHwxfHNlYXJjaHwxfHxjb2ZmZWUlMjBkcmlua3N8ZW58MHx8fHwxNzYwNDU4MTUyfDA&ixlib=rb-4.1.0&q=85",
            "sizes": [
                {"name": "Single", "price": 3.5},
                {"name": "Double", "price": 4.5}
            ],
            "customizations": ["Extra Shot", "Sugar", "Vanilla Syrup"]
        },
        {
            "id": str(uuid.uuid4()),
            "name": "Creamy Latte",
            "description": "Smooth espresso with steamed milk and beautiful latte art",
            "category": "Latte",
            "base_price": 4.5,
            "image_url": "https://images.unsplash.com/photo-1578730170052-ac626460cc5f?crop=entropy&cs=srgb&fm=jpg&ixid=M3w3NDQ2MzR8MHwxfHNlYXJjaHw0fHxsYXR0ZSUyMGNhcHB1Y2Npbm98ZW58MHx8fHwxNzYwNDU4MTU5fDA&ixlib=rb-4.1.0&q=85",
            "sizes": [
                {"name": "Small", "price": 4.5},
                {"name": "Medium", "price": 5.5},
                {"name": "Large", "price": 6.5}
            ],
            "customizations": ["Whole Milk", "Almond Milk", "Oat Milk", "Soy Milk", "Caramel Syrup", "Vanilla Syrup", "Hazelnut Syrup"]
        },
        {
            "id": str(uuid.uuid4()),
            "name": "Iced Coffee",
            "description": "Refreshing cold brew coffee served over ice",
            "category": "Cold Brew",
            "base_price": 4.0,
            "image_url": "https://images.unsplash.com/photo-1534414671319-4fc58cc112e1?crop=entropy&cs=srgb&fm=jpg&ixid=M3w3NTY2Njl8MHwxfHNlYXJjaHwzfHxjb2ZmZWUlMjBkcmlua3N8ZW58MHx8fHwxNzYwNDU4MTUyfDA&ixlib=rb-4.1.0&q=85",
            "sizes": [
                {"name": "Small", "price": 4.0},
                {"name": "Medium", "price": 5.0},
                {"name": "Large", "price": 6.0}
            ],
            "customizations": ["Whole Milk", "Almond Milk", "Oat Milk", "Vanilla Syrup", "Caramel Syrup", "Extra Ice"]
        },
        {
            "id": str(uuid.uuid4()),
            "name": "Cappuccino",
            "description": "Perfect balance of espresso, steamed milk, and foam",
            "category": "Cappuccino",
            "base_price": 4.5,
            "image_url": "https://images.unsplash.com/photo-1504705707-2159776e0146?crop=entropy&cs=srgb&fm=jpg&ixid=M3w3NDQ2MzR8MHwxfHNlYXJjaHwzfHxsYXR0ZSUyMGNhcHB1Y2Npbm98ZW58MHx8fHwxNzYwNDU4MTU5fDA&ixlib=rb-4.1.0&q=85",
            "sizes": [
                {"name": "Small", "price": 4.5},
                {"name": "Medium", "price": 5.5},
                {"name": "Large", "price": 6.5}
            ],
            "customizations": ["Whole Milk", "Almond Milk", "Oat Milk", "Extra Foam", "Cinnamon"]
        },
        {
            "id": str(uuid.uuid4()),
            "name": "Mocha Delight",
            "description": "Rich chocolate blended with espresso and steamed milk",
            "category": "Specialty",
            "base_price": 5.5,
            "image_url": "https://images.unsplash.com/photo-1517701550927-30cf4ba1dba5?crop=entropy&cs=srgb&fm=jpg&ixid=M3w3NTY2Njl8MHwxfHNlYXJjaHw0fHxjb2ZmZWUlMjBkcmlua3N8ZW58MHx8fHwxNzYwNDU4MTUyfDA&ixlib=rb-4.1.0&q=85",
            "sizes": [
                {"name": "Small", "price": 5.5},
                {"name": "Medium", "price": 6.5},
                {"name": "Large", "price": 7.5}
            ],
            "customizations": ["Whole Milk", "Almond Milk", "Whipped Cream", "Extra Chocolate", "Caramel Drizzle"]
        },
        {
            "id": str(uuid.uuid4()),
            "name": "Caramel Macchiato",
            "description": "Espresso with vanilla-flavored milk and caramel drizzle",
            "category": "Specialty",
            "base_price": 5.5,
            "image_url": "https://images.unsplash.com/photo-1627998691167-4dab0dfcae9f?crop=entropy&cs=srgb&fm=jpg&ixid=M3w3NTY2Njl8MHwxfHNlYXJjaHwyfHxjb2ZmZWUlMjBkcmlua3N8ZW58MHx8fHwxNzYwNDU4MTUyfDA&ixlib=rb-4.1.0&q=85",
            "sizes": [
                {"name": "Small", "price": 5.5},
                {"name": "Medium", "price": 6.5},
                {"name": "Large", "price": 7.5}
            ],
            "customizations": ["Whole Milk", "Almond Milk", "Oat Milk", "Extra Caramel", "Whipped Cream"]
        },
        {
            "id": str(uuid.uuid4()),
            "name": "Cold Brew Classic",
            "description": "Smooth cold brew steeped for 12 hours",
            "category": "Cold Brew",
            "base_price": 4.5,
            "image_url": "https://images.pexels.com/photos/34285936/pexels-photo-34285936.jpeg",
            "sizes": [
                {"name": "Small", "price": 4.5},
                {"name": "Medium", "price": 5.5},
                {"name": "Large", "price": 6.5}
            ],
            "customizations": ["Vanilla Syrup", "Caramel Syrup", "Cream", "Extra Ice"]
        },
        {
            "id": str(uuid.uuid4()),
            "name": "Americano",
            "description": "Espresso shots diluted with hot water",
            "category": "Espresso",
            "base_price": 3.5,
            "image_url": "https://images.pexels.com/photos/34280991/pexels-photo-34280991.jpeg",
            "sizes": [
                {"name": "Small", "price": 3.5},
                {"name": "Medium", "price": 4.5},
                {"name": "Large", "price": 5.5}
            ],
            "customizations": ["Extra Shot", "Sugar", "Cream"]
        }
    ]
    
    await db.menu_items.insert_many(menu_items)
    
    # Create admin user
    admin_exists = await db.users.find_one({"email": "admin@coffee.com"})
    if not admin_exists:
        admin_user = {
            "id": str(uuid.uuid4()),
            "email": "admin@coffee.com",
            "name": "Admin",
            "role": "admin",
            "password_hash": hash_password("admin123"),
            "created_at": datetime.now(timezone.utc).isoformat()
        }
        await db.users.insert_one(admin_user)
    
    return {"message": "Data initialized successfully", "admin_credentials": {"email": "admin@coffee.com", "password": "admin123"}}

# Include the router in the main app
app.include_router(api_router)

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=os.environ.get('CORS_ORIGINS', '*').split(','),
    allow_methods=["*"],
    allow_headers=["*"],
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()
