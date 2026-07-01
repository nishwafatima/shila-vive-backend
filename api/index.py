import setuptools  # noqa: F401
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import razorpay
import hmac
import hashlib
import os
from datetime import datetime

RAZORPAY_KEY_ID         = os.environ.get("RAZORPAY_KEY_ID", "")
RAZORPAY_KEY_SECRET     = os.environ.get("RAZORPAY_KEY_SECRET", "")
RAZORPAY_WEBHOOK_SECRET = os.environ.get("RAZORPAY_WEBHOOK_SECRET", "")
ADMIN_SECRET            = os.environ.get("ADMIN_SECRET", "")

if not RAZORPAY_KEY_ID or not RAZORPAY_KEY_SECRET:
    raise RuntimeError(
        "RAZORPAY_KEY_ID / RAZORPAY_KEY_SECRET env vars are not set."
    )

client = razorpay.Client(auth=(RAZORPAY_KEY_ID, RAZORPAY_KEY_SECRET))

app = FastAPI(title="Shila Vive Backend")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

orders = {}
PRODUCT_NAME = "Pure Himalayan Shilajit 100g Natural Resin"

class CreateOrderRequest(BaseModel):
    amount:   int
    quantity: int
    name:     str
    email:    str
    phone:    str
    address:  str = ""   # ADD
    city:     str = ""   # ADD
    pincode:  str = ""   # ADD
    state:    str = ""   # ADD

class VerifyPaymentRequest(BaseModel):
    razorpay_order_id:   str
    razorpay_payment_id: str
    razorpay_signature:  str
    name:     str
    email:    str
    phone:    str
    quantity: int
    address:  str = ""   # ADD
    city:     str = ""   # ADD
    pincode:  str = ""   # ADD
    state:    str = ""   # ADD

@app.get("/")
def root():
    return {"status": "Shila Vive backend running"}

@app.post("/create-order")
def create_order(req: CreateOrderRequest):
    if req.amount <= 0 or req.quantity <= 0:
        raise HTTPException(status_code=400, detail="Invalid amount or quantity")
    try:
        amount_paise = req.amount * 100
        rzp_order = client.order.create({
            "amount":   amount_paise,
            "currency": "INR",
            "receipt":  f"rcpt_{datetime.now().strftime('%Y%m%d%H%M%S')}",
            "notes": {
                "customer_name":  req.name,
                "customer_email": req.email,
                "customer_phone": req.phone,
                "quantity":       str(req.quantity),
                "product":        PRODUCT_NAME,
            },
        })
        orders[rzp_order["id"]] = {
            "order_id":   rzp_order["id"],
            "amount_inr": req.amount,
            "quantity":   req.quantity,
            "name":       req.name,
            "email":      req.email,
            "phone":      req.phone,
            "status":     "created",
            "created_at": datetime.now().isoformat(),
            "address":  req.address,   # ADD
            "city":     req.city,      # ADD
            "pincode":  req.pincode,   # ADD
            "state":    req.state,     # ADD
        }
        return {
            "order_id":     rzp_order["id"],
            "amount_paise": amount_paise,
            "currency":     "INR",
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/verify-payment")
def verify_payment(req: VerifyPaymentRequest):
    body     = f"{req.razorpay_order_id}|{req.razorpay_payment_id}"
    expected = hmac.new(
        RAZORPAY_KEY_SECRET.encode(),
        body.encode(),
        hashlib.sha256,
    ).hexdigest()
    if not hmac.compare_digest(expected, req.razorpay_signature):
        raise HTTPException(status_code=400, detail="Invalid payment signature")
    if req.razorpay_order_id in orders:
        orders[req.razorpay_order_id].update({
            "payment_id": req.razorpay_payment_id,
            "status":     "paid",
            "paid_at":    datetime.now().isoformat(),
        })
    return {
        "status":     "success",
        "order_id":   req.razorpay_order_id,
        "payment_id": req.razorpay_payment_id,
        "message":    "Payment verified successfully",
    }

@app.post("/razorpay-webhook")
async def razorpay_webhook(request: Request):
    if not RAZORPAY_WEBHOOK_SECRET:
        raise HTTPException(status_code=503, detail="Webhook not configured")
    raw = await request.body()
    sig = request.headers.get("x-razorpay-signature", "")
    expected = hmac.new(
        RAZORPAY_WEBHOOK_SECRET.encode(),
        raw,
        hashlib.sha256,
    ).hexdigest()
    if not hmac.compare_digest(expected, sig):
        raise HTTPException(status_code=400, detail="Invalid webhook signature")
    return {"status": "ok"}

@app.get("/orders")
def list_orders(secret: str = ""):
    if not ADMIN_SECRET or secret != ADMIN_SECRET:
        raise HTTPException(status_code=403, detail="Forbidden")
    return {"total": len(orders), "orders": list(orders.values())}
