"""
Shila Vive backend — Razorpay create-order + verify-payment.

Deploy target: Vercel (Python serverless). File lives at /api/index.py so
Vercel auto-detects it as a function; vercel.json rewrites all paths here.

NOTE on storage: `orders` is in-memory and DOES NOT persist on serverless
(each invocation can be a fresh instance). Payments still verify fine because
verification is stateless (HMAC). But /orders will be unreliable. For real
order records, either rely on the Razorpay Dashboard, or wire a DB
(Upstash Redis / MongoDB Atlas / Supabase) in the marked spots below.
"""
import setuptools  # noqa: F401  — provides pkg_resources for razorpay
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import razorpay
import hmac
import hashlib
import os
from datetime import datetime

# ── Config (env-only; NO secret defaults committed to git) ────────────
RAZORPAY_KEY_ID         = os.environ.get("RAZORPAY_KEY_ID", "")
RAZORPAY_KEY_SECRET     = os.environ.get("RAZORPAY_KEY_SECRET", "")
RAZORPAY_WEBHOOK_SECRET = os.environ.get("RAZORPAY_WEBHOOK_SECRET", "")  # optional
ADMIN_SECRET            = os.environ.get("ADMIN_SECRET", "")

if not RAZORPAY_KEY_ID or not RAZORPAY_KEY_SECRET:
    # Fail loud at import if creds missing, so prod never silently runs broken.
    raise RuntimeError(
        "RAZORPAY_KEY_ID / RAZORPAY_KEY_SECRET env vars are not set. "
        "Set them in Vercel → Project → Settings → Environment Variables."
    )

client = razorpay.Client(auth=(RAZORPAY_KEY_ID, RAZORPAY_KEY_SECRET))

app = FastAPI(title="Shila Vive Backend")

# Tighten origins for production if you like; "*" is fine for a public store.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── In-memory store (see NOTE above — swap for a DB for persistence) ──
orders = {}

PRODUCT_NAME = "Pure Himalayan Shilajit 100g Natural Resin"


class CreateOrderRequest(BaseModel):
    amount:   int
    quantity: int
    name:     str
    email:    str
    phone:    str


class VerifyPaymentRequest(BaseModel):
    razorpay_order_id:   str
    razorpay_payment_id: str
    razorpay_signature:  str
    name:     str
    email:    str
    phone:    str
    quantity: int


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
        }
        # DB HOOK: persist `orders[rzp_order["id"]]` here for real tracking.
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
    # DB HOOK: mark order paid in your DB here.

    return {
        "status":     "success",
        "order_id":   req.razorpay_order_id,
        "payment_id": req.razorpay_payment_id,
        "message":    "Payment verified successfully",
    }


@app.post("/razorpay-webhook")
async def razorpay_webhook(request: Request):
    """
    Reliable source of truth: Razorpay calls this even if the customer
    closes the tab after paying. Configure in Razorpay Dashboard →
    Settings → Webhooks, event `payment.captured`, with the same secret
    you put in RAZORPAY_WEBHOOK_SECRET. No-op if the secret isn't set.
    """
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

    # DB HOOK: parse `raw` JSON and persist the captured payment here.
    return {"status": "ok"}


@app.get("/orders")
def list_orders(secret: str = ""):
    if not ADMIN_SECRET or secret != ADMIN_SECRET:
        raise HTTPException(status_code=403, detail="Forbidden")
    return {"total": len(orders), "orders": list(orders.values())}
