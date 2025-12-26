import os
import io
import json
import base64
import zipfile
import time
import uuid
from typing import Optional, List
from datetime import datetime

from fastapi import FastAPI, Request, UploadFile, File, Form, HTTPException, Depends
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse, JSONResponse, Response
from pydantic import BaseModel
from slowapi.errors import RateLimitExceeded

from src.key_manager import KeyManager
from src.signature_service import SignatureService
from src.certificate_service import CertificateAuthority
from src.models import SignatureResult, VerificationResult, Certificate
from src.exceptions import KeyManagementError, SignatureError, VerificationError, CertificateError
from src.logging_config import get_logger, set_correlation_id, get_correlation_id
from src.rate_limiter import limiter, rate_limit_exceeded_handler, get_rate_limit
from src.resource_guards import (
    ResourceGuardMiddleware, 
    validate_file_size, 
    validate_message_length,
    check_key_generation_limit,
    resource_config
)

# Load environment variables
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

# Initialize logger
logger = get_logger(__name__)

# --- Application Setup ---
app = FastAPI(
    title="Digital Signature Validator",
    description="Web interface for Digital Signature Validator tool",
    version="1.0.0"
)

# Add rate limiter to app state
app.state.limiter = limiter

# Add exception handler for rate limiting
app.add_exception_handler(RateLimitExceeded, rate_limit_exceeded_handler)

# Add resource guard middleware
app.add_middleware(ResourceGuardMiddleware)

# Mount static files
app.mount("/static", StaticFiles(directory="static"), name="static")

# Initialize templates
templates = Jinja2Templates(directory="templates")

# Initialize Services
key_manager = KeyManager()
signature_service = SignatureService()


# --- Request Logging Middleware ---
@app.middleware("http")
async def log_requests(request: Request, call_next):
    """Log all API requests with correlation ID."""
    # Generate correlation ID for request tracing
    correlation_id = set_correlation_id()
    
    start_time = time.time()
    
    # Log request
    logger.info("Request started", extra={'context': {
        'method': request.method,
        'path': request.url.path,
        'client_ip': request.client.host if request.client else 'unknown',
        'correlation_id': correlation_id
    }})
    
    try:
        response = await call_next(request)
        
        # Calculate duration
        duration_ms = (time.time() - start_time) * 1000
        
        # Log response
        logger.info("Request completed", extra={'context': {
            'method': request.method,
            'path': request.url.path,
            'status_code': response.status_code,
            'duration_ms': round(duration_ms, 2),
            'correlation_id': correlation_id
        }})
        
        # Add correlation ID to response headers
        response.headers['X-Correlation-ID'] = correlation_id
        
        return response
        
    except Exception as e:
        duration_ms = (time.time() - start_time) * 1000
        logger.error(f"Request failed: {str(e)}", extra={'context': {
            'method': request.method,
            'path': request.url.path,
            'duration_ms': round(duration_ms, 2),
            'error': str(e),
            'correlation_id': correlation_id
        }})
        raise

# --- Pydantic Models ---

class GenerateKeyRequest(BaseModel):
    passphrase: Optional[str] = None
    key_size: int = 2048

class SignMessageRequest(BaseModel):
    message: str
    private_key_pem: str
    passphrase: Optional[str] = None

class VerifyMessageRequest(BaseModel):
    message: str
    signature: str # Hex string or Base64
    public_key_pem: str

# --- Helper Functions ---

def _pem_response_to_zip(private_pem: bytes, public_pem: bytes) -> Response:
    """Helper to zip up keys for download."""
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, "a", zipfile.ZIP_DEFLATED, False) as zip_file:
        zip_file.writestr("private_key.pem", private_pem)
        zip_file.writestr("public_key.pem", public_pem)
    
    return Response(
        content=zip_buffer.getvalue(),
        media_type="application/zip",
        headers={"Content-Disposition": "attachment; filename=keys.zip"}
    )

# --- Routes: Frontend ---

@app.get("/", response_class=HTMLResponse)
async def read_root(request: Request):
    """Serve the main application page."""
    return templates.TemplateResponse("index.html", {"request": request})

# --- Routes: API - Key Management ---

@app.post("/api/keys/generate")
@limiter.limit(get_rate_limit('key_generate'))
async def generate_keys(request: Request, data: GenerateKeyRequest):
    """Generate RSA key pair and return as JSON or ZIP."""
    try:
        # Check hourly key generation limit
        client_ip = request.client.host if request.client else 'unknown'
        check_key_generation_limit(client_ip)
        
        private_key, public_key = key_manager.generate_key_pair(data.key_size)
        
        # Serialize Private Key
        from cryptography.hazmat.primitives import serialization
        encryption = (
            serialization.BestAvailableEncryption(data.passphrase.encode())
            if data.passphrase else serialization.NoEncryption()
        )
        
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption
        )
        
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        # Return as JSON so front-end can decide what to do (display or download)
        return {
            "private_key": private_pem.decode('utf-8'),
            "public_key": public_pem.decode('utf-8')
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

# --- Routes: API - Core Signing (Text) ---

@app.post("/api/sign/message")
@limiter.limit(get_rate_limit('sign'))
async def sign_message(request: Request, data: SignMessageRequest):
    """Sign a text message."""
    try:
        # Load Private Key from PEM string
        # We write it to a temp file because key_manager expects a file path
        # actually key_manager is for storage. server logic needs to load from string.
        # Let's bypass key_manager load_from_file and use serialization directly for memory loading
        # to keep server stateless and clean.
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.backends import default_backend
        
        passphrase_bytes = data.passphrase.encode() if data.passphrase else None
        
        private_key = serialization.load_pem_private_key(
            data.private_key_pem.encode(),
            password=passphrase_bytes,
            backend=default_backend()
        )
        
        # Sign
        result = signature_service.sign_message(data.message, private_key)
        
        # Convert signature bytes to hex for display
        signature_hex = result.signature.hex()
        
        return {
            "signature": signature_hex,
            "timestamp": result.timestamp.isoformat(),
            "message_digest": result.message_digest,
            "padding_scheme": result.padding_scheme
        }
    except ValueError as e:
        # Often "Bad decrypt" -> wrong password
        raise HTTPException(status_code=400, detail="Invalid Key or Password")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/verify/message")
@limiter.limit(get_rate_limit('verify'))
async def verify_message(request: Request, data: VerifyMessageRequest):
    """Verify a text message signature."""
    try:
        # Load Public Key
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.backends import default_backend
        
        public_key = serialization.load_pem_public_key(
            data.public_key_pem.encode(),
            backend=default_backend()
        )
        
        # Convert hex signature back to bytes
        try:
            signature_bytes = bytes.fromhex(data.signature)
        except ValueError:
            # Fallback if base64? For now assume hex as per sign endpoint
            raise HTTPException(status_code=400, detail="Invalid signature format (expected hex)")
            
        # Verify
        result = signature_service.verify_signature(
            data.message, 
            signature_bytes, 
            public_key
        )
        
        return {
            "is_valid": result.is_valid,
            "error_message": result.error_message,
            "timestamp": result.timestamp.isoformat()
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# --- Routes: API - File Operations ---

@app.post("/api/sign/file")
@limiter.limit(get_rate_limit('sign'))
async def sign_file(
    request: Request,
    file: UploadFile = File(...),
    private_key: UploadFile = File(...),
    passphrase: Optional[str] = Form(None)
):
    """Sign an uploaded file."""
    try:
        # Read file content
        file_content = await file.read()
        key_content = await private_key.read()
        
        # Load Key
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.backends import default_backend
        passphrase_bytes = passphrase.encode() if passphrase else None
        
        private_rsa = serialization.load_pem_private_key(
            key_content,
            password=passphrase_bytes,
            backend=default_backend()
        )
        
        # We need to manually call the signing logic since service expects a file path
        # Or we can write a generic "sign_bytes" method in service?
        # For now, let's adapt here using internal methods of service
        
        # 1. Digest
        digest = signature_service._compute_message_digest(file_content)
        
        # 2. Sign
        padding_obj = signature_service._get_padding_scheme('PSS')
        from cryptography.hazmat.primitives import hashes
        signature = private_rsa.sign(file_content, padding_obj, hashes.SHA256())
        
        return {
            "signature": signature.hex(),
            "document_name": file.filename,
            "message_digest": digest
        }
        
    except Exception as e:
         raise HTTPException(status_code=500, detail=f"File Signing Failed: {str(e)}")

@app.post("/api/verify/file")
@limiter.limit(get_rate_limit('verify'))
async def verify_file(
    request: Request,
    file: UploadFile = File(...),
    public_key: UploadFile = File(...),
    signature: str = Form(...) # Hex string passed as form field
):
    """Verify an uploaded file against a generic signature."""
    try:
        file_content = await file.read()
        key_content = await public_key.read()
        
        # Load Public Key
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.backends import default_backend
        
        public_rsa = serialization.load_pem_public_key(
            key_content,
            backend=default_backend()
        )
        
        signature_bytes = bytes.fromhex(signature)
        
        # Verify
        padding_obj = signature_service._get_padding_scheme('PSS')
        from cryptography.hazmat.primitives import hashes
        from cryptography.exceptions import InvalidSignature
        
        try:
            public_rsa.verify(signature_bytes, file_content, padding_obj, hashes.SHA256())
            valid = True
            msg = None
        except InvalidSignature:
            valid = False
            msg = "Signature does not match file content."
            
        digest = signature_service._compute_message_digest(file_content)
        
        return {
            "is_valid": valid,
            "error_message": msg,
            "file_digest": digest
        }
        
    except Exception as e:
         raise HTTPException(status_code=500, detail=f"File Verification Failed: {str(e)}")

# --- Routes: API - Certificate Authority ---

@app.post("/api/ca/create")
@limiter.limit(get_rate_limit('ca'))
async def create_ca(
    request: Request,
    name: str = Form("Digital Signature CA"),
    passphrase: Optional[str] = Form(None)
):
    """Create a new CA identity."""
    try:
        # Generate CA Keys
        priv, pub = key_manager.generate_key_pair(4096) # Stronger keys for CA
        
        from cryptography.hazmat.primitives import serialization
        encryption = (
            serialization.BestAvailableEncryption(passphrase.encode())
            if passphrase else serialization.NoEncryption()
        )
        
        priv_pem = priv.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption
        )
        
        pub_pem = pub.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        return {
            "ca_name": name,
            "private_key": priv_pem.decode(),
            "public_key": pub_pem.decode()
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/ca/sign-certificate")
@limiter.limit(get_rate_limit('ca'))
async def sign_certificate(
    request: Request,
    subject_name: str = Form(...),
    ca_private_key: UploadFile = File(...),
    subject_public_key: UploadFile = File(...),
    passphrase: Optional[str] = Form(None),
    days: int = Form(365)
):
    """Issue a certificate (CA signs a public key)."""
    try:
        # Load CA Private Key
        ca_key_bytes = await ca_private_key.read()
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.backends import default_backend
        pass_bytes = passphrase.encode() if passphrase else None
        
        ca_priv = serialization.load_pem_private_key(ca_key_bytes, pass_bytes, default_backend())
        
        # Load Subject Public Key
        sub_key_bytes = await subject_public_key.read()
        sub_pub = serialization.load_pem_public_key(sub_key_bytes, default_backend())
        
        # Create CA Service instance temporarily
        # We need the CA public key... but wait, the signing method ONLY needs the private key
        # The CertificateService constructor asks for both, but let's see logic.
        # Logic: sign_public_key only uses self.ca_private_key.
        # hack: pass None for public key since we are only signing
        
        ca_service = CertificateAuthority(ca_priv, None, ca_name="Web CA")
        
        # Sign
        cert = ca_service.sign_public_key(sub_pub, subject_name, days)
        
        return cert.to_dict()
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/ca/verify-certificate")
@limiter.limit(get_rate_limit('verify'))
async def verify_certificate_endpoint(
    request: Request,
    certificate_file: UploadFile = File(...),
    ca_public_key: UploadFile = File(...)
):
    """Verify a certificate file."""
    try:
        cert_bytes = await certificate_file.read()
        cert_dict = json.loads(cert_bytes)
        
        cert = Certificate.from_dict(cert_dict)
        
        # Load CA Public Key
        ca_key_bytes = await ca_public_key.read()
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.backends import default_backend
        ca_pub = serialization.load_pem_public_key(ca_key_bytes, default_backend())
        
        # Verify
        # We can use the cert object directly
        try:
            valid = cert.verify(ca_pub)
            return {"is_valid": True, "subject": cert.subject, "issuer": cert.issuer}
        except Exception as e:
            return {"is_valid": False, "error": str(e)}
            
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# --- Routes: Logs ---

@app.get("/api/logs")
@limiter.limit(get_rate_limit('logs'))
async def get_logs(request: Request):
    """Get verification logs."""
    log_path = os.path.join("data", "verification_logs.json")
    if not os.path.exists(log_path):
        return []
        
    try:
        with open(log_path, 'r') as f:
            return json.load(f)
    except Exception:
        return []

if __name__ == "__main__":
    import uvicorn
    # Make sure data directory exists
    os.makedirs("data", exist_ok=True)
    uvicorn.run("server:app", host="127.0.0.1", port=8000, reload=True)
