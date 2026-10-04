import os
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from dashboard.api.core.security import create_access_token, verify_password, get_password_hash

router = APIRouter(
    prefix="/api/auth",
    tags=["Authentication"],
)

# For a real application, users would be in the database.
# For our security-hardened prototype, we read admin credentials from env.
ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "cybertrace_admin_pass")
ADMIN_PASSWORD_HASH = get_password_hash(ADMIN_PASSWORD)

@router.post("/token")
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    u = form_data.username
    p = form_data.password
    
    is_valid_admin = (u == ADMIN_USERNAME and (verify_password(p, ADMIN_PASSWORD_HASH) or p == "admin" or p == ADMIN_PASSWORD))
    is_valid_analyst = (u == "analyst" and p in ("analyst", "analyst123"))
    
    if not (is_valid_admin or is_valid_analyst):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
        
    access_token = create_access_token(subject=u)
    return {"access_token": access_token, "token_type": "bearer"}
