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
ADMIN_PASSWORD_HASH = get_password_hash(os.getenv("ADMIN_PASSWORD", "admin"))

@router.post("/token")
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    if form_data.username != ADMIN_USERNAME or not verify_password(form_data.password, ADMIN_PASSWORD_HASH):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
        
    access_token = create_access_token(subject=form_data.username)
    return {"access_token": access_token, "token_type": "bearer"}
