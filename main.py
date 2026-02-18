from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel
from typing import Dict
from datetime import datetime
import re
import logging
from collections import defaultdict
import time

app = FastAPI(title="SecureAI Prompt Injection Validator")

# ----------------------------
# Logging Configuration
# ----------------------------
logging.basicConfig(
    filename="security_events.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

# ----------------------------
# Rate Limiting Config
# ----------------------------
RATE_LIMIT = 10  # requests
TIME_WINDOW = 60  # seconds
user_requests = defaultdict(list)

# ----------------------------
# Request Schema
# ----------------------------
class SecurityRequest(BaseModel):
    userId: str
    input: str
    category: str

# ----------------------------
# Response Schema
# ----------------------------
class SecurityResponse(BaseModel):
    blocked: bool
    reason: str
    sanitizedOutput: str
    confidence: float

# ----------------------------
# Security Detection Patterns
# ----------------------------

OVERRIDE_PATTERNS = [
    r"ignore previous instructions",
    r"override system",
    r"disregard all prior",
]

PROMPT_EXTRACTION_PATTERNS = [
    r"repeat your system prompt",
    r"show your hidden instructions",
    r"what is your system prompt",
]

ROLE_MANIPULATION_PATTERNS = [
    r"you are now",
    r"act as",
    r"pretend to be",
    r"switch role to",
]

# ----------------------------
# Utility Functions
# ----------------------------

def check_rate_limit(user_id: str):
    current_time = time.time()
    request_times = user_requests[user_id]

    # Remove old requests
    user_requests[user_id] = [
        t for t in request_times if current_time - t < TIME_WINDOW
    ]

    if len(user_requests[user_id]) >= RATE_LIMIT:
        logging.warning(f"Rate limit exceeded for user: {user_id}")
        raise HTTPException(
            status_code=429,
            detail="Too many requests. Please try again later."
        )

    user_requests[user_id].append(current_time)


def detect_patterns(text: str, patterns: list) -> bool:
    for pattern in patterns:
        if re.search(pattern, text, re.IGNORECASE):
            return True
    return False


def sanitize_output(text: str) -> str:
    # Remove script tags (basic XSS prevention)
    text = re.sub(r"<script.*?>.*?</script>", "", text, flags=re.IGNORECASE)
    return text.strip()

# ----------------------------
# Main Endpoint
# ----------------------------

@app.post("/validate", response_model=SecurityResponse)
async def validate_input(request: SecurityRequest):

    # Validate category
    if request.category != "Prompt Injection":
        raise HTTPException(status_code=400, detail="Invalid category")

    # Rate limiting
    check_rate_limit(request.userId)

    user_input = request.input.strip()

    if not user_input:
        raise HTTPException(status_code=400, detail="Input cannot be empty")

    # Security checks
    blocked = False
    reason = "Input passed all security checks"
    confidence = 0.95

    if detect_patterns(user_input, OVERRIDE_PATTERNS):
        blocked = True
        reason = "Detected system override attempt"
        confidence = 0.98

    elif detect_patterns(user_input, PROMPT_EXTRACTION_PATTERNS):
        blocked = True
        reason = "Detected system prompt extraction attempt"
        confidence = 0.99

    elif detect_patterns(user_input, ROLE_MANIPULATION_PATTERNS):
        blocked = True
        reason = "Detected role manipulation attempt"
        confidence = 0.97

    # Log event
    if blocked:
        logging.warning(
            f"Blocked input from user {request.userId}: {reason}"
        )
    else:
        logging.info(f"Allowed input from user {request.userId}")

    sanitized_output = "" if blocked else sanitize_output(user_input)

    return SecurityResponse(
        blocked=blocked,
        reason=reason,
        sanitizedOutput=sanitized_output,
        confidence=confidence
    )

