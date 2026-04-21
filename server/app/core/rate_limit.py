import os
from collections import defaultdict
import time

login_attempts = defaultdict(list)
forgot_password_attempts = defaultdict(list)

MAX_ATTEMPTS = int(os.getenv("LOGIN_RATE_LIMIT_MAX_ATTEMPTS", 5))
WINDOW_SECONDS = int(os.getenv("LOGIN_RATE_LIMIT_WINDOW_SECONDS", 60))
FORGOT_PASSWORD_MAX_ATTEMPTS = int(os.getenv("FORGOT_PASSWORD_RATE_LIMIT_MAX_ATTEMPTS", 5))
FORGOT_PASSWORD_WINDOW_SECONDS = int(os.getenv("FORGOT_PASSWORD_RATE_LIMIT_WINDOW_SECONDS", 300))
