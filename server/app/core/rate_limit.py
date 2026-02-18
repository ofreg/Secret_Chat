from collections import defaultdict
import time

login_attempts = defaultdict(list)

MAX_ATTEMPTS = 5
WINDOW_SECONDS = 60
