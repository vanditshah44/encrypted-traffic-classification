import os
import json
import time
import random
import subprocess
from datetime import datetime
from pathlib import Path

import requests
from selenium import webdriver
from selenium.webdriver.firefox.options import Options
from selenium.common.exceptions import WebDriverException, NoSuchElementException
from webdriver_manager.firefox import GeckoDriverManager
from selenium.webdriver.firefox.service import Service
import config
# ==========================
# CONFIGURATION
# ==========================

# --- IMPORTANT: change these ---
TELEGRAM_BOT_TOKEN = config.tgBOT
TELEGRAM_CHAT_ID = config.chatID

# Name of the network interface inside the VM (check with `ip a`)
CAPTURE_IFACE = "ens18"  # <-- CHANGE if needed (e.g. enp0s3, eth0, etc.)

# Where to save captures and metadata
BASE_DIR = Path.home() / "tls_dataset"
PCAP_DIR = BASE_DIR / "pcaps"
META_DIR = BASE_DIR / "meta"

# Session length per site (in seconds)
SESSION_DURATION_SEC = 30 * 60  # 30 minutes

# Firefox profile (optional): if you want to keep logins,
# create/log in once in that profile and put the path here.
# To find profiles, run `firefox -P` and check paths in about:support.
FIREFOX_PROFILE_PATH = config.profilePath  # e.g. "/home/youruser/.mozilla/firefox/abcd1234.default-release"

# Use headless? (False = you see the browser, easier for debugging)
HEADLESS = False


# ==========================
# TELEGRAM HELPERS
# ==========================

def send_telegram(message: str):
    """Send a message to your Telegram chat."""
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        print(f"[WARN] Telegram not configured, message was: {message}")
        return

    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    try:
        requests.post(url, data={"chat_id": TELEGRAM_CHAT_ID, "text": message[:4000]})
    except Exception as e:
        print(f"[ERROR] Failed to send Telegram message: {e}")


# ==========================
# TCPDUMP HELPERS
# ==========================

def start_capture(label: str) -> (subprocess.Popen, Path):
    """
    Start tcpdump capture on CAPTURE_IFACE with a labeled filename.
    Returns (process, path_to_pcap).
    """
    timestamp = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    pcap_filename = f"{label}_{timestamp}.pcap"
    pcap_path = PCAP_DIR / pcap_filename
    PCAP_DIR.mkdir(parents=True, exist_ok=True)

    cmd = [
        "sudo", "tcpdump",
        "-i", CAPTURE_IFACE,
        "-s", "0",       # full packet
        "-n",            # no DNS resolution
        "-w", str(pcap_path)
    ]
    print(f"[+] Starting capture: {' '.join(cmd)}")
    try:
        proc = subprocess.Popen(cmd)
    except Exception as e:
        send_telegram(f"[FATAL] Failed to start tcpdump for {label}: {e}")
        raise
    return proc, pcap_path


def stop_capture(proc: subprocess.Popen, label: str):
    """Stop tcpdump cleanly."""
    if proc is None:
        return
    print(f"[+] Stopping capture for {label}")
    try:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
    except Exception as e:
        send_telegram(f"[WARN] Failed to terminate tcpdump for {label}: {e}")


# ==========================
# BROWSER / HUMAN-LIKE HELPERS
# ==========================
def create_firefox_driver() -> webdriver.Firefox:
    """Create and return a Firefox WebDriver instance using a COPY of your real profile."""

    if not FIREFOX_PROFILE_PATH:
        raise RuntimeError("FIREFOX_PROFILE_PATH is not set in config.profilePath")

    profile_src = Path(FIREFOX_PROFILE_PATH).expanduser()

    if not profile_src.is_dir():
        raise RuntimeError(f"Firefox profile path does not exist: {profile_src}")

    # Where to put the per-run copy of the profile
    tmp_root = Path(os.environ.get("TMPDIR", "/tmp"))
    run_profile = tmp_root / "selenium-firefox-profile"

    # Clean old copy if exists, then copy fresh
    if run_profile.exists():
        shutil.rmtree(run_profile)
    shutil.copytree(profile_src, run_profile)

    print(f"[+] Using Firefox profile copy at: {run_profile}")

    options = Options()
    options.headless = HEADLESS

    # Tell Firefox to use this profile directory
    options.add_argument("-profile")
    options.add_argument(str(run_profile))

    # TLS / DoH preferences as you had
    options.set_preference("security.tls.version.min", 4)
    options.set_preference("security.tls.version.max", 4)
    options.set_preference("network.trr.mode", 3)
    options.set_preference("network.trr.uri", "https://mozilla.cloudflare-dns.com/dns-query")
    options.set_preference("network.trr.custom.uri", "https://mozilla.cloudflare-dns.com/dns-query")

    # If you are using a custom non-snap Firefox binary, point to it here:
    # options.binary_location = "/home/youruser/firefox/firefox"

    service = Service(GeckoDriverManager().install())

    driver = webdriver.Firefox(
        service=service,
        options=options,
    )
    driver.set_page_load_timeout(60)
    return driver


def human_pause(min_sec=5.0, max_sec=30.0):
    time.sleep(random.uniform(min_sec, max_sec))


def human_scroll_page(driver, total_scroll_time: int):
    """Scroll down the page for total_scroll_time seconds with random steps."""
    start = time.time()
    while time.time() - start < total_scroll_time:
        scroll_amount = random.randint(200, 800)
        driver.execute_script("window.scrollBy(0, arguments[0]);", scroll_amount)
        human_pause(1.0, 3.0)


# ==========================
# SITE-SPECIFIC BEHAVIOURS
# (simple but extendable)
# ==========================

QUERIES = [
    # Tech / CS / Cyber
    "linux commands cheat sheet",
    "how to secure a web server",
    "kali linux tutorial",
    "what is tls 1.3",
    "difference between tcp and udp",
    "best laptop for programming 2025",
    "how to learn penetration testing",
    "what is docker container",
    "how to use proxmox",
    "introduction to machine learning",

    # Everyday stuff
    "weather in munich today",
    "cheap vegetarian recipes",
    "how to sleep better at night",
    "how to build a study routine",
    "how many calories in banana",
    "bus route from munich to berlin",
    "best budget earphones under 50 euro",
    "how to fix slow wifi",
    "how to unclog a sink",

    # News / Finance
    "latest tech news",
    "stock market news today",
    "bitcoin price chart",
    "europe inflation rate 2025",
    "best index funds long term",
    "german economy news",

    # Entertainment
    "best movies on netflix",
    "top bollywood movies 2020",
    "funny cat videos",
    "latest football highlights",
    "cristiano ronaldo goals",
    "best anime of all time",

    # Shopping intent
    "best mechanical keyboard",
    "cheap gaming mouse",
    "office chair for back pain",
    "noise cancelling headphones",
    "portable monitor for laptop",
    "refurbished thinkpad germany",

    # Education / Career
    "cyber security jobs in germany",
    "how to write a good cv",
    "how to prepare for interview",
    "online courses for data science",
    "free cyber security courses",
    "learn german b1 free",

    # Random questions
    "why is the sky blue",
    "how planes fly",
    "benefits of being vegetarian",
    "how to gain weight healthy",
    "best morning routine for students",
    "how many hours should i study a day",
]

def browse_google(driver, session_seconds):
    driver.get("https://www.google.com")
    human_pause(3, 5)

    start = time.time()
    while time.time() - start < session_seconds:
        try:
            # 1) Pick a random query
            query = random.choice(QUERIES)

            # 2) Go to google home (fresh)
            driver.get("https://www.google.com")
            human_pause(2, 4)

            # 3) Find the search box and search
            box = driver.find_element("name", "q")
            box.clear()
            box.send_keys(query)
            box.submit()
            human_pause(3, 6)

            # 4) Scroll the results page a bit
            human_scroll_page(driver, random.randint(5, 15))

            # 5) Collect result links (avoid google internal links)
            results = driver.find_elements(
                "css selector",
                "div#search a[href]"
            )

            links = []
            for r in results:
                href = r.get_attribute("href")
                if not href:
                    continue
                # skip Google internal links
                if "google." in href:
                    continue
                links.append(r)

            # 6) Click a random result if available
            if links:
                link = random.choice(links)
                try:
                    link.click()
                    # stay on the result page for a bit, scroll like a human
                    human_pause(3, 7)
                    human_scroll_page(driver, random.randint(10, 25))
                    human_pause(3, 8)
                except WebDriverException as e:
                    print(f"[WARN] Failed to click result: {e}")

                # 7) Sometimes go back, sometimes start a fresh search
                if random.random() < 0.5:
                    try:
                        driver.back()
                        human_pause(2, 4)
                    except WebDriverException:
                        pass

            # 8) Pause before next query
            human_pause(5, 12)

        except NoSuchElementException:
            # If search box or something not found, just try again
            human_pause(3, 6)
        except WebDriverException as e:
            print(f"[WARN] WebDriver error in browse_google: {e}")
            human_pause(5, 10)



def browse_youtube(driver, session_seconds):
    driver.get("https://www.youtube.com")
    human_pause(5, 8)

    start = time.time()
    while time.time() - start < session_seconds:
        # Click a random video on the homepage
        try:
            videos = driver.find_elements("css selector", "ytd-rich-item-renderer a#thumbnail")
            if videos:
                random.choice(videos).click()
                human_pause(5, 10)
                # Scroll comments / suggested videos
                human_scroll_page(driver, random.randint(20, 40))
        except WebDriverException as e:
            print(f"[WARN] YouTube click failed: {e}")
        human_pause(5, 10)
        driver.get("https://www.youtube.com")
        human_pause(3, 5)


def browse_instagram(driver, session_seconds):
    driver.get("https://www.instagram.com")
    human_pause(5, 8)
    start = time.time()
    while time.time() - start < session_seconds:
        # Scroll feed
        human_scroll_page(driver, random.randint(10, 25))
        human_pause(5, 10)


def browse_twitter(driver, session_seconds):
    driver.get("https://x.com/home")
    human_pause(5, 8)
    start = time.time()
    while time.time() - start < session_seconds:
        human_scroll_page(driver, random.randint(10, 25))
        human_pause(5, 10)


def browse_facebook(driver, session_seconds):
    driver.get("https://www.facebook.com")
    human_pause(5, 8)
    start = time.time()
    while time.time() - start < session_seconds:
        human_scroll_page(driver, random.randint(10, 25))
        human_pause(5, 10)


def browse_reddit(driver, session_seconds):
    driver.get("https://www.reddit.com")
    human_pause(5, 8)
    start = time.time()
    while time.time() - start < session_seconds:
        human_scroll_page(driver, random.randint(15, 30))
        human_pause(5, 10)


def browse_linkedin(driver, session_seconds):
    driver.get("https://www.linkedin.com/feed/")
    human_pause(5, 8)
    start = time.time()
    while time.time() - start < session_seconds:
        human_scroll_page(driver, random.randint(10, 20))
        human_pause(5, 10)


def browse_amazon(driver, session_seconds):
    driver.get("https://www.amazon.com")
    human_pause(5, 8)
    start = time.time()
    while time.time() - start < session_seconds:
        try:
            box = driver.find_element("id", "twotabsearchtextbox")
            query = random.choice(["laptop", "headphones", "keyboard", "shoes"])
            box.clear()
            box.send_keys(query)
            box.submit()
            human_pause(5, 8)
            human_scroll_page(driver, random.randint(15, 30))
        except NoSuchElementException:
            pass
        human_pause(5, 10)


def browse_ebay(driver, session_seconds):
    driver.get("https://www.ebay.com")
    human_pause(5, 8)
    start = time.time()
    while time.time() - start < session_seconds:
        try:
            box = driver.find_element("id", "gh-ac")
            query = random.choice(["watch", "phone", "camera"])
            box.clear()
            box.send_keys(query)
            box.submit()
            human_pause(5, 8)
            human_scroll_page(driver, random.randint(15, 30))
        except NoSuchElementException:
            pass
        human_pause(5, 10)


def browse_cnn(driver, session_seconds):
    driver.get("https://www.cnn.com")
    human_pause(5, 8)
    start = time.time()
    while time.time() - start < session_seconds:
        human_scroll_page(driver, random.randint(15, 30))
        human_pause(5, 10)


def browse_bbc(driver, session_seconds):
    driver.get("https://www.bbc.com/news")
    human_pause(5, 8)
    start = time.time()
    while time.time() - start < session_seconds:
        human_scroll_page(driver, random.randint(15, 30))
        human_pause(5, 10)


def browse_wikipedia(driver, session_seconds):
    driver.get("https://www.wikipedia.org")
    human_pause(3, 5)
    start = time.time()
    while time.time() - start < session_seconds:
        try:
            # Go to random article via search
            search_input = driver.find_element("id", "searchInput")
            term = random.choice(["Germany", "Machine learning", "Cybersecurity", "Music", "Football"])
            search_input.clear()
            search_input.send_keys(term)
            search_input.submit()
            human_pause(5, 8)
            human_scroll_page(driver, random.randint(10, 20))
            driver.back()
            human_pause(3, 5)
        except NoSuchElementException:
            break


def browse_spotify(driver, session_seconds):
    driver.get("https://open.spotify.com")
    human_pause(8, 12)
    start = time.time()
    while time.time() - start < session_seconds:
        human_scroll_page(driver, random.randint(10, 20))
        human_pause(5, 10)


def browse_stackoverflow(driver, session_seconds):
    driver.get("https://stackoverflow.com/questions")
    human_pause(5, 8)
    start = time.time()
    while time.time() - start < session_seconds:
        human_scroll_page(driver, random.randint(15, 25))
        human_pause(5, 10)


def browse_github(driver, session_seconds):
    driver.get("https://github.com/trending")
    human_pause(5, 8)
    start = time.time()
    while time.time() - start < session_seconds:
        human_scroll_page(driver, random.randint(10, 20))
        human_pause(5, 10)





# ==========================
# SITE LIST
# ==========================

SITE_CONFIGS = [
    # Search
    {"name": "google", "category": "search", "handler": browse_google},

    # Video
    {"name": "youtube", "category": "video", "handler": browse_youtube},

    # Social
    {"name": "instagram", "category": "social", "handler": browse_instagram},
    {"name": "twitter",   "category": "social", "handler": browse_twitter},
    {"name": "facebook",  "category": "social", "handler": browse_facebook},
    {"name": "reddit",    "category": "social", "handler": browse_reddit},
    {"name": "linkedin",  "category": "social", "handler": browse_linkedin},

    # Shopping
    {"name": "amazon", "category": "shopping", "handler": browse_amazon},
    {"name": "ebay",   "category": "shopping", "handler": browse_ebay},

    # News / Info
    {"name": "cnn",       "category": "news", "handler": browse_cnn},
    {"name": "bbc",       "category": "news", "handler": browse_bbc},
    {"name": "wikipedia", "category": "news", "handler": browse_wikipedia},

    # Music / Entertainment
    {"name": "spotify", "category": "music", "handler": browse_spotify},

    # Dev / Tech
    {"name": "stackoverflow", "category": "tech", "handler": browse_stackoverflow},
    {"name": "github",        "category": "tech", "handler": browse_github},

    # Messaging
    
]


# ==========================
# MAIN SESSION LOGIC
# ==========================

def run_site_session(site_cfg):
    """
    For one site:
      - start tcpdump
      - start Firefox
      - run browsing behaviour for SESSION_DURATION_SEC
      - stop tcpdump
      - write small metadata json
    """
    name = site_cfg["name"]
    category = site_cfg["category"]
    handler = site_cfg["handler"]

    label = f"{category}_{name}"
    send_telegram(f"Starting session for {name} [{category}]")

    meta = {
        "site": name,
        "category": category,
        "label": label,
        "start_utc": datetime.utcnow().isoformat() + "Z",
        "duration_sec": SESSION_DURATION_SEC,
        "pcap_file": None,
        "error": None,
    }

    META_DIR.mkdir(parents=True, exist_ok=True)

    proc = None
    driver = None
    try:
        proc, pcap_path = start_capture(label)
        meta["pcap_file"] = str(pcap_path.name)

        driver = create_firefox_driver()
        session_start = time.time()

        # Run handler but ensure it doesn't exceed SESSION_DURATION_SEC
        handler(driver, SESSION_DURATION_SEC)

        # If handler returns earlier, we still ensure minimum session time if you want
        # while time.time() - session_start < SESSION_DURATION_SEC:
        #     time.sleep(5)

        send_telegram(f"Finished behaviour for {name}, stopping capture...")
    except Exception as e:
        err_msg = f"[ERROR] Session for {name} failed: {e}"
        print(err_msg)
        meta["error"] = str(e)
        send_telegram(err_msg)
    finally:
        if driver is not None:
            try:
                driver.quit()
            except Exception:
                pass
        if proc is not None:
            stop_capture(proc, label)

        meta["end_utc"] = datetime.utcnow().isoformat() + "Z"
        meta_path = META_DIR / f"{label}_{datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')}.json"
        with open(meta_path, "w") as f:
            json.dump(meta, f, indent=2)

        print(f"[+] Metadata written to {meta_path}")


def main():
    BASE_DIR.mkdir(parents=True, exist_ok=True)
    PCAP_DIR.mkdir(parents=True, exist_ok=True)
    META_DIR.mkdir(parents=True, exist_ok=True)

    send_telegram("=== TLS benign capture bot starting ===")

    for site in SITE_CONFIGS:
        run_site_session(site)

    send_telegram("=== TLS benign capture bot finished all sites ===")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        send_telegram(f"[FATAL] Main crashed: {exc}")
        raise
