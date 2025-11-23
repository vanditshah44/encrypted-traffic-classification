# Benign TLS 1.3 Dataset Generator (Thesis Project)

_Automated benign traffic generator for TLS 1.3 network research_

This project is part of my **M.Sc. Cyber Security** thesis focusing on **attack detection in encrypted TLS 1.3 traffic**.  
The goal of this tool is to generate **realistic benign TLS traffic**, capture it as `.pcap` files, and store rich metadata for later feature extraction and machine-learning–based detection.

The script automates a real Firefox browser using Selenium (with your own Firefox profile and logins) and simultaneously captures all traffic via `tcpdump`. Each browsing session is labeled per site/category and stored with JSON metadata.

---

## ✨ Features

- **Automated Firefox browsing** using Selenium + GeckoDriver
- **Uses a COPY of your real Firefox profile**  
  → keeps logins, cookies, settings, but protects the original profile
- **Human-like behaviour**:
  - random delays
  - scrolling behaviour
  - random query selection (for Google)
  - random link selection on result pages
- **Traffic capture with tcpdump**:
  - interface configurable (e.g. `ens18`, `eth0`, `enp0s3`)
  - full packets (`-s 0`), no DNS resolution (`-n`)
- **Per-site sessions**:
  - configurable session duration (default: 30 minutes per site)
  - curated list of popular sites in different categories:
    - search, video, social, news, tech, shopping, music, etc.
- **Metadata for each capture** (JSON):
  - site name, category, label
  - start/end times (UTC)
  - duration
  - pcap filename
  - error information if something fails
- **Telegram integration** (optional):
  - sends start/finish/fatal error notifications to a Telegram chat
- **Filesystem layout**:
  - `tls_dataset/pcaps` – raw pcaps
  - `tls_dataset/meta` – JSON metadata

---

## 🧱 Project Structure

The core logic is in a single script:

- `main.py` – orchestrates:
  - starting tcpdump
  - launching Firefox
  - simulating browsing behaviour for each site
  - capturing and labeling traffic
  - writing metadata
  - sending Telegram notifications

Configurable values (tokens, interface, profile, etc.) are read from:

- `config.py` (user-created, not committed)

---

## ⚙️ Requirements

### System

- Linux environment (e.g. Ubuntu in VM / Proxmox guest)
- `tcpdump` installed and `sudo` rights to run it
- Firefox browser installed
- Python 3.8+ recommended



---

## 🔐 Configuration

Create a `config.py` next to `main.py` with your own values:

```python
# config.py (example)

# Telegram bot (optional; leave empty if you don’t want notifications)
tgBOT = ""      # e.g. "1234567890:ABCDEF..."
chatID = ""     # e.g. your chat ID as string

# Path to your real Firefox profile (with logins/cookies)
# To find it, open Firefox → about:support → "Profile Directory"
profilePath = "/home/youruser/.mozilla/firefox/abcd1234.default-release"
```


---

## 🌐 Firefox Profile Handling

The script:

1. Reads `FIREFOX_PROFILE_PATH` from `config.profilePath`.
2. Copies that entire profile into a **temporary directory** each run:
   - by default under `$TMPDIR/selenium-firefox-profile`
3. Launches Firefox with:
   - `-profile <copied_profile_path>`
4. Applies some TLS/DoH preferences:
   - `security.tls.version.min = 4`
   - `security.tls.version.max = 4`
   - `network.trr.mode = 3`
   - `network.trr.uri = https://mozilla.cloudflare-dns.com/dns-query`
   - `network.trr.custom.uri = https://mozilla.cloudflare-dns.com/dns-query`

This approach gives you:

- realistic traffic using **your actual accounts/sessions**
- safety against corrupting your real profile
- no “profile in use” lock issues

---

## 🧪 Supported Sites & Behaviours

Each site has its own handler function with simple but realistic behaviour:

- **Search**
  - `google`  
    - random queries from a curated list  
    - search, scroll results, click non-Google links, sometimes go back

- **Video**
  - `youtube`  
    - open homepage, click random videos, scroll, return to homepage

- **Social**
  - `instagram`, `twitter (x.com)`, `facebook`, `reddit`, `linkedin`  
    - open feed/home, scroll for a while with pauses

- **Shopping**
  - `amazon`, `ebay`  
    - random product queries, search, scroll product listings

- **News / Info**
  - `cnn`, `bbc`, `wikipedia`  
    - scroll pages; on Wikipedia, search random topics and read articles

- **Music**
  - `spotify`  
    - open, scroll UI to simulate browsing

- **Dev / Tech**
  - `stackoverflow`, `github`  
    - open questions/trending repos, scroll lists

Each site has a `browse_<site>()` function and is registered in `SITE_CONFIGS`.

---

## ▶️ Running the Script

1. Make sure `tcpdump` is installed:

```bash
sudo apt install tcpdump
```

2. Ensure your capture interface is correct in `main.py`:

```python
CAPTURE_IFACE = "ens18"  # change to eth0, enp0s3, etc. if needed
```

3. Optionally, set a temporary directory for the Firefox profile copy:

```bash
export TMPDIR="$HOME/firefox-tmp"
```

4. Run:

```bash
TMPDIR="$HOME/firefox-tmp" python3 main.py
```

The script will:

- iterate over all entries in `SITE_CONFIGS`
- for each site:
  - start `tcpdump`
  - open Firefox with your (copied) profile
  - run that site’s browsing behaviour for `SESSION_DURATION_SEC` (default 30 min)
  - stop the capture
  - write metadata JSON
  - send Telegram notifications (if configured)

---

## 📂 Output Layout

By default, data is stored under `~/tls_dataset`:

```text
tls_dataset/
├── pcaps/
│   ├── search_google_20250101T120000Z.pcap
│   ├── video_youtube_20250101T123000Z.pcap
│   └── ...
└── meta/
    ├── search_google_20250101T120000Z.json
    ├── video_youtube_20250101T123000Z.json
    └── ...
```

Sample metadata file:

```json
{
  "site": "google",
  "category": "search",
  "label": "search_google",
  "start_utc": "2025-01-01T12:00:00Z",
  "end_utc": "2025-01-01T12:30:05Z",
  "duration_sec": 1800,
  "pcap_file": "search_google_20250101T120000Z.pcap",
  "error": null
}
```

---

## 🔭 Future Work

Some ideas for extending and improving this project:

- **Richer per-site behaviour**
  - Simulate logins / account interactions (messages, comments, likes) where ethically and legally allowed
  - Follow internal links, browse multiple pages per session
  - Add device/OS variations via user-agents

- **Traffic diversity**
  - Add more websites (banking portals, cloud dashboards, dev platforms)
  - Vary connection settings (e.g. different DNS resolvers, proxies, VPNs)

- **Labeling & ML pipeline**
  - Convert pcaps to flow-based CSV/Parquet using tools like Zeek/TShark
  - Extract TLS-level features (JA3/JA4, SNI, cipher suites, packet timings)
  - Train supervised/unsupervised models for benign vs. malicious detection
  - Integrate with Jupyter notebooks for exploratory data analysis

- **Automation & orchestration**
  - Dockerize the environment
  - Integrate with Proxmox APIs to spin up dedicated capture VMs
  - Add scheduling / cron-based long-running data collection

- **Robustness**
  - Better retry logic on site failures / timeouts
  - Fine-grained logging and metrics (e.g. Prometheus/Grafana integration)

---

## ⚖️ Ethics & Responsible Use

This tool is intended **strictly for research and educational purposes**:

- generating benign TLS traffic for academic work
- building datasets for intrusion detection & anomaly detection
- studying encrypted traffic patterns

Users are responsible for:

- complying with the Terms of Service of visited websites
- respecting legal and ethical constraints
- not using this tool for abusive, malicious, or unauthorized traffic generation

---

## 📎 Thesis Context

This project is part of my ongoing work on:

> **“Attack Detection in Encrypted TLS 1.3 ”**

It demonstrates:

- practical skills in network security
- Python automation
- browser instrumentation
- dataset engineering
- lab setup for encrypted traffic analysis

Feel free to reach out if you’re interested in the research or potential collaboration.
