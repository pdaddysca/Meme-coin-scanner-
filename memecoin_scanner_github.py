
"""
Meme Coin Scanner Bot — GitHub Actions version (v3, Moralis removed)
-----------------------------------------------------------------------------
Single scan per invocation — GitHub Actions' own schedule handles repeating.
Alert-only. Does NOT buy or execute anything.

NOTE: Moralis discontinued its free tier (Aug 2026) — removed from this
script. Holder count + top-10 concentration now come from GoPlus Security
instead, which is free with no signup/key needed at all. One less account
to manage.

CORRECTIONS APPLIED (per your instructions, in your stated order):
  1. Only alert if 1h price change is between +5% and +40%
  2. Only alert on pools less than 30 minutes old
  3. Holder count unknown (N/A) = automatic FAIL, not a skip
  4. Top 10 holders must hold less than 30% of supply
  9. Token price logged at the moment of the signal (signal_log.json)
  5. Minimum liquidity raised to $25,000
  6. Blocked if 24h volume is more than 15x liquidity
  7. Blocked if name is a duplicate/near-duplicate of a previously alerted token
  8. Ethereum tokens: must pass LP-lock + honeypot check, else skipped
  10. Blocked if RugCheck score is risky (Solana only)

HONESTY NOTE: with all of these stacked together, expect few or zero alerts
in many scan windows — that's the intended effect, not a bug. GoPlus's
Solana support is newer and less battle-tested than its Ethereum/Base
support — watch its output during paper testing to confirm it's returning
sane numbers before trusting it.

DATA SOURCES:
  - DexScreener (free, no key)      -> price, liquidity, volume, age, socials
  - RugCheck (free, Solana only)    -> risk score
  - GoPlus Security (free, no key)  -> holder count, top-10 %, LP lock, honeypot
  - Bubblemaps (unofficial)         -> linked-wallet cluster %, best-effort
  - Telegram Bot API                -> sends the alert

CONFIG: values below come from environment variables (GitHub Secrets),
since this file lives in a public repo.
"""

import requests
import time
import json
import os
import difflib

# ============ CONFIG (from GitHub Secrets / environment variables) ============

TELEGRAM_BOT_TOKEN = os.environ["TELEGRAM_BOT_TOKEN"]
TELEGRAM_CHAT_ID = os.environ["TELEGRAM_CHAT_ID"]

CHAINS = ["solana", "base", "ethereum"]

# GoPlus Security chain IDs (EVM chains use numeric IDs; Solana has its own path)
GOPLUS_CHAIN_MAP = {
    "ethereum": "1",
    "base": "8453",
}

FILTERS = {
    "min_liquidity_usd": 25000,          # correction 5
    "max_age_minutes": 30,               # correction 2
    "min_volume_24h_usd": 20000,
    "min_vol_to_liq_ratio": 0.5,
    "max_vol_to_liq_ratio": 15,          # correction 6
    "min_price_change_1h_pct": 5,        # correction 1 (lower bound)
    "max_price_change_1h_pct": 40,       # correction 1 (upper bound)
    "require_social_link": True,
    "min_holder_count": 50,
    "max_top10_holder_pct": 30,          # correction 4
    "max_cluster_pct": 25,               # bubble map check, best-effort
    "name_similarity_threshold": 0.85,   # correction 7
    "max_rugcheck_score": 50,            # correction 10 (adjust once you see real scores)
    "min_lp_locked_pct": 50,             # correction 8
}

SEEN_FILE = "seen_tokens.json"
NAMES_FILE = "alerted_names.json"
SIGNAL_LOG_FILE = "signal_log.json"

# ============ STATE ============

def load_json_set(path):
    if os.path.exists(path):
        with open(path, "r") as f:
            return set(json.load(f))
    return set()

def save_json_set(path, data):
    with open(path, "w") as f:
        json.dump(list(data), f)

def load_signal_log():
    if os.path.exists(SIGNAL_LOG_FILE):
        with open(SIGNAL_LOG_FILE, "r") as f:
            return json.load(f)
    return []

def save_signal_log(log):
    with open(SIGNAL_LOG_FILE, "w") as f:
        json.dump(log, f, indent=2)

# ============ DATA FETCHING ============

def get_latest_token_profiles():
    url = "https://api.dexscreener.com/token-profiles/latest/v1"
    try:
        resp = requests.get(url, timeout=10)
        resp.raise_for_status()
        return resp.json()
    except Exception as e:
        print(f"[error] fetching token profiles: {e}")
        return []

def get_pair_data(chain_id, token_address):
    url = f"https://api.dexscreener.com/latest/dex/tokens/{token_address}"
    try:
        resp = requests.get(url, timeout=10)
        resp.raise_for_status()
        data = resp.json()
        pairs = data.get("pairs") or []
        pairs = [p for p in pairs if p.get("chainId") == chain_id]
        if not pairs:
            return None
        return max(pairs, key=lambda p: p.get("liquidity", {}).get("usd", 0))
    except Exception as e:
        print(f"[error] fetching pair data for {token_address}: {e}")
        return None

def has_social_presence(pair):
    info = pair.get("info", {})
    return bool(info.get("websites") or info.get("socials"))

def get_goplus_security(chain_id, token_address):
    """
    Free, no-key security + holder data via GoPlus.
    Returns dict with holder_count, top10_pct, is_honeypot, lp_locked_pct,
    or None if unavailable (caller treats None as FAIL for the relevant checks).

    NOTE: GoPlus's Solana endpoint is newer/less proven than its EVM one —
    verify its numbers against a few real tokens during paper testing.
    """
    try:
        if chain_id == "solana":
            url = f"https://api.gopluslabs.io/api/v1/solana/token_security?contract_addresses={token_address}"
        else:
            goplus_chain = GOPLUS_CHAIN_MAP.get(chain_id)
            if not goplus_chain:
                return None
            url = f"https://api.gopluslabs.io/api/v1/token_security/{goplus_chain}?contract_addresses={token_address}"

        resp = requests.get(url, timeout=10)
        if resp.status_code != 200:
            return None
        data = resp.json()
        result = data.get("result", {})
        token_data = result.get(token_address.lower()) or result.get(token_address)
        if not token_data:
            return None

        holder_count_raw = token_data.get("holder_count")
        holder_count = int(holder_count_raw) if holder_count_raw not in (None, "") else None

        holders = token_data.get("holders", []) or []
        top10_pct = None
        if holders:
            sorted_holders = sorted(holders, key=lambda h: float(h.get("percent", 0) or 0), reverse=True)
            top10_pct = sum(float(h.get("percent", 0) or 0) for h in sorted_holders[:10]) * 100

        is_honeypot = token_data.get("is_honeypot") == "1"
        lp_holders = token_data.get("lp_holders", []) or []
        lp_locked_pct = sum(
            float(h.get("percent", 0) or 0) * 100
            for h in lp_holders
            if h.get("is_locked") in (1, "1")
        )

        return {
            "holder_count": holder_count,
            "top10_pct": top10_pct,
            "is_honeypot": is_honeypot,
            "lp_locked_pct": lp_locked_pct,
        }
    except Exception as e:
        print(f"[error] fetching goplus security for {token_address}: {e}")
        return None

def get_bubblemap_cluster_pct(chain_id, token_address):
    """Best-effort, unofficial endpoint. Returns None (skipped) if unavailable."""
    bm_chain = {"solana": "sol", "ethereum": "eth", "base": "base"}.get(chain_id)
    if not bm_chain:
        return None

    url = f"https://api-legacy.bubblemaps.io/map-data?token={token_address}&chain={bm_chain}"
    try:
        resp = requests.get(url, timeout=10)
        if resp.status_code != 200:
            return None
        data = resp.json()
        nodes = data.get("nodes", [])
        if not nodes:
            return None

        cluster_totals, cluster_sizes = {}, {}
        for node in nodes:
            cid = node.get("cluster")
            pct = node.get("percentage", 0) or 0
            if cid is None:
                continue
            cluster_totals[cid] = cluster_totals.get(cid, 0) + pct
            cluster_sizes[cid] = cluster_sizes.get(cid, 0) + 1

        linked_pcts = [pct for cid, pct in cluster_totals.items() if cluster_sizes.get(cid, 0) > 1]
        return max(linked_pcts) if linked_pcts else 0
    except Exception as e:
        print(f"[error] fetching bubblemap data for {token_address}: {e}")
        return None

def get_rugcheck_report(token_address):
    """Solana only. Correction 10 uses this to block risky-scored tokens."""
    url = f"https://api.rugcheck.xyz/v1/tokens/{token_address}/report"
    try:
        resp = requests.get(url, timeout=10)
        if resp.status_code != 200:
            return None
        return resp.json()
    except Exception as e:
        print(f"[error] fetching rugcheck for {token_address}: {e}")
        return None

# ============ DUPLICATE NAME CHECK (correction 7) ============

def normalize_name(name):
    return "".join(ch.lower() for ch in (name or "") if ch.isalnum())

def is_duplicate_name(name, alerted_names):
    norm = normalize_name(name)
    if not norm:
        return False
    for existing in alerted_names:
        ratio = difflib.SequenceMatcher(None, norm, existing).ratio()
        if ratio >= FILTERS["name_similarity_threshold"]:
            return True
    return False

# ============ FILTERING ============

def passes_filters(pair, goplus_data, cluster_pct, chain_id, rugcheck, alerted_names):
    liq = pair.get("liquidity", {}).get("usd", 0) or 0
    vol24 = pair.get("volume", {}).get("h24", 0) or 0
    price_change_1h = pair.get("priceChange", {}).get("h1", 0) or 0
    created_at_ms = pair.get("pairCreatedAt", 0) or 0
    name = pair.get("baseToken", {}).get("name", "")

    # correction 2
    if not created_at_ms:
        return False, "pool age unknown (fail closed)"
    age_minutes = (time.time() * 1000 - created_at_ms) / (1000 * 60)
    if age_minutes > FILTERS["max_age_minutes"]:
        return False, "pool too old (>30 min)"

    # correction 5
    if liq < FILTERS["min_liquidity_usd"]:
        return False, "liquidity too low"

    if vol24 < FILTERS["min_volume_24h_usd"]:
        return False, "volume too low"

    if liq > 0:
        vol_liq_ratio = vol24 / liq
        if vol_liq_ratio < FILTERS["min_vol_to_liq_ratio"]:
            return False, "vol/liq ratio too low"
        if vol_liq_ratio > FILTERS["max_vol_to_liq_ratio"]:  # correction 6
            return False, "vol/liq ratio too high (wash trading risk)"

    # correction 1
    if not (FILTERS["min_price_change_1h_pct"] <= price_change_1h <= FILTERS["max_price_change_1h_pct"]):
        return False, "1h price change outside +5%/+40% band"

    if FILTERS["require_social_link"] and not has_social_presence(pair):
        return False, "no social presence"

    # corrections 3 & 4: unknown data = FAIL, not skip
    if goplus_data is None:
        return False, "holder/security data unavailable (fail closed)"
    if goplus_data["holder_count"] is None or goplus_data["holder_count"] < FILTERS["min_holder_count"]:
        return False, "holder count too low or unverified"
    if goplus_data["top10_pct"] is None or goplus_data["top10_pct"] >= FILTERS["max_top10_holder_pct"]:
        return False, "top 10 holders too concentrated or unverified"

    # bubble map: best-effort, skips gracefully
    if cluster_pct is not None and cluster_pct > FILTERS["max_cluster_pct"]:
        return False, "linked wallet cluster too large"

    # correction 8: Ethereum only
    if chain_id == "ethereum":
        if goplus_data["is_honeypot"]:
            return False, "honeypot detected"
        if goplus_data["lp_locked_pct"] < FILTERS["min_lp_locked_pct"]:
            return False, "LP not sufficiently locked"

    # correction 10: Solana only
    if chain_id == "solana":
        if rugcheck is None:
            return False, "rugcheck unavailable (fail closed)"
        score = rugcheck.get("score")
        risks = rugcheck.get("risks", []) or []
        if any(r.get("level") == "danger" for r in risks):
            return False, "rugcheck flagged a danger-level risk"
        if score is not None and score > FILTERS["max_rugcheck_score"]:
            return False, "rugcheck score too risky"

    # correction 7
    if is_duplicate_name(name, alerted_names):
        return False, "duplicate or copycat name already alerted"

    return True, "passed"

# ============ ALERTING ============

def send_telegram_alert(message):
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    payload = {
        "chat_id": TELEGRAM_CHAT_ID,
        "text": message,
        "parse_mode": "Markdown",
        "disable_web_page_preview": False,
    }
    try:
        resp = requests.post(url, data=payload, timeout=10)
        if resp.status_code != 200:
            print(f"[error] telegram send failed: {resp.status_code} {resp.text}")
    except Exception as e:
        print(f"[error] sending telegram alert: {e}")

def format_alert(pair, rugcheck, goplus_data, cluster_pct, price_usd):
    name = pair.get("baseToken", {}).get("name", "Unknown")
    symbol = pair.get("baseToken", {}).get("symbol", "?")
    address = pair.get("baseToken", {}).get("address", "")
    chain = pair.get("chainId", "")
    liq = pair.get("liquidity", {}).get("usd", 0)
    vol24 = pair.get("volume", {}).get("h24", 0)
    change1h = pair.get("priceChange", {}).get("h1", 0)
    url = pair.get("url", "")

    lines = [
        f"*{name}* (${symbol}) on {chain.upper()}",
        f"Price: ${price_usd}" if price_usd else "Price: N/A",
        f"Liquidity: ${liq:,.0f}",
        f"24h Volume: ${vol24:,.0f}",
        f"1h Change: {change1h:+.1f}%",
        f"Holders: {goplus_data['holder_count']}",
        f"Top 10 holders: {goplus_data['top10_pct']:.1f}%",
        f"Largest linked cluster: {f'{cluster_pct:.1f}%' if cluster_pct is not None else 'N/A'}",
    ]

    if chain == "ethereum":
        lines.append(f"LP locked: {goplus_data['lp_locked_pct']:.1f}%")
        lines.append(f"Honeypot: {'YES - BLOCKED' if goplus_data['is_honeypot'] else 'No'}")

    if rugcheck:
        lines.append(f"RugCheck score: {rugcheck.get('score', 'N/A')}")

    lines.append(f"[Chart]({url})")
    lines.append(f"`{address}`")
    lines.append("")
    lines.append("_Passed all automated checks (age, liquidity, price band, holders, "
                  "top-10 concentration, bubble map, LP/honeypot where applicable, RugCheck, "
                  "duplicate-name check)._")
    lines.append("_Still check yourself: verified socials, posting activity, narrative, conviction._")

    return "\n".join(lines)

# ============ MAIN (single scan, then exit) ============

def main():
    print("Meme coin scanner — single run (GitHub Actions mode, v3). Alert-only.")
    seen = load_json_set(SEEN_FILE)
    alerted_names = load_json_set(NAMES_FILE)
    signal_log = load_signal_log()
    new_alerts = 0

    profiles = get_latest_token_profiles()

    for profile in profiles:
        chain_id = profile.get("chainId")
        token_address = profile.get("tokenAddress")

        if chain_id not in CHAINS or not token_address:
            continue
        if token_address in seen:
            continue

        pair = get_pair_data(chain_id, token_address)
        if not pair:
            seen.add(token_address)
            continue

        goplus_data = get_goplus_security(chain_id, token_address)
        cluster_pct = get_bubblemap_cluster_pct(chain_id, token_address)
        rugcheck = get_rugcheck_report(token_address) if chain_id == "solana" else None

        ok, reason = passes_filters(pair, goplus_data, cluster_pct, chain_id, rugcheck, alerted_names)
        seen.add(token_address)

        if not ok:
            print(f"[skip] {profile.get('description', token_address)} — {reason}")
            continue

        price_usd = pair.get("priceUsd")
        name = pair.get("baseToken", {}).get("name", "")

        message = format_alert(pair, rugcheck, goplus_data, cluster_pct, price_usd)
        send_telegram_alert(message)

        signal_log.append({
            "timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "name": name,
            "symbol": pair.get("baseToken", {}).get("symbol", ""),
            "chain": chain_id,
            "address": token_address,
            "price_usd": price_usd,
            "liquidity_usd": pair.get("liquidity", {}).get("usd", 0),
        })

        alerted_names.add(normalize_name(name))
        new_alerts += 1
        print(f"[alert sent] {profile.get('description', token_address)}")
        time.sleep(1)

    save_json_set(SEEN_FILE, seen)
    save_json_set(NAMES_FILE, alerted_names)
    save_signal_log(signal_log)
    print(f"[run complete] {new_alerts} alert(s) sent.")

if __name__ == "__main__":
    main()
