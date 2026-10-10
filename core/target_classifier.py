import re
from typing import Tuple, Optional

COMMON_TLDS = {
    "com", "org", "net", "edu", "gov", "mil", "int", "io", "co", "ai", "app", 
    "dev", "xyz", "in", "uk", "de", "fr", "cn", "jp", "br", "it", "nl", "ru", 
    "ch", "se", "no", "es", "info", "biz", "me", "cc", "tv", "online", "site", 
    "tech", "store", "cloud", "live", "digital", "global", "guru", "agency", 
    "top", "pro", "icu", "club", "vip", "network", "solutions", "group", "link",
    "ca", "au", "eu", "us", "id", "ir", "tr", "pl", "tw", "ua", "vn", "mx", "ar", "za", "cz"
}

PACKAGE_PREFIXES = (
    "com.", "org.", "net.", "io.", "android.", "google.", "de.", "fr.", "ru.", "in.", "uk."
)

def classify_target(target: str, explicit_type: Optional[str] = None) -> Tuple[str, bool]:
    """
    Classifies and normalizes a target input string.
    Returns (normalized_target, is_web).
    
    :param target: Raw input string (e.g. 'coaching1.opanbaux.com', 'com.spotify.music', 'https://example.com')
    :param explicit_type: 'web', 'apk', 'mobile', or None/'auto'
    :return: (normalized_target, is_web)
    """
    cleaned = (target or "").strip()
    if not cleaned:
        return cleaned, False

    # 1. Handle explicit type override if passed
    if explicit_type:
        exp = explicit_type.strip().lower()
        if exp in ("web", "website"):
            if not cleaned.startswith(("http://", "https://")):
                cleaned = f"https://{cleaned}"
            return cleaned, True
        elif exp in ("apk", "mobile", "android"):
            return cleaned, False

    # 2. Check for explicit protocol
    if cleaned.startswith(("http://", "https://")):
        if "play.google.com/store/apps" in cleaned or "market://" in cleaned:
            return cleaned, False
        return cleaned, True

    if cleaned.startswith("market://"):
        return cleaned, False

    # 3. Check for direct APK / installer archives
    if cleaned.lower().endswith((".apk", ".xapk", ".zip")):
        return cleaned, False

    # 4. Check for localhost or local development addresses
    if re.match(r'^(localhost|127\.0\.0\.1)(:\d+)?(/.*)?$', cleaned, re.IGNORECASE):
        return f"http://{cleaned}", True

    # 5. Extract host candidate (strip path, port, query)
    host_candidate = cleaned.split('/')[0].split('?')[0].split(':')[0].strip().lower()
    host_parts = host_candidate.split('.')

    if len(host_parts) >= 2:
        last_tld = host_parts[-1]
        second_last = host_parts[-2] if len(host_parts) >= 3 else ""

        # Compound TLDs (e.g. .co.uk, .com.au, .co.in)
        is_compound_tld = second_last in ("co", "com", "org", "gov", "edu", "net") and last_tld in ("uk", "au", "in", "za", "br", "jp")

        # Standard Android reverse-domain package check:
        # e.g., com.spotify.music, org.videolan.vlc
        # Starts with package prefix (com., org., etc.) and does NOT end with a known TLD
        if cleaned.lower().startswith(PACKAGE_PREFIXES) and last_tld not in COMMON_TLDS and not is_compound_tld:
            return cleaned, False

        # If the domain ends with a recognized TLD, it is a website
        if last_tld in COMMON_TLDS or is_compound_tld:
            return f"https://{cleaned}", True

    # 6. If it contains path slashes and doesn't look like a package, treat as web URL
    if "/" in cleaned and not cleaned.lower().startswith(PACKAGE_PREFIXES):
        return f"https://{cleaned}", True

    # Default fallback: treat as APK package ID or keyword search
    return cleaned, False
