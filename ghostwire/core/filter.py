"""Noise filter module for GhostWire.
Scrubs trackers, analytics, telemetry, static assets, and third-party noise.
"""

from typing import Set
from urllib.parse import urlparse

# Extensions to discard (static assets)
STATIC_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".ico", ".bmp", ".tiff",
    ".css", ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".mp4", ".webm", ".ogv", ".mp3", ".wav", ".flac",
    ".map", ".wasm", ".webmanifest", "/manifest.json"
}

# Domains / host substrings to discard (trackers, telemetry, ads, CDNs)
TRACKER_DOMAINS = {
    "google-analytics.com", "googletagmanager.com", "doubleclick.net", "analytics.google.com",
    "sentry.io", "browser.sentry-cdn.com",
    "datadoghq.com", "browser-intake-datadoghq.com",
    "hotjar.com", "script.hotjar.com",
    "connect.facebook.net", "facebook.com/tr",
    "mixpanel.com", "api.mixpanel.com",
    "segment.io", "api.segment.io", "cdn.segment.com",
    "cloudflareinsights.com", "static.cloudflareinsights.com",
    "clarity.ms",
    "intercom.io", "api-iam.intercom.io",
    "amplitude.com", "api2.amplitude.com",
    "fullstory.com",
    "logrocket.io",
    "newrelic.com", "nr-data.net",
    "branch.io", "api2.branch.io",
    "criteo.com", "criteo.net",
    "scorecardresearch.com",
    "adnxs.com",
    # Ads & tag management
    "googleadservices.com", "googlesyndication.com", "googletagservices.com", "gstatic.com",
    "bat.bing.com", "px.ads.linkedin.com", "snap.licdn.com", "analytics.tiktok.com", "ct.pinterest.com",
    "ads-twitter.com", "static.ads-twitter.com", "taboola.com", "outbrain.com", "quantserve.com",
    # Marketing, CRM & visitor intelligence
    "hubspot.com", "hubapi.com", "hscollectedforms.net", "hs-analytics.net", "hs-scripts.com",
    "hs-banner.com", "hsforms.com", "hsadspixel.net", "lusha.com", "clearbit.com", "6sc.co",
    # Product analytics & session replay
    "posthog.com", "heapanalytics.com", "plausible.io", "mouseflow.com", "smartlook.com", "pendo.io",
    # Consent banners
    "onetrust.com", "cookielaw.org", "cookiebot.com", "trustarc.com",
    # Google anti-abuse / web attestation
    "jnn-pa.googleapis.com",
}

# Path segments that mark telemetry on any host (first-party tunnels such as /api/sentry included)
TRACKER_PATH_SEGMENTS = {
    "collect", "log_event", "beacon", "pixel", "sentry", "telemetry", "rum", "rmkt", "ccm", "pagead",
}

# Content-types that represent real data/API exchanges
API_CONTENT_TYPES = {
    "application/json",
    "application/problem+json",
    "application/x-www-form-urlencoded",
    "multipart/form-data",
    "application/graphql",
    "application/graphql+json",
    "text/json"
}


class NoiseFilter:
    def __init__(self, target_domains: Set[str] = None):
        """
        Optional target_domains can restrict analysis strictly to specified domains.
        """
        self.target_domains = target_domains or set()

    def is_api_transaction(self, method: str, url: str, status_code: int, 
                           req_content_type: str = "", res_content_type: str = "") -> bool:
        """Determines if a captured HTTP transaction is a genuine API call vs web asset/tracker."""
        # 1. Skip pre-flight OPTIONS requests or error redirects
        if method.upper() in {"OPTIONS", "HEAD"}:
            return False

        parsed = urlparse(url)
        path = parsed.path.lower()
        hostname = (parsed.hostname or "").lower()

        # Entries without a real http(s) URL (data:, blob:, chrome-extension:, malformed) are not API calls
        if parsed.scheme not in {"http", "https"} or not hostname:
            return False

        # 4. If target_domains specified, filter by them (an explicit target overrides the tracker lists)
        if self.target_domains:
            if not any(target in hostname for target in self.target_domains):
                return False
        else:
            # 2. Filter out known tracker domains (the domain itself or any subdomain)
            if any(hostname == tracker or hostname.endswith("." + tracker) for tracker in TRACKER_DOMAINS):
                return False
            # Telemetry endpoints recognisable by path, whatever the host
            if any(segment in TRACKER_PATH_SEGMENTS for segment in path.split("/")):
                return False

        # 3. Filter out static file extensions
        for ext in STATIC_EXTENSIONS:
            if path.endswith(ext):
                return False

        # 5. Check Content-Type markers
        req_ct = (req_content_type or "").lower()
        res_ct = (res_content_type or "").lower()

        for api_ct in API_CONTENT_TYPES:
            if api_ct in req_ct or api_ct in res_ct:
                return True

        # 6. Check common API path conventions
        api_path_indicators = [
            "/api/", "/v1/", "/v2/", "/v3/", "/v4/", "/graphql",
            "/rest/", "/rpc/", "/query", "/mutation", "/service/"
        ]
        if any(indicator in path for indicator in api_path_indicators):
            return True

        # 7. Non-GET methods with body are almost always stateful API calls
        if method.upper() in {"POST", "PUT", "PATCH", "DELETE"} and (res_ct.startswith("text/") or not res_ct):
            return True

        return False
