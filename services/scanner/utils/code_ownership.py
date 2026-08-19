"""Code-ownership classification for findings — is a finding in the user's own
APP code, or in THIRD-PARTY / vendored / bundled code they copied into the repo?

Motivation (Project-Taaza validation): a repo that vendors PHPMailer / FPDF by
copying the source in gets those files scanned like app code, so "your code has 11
SQL injections" (urgent) is buried among "a bundled library uses exec()" (noise).
Tagging ownership lets the report lead with the user's own code.

PRECISION-FIRST: this is path-based and conservative. When it is not *confident*
a path is third-party, it returns APP. Misclassifying real app code as third-party
would visually de-prioritize a genuine bug (a false negative in disguise), so the
default is always APP.
"""
from __future__ import annotations

import re

APP = "app"
THIRD_PARTY = "third_party"

# Package-manager / dependency directories — never hand-written first-party source.
_DEP_DIRS = {
    "node_modules", "bower_components", "jspm_packages",
    "vendor", "vendored", "third_party", "third-party", "thirdparty",
    "site-packages", ".venv", "venv", "virtualenv", "external", "externals",
}

# Build output that bundles library code (not source the user edits by hand),
# incl. pre-rendered/static-export publish dirs (the deploy snapshot, regenerated
# from source — findings here are build artifacts, not hand-written code).
_GENERATED_DIRS = {
    "dist", ".next", "_next", ".nuxt", ".output", ".vercel",
    "netlify-static", "_site", "storybook-static", ".docusaurus",
}

# Distinctive vendored-library directory names (exact path segment, lower-cased).
# Each is a library name that is essentially never a user's own app directory, so
# matching it is high-confidence. Curated (extend as new common vendored libs turn
# up) rather than broad, to keep precision high.
_VENDORED_LIB_DIRS = {
    # PHP libraries commonly copied in (no composer):
    "phpmailer", "fpdf", "fpdi", "tcpdf", "mpdf", "dompdf",
    "phpexcel", "phpspreadsheet", "phpword", "htmlpurifier", "smarty",
    "swiftmailer", "simplehtmldom", "phpqrcode", "phpgangsta",
    # JS/CSS libraries commonly copied in (no npm):
    "tinymce", "ckeditor", "datatables", "fullcalendar", "highcharts",
    "summernote", "dropzone", "jspdf", "select2", "fontawesome", "font-awesome",
}

# Minified / bundled files are shipped library builds, not source.
_MIN_RE = re.compile(r"(\.min\.(js|css)|\.bundle\.(js|css)|[.-]min\.[a-z0-9]+)$", re.I)

# Distinctive self-identification banners that distributed JS/CSS library builds
# carry at the very top (in the preserved `/*! … */` license comment). Matching one
# is high-confidence evidence the file is a vendored library copy — even when it is
# NOT minified and does NOT live in a vendored directory (e.g. an unminified
# assets/js/jquery-1.12.3.js or assets/js/bootstrap.js copied straight in). Curated
# to distinctive "Name vVersion"-style phrases so app source that merely *mentions* a
# library is never matched; also gated on a leading comment (see is_vendored_asset).
_LIB_BANNER_RE = re.compile(
    r"jQuery JavaScript Library|jQuery UI(?: -)? v|Sizzle\.js|jQuery Foundation|"
    r"Bootstrap v|getbootstrap\.com|AngularJS v|Angular Material|"
    r"Vue\.js v|vuejs\.org|React v\d|reactjs\.org|"
    r"@license (?:React|Lodash)|Lodash <|lodash\.com/license|Lo-Dash|Underscore\.js|"
    r"Moment\.js|momentjs\.com|D3\.js|Highcharts JS|Chart\.js v|"
    r"Popper\.js|@popperjs|Modernizr \d|Font Awesome (?:Free|\d)|fontawesome\.com|"
    r"Select2 \d|DataTables \d|datatables\.net|Slick(?: Slider)? v|Swiper \d|swiperjs\.com|"
    r"Owl Carousel|toastr|SweetAlert|Tether\.js|Handlebars v|Backbone\.js|Ember\.js|"
    r"normalize\.css v|animate\.css",
    re.I,
)
_ASSET_EXTS = (".js", ".css", ".mjs", ".cjs")


def is_vendored_asset(abs_path: str) -> bool:
    """True when a JS/CSS file is a vendored third-party library build, judged from a
    distribution banner at the top of the file. Precision-first: only fires when the
    file *opens* with a comment banner carrying a distinctive library signature, so a
    hand-written app file that merely references a library elsewhere is never tagged."""
    if not abs_path.lower().endswith(_ASSET_EXTS):
        return False
    try:
        with open(abs_path, encoding="utf-8", errors="ignore") as fh:
            head = fh.read(4096)
    except OSError:
        return False
    stripped = head.lstrip()
    if not stripped.startswith("/*"):
        return False  # distribution banners are a leading /*! … */ block; app logic isn't
    # The banner sits at the very top — a library reference deeper in the file (or a
    # hand-written /* license */ header that merely mentions a lib) must not count.
    return bool(_LIB_BANNER_RE.search(stripped[:800]))


def classify(file_path: str | None) -> tuple[str, str | None]:
    """Return (ownership, reason). ownership is "app" or "third_party"."""
    if not file_path:
        return APP, None
    p = file_path.replace("\\", "/")
    segs = [s for s in p.lower().split("/") if s and s != "."]

    for s in segs:
        if s in _VENDORED_LIB_DIRS:
            return THIRD_PARTY, f"vendored library directory: {s}"
    for s in segs:
        if s in _DEP_DIRS:
            return THIRD_PARTY, f"dependency directory: {s}"
    for s in segs:
        if s in _GENERATED_DIRS:
            return THIRD_PARTY, f"build/bundled output: {s}"
    if _MIN_RE.search(p):
        return THIRD_PARTY, "minified/bundled library file"

    return APP, None
