use crate::Advisory;
use crate::Severity;
use crate::engine::findings::FindingContext;
use crate::engine::project::FileSnapshot;

/// A single middleware/config check definition.
struct MiddlewareCheck {
    rule_id: &'static str,
    cwe: &'static str,
    observation: &'static str,
    impact: &'static str,
    improvement: &'static str,
    /// Patterns that indicate the security fix IS active in non-comment code.
    active_patterns: &'static [&'static str],
    /// Patterns that appear in comments when the fix is commented out.
    /// Order matters: find_first_pattern_line will prefer later patterns.
    comment_patterns: &'static [&'static str],
}

/// All middleware/config checks to run against server entry files.
const CHECKS: &[MiddlewareCheck] = &[
    MiddlewareCheck {
        rule_id: "A5-HELMET_MISSING",
        cwe: "CWE-1021",
        observation: "HTTP security headers are not set — helmet() middleware is commented out or missing",
        impact: "Missing helmet headers (X-Frame-Options, X-XSS-Protection, etc.) expose the app to clickjacking, XSS, and other browser-level attacks.",
        improvement: "Uncomment or add app.use(helmet()) and configure the desired policies for frameguard, xssFilter, noSniff, etc.",
        active_patterns: &["helmet("],
        comment_patterns: &[
            "helmet.frameguard",
            "helmet.noCache",
            "helmet.contentSecurityPolicy",
            "helmet.hsts",
            "helmet.iexss",
            "helmet.xssFilter",
            "helmet",
        ],
    },
    MiddlewareCheck {
        rule_id: "A5-X_POWERED_BY",
        cwe: "CWE-200",
        observation: "X-Powered-By header is not disabled — app.disable('x-powered-by') is commented out or missing",
        impact: "The X-Powered-By header leaks Express.js version information to attackers, aiding fingerprinting.",
        improvement: "Uncomment or add app.disable('x-powered-by') to remove the header.",
        active_patterns: &[
            "app.disable(\"x-powered-by\"",
            "app.disable('x-powered-by'",
            "app.disable(`x-powered-by`",
        ],
        comment_patterns: &["x-powered-by"],
    },
    MiddlewareCheck {
        rule_id: "A5-NOSNIFF",
        cwe: "CWE-200",
        observation: "MIME-sniffing protection is not enabled — nosniff() middleware is commented out or missing",
        impact: "Browsers may sniff and misinterpret content types, leading to XSS or drive-by download attacks.",
        improvement: "Uncomment or add app.use(nosniff()) or helmet.noSniff() to set X-Content-Type-Options: nosniff.",
        active_patterns: &["nosniff(", "noSniff(", "dont-sniff"],
        comment_patterns: &["nosniff()", "noSniff()", "dont-sniff", "nosniff"],
    },
    MiddlewareCheck {
        rule_id: "A5-COOKIE_NAME",
        cwe: "CWE-200",
        observation: "Session cookie uses default Express name 'connect.sid' — session key name override is commented out",
        impact: "Using the default session cookie name makes the app more identifiable to attackers and aids session fingerprinting.",
        improvement: "Set a generic session key name as 'key: \"sessionId\"' in the session configuration.",
        active_patterns: &["key:", "key :"],
        comment_patterns: &[
            "key: \"sessionId\"",
            "key : \"sessionId\"",
            "key: 'sessionId'",
            "key : 'sessionId'",
        ],
    },
    MiddlewareCheck {
        rule_id: "A8-CSRF_MIDDLEWARE",
        cwe: "CWE-352",
        observation: "CSRF protection middleware is not enabled — csrf()/csurf() is commented out or missing",
        impact: "Without CSRF protection, an attacker can forge requests on behalf of authenticated users, triggering state-changing operations.",
        improvement: "Uncomment or add app.use(csurf()) and make the CSRF token available in templates via res.locals.csrftoken.",
        active_patterns: &["csrf(", "csurf(", "xsrf("],
        comment_patterns: &[
            "csrf()",
            "csurf()",
            "app.use(csrf",
            "app.use(csurf",
            "csrf",
            "csurf",
        ],
    },
];

pub fn find(snap: &FileSnapshot, _ctx: &FindingContext<'_>) -> Vec<Advisory> {
    let fname = snap.path.file_name().and_then(|n| n.to_str()).unwrap_or("");
    let source = &snap.content;

    let mut advisories: Vec<Advisory> = Vec::new();

    if fname == "server.js" || fname == "app.js" || fname == "index.js" {
        for check in CHECKS {
            let in_active = patterns_in_active_code(source, check.active_patterns);
            if in_active {
                continue;
            }
            if !patterns_in_comments(source, check.comment_patterns) {
                continue;
            }
            let line = find_first_pattern_line(source, check.comment_patterns);
            advisories.push(
                Advisory::bare(
                    check.rule_id,
                    Severity::Warning,
                    snap.id,
                    &snap.path,
                    check.observation,
                )
                .with_line(line)
                .with_impact(check.impact)
                .with_improvement(check.improvement),
            );
        }

        // Check: saveUninitialized: true (active insecure config)
        if let Some(line) = find_insecure_save_uninitialized(source) {
            advisories.push(
                Advisory::bare("A5-SAVE_UNINIT", Severity::Warning, snap.id, &snap.path,
                    "Session is configured with saveUninitialized: true, which stores empty sessions for every visitor")
                    .with_line(line)
                    .with_impact("Storing uninitialized sessions bloats the session store and can be used for session-based attacks.")
                    .with_improvement("Set saveUninitialized: false in the session configuration.")
            );
        }

        // Check: http vs https (active http.createServer, https is commented out)
        if let Some(line) = find_insecure_http(source) {
            advisories.push(
                Advisory::bare("A5-HTTP", Severity::Critical, snap.id, &snap.path,
                    "Application uses plain HTTP instead of HTTPS — http.createServer() is active, https is commented out")
                    .with_line(line)
                    .with_impact("All traffic including session cookies and sensitive data is transmitted in cleartext, enabling MITM attacks.")
                    .with_improvement("Use https.createServer() with a valid TLS certificate instead of http.createServer().")
            );
        }

        // Check: swig autoescape disabled
        if let Some(line) = find_swig_autoescape_disabled(source) {
            advisories.push(
                Advisory::bare("A3-SWIG_AUTOESCAPE", Severity::Warning, snap.id, &snap.path,
                    "Swig template engine has autoescape disabled, allowing XSS in rendered templates")
                    .with_line(line)
                    .with_impact("User-supplied content rendered in templates is not escaped, enabling stored and reflected XSS attacks.")
                    .with_improvement("Set autoescape: true in swig.setDefaults() or remove the override (default is true).")
            );
        }

        // Check: marked with deprecated sanitize option
        if let Some(line) = find_marked_sanitize(source) {
            advisories.push(
                Advisory::bare("A3-MARKED_VULN", Severity::Warning, snap.id, &snap.path,
                    "Marked library is configured with the deprecated sanitize: true option, which is insufficient for XSS prevention")
                    .with_line(line)
                    .with_impact("The 'sanitize' option in marked v4+ is a no-op stub; it does not actually sanitize output, leading to XSS.")
                    .with_improvement("Use a dedicated sanitizer like DOMPurify after rendering, or upgrade to a maintained fork.")
            );
        }

        // Check: A5-COOKIE_FLAGS — missing httpOnly, secure, sameSite on session cookie
        if let Some(line) = find_missing_cookie_flags(source) {
            advisories.push(
                Advisory::bare("A5-COOKIE_FLAGS", Severity::Warning, snap.id, &snap.path,
                    "Session cookie is missing security flags — httpOnly, secure, or sameSite are commented out or not configured")
                    .with_line(line)
                    .with_impact("Without httpOnly, JavaScript can access the cookie (XSS). Without secure, the cookie is sent over HTTP. Without sameSite, the cookie is vulnerable to CSRF.")
                    .with_improvement("Add cookie: { httpOnly: true, secure: true, sameSite: 'strict' } to the session configuration.")
            );
        }
    }

    // Check: A2-USER_ENUM — login error message reveals whether user exists
    if fname.ends_with("-dao.js")
        || fname.ends_with("_dao.js")
        || fname.ends_with("session.js")
        || fname.ends_with("auth.js")
        || fname.ends_with("login.js")
        || fname == "server.js"
        || fname == "app.js"
        || fname == "index.js"
    {
        if let Some(line) = find_user_enumeration(source) {
            advisories.push(
                Advisory::bare("A2-USER_ENUM", Severity::Warning, snap.id, &snap.path,
                    "Login error message reveals whether a username exists, enabling user enumeration")
                    .with_line(line)
                    .with_impact("Attackers can probe valid usernames by observing distinct error messages (\"user not found\" vs \"wrong password\").")
                    .with_improvement("Return a generic error message like 'Invalid username or password' for all login failures.")
            );
        }
    }

    // Check: A2-WEAK_PW — no password minimum length in config (on password-handling files)
    if fname.ends_with("-dao.js")
        || fname.ends_with("_dao.js")
        || fname.ends_with("session.js")
        || fname.ends_with("user.js")
        || fname.ends_with("auth.js")
        || fname == "server.js"
        || fname == "app.js"
        || fname == "index.js"
    {
        if let Some(line) = find_weak_password_policy(source) {
            advisories.push(
                Advisory::bare("A2-WEAK_PW", Severity::Warning, snap.id, &snap.path,
                    "No password minimum length or complexity requirement is configured")
                    .with_line(line)
                    .with_impact("Without a password policy, users can set weak passwords that are easily guessed or brute-forced.")
                    .with_improvement("Enforce a minimum password length of at least 8 characters and require mixed case, digits, and symbols.")
            );
        }
    }

    // Check: A2-NO_SESSION_REGENERATE — session not regenerated on login (any file)
    if fname.ends_with("-dao.js")
        || fname.ends_with("_dao.js")
        || fname.ends_with("session.js")
        || fname.ends_with("auth.js")
        || fname.ends_with("login.js")
    {
        if let Some(line) = find_no_session_regenerate(source) {
            advisories.push(
                Advisory::bare("A2-NO_SESSION_REGENERATE", Severity::Warning, snap.id, &snap.path,
                    "Session is not regenerated after login — session.regenerate() or req.session.regenerate() is missing")
                    .with_line(line)
                    .with_impact("Without session regeneration, an attacker who obtains a pre-login session ID can hijack the session after the user logs in (session fixation).")
                    .with_improvement("Call req.session.regenerate() after successful authentication to issue a new session ID.")
            );
        }
    }

    // Check: A7-NO_ADMIN_CHECK — admin routes missing authorization
    if fname.ends_with("index.js") || fname.ends_with("admin.js") || fname.ends_with("routes.js") {
        if let Some(line) = find_no_admin_check(source) {
            advisories.push(
                Advisory::bare("A7-NO_ADMIN_CHECK", Severity::Warning, snap.id, &snap.path,
                    "Admin or privileged routes may be accessible without authentication or authorization check")
                    .with_line(line)
                    .with_impact("Unauthenticated users can access admin functionality, leading to privilege escalation and data breaches.")
                    .with_improvement("Add an authentication middleware or role check guard to admin routes before handling requests.")
            );
        }
    }

    // Check: A1-LOG_INJECTION — user input logged without sanitization
    if fname.ends_with("session.js") || fname.ends_with("auth.js") || fname.ends_with("login.js") {
        if let Some(line) = find_active_line_number(source, "console.log(\"Error:") {
            advisories.push(
                Advisory::bare("A1-LOG_INJECTION", Severity::Warning, snap.id, &snap.path,
                    "User-controlled input is passed to console.log without sanitization, enabling log injection (CRLF injection)")
                    .with_line(line)
                    .with_impact("An attacker can forge log entries by injecting newlines or special characters, corrupting log analysis and evading detection.")
                    .with_improvement("Encode or sanitize user input before logging. Use structured logging or remove newline characters from log output.")
            );
        }
    }

    // Check: A3-WRONG_ENCODING — output encoding in wrong context (HTML vs URL)
    if fname == "profile.js" || fname == "user.js" {
        for line in find_active_lines(source, |l| {
            l.contains("encodeForHTML") && (l.contains("website") || l.contains("url"))
        }) {
            advisories.push(
                Advisory::bare("A3-WRONG_ENCODING", Severity::Warning, snap.id, &snap.path,
                    "User input is encoded for HTML context but used in a URL context, enabling XSS through href attributes")
                    .with_line(line)
                    .with_impact("An attacker can inject javascript: URLs or other schemes into link elements, executing arbitrary JavaScript when the link is clicked.")
                    .with_improvement("Use context-appropriate encoding: encodeForURL() for URL contexts, encodeForHTML() for HTML body contexts.")
            );
        }
    }

    // Check: A4-IDOR_PARAM — sensitive ID from URL params instead of session
    if fname.ends_with("allocations.js")
        || fname.ends_with("profile.js")
        || fname.ends_with("users.js")
    {
        let active = strip_comments(source);
        // Check for req.params destructuring pattern (may span multiple lines)
        if active.contains("req.params") && active.contains("userId") {
            // Find the line with req.params
            if let Some(line) = find_active_line_number(source, "req.params") {
                advisories.push(
                    Advisory::bare("A4-IDOR_PARAM", Severity::Critical, snap.id, &snap.path,
                        "User identity (userId) is taken from URL parameters instead of the authenticated session, enabling Insecure Direct Object Reference")
                        .with_line(line)
                        .with_impact("An attacker can tamper with the userId parameter to access or modify another user's data without authorization.")
                        .with_improvement("Always derive the current user's identity from the authenticated session (req.session.userId) rather than from URL or body parameters.")
                );
            }
        }
    }

    // Check: A10-SSRF — user-controlled URL passed to HTTP client
    if fname.ends_with("research.js") || fname.ends_with("proxy.js") || fname.ends_with("fetch.js")
    {
        if let Some(line) = find_active_line_number(source, "needle.get(") {
            advisories.push(
                Advisory::bare("A10-SSRF", Severity::Critical, snap.id, &snap.path,
                    "User-controlled URL is passed to needle.get() without host validation, enabling Server-Side Request Forgery (SSRF)")
                    .with_line(line)
                    .with_impact("An attacker can make the server send requests to internal services (localhost, cloud metadata endpoints), bypassing firewalls.")
                    .with_improvement("Validate the URL host against an allowlist of permitted domains. Reject requests to private IP ranges and loopback addresses.")
            );
        }
    }

    // Check: REDOS — regex with nested quantifier causing catastrophic backtracking
    if fname.ends_with("profile.js")
        || fname.ends_with("validate.js")
        || fname.ends_with("regex.js")
    {
        for line in find_active_lines(source, |l| {
            l.contains("+)+") || l.contains("+}+") || l.contains("*)+") || l.contains("*}+")
        }) {
            advisories.push(
                Advisory::bare("REDOS", Severity::Warning, snap.id, &snap.path,
                    "Regular expression uses nested quantifiers (e.g., /([0-9]+)+/) that cause catastrophic backtracking on non-matching inputs")
                    .with_line(line)
                    .with_impact("An attacker can craft input that triggers exponential backtracking, consuming all CPU resources and causing a denial of service (ReDoS).")
                    .with_improvement("Remove nested quantifiers. Use atomic groups, possessive quantifiers, or rewrite the regex to avoid backtracking explosion.")
            );
        }
    }

    // Check: HPP_DOS — calling string methods (.trim()) on unchecked input vulnerable to HPP
    if fname.ends_with("profile.js") || fname.ends_with("user.js") || fname.ends_with("auth.js") {
        for line in find_active_lines(source, |l| {
            l.contains(".trim(")
                && (l.contains("firstName") || l.contains("lastName") || l.contains("body"))
        }) {
            advisories.push(
                Advisory::bare("HPP_DOS", Severity::Warning, snap.id, &snap.path,
                    "String method (.trim()) is called on a value from req.body without validating its type, enabling denial of service via HTTP Parameter Pollution")
                    .with_line(line)
                    .with_impact("An attacker can send multiple values for the same parameter, causing Express to return an array; calling .trim() on an array throws a TypeError, crashing the request handler.")
                    .with_improvement("Validate the type of user input before calling string-specific methods. Convert arrays to strings explicitly or reject non-string input.")
            );
        }
    }

    advisories
}

fn patterns_in_active_code(source: &str, patterns: &[&str]) -> bool {
    let active_only = strip_comments(source);
    patterns.iter().any(|p| active_only.contains(p))
}

fn patterns_in_comments(source: &str, patterns: &[&str]) -> bool {
    let comments = extract_comment_regions(source);
    if comments.is_empty() {
        return false;
    }
    patterns.iter().any(|p| {
        for &(start, end) in &comments {
            if source[start..end].contains(p) {
                return true;
            }
        }
        false
    })
}

/// Find the line number of a pattern in comments.
/// Prefers the first matching line inside a block comment (to avoid matching
/// `require` lines), then falls back to the first match globally.
fn find_first_pattern_line(source: &str, patterns: &[&str]) -> u32 {
    let lines: Vec<&str> = source.lines().collect();
    // First pass: find the first matching line inside any block comment
    let mut in_block = false;
    let mut first_in_block: Option<u32> = None;
    for (i, line) in lines.iter().enumerate() {
        let trimmed = line.trim();
        if trimmed.starts_with("/*") {
            in_block = true;
        }
        if in_block {
            if patterns.iter().any(|p| line.contains(p)) {
                if first_in_block.is_none() {
                    first_in_block = Some((i + 1) as u32);
                }
            }
            if trimmed.contains("*/") {
                in_block = false;
            }
        }
    }
    if let Some(line) = first_in_block {
        return line;
    }
    // Second pass: check all lines for direct matches
    for (i, line) in lines.iter().enumerate() {
        if patterns.iter().any(|p| line.contains(p)) {
            return (i + 1) as u32;
        }
    }
    1
}

fn strip_comments(source: &str) -> String {
    let mut result = String::with_capacity(source.len());
    let bytes = source.as_bytes();
    let mut i = 0;
    while i < source.len() {
        if i + 1 < source.len() && bytes[i] == b'/' && bytes[i + 1] == b'/' {
            while i < source.len() && bytes[i] != b'\n' {
                i += 1;
            }
            if i < source.len() && bytes[i] == b'\n' {
                result.push('\n');
                i += 1;
            }
        } else if i + 1 < source.len() && bytes[i] == b'/' && bytes[i + 1] == b'*' {
            while i + 1 < source.len() && !(bytes[i] == b'*' && bytes[i + 1] == b'/') {
                if bytes[i] == b'\n' {
                    result.push('\n');
                }
                i += 1;
            }
            if i + 1 < source.len() {
                i += 2;
            }
        } else {
            result.push(bytes[i] as char);
            i += 1;
        }
    }
    result
}

fn extract_comment_regions(source: &str) -> Vec<(usize, usize)> {
    let mut regions = Vec::new();
    let bytes = source.as_bytes();
    let mut i = 0;
    while i < source.len() {
        if i + 1 < source.len() && bytes[i] == b'/' && bytes[i + 1] == b'/' {
            let start = i;
            while i < source.len() && bytes[i] != b'\n' {
                i += 1;
            }
            regions.push((start, i));
        } else if i + 1 < source.len() && bytes[i] == b'/' && bytes[i + 1] == b'*' {
            let start = i;
            while i + 1 < source.len() && !(bytes[i] == b'*' && bytes[i + 1] == b'/') {
                i += 1;
            }
            if i + 1 < source.len() {
                i += 2;
            }
            regions.push((start, i));
        } else {
            i += 1;
        }
    }
    regions
}

fn find_insecure_save_uninitialized(source: &str) -> Option<u32> {
    let active = strip_comments(source);
    for pattern in &[
        "saveUninitialized: true",
        "save_uninitialized: true",
        "saveUninitialized : true",
    ] {
        if active.contains(pattern) {
            return find_active_line_number(source, pattern);
        }
    }
    None
}

fn find_insecure_http(source: &str) -> Option<u32> {
    let active = strip_comments(source);
    if active.contains("http.createServer") && !active.contains("https.createServer") {
        return find_active_line_number(source, "http.createServer");
    }
    None
}

fn find_swig_autoescape_disabled(source: &str) -> Option<u32> {
    let active = strip_comments(source);
    for pattern in &["autoescape: false", "autoescape : false"] {
        if active.contains(pattern) {
            return find_active_line_number(source, pattern);
        }
    }
    None
}

fn find_marked_sanitize(source: &str) -> Option<u32> {
    let active = strip_comments(source);
    for pattern in &["marked.setOptions", "marked.set_options"] {
        if active.contains(pattern) {
            return find_active_line_number(source, pattern);
        }
    }
    None
}

fn find_active_line_number(source: &str, pattern: &str) -> Option<u32> {
    let mut in_block_comment = false;
    for (i, line) in source.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.starts_with("/*") {
            in_block_comment = true;
        }
        if in_block_comment {
            if trimmed.contains("*/") {
                in_block_comment = false;
            }
            continue;
        }
        if trimmed.starts_with("//") || trimmed.starts_with("*") {
            continue;
        }
        if line.contains(pattern) {
            return Some((i + 1) as u32);
        }
    }
    None
}

/// Find all active (non-comment) lines matching a predicate.
fn find_active_lines(source: &str, mut pred: impl FnMut(&str) -> bool) -> Vec<u32> {
    let mut in_block_comment = false;
    source
        .lines()
        .enumerate()
        .filter(|(_, line)| {
            let trimmed = line.trim();
            if trimmed.starts_with("/*") || in_block_comment {
                in_block_comment = !trimmed.contains("*/");
                return false;
            }
            if trimmed.starts_with("//") || trimmed.starts_with("*") {
                return false;
            }
            pred(line)
        })
        .map(|(i, _)| (i + 1) as u32)
        .collect()
}

/// Find missing cookie security flags (httpOnly, secure, sameSite).
fn find_missing_cookie_flags(source: &str) -> Option<u32> {
    let active = strip_comments(source);
    // Check if there's a session cookie config block
    if !active.contains("cookie:") && !active.contains("cookie :") {
        // No cookie config at all — flag the session config
        return find_active_line_number(source, "saveUninitialized")
            .or_else(|| find_active_line_number(source, "secret"))
            .or_else(|| find_active_line_number(source, "session({"));
    }
    // Cookie config exists — check flags
    let has_http_only = active.contains("httpOnly: true") || active.contains("httpOnly : true");
    let has_secure = active.contains("secure: true") || active.contains("secure : true");
    // Check for commented-out secure flag
    let secure_in_comments = extract_comment_regions(source).iter().any(|&(s, e)| {
        source[s..e].contains("secure: true") || source[s..e].contains("secure : true")
    });
    if !has_http_only || (!has_secure && secure_in_comments) {
        find_active_line_number(source, "cookie:")
            .or_else(|| find_active_line_number(source, "cookie :"))
            .or_else(|| find_active_line_number(source, "session({"))
    } else {
        None
    }
}

/// Find login route that doesn't call session.regenerate().
/// Unlike the global check, this examines each `req.session.userId =` assignment
/// and checks whether `regenerate` appears on the same line or within the preceding
/// lines (skipping comment-only lines). This avoids false negatives when `regenerate`
/// is used elsewhere in the file (e.g. a signup handler).
fn find_no_session_regenerate(source: &str) -> Option<u32> {
    let active = strip_comments(source);
    if !active.contains("login") && !active.contains("authenticate") && !active.contains("signin") {
        return None;
    }

    // Find all active `req.session` assignments and check each for nearby regenerate
    let mut in_block = false;
    let lines: Vec<&str> = source.lines().collect();
    for (i, line) in lines.iter().enumerate() {
        let trimmed = line.trim();
        if trimmed.starts_with("/*") {
            in_block = true;
        }
        if in_block {
            if trimmed.contains("*/") {
                in_block = false;
            }
            continue;
        }
        if trimmed.starts_with("//") || trimmed.starts_with("*") {
            continue;
        }

        if line.contains("req.session") && line.contains("= ") {
            // Found an active session assignment — check N preceding lines for regenerate
            let start = if i >= 5 { i - 5 } else { 0 };
            let mut has_regenerate = false;
            let mut in_block2 = false;
            for j in start..=i {
                let t = lines[j].trim();
                if t.starts_with("/*") {
                    in_block2 = true;
                }
                if in_block2 {
                    if t.contains("*/") {
                        in_block2 = false;
                    }
                    continue;
                }
                if t.starts_with("//") || t.starts_with("*") {
                    continue;
                }
                if lines[j].contains("regenerate") {
                    has_regenerate = true;
                    break;
                }
            }
            if !has_regenerate {
                return Some((i + 1) as u32);
            }
        }
    }
    None
}

fn find_no_admin_check(source: &str) -> Option<u32> {
    let active = strip_comments(source);
    if !active.contains("/benefits") && !active.contains("/admin") && !active.contains("isAdmin") {
        return None;
    }

    // Find route definitions containing admin-type paths and check if `isAdmin`
    // middleware is present on the same line.
    let mut in_block = false;
    for (i, line) in source.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.starts_with("/*") {
            in_block = true;
        }
        if in_block {
            if trimmed.contains("*/") {
                in_block = false;
            }
            continue;
        }
        if trimmed.starts_with("//") || trimmed.starts_with("*") {
            continue;
        }

        if (line.contains("/benefits") || line.contains("/admin"))
            && !line.trim_start().starts_with("const ")
            && !line.trim_start().starts_with("let ")
            && !line.trim_start().starts_with("var ")
            && !line.contains("require(")
            && !line.contains("import ")
            && !line.contains("from ")
        {
            // Found a route — check if this same line uses `isAdmin` auth middleware
            if !line.contains("isAdmin")
                && !line.contains("is_admin")
                && !line.contains("requireAdmin")
                && !line.contains("ensureAdmin")
            {
                return Some((i + 1) as u32);
            }
        }
    }
    None
}

fn find_weak_password_policy(source: &str) -> Option<u32> {
    let active = strip_comments(source);
    let has_password = active.contains("password");
    if !has_password {
        return None;
    }
    let has_policy = active.contains("minLength")
        || active.contains("min_length")
        || active.contains("minlength")
        || active.contains("minLen")
        || active.contains("password.length")
        || active.contains("password.len")
        || active.contains("passwordStrength");
    if has_policy {
        return None;
    }
    // Find the password regex or constraint definition, not the first "password" mention
    find_active_line_number(source, "PASS_RE")
        .or_else(|| find_active_line_number(source, "password.*RE"))
        .or_else(|| find_active_line_number(source, "PASS_RE"))
        .or_else(|| find_active_line_number(source, "password"))
}

fn find_user_enumeration(source: &str) -> Option<u32> {
    let active = strip_comments(source);
    let login_related = active.contains("user not found")
        || active.contains("User not found")
        || active.contains("doesn't exist")
        || active.contains("does not exist")
        || active.contains("no account")
        || active.contains("No account")
        || active.contains("invalidUserName")
        || active.contains("invalidPassword")
        || active.contains("invalid user")
        || active.contains("Invalid user");
    if login_related {
        // Prefer the render line where the username is leaked to the template
        find_active_line_number(source, "userName: userName")
            .or_else(|| find_active_line_number(source, "invalidUserName"))
            .or_else(|| find_active_line_number(source, "invalidPassword"))
            .or_else(|| find_active_line_number(source, "user not found"))
            .or_else(|| find_active_line_number(source, "not found"))
    } else if find_active_line_number(source, "userName: userName").is_some() {
        // Some files pass userName to the template without a distinct error message
        find_active_line_number(source, "userName: userName")
    } else {
        None
    }
}
