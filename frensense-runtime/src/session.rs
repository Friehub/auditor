use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct SessionManager {
    pub login_url: String,
    pub username_field: String,
    pub password_field: String,
    pub csrf_field: String,
    pub csrf_cookie_name: String,
    pub session_cookie_name: String,
}

#[derive(Debug, Clone)]
pub struct Session {
    pub cookies: HashMap<String, String>,
    pub csrf_token: Option<String>,
}

impl SessionManager {
    pub fn new(login_url: impl Into<String>) -> Self {
        Self {
            login_url: login_url.into(),
            username_field: "userName".to_string(),
            password_field: "password".to_string(),
            csrf_field: "_csrf".to_string(),
            csrf_cookie_name: "_csrf".to_string(),
            session_cookie_name: "connect.sid".to_string(),
        }
    }

    pub fn with_credentials(mut self, username_field: &str, password_field: &str) -> Self {
        self.username_field = username_field.to_string();
        self.password_field = password_field.to_string();
        self
    }

    pub fn with_csrf(mut self, field: &str, cookie: &str) -> Self {
        self.csrf_field = field.to_string();
        self.csrf_cookie_name = cookie.to_string();
        self
    }

    pub fn with_session_cookie(mut self, name: &str) -> Self {
        self.session_cookie_name = name.to_string();
        self
    }

    /// Acquire a session by:
    /// 1. GET login page → extract CSRF cookie + hidden field token
    /// 2. POST credentials + CSRF token → capture session cookie
    pub async fn acquire_session(
        &self,
        client: &reqwest::Client,
        username: &str,
        password: &str,
    ) -> Result<Session, String> {
        let get_resp = client
            .get(&self.login_url)
            .send()
            .await
            .map_err(|e| format!("Login page GET failed: {e}"))?;

        let _status = get_resp.status().as_u16();
        let headers = get_resp.headers().clone();
        let body = get_resp
            .text()
            .await
            .map_err(|e| format!("Login page body read failed: {e}"))?;

        let mut cookies: HashMap<String, String> = HashMap::new();

        // Extract all Set-Cookie headers
        for cookie_header in headers.get_all("set-cookie") {
            if let Ok(val) = cookie_header.to_str() {
                if let Some(semi) = val.find(';') {
                    let pair = &val[..semi];
                    if let Some(eq) = pair.find('=') {
                        let name = pair[..eq].to_string();
                        let value = pair[eq + 1..].to_string();
                        cookies.insert(name, value);
                    }
                }
            }
        }

        // Extract CSRF token from HTML
        let csrf_token = extract_csrf_from_html(&body, &self.csrf_field);

        // Build POST form
        let mut form_params: Vec<(&str, &str)> = vec![
            (&self.username_field, username),
            (&self.password_field, password),
        ];
        if let Some(ref token) = csrf_token {
            form_params.push((&self.csrf_field, token));
        }

        // Build cookie header from extracted cookies
        let cookie_str = cookies
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
            .join("; ");

        let mut post_req = client
            .post(&self.login_url)
            .header("Cookie", cookie_str)
            .form(&form_params);

        // Some frameworks need the CSRF token in a header too
        if let Some(ref token) = csrf_token {
            post_req = post_req.header("X-CSRF-Token", token);
        }

        let post_resp = post_req
            .send()
            .await
            .map_err(|e| format!("Login POST failed: {e}"))?;

        let post_status = post_resp.status().as_u16();

        // Extract session cookie from login response
        for cookie_header in post_resp.headers().get_all("set-cookie") {
            if let Ok(val) = cookie_header.to_str() {
                if let Some(semi) = val.find(';') {
                    let pair = &val[..semi];
                    if let Some(eq) = pair.find('=') {
                        let name = pair[..eq].to_string();
                        let value = pair[eq + 1..].to_string();
                        cookies.insert(name, value);
                    }
                }
            }
        }

        let has_session = cookies.contains_key(&self.session_cookie_name);

        if !has_session && post_status >= 400 {
            return Err(format!(
                "Login failed (HTTP {post_status}). Check credentials or login URL."
            ));
        }

        Ok(Session {
            cookies,
            csrf_token,
        })
    }
}

pub fn apply_session_to_request(
    session: &Session,
    request: reqwest::RequestBuilder,
) -> reqwest::RequestBuilder {
    let cookie_str = session
        .cookies
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("; ");

    let request = request.header("Cookie", cookie_str);

    if let Some(ref token) = session.csrf_token {
        request.header("X-CSRF-Token", token)
    } else {
        request
    }
}

fn extract_csrf_from_html(html: &str, field_name: &str) -> Option<String> {
    // Pattern 1: <input type="hidden" name="_csrf" value="TOKEN">
    let pattern = format!(
        r#"name=["']{}["'][^>]*value=["']([^"']+)["']"#,
        regex::escape(field_name)
    );
    if let Ok(re) = regex::Regex::new(&pattern) {
        if let Some(cap) = re.captures(html) {
            return Some(cap[1].to_string());
        }
    }

    // Pattern 2: <meta name="_csrf" content="TOKEN">
    let pattern2 = format!(
        r#"<meta[^>]*name=["']{}["'][^>]*content=["']([^"']+)["']"#,
        regex::escape(field_name)
    );
    if let Ok(re) = regex::Regex::new(&pattern2) {
        if let Some(cap) = re.captures(html) {
            return Some(cap[1].to_string());
        }
    }

    // Pattern 3: csrf token in script variable
    let pattern3 = format!(r#"csrf[Token]*\s*=\s*["']([^"']+)["']"#);
    if let Ok(re) = regex::Regex::new(&pattern3) {
        if let Some(cap) = re.captures(html) {
            return Some(cap[1].to_string());
        }
    }

    None
}
