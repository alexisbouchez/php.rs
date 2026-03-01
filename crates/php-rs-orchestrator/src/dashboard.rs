//! Server-rendered HTML dashboard for the PaaS.
//!
//! Served on the same port as the API under the `/dashboard/` prefix.
//! Uses session cookie auth (same as API).

use std::collections::HashMap;

use crate::state::{self, PlatformState};

/// Render the dashboard page for a given path.
/// Returns (status_code, content_type, body).
pub fn render_dashboard(
    path: &str,
    user_id: Option<u64>,
    _headers: &HashMap<String, String>,
) -> (u16, &'static str, String) {
    // Require authentication for all dashboard pages except login.
    if user_id.is_none() && path != "/dashboard/login" {
        return (
            302,
            "text/html",
            redirect_html("/dashboard/login"),
        );
    }

    let user_store = crate::auth::UserStore::load();
    let username = user_id
        .and_then(|uid| user_store.get_user(uid))
        .map(|u| u.username.clone())
        .unwrap_or_default();

    match path {
        "/dashboard" | "/dashboard/" => render_app_list(&username),
        "/dashboard/login" => render_login_page(),
        p if p.starts_with("/dashboard/apps/") => {
            let app_name = p.strip_prefix("/dashboard/apps/").unwrap_or("");
            if app_name.is_empty() {
                render_app_list(&username)
            } else {
                render_app_detail(app_name, &username)
            }
        }
        _ => (404, "text/html", render_404()),
    }
}

fn redirect_html(url: &str) -> String {
    format!(
        "<html><head><meta http-equiv=\"refresh\" content=\"0;url={}\"></head><body>Redirecting...</body></html>",
        url
    )
}

fn render_404() -> String {
    page_layout(
        "Not Found",
        "",
        "<div class=\"card\"><h2>404 — Page Not Found</h2><p><a href=\"/dashboard\">Back to Dashboard</a></p></div>",
    )
}

fn render_login_page() -> (u16, &'static str, String) {
    let html = page_layout("Login", "", &format!(r#"
        <div class="card" style="max-width:400px;margin:80px auto">
            <h2>php.rs Dashboard</h2>
            <form method="POST" action="/api/auth/login" id="loginForm">
                <div class="form-group">
                    <label for="username">Username</label>
                    <input type="text" id="username" name="username" required autofocus>
                </div>
                <div class="form-group">
                    <label for="password">Password</label>
                    <input type="password" id="password" name="password" required>
                </div>
                <button type="submit" class="btn btn-primary" style="width:100%">Log In</button>
                <p style="margin-top:16px;text-align:center;color:#666">
                    Don't have an account? <a href="/api/auth/register">Register via API</a>
                </p>
            </form>
            <script>
            document.getElementById('loginForm').addEventListener('submit', async function(e) {{
                e.preventDefault();
                const resp = await fetch('/api/auth/login', {{
                    method: 'POST',
                    headers: {{'Content-Type': 'application/json'}},
                    body: JSON.stringify({{
                        username: document.getElementById('username').value,
                        password: document.getElementById('password').value
                    }})
                }});
                if (resp.ok) {{
                    window.location.href = '/dashboard';
                }} else {{
                    const data = await resp.json();
                    alert(data.error || 'Login failed');
                }}
            }});
            </script>
        </div>
    "#));
    (200, "text/html", html)
}

fn render_app_list(username: &str) -> (u16, &'static str, String) {
    let state = PlatformState::load();

    let mut rows = String::new();
    let mut app_names: Vec<&String> = state.apps.keys().collect();
    app_names.sort();

    for name in app_names {
        let app = &state.apps[name];
        let status = if app.is_running() {
            "<span class=\"badge badge-green\">running</span>"
        } else if app.pid.is_some() {
            "<span class=\"badge badge-red\">crashed</span>"
        } else {
            "<span class=\"badge badge-gray\">stopped</span>"
        };
        let instances = crate::scaling::current_instance_count(app);
        let workers = app.worker_configs.iter().map(|w| w.count as usize).sum::<usize>();
        let crons = app.cron_jobs.len();

        rows.push_str(&format!(
            r#"<tr>
                <td><a href="/dashboard/apps/{name}">{name}</a></td>
                <td>{status}</td>
                <td>{port}</td>
                <td>{instances}</td>
                <td>{workers}</td>
                <td>{crons}</td>
                <td>{created}</td>
            </tr>"#,
            name = name,
            status = status,
            port = app.port,
            instances = instances,
            workers = workers,
            crons = crons,
            created = &app.created_at[..10],
        ));
    }

    if rows.is_empty() {
        rows = "<tr><td colspan=\"7\" style=\"text-align:center;padding:40px;color:#666\">No apps yet. Create one with <code>php-rs-ctl app create</code></td></tr>".into();
    }

    let content = format!(r#"
        <div class="header-row">
            <h2>Applications</h2>
            <span class="badge badge-blue">{count} apps</span>
        </div>
        <div class="card">
            <table>
                <thead>
                    <tr>
                        <th>Name</th>
                        <th>Status</th>
                        <th>Port</th>
                        <th>Instances</th>
                        <th>Workers</th>
                        <th>Crons</th>
                        <th>Created</th>
                    </tr>
                </thead>
                <tbody>
                    {rows}
                </tbody>
            </table>
        </div>
    "#, count = state.apps.len(), rows = rows);

    (200, "text/html", page_layout("Dashboard", username, &content))
}

fn render_app_detail(name: &str, username: &str) -> (u16, &'static str, String) {
    let state = PlatformState::load();
    let app = match state.get_app(name) {
        Some(a) => a,
        None => {
            return (404, "text/html", page_layout("Not Found", username,
                &format!("<div class=\"card\"><h2>App '{}' not found</h2><p><a href=\"/dashboard\">Back</a></p></div>", name)));
        }
    };

    let status_badge = if app.is_running() {
        "<span class=\"badge badge-green\">running</span>"
    } else if app.pid.is_some() {
        "<span class=\"badge badge-red\">crashed</span>"
    } else {
        "<span class=\"badge badge-gray\">stopped</span>"
    };

    let instances = crate::scaling::current_instance_count(app);

    // Environment variables.
    let mut env_rows = String::new();
    let mut keys: Vec<&String> = app.env.keys().collect();
    keys.sort();
    for key in keys {
        let val = &app.env[key];
        let display = if crate::secrets::is_encrypted(val) {
            "[encrypted]".to_string()
        } else {
            html_escape(val)
        };
        env_rows.push_str(&format!(
            "<tr><td><code>{}</code></td><td><code>{}</code></td></tr>",
            html_escape(key),
            display
        ));
    }

    // Cron jobs.
    let mut cron_rows = String::new();
    for job in &app.cron_jobs {
        let status = if job.enabled { "enabled" } else { "disabled" };
        cron_rows.push_str(&format!(
            "<tr><td>#{}</td><td><code>{}</code></td><td>{}</td><td>{}</td></tr>",
            job.id, job.schedule, job.command, status
        ));
    }

    // Worker configs.
    let mut worker_rows = String::new();
    for wc in &app.worker_configs {
        let running = wc.pids.iter().filter(|&&p| state::process_alive(p)).count();
        let status = if wc.enabled { "enabled" } else { "disabled" };
        worker_rows.push_str(&format!(
            "<tr><td>#{}</td><td>{}</td><td>{}</td><td>{}/{}</td><td>{}</td></tr>",
            wc.id, wc.command, status, running, wc.count,
            wc.pids.iter().map(|p| p.to_string()).collect::<Vec<_>>().join(", ")
        ));
    }

    // Releases.
    let mut release_rows = String::new();
    for r in app.releases.iter().rev().take(10) {
        let current = if Some(r.version) == app.current_release { " (current)" } else { "" };
        release_rows.push_str(&format!(
            "<tr><td>v{}{}</td><td>{}</td><td><code>{}</code></td></tr>",
            r.version, current, r.deployed_at, r.path
        ));
    }

    let content = format!(r#"
        <p><a href="/dashboard">&larr; Back to apps</a></p>
        <div class="header-row">
            <h2>{name} {status}</h2>
        </div>

        <div class="grid">
            <div class="card">
                <h3>Overview</h3>
                <table class="info-table">
                    <tr><td>Port</td><td>{port}</td></tr>
                    <tr><td>PID</td><td>{pid}</td></tr>
                    <tr><td>Root</td><td><code>{root}</code></td></tr>
                    <tr><td>Entry</td><td><code>{entry}</code></td></tr>
                    <tr><td>DocRoot</td><td><code>{docroot}</code></td></tr>
                    <tr><td>Workers</td><td>{worker_count}</td></tr>
                    <tr><td>Instances</td><td>{instances} (min: {min}, max: {max})</td></tr>
                    <tr><td>Created</td><td>{created}</td></tr>
                </table>
            </div>

            <div class="card">
                <h3>Environment Variables</h3>
                {env_section}
            </div>
        </div>

        {cron_section}

        {worker_section}

        {release_section}
    "#,
        name = name,
        status = status_badge,
        port = app.port,
        pid = app.pid.map(|p| p.to_string()).unwrap_or("-".into()),
        root = app.root,
        entry = app.entry,
        docroot = app.docroot,
        worker_count = if app.workers == 0 { "auto".into() } else { app.workers.to_string() },
        instances = instances,
        min = app.scaling.min_instances,
        max = app.scaling.max_instances,
        created = app.created_at,
        env_section = if env_rows.is_empty() {
            "<p class=\"muted\">No environment variables</p>".to_string()
        } else {
            format!("<table><thead><tr><th>Key</th><th>Value</th></tr></thead><tbody>{}</tbody></table>", env_rows)
        },
        cron_section = if cron_rows.is_empty() {
            String::new()
        } else {
            format!(r#"<div class="card"><h3>Cron Jobs</h3><table><thead><tr><th>ID</th><th>Schedule</th><th>Command</th><th>Status</th></tr></thead><tbody>{}</tbody></table></div>"#, cron_rows)
        },
        worker_section = if worker_rows.is_empty() {
            String::new()
        } else {
            format!(r#"<div class="card"><h3>Workers</h3><table><thead><tr><th>ID</th><th>Command</th><th>Status</th><th>Running</th><th>PIDs</th></tr></thead><tbody>{}</tbody></table></div>"#, worker_rows)
        },
        release_section = if release_rows.is_empty() {
            String::new()
        } else {
            format!(r#"<div class="card"><h3>Releases</h3><table><thead><tr><th>Version</th><th>Deployed</th><th>Path</th></tr></thead><tbody>{}</tbody></table></div>"#, release_rows)
        },
    );

    (200, "text/html", page_layout(&format!("{} — Dashboard", name), username, &content))
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn page_layout(title: &str, username: &str, content: &str) -> String {
    let nav = if username.is_empty() {
        String::new()
    } else {
        let mut n = String::new();
        n.push_str("<nav><div class=\"nav-left\">");
        n.push_str("<a href=\"/dashboard\" class=\"nav-brand\">php.rs</a>");
        n.push_str("<a href=\"/dashboard\">Apps</a>");
        n.push_str("</div><div class=\"nav-right\">");
        n.push_str(&format!("<span class=\"nav-user\">{}</span>", username));
        n.push_str("<a href=\"/dashboard/login\" id=\"logoutBtn\">Logout</a>");
        n.push_str("</div></nav>");
        n.push_str("<script>document.getElementById('logoutBtn').addEventListener('click',function(e){e.preventDefault();fetch('/api/auth/logout',{method:'POST'}).then(function(){location.href='/dashboard/login'})});</script>");
        n
    };

    format!(r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{title}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #f5f5f5; color: #333; }}
        nav {{ background: #1a1a2e; color: #fff; padding: 0 24px; height: 56px; display: flex; align-items: center; justify-content: space-between; }}
        .nav-left, .nav-right {{ display: flex; align-items: center; gap: 20px; }}
        .nav-brand {{ font-weight: 700; font-size: 18px; color: #4ade80; text-decoration: none; }}
        nav a {{ color: #ccc; text-decoration: none; font-size: 14px; }} nav a:hover {{ color: #fff; }}
        .nav-user {{ color: #aaa; font-size: 13px; }}
        .container {{ max-width: 1200px; margin: 0 auto; padding: 24px; }}
        .card {{ background: #fff; border-radius: 8px; padding: 24px; margin-bottom: 16px; box-shadow: 0 1px 3px rgba(0,0,0,.08); }}
        .header-row {{ display: flex; align-items: center; gap: 12px; margin-bottom: 16px; }}
        h2 {{ font-size: 22px; font-weight: 600; }}
        h3 {{ font-size: 16px; font-weight: 600; margin-bottom: 12px; }}
        table {{ width: 100%; border-collapse: collapse; font-size: 14px; }}
        thead th {{ text-align: left; padding: 8px 12px; border-bottom: 2px solid #eee; color: #666; font-weight: 500; }}
        tbody td {{ padding: 8px 12px; border-bottom: 1px solid #f0f0f0; }}
        tbody tr:hover {{ background: #fafafa; }}
        .info-table td:first-child {{ font-weight: 500; color: #666; width: 120px; }}
        code {{ background: #f0f0f0; padding: 2px 6px; border-radius: 3px; font-size: 13px; }}
        a {{ color: #2563eb; text-decoration: none; }} a:hover {{ text-decoration: underline; }}
        .badge {{ display: inline-block; padding: 2px 8px; border-radius: 10px; font-size: 12px; font-weight: 500; }}
        .badge-green {{ background: #dcfce7; color: #166534; }}
        .badge-red {{ background: #fee2e2; color: #991b1b; }}
        .badge-gray {{ background: #f3f4f6; color: #6b7280; }}
        .badge-blue {{ background: #dbeafe; color: #1d4ed8; }}
        .grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 16px; }}
        @media (max-width: 768px) {{ .grid {{ grid-template-columns: 1fr; }} }}
        .muted {{ color: #999; font-size: 14px; }}
        .form-group {{ margin-bottom: 16px; }}
        .form-group label {{ display: block; font-size: 14px; font-weight: 500; margin-bottom: 4px; }}
        .form-group input {{ width: 100%; padding: 8px 12px; border: 1px solid #ddd; border-radius: 6px; font-size: 14px; }}
        .btn {{ padding: 8px 16px; border: none; border-radius: 6px; cursor: pointer; font-size: 14px; font-weight: 500; }}
        .btn-primary {{ background: #2563eb; color: #fff; }} .btn-primary:hover {{ background: #1d4ed8; }}
    </style>
</head>
<body>
    {nav}
    <div class="container">
        {content}
    </div>
</body>
</html>"#, title = title, nav = nav, content = content)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_html_escape() {
        assert_eq!(html_escape("<script>"), "&lt;script&gt;");
        assert_eq!(html_escape("a&b"), "a&amp;b");
        assert_eq!(html_escape("\"quotes\""), "&quot;quotes&quot;");
    }

    #[test]
    fn test_render_login_page() {
        let (status, content_type, body) = render_login_page();
        assert_eq!(status, 200);
        assert_eq!(content_type, "text/html");
        assert!(body.contains("Login"));
        assert!(body.contains("loginForm"));
    }

    #[test]
    fn test_render_404() {
        let html = render_404();
        assert!(html.contains("404"));
        assert!(html.contains("Not Found"));
    }

    #[test]
    fn test_render_dashboard_unauthenticated() {
        let (status, _, body) = render_dashboard("/dashboard", None, &HashMap::new());
        assert_eq!(status, 302);
        assert!(body.contains("/dashboard/login"));
    }

    #[test]
    fn test_render_dashboard_login_no_auth_needed() {
        let (status, _, body) = render_dashboard("/dashboard/login", None, &HashMap::new());
        assert_eq!(status, 200);
        assert!(body.contains("Login"));
    }

    #[test]
    fn test_page_layout() {
        let html = page_layout("Test Title", "admin", "<p>Hello</p>");
        assert!(html.contains("Test Title"));
        assert!(html.contains("admin"));
        assert!(html.contains("<p>Hello</p>"));
        assert!(html.contains("php.rs"));
    }

    #[test]
    fn test_page_layout_no_user() {
        let html = page_layout("Login", "", "<p>Form</p>");
        assert!(!html.contains("Logout"));
    }
}
