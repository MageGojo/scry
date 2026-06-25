//! 「掉登录」检测:响应是否表明会话已失效(需触发重登)。

use crate::{LoggedOutSpec, Resp};

/// 响应是否看起来「掉登录」(状态码 / 重定向到 login / 正文标记任一命中)。
pub fn looks_logged_out(resp: &Resp, spec: &LoggedOutSpec) -> bool {
    if spec.statuses.contains(&resp.status) {
        return true;
    }
    if spec.redirect_to_login && (300..400).contains(&resp.status) {
        if let Some(loc) = resp
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("location"))
            .map(|(_, v)| v.to_lowercase())
        {
            if loc.contains("login") || loc.contains("signin") || loc.contains("auth") {
                return true;
            }
        }
    }
    if let Some(s) = &spec.body_contains {
        if !s.is_empty() && String::from_utf8_lossy(resp.body).contains(s.as_str()) {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_triggers() {
        let spec = LoggedOutSpec::default();
        assert!(looks_logged_out(&Resp::new(401, &[], b""), &spec));
        assert!(looks_logged_out(&Resp::new(403, &[], b""), &spec));
        assert!(!looks_logged_out(&Resp::new(200, &[], b""), &spec));
    }

    #[test]
    fn redirect_to_login_triggers() {
        let spec = LoggedOutSpec::default();
        let headers = vec![("Location".into(), "https://x/login?next=/a".into())];
        assert!(looks_logged_out(&Resp::new(302, &headers, b""), &spec));
        let other = vec![("Location".into(), "https://x/home".into())];
        assert!(!looks_logged_out(&Resp::new(302, &other, b""), &spec));
    }

    #[test]
    fn body_marker_triggers() {
        let spec = LoggedOutSpec {
            statuses: vec![],
            redirect_to_login: false,
            body_contains: Some("session expired".into()),
        };
        assert!(looks_logged_out(
            &Resp::new(200, &[], b"your session expired, please re-login"),
            &spec
        ));
        assert!(!looks_logged_out(&Resp::new(200, &[], b"welcome"), &spec));
    }
}
