#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FailedLogin {
    pub user: String,
    pub ip: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseOutcome {
    Failed(FailedLogin),
    Ignored,
    Malformed,
}

pub fn parse_line(line: &str) -> ParseOutcome {
    if line.contains("Accepted password") || line.contains("Accepted publickey") {
        return ParseOutcome::Ignored;
    }
    if line.contains("Invalid user") && !line.contains("Failed password") {
        return ParseOutcome::Ignored;
    }
    if line.contains("Failed password for") {
        return parse_failed_password(line);
    }
    ParseOutcome::Malformed
}

fn parse_failed_password(line: &str) -> ParseOutcome {
    let after_for = match line.find("Failed password for ") {
        Some(pos) => pos + "Failed password for ".len(),
        None => return ParseOutcome::Malformed,
    };

    let rest = &line[after_for..];

    let (user, rest_after_user) = if let Some(stripped) = rest.strip_prefix("invalid user ") {
        match stripped.split_once(' ') {
            Some((u, r)) => (u.to_string(), r),
            None => return ParseOutcome::Malformed,
        }
    } else {
        match rest.split_once(' ') {
            Some((u, r)) => (u.to_string(), r),
            None => return ParseOutcome::Malformed,
        }
    };

    let after_from = match rest_after_user.find("from ") {
        Some(pos) => pos + "from ".len(),
        None => return ParseOutcome::Malformed,
    };

    let ip = match rest_after_user[after_from..].split_whitespace().next() {
        Some(ip) => ip.to_string(),
        None => return ParseOutcome::Malformed,
    };

    if user.is_empty() || ip.is_empty() {
        return ParseOutcome::Malformed;
    }

    ParseOutcome::Failed(FailedLogin { user, ip })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn failed(user: &str, ip: &str) -> ParseOutcome {
        ParseOutcome::Failed(FailedLogin {
            user: user.to_string(),
            ip: ip.to_string(),
        })
    }

    #[test]
    fn test_failed_normal_user() {
        let line = "Jan 10 08:16:03 srv01 sshd[1002]: Failed password for root from 198.51.100.23 port 55432 ssh2";
        assert_eq!(parse_line(line), failed("root", "198.51.100.23"));
    }

    #[test]
    fn test_failed_invalid_user() {
        let line = "Jan 10 08:15:21 srv01 sshd[1001]: Failed password for invalid user admin from 203.0.113.10 port 34567 ssh2";
        assert_eq!(parse_line(line), failed("admin", "203.0.113.10"));
    }

    #[test]
    fn test_accepted_ignored() {
        let line = "Jan 10 08:16:44 srv01 sshd[1003]: Accepted password for student from 192.0.2.15 port 44822 ssh2";
        assert_eq!(parse_line(line), ParseOutcome::Ignored);
    }

    #[test]
    fn test_invalid_user_notice_ignored() {
        let line =
            "Jan 10 08:19:41 srv01 sshd[1006]: Invalid user oracle from 192.0.2.55 port 51200";
        assert_eq!(parse_line(line), ParseOutcome::Ignored);
    }

    #[test]
    fn test_malformed_does_not_crash() {
        assert_eq!(
            parse_line("MALFORMED LINE WITHOUT EXPECTED SSH FIELDS"),
            ParseOutcome::Malformed
        );
    }

    #[test]
    fn test_empty_line_malformed() {
        assert_eq!(parse_line(""), ParseOutcome::Malformed);
    }

    #[test]
    fn test_failed_guest_invalid_user() {
        let line = "Jan 10 08:21:00 srv01 sshd[1008]: Failed password for invalid user guest from 203.0.113.77 port 60000 ssh2";
        assert_eq!(parse_line(line), failed("guest", "203.0.113.77"));
    }
}
