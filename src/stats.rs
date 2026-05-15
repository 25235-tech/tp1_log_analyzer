use std::collections::HashMap;

use crate::parser::FailedLogin;

pub fn count_by_ip(events: &[FailedLogin]) -> Vec<(String, usize)> {
    let mut map: HashMap<String, usize> = HashMap::new();
    for event in events {
        *map.entry(event.ip.clone()).or_insert(0) += 1;
    }
    sorted_desc(map)
}

pub fn count_by_user(events: &[FailedLogin]) -> Vec<(String, usize)> {
    let mut map: HashMap<String, usize> = HashMap::new();
    for event in events {
        *map.entry(event.user.clone()).or_insert(0) += 1;
    }
    sorted_desc(map)
}

fn sorted_desc(map: HashMap<String, usize>) -> Vec<(String, usize)> {
    let mut pairs: Vec<(String, usize)> = map.into_iter().collect();
    pairs.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    pairs
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::FailedLogin;

    fn mk(user: &str, ip: &str) -> FailedLogin {
        FailedLogin {
            user: user.to_string(),
            ip: ip.to_string(),
        }
    }

    #[test]
    fn test_count_by_ip_basic() {
        let events = vec![
            mk("root", "1.2.3.4"),
            mk("admin", "1.2.3.4"),
            mk("guest", "5.6.7.8"),
        ];
        let result = count_by_ip(&events);
        assert_eq!(result[0], ("1.2.3.4".to_string(), 2));
        assert_eq!(result[1], ("5.6.7.8".to_string(), 1));
    }

    #[test]
    fn test_count_by_user_basic() {
        let events = vec![
            mk("root", "1.2.3.4"),
            mk("root", "5.6.7.8"),
            mk("admin", "1.2.3.4"),
        ];
        let result = count_by_user(&events);
        assert_eq!(result[0], ("root".to_string(), 2));
        assert_eq!(result[1], ("admin".to_string(), 1));
    }

    #[test]
    fn test_count_empty() {
        let events: Vec<FailedLogin> = vec![];
        assert!(count_by_ip(&events).is_empty());
        assert!(count_by_user(&events).is_empty());
    }

    #[test]
    fn test_sorted_descending() {
        let events = vec![
            mk("u1", "10.0.0.1"),
            mk("u2", "10.0.0.2"),
            mk("u3", "10.0.0.2"),
            mk("u4", "10.0.0.3"),
            mk("u5", "10.0.0.3"),
            mk("u6", "10.0.0.3"),
        ];
        let result = count_by_ip(&events);
        assert_eq!(result[0].1, 3);
        assert_eq!(result[1].1, 2);
        assert_eq!(result[2].1, 1);
    }
}
