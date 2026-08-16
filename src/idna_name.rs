//! Internationalized domain names → ASCII A-labels / Unicode U-labels.

use std::borrow::Cow;

#[derive(Debug, Clone, thiserror::Error)]
pub enum IdnaError {
    #[error("empty name")]
    Empty,
    #[error("idna conversion failed: {0}")]
    Convert(String),
    #[error("non-ASCII without idna support")]
    NeedsIdna,
}

/// Convert a presentation name to ASCII (A-labels), without trailing dot.
pub fn to_ascii(name: &str) -> Result<String, IdnaError> {
    let n = name;
    if n.is_empty() {
        return Err(IdnaError::Empty);
    }
    let absolute = n.ends_with('.');
    let core = n.trim_end_matches('.');
    if core.is_empty() {
        return Ok(".".into());
    }

    let ascii = to_ascii_core(core)?;
    if absolute {
        Ok(format!("{}.", ascii))
    } else {
        Ok(ascii)
    }
}

fn to_ascii_core(core: &str) -> Result<String, IdnaError> {
    #[cfg(feature = "idna-name")]
    {
        match idna::domain_to_ascii(core) {
            Ok(ascii) => {
                if !core.starts_with("xn--") {
                    let (unicode, result) = idna::domain_to_unicode(&ascii);
                    if result.is_err() || unicode != core {
                        return Err(IdnaError::Convert("round-trip mismatch".to_owned()));
                    }
                }
                Ok(ascii)
            }
            Err(e) => Err(IdnaError::Convert(format!("{:?}", e))),
        }
    }
    #[cfg(not(feature = "idna-name"))]
    {
        if core.is_ascii() {
            Ok(core.to_ascii_lowercase())
        } else {
            Err(IdnaError::NeedsIdna)
        }
    }
}

/// Unicode form for display / D-Bus results.
pub fn to_unicode(name: &str) -> Result<String, IdnaError> {
    let n = name.trim().trim_end_matches('.');
    if n.is_empty() {
        return Ok(".".into());
    }
    #[cfg(feature = "idna-name")]
    {
        match idna::domain_to_unicode(n) {
            (s, Ok(())) => Ok(s),
            (s, Err(_)) => Ok(s), // best-effort
        }
    }
    #[cfg(not(feature = "idna-name"))]
    {
        Ok(n.to_string())
    }
}

/// Lowercase ASCII name suitable as cache key (A-labels).
pub fn cache_key_name(name: &str) -> Result<String, IdnaError> {
    Ok(to_ascii(name)?.trim_end_matches('.').to_ascii_lowercase())
}

pub fn is_ldh_label(lab: &str) -> bool {
    if lab.is_empty() || lab.len() > 63 {
        return false;
    }
    let b = lab.as_bytes();
    if b[0] == b'-' || b[lab.len() - 1] == b'-' {
        return false;
    }
    b.iter().all(|c| c.is_ascii_alphanumeric() || *c == b'-')
}

/// Validate each label of an ASCII domain.
pub fn validate_ascii_domain(name: &str) -> bool {
    let n = name.trim().trim_end_matches('.');
    if n.is_empty() {
        return true; // root
    }
    n.split('.').all(is_ldh_label)
}

pub fn cow_ascii_lower(s: &str) -> Cow<'_, str> {
    if s.bytes().any(|b| (b'A'..=b'Z').contains(&b)) {
        Cow::Owned(s.to_ascii_lowercase())
    } else {
        Cow::Borrowed(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ascii_path() {
        #[cfg(feature = "idna-name")]
        assert!(to_ascii("ExAmPle.COM").is_err());
        #[cfg(not(feature = "idna-name"))]
        assert_eq!(to_ascii("ExAmPle.COM").unwrap(), "example.com");
        assert_eq!(to_ascii("example.com").unwrap(), "example.com");
        assert!(validate_ascii_domain("example.com"));
    }
}
