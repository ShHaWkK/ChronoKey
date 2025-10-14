use anyhow::{anyhow, Result};
use regex::Regex;

pub fn normalize_validity(input: &str) -> Result<String> {
    let trimmed = input.trim();
    if is_relative_validity(trimmed) || is_absolute_validity(trimmed) {
        Ok(trimmed.to_string())
    } else {
        Err(anyhow!("unsupported validity format: {trimmed}"))
    }
}

fn is_relative_validity(input: &str) -> bool {
    let re = Regex::new(r"^\+[0-9]+[smhdw]$").unwrap();
    re.is_match(input)
}

fn is_absolute_validity(input: &str) -> bool {
    let re = Regex::new(r"^[0-9]{14}$").unwrap();
    re.is_match(input)
}

pub fn parse_ttl_seconds(input: &str) -> Result<i64> {
    let trimmed = input.trim();
    if let Ok(secs) = trimmed.parse::<i64>() {
        return Ok(secs);
    }
    let re = Regex::new(r"^([0-9]+)([smhdw])$").unwrap();
    if let Some(caps) = re.captures(trimmed) {
        let value: i64 = caps[1].parse()?;
        let multiplier = match &caps[2] {
            "s" => 1,
            "m" => 60,
            "h" => 60 * 60,
            "d" => 60 * 60 * 24,
            "w" => 60 * 60 * 24 * 7,
            _ => 1,
        };
        return Ok(value * multiplier);
    }
    Err(anyhow!("unsupported TTL format: {trimmed}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validity_formats() {
        assert!(normalize_validity("+4h").is_ok());
        assert!(normalize_validity("20240101000000").is_ok());
        assert!(normalize_validity("invalid").is_err());
    }

    #[test]
    fn ttl_parsing() {
        assert_eq!(parse_ttl_seconds("60").unwrap(), 60);
        assert_eq!(parse_ttl_seconds("5m").unwrap(), 300);
        assert!(parse_ttl_seconds("what").is_err());
    }
}
