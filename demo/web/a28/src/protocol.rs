use crate::a28::{self, ScoreDomain, TemplateView};
use serde::{Deserialize, Serialize};
use std::io::{self, BufRead};

pub const MAX_LINE_BYTES: usize = 1024 * 1024;

#[derive(Debug, Serialize)]
pub struct Failure {
    pub code: &'static str,
    pub message: String,
}

impl Failure {
    pub fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self { code, message: message.into() }
    }

    pub fn invalid(message: impl Into<String>) -> Self {
        Self::new("invalid_request", message)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub id: String,
    pub command: Option<String>,
    pub query: Option<Vec<i64>>,
    pub gallery: Option<Vec<Vec<i64>>>,
    pub thresholds: Option<Vec<i64>>,
}

pub struct Evaluation<'a> {
    pub query: &'a [i64],
    pub gallery: &'a [Vec<i64>],
    pub thresholds: &'a [i64],
}

impl Request {
    pub fn validate_id(&self) -> Result<(), Failure> {
        if !valid_id(&self.id) {
            return Err(Failure::invalid("id must contain 1..128 bytes without control characters"));
        }
        Ok(())
    }

    pub fn is_status(&self) -> Result<bool, Failure> {
        match self.command.as_deref() {
            None => Ok(false),
            Some("status") if self.query.is_none() && self.gallery.is_none() && self.thresholds.is_none() => Ok(true),
            _ => Err(Failure::invalid("status accepts only id and command; evaluations omit command")),
        }
    }

    pub fn evaluation(&self) -> Result<Evaluation<'_>, Failure> {
        let request = Evaluation {
            query: self.query.as_deref().ok_or_else(|| Failure::invalid("query is required"))?,
            gallery: self.gallery.as_deref().ok_or_else(|| Failure::invalid("gallery is required"))?,
            thresholds: self.thresholds.as_deref().ok_or_else(|| Failure::invalid("thresholds are required"))?,
        };
        if !(1..=a28::MAX_GALLERY_SIZE).contains(&request.gallery.len()) {
            return Err(Failure::invalid("gallery must contain 1..128 templates"));
        }
        if request.thresholds.len() != request.gallery.len() {
            return Err(Failure::invalid("each template needs exactly one integer threshold"));
        }
        check_vector(request.query)?;
        if norm2(request.query) > a28::PROBE_NORM2_MAX {
            return Err(Failure::invalid("query squared norm exceeds 1024"));
        }
        for template in request.gallery {
            check_vector(template)?;
        }
        // Reject domains outside A28 before spending any encrypted work.
        request.views_and_domain()?;
        Ok(request)
    }
}

fn valid_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= 128 && !id.chars().any(char::is_control)
}

pub fn recover_id(bytes: &[u8]) -> Option<String> {
    // Ignore invalid evaluation fields without copying or returning their contents.
    // Serde still rejects duplicate id fields and malformed JSON.
    #[derive(Deserialize)]
    struct Identity { id: String }
    let identity: Identity = serde_json::from_slice(bytes).ok()?;
    valid_id(&identity.id).then_some(identity.id)
}

fn check_vector(vector: &[i64]) -> Result<(), Failure> {
    if vector.len() != a28::PROBE_DIM || vector.iter().any(|value| !(-3..=3).contains(value)) {
        return Err(Failure::invalid("each vector must have 512 integer coordinates in [-3,3]"));
    }
    Ok(())
}

fn norm2(vector: &[i64]) -> i64 {
    // Called only after bounding the number and value of coordinates.
    vector.iter().map(|value| value * value).sum()
}

impl Evaluation<'_> {
    pub fn views_and_domain(&self) -> Result<(Vec<TemplateView<'_>>, ScoreDomain), Failure> {
        let views: Vec<_> = self.gallery.iter().zip(self.thresholds)
            .map(|(template, &threshold)| TemplateView { template, norm2: norm2(template), threshold })
            .collect();
        let domain = a28::cauchy_score_domain(&views)
            .map_err(|_| Failure::invalid("gallery Cauchy score domain must fit within 4096 integers"))?;
        Ok((views, domain))
    }

    pub fn expected_id(&self) -> u64 {
        let (winner, score) = self.gallery.iter().enumerate()
            .map(|(index, row)| {
                let score = norm2(row) - 2 * row.iter().zip(self.query).map(|(g, q)| g * q).sum::<i64>();
                (index, score)
            })
            .min_by_key(|&(index, score)| (score, index))
            .expect("nonempty validated gallery");
        if score <= self.thresholds[winner] { winner as u64 + 1 } else { 0 }
    }
}

/// Drain an oversized line without ever accumulating more than the limit.
pub fn read_line(reader: &mut impl BufRead) -> io::Result<Option<Result<Vec<u8>, Failure>>> {
    let mut line = Vec::new();
    let mut oversized = false;
    let mut seen = false;
    loop {
        let available = reader.fill_buf()?;
        if available.is_empty() {
            if !seen { return Ok(None); }
            break;
        }
        seen = true;
        let count = available.iter().position(|&byte| byte == b'\n').map_or(available.len(), |i| i + 1);
        let complete = available[count - 1] == b'\n';
        if !oversized {
            if line.len() + count > MAX_LINE_BYTES {
                oversized = true;
                line.clear();
            } else {
                line.extend_from_slice(&available[..count]);
            }
        }
        reader.consume(count);
        if complete { break; }
    }
    if oversized {
        Ok(Some(Err(Failure::new("request_too_large", "JSON line exceeds 1 MiB"))))
    } else {
        Ok(Some(Ok(line)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn request() -> Request {
        Request { id: "test".into(), command: None, query: Some(vec![0; 512]),
            gallery: Some(vec![vec![0; 512]; 2]), thresholds: Some(vec![273, 273]) }
    }

    #[test]
    fn dynamic_thresholds_preserve_first_minimum_then_winner_threshold() {
        let mut request = request();
        assert_eq!(request.evaluation().unwrap().expected_id(), 1);
        request.thresholds = Some(vec![-1, 273]);
        assert_eq!(request.evaluation().unwrap().expected_id(), 0);
        request.thresholds = Some(vec![i64::MAX, i64::MIN]);
        assert_eq!(request.evaluation().unwrap().expected_id(), 1);
    }

    #[test]
    fn invalid_shapes_coordinates_norms_and_domains_are_rejected() {
        let mut value = request();
        value.query = Some(vec![0; 511]);
        assert!(value.evaluation().is_err());
        value.query = Some(vec![4; 512]);
        assert!(value.evaluation().is_err());
        value.query = Some(vec![3; 512]);
        assert!(value.evaluation().is_err());
        value.query = Some(vec![0; 512]);
        value.gallery = Some(vec![vec![3; 512]; 2]);
        assert!(value.evaluation().is_err());
        value.gallery = Some(vec![vec![0; 512]; 129]);
        value.thresholds = Some(vec![4; 129]);
        assert!(value.evaluation().is_err());
    }

    #[test]
    fn status_is_separate_and_unknown_or_duplicate_fields_fail() {
        let status: Request = serde_json::from_str(r#"{"id":"ping","command":"status"}"#).unwrap();
        assert!(status.is_status().unwrap());
        assert!(serde_json::from_str::<Request>(r#"{"id":"a","id":"b"}"#).is_err());
        assert!(serde_json::from_str::<Request>(r#"{"id":"a","unknown":0}"#).is_err());
        let mut value = request();
        value.command = Some("status".into());
        assert!(value.is_status().is_err());
        assert_eq!(recover_id(br#"{"id":"bad-query","query":[0.5]}"#).as_deref(), Some("bad-query"));
        assert!(recover_id(br#"{"id":"a","id":"b"}"#).is_none());
    }

    #[test]
    fn oversized_line_does_not_consume_the_next_request() {
        let mut bytes = vec![b'x'; MAX_LINE_BYTES + 100];
        bytes.extend_from_slice(b"\n{\"id\":\"ping\",\"command\":\"status\"}\n");
        let mut reader = Cursor::new(bytes);
        assert!(read_line(&mut reader).unwrap().unwrap().is_err());
        let second = read_line(&mut reader).unwrap().unwrap().unwrap();
        assert!(serde_json::from_slice::<Request>(&second).unwrap().is_status().unwrap());
        assert!(read_line(&mut reader).unwrap().is_none());
    }
}
