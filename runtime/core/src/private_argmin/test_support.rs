//! Shared fixtures for domain and historical circuit tests.
use super::contracts::TemplateView;

pub(super) fn entry<'a>(template: &'a [i64], threshold: i64) -> TemplateView<'a> {
    TemplateView {
        template,
        norm2: template.iter().map(|value| value * value).sum(),
        threshold,
    }
}

pub(super) fn negacyclic_division_sample(body: &[u64], rotation: usize, degree: usize) -> u64 {
    let exponent = degree + rotation;
    let value = body[exponent % body.len()];
    if (exponent / body.len()).is_multiple_of(2) {
        value
    } else {
        value.wrapping_neg()
    }
}
