// Actual reached public operations and separately observed body/address changes.
#[derive(Default)]
struct CenteringCounts {
    calls: usize,
    mask_terms: usize,
    body_additions: usize,
    body_words: usize,
    body_addresses: usize,
}

impl CenteringCounts {
    fn record(&mut self, metrics: &d1::Metrics, observed: &d1::Observation) {
        self.calls += metrics.public_centering_calls;
        self.mask_terms += metrics.public_centering_mask_terms;
        self.body_additions += metrics.public_centering_body_additions;
        self.body_words += usize::from(observed.centering_body_changed);
        self.body_addresses += usize::from(observed.centering_address_changed);
    }

    fn add(&mut self, other: &Self) {
        self.calls += other.calls;
        self.mask_terms += other.mask_terms;
        self.body_additions += other.body_additions;
        self.body_words += other.body_words;
        self.body_addresses += other.body_addresses;
    }

    fn matches(&self, completed_merges: usize) -> bool {
        (self.calls, self.mask_terms, self.body_additions)
            == (completed_merges, 859 * completed_merges, completed_merges)
            && self.body_addresses <= self.body_words
            && self.body_words <= completed_merges
    }

    fn changes(&self) -> Value {
        json!({"body_words":self.body_words,"body_addresses":self.body_addresses})
    }

    fn with_physical(&self, mut value: Value) -> Value {
        value["public_centering_calls"] = json!(self.calls);
        value["public_centering_mask_terms"] = json!(self.mask_terms);
        value["public_centering_body_additions"] = json!(self.body_additions);
        value
    }
}
