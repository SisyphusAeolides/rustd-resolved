// src/supremacy/mod_exports.rs
use std::sync::Arc;
use crate::supremacy::l2_cache::L2Cache;
use crate::supremacy::obs::Metrics;
use crate::supremacy::swr::SwrConfig;

pub struct SupremacyResolver {
    pub cache: Arc<L2Cache>,
    pub metrics: Arc<Metrics>,
}

impl SupremacyResolver {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            cache: L2Cache::new(6, 8192, SwrConfig::default()),
            metrics: Arc::new(Metrics::default()),
        })
    }
}
