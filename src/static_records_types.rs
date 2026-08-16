// SPDX-License-Identifier: LGPL-2.1-or-later
static SYSTEM_RECORDS: OnceLock<Mutex<StaticRecords>> = OnceLock::new();

pub fn answer(enabled: bool, query: &[u8]) -> Result<Option<Vec<u8>>, WireError> {
    if !enabled {
        return Ok(None);
    }
    SYSTEM_RECORDS
        .get_or_init(|| Mutex::new(StaticRecords::system(true)))
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .answer(query)
}

pub fn invalidate_system() {
    if let Some(records) = SYSTEM_RECORDS.get() {
        records
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .invalidate();
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct StaticRecord {
    class: u16,
    rr_type: u16,
    rdata: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct FileStamp {
    path: PathBuf,
    masked: bool,
    length: u64,
    modified: Option<SystemTime>,
}

#[derive(Clone, Debug)]
struct SelectedFile {
    path: PathBuf,
    masked: bool,
}

#[derive(Debug)]
pub struct StaticRecords {
    enabled: bool,
    directories: Vec<PathBuf>,
    records: HashMap<String, Vec<StaticRecord>>,
    fingerprint: Vec<FileStamp>,
    last_checked: Option<Instant>,
}

impl StaticRecords {
    pub fn system(enabled: bool) -> Self {
        let mut directories = crate::native_paths::static_record_directories();
        #[cfg(feature = "systemd-compat-paths")]
        directories.extend(crate::native_paths::static_record_directories_compat());
        Self::new(enabled, directories)
    }

    pub fn new(enabled: bool, directories: Vec<PathBuf>) -> Self {
        Self {
            enabled,
            directories,
            records: HashMap::new(),
            fingerprint: Vec::new(),
            last_checked: None,
        }
    }

    pub fn answer(&mut self, query: &[u8]) -> Result<Option<Vec<u8>>, WireError> {
        if !self.enabled {
            return Ok(None);
        }
        let _ = self.refresh_if_due();
        let question = wire::first_question(query)?;
        let key = canonical_name(question.name.text());
        let Some(records) = self.records.get(&key) else {
            return Ok(None);
        };
        build_response(query, &question, records).map(Some)
    }

    pub fn invalidate(&mut self) {
        self.last_checked = None;
        self.fingerprint.clear();
        self.records.clear();
    }

    #[cfg(test)]
    fn force_reload(&mut self) -> io::Result<()> {
        self.last_checked = None;
        self.refresh_if_due()
    }

    fn refresh_if_due(&mut self) -> io::Result<()> {
        let now = Instant::now();
        if self
            .last_checked
            .is_some_and(|checked| now.saturating_duration_since(checked) < RECHECK_INTERVAL)
        {
            return Ok(());
        }
        self.last_checked = Some(now);

        let selected = select_files(&self.directories)?;
        let fingerprint = fingerprint(&selected)?;
        if fingerprint == self.fingerprint {
            return Ok(());
        }

        let records = load_selected_files(&selected);
        self.records = records;
        self.fingerprint = fingerprint;
        Ok(())
    }
}

#[cfg(test)]
mod system_path_tests {
    use super::*;

    #[test]
    fn native_static_record_paths_follow_rustd_layout() {
        let database = StaticRecords::system(true);
        assert_eq!(
            database.directories,
            vec![
                PathBuf::from("/usr/lib/rustd/resolve/static.d"),
                PathBuf::from("/usr/local/lib/rustd/resolve/static.d"),
                PathBuf::from("/run/rustd/resolve/static.d"),
                PathBuf::from("/etc/rustd/resolve/static.d"),
            ]
        );
    }
}
