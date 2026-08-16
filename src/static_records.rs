// SPDX-License-Identifier: LGPL-2.1-or-later
use crate::json::{self, Value};
use crate::wire::{
    self, Question, WireError, CLASS_ANY, CLASS_IN, TYPE_A, TYPE_AAAA, TYPE_ANY, TYPE_CNAME,
    TYPE_DNAME, TYPE_NS, TYPE_PTR,
};
use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::io::{self, Read};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant, SystemTime};

const RECHECK_INTERVAL: Duration = Duration::from_secs(2);
const MAX_RECORD_FILE_SIZE: usize = 1024 * 1024;
const MAX_RECORD_FILE_READ: u64 = 1024 * 1024 + 1;
const FLAG_QR: u16 = 0x8000;
const FLAG_AA: u16 = 0x0400;
const FLAG_TC: u16 = 0x0200;
const FLAG_RA: u16 = 0x0080;
const FLAG_AD: u16 = 0x0020;
const RCODE_MASK: u16 = 0x000f;

include!("static_records_types.rs");
include!("static_records_files.rs");
include!("static_records_parse.rs");
include!("static_records_response.rs");
include!("static_records_tests.rs");
