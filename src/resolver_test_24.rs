#[cfg(test)]
mod test_24_authenticated_dns_over_tls {
    use super::*;
    use std::fs;
    use std::io::{BufRead, BufReader};
    use std::path::{Path, PathBuf};
    use std::process::{Child, Command, Stdio};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Mutex;

    static TLS_ENV_LOCK: Mutex<()> = Mutex::new(());
    static TLS_TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

    struct EnvGuard {
        key: &'static str,
        previous: Option<std::ffi::OsString>,
    }

    impl EnvGuard {
        fn set(key: &'static str, value: Option<&Path>) -> Self {
            let previous = std::env::var_os(key);
            match value {
                Some(value) => std::env::set_var(key, value),
                None => std::env::remove_var(key),
            }
            Self { key, previous }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            match self.previous.as_ref() {
                Some(value) => std::env::set_var(self.key, value),
                None => std::env::remove_var(self.key),
            }
        }
    }

    struct TestTlsServer {
        child: Option<Child>,
        address: SocketAddr,
        certificate: PathBuf,
        directory: PathBuf,
    }

    impl TestTlsServer {
        fn spawn(frames: usize, expected_sni: Option<&str>) -> Self {
            let sequence = TLS_TEST_COUNTER.fetch_add(1, Ordering::Relaxed);
            let directory = std::env::temp_dir().join(format!(
                "rustd-resolved-tls-{}-{sequence}",
                std::process::id()
            ));
            let _ = fs::remove_dir_all(&directory);
            fs::create_dir_all(&directory).expect("TLS test directory");
            let certificate = directory.join("server.crt");
            let key = directory.join("server.key");

            let status = Command::new("openssl")
                .args([
                    "req",
                    "-x509",
                    "-newkey",
                    "rsa:2048",
                    "-nodes",
                    "-days",
                    "1",
                    "-subj",
                    "/CN=resolver.example",
                    "-addext",
                    "subjectAltName=DNS:resolver.example,IP:127.0.0.1",
                    "-keyout",
                ])
                .arg(&key)
                .arg("-out")
                .arg(&certificate)
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .expect("run openssl");
            assert!(status.success(), "generate TLS test certificate");

            let script = r#"
import socket, ssl, struct, sys
cert, key, frames, expected_sni = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4]
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.minimum_version = ssl.TLSVersion.TLSv1_2
context.load_cert_chain(cert, key)
seen = {"name": None}
def server_name(ssl_socket, name, initial_context):
    seen["name"] = name
context.set_servername_callback(server_name)
listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
listener.bind(("127.0.0.1", 0))
listener.listen(1)
print(listener.getsockname()[1], flush=True)
raw, _ = listener.accept()
wanted = None if expected_sni == "-" else expected_sni
try:
    with context.wrap_socket(raw, server_side=True) as stream:
        if seen["name"] != wanted:
            raise RuntimeError(f"unexpected SNI: {seen['name']!r}, wanted {wanted!r}")
        def read_exact(count):
            data = b""
            while len(data) < count:
                chunk = stream.recv(count - len(data))
                if not chunk:
                    raise EOFError("TLS client closed")
                data += chunk
            return data
        for _ in range(frames):
            size = struct.unpack("!H", read_exact(2))[0]
            query = bytearray(read_exact(size))
            flags = struct.unpack("!H", query[2:4])[0] | 0x8080
            query[2:4] = struct.pack("!H", flags & ~0x0200)
            stream.sendall(struct.pack("!H", len(query)) + query)
except ssl.SSLError:
    if frames != 0:
        raise
    if seen["name"] != wanted:
        raise RuntimeError(f"unexpected SNI: {seen['name']!r}, wanted {wanted!r}")
listener.close()
"#;

            let mut child = Command::new("python3")
                .arg("-c")
                .arg(script)
                .arg(&certificate)
                .arg(&key)
                .arg(frames.to_string())
                .arg(expected_sni.unwrap_or("-"))
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .expect("spawn TLS test server");
            let mut line = String::new();
            BufReader::new(child.stdout.as_mut().expect("TLS server stdout"))
                .read_line(&mut line)
                .expect("TLS server port");
            let port = line.trim().parse::<u16>().expect("TLS server port number");
            Self {
                child: Some(child),
                address: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port),
                certificate,
                directory,
            }
        }

        const fn address(&self) -> SocketAddr {
            self.address
        }

        fn certificate(&self) -> &Path {
            &self.certificate
        }

        fn wait_success(mut self) {
            let output = self
                .child
                .take()
                .expect("TLS server child")
                .wait_with_output()
                .expect("wait for TLS server");
            assert!(
                output.status.success(),
                "TLS test server failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }

    impl Drop for TestTlsServer {
        fn drop(&mut self) {
            if let Some(mut child) = self.child.take() {
                let _ = child.kill();
                let _ = child.wait();
            }
            let _ = fs::remove_dir_all(&self.directory);
        }
    }

    fn resolver_for_tls(server: &TestTlsServer, mode: TlsMode) -> Resolver {
        let address = server.address();
        Resolver::new(Config {
            upstreams: vec![address],
            upstream_specs: vec![DnsServerSpec {
                address,
                interface: None,
                server_name: Some("resolver.example".to_owned()),
            }],
            fallback_upstreams: Vec::new(),
            fallback_upstream_specs: Vec::new(),
            cache: false,
            attempts: 2,
            query_timeout: Duration::from_secs(2),
            read_etc_hosts: false,
            read_static_records: false,
            dnssec: ValidationMode::No,
            dns_over_tls: mode,
            ..Config::default()
        })
    }

    #[test]
    fn strict_tls_verifies_trusted_name_and_reuses_connection() {
        let _lock = TLS_ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let server = TestTlsServer::spawn(2, Some("resolver.example"));
        let _certificate = EnvGuard::set("SSL_CERT_FILE", Some(server.certificate()));
        let resolver = resolver_for_tls(&server, TlsMode::Yes);
        let key = ServerKey::new(ScopeKind::Global, server.address());

        for (id, name) in [(0x7b01, "tls-one.example"), (0x7b02, "tls-two.example")] {
            let query = make_query(name, TYPE_A, id).expect("TLS DNS query");
            let response = resolver
                .exchange_tls(key, &query, Duration::from_secs(2), true)
                .expect("strict TLS DNS response");
            response_matches(&query, &response).expect("matching TLS DNS response");
        }
        assert_eq!(
            resolver
                .tls_streams
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .get(&TlsPoolKey::new(key, true))
                .map_or(0, Vec::len),
            1
        );
        server.wait_success();
    }

    #[test]
    fn opportunistic_tls_accepts_untrusted_certificate_but_uses_sni() {
        let _lock = TLS_ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let server = TestTlsServer::spawn(1, Some("resolver.example"));
        let _certificate = EnvGuard::set("SSL_CERT_FILE", None);
        let resolver = resolver_for_tls(&server, TlsMode::Opportunistic);
        let key = ServerKey::new(ScopeKind::Global, server.address());
        let query = make_query("opportunistic-encrypted.example", TYPE_A, 0x7b03)
            .expect("TLS DNS query");
        resolver
            .exchange_tls(key, &query, Duration::from_secs(2), false)
            .expect("opportunistic TLS response");
        server.wait_success();
    }

    #[test]
    fn strict_tls_rejects_hostname_mismatch() {
        let _lock = TLS_ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let server = TestTlsServer::spawn(0, Some("wrong.example"));
        let _certificate = EnvGuard::set("SSL_CERT_FILE", Some(server.certificate()));
        assert!(TlsStream::connect(
            server.address(),
            None,
            0,
            Some("wrong.example"),
            true,
            Duration::from_secs(2),
        )
        .is_err());
        server.wait_success();
    }

    #[test]
    fn strict_tls_verifies_ip_when_server_name_is_absent() {
        let _lock = TLS_ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let server = TestTlsServer::spawn(0, None);
        let _certificate = EnvGuard::set("SSL_CERT_FILE", Some(server.certificate()));
        TlsStream::connect(
            server.address(),
            None,
            0,
            None,
            true,
            Duration::from_secs(2),
        )
        .expect("strict TLS IP verification");
        server.wait_success();
    }
}
