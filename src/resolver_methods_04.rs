impl Resolver {
    fn udp_transaction_timeout(&self, remaining: Duration) -> Duration {
        self.config()
            .query_timeout
            .min(DNS_TRANSACTION_UDP_TIMEOUT)
            .min(remaining)
    }

    fn tcp_transaction_timeout(&self, remaining: Duration) -> Duration {
        let query_timeout = self.config().query_timeout;
        let timeout = if query_timeout == DNS_TRANSACTION_UDP_TIMEOUT {
            DNS_TRANSACTION_TCP_TIMEOUT
        } else {
            query_timeout.min(DNS_TRANSACTION_TCP_TIMEOUT)
        };
        timeout.min(remaining)
    }

    fn take_udp_socket(&self, server: ServerKey) -> Result<UdpSocket, ResolveError> {
        let pooled = {
            let mut sockets = self
                .udp_sockets
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            sockets.get_mut(&server).and_then(Vec::pop)
        };

        if let Some(socket) = pooled {
            return Ok(socket);
        }

        let address = server.server();
        let fd = native::udp_connect(
            address,
            self.server_transport_ifindex(server)?,
            self.server_firewall_mark(server),
        )?;
        // SAFETY: the native connector returns a fresh owned UDP socket descriptor on success.
        let socket = unsafe { <UdpSocket as std::os::fd::FromRawFd>::from_raw_fd(fd) };
        let _ = native::enable_udp_fragment_size(socket.as_raw_fd(), address.is_ipv6());
        Ok(socket)
    }

    fn recycle_udp_socket(&self, server: ServerKey, socket: UdpSocket) {
        let mut sockets = self
            .udp_sockets
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let pool = sockets.entry(server).or_default();
        if pool.len() < UDP_POOL_PER_SERVER_MAX {
            pool.push(socket);
        }
    }

    fn exchange_udp(
        &self,
        server: ServerKey,
        query: &[u8],
        remaining: Duration,
    ) -> Result<(Vec<u8>, u32), ResolveError> {
        let socket = self.take_udp_socket(server)?;
        let timeout = self.udp_transaction_timeout(remaining);
        socket.set_read_timeout(Some(timeout))?;
        socket.set_write_timeout(Some(timeout))?;
        let result = (|| {
            crate::query_cancel::check()?;
            if socket.send(query)? != query.len() {
                return Err(ResolveError::Protocol("short UDP send"));
            }

            let started = Instant::now();
            let mut response = vec![0; usize::from(u16::MAX)];
            loop {
                let Some(remaining) = timeout.checked_sub(started.elapsed()) else {
                    return Err(
                        io::Error::new(io::ErrorKind::TimedOut, "DNS UDP query timed out").into(),
                    );
                };
                if remaining.is_zero() {
                    return Err(
                        io::Error::new(io::ErrorKind::TimedOut, "DNS UDP query timed out").into(),
                    );
                }
                crate::query_cancel::check()?;
                socket.set_read_timeout(Some(
                    remaining.min(QUERY_CANCELLATION_POLL_INTERVAL),
                ))?;
                let (length, fragment_size) = match native::udp_recv(
                    socket.as_raw_fd(),
                    &mut response,
                ) {
                    Ok(result) => result,
                    Err(error)
                        if matches!(
                            error.kind(),
                            io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
                        ) =>
                    {
                        crate::query_cancel::check()?;
                        continue;
                    }
                    Err(error) => return Err(error.into()),
                };
                if response_matches(query, &response[..length]).is_err() {
                    continue;
                }
                response.truncate(length);
                return Ok((response, fragment_size));
            }
        })();

        if result.is_ok() {
            self.recycle_udp_socket(server, socket);
        }
        result
    }

    fn udp_path_mtu(&self, server: ServerKey) -> Option<u32> {
        let socket = self.take_udp_socket(server).ok()?;
        let address = server.server();
        let result = native::udp_path_mtu(socket.as_raw_fd(), address.is_ipv6()).ok();
        self.recycle_udp_socket(server, socket);
        result
    }

    fn new_tcp_stream(
        &self,
        server: ServerKey,
        timeout: Duration,
    ) -> Result<TcpStream, ResolveError> {
        let fd = native::tcp_connect(
            server.server(),
            self.server_transport_ifindex(server)?,
            self.server_firewall_mark(server),
            timeout,
        )?;
        // SAFETY: the native connector returns a fresh owned TCP socket descriptor on success.
        let stream = unsafe { <TcpStream as std::os::fd::FromRawFd>::from_raw_fd(fd) };
        stream.set_read_timeout(Some(timeout))?;
        stream.set_write_timeout(Some(timeout))?;
        Ok(stream)
    }

    fn take_tcp_stream(
        &self,
        server: ServerKey,
        timeout: Duration,
    ) -> Result<(TcpStream, bool), ResolveError> {
        let pooled = {
            let mut streams = self
                .tcp_streams
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            streams.get_mut(&server).and_then(Vec::pop)
        };
        let reused = pooled.is_some();
        let stream = match pooled {
            Some(stream) => stream,
            None => self.new_tcp_stream(server, timeout)?,
        };
        stream.set_read_timeout(Some(timeout))?;
        stream.set_write_timeout(Some(timeout))?;
        Ok((stream, reused))
    }

    fn recycle_tcp_stream(&self, server: ServerKey, stream: TcpStream) {
        let mut streams = self
            .tcp_streams
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let pool = streams.entry(server).or_default();
        if pool.len() < TCP_POOL_PER_SERVER_MAX {
            pool.push(stream);
        }
    }

    fn exchange_tcp_stream(
        stream: &mut TcpStream,
        query: &[u8],
    ) -> Result<Vec<u8>, ResolveError> {
        let query_length = u16::try_from(query.len())
            .map_err(|_| ResolveError::Protocol("DNS query exceeds the TCP frame limit"))?;
        stream.write_all(&query_length.to_be_bytes())?;
        stream.write_all(query)?;

        let mut length = [0; 2];
        stream.read_exact(&mut length)?;
        let length = usize::from(u16::from_be_bytes(length));
        if length < wire::DNS_HEADER_LEN {
            return Err(ResolveError::Protocol("short DNS-over-TCP frame"));
        }
        let mut response = vec![0; length];
        stream.read_exact(&mut response)?;
        response_matches(query, &response)?;
        if Header::parse(&response)?.truncated() {
            return Err(ResolveError::Protocol(
                "truncated DNS-over-TCP response",
            ));
        }
        Ok(response)
    }

    fn exchange_tcp(
        &self,
        server: ServerKey,
        query: &[u8],
        remaining: Duration,
    ) -> Result<Vec<u8>, ResolveError> {
        let timeout = self.tcp_transaction_timeout(remaining);
        let started = Instant::now();
        let (mut stream, reused) = self.take_tcp_stream(server, timeout)?;
        let result = Self::exchange_tcp_stream(&mut stream, query);
        if result.is_ok() {
            self.recycle_tcp_stream(server, stream);
            return result;
        }
        if !reused {
            return result;
        }

        let Some(timeout) = timeout.checked_sub(started.elapsed()) else {
            return result;
        };
        if timeout.is_zero() {
            return result;
        }
        let mut fresh = self.new_tcp_stream(server, timeout)?;
        let result = Self::exchange_tcp_stream(&mut fresh, query);
        if result.is_ok() {
            self.recycle_tcp_stream(server, fresh);
        }
        result
    }

    fn new_tls_stream(
        &self,
        server: ServerKey,
        strict: bool,
        timeout: Duration,
    ) -> Result<TlsStream, ResolveError> {
        let (endpoint, server_name) = self.server_tls_endpoint(server);
        Ok(TlsStream::connect(
            endpoint,
            self.server_transport_ifindex(server)?,
            self.server_firewall_mark(server),
            server_name.as_deref(),
            strict,
            timeout,
        )?)
    }

    fn take_tls_stream(
        &self,
        server: ServerKey,
        strict: bool,
        timeout: Duration,
    ) -> Result<(TlsStream, bool), ResolveError> {
        let key = TlsPoolKey::new(server, strict);
        let pooled = {
            let mut streams = self
                .tls_streams
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            streams.get_mut(&key).and_then(Vec::pop)
        };
        let reused = pooled.is_some();
        let mut stream = match pooled {
            Some(stream) => stream,
            None => self.new_tls_stream(server, strict, timeout)?,
        };
        stream.set_timeout(timeout)?;
        Ok((stream, reused))
    }

    fn recycle_tls_stream(&self, server: ServerKey, strict: bool, stream: TlsStream) {
        let mut streams = self
            .tls_streams
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let pool = streams.entry(TlsPoolKey::new(server, strict)).or_default();
        if pool.len() < TLS_POOL_PER_SERVER_MAX {
            pool.push(stream);
        }
    }

    fn exchange_tls_stream(
        stream: &mut TlsStream,
        query: &[u8],
    ) -> Result<Vec<u8>, ResolveError> {
        let query_length = u16::try_from(query.len())
            .map_err(|_| ResolveError::Protocol("DNS query exceeds the TLS frame limit"))?;
        stream.write_all(&query_length.to_be_bytes())?;
        stream.write_all(query)?;

        let mut length = [0; 2];
        stream.read_exact(&mut length)?;
        let length = usize::from(u16::from_be_bytes(length));
        if length < wire::DNS_HEADER_LEN {
            return Err(ResolveError::Protocol("short DNS-over-TLS frame"));
        }
        let mut response = vec![0; length];
        stream.read_exact(&mut response)?;
        response_matches(query, &response)?;
        if Header::parse(&response)?.truncated() {
            return Err(ResolveError::Protocol(
                "truncated DNS-over-TLS response",
            ));
        }
        Ok(response)
    }

    fn exchange_tls(
        &self,
        server: ServerKey,
        query: &[u8],
        remaining: Duration,
        strict: bool,
    ) -> Result<Vec<u8>, ResolveError> {
        let timeout = self.tcp_transaction_timeout(remaining);
        let started = Instant::now();
        let (mut stream, reused) = self.take_tls_stream(server, strict, timeout)?;
        let result = Self::exchange_tls_stream(&mut stream, query);
        if result.is_ok() {
            self.recycle_tls_stream(server, strict, stream);
            return result;
        }
        if !reused {
            return result;
        }

        let Some(timeout) = timeout.checked_sub(started.elapsed()) else {
            return result;
        };
        if timeout.is_zero() {
            return result;
        }
        let mut fresh = self.new_tls_stream(server, strict, timeout)?;
        let result = Self::exchange_tls_stream(&mut fresh, query);
        if result.is_ok() {
            self.recycle_tls_stream(server, strict, fresh);
        }
        result
    }

    pub fn lookup_name(&self, name: &str, family: i32) -> Result<NameLookup, ResolveError> {
        self.lookup_name_on_link(name, family, None)
    }

    pub fn lookup_name_on_link(
        &self,
        name: &str,
        family: i32,
        ifindex: Option<i32>,
    ) -> Result<NameLookup, ResolveError> {
        self.lookup_name_on_link_with_request_flags(name, family, ifindex, 0)
    }

    pub fn lookup_name_on_link_with_request_flags(
        &self,
        name: &str,
        family: i32,
        ifindex: Option<i32>,
        request_flags: u64,
    ) -> Result<NameLookup, ResolveError> {
        let types: &[u16] = match family {
            0 => &[TYPE_A, TYPE_AAAA],
            2 => &[TYPE_A],
            10 => &[TYPE_AAAA],
            _ => return Err(ResolveError::UnsupportedFamily(family)),
        };
        if request_flags & crate::dbus_resolve1_abi::flags::SD_RESOLVED_NO_SYNTHESIZE == 0
            && self.has_local_name(name, types)?
        {
            return self.lookup_name_exact(name, types, ifindex, request_flags);
        }

        let domains = self.search_domains(ifindex)?;
        let candidates = if request_flags
            & crate::dbus_resolve1_abi::flags::SD_RESOLVED_NO_SEARCH
            != 0
        {
            vec![name.to_owned()]
        } else {
            lookup_candidates(
                name,
                &domains,
                self.config().resolve_unicast_single_label
                    || request_flags
                        & crate::dbus_resolve1_abi::flags::SD_RESOLVED_RELAX_SINGLE_LABEL
                        != 0,
            )
        };
        let mut last_error = None;
        for candidate in candidates {
            match self.lookup_name_exact(&candidate, types, ifindex, request_flags) {
                Ok(result) => return Ok(result),
                Err(error) => last_error = Some(error),
            }
        }
        Err(last_error.unwrap_or(ResolveError::NoSuchResourceRecord))
    }

    fn has_local_name(&self, name: &str, types: &[u16]) -> Result<bool, ResolveError> {
        let hosts = self.hosts();
        for &rr_type in types {
            let query = make_query(name, rr_type, 0)?;
            let question = first_question(&query)?;
            if hosts.lookup(&question).is_some() {
                return Ok(true);
            }
        }
        Ok(false)
    }
}
