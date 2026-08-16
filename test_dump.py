import json, socket, sys
sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
sock.connect("/run/systemd/resolve/io.systemd.Resolve.Monitor")
# actually we can just look at `src/bin/resolvectl.rs` `interactive_parameters` or `DumpServerState` to see how it's handled. 
