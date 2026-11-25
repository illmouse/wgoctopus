import asyncssh


class SSHServer(asyncssh.SSHServer):
    def __init__(self, allowed_port):
        self.allowed_port = allowed_port

    def begin_auth(self, username):
        return True

    def password_auth_supported(self):
        return True

    def validate_password(self, username, password):
        return password == "bootstrap-password"

    def public_key_auth_supported(self):
        return True

    def connection_requested(self, dest_host, dest_port, orig_host, orig_port):
        return dest_host in {"127.0.0.1", "localhost"} and dest_port == self.allowed_port


async def start_server(port, allowed_port, key, client_key):
    return await asyncssh.create_server(
        lambda: SSHServer(allowed_port), "127.0.0.1", port,
        server_host_keys=[key], authorized_client_keys=asyncssh.import_authorized_keys(client_key.export_public_key().decode()),
        allow_pty=False, encoding=None,
    )
