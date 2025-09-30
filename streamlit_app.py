import base64
import configparser
import hashlib
import os
import socket
import select
import sys
import threading
import time
from collections import deque

import streamlit as st
from Crypto.Cipher import AES


APP_TITLE = "NEURON Server v1.2"
DEFAULT_CONF_PATH = os.path.join(os.getcwd(), "neuron.conf")


def compute_key(password: str) -> bytes:
    """Replicate original hasher: md5(sha512(password).hexdigest()).hexdigest() as bytes."""
    sha512_hex = hashlib.sha512(password.encode("utf-8")).hexdigest()
    md5_hex = hashlib.md5(sha512_hex.encode("utf-8")).hexdigest()
    return md5_hex.encode("utf-8")


def _pad_message(message: str, block_size: int = 32, pad_char: str = "{") -> str:
    padding_len = (block_size - (len(message) % block_size)) % block_size
    if padding_len == 0:
        padding_len = block_size
    return message + (pad_char * padding_len)


def encrypt(secret_key: bytes, data: str) -> bytes:
    cipher = AES.new(secret_key, AES.MODE_ECB)
    padded = _pad_message(data)
    ciphertext = cipher.encrypt(padded.encode("utf-8"))
    return base64.b64encode(ciphertext)


def decrypt(secret_key: bytes, data: bytes) -> str:
    cipher = AES.new(secret_key, AES.MODE_ECB)
    decoded = base64.b64decode(data)
    plaintext = cipher.decrypt(decoded).decode("utf-8")
    return plaintext.rstrip("{")


def load_config(conf_path: str = DEFAULT_CONF_PATH):
    config = configparser.ConfigParser()
    read_files = config.read(conf_path)
    if not read_files:
        # Provide safe defaults if config missing
        return "0.0.0.0", 80, "password", False

    host = config.get("config", "HOST", fallback="0.0.0.0")
    port = config.getint("config", "PORT", fallback=80)
    password = config.get("config", "PASSWORD", fallback="password")
    view_flag = config.get("config", "VIEW", fallback="0").strip()
    view = view_flag == "1"
    return host, port, password, view


class NeuronServer(threading.Thread):
    def __init__(
        self,
        host: str,
        port: int,
        password: str,
        view_logs: bool,
        log_sink: deque,
    ) -> None:
        super().__init__(daemon=True)
        self.host = host
        self.port = port
        self.password = password
        self.view_logs = view_logs
        self.log_sink = log_sink
        self.key = compute_key(password)
        self.stop_event = threading.Event()
        self.socket_list = []
        self.recv_buffer = 4096

    def log(self, message: str) -> None:
        timestamp = time.strftime("%H:%M:%S")
        entry = f"[{timestamp}] {message}"
        self.log_sink.append(entry)
        # Cap log size to prevent unbounded memory
        while len(self.log_sink) > 5000:
            self.log_sink.popleft()

    def broadcast(self, server_socket, source_socket, message_bytes: bytes) -> None:
        for sock in list(self.socket_list):
            if sock != server_socket and sock != source_socket:
                try:
                    sock.send(message_bytes)
                except Exception:
                    try:
                        sock.close()
                    except Exception:
                        pass
                    if sock in self.socket_list:
                        self.socket_list.remove(sock)

    def run(self) -> None:
        try:
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server_socket.bind((self.host, self.port))
            server_socket.listen(10)
            self.socket_list.append(server_socket)
            self.log(f"neuron server started on {self.host}:{self.port}")
        except Exception as e:
            self.log(f"Failed to start server: {e}")
            return

        while not self.stop_event.is_set():
            try:
                ready_to_read, _, _ = select.select(self.socket_list, [], [], 0.2)
            except Exception as e:
                self.log(f"select() error: {e}")
                break

            for sock in ready_to_read:
                if sock is server_socket:
                    try:
                        sockfd, addr = server_socket.accept()
                        self.socket_list.append(sockfd)
                        self.log(f"user {addr[0]}:{addr[1]} connected")
                        self.broadcast(
                            server_socket,
                            sockfd,
                            encrypt(self.key, f"[{addr[0]}:{addr[1]}] entered our chatting room\n"),
                        )
                    except Exception as e:
                        self.log(f"accept() error: {e}")
                else:
                    try:
                        data = sock.recv(self.recv_buffer)
                        if data:
                            try:
                                plain = decrypt(self.key, data)
                            except Exception as e:
                                self.log(f"decryption error: {e}")
                                plain = None

                            if plain:
                                self.broadcast(
                                    server_socket,
                                    sock,
                                    encrypt(self.key, "\r" + plain),
                                )
                                if self.view_logs:
                                    self.log(plain.rstrip("\n"))
                        else:
                            if sock in self.socket_list:
                                self.socket_list.remove(sock)
                            try:
                                addr = sock.getpeername()
                            except Exception:
                                addr = ("?", "?")
                            self.broadcast(
                                server_socket,
                                sock,
                                encrypt(self.key, f"user ({addr[0]}, {addr[1]}) is offline\n"),
                            )
                            try:
                                sock.close()
                            except Exception:
                                pass
                    except Exception:
                        try:
                            addr = sock.getpeername()
                        except Exception:
                            addr = ("?", "?")
                        self.broadcast(
                            server_socket,
                            sock,
                            encrypt(self.key, f"user ({addr[0]}, {addr[1]}) is offline\n"),
                        )
                        try:
                            sock.close()
                        except Exception:
                            pass
                        if sock in self.socket_list:
                            self.socket_list.remove(sock)

        try:
            for s in list(self.socket_list):
                try:
                    s.close()
                except Exception:
                    pass
            self.socket_list.clear()
        finally:
            self.log("server stopped")


def ensure_session_state() -> None:
    if "logs" not in st.session_state:
        st.session_state.logs = deque(maxlen=5000)
    if "server" not in st.session_state:
        st.session_state.server = None
    if "config_loaded" not in st.session_state:
        host, port, password, view = load_config(DEFAULT_CONF_PATH)
        st.session_state.host = host
        st.session_state.port = port
        st.session_state.password = password
        st.session_state.view = view
        st.session_state.config_loaded = True


def render_controls() -> None:
    st.subheader("Server Configuration")
    st.text_input("Host", key="host")
    st.number_input("Port", min_value=1, max_value=65535, key="port")
    st.text_input("Password", type="password", key="password")
    st.checkbox("View live chat in UI (VIEW)", key="view")

    col1, col2, col3 = st.columns(3)
    with col1:
        if st.session_state.server is None or not st.session_state.server.is_alive():
            if st.button("Start Server", use_container_width=True):
                server = NeuronServer(
                    host=str(st.session_state.host),
                    port=int(st.session_state.port),
                    password=str(st.session_state.password),
                    view_logs=bool(st.session_state.view),
                    log_sink=st.session_state.logs,
                )
                st.session_state.server = server
                server.start()
                time.sleep(0.1)
        else:
            st.button("Start Server", use_container_width=True, disabled=True)

    with col2:
        if st.session_state.server is not None and st.session_state.server.is_alive():
            if st.button("Stop Server", type="secondary", use_container_width=True):
                st.session_state.server.stop_event.set()
                st.session_state.server.join(timeout=1.0)
                if st.session_state.server.is_alive():
                    # Leave the thread to finish closing sockets; it will stop soon
                    pass
                st.session_state.server = None
        else:
            st.button("Stop Server", use_container_width=True, disabled=True)

    with col3:
        if st.button("Clear Logs", use_container_width=True):
            st.session_state.logs.clear()

    st.divider()


def render_status() -> None:
    server = st.session_state.server
    if server is not None and server.is_alive():
        st.success(f"Running on {server.host}:{server.port}")
    else:
        st.info("Server is stopped")


def render_logs() -> None:
    st.subheader("Live Logs")
    logs_text = "\n".join(st.session_state.logs)
    st.text_area(
        label="",
        value=logs_text,
        height=400,
        key="logs_view",
    )
    st.caption("Click any button to refresh. Logs retain last 5000 entries.")


def main() -> None:
    st.set_page_config(page_title=APP_TITLE, page_icon="🧠", layout="wide")
    st.title(APP_TITLE)
    st.caption("Encrypted TCP chat server with Streamlit controls")

    ensure_session_state()
    render_controls()
    render_status()
    render_logs()


if __name__ == "__main__":
    main()

