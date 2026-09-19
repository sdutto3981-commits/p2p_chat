"""
Applicazione Textual: layout a tre colonne (grafo | chat | log),
input testuale per comandi (send, sendfile, peers).
"""

import os
import threading

from textual.app import App, ComposeResult
from textual.containers import Horizontal, Vertical
from textual.widgets import Header, Footer, Static, Input, RichLog

from peer_node import PeerNode
from ui.graph_panel import GraphPanel


LOG_COLOR_MAP = {
    "debug": "dim",
    "info": "white",
    "warning": "yellow",
    "error": "red",
    "critical": "bold red",
}


class P2PApp(App):
    CSS = """
    Screen {
        layout: horizontal;
    }
    #graph_sidebar {
        width: 30%;
        border: solid green;
        padding: 1;
    }
    #main_area {
        width: 40%;
    }
    #log_sidebar {
        width: 30%;
        border: solid blue;
    }
    #chat_log {
        height: 1fr;
        border: solid white;
    }
    #input_box {
        dock: bottom;
    }
    """

    BINDINGS = [("q", "quit", "Esci")]

    def __init__(self, hostname):
        super().__init__()
        self.hostname = hostname
        self.node = PeerNode(
            hostname,
            on_peer_update=self._handle_peer_update,
            on_message=self._handle_message,
            on_log=self._handle_log,
        )

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        self.graph_panel = GraphPanel(self.hostname)

        with Horizontal():
            with Vertical(id="graph_sidebar"):
                yield Static("[bold]RETE — nodi attivi[/bold]")
                yield self.graph_panel

            with Vertical(id="main_area"):
                self.chat_log = RichLog(id="chat_log", wrap=True, markup=True)
                yield self.chat_log
                self.input_box = Input(
                    placeholder="send <host> <msg>  |  sendfile <host> <path>  |  peers",
                    id="input_box"
                )
                yield self.input_box

            with Vertical(id="log_sidebar"):
                yield Static("[bold]LOG DI SISTEMA[/bold]")
                self.log_panel = RichLog(id="log_panel", wrap=True, markup=True, max_lines=300)
                yield self.log_panel

        yield Footer()

    def on_mount(self):
        self.chat_log.write(f"[bold]Nodo '{self.hostname}' avviato.[/bold]")
        self.chat_log.write(f"[dim]Log su file: {self.node.log_filepath}[/dim]")
        self.node.start()
        self.input_box.focus()

    # ---- callback dal thread di rete verso la UI ----

    def _handle_peer_update(self, peers_snapshot):
        self.call_from_thread(self.graph_panel.update_peers, peers_snapshot)

    def _handle_message(self, sender, text):
        self.call_from_thread(self.chat_log.write, f"[bold cyan]{sender}[/bold cyan]: {text}")

    def _handle_log(self, level, msg):
        color = LOG_COLOR_MAP.get(level, "white")
        from datetime import datetime
        ts = datetime.now().strftime("%H:%M:%S")
        self.call_from_thread(
            self.log_panel.write, f"[{color}]{ts} {level.upper():8} {msg}[/{color}]"
        )

    # ---- input utente ----

    def on_input_submitted(self, event: Input.Submitted):
        cmd = event.value.strip()
        self.input_box.value = ""

        if cmd == "peers":
            hosts = list(self.node.get_peers_snapshot().keys())
            self.chat_log.write(f"[dim]Peer conosciuti: {hosts}[/dim]")

        elif cmd.startswith("sendfile "):
            parts = cmd.split(" ", 2)
            if len(parts) < 3:
                self.chat_log.write("[red]Uso: sendfile <hostname> <percorso_file>[/red]")
                return
            _, target, filepath = parts
            filepath = filepath.strip().strip('"').strip("'")
            self.chat_log.write(f"[bold magenta]io -> {target}[/bold magenta]: [file] {os.path.basename(filepath)}")
            threading.Thread(target=self._sendfile_async, args=(target, filepath), daemon=True).start()

        elif cmd.startswith("send "):
            parts = cmd.split(" ", 2)
            if len(parts) < 3:
                self.chat_log.write("[red]Uso: send <hostname> <messaggio>[/red]")
                return
            _, target, msg = parts
            self.chat_log.write(f"[bold magenta]io -> {target}[/bold magenta]: {msg}")
            threading.Thread(target=self._sendmsg_async, args=(target, msg), daemon=True).start()

        elif cmd:
            self.chat_log.write(f"[red]Comando non riconosciuto: {cmd}[/red]")

    def _sendmsg_async(self, target, msg):
        ok, err = self.node.send_message(target, msg)
        if not ok:
            self.call_from_thread(self.chat_log.write, f"[red]Errore invio a {target}: {err}[/red]")

    def _sendfile_async(self, target, filepath):
        ok, err = self.node.send_file(target, filepath)
        if not ok:
            self.call_from_thread(self.chat_log.write, f"[red]Errore invio file a {target}: {err}[/red]")
