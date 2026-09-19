"""
Applicazione Textual: layout a quattro colonne (grafo | chat | file | log),
input testuale per comandi (send, sendfile, history, peers).
"""

import os
import threading
from datetime import datetime

from textual.app import App, ComposeResult
from textual.containers import Horizontal, Vertical
from textual.widgets import Header, Footer, Static, Input, RichLog

from peer_node import PeerNode
from ui.graph_panel import GraphPanel
from ui.transfers_panel import TransfersPanel

try:
    from plyer import notification
    _NOTIFICATIONS_AVAILABLE = True
except ImportError:
    _NOTIFICATIONS_AVAILABLE = False


LOG_COLOR_MAP = {
    "debug": "dim",
    "info": "white",
    "warning": "yellow",
    "error": "red",
    "critical": "bold red",
}


def _desktop_notify(title, message):
    if not _NOTIFICATIONS_AVAILABLE:
        return
    try:
        notification.notify(title=title, message=message, timeout=4)
    except Exception:
        pass


class P2PApp(App):
    CSS = """
    Screen {
        layout: horizontal;
    }
    #graph_sidebar {
        width: 25%;
        border: solid green;
        padding: 1;
    }
    #main_area {
        width: 30%;
    }
    #transfers_sidebar {
        width: 25%;
        border: solid yellow;
        padding: 1;
    }
    #log_sidebar {
        width: 20%;
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
        self.transfers_panel = TransfersPanel(self.node.transfer_log)

        with Horizontal():
            with Vertical(id="graph_sidebar"):
                yield Static("[bold]RETE — nodi attivi[/bold]")
                yield self.graph_panel

            with Vertical(id="main_area"):
                self.chat_log = RichLog(id="chat_log", wrap=True, markup=True)
                yield self.chat_log
                self.input_box = Input(
                    placeholder="send <host> <msg> | sendfile <host> <path> | history <host> | peers",
                    id="input_box"
                )
                yield self.input_box

            with Vertical(id="transfers_sidebar"):
                yield Static("[bold]FILE SCAMBIATI[/bold]")
                yield self.transfers_panel

            with Vertical(id="log_sidebar"):
                yield Static("[bold]LOG[/bold]")
                self.log_panel = RichLog(id="log_panel", wrap=True, markup=True, max_lines=300)
                yield self.log_panel

        yield Footer()

    def on_mount(self):
        self.chat_log.write(f"[bold]Nodo '{self.hostname}' avviato.[/bold]")
        self.chat_log.write(f"[dim]Log su file: {self.node.log_filepath}[/dim]")
        self.transfers_panel.refresh_view()
        self.node.start()
        self.input_box.focus()

    def action_quit(self):
        # announce_goodbye chiama internamente self.log() -> on_log() -> call_from_thread(),
        # che è valido solo se chiamato da un thread diverso da quello dell'app.
        # action_quit gira nel thread principale, quindi va eseguito in un thread separato.
        import threading
        t = threading.Thread(target=self.node.announce_goodbye, daemon=True)
        t.start()
        t.join(timeout=1.0)  # aspetta al massimo 1 secondo che il broadcast parta, poi esce comunque
        self.exit()

    # ---- callback dal thread di rete verso la UI ----

    def _handle_peer_update(self, peers_snapshot):
        self.call_from_thread(self.graph_panel.update_peers, peers_snapshot)

    def _handle_message(self, sender, text):
        self.call_from_thread(self.chat_log.write, f"[bold cyan]{sender}[/bold cyan]: {text}")
        _desktop_notify(f"Messaggio da {sender}", text[:100])
        if text.startswith("[FILE]"):
            self.call_from_thread(self.transfers_panel.refresh_view)

    def _handle_log(self, level, msg):
        color = LOG_COLOR_MAP.get(level, "white")
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

        elif cmd.startswith("history "):
            target = cmd.split(" ", 1)[1].strip()
            msgs = self.node.message_log.get_by_peer(target)
            files = self.node.transfer_log.get_by_peer(target)
            self.chat_log.write(f"\n[bold]--- Cronologia con {target} ---[/bold]")
            combined = [('msg', m) for m in msgs] + [('file', f) for f in files]
            combined.sort(key=lambda x: x[1]['timestamp'])
            for kind, e in combined:
                ts = e['timestamp'].split('T')[1][:8]
                if kind == 'msg':
                    arrow = "→" if e['direction'] == 'sent' else "←"
                    self.chat_log.write(f"  [dim]{ts}[/dim] {arrow} {e['text']}")
                else:
                    arrow = "↑" if e['direction'] == 'sent' else "↓"
                    self.chat_log.write(f"  [dim]{ts}[/dim] {arrow} [FILE] {e['filename']}")
            self.chat_log.write("[bold]--- fine cronologia ---[/bold]\n")

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
        def progress_cb(sent, total):
            pct = int(sent / total * 100)
            self.call_from_thread(self._update_progress_line, target, pct)

        ok, err = self.node.send_file(target, filepath, on_progress=progress_cb)
        if not ok:
            self.call_from_thread(self.chat_log.write, f"[red]Errore invio file a {target}: {err}[/red]")
        else:
            self.call_from_thread(self.chat_log.write, f"[green]✓ Invio completato a {target}[/green]")
            self.call_from_thread(self.transfers_panel.refresh_view)

    def _update_progress_line(self, target, pct):
        bar_len = 20
        filled = int(bar_len * pct / 100)
        bar = "█" * filled + "░" * (bar_len - filled)
        self.log_panel.write(f"[cyan]Invio a {target}: [{bar}] {pct}%[/cyan]")
