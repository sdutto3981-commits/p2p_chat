"""
Widget Textual che rappresenta testualmente lo stato della rete:
nodo locale al centro, peer conosciuti sotto con IP e orario di scoperta.
Si aggiorna sia in aggiunta che in rimozione (lifecycle completo).
"""

from datetime import datetime
from textual.widgets import Static


class GraphPanel(Static):
    def __init__(self, hostname):
        super().__init__()
        self.hostname = hostname
        self.peers = {}  # hostname -> (ip, discovered_at_str)

    def update_peers(self, peers_snapshot):
        """
        peers_snapshot: dict hostname -> (ip, last_seen_timestamp)
        proveniente da PeerNode.get_peers_snapshot()
        """
        now = datetime.now().strftime("%H:%M:%S")

        for host, (ip, _last_seen) in peers_snapshot.items():
            if host not in self.peers:
                self.peers[host] = (ip, now)
            else:
                self.peers[host] = (ip, self.peers[host][1])  # mantieni orario di prima scoperta

        for host in list(self.peers.keys()):
            if host not in peers_snapshot:
                del self.peers[host]

        self._refresh_view()

    def _refresh_view(self):
        lines = [f"[bold red]● {self.hostname}[/bold red] (io)", ""]
        if not self.peers:
            lines.append("[dim](nessun peer ancora scoperto...)[/dim]")
        else:
            for host, (ip, seen) in self.peers.items():
                lines.append("  │")
                lines.append(f"  ├── [bold green]● {host}[/bold green]")
                lines.append(f"  │     [dim]{ip}[/dim]")
                lines.append(f"  │     [dim]scoperto {seen}[/dim]")
        lines.append("")
        lines.append(f"[dim]Totale peer: {len(self.peers)}[/dim]")
        self.update("\n".join(lines))
