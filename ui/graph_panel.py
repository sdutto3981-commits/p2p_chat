"""
Widget Textual con rappresentazione a grafo (box-drawing Unicode).
Si aggiorna sia in aggiunta che in rimozione (lifecycle completo).
"""

from datetime import datetime
from textual.widgets import Static


class GraphPanel(Static):
    def __init__(self, hostname):
        super().__init__()
        self.hostname = hostname
        self.peers = {}

    def update_peers(self, peers_snapshot):
        now = datetime.now().strftime("%H:%M:%S")
        for host, (ip, _last_seen) in peers_snapshot.items():
            if host not in self.peers:
                self.peers[host] = (ip, now)
            else:
                self.peers[host] = (ip, self.peers[host][1])
        for host in list(self.peers.keys()):
            if host not in peers_snapshot:
                del self.peers[host]
        self._refresh_view()

    def _refresh_view(self):
        lines = []
        lines.append("        [bold red]┌─────────────┐[/bold red]")
        lines.append(f"        [bold red]│ ● {self.hostname[:9]:<9} │[/bold red]  [dim](io)[/dim]")
        lines.append("        [bold red]└──────┬──────┘[/bold red]")

        if not self.peers:
            lines.append("               [dim]│[/dim]")
            lines.append("               [dim](nessun peer)[/dim]")
        else:
            items = list(self.peers.items())
            for i, (host, (ip, seen)) in enumerate(items):
                is_last = (i == len(items) - 1)
                branch = "└──" if is_last else "├──"
                vbar = "   " if is_last else "│  "
                lines.append(f"               {branch}[bold green]● {host}[/bold green]")
                lines.append(f"               {vbar}  [dim]{ip} · dal {seen}[/dim]")

        lines.append("")
        lines.append(f"[dim]Nodi connessi: {len(self.peers)}[/dim]")
        self.update("\n".join(lines))
