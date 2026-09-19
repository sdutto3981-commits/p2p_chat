"""
Widget Textual che mostra lo storico dei file/media scambiati,
raggruppati per peer, con direzione e percorso su disco.
"""

from textual.widgets import Static


def format_size(num_bytes):
    for unit in ['B', 'KB', 'MB', 'GB']:
        if num_bytes < 1024:
            return f"{num_bytes:.0f}{unit}"
        num_bytes /= 1024
    return f"{num_bytes:.1f}TB"


class TransfersPanel(Static):
    def __init__(self, transfer_log):
        super().__init__()
        self.transfer_log = transfer_log

    def refresh_view(self):
        entries = self.transfer_log.get_all()
        if not entries:
            self.update("[dim](nessun file scambiato ancora)[/dim]")
            return

        by_peer = {}
        for e in entries:
            by_peer.setdefault(e['peer'], []).append(e)

        lines = []
        for peer, items in by_peer.items():
            sent_count = sum(1 for e in items if e['direction'] == 'sent')
            recv_count = sum(1 for e in items if e['direction'] == 'received')
            lines.append(f"[bold yellow]{peer}[/bold yellow] [dim](↑{sent_count} ↓{recv_count})[/dim]")

            for e in sorted(items, key=lambda x: x['timestamp'], reverse=True):
                arrow = "↑" if e['direction'] == 'sent' else "↓"
                color = "green" if e['direction'] == 'sent' else "cyan"
                ts = e['timestamp'].split('T')[1][:8]
                size = format_size(e['filesize'])
                lines.append(f"  [{color}]{arrow}[/{color}] {e['filename']} [dim]({size}, {ts})[/dim]")

            lines.append("")

        lines.append(f"[dim]Totale: {len(entries)} file — ~/P2PChat/[/dim]")
        self.update("\n".join(lines))
