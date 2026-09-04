from __future__ import annotations

from rich.align import Align
from rich.console import Console
from rich.panel import Panel
from rich.text import Text


RECOONGAN_BANNER = r"""
 ____  _____  ____   ___ ====___  _   _   ____      _     _   _
|  _ \| ____|/ ___| /  _ \__/ _ \| \ | | / ___|    / \   | \ | |
| |_) |  _| | |    |  / \ || / \ |  \| || |  _    / _ \  |  \| |
|  _ <| |___| |___ |  \_/ || \_/ | |\  || |_| |  / ___ \ | |\  |
|_| \_\_____|\____| \____/==\___/|_| \_| \____| /_/   \_\|_| \_|
""".strip("\n")


def print_recoongan_banner(
    console: Console,
) -> None:
    """Print the ReConngan terminal banner."""

    if console.width < 90:
        compact = Text()
        compact.append(
            "REC",
            style="bold #b9c5bd",
        )
        compact.append(
            "(O)==(O)",
            style="bold #9fb7aa",
        )
        compact.append(
            "NGAN",
            style="bold #b9c5bd",
        )
        compact.append(
            "\nEvidence-driven HTTP security reconnaissance scanner",
            style="dim #8fa59b",
        )

        console.print(
            Panel.fit(
                compact,
                border_style="#5d2040",
                padding=(1, 2),
            )
        )

        return

    body = Text(
        RECOONGAN_BANNER,
        style="bold #b9c5bd",
    )

    body.append(
        "\nEvidence-driven HTTP security reconnaissance scanner",
        style="dim #8fa59b",
    )

    console.print(
        Panel(
            Align.center(
                body,
            ),
            border_style="#5d2040",
            padding=(1, 2),
        )
    )
