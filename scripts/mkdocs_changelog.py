"""Copy CHANGELOG.md into the MkDocs tree and point its edit link at the source."""

from __future__ import annotations

from pathlib import Path


def on_pre_build(config) -> None:
    """Write docs/changelog.md from CHANGELOG.md when the text changed."""
    root = Path(config.config_file_path).resolve().parent
    source = root / "CHANGELOG.md"
    dest = Path(config.docs_dir) / "changelog.md"
    text = source.read_text()
    if dest.is_file() and dest.read_text() == text:
        return
    dest.write_text(text)


def on_nav(nav, config, files):
    """Link the static dashboard without rendering it as a Markdown page."""
    from mkdocs.structure.nav import Link

    link = Link("Dashboard", "dashboard.html")
    items = nav.items
    for index, item in enumerate(items):
        file = getattr(item, "file", None)
        if file is not None and file.src_path == "developer-guide.md":
            items.insert(index, link)
            return nav
    items.append(link)
    return nav


def on_page_context(context, page, config, nav):
    """Send the changelog edit button to CHANGELOG.md in the repository."""
    if page.file.src_path == "changelog.md":
        page.edit_url = (
            "https://github.com/mrjoshuap/ansible-ezcve/edit/main/CHANGELOG.md"
        )
    return context
