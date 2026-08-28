# -*- coding: utf-8 -*-
# Wordlist Hub v1.5 - Burp Suite Jython Extension
#
# V1.1  SecLists live catalog + GitHub RAW download + local cache
# V1.2  Search + categories
# V1.3  Custom RAW URL wordlists
# V1.4  Favorites + Recent
# V1.5  Update/Delete cache + storage usage + offline cached lists
#
# Target: Burp legacy Extender API + Jython 2.7.x

from burp import IBurpExtender, ITab, IIntruderPayloadGeneratorFactory, IIntruderPayloadGenerator

from java.awt import BorderLayout, Dimension, FlowLayout
from java.awt.event import MouseAdapter
from javax.swing import (JPanel, JSplitPane, JList, JScrollPane, JTextArea, JButton,
                         JLabel, DefaultListModel, ListSelectionModel, JTextField,
                         JComboBox, JOptionPane, JTabbedPane, JCheckBox, JProgressBar,
                         SwingWorker, BoxLayout, JTree, JTable, ListSelectionModel,
                         DefaultListCellRenderer)
from javax.swing.border import EmptyBorder
from javax.swing.tree import (DefaultMutableTreeNode, DefaultTreeModel,
                              TreeSelectionModel, DefaultTreeCellRenderer)
from javax.swing.table import DefaultTableModel
from javax.swing.event import DocumentListener

import os
import json
import time
import hashlib
import codecs
import urllib2
import urlparse


APP = "Wordlist Hub"
VERSION = "2.5"

GITHUB_API_TREE = "https://api.github.com/repos/danielmiessler/SecLists/git/trees/master?recursive=1"
RAW_BASE = "https://raw.githubusercontent.com/danielmiessler/SecLists/master/"

# Avoid obviously non-wordlist repository artifacts in the browser.
ALLOWED_EXTENSIONS = (".txt", ".lst", ".dic", ".csv", ".json", ".xml", ".fuzz", ".payloads")
SKIP_PREFIXES = (".git", ".github/", ".bin/")


def ensure_dir(path):
    if not os.path.isdir(path):
        os.makedirs(path)


def safe_unicode(value):
    try:
        if isinstance(value, unicode):
            return value
        return unicode(value, "utf-8", "replace")
    except:
        return unicode(str(value), "utf-8", "replace")


class BurpExtender(IBurpExtender, ITab, IIntruderPayloadGeneratorFactory):

    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()
        callbacks.setExtensionName("%s v%s" % (APP, VERSION))

        self.home = os.path.join(os.path.expanduser("~"), ".wordlist-hub")
        self.cache_dir = os.path.join(self.home, "cache")
        self.catalog_file = os.path.join(self.home, "seclists_catalog.json")
        self.settings_file = os.path.join(self.home, "settings.json")
        ensure_dir(self.home)
        ensure_dir(self.cache_dir)

        self.settings = {
            "favorites": [],
            "recent": [],
            "custom": []
        }
        self.catalog = []
        self.filtered = []
        self.active_entry = None
        self.active_payloads = []

        self._load_settings()
        self._load_catalog()
        self._build_ui()

        callbacks.addSuiteTab(self)
        callbacks.registerIntruderPayloadGeneratorFactory(self)

        self._log("Loaded v%s. Cache: %s" % (VERSION, self.cache_dir))
        self._refresh_all()

    # ---------- Burp integration ----------

    def getTabCaption(self):
        return "Wordlist Hub"

    def getUiComponent(self):
        return self.main_panel

    def getGeneratorName(self):
        return "Wordlist Hub"

    def createNewInstance(self, attack):
        if self.active_entry:
            path = self._cache_path(self.active_entry)
            if os.path.isfile(path):
                return StreamingWordlistPayloadGenerator(path)
        return WordlistHubPayloadGenerator(["WORDLIST_HUB_NO_WORDLIST_SELECTED"])

    # ---------- Persistence ----------

    def _load_settings(self):
        try:
            if os.path.isfile(self.settings_file):
                fh = open(self.settings_file, "rb")
                data = json.loads(fh.read().decode("utf-8"))
                fh.close()
                for k in self.settings:
                    if k in data:
                        self.settings[k] = data[k]
        except Exception as e:
            self._log("Settings load error: %s" % e)

    def _save_settings(self):
        try:
            fh = open(self.settings_file, "wb")
            fh.write(json.dumps(self.settings, indent=2).encode("utf-8"))
            fh.close()
        except Exception as e:
            self._log("Settings save error: %s" % e)

    def _load_catalog(self):
        try:
            if os.path.isfile(self.catalog_file):
                fh = open(self.catalog_file, "rb")
                data = json.loads(fh.read().decode("utf-8"))
                fh.close()
                self.catalog = data.get("entries", [])
        except Exception as e:
            self._log("Catalog load error: %s" % e)
            self.catalog = []

    def _save_catalog(self):
        try:
            data = {"updated": int(time.time()), "entries": self.catalog}
            fh = open(self.catalog_file, "wb")
            fh.write(json.dumps(data).encode("utf-8"))
            fh.close()
        except Exception as e:
            self._log("Catalog save error: %s" % e)

    # ---------- UI ----------

    def _build_ui(self):
        self.main_panel = JPanel(BorderLayout())
        self.main_panel.setBorder(EmptyBorder(8, 8, 8, 8))

        top = JPanel(BorderLayout())
        title = JLabel("Wordlist Hub v%s" % VERSION)
        top.add(title, BorderLayout.WEST)

        self.storage_label = JLabel("")
        top.add(self.storage_label, BorderLayout.EAST)
        self.main_panel.add(top, BorderLayout.NORTH)

        self.tabs = JTabbedPane()
        self.tabs.addTab("Browse", self._build_browse_tab())
        self.tabs.addTab("Sources", self._build_custom_tab())
        self.tabs.addTab("Manage", self._build_manage_tab())
        self.main_panel.add(self.tabs, BorderLayout.CENTER)

        self.status = JLabel("Ready")
        self.main_panel.add(self.status, BorderLayout.SOUTH)

    def _build_browse_tab(self):
        panel = JPanel(BorderLayout())

        filters = JPanel(FlowLayout(FlowLayout.LEFT))
        filters.add(JLabel("Search:"))
        self.search_field = JTextField(24)
        self.search_field.addActionListener(lambda e: self._apply_filters())
        self.search_field.getDocument().addDocumentListener(SearchDocumentListener(self))
        filters.add(self.search_field)

        filters.add(JLabel("Category:"))
        self.category_combo = JComboBox(["All"])
        self.category_combo.addActionListener(lambda e: self._apply_filters())
        filters.add(self.category_combo)

        refresh_btn = JButton("Refresh SecLists Catalog", actionPerformed=lambda e: self._refresh_catalog_async())
        filters.add(refresh_btn)

        self.cached_only = JCheckBox("Cached only")
        self.cached_only.addActionListener(lambda e: self._apply_filters())
        filters.add(self.cached_only)

        panel.add(filters, BorderLayout.NORTH)

        # Tree browser
        self.tree_root = DefaultMutableTreeNode("Wordlists")
        self.tree_model = DefaultTreeModel(self.tree_root)
        self.wordlist_tree = JTree(self.tree_model)
        self.wordlist_tree.setCellRenderer(WordlistTreeCellRenderer())
        self.wordlist_tree.getSelectionModel().setSelectionMode(TreeSelectionModel.SINGLE_TREE_SELECTION)
        self.wordlist_tree.addTreeSelectionListener(lambda e: self._on_tree_selection())
        left = JScrollPane(self.wordlist_tree)
        left.setPreferredSize(Dimension(440, 520))

        right = JPanel(BorderLayout())
        self.preview = JTextArea()
        self.preview.setEditable(False)
        self.preview.setLineWrap(False)
        right.add(JScrollPane(self.preview), BorderLayout.CENTER)

        actions = JPanel(FlowLayout(FlowLayout.LEFT))
        self.download_btn = JButton("Download", actionPerformed=lambda e: self._download_selected(False))
        self.intruder_btn = JButton("Set as Intruder Wordlist", actionPerformed=lambda e: self._activate_selected())
        self.favorite_btn = JButton("Favorite", actionPerformed=lambda e: self._toggle_favorite())
        self.update_btn = JButton("Update", actionPerformed=lambda e: self._download_selected(True))
        self.delete_btn = JButton("Delete Cache", actionPerformed=lambda e: self._delete_selected_cache())
        for b in [self.download_btn, self.intruder_btn, self.favorite_btn, self.update_btn, self.delete_btn]:
            actions.add(b)
        right.add(actions, BorderLayout.SOUTH)

        split = JSplitPane(JSplitPane.HORIZONTAL_SPLIT, left, right)
        split.setResizeWeight(0.35)
        panel.add(split, BorderLayout.CENTER)
        return panel

    def _build_custom_tab(self):
        panel = JPanel()
        panel.setLayout(BoxLayout(panel, BoxLayout.Y_AXIS))

        row1 = JPanel(FlowLayout(FlowLayout.LEFT))
        row1.add(JLabel("Name:"))
        self.custom_name = JTextField(25)
        row1.add(self.custom_name)
        panel.add(row1)

        row2 = JPanel(FlowLayout(FlowLayout.LEFT))
        row2.add(JLabel("GitHub / RAW URL:"))
        self.custom_url = JTextField(60)
        row2.add(self.custom_url)
        panel.add(row2)

        row3 = JPanel(FlowLayout(FlowLayout.LEFT))
        row3.add(JLabel("Category:"))
        self.custom_category = JTextField("Custom", 20)
        row3.add(self.custom_category)
        row3.add(JButton("+ Add Source", actionPerformed=lambda e: self._add_custom()))
        panel.add(row3)

        note = JTextArea(
            "Paste a GitHub repository, directory, file URL, or a direct RAW/text URL.\n"
            "GitHub repository/directory URLs are expanded automatically; GitHub blob files are converted to RAW automatically."
        )
        note.setEditable(False)
        note.setOpaque(False)
        panel.add(note)
        return panel

    def _build_manage_tab(self):
        panel = JPanel(BorderLayout())

        self.cache_table_model = DefaultTableModel(
            ["Source", "Wordlist", "Category", "Entries", "Size", "Local Path"], 0
        )
        self.cache_table = JTable(self.cache_table_model)
        self.cache_table.setAutoCreateRowSorter(True)
        panel.add(JScrollPane(self.cache_table), BorderLayout.CENTER)

        buttons = JPanel(FlowLayout(FlowLayout.LEFT))
        buttons.add(JButton("Favorites in Browse", actionPerformed=lambda e: self._browse_special("favorites")))
        buttons.add(JButton("Recent in Browse", actionPerformed=lambda e: self._browse_special("recent")))
        buttons.add(JButton("Delete Selected Cache", actionPerformed=lambda e: self._delete_manage_selected()))
        buttons.add(JButton("Clear All Cache", actionPerformed=lambda e: self._clear_all_cache()))
        buttons.add(JButton("Open Cache Folder", actionPerformed=lambda e: self._open_cache_folder()))
        buttons.add(JButton("Refresh", actionPerformed=lambda e: self._refresh_manage_table()))
        panel.add(buttons, BorderLayout.SOUTH)
        return panel

    # ---------- Catalog ----------

    def _refresh_catalog_async(self):
        self.status.setText("Fetching SecLists catalog from GitHub...")
        worker = CatalogWorker(self)
        worker.execute()

    def _catalog_finished(self, entries, error):
        if error:
            self.status.setText("Catalog refresh failed: %s" % error)
            JOptionPane.showMessageDialog(self.main_panel,
                "Could not refresh SecLists catalog.\n\n%s\n\nExisting local catalog is still available." % error,
                APP, JOptionPane.WARNING_MESSAGE)
            return

        self.catalog = entries
        self._save_catalog()
        self.status.setText("SecLists catalog updated: %d wordlists" % len(entries))
        self._refresh_all()

    def _all_entries(self):
        result = list(self.catalog)
        for c in self.settings.get("custom", []):
            entry = dict(c)
            entry["source"] = "Custom"
            result.append(entry)
        return result

    def _refresh_all(self):
        self._refresh_categories()
        self._apply_filters()
        self._update_storage_label()

    def _refresh_categories(self):
        current = self.category_combo.getSelectedItem() if hasattr(self, "category_combo") else "All"
        cats = set()
        for e in self._all_entries():
            cats.add(e.get("category", "Other"))
        self.category_combo.removeAllItems()
        self.category_combo.addItem("All")
        for c in sorted(cats):
            self.category_combo.addItem(c)
        self.category_combo.setSelectedItem(current if current in cats or current == "All" else "All")

    def _apply_filters(self):
        query = safe_unicode(self.search_field.getText()).strip().lower()
        category = self.category_combo.getSelectedItem()
        cached_only = self.cached_only.isSelected()

        self.filtered = []
        for e in self._all_entries():
            if category and category != "All" and e.get("category") != category:
                continue
            hay = (e.get("name", "") + " " + e.get("path", "") + " " +
                   e.get("category", "") + " " + e.get("source_name", "")).lower()
            if query and query not in hay:
                continue
            if cached_only and not os.path.isfile(self._cache_path(e)):
                continue
            self.filtered.append(e)

        self.filtered.sort(key=lambda x: (
            x.get("source", ""), x.get("category", ""), x.get("path", x.get("name", ""))
        ))
        self._build_tree(self.filtered)
        self.status.setText("%d wordlists shown" % len(self.filtered))
        self.preview.setText("Select a wordlist to preview its details.")
        self._refresh_manage_table()

    def _build_tree(self, entries):
        root = DefaultMutableTreeNode("Wordlists (%d)" % len(entries))
        node_map = {}
        favs = set(self.settings.get("favorites", []))
        by_id = dict((self._entry_id(e), e) for e in entries)

        fav_node = DefaultMutableTreeNode("Favorites")
        for eid in self.settings.get("favorites", []):
            e = by_id.get(eid)
            if e:
                fav_node.add(DefaultMutableTreeNode(WordlistTreeItem(u"★ " + e.get("name", ""), e)))
        if fav_node.getChildCount() > 0:
            root.add(fav_node)

        recent_node = DefaultMutableTreeNode("Recent")
        for eid in self.settings.get("recent", [])[:20]:
            e = by_id.get(eid)
            if e:
                recent_node.add(DefaultMutableTreeNode(WordlistTreeItem(e.get("name", ""), e)))
        if recent_node.getChildCount() > 0:
            root.add(recent_node)

        for e in entries:
            source = e.get("source_name") or e.get("source", "Other")
            category = e.get("category", "Other")
            path = e.get("path", e.get("name", ""))
            # For SecLists category is already first path component; avoid repeating it.
            parts = [x for x in path.replace("\\\\", "/").split("/") if x]
            if parts and parts[0] == category:
                parts = parts[1:]
            if not parts:
                parts = [e.get("name", "wordlist")]

            parent = root
            hierarchy = [source, category] + parts[:-1]
            key = ""
            for part in hierarchy:
                key += "/" + part
                if key not in node_map:
                    n = DefaultMutableTreeNode(part)
                    parent.add(n)
                    node_map[key] = n
                parent = node_map[key]

            label = e.get("name", parts[-1])
            if self._entry_id(e) in favs:
                label = u"\u2605 " + label
            if os.path.isfile(self._cache_path(e)):
                label += " [cached]"
            leaf = DefaultMutableTreeNode(WordlistTreeItem(label, e))
            parent.add(leaf)

        self.tree_root = root
        self.tree_model.setRoot(root)
        self.tree_model.reload()

        # Search results should be immediately visible.
        if safe_unicode(self.search_field.getText()).strip():
            for row in range(min(self.wordlist_tree.getRowCount(), 200)):
                self.wordlist_tree.expandRow(row)

    def _selected_entry(self):
        path = self.wordlist_tree.getSelectionPath()
        if path is None:
            return None
        node = path.getLastPathComponent()
        obj = node.getUserObject()
        if isinstance(obj, WordlistTreeItem):
            return obj.entry
        return None

    def _on_tree_selection(self):
        e = self._selected_entry()
        if e:
            self._render_preview(e)

    # ---------- Selection / preview ----------

    def _render_preview(self, e):
        path = self._cache_path(e)
        size = os.path.getsize(path) if os.path.isfile(path) else e.get("size", 0)
        entry_count = self._count_entries(path) if os.path.isfile(path) else None
        lines = [
            "Name: %s" % e.get("name", ""),
            "Source: %s" % (e.get("source_name") or e.get("source", "SecLists")),
            "Category: %s" % e.get("category", "Other"),
            "Repository path: %s" % e.get("path", ""),
            "Size: %s" % self._human_size(size or 0),
            "Entries: %s" % (str(entry_count) if entry_count is not None else "Download to calculate"),
            "Cached: %s" % ("Yes" if os.path.isfile(path) else "No"),
            "Remote URL: %s" % self._entry_url(e),
            "Local path: %s" % path,
            "Cached modified: %s" % (time.ctime(os.path.getmtime(path)) if os.path.isfile(path) else "N/A"),
            "",
            "Preview",
            "-" * 70
        ]
        if os.path.isfile(path):
            try:
                fh = open(path, "rb")
                count = 0
                for raw in fh:
                    if count >= 60:
                        lines.append("...")
                        break
                    lines.append(raw.decode("utf-8", "replace").rstrip("\r\n"))
                    count += 1
                fh.close()
            except Exception as ex:
                lines.append("Preview error: %s" % ex)
        else:
            lines.append("Not downloaded yet. Click Download or Set as Intruder Wordlist.")
        self.preview.setText("\n".join(lines))
        self.preview.setCaretPosition(0)

        isfav = self._entry_id(e) in self.settings.get("favorites", [])
        self.favorite_btn.setText("Unfavorite" if isfav else "Favorite")

    # ---------- Download / cache ----------

    def _cache_path(self, e):
        source = e.get("source", "SecLists")
        if source == "Custom":
            digest = hashlib.sha1(e.get("url", "").encode("utf-8")).hexdigest()
            filename = self._safe_filename(e.get("name", "custom")) + "-" + digest[:10] + ".txt"
            return os.path.join(self.cache_dir, "custom", filename)

        rel = e.get("path", e.get("name", "wordlist.txt")).replace("/", os.sep)
        return os.path.join(self.cache_dir, "seclists", rel)

    def _safe_filename(self, name):
        allowed = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_."
        return "".join([c if c in allowed else "_" for c in name])

    def _entry_url(self, e):
        if e.get("source") == "Custom":
            url = e.get("url", "")
            # Convert normal GitHub file URLs to RAW automatically.
            # Directory/repository URLs are expanded into catalog entries when added.
            try:
                p = urlparse.urlparse(url)
                if p.netloc.lower() == "github.com":
                    parts = [x for x in p.path.split("/") if x]
                    if len(parts) >= 5 and parts[2] == "blob":
                        owner, repo, branch = parts[0], parts[1], parts[3]
                        rel = "/".join(parts[4:])
                        return "https://raw.githubusercontent.com/%s/%s/%s/%s" % (
                            owner, repo, branch, rel
                        )
            except:
                pass
            return url
        return RAW_BASE + e.get("path", "")

    def _download_selected(self, force):
        e = self._selected_entry()
        if not e:
            return
        self._download_entry_async(e, force, False)

    def _download_entry_async(self, e, force, activate_after):
        dest = self._cache_path(e)
        if os.path.isfile(dest) and not force:
            self.status.setText("Using cached wordlist: %s" % e.get("name"))
            if activate_after:
                self._activate_from_cache(e)
            else:
                self._render_preview(e)
            return
        self.status.setText("Downloading %s..." % e.get("name"))
        DownloadWorker(self, e, force, activate_after).execute()

    def _download_finished(self, e, error, activate_after):
        if error:
            self.status.setText("Download failed")
            JOptionPane.showMessageDialog(self.main_panel, "Download failed:\n%s" % error,
                                          APP, JOptionPane.ERROR_MESSAGE)
            return
        self.status.setText("Downloaded: %s" % e.get("name"))
        self._touch_recent(e)
        self._update_storage_label()
        self._apply_filters()
        if activate_after:
            self._activate_from_cache(e)
        else:
            # Filtering rebuilds the list; show a simple success message.
            JOptionPane.showMessageDialog(self.main_panel, "Wordlist cached successfully.",
                                          APP, JOptionPane.INFORMATION_MESSAGE)

    def _delete_selected_cache(self):
        e = self._selected_entry()
        if not e:
            return
        p = self._cache_path(e)
        if os.path.isfile(p):
            try:
                os.remove(p)
                self.status.setText("Deleted cached copy: %s" % e.get("name"))
            except Exception as ex:
                JOptionPane.showMessageDialog(self.main_panel, str(ex), APP, JOptionPane.ERROR_MESSAGE)
        self._refresh_all()

    def _clear_all_cache(self):
        answer = JOptionPane.showConfirmDialog(
            self.main_panel,
            "Delete all downloaded Wordlist Hub wordlists?",
            APP,
            JOptionPane.YES_NO_OPTION
        )
        if answer != JOptionPane.YES_OPTION:
            return
        for root, dirs, files in os.walk(self.cache_dir, topdown=False):
            for f in files:
                try:
                    os.remove(os.path.join(root, f))
                except:
                    pass
            for d in dirs:
                try:
                    os.rmdir(os.path.join(root, d))
                except:
                    pass
        self.active_entry = None
        self.active_payloads = []
        self._refresh_all()
        self.status.setText("All cached wordlists cleared.")

    # ---------- Intruder ----------

    def _activate_selected(self):
        e = self._selected_entry()
        if not e:
            return
        p = self._cache_path(e)
        if not os.path.isfile(p):
            self._download_entry_async(e, False, True)
        else:
            self._activate_from_cache(e)

    def _activate_from_cache(self, e):
        try:
            path = self._cache_path(e)
            count = self._count_entries(path)
            size = os.path.getsize(path)

            if count >= 1000000:
                answer = JOptionPane.showConfirmDialog(
                    self.main_panel,
                    "This wordlist contains approximately %d payloads (%s).\n\n"
                    "Intruder may generate a very large number of requests.\nContinue?" %
                    (count, self._human_size(size)),
                    APP,
                    JOptionPane.YES_NO_OPTION
                )
                if answer != JOptionPane.YES_OPTION:
                    return

            self.active_entry = e
            self.active_payloads = []  # V2 streams from disk instead of loading into JVM memory.
            self._touch_recent(e)
            self.status.setText("Intruder active: %s (%d payloads, streaming)" % (e.get("name"), count))
            JOptionPane.showMessageDialog(
                self.main_panel,
                "Active Intruder wordlist:\n%s\n\nPayloads: %d\nSize: %s\nMode: Streaming\n\n"
                "Intruder -> Payload type: Extension-generated -> Wordlist Hub" %
                (e.get("name"), count, self._human_size(size)),
                APP,
                JOptionPane.INFORMATION_MESSAGE
            )
        except Exception as ex:
            JOptionPane.showMessageDialog(self.main_panel, "Could not load wordlist:\n%s" % ex,
                                          APP, JOptionPane.ERROR_MESSAGE)

    def _count_entries(self, path):
        count = 0
        try:
            fh = open(path, "rb")
            for raw in fh:
                if raw.rstrip("\r\n"):
                    count += 1
            fh.close()
        except:
            return 0
        return count

    # ---------- Favorites / recent ----------

    def _entry_id(self, e):
        if e.get("source") == "Custom":
            return "custom:" + e.get("url", "")
        return "seclists:" + e.get("path", "")

    def _toggle_favorite(self):
        e = self._selected_entry()
        if not e:
            return
        eid = self._entry_id(e)
        favs = self.settings.setdefault("favorites", [])
        if eid in favs:
            favs.remove(eid)
        else:
            favs.insert(0, eid)
        self._save_settings()
        self._apply_filters()

    def _touch_recent(self, e):
        eid = self._entry_id(e)
        recent = self.settings.setdefault("recent", [])
        if eid in recent:
            recent.remove(eid)
        recent.insert(0, eid)
        del recent[20:]
        self._save_settings()

    def _browse_special(self, which):
        ids = set(self.settings.get(which, []))
        if not ids:
            JOptionPane.showMessageDialog(self.main_panel, "Nothing here yet.", APP,
                                          JOptionPane.INFORMATION_MESSAGE)
            return
        # Use a temporary tree view containing only matching entries.
        entries = [e for e in self._all_entries() if self._entry_id(e) in ids]
        self.filtered = entries
        self._build_tree(entries)
        self.tabs.setSelectedIndex(0)
        self.status.setText("%s: %d wordlists" % (which.title(), len(entries)))

    def _refresh_manage_table(self):
        if not hasattr(self, "cache_table_model"):
            return
        self.cache_table_model.setRowCount(0)
        for e in self._all_entries():
            p = self._cache_path(e)
            if os.path.isfile(p):
                try:
                    size = os.path.getsize(p)
                except:
                    size = 0
                self.cache_table_model.addRow([
                    e.get("source_name") or e.get("source", ""),
                    e.get("name", ""),
                    e.get("category", ""),
                    self._count_entries(p),
                    self._human_size(size),
                    p
                ])

    def _delete_manage_selected(self):
        row = self.cache_table.getSelectedRow()
        if row < 0:
            return
        model_row = self.cache_table.convertRowIndexToModel(row)
        path = self.cache_table_model.getValueAt(model_row, 5)
        try:
            if os.path.isfile(path):
                os.remove(path)
            self._refresh_all()
            self.status.setText("Cached wordlist deleted.")
        except Exception as ex:
            JOptionPane.showMessageDialog(self.main_panel, str(ex), APP, JOptionPane.ERROR_MESSAGE)

    # ---------- Custom ----------

    def _add_custom(self):
        name = safe_unicode(self.custom_name.getText()).strip()
        url = safe_unicode(self.custom_url.getText()).strip()
        category = safe_unicode(self.custom_category.getText()).strip() or "Custom"

        if not name or not url:
            JOptionPane.showMessageDialog(self.main_panel, "Name and URL are required.",
                                          APP, JOptionPane.WARNING_MESSAGE)
            return
        if not (url.startswith("https://") or url.startswith("http://")):
            JOptionPane.showMessageDialog(self.main_panel, "URL must start with http:// or https://",
                                          APP, JOptionPane.WARNING_MESSAGE)
            return

        for existing in self.settings.get("custom", []):
            if existing.get("root_url", existing.get("url", "")).rstrip("/") == url.rstrip("/"):
                JOptionPane.showMessageDialog(self.main_panel, "This source is already configured.",
                                              APP, JOptionPane.WARNING_MESSAGE)
                return

        gh = self._parse_github_url(url)
        if gh and gh.get("kind") in ("repo", "dir"):
            self.status.setText("Importing GitHub source: %s..." % name)
            CustomGithubCatalogWorker(self, name, url, category, gh).execute()
            return

        # Individual file or non-GitHub direct URL.
        entry = {
            "name": name,
            "path": gh.get("relpath", name) if gh else name,
            "category": category,
            "source": "Custom",
            "url": url
        }
        self._store_custom_entries([entry])
        self.custom_name.setText("")
        self.custom_url.setText("")
        self._refresh_all()
        self.tabs.setSelectedIndex(0)
        self.status.setText("Custom wordlist added: %s" % name)

    def _parse_github_url(self, url):
        """Recognize github.com/{owner}/{repo}, /tree/{branch}/path and /blob/{branch}/file."""
        try:
            p = urlparse.urlparse(url)
            if p.netloc.lower() not in ("github.com", "www.github.com"):
                return None
            parts = [x for x in p.path.split("/") if x]
            if len(parts) < 2:
                return None
            owner, repo = parts[0], parts[1]
            if repo.endswith(".git"):
                repo = repo[:-4]

            if len(parts) == 2:
                return {"kind": "repo", "owner": owner, "repo": repo,
                        "branch": None, "relpath": ""}

            if len(parts) >= 4 and parts[2] == "tree":
                return {"kind": "dir", "owner": owner, "repo": repo,
                        "branch": parts[3], "relpath": "/".join(parts[4:])}

            if len(parts) >= 5 and parts[2] == "blob":
                return {"kind": "file", "owner": owner, "repo": repo,
                        "branch": parts[3], "relpath": "/".join(parts[4:])}
        except:
            return None
        return None

    def _store_custom_entries(self, entries):
        custom = self.settings.setdefault("custom", [])
        existing = set([x.get("url", "") for x in custom])
        added = 0
        for entry in entries:
            if entry.get("url", "") not in existing:
                custom.append(entry)
                existing.add(entry.get("url", ""))
                added += 1
        self._save_settings()
        return added

    def _custom_catalog_finished(self, source_name, entries, error):
        if error:
            self.status.setText("GitHub source import failed")
            JOptionPane.showMessageDialog(
                self.main_panel,
                "Could not import GitHub repository/directory.\\n\\n%s" % error,
                APP, JOptionPane.ERROR_MESSAGE
            )
            return
        added = self._store_custom_entries(entries)
        self.custom_name.setText("")
        self.custom_url.setText("")
        self._refresh_all()
        self.tabs.setSelectedIndex(0)
        self.status.setText("Imported %d wordlists from %s" % (added, source_name))
        JOptionPane.showMessageDialog(
            self.main_panel,
            "Imported %d wordlists from:\\n%s" % (added, source_name),
            APP, JOptionPane.INFORMATION_MESSAGE
        )

    def _open_cache_folder(self):
        try:
            from java.awt import Desktop
            from java.io import File
            Desktop.getDesktop().open(File(self.cache_dir))
        except Exception as ex:
            JOptionPane.showMessageDialog(self.main_panel, "Cache folder:\\n%s\\n\\n%s" % (self.cache_dir, ex),
                                          APP, JOptionPane.INFORMATION_MESSAGE)

    # ---------- Storage ----------

    def _storage_bytes(self):
        total = 0
        for root, dirs, files in os.walk(self.cache_dir):
            for f in files:
                try:
                    total += os.path.getsize(os.path.join(root, f))
                except:
                    pass
        return total

    def _human_size(self, n):
        value = float(n)
        for unit in ["B", "KB", "MB", "GB"]:
            if value < 1024.0:
                return "%.1f %s" % (value, unit)
            value /= 1024.0
        return "%.1f TB" % value

    def _update_storage_label(self):
        cached_count = sum(1 for e in self._all_entries() if os.path.isfile(self._cache_path(e)))
        self.storage_label.setText("Cache: %s | %d cached lists | %s" % (
            self._human_size(self._storage_bytes()), cached_count, self.cache_dir
        ))

    def _log(self, msg):
        try:
            self.callbacks.printOutput("[Wordlist Hub] %s" % msg)
        except:
            pass


class WordlistTreeCellRenderer(DefaultTreeCellRenderer):
    """Explicit renderer because Jython objects are otherwise shown as <__main__.Object at ...>."""
    def getTreeCellRendererComponent(self, tree, value, selected, expanded,
                                     leaf, row, hasFocus):
        component = DefaultTreeCellRenderer.getTreeCellRendererComponent(
            self, tree, value, selected, expanded, leaf, row, hasFocus
        )
        try:
            if isinstance(value, DefaultMutableTreeNode):
                obj = value.getUserObject()
                if isinstance(obj, WordlistTreeItem):
                    component.setText(obj.label)
                elif obj is not None:
                    component.setText(str(obj))
        except:
            pass
        return component


class WordlistTreeItem(object):
    def __init__(self, label, entry):
        self.label = label
        self.entry = entry

    def __str__(self):
        return self.label


class SearchDocumentListener(DocumentListener):
    def __init__(self, extender):
        self.extender = extender

    def insertUpdate(self, event):
        self.extender._apply_filters()

    def removeUpdate(self, event):
        self.extender._apply_filters()

    def changedUpdate(self, event):
        self.extender._apply_filters()


class StreamingWordlistPayloadGenerator(IIntruderPayloadGenerator):
    """Reads one payload at a time so large lists are not loaded into JVM memory."""
    def __init__(self, path):
        self.path = path
        self.handle = None
        self.next_payload = None
        self._open()

    def _open(self):
        if self.handle:
            try:
                self.handle.close()
            except:
                pass
        self.handle = open(self.path, "rb")
        self.next_payload = None
        self._advance()

    def _advance(self):
        self.next_payload = None
        while True:
            raw = self.handle.readline()
            if not raw:
                return
            value = raw.rstrip("\r\n")
            if value:
                self.next_payload = value
                return

    def hasMorePayloads(self):
        return self.next_payload is not None

    def getNextPayload(self, baseValue):
        if self.next_payload is None:
            return None
        current = self.next_payload
        self._advance()
        return current

    def reset(self):
        self._open()


class CatalogWorker(SwingWorker):
    def __init__(self, extender):
        self.extender = extender
        SwingWorker.__init__(self)

    def doInBackground(self):
        try:
            req = urllib2.Request(GITHUB_API_TREE)
            req.add_header("User-Agent", "Burp-Wordlist-Hub/2.5")
            req.add_header("Accept", "application/vnd.github+json")
            response = urllib2.urlopen(req, timeout=30)
            raw = response.read()
            response.close()
            data = json.loads(raw.decode("utf-8"))

            if data.get("truncated"):
                raise Exception("GitHub returned a truncated repository tree.")

            entries = []
            for item in data.get("tree", []):
                if item.get("type") != "blob":
                    continue
                path = item.get("path", "")
                if any(path.startswith(x) for x in SKIP_PREFIXES):
                    continue
                lower = path.lower()
                if not lower.endswith(ALLOWED_EXTENSIONS):
                    continue
                parts = path.split("/")
                category = parts[0] if len(parts) > 1 else "Other"
                entries.append({
                    "name": parts[-1],
                    "path": path,
                    "category": category,
                    "source": "SecLists",
                    "size": item.get("size", 0)
                })
            self.result_entries = entries
            self.result_error = None
        except Exception as e:
            self.result_entries = None
            self.result_error = str(e)
        return None

    def done(self):
        self.extender._catalog_finished(self.result_entries, self.result_error)


class CustomGithubCatalogWorker(SwingWorker):
    def __init__(self, extender, source_name, original_url, category, parsed):
        self.extender = extender
        self.source_name = source_name
        self.original_url = original_url
        self.category = category
        self.parsed = parsed
        SwingWorker.__init__(self)

    def _request_json(self, url):
        req = urllib2.Request(url)
        req.add_header("User-Agent", "Burp-Wordlist-Hub/2.5.2")
        req.add_header("Accept", "application/vnd.github+json")
        response = urllib2.urlopen(req, timeout=30)
        raw = response.read()
        response.close()
        return json.loads(raw.decode("utf-8"))

    def doInBackground(self):
        try:
            owner = self.parsed["owner"]
            repo = self.parsed["repo"]
            branch = self.parsed.get("branch")

            # For bare repository URLs discover the default branch first.
            if not branch:
                repo_info = self._request_json(
                    "https://api.github.com/repos/%s/%s" % (owner, repo)
                )
                branch = repo_info.get("default_branch", "main")

            api = "https://api.github.com/repos/%s/%s/git/trees/%s?recursive=1" % (
                owner, repo, branch
            )
            data = self._request_json(api)
            if data.get("truncated"):
                raise Exception("GitHub returned a truncated repository tree.")

            prefix = self.parsed.get("relpath", "").strip("/")
            if prefix:
                prefix = prefix + "/"

            entries = []
            for item in data.get("tree", []):
                if item.get("type") != "blob":
                    continue
                path = item.get("path", "")
                if prefix and not path.startswith(prefix):
                    continue
                if any(path.startswith(x) for x in SKIP_PREFIXES):
                    continue
                if not path.lower().endswith(ALLOWED_EXTENSIONS):
                    continue

                # Preserve useful hierarchy after the selected directory.
                relative = path[len(prefix):] if prefix else path
                pieces = relative.split("/")
                subcat = self.category
                if len(pieces) > 1:
                    subcat = "%s / %s" % (self.category, pieces[0])

                raw_url = "https://raw.githubusercontent.com/%s/%s/%s/%s" % (
                    owner, repo, branch, path
                )
                entries.append({
                    "name": pieces[-1],
                    "path": path,
                    "category": subcat,
                    "source": "Custom",
                    "url": raw_url,
                    "root_url": self.original_url,
                    "source_name": self.source_name
                })

            if not entries:
                raise Exception("No supported wordlist files were found under this GitHub source.")

            self.result_entries = entries
            self.result_error = None
        except Exception as e:
            self.result_entries = None
            self.result_error = str(e)
        return None

    def done(self):
        self.extender._custom_catalog_finished(
            self.source_name, self.result_entries, self.result_error
        )


class DownloadWorker(SwingWorker):
    def __init__(self, extender, entry, force, activate_after):
        self.extender = extender
        self.entry = entry
        self.force = force
        self.activate_after = activate_after
        SwingWorker.__init__(self)

    def doInBackground(self):
        try:
            url = self.extender._entry_url(self.entry)
            if not url:
                raise Exception("No download URL.")
            req = urllib2.Request(url)
            req.add_header("User-Agent", "Burp-Wordlist-Hub/2.5")
            response = urllib2.urlopen(req, timeout=60)
            content_type = response.info().getheader("Content-Type") or ""
            data = response.read()
            final_url = response.geturl()
            response.close()

            # Never cache GitHub/web HTML pages as wordlists.
            probe = data[:4096].lstrip().lower()
            if ("text/html" in content_type.lower() or
                    probe.startswith("<!doctype html") or
                    probe.startswith("<html") or
                    "<html" in probe[:1000]):
                raise Exception(
                    "The URL returned an HTML webpage instead of a wordlist. "
                    "For GitHub, paste a repository/tree/blob URL and Wordlist Hub will resolve it automatically."
                )

            if len(data) == 0:
                raise Exception("The downloaded wordlist is empty.")

            dest = self.extender._cache_path(self.entry)
            ensure_dir(os.path.dirname(dest))
            tmp = dest + ".tmp"
            fh = open(tmp, "wb")
            fh.write(data)
            fh.close()
            if os.path.isfile(dest):
                os.remove(dest)
            os.rename(tmp, dest)
            self.result_error = None
        except Exception as e:
            self.result_error = str(e)
        return None

    def done(self):
        self.extender._download_finished(self.entry, self.result_error, self.activate_after)


class WordlistHubPayloadGenerator(IIntruderPayloadGenerator):
    def __init__(self, payloads):
        self.payloads = payloads
        self.index = 0

    def hasMorePayloads(self):
        return self.index < len(self.payloads)

    def getNextPayload(self, baseValue):
        if not self.hasMorePayloads():
            return None
        payload = self.payloads[self.index]
        self.index += 1
        # Cached payloads are kept as byte strings to avoid changing arbitrary wordlist bytes.
        if isinstance(payload, unicode):
            return payload.encode("utf-8")
        return payload

    def reset(self):
        self.index = 0

