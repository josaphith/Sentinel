import csv
import hashlib
import os
import queue
import sqlite3
import threading
import time
from datetime import datetime
from pathlib import Path
from tkinter import filedialog, messagebox

import customtkinter as ctk
from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer
from security import BaselineGuard, BaselineIntegrityError
from windows_audit import lookup_file_events

try:
    from winotify import Notification
except ImportError:
    Notification = None

try:
    import pystray
    from PIL import Image, ImageDraw
except ImportError:
    pystray = None

APP_DIR = Path(os.environ.get('LOCALAPPDATA', str(Path.home()))) / 'SimpleFIM'
APP_DIR.mkdir(parents=True, exist_ok=True)
DB_PATH = APP_DIR / 'fim.db'
SCAN_INTERVAL = 60
FULL_HASH_INTERVAL = 300  # Force content hashing even when metadata is unchanged
CRITICAL_PARTS = ("\\windows\\system32\\drivers\\etc\\", "\\windows\\system32\\config\\", "\\microsoft\\windows\\start menu\\programs\\startup\\")


def is_critical(path):
    normalized = os.path.normcase(os.path.abspath(path)).lower().replace("/", "\\")
    return any(part in normalized for part in CRITICAL_PARTS)


def timestamp():
    return datetime.now().astimezone().isoformat(timespec='seconds')


def hash_file(path):
    digest = hashlib.sha256()
    with open(path, 'rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def db_connect():
    connection = sqlite3.connect(DB_PATH, timeout=15)
    connection.execute('PRAGMA busy_timeout=15000')
    connection.execute('PRAGMA journal_mode=WAL')
    return connection


def init_db():
    with db_connect() as con:
        con.executescript('''
            CREATE TABLE IF NOT EXISTS folders (
                path TEXT PRIMARY KEY
            );
            CREATE TABLE IF NOT EXISTS files (
                path TEXT PRIMARY KEY,
                folder TEXT NOT NULL,
                sha256 TEXT NOT NULL,
                size INTEGER NOT NULL,
                mtime_ns INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                detected_at TEXT NOT NULL,
                event_type TEXT NOT NULL,
                path TEXT NOT NULL,
                old_hash TEXT,
                new_hash TEXT,
                old_size INTEGER,
                new_size INTEGER,
                details TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_events_path ON events(path);
        ''')


class ChangeHandler(FileSystemEventHandler):
    def __init__(self, wake):
        self.wake = wake

    def on_any_event(self, event):
        self.wake.set()


class Monitor:
    def __init__(self, ui_queue):
        self.ui_queue = ui_queue
        self.commands = queue.Queue()
        self.guard = BaselineGuard(APP_DIR)
        self.guard_ready = False
        self.read_errors = set()
        self.wake = threading.Event()
        self.shutdown = threading.Event()
        self.active = False
        self.observer = None
        self.thread = threading.Thread(target=self.run, daemon=True)
        self.thread.start()

    def post(self, command, value=None):
        self.commands.put((command, value))
        self.wake.set()

    def notify(self, event_type, path):
        self.ui_queue.put(('event', (event_type, path)))

    def record(self, con, kind, path, old=None, new=None, details=''):
        con.execute('''
            INSERT INTO events
            (detected_at,event_type,path,old_hash,new_hash,old_size,new_size,details)
            VALUES (?,?,?,?,?,?,?,?)
        ''', (timestamp(), kind, path,
              old[0] if old else None, new[0] if new else None,
              old[1] if old else None, new[1] if new else None, details))
        if is_critical(path) and kind in ('CREATED', 'MODIFIED', 'DELETED'):
            self.ui_queue.put(('critical', (kind, path)))
        else:
            self.notify(kind, path)

    def folders(self, con):
        return [row[0] for row in con.execute('SELECT path FROM folders ORDER BY path')]

    def scan(self, con, folder, initial=False, force_hash=False):
        folder = os.path.normcase(os.path.abspath(folder))
        if not os.path.isdir(folder):
            self.ui_queue.put(('status', f'Folder unavailable: {folder}'))
            return

        previous = {
            row[0]: (row[1], row[2], row[3])
            for row in con.execute(
                'SELECT path,sha256,size,mtime_ns FROM files WHERE folder=?',
                (folder,))
        }
        seen = set()
        inaccessible = set()
        walk_errors = []

        def on_walk_error(error):
            walk_errors.append(str(error))

        for root, dirs, filenames in os.walk(folder, onerror=on_walk_error, followlinks=False):
            # Do not traverse directory reparse points or symlinks.
            dirs[:] = [d for d in dirs if not os.path.islink(os.path.join(root, d))]
            for name in filenames:
                path = os.path.normcase(os.path.abspath(os.path.join(root, name)))
                if os.path.islink(path):
                    continue
                seen.add(path)
                try:
                    before = os.stat(path)
                    old = previous.get(path)
                    # Fast path: unchanged metadata. A forced hash runs periodically.
                    if (not force_hash and old is not None
                            and old[1:] == (before.st_size, before.st_mtime_ns)):
                        self.read_errors.discard(path)
                        continue
                    digest = hash_file(path)
                    after = os.stat(path)
                    if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
                        raise OSError('File changed during hashing')
                    current = (digest, after.st_size, after.st_mtime_ns)
                except OSError as exc:
                    inaccessible.add(path)
                    if path not in self.read_errors:
                        self.record(con, 'READ_ERROR', path, old=previous.get(path), details=str(exc))
                        self.read_errors.add(path)
                    self.ui_queue.put(('status', f'Cannot read {path}: {exc}'))
                    continue

                self.read_errors.discard(path)
                old = previous.get(path)
                if old is None:
                    if not initial:
                        self.record(con, 'CREATED', path, new=current)
                elif old[0] != current[0]:
                    self.record(con, 'MODIFIED', path, old=old, new=current)
                elif old[1:] != current[1:]:
                    self.record(con, 'METADATA', path, old=old, new=current,
                                details='Size or modification time changed without content hash change')

                con.execute('''
                    INSERT INTO files(path,folder,sha256,size,mtime_ns)
                    VALUES (?,?,?,?,?)
                    ON CONFLICT(path) DO UPDATE SET
                        folder=excluded.folder, sha256=excluded.sha256,
                        size=excluded.size, mtime_ns=excluded.mtime_ns
                ''', (path, folder, *current))

        # If walking a directory failed, avoid falsely marking its contents deleted.
        if not walk_errors:
            for path, old in previous.items():
                if path not in seen and path not in inaccessible:
                    self.record(con, 'DELETED', path, old=old)
                    con.execute('DELETE FROM files WHERE path=?', (path,))
        else:
            self.ui_queue.put(('status', 'Some directories could not be scanned; deletion checks skipped'))

        self.guard.seal(con)
        con.commit()  # Atomic: baseline, events, and seal commit together.
        self.ui_queue.put(('refresh', None))

    def stop_observer(self):
        if self.observer:
            self.observer.stop()
            self.observer.join(timeout=5)
            self.observer = None

    def start_observer(self, con):
        self.stop_observer()
        folders = [f for f in self.folders(con) if os.path.isdir(f)]
        if not folders:
            self.active = False
            self.ui_queue.put(('status', 'No available folders to monitor'))
            return
        observer = Observer()
        for folder in folders:
            observer.schedule(ChangeHandler(self.wake), folder, recursive=True)
        observer.start()
        self.observer = observer
        self.active = True
        self.ui_queue.put(('status', 'Monitoring active'))

    def run(self):
        con = db_connect()
        try:
            self.guard.initialize_and_verify(con)
            self.guard_ready = True
        except BaselineIntegrityError as exc:
            self.ui_queue.put(('status', f'BASELINE LOCKED: {exc}'))
        next_scan = time.monotonic() + SCAN_INTERVAL
        next_full_hash = time.monotonic() + FULL_HASH_INTERVAL
        try:
            while not self.shutdown.is_set():
                self.wake.wait(timeout=1)
                changed = self.wake.is_set()
                self.wake.clear()
                # Debounce bursts of watchdog events.
                if changed and self.commands.empty() and self.active:
                    time.sleep(0.4)
                    self.wake.clear()
                try:
                    while True:
                        command, value = self.commands.get_nowait()
                        if command == 'reset_baseline':
                            self.stop_observer()
                            self.active = False
                            self.guard.reset(con)
                            self.guard_ready = True
                            self.ui_queue.put(('status', 'Baseline and history reset. Add folders again.'))
                            self.ui_queue.put(('refresh', None))
                            continue
                        if not self.guard_ready and command != 'quit':
                            self.ui_queue.put(('status', 'Baseline locked. Use Reset Baseline to discard it.'))
                            continue
                        if command == 'quit':
                            self.shutdown.set()
                            break
                        if command == 'add':
                            folder = os.path.normcase(os.path.abspath(value))
                            exists = con.execute('SELECT 1 FROM folders WHERE path=?', (folder,)).fetchone()
                            if not exists:
                                con.execute('INSERT INTO folders(path) VALUES (?)', (folder,))
                                self.scan(con, folder, initial=True, force_hash=True)
                            if self.active:
                                self.start_observer(con)
                            self.ui_queue.put(('refresh', None))
                        elif command == 'remove':
                            folder = value
                            con.execute('DELETE FROM folders WHERE path=?', (folder,))
                            con.execute('DELETE FROM files WHERE folder=?', (folder,))
                            self.guard.seal(con)
                            con.commit()
                            if self.active:
                                self.start_observer(con)
                            self.ui_queue.put(('refresh', None))
                        elif command == 'start':
                            self.start_observer(con)
                            changed = True
                        elif command == 'stop':
                            self.active = False
                            self.stop_observer()
                            self.ui_queue.put(('status', 'Monitoring stopped'))
                        elif command == 'scan':
                            changed = True
                except queue.Empty:
                    pass
                if self.shutdown.is_set():
                    break
                if self.guard_ready and (changed or (self.active and time.monotonic() >= next_scan)):
                    try:
                        self.guard.initialize_and_verify(con)
                    except BaselineIntegrityError as exc:
                        self.guard_ready = False
                        self.active = False
                        self.stop_observer()
                        self.ui_queue.put(('status', f'BASELINE LOCKED: {exc}'))
                        continue
                    force_hash = time.monotonic() >= next_full_hash
                    for folder in self.folders(con):
                        self.scan(con, folder, force_hash=force_hash)
                    next_scan = time.monotonic() + SCAN_INTERVAL
                    if force_hash:
                        next_full_hash = time.monotonic() + FULL_HASH_INTERVAL
            self.stop_observer()
        except Exception as exc:
            self.ui_queue.put(('status', f'Monitor error: {exc}'))
        finally:
            con.close()
            self.ui_queue.put(('stopped', None))


class ToolTip:
    """Delayed tooltip for any CustomTkinter widget; no extra dependencies."""
    def __init__(self, widget, text, delay=550):
        self.widget, self.text, self.delay = widget, text, delay
        self.pending = None
        self.popup = None
        widget.bind('<Enter>', self.schedule, add='+')
        widget.bind('<Leave>', self.hide, add='+')
        widget.bind('<ButtonPress>', self.hide, add='+')

    def schedule(self, _event=None):
        self.cancel()
        self.pending = self.widget.after(self.delay, self.show)

    def cancel(self):
        if self.pending is not None:
            try:
                self.widget.after_cancel(self.pending)
            except Exception:
                pass
            self.pending = None

    def show(self):
        self.pending = None
        if self.popup or not self.widget.winfo_exists():
            return
        import tkinter as tk
        x = self.widget.winfo_rootx() + 15
        y = self.widget.winfo_rooty() + self.widget.winfo_height() + 8
        self.popup = tk.Toplevel(self.widget)
        self.popup.wm_overrideredirect(True)
        self.popup.wm_attributes('-topmost', True)
        label = tk.Label(self.popup, text=self.text, bg='#253247', fg='#f8fafc',
                         justify='left', padx=12, pady=9, wraplength=330,
                         font=('Segoe UI', 10), relief='solid', bd=1)
        label.pack()
        self.popup.geometry(f'+{x}+{y}')

    def hide(self, _event=None):
        self.cancel()
        if self.popup is not None:
            self.popup.destroy()
            self.popup = None


class FIMApp(ctk.CTk):
    BG = '#0b1220'
    PANEL = '#172338'
    PANEL_2 = '#1c2b43'
    MUTED = '#94a3b8'
    ACCENT = '#3b82f6'
    GREEN = '#10b981'

    def __init__(self):
        super().__init__()
        self.title('Sentinel | File Integrity Monitor')
        self.geometry('1190x790')
        self.minsize(930, 650)
        self.configure(fg_color=self.BG)
        self.ui_queue = queue.Queue()
        self.monitor = Monitor(self.ui_queue)
        self.tray = None
        self.closing = False
        self.protocol('WM_DELETE_WINDOW', self.hide_to_tray)
        self._build_ui()
        self.refresh()
        self.after(300, self.process_ui)
        self.monitor.post('start')

    def _label(self, parent, text, size=13, color=None, bold=False, **kwargs):
        return ctk.CTkLabel(parent, text=text, text_color=color or '#f8fafc',
                            font=ctk.CTkFont(family='Segoe UI', size=size,
                                             weight='bold' if bold else 'normal'), **kwargs)

    def _button(self, parent, title, command, tip, color=None, width=130):
        button = ctk.CTkButton(parent, text=title, command=command, width=width,
                              height=38, corner_radius=9,
                              fg_color=color or self.ACCENT,
                              hover_color='#2563eb' if color is None else '#334155',
                              font=ctk.CTkFont(size=12, weight='bold'))
        button.pack(side='left', padx=(0, 8), pady=4)
        ToolTip(button, tip)
        return button

    def _card(self, parent, title):
        frame = ctk.CTkFrame(parent, fg_color=self.PANEL, corner_radius=14)
        self._label(frame, title, 15, bold=True).pack(anchor='w', padx=18, pady=(14, 8))
        return frame

    def _build_ui(self):
        header = ctk.CTkFrame(self, fg_color=self.PANEL, corner_radius=0, height=82)
        header.pack(fill='x')
        header.pack_propagate(False)
        heading = ctk.CTkFrame(header, fg_color='transparent')
        heading.pack(side='left', padx=24, pady=12)
        self._label(heading, '◆  SENTINEL', 24, bold=True).pack(anchor='w')
        self._label(heading, 'File integrity monitoring • Windows', 11, self.MUTED).pack(anchor='w')
        self._button(header, '❔  Tutorial', self.show_tutorial,
                     'Open a step-by-step guide to monitoring and investigating files.',
                     color='#334155', width=120).pack_configure(side='right', padx=18)

        body = ctk.CTkScrollableFrame(self, fg_color=self.BG, corner_radius=0)
        body.pack(fill='both', expand=True, padx=20, pady=(14, 8))

        status_card = ctk.CTkFrame(body, fg_color=self.PANEL, corner_radius=14)
        status_card.pack(fill='x', pady=(0, 12))
        self._label(status_card, 'MONITOR STATUS', 11, self.MUTED, bold=True).pack(anchor='w', padx=18, pady=(12, 0))
        self.status = self._label(status_card, 'Starting…', 15, bold=True)
        self.status.pack(anchor='w', padx=18, pady=(3, 12))

        metrics = ctk.CTkFrame(body, fg_color='transparent')
        metrics.pack(fill='x', pady=(0, 12))
        self.metric_labels = {}
        for index, (key, title) in enumerate((('folders', 'MONITORED FOLDERS'),
                                               ('files', 'BASELINE FILES'),
                                               ('events', 'RECORDED EVENTS'))):
            metrics.grid_columnconfigure(index, weight=1, uniform='stats')
            panel = ctk.CTkFrame(metrics, fg_color=self.PANEL, corner_radius=13)
            panel.grid(row=0, column=index, sticky='ew', padx=(0 if index == 0 else 5, 0))
            self._label(panel, title, 11, self.MUTED, bold=True).pack(anchor='w', padx=17, pady=(12, 0))
            value = self._label(panel, '0', 27, bold=True)
            value.pack(anchor='w', padx=17, pady=(0, 12))
            self.metric_labels[key] = value

        folder_card = self._card(body, '01   Folders & monitoring')
        folder_card.pack(fill='x', pady=(0, 12))
        row = ctk.CTkFrame(folder_card, fg_color='transparent')
        row.pack(fill='x', padx=18, pady=(0, 8))
        self.folder_menu = ctk.CTkOptionMenu(row, values=['No folders'], width=460,
                                              fg_color=self.PANEL_2, button_color='#334155',
                                              button_hover_color='#475569')
        self.folder_menu.pack(side='left', fill='x', expand=True, padx=(0, 10))
        ToolTip(self.folder_menu, 'Select one of your registered folders. Files are not copied into the app.')
        self._button(row, '+ Add Folder', self.add_folder,
                     'Choose a folder and save its existing files as the initial trusted baseline.', width=125)
        self._button(row, 'Remove', self.remove_folder,
                     'Stop tracking the selected folder and remove its saved file baselines.',
                     color='#475569', width=88)
        row2 = ctk.CTkFrame(folder_card, fg_color='transparent')
        row2.pack(fill='x', padx=18, pady=(0, 14))
        self._button(row2, '▶ Start', lambda: self.monitor.post('start'),
                     'Enable continuous Watchdog monitoring and periodic verification scans.',
                     color='#047857', width=120)
        self._button(row2, '■ Stop', lambda: self.monitor.post('stop'),
                     'Pause automatic monitoring. Scan Now still works while stopped.',
                     color='#475569', width=115)
        self._button(row2, '⟳ Scan Now', lambda: self.monitor.post('scan'),
                     'Compare files against their saved baseline immediately, even if monitoring is stopped.',
                     width=130)
        self._label(row2, 'Tip: adding a folder creates a baseline; it does not generate CREATED events.',
                    11, self.MUTED).pack(side='left', padx=8)

        events_card = self._card(body, '02   Recent activity')
        events_card.pack(fill='both', expand=True, pady=(0, 12))
        actions = ctk.CTkFrame(events_card, fg_color='transparent')
        actions.pack(fill='x', padx=18, pady=(0, 6))
        self._button(actions, 'Export CSV', self.export_csv,
                     'Save the complete event history as a CSV spreadsheet.',
                     color='#334155', width=120)
        self._button(actions, 'Export TXT', self.export_txt,
                     'Save the complete event history as a plain-text report.',
                     color='#334155', width=120)
        self._button(actions, 'Show All Events', self.refresh,
                     'Return to the latest 200 events after viewing a file history or Windows audit.',
                     color='#334155', width=155)
        self.log = ctk.CTkTextbox(events_card, wrap='none', height=205,
                                  fg_color='#0e192b', text_color='#e2e8f0',
                                  font=ctk.CTkFont(family='Consolas', size=12),
                                  corner_radius=9)
        self.log.pack(fill='both', expand=True, padx=18, pady=(0, 16))
        self.log.configure(state='disabled')

        investigation = self._card(body, '03   File investigation')
        investigation.pack(fill='x', pady=(0, 12))
        self._label(investigation, 'Enter the exact path of a monitored file', 11, self.MUTED).pack(
            anchor='w', padx=18)
        self.path_entry = ctk.CTkEntry(investigation, height=38,
                                       placeholder_text=r'C:\Users\me\Documents\example.txt',
                                       fg_color='#0e192b', border_color='#334155')
        self.path_entry.pack(fill='x', padx=18, pady=(4, 10))
        ToolTip(self.path_entry, 'Paste the complete path, including filename and extension.')
        investigation_buttons = ctk.CTkFrame(investigation, fg_color='transparent')
        investigation_buttons.pack(fill='x', padx=18, pady=(0, 14))
        self._button(investigation_buttons, 'File History', self.show_history,
                     'Filter saved FIM events to the exact file path entered above.', width=145)
        self._button(investigation_buttons, 'Windows Audit Logs', self.audit_file,
                     'Search available Windows Security/Sysmon events. Auditing must already be configured.',
                     color='#334155', width=170)

        footer = ctk.CTkFrame(body, fg_color='transparent')
        footer.pack(fill='x', pady=(0, 12))
        self._button(footer, 'Hide to Tray', self.hide_to_tray,
                     'Hide this window while monitoring continues in the system tray.',
                     color='#334155', width=145)
        self._button(footer, 'Reset Baseline', self.reset_baseline,
                     'DANGER: permanently discard registered folders, trusted hashes AND event history.',
                     color='#8b343f', width=150)
        self._label(footer, 'Hover over any button for an explanation.', 11, self.MUTED).pack(
            side='right', padx=8)

    def show_tutorial(self):
        win = ctk.CTkToplevel(self)
        win.title('Sentinel • Getting Started')
        win.geometry('730x620')
        win.minsize(550, 420)
        win.configure(fg_color=self.BG)
        win.transient(self)
        win.lift()
        content = ctk.CTkScrollableFrame(win, fg_color=self.BG)
        content.pack(fill='both', expand=True, padx=20, pady=18)
        self._label(content, 'Getting started with Sentinel', 23, bold=True).pack(anchor='w', pady=(0, 5))
        self._label(content, 'Follow these steps to test your file integrity monitor.',
                    12, self.MUTED).pack(anchor='w', pady=(0, 18))
        steps = [
            ('1. Add a folder', 'Click + Add Folder and select a test directory. Sentinel records the files already there as its trusted baseline; it does not copy them or show them as new events.'),
            ('2. Start monitoring', 'Click Start to enable continuous monitoring. The status should say Monitoring active. You can also use Scan Now to perform a one-time check.'),
            ('3. Create a test file', 'Create test.txt inside the monitored folder. You should see a CREATED event, usually within a few seconds.'),
            ('4. Modify and delete it', 'Edit test.txt and save to generate MODIFIED; then delete it to generate DELETED. A renamed file may appear as a deletion plus a creation.'),
            ('5. Investigate a file', 'Paste its full path into File investigation. File History shows recorded FIM events; Windows Audit Logs searches available Security and Sysmon records.'),
            ('6. Export your findings', 'Export CSV creates a spreadsheet-friendly report. Export TXT saves a text report. Both include the stored event history.'),
            ('7. Background monitoring', 'Hide to Tray keeps the program running in your Windows session. Use the tray menu to show it again or exit completely.'),
            ('8. Recover with caution', 'Reset Baseline deletes the trusted folder list, hashes and event history. Export evidence and make a backup before resetting.'),
        ]
        for title, detail in steps:
            frame = ctk.CTkFrame(content, fg_color=self.PANEL, corner_radius=12)
            frame.pack(fill='x', pady=5)
            self._label(frame, title, 15, bold=True).pack(anchor='w', padx=16, pady=(12, 3))
            self._label(frame, detail, 12, self.MUTED, wraplength=620,
                        justify='left').pack(anchor='w', padx=16, pady=(0, 13))
        self._label(content, 'Note: the event timestamp is the detection time, not proof of the exact edit time. Windows auditing must be configured in advance to collect account/process evidence.',
                    12, '#fbbf24', wraplength=620, justify='left').pack(anchor='w', pady=12)
        ctk.CTkButton(content, text='Close Tutorial', command=win.destroy).pack(pady=12)

    def add_folder(self):
        folder = filedialog.askdirectory()
        if folder:
            self.status.configure(text='Adding folder and calculating baseline…')
            self.monitor.post('add', folder)

    def remove_folder(self):
        folder = self.folder_menu.get()
        if folder == 'No folders':
            return
        if messagebox.askyesno('Remove folder', f'Stop monitoring this folder?\n{folder}'):
            self.monitor.post('remove', folder)

    def refresh(self):
        with db_connect() as con:
            folders = [row[0] for row in con.execute('SELECT path FROM folders ORDER BY path')]
            rows = con.execute("""
                SELECT detected_at,event_type,path,old_hash,new_hash,old_size,new_size,details
                FROM events ORDER BY id DESC LIMIT 200
            """).fetchall()
            file_count = con.execute('SELECT COUNT(*) FROM files').fetchone()[0]
            event_count = con.execute('SELECT COUNT(*) FROM events').fetchone()[0]
        self.folder_menu.configure(values=folders or ['No folders'])
        self.folder_menu.set(folders[0] if folders else 'No folders')
        for key, count in (('folders', len(folders)), ('files', file_count), ('events', event_count)):
            self.metric_labels[key].configure(text=str(count))
        self.show_rows(rows)

    def show_rows(self, rows):
        self.log.configure(state='normal')
        self.log.delete('1.0', 'end')
        if not rows:
            self.log.insert('end', 'No events to display yet. Add a folder, then create or edit a file.\n')
        for detected, kind, path, old_hash, new_hash, old_size, new_size, details in rows:
            self.log.insert('end', f'[{detected}] {kind}: {path}\n')
            self.log.insert('end', f'  Old SHA-256: {old_hash or "—"}\n')
            self.log.insert('end', f'  New SHA-256: {new_hash or "—"}\n')
            self.log.insert('end', f'  Size: {old_size} -> {new_size} bytes\n')
            if details:
                self.log.insert('end', f'  Details: {details}\n')
            self.log.insert('end', '\n')
        self.log.configure(state='disabled')

    def show_history(self):
        path = self.path_entry.get().strip()
        if not path:
            messagebox.showinfo('File history', 'Enter a file path first.')
            return
        path = os.path.normcase(os.path.abspath(path))
        with db_connect() as con:
            rows = con.execute("""
                SELECT detected_at,event_type,path,old_hash,new_hash,old_size,new_size,details
                FROM events WHERE path=? ORDER BY id DESC
            """, (path,)).fetchall()
        self.show_rows(rows)
        self.status.configure(text=f'{len(rows)} historical events for {path}')

    def audit_file(self):
        path = self.path_entry.get().strip()
        if not path:
            messagebox.showinfo('Windows audit', 'Enter an exact file path first.')
            return
        self.status.configure(text='Searching Windows event logs (up to 5000 records/channel)...')
        def work():
            try:
                result = lookup_file_events(path)
            except Exception as exc:
                result = [f'Audit search failed: {exc}']
            self.ui_queue.put(('audit', result))
        threading.Thread(target=work, daemon=True).start()

    def reset_baseline(self):
        if messagebox.askyesno('Reset trusted baseline',
                'RECOVERY: This permanently discards monitored folders, hashes AND event history. Export evidence first if possible. Continue?'):
            self.monitor.post('reset_baseline')

    def export(self, filetype):
        extension = '.csv' if filetype == 'csv' else '.txt'
        path = filedialog.asksaveasfilename(defaultextension=extension,
                                             filetypes=[(filetype.upper(), '*' + extension)])
        if not path:
            return
        with db_connect() as con:
            rows = con.execute("""
                SELECT detected_at,event_type,path,old_hash,new_hash,old_size,new_size,details
                FROM events ORDER BY id
            """).fetchall()
        headings = ['Detected At', 'Event', 'Path', 'Old SHA256', 'New SHA256',
                    'Old Size', 'New Size', 'Details']
        try:
            with open(path, 'w', encoding='utf-8-sig', newline='') as stream:
                if filetype == 'csv':
                    writer = csv.writer(stream)
                    writer.writerow(headings)
                    writer.writerows(rows)
                else:
                    for row in rows:
                        stream.write(' | '.join('' if x is None else str(x) for x in row) + '\n')
            messagebox.showinfo('Export', f'Exported {len(rows)} events.')
        except OSError as exc:
            messagebox.showerror('Export failed', str(exc))

    def export_csv(self):
        self.export('csv')

    def export_txt(self):
        self.export('txt')

    def process_ui(self):
        if self.closing:
            return
        refresh_needed = False
        try:
            while True:
                kind, payload = self.ui_queue.get_nowait()
                if kind == 'refresh':
                    refresh_needed = True
                elif kind == 'event':
                    event_type, path = payload
                    if event_type in ('CREATED', 'MODIFIED', 'DELETED'):
                        self.windows_notification(event_type, path)
                    refresh_needed = True
                elif kind == 'status':
                    self.status.configure(text=payload)
                elif kind == 'critical':
                    event_type, path = payload
                    self.windows_notification('CRITICAL ' + event_type, path)
                    refresh_needed = True
                elif kind == 'audit':
                    self.log.configure(state='normal')
                    self.log.delete('1.0', 'end')
                    self.log.insert('end', 'Windows audit results (correlation only; not proof of modification):\n\n')
                    self.log.insert('end', '\n'.join(payload))
                    self.log.configure(state='disabled')
                    self.status.configure(text=f'Windows audit search completed ({len(payload)} result lines)')
        except queue.Empty:
            pass
        if refresh_needed:
            self.refresh()
        self.after(300, self.process_ui)

    def windows_notification(self, kind, path):
        if Notification is None:
            return
        try:
            toast = Notification(app_id='Simple FIM', title=f'File {kind.lower()}',
                                 msg=path, duration='short')
            toast.show()
        except Exception:
            pass

    def tray_icon_image(self):
        img = Image.new('RGB', (64, 64), '#1f2937')
        draw = ImageDraw.Draw(img)
        draw.rounded_rectangle((12, 8, 52, 56), radius=7, outline='#60a5fa', width=4)
        draw.line([(22, 32), (29, 40), (44, 22)], fill='#34d399', width=5)
        return img

    def hide_to_tray(self):
        if pystray is None:
            messagebox.showinfo('Tray unavailable', 'Install pystray and pillow to hide to tray.')
            return
        self.withdraw()
        if self.tray is None:
            menu = pystray.Menu(
                pystray.MenuItem('Show', lambda icon, item: self.after(0, self.show_window)),
                pystray.MenuItem('Exit', lambda icon, item: self.after(0, self.exit_app)),
            )
            self.tray = pystray.Icon('SimpleFIM', self.tray_icon_image(), 'File Integrity Monitor', menu)
            threading.Thread(target=self.tray.run, daemon=True).start()

    def show_window(self):
        self.deiconify()
        self.lift()

    def exit_app(self):
        if self.closing:
            return
        self.closing = True
        self.monitor.post('quit')
        if self.tray is not None:
            self.tray.stop()
        self.destroy()


if __name__ == '__main__':
    ctk.set_appearance_mode('dark')
    ctk.set_default_color_theme('blue')
    init_db()
    FIMApp().mainloop()