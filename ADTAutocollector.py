import re
import shutil
import tkinter as tk
from tkinter import scrolledtext, messagebox, filedialog
from pathlib import Path
from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer
from datetime import datetime

# --- CONFIGURATION (Default Values) ---
# These are now default values (can be changed by user in the GUI).
DEFAULT_SOURCE_PATH = Path(r"/Users/khaitran/Desktop/Fabrinet/ATDX Copy Project/testfolder1")
DEFAULT_DESTINATION_PATH = Path(r"/Users/khaitran/Desktop/Fabrinet/ATDX Copy Project/test2")

# Rename only files ending in "pass.ATD" (case-insensitive)
ATD_RE = re.compile(r"pass\.atd$", re.IGNORECASE)

# Move only files ending in "pass.ATDX" (case-insensitive)
ATDX_RE = re.compile(r"pass\.atdx$", re.IGNORECASE)


class AutoCollector(FileSystemEventHandler):
    def __init__(self, src: Path, dst: Path, log_display):
        self.src = src
        self.dst = dst
        self.log_display = log_display

    def report_message(self, message, level="INFO"):
        """Reports messages to the GUI log display with colored tags."""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        level_tag = ""
        if level == "INFO":
            level_tag = "info_tag"
        elif level == "SUCCESS":
            level_tag = "success_tag"
        elif level == "ERROR":
            level_tag = "error_tag"

        self.log_display.config(state=tk.NORMAL)
        self.log_display.insert(tk.END, f"{timestamp} ", "timestamp_tag")
        self.log_display.insert(tk.END, f"[{level}] ", level_tag)
        self.log_display.insert(tk.END, f"{message}\n", "message_tag")
        self.log_display.see(tk.END)
        self.log_display.config(state=tk.DISABLED)

    def process(self, path: Path):
        """
        Processes a file, checking if it needs to be renamed and/or moved.
        It first checks for a '.atd' file to rename, then checks for a
        'pass.atdx' file to move.
        """
        if not path.is_file():
            return

        # If it ends in "pass.atd", rename to "pass.atdx"
        if ATD_RE.search(path.name):
            new_path = path.with_suffix(".ATDX")
            try:
                # Rename the file
                path.rename(new_path)
                self.report_message(f"RENAMED: {path.name} TO {new_path.name}", level="SUCCESS")
                # Update the path variable to the new path so the next check uses the new filename
                path = new_path
            except Exception as e:
                self.report_message(f"Failed to rename {path.name}: {e}", level="ERROR")
                return

        # If the file name now ends in "pass.atdx", move it
        if ATDX_RE.search(path.name):
            try:
                rel = path.relative_to(self.src)
                target = self.dst / rel
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.move(str(path), str(target))
                self.report_message(f"MOVED: {rel} TO {target}", level="SUCCESS")
            except Exception as e:
                self.report_message(f"Failed to move {rel}: {e}", level="ERROR")

    def on_any_event(self, event):
        try:
            src_path = Path(event.src_path)
        except Exception as e:
            self.report_message(f"Could not get event source path: {e}", level="ERROR")
            return
        self.process(src_path)


class AutoCollectorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("ATDX AutoCollector")
        self.root.geometry("700x500")
        self.root.configure(bg="#333333")

        self.source_path_var = tk.StringVar(value=str(DEFAULT_SOURCE_PATH))
        self.destination_path_var = tk.StringVar(value=str(DEFAULT_DESTINATION_PATH))

        self.observer = None
        self.handler = None
        self.is_monitoring_active = False

        self.create_widgets()
        self.configure_tags()
        self.check_paths()
        self.update_toggle_button()

    def create_widgets(self):
        # Path display
        path_frame = tk.LabelFrame(self.root, text="Paths", padx=10, pady=10, bg="#444444", fg="white")
        path_frame.pack(padx=10, pady=10, fill="x")

        # Source Path
        source_frame = tk.Frame(path_frame, bg="#444444")
        source_frame.pack(fill="x", pady=2)
        tk.Label(source_frame, text="Source:", bg="#444444", fg="white").pack(side=tk.LEFT, padx=5)
        self.source_path_entry = tk.Entry(source_frame, textvariable=self.source_path_var, width=50, bg="#666666",
                                          fg="white")
        self.source_path_entry.pack(side=tk.LEFT, fill="x", expand=True)
        self.source_browse_button = tk.Button(source_frame, text="Browse", command=lambda: self.browse_path(self.source_path_var))
        self.source_browse_button.pack(side=tk.LEFT, padx=5)

        # Destination Path
        dest_frame = tk.Frame(path_frame, bg="#444444")
        dest_frame.pack(fill="x", pady=2)
        tk.Label(dest_frame, text="Destination:", bg="#444444", fg="white").pack(side=tk.LEFT, padx=5)
        self.destination_path_entry = tk.Entry(dest_frame, textvariable=self.destination_path_var, width=50,
                                               bg="#666666", fg="white")
        self.destination_path_entry.pack(side=tk.LEFT, fill="x", expand=True)
        self.destination_browse_button = tk.Button(dest_frame, text="Browse", command=lambda: self.browse_path(self.destination_path_var))
        self.destination_browse_button.pack(side=tk.LEFT, padx=5)

        # Control button (single toggle button)
        control_frame = tk.Frame(self.root, padx=10, pady=5)
        control_frame.pack(pady=5)
        self.toggle_button = tk.Button(control_frame, text="Start Monitoring", command=self.toggle_monitoring)
        self.toggle_button.pack(padx=5)

        # Activity Log area
        log_frame = tk.LabelFrame(self.root, text="Activity Log", padx=10, pady=10, bg="#444444", fg="white")
        log_frame.pack(padx=10, pady=10, fill="both", expand=True)

        self.log_text = scrolledtext.ScrolledText(log_frame, width=80, height=20, wrap=tk.WORD,
                                                  bg="#222222", fg="white", insertbackground="white")
        self.log_text.pack(fill="both", expand=True)
        self.log_text.config(state=tk.DISABLED)

    def configure_tags(self):
        self.log_text.tag_configure("info_tag", foreground="blue")
        self.log_text.tag_configure("success_tag", foreground="green")
        self.log_text.tag_configure("error_tag", foreground="red")
        self.log_text.tag_configure("timestamp_tag", foreground="gray")
        self.log_text.tag_configure("message_tag", foreground="white")

    def browse_path(self, path_var):
        """Opens a directory selection dialog and updates the corresponding StringVar."""
        initial_dir = path_var.get()
        if not Path(initial_dir).is_dir():
            initial_dir = None
        selected_dir = filedialog.askdirectory(initialdir=initial_dir)
        if selected_dir:
            path_var.set(selected_dir)
            self.update_toggle_button()

    def check_paths(self):
        # Get paths from the Entry widgets
        source_path = Path(self.source_path_var.get())
        destination_path = Path(self.destination_path_var.get())

        source_exists = source_path.is_dir()
        dest_exists = destination_path.is_dir()

        if not source_exists:
            messagebox.showerror("Error", f"Source directory not found: {source_path}")
            self.toggle_button.config(state=tk.DISABLED)
            return False
        if not dest_exists:
            messagebox.showerror("Error", f"Destination directory not found: {destination_path}")
            self.toggle_button.config(state=tk.DISABLED)
            return False
        return True

    def toggle_monitoring(self):
        if self.is_monitoring_active:
            self.stop_monitoring()
        else:
            self.start_monitoring()
        self.update_toggle_button()

    def start_monitoring(self):
        if not self.check_paths():
            return

        # Get current paths from the Entry widgets
        source_path = Path(self.source_path_var.get())
        destination_path = Path(self.destination_path_var.get())

        self.log_text.config(state=tk.NORMAL)
        self.log_text.delete(1.0, tk.END)
        self.log_text.config(state=tk.DISABLED)

        # Pass new paths to the AutoCollector handler
        self.handler = AutoCollector(source_path, destination_path, self.log_text)
        self.handler.report_message("Starting AutoCollector...", level="INFO")

        self.observer = Observer()
        self.observer.schedule(self.handler, str(source_path), recursive=True)
        self.observer.start()

        self.handler.report_message(f"Watching: {source_path}", level="INFO")
        self.handler.report_message(f"Destination: {destination_path}", level="INFO")

        self.handler.report_message("Performing initial scan of existing files...", level="INFO")
        self.initial_scan(self.handler)
        self.handler.report_message("Initial scan complete.", level="INFO")
        self.handler.report_message("Monitoring started. All activities will appear below.", level="INFO")

        self.is_monitoring_active = True
        self.toggle_path_entries(False)

    def stop_monitoring(self):
        if self.observer:
            self.observer.stop()
            self.observer.join()
            self.observer = None
            if self.handler:
                self.handler.report_message("Stopping AutoCollector...", level="INFO")
                self.handler.report_message("Monitoring stopped.", level="INFO")
            self.handler = None
            messagebox.showinfo("Info", "Monitoring stopped.")
        self.is_monitoring_active = False
        self.toggle_path_entries(True)

    def update_toggle_button(self):
        if self.is_monitoring_active:
            self.toggle_button.config(text="Stop Monitoring")
        else:
            self.toggle_button.config(text="Start Monitoring")

        if self.check_paths():
            self.toggle_button.config(state=tk.NORMAL)

    def toggle_path_entries(self, state):
        """Enables or disables the path entry widgets and browse buttons."""
        if state:  # Enable
            self.source_path_entry.config(state=tk.NORMAL)
            self.source_browse_button.config(state=tk.NORMAL)
            self.destination_path_entry.config(state=tk.NORMAL)
            self.destination_browse_button.config(state=tk.NORMAL)
        else:  # Disable
            self.source_path_entry.config(state=tk.DISABLED)
            self.source_browse_button.config(state=tk.DISABLED)
            self.destination_path_entry.config(state=tk.DISABLED)
            self.destination_browse_button.config(state=tk.DISABLED)

    def initial_scan(self, handler: AutoCollector):
        try:
            for p in handler.src.rglob("**/*"):
                handler.process(p)
        except Exception as e:
            handler.report_message(f"Error during initial scan: {e}", level="ERROR")

    def on_closing(self):
        if messagebox.askokcancel("Quit", "Do you want to stop monitoring and quit?"):
            self.stop_monitoring()
            self.root.destroy()


def main():
    root = tk.Tk()
    app = AutoCollectorApp(root)
    root.protocol("WM_DELETE_WINDOW", app.on_closing)
    root.mainloop()


if __name__ == "__main__":
    main()