import sys
import os
import subprocess 
import hashlib 
from PySide6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                               QHBoxLayout, QPushButton, QMenuBar, QFileDialog, 
                               QTextEdit, QLabel, QProgressDialog)
from PySide6.QtCore import QThread, Signal, Slot, Qt

# NEW IMPORT for Plugin System
import importlib.util 

# Import your core analysis script functions
from acquisition import perform_forensic_imaging, verify_integrity
from analysis import perform_file_carving, analyze_disk_image, analyze_registry_hive, analyze_memory_dump 

# --- Console Output Redirect Class (Part 1, Step 2) ---
# This captures all stdout (print statements) and redirects them to the QTextEdit widget
class ConsoleRedirector(object):
    def __init__(self, widget):
        self.widget = widget

    def write(self, text):
        # Only append text that isn't empty, to prevent excessive blank lines
        if text.strip():
            self.widget.append(text.strip())

    def flush(self):
        pass # Required for file-like object

# --- 1. Worker Thread Class ---
class ForensicWorker(QThread):
    finished = Signal(str, str)
    progress_update = Signal(str)
    
    def __init__(self, func, *args, **kwargs):
        super().__init__()
        self.func = func
        self.args = args
        self.kwargs = kwargs
        self.setObjectName(f"WORKER-{func.__name__.upper()}")

    def run(self):
        self.progress_update.emit(f"Running task: {self.func.__name__}...")
        
        try:
            if self.func == perform_forensic_imaging:
                success, log_path = self.func(*self.args)
                if success:
                    self.finished.emit(self.func.__name__, f"Acquisition complete. Log: {log_path}")
                else:
                    self.finished.emit(self.func.__name__, "Acquisition failed. Check console for details.")
            
            # --- Analysis Logic & Plugin Logic ---
            elif self.func in [analyze_disk_image, perform_file_carving, analyze_registry_hive, analyze_memory_dump] or hasattr(self.func, '__self__') and isinstance(self.func.__self__, object):
                # The plugin.run() method is executed here.
                # If the function is a method (like run_plugin), it returns a summary message.
                result = self.func(*self.args) 
                
                # Check if the analysis function returned a string result (for plugin or summary)
                if isinstance(result, str) and result:
                     self.finished.emit(self.func.__name__, result)
                else:
                    self.finished.emit(self.func.__name__, f"Analysis for {self.func.__name__} finished successfully.")

        except Exception as e:
            self.finished.emit(self.func.__name__, f"Task failed with critical error: {e}")

# --- 2. Main Application Window Class ---
class DigitalForensicsSuite(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Digital Forensics Suite - Console")
        self.setGeometry(100, 100, 1000, 700)
        
        # --- Apply Dark Theme Stylesheet (Part 1, Step 1) ---
        dark_stylesheet = """
        QMainWindow { background-color: #1e1e1e; color: #d4d4d4; }
        QTextEdit { background-color: #252526; color: #d4d4d4; border: 1px solid #3c3c3c; font-family: 'Consolas', 'Courier New', monospace; }
        QLabel { color: #569cd6; font-weight: bold; }
        QMenuBar { background-color: #333333; color: #d4d4d4; }
        QMenuBar::item:selected { background-color: #007acc; }
        QMenu { background-color: #3c3c3c; border: 1px solid #555; }
        QMenu::item:selected { background-color: #007acc; }
        QPushButton { background-color: #007acc; color: white; border: none; padding: 5px 15px; }
        QStatusBar { background-color: #007acc; color: white; font-weight: bold; }
        """
        self.setStyleSheet(dark_stylesheet)
        
        # --- Data Storage ---
        self.current_image_path = None
        self.current_hive_path = None
        self.current_dump_path = None
        self.current_worker = None
        self.plugins = {} # Store dynamically loaded plugins
        
        # --- UI Components ---
        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        self.layout = QVBoxLayout(self.central_widget)
        
        # Output Console
        self.console = QTextEdit()
        self.console.setReadOnly(True)
        self.console.setFontPointSize(10) # Hacking-friendly font size
        self.layout.addWidget(QLabel("Analysis Console:"))
        self.layout.addWidget(self.console)
        
        # Redirect stdout and stderr (Part 1, Step 2)
        sys.stdout = ConsoleRedirector(self.console)
        sys.stderr = ConsoleRedirector(self.console) 
        
        # Status Bar
        self.statusBar().showMessage("Ready for operation.")
        
        self.load_plugins() # <<< ADDED: Load plugins before menu creation
        self.create_menu()


    def load_plugins(self):
        self.plugins = {}
        plugin_root = os.path.join(os.path.dirname(__file__), 'plugins')
        
        self.log("\n[+] Scanning for and loading external plugins...")
        
        for name in os.listdir(plugin_root):
            if os.path.isdir(os.path.join(plugin_root, name)) and not name.startswith('__'):
                # Assumes plugin code is named module_name/module_name.py
                plugin_file_name = f"{name}_parser.py" # Based on prompt structure
                plugin_file_path = os.path.join(plugin_root, name, plugin_file_name)

                if not os.path.exists(plugin_file_path):
                    continue

                try:
                    spec = importlib.util.spec_from_file_location(name, plugin_file_path)
                    module = importlib.util.module_from_spec(spec)
                    sys.modules[name] = module
                    spec.loader.exec_module(module)
                    
                    # Get the plugin class via a helper function from the module
                    plugin_class = getattr(module, 'get_plugin_class')()
                    
                    self.plugins[plugin_class.NAME] = plugin_class
                    self.log(f"|-- LOADED PLUGIN: {plugin_class.NAME}")
                    
                except Exception as e:
                    self.log(f"|-- FAILED to load plugin {name}: {e}")
        
        self.log(f"Loaded {len(self.plugins)} plugins.")

    def create_menu(self):
        menu_bar = self.menuBar()
        
        # --- File Menu (Acquisition/Loading) ---
        file_menu = menu_bar.addMenu("&File")
        
        acq_action = file_menu.addAction("Start Disk &Acquisition...")
        acq_action.triggered.connect(self.start_acquisition_dialog)
        
        load_action = file_menu.addAction("&Load Forensic Image...")
        load_action.triggered.connect(self.load_image_dialog)
        
        file_menu.addSeparator()
        
        verify_action = file_menu.addAction("&Verify Integrity (Hash Check)")
        verify_action.triggered.connect(self.start_integrity_check)
        
        # --- Analysis Menu ---
        analysis_menu = menu_bar.addMenu("&Analysis")
        
        fs_action = analysis_menu.addAction("&File System Listing (PyTSK3)")
        fs_action.triggered.connect(self.start_fs_analysis)
        
        carve_action = analysis_menu.addAction("Start &Data Carving...")
        carve_action.triggered.connect(self.start_carving_analysis)
        
        analysis_menu.addSeparator()

        reg_action = analysis_menu.addAction("&Windows Registry Analysis (Regipy)")
        reg_action.triggered.connect(self.start_registry_analysis)

        mem_action = analysis_menu.addAction("&Memory Analysis (Volatility3)")
        mem_action.triggered.connect(self.start_memory_analysis)
        
        # --- Plugins Menu (Part 2, Step 3) ---
        if self.plugins:
            plugins_menu = menu_bar.addMenu("&Plugins")
            for name, plugin_class in self.plugins.items():
                action = plugins_menu.addAction(name)
                # Use lambda to pass the plugin class to run_plugin
                action.triggered.connect(lambda checked, p=plugin_class: self.run_plugin(p))


    @Slot(str, str)
    def task_finished(self, func_name, message):
        self.log(f"*** TASK FINISHED: {func_name} ***")
        self.log(message)
        self.statusBar().showMessage(f"Task {func_name} completed.")
        self.current_worker = None

    def start_acquisition_dialog(self):
        # ... (Acquisition dialog and thread startup logic) ...
        self.log("Opening acquisition dialog...")
        
        source_device, _ = QFileDialog.getOpenFileName(self, "Select Source Device/File (Run as Admin for Devices)")
        output_image, _ = QFileDialog.getSaveFileName(self, "Save Output Forensic Image (.dd)")
        
        if source_device and output_image:
            log_file = output_image + ".log"
            self.log(f"Acquisition setup: Source={source_device}, Output={output_image}")
            self.statusBar().showMessage("Acquisition in progress...")

            self.current_worker = ForensicWorker(perform_forensic_imaging, source_device, output_image, log_file)
            self.current_worker.finished.connect(self.task_finished)
            self.current_worker.start()
    
    def start_integrity_check(self):
        if not self.current_image_path:
            self.log("ERROR: Please load an image first.")
            return
        self.log("Integrity check requires original source and log data, running dummy check...")
        self.statusBar().showMessage("Running dummy integrity check.")

    def load_image_dialog(self):
        path, _ = QFileDialog.getOpenFileName(self, "Select Forensic Image (.dd, .E01)", filter="Disk Images (*.dd *.raw *.img);;All Files (*)")
        if path:
            self.current_image_path = path
            self.log(f"Successfully loaded image: {path}. Ready for analysis.")
            self.statusBar().showMessage("Image loaded.")

    def start_fs_analysis(self):
        if not self.current_image_path:
            self.log("ERROR: Please load a forensic image first (File -> Load Forensic Image).")
            return
        self.log(f"Starting File System Analysis on {self.current_image_path}...")
        self.statusBar().showMessage("Analyzing file system...")
        self.current_worker = ForensicWorker(analyze_disk_image, self.current_image_path)
        self.current_worker.finished.connect(self.task_finished)
        self.current_worker.start()

    def start_carving_analysis(self):
        if not self.current_image_path:
            self.log("ERROR: Please load a forensic image first (File -> Load Forensic Image).")
            return
        output_dir = "carved_files_output"
        self.log(f"Starting Data Carving on {self.current_image_path}...")
        self.statusBar().showMessage("Carving unallocated space...")
        self.current_worker = ForensicWorker(perform_file_carving, self.current_image_path, output_dir)
        self.current_worker.finished.connect(self.task_finished)
        self.current_worker.start()

    def start_registry_analysis(self):
        hive_path, _ = QFileDialog.getOpenFileName(self, "Select Registry Hive File (e.g., SYSTEM_TEST_HIVE.DAT)", filter="Registry Hives (*.dat *.hiv);;All Files (*)")
        if hive_path:
            self.log(f"Starting Registry Analysis on {hive_path}...")
            self.statusBar().showMessage("Analyzing Registry...")
            self.current_worker = ForensicWorker(analyze_registry_hive, hive_path, "SYSTEM")
            self.current_worker.finished.connect(self.task_finished)
            self.current_worker.start()

    def start_memory_analysis(self):
        dump_path, _ = QFileDialog.getOpenFileName(self, "Select Memory Dump File (.dmp, .raw)", filter="Memory Dumps (*.dmp *.raw);;All Files (*)")
        if dump_path:
            self.log(f"Starting Volatility3 Memory Analysis on {dump_path}...")
            self.statusBar().showMessage("Analyzing RAM dump...")
            self.current_worker = ForensicWorker(analyze_memory_dump, dump_path)
            self.current_worker.finished.connect(self.task_finished)
            self.current_worker.start()

    # --- Plugin Execution Logic (Part 2, Step 3) ---
    def run_plugin(self, plugin_class):
        if not self.current_image_path and plugin_class.TARGET_TYPE == "disk_image":
            self.log("ERROR: Plugin requires a loaded forensic image (File -> Load Forensic Image).")
            return
            
        self.log(f"Starting Plugin: {plugin_class.NAME}...")
        self.statusBar().showMessage(f"Running custom plugin: {plugin_class.NAME}...")
        
        # Instantiate and run the plugin in the worker thread
        # The constructor must match the plugin interface defined in browser_parser.py
        plugin_instance = plugin_class(self.current_image_path, "plugin_output")
        
        # We pass the instance's .run method to the worker
        self.current_worker = ForensicWorker(plugin_instance.run)
        self.current_worker.finished.connect(self.task_finished)
        self.current_worker.start()

if __name__ == '__main__':
    QThread.currentThread().setObjectName("MAIN_GUI_THREAD")

    try:
        app = QApplication(sys.argv)
        window = DigitalForensicsSuite()
        window.show()
        sys.exit(app.exec())
    except ImportError:
        print("CRITICAL ERROR: PySide6 not installed. Please run: pip install PySide6")
        sys.exit(1)