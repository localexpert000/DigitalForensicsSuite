import sys
import os
from PySide6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                               QHBoxLayout, QPushButton, QMenuBar, QFileDialog, 
                               QTextEdit, QLabel, QProgressDialog)
from PySide6.QtCore import QThread, Signal, Slot, Qt

# Import your core analysis script functions
from acquisition import perform_forensic_imaging, verify_integrity
from analysis import perform_file_carving, analyze_disk_image, analyze_registry_hive

# --- 1. Worker Thread Class ---
# This class runs your heavy analysis functions in the background
class ForensicWorker(QThread):
    # Signals to communicate results back to the main GUI thread
    finished = Signal(str, str) # signal(function_name, message)
    progress_update = Signal(str) # signal(status_message)
    
    def __init__(self, func, *args, **kwargs):
        super().__init__()
        self.func = func
        self.args = args
        self.kwargs = kwargs

    def run(self):
        # Placeholder for real-time progress update from dcfldd (Advanced integration)
        self.progress_update.emit(f"Running task: {self.func.__name__}...")
        
        try:
            # Execute the passed-in function (e.g., perform_forensic_imaging)
            if self.func == perform_forensic_imaging:
                success, log_path = self.func(*self.args)
                if success:
                    self.finished.emit(self.func.__name__, f"Acquisition complete. Log: {log_path}")
                else:
                    self.finished.emit(self.func.__name__, "Acquisition failed. Check console for details.")
            
            # Simplified execution for analysis functions
            elif self.func in [analyze_disk_image, perform_file_carving, analyze_registry_hive]:
                self.func(*self.args) # Run the analysis function
                self.finished.emit(self.func.__name__, f"Analysis for {self.func.__name__} finished successfully.")

        except Exception as e:
            self.finished.emit(self.func.__name__, f"Task failed with critical error: {e}")


# --- 2. Main Application Window Class ---
class DigitalForensicsSuite(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Digital Forensics Suite - Console")
        self.setGeometry(100, 100, 1000, 700) # Set initial window size
        
        # --- UI Components ---
        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        self.layout = QVBoxLayout(self.central_widget)
        
        # Output Console (The 'Hacking Vibe' log area)
        self.console = QTextEdit()
        self.console.setReadOnly(True)
        self.layout.addWidget(QLabel("Analysis Console:"))
        self.layout.addWidget(self.console)
        
        # Status Bar
        self.statusBar().showMessage("Ready for operation.")
        
        self.create_menu()
        self.current_worker = None

    def create_menu(self):
        menu_bar = self.menuBar()
        
        # --- File Menu (Acquisition/Loading) ---
        file_menu = menu_bar.addMenu("&File")
        
        # Acquisition Action (P1 Feature)
        acq_action = file_menu.addAction("Start Disk &Acquisition...")
        acq_action.triggered.connect(self.start_acquisition_dialog)
        
        # Load Image Action
        load_action = file_menu.addAction("&Load Forensic Image...")
        load_action.triggered.connect(self.load_image_dialog)
        
        # --- Analysis Menu ---
        analysis_menu = menu_bar.addMenu("&Analysis")
        
        # File System Analysis (P1 Feature)
        fs_action = analysis_menu.addAction("&File System Listing (PyTSK3)")
        fs_action.triggered.connect(self.start_fs_analysis)
        
        # Data Carving (P1/P2 Feature)
        carve_action = analysis_menu.addAction("Start &Data Carving...")
        carve_action.triggered.connect(self.start_carving_analysis)
        
        # Registry Analysis (P1/P2 Feature)
        reg_action = analysis_menu.addAction("&Windows Registry Analysis (Regipy)")
        reg_action.triggered.connect(self.start_registry_analysis)

        # Memory Analysis (P2 Feature)
        mem_action = analysis_menu.addAction("&Memory Analysis (Volatility3)")
        mem_action.triggered.connect(self.start_memory_analysis)

        self.current_image_path = None
        self.current_hive_path = None


    # --- 3. Dialogs and Task Runners ---

    def log(self, message):
        """Simple logging to the internal console."""
        self.console.append(f"[{QThread.currentThread().objectName()}] {message}")
    
    # Slot to receive messages from the background worker
    @Slot(str, str)
    def task_finished(self, func_name, message):
        self.log(f"*** TASK FINISHED: {func_name} ***")
        self.log(message)
        self.statusBar().showMessage(f"Task {func_name} completed.")
        self.current_worker = None # Free up the worker

    def start_acquisition_dialog(self):
        self.log("Opening acquisition dialog...")
        
        # --- Simplified Dialog for Demo ---
        # In a real tool, this dialog collects source device, output path, and case info.
        source_device = QFileDialog.getOpenFileName(self, "Select Source Device/File (Run as Admin for Devices)")
        output_image = QFileDialog.getSaveFileName(self, "Save Output Forensic Image (.dd)")
        
        if source_device[0] and output_image[0]:
            log_file = output_image[0] + ".log"
            self.log(f"Acquisition setup: Source={source_device[0]}, Output={output_image[0]}")
            self.statusBar().showMessage("Acquisition in progress...")

            # --- 4. Start Threaded Execution ---
            self.current_worker = ForensicWorker(perform_forensic_imaging, source_device[0], output_image[0], log_file)
            self.current_worker.finished.connect(self.task_finished)
            self.current_worker.start()
    
    def load_image_dialog(self):
        # Load any DD or E01 file
        path, _ = QFileDialog.getOpenFileName(self, "Select Forensic Image (.dd, .E01)")
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
        
        # Start the PyTSK3 task in a background thread
        self.current_worker = ForensicWorker(analyze_disk_image, self.current_image_path)
        self.current_worker.finished.connect(self.task_finished)
        self.current_worker.start()

    def start_carving_analysis(self):
        if not self.current_image_path:
            self.log("ERROR: Please load a forensic image first (File -> Load Forensic Image).")
            return
            
        output_dir = "carved_files_output" # Static output folder for this demo
        self.log(f"Starting Data Carving on {self.current_image_path}...")
        self.statusBar().showMessage("Carving unallocated space...")
        
        # Start the Carving task in a background thread
        self.current_worker = ForensicWorker(perform_file_carving, self.current_image_path, output_dir)
        self.current_worker.finished.connect(self.task_finished)
        self.current_worker.start()

    def start_registry_analysis(self):
        # --- Simplified Registry Loading ---
        # In a real tool, this extracts the hive from the loaded image (self.current_image_path)
        hive_path, _ = QFileDialog.getOpenFileName(self, "Select Registry Hive File (e.g., NTUSER.DAT)")
        if hive_path:
            self.current_hive_path = hive_path
            self.log(f"Starting Registry Analysis on {self.current_hive_path}...")
            self.statusBar().showMessage("Analyzing Registry...")

            # Start the Regipy task in a background thread
            # NOTE: We pass a mock name 'SOFTWARE' as Regipy needs a hive name for context
            self.current_worker = ForensicWorker(analyze_registry_hive, self.current_hive_path, "SOFTWARE")
            self.current_worker.finished.connect(self.task_finished)
            self.current_worker.start()

    def start_memory_analysis(self):
        # Memory analysis is similar to Registry: load the raw dump file
        dump_path, _ = QFileDialog.getOpenFileName(self, "Select Memory Dump File (.dmp, .raw)")
        if dump_path:
            self.log(f"Starting Volatility3 Memory Analysis on {dump_path}...")
            self.statusBar().showMessage("Analyzing RAM dump...")
            
            # Start the Volatility task in a background thread
            self.current_worker = ForensicWorker(analyze_memory_dump, dump_path)
            self.current_worker.finished.connect(self.task_finished)
            self.current_worker.start()

if __name__ == '__main__':
    # Give the main thread a name for logging purposes
    QThread.currentThread().setObjectName("MAIN_GUI_THREAD")

    app = QApplication(sys.argv)
    window = DigitalForensicsSuite()
    window.show()
    sys.exit(app.exec())