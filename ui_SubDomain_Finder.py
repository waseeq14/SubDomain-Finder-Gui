import sys
import os
import json
import re
import dns.resolver
import requests
from functools import partial
from threading import Thread
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QLabel, QLineEdit,
    QPushButton, QTextEdit, QComboBox, QFileDialog, QMessageBox, QTabWidget,
    QProgressBar
)
from PySide6.QtGui import QIcon
from PySide6.QtCore import QObject, Signal

API_FILE = './api.json'
REQUIRED_APIS = ['virustotal', 'securitytrails']

class SignalEmitter(QObject):
    progress_updated = Signal(int)
    update_output = Signal(list)
    update_api_output = Signal(str, list)

def load_api_keys():
    if not os.path.exists(API_FILE):
        print(f"Config file does not exist. Initializing with empty keys.\n")
        return {}

    try:
        with open(API_FILE, 'r') as file:
            config = json.load(file)
    except json.JSONDecodeError:
        return {}

    return config

def save_api_keys(api_keys):
    with open(API_FILE, 'w') as file:
        json.dump(api_keys, file, indent=4)

def validate_api_key(api_key):
    pattern = r'^[a-zA-Z0-9_-]{30,}$'
    return re.match(pattern, api_key) is not None

def fetch_subdomains_from_virustotal(domain, api_key):
    url = f"https://www.virustotal.com/api/v3/domains/{domain}/subdomains"
    headers = {
        "x-apikey": api_key
    }
    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        data = response.json()
        subdomains = [item['id'] for item in data.get('data', [])]
        return subdomains
    else:
        return []

def fetch_subdomains_from_dnsdumpster(domain):
    url = "https://api.hackertarget.com/hostsearch/?q=" + domain
    response = requests.get(url)

    if response.status_code == 200:
        subdomains = [line.split(',')[0] for line in response.text.splitlines()]
        return subdomains
    else:
        return []

def fetch_subdomains_from_securitytrails(domain, api_key):
    url = f"https://api.securitytrails.com/v1/domain/{domain}/subdomains"
    headers = {
        "APIKEY": api_key
    }
    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        data = response.json()
        subdomains = [f"{sub}.{domain}" for sub in data['subdomains']]
        return subdomains
    else:
        return []

def subdomain_enum(domain, wordlist, progress_callback):
    output = []
    subdomains = []
    with open(wordlist, 'r') as file:
        subdomains = file.read().splitlines()

    total_subdomains = len(subdomains)
    progress_step = 100 / total_subdomains
    current_progress = 0

    for idx, subdomain in enumerate(subdomains, 1):
        try:
            full_domain = f"{subdomain}.{domain}"
            result = dns.resolver.resolve(full_domain, 'A')
            for ipval in result:
                output_line = f'{full_domain} | {ipval.to_text()}'
                output.append(output_line)

            current_progress = idx * progress_step
            progress_callback.progress_updated.emit(int(current_progress))
        except Exception as e:
            pass
    
    progress_callback.progress_updated.emit(int(100))
    return output

def enumerate_with_api(domain, api_keys, signal_emitter):
    if api_keys.get('virustotal'):
        vt_subdomains = fetch_subdomains_from_virustotal(domain, api_keys.get('virustotal'))
        signal_emitter.progress_updated.emit(33)
        signal_emitter.update_api_output.emit("VirusTotal", vt_subdomains)
    else:
        signal_emitter.update_api_output.emit("VirusTotal", ["The API key has not been set for VirusTotal."])

    if api_keys.get('securitytrails'):
        st_subdomains = fetch_subdomains_from_securitytrails(domain, api_keys.get('securitytrails'))
        signal_emitter.progress_updated.emit(66)
        signal_emitter.update_api_output.emit("SecurityTrails", st_subdomains)
    else:
        signal_emitter.update_api_output.emit("SecurityTrails", ["The API key has not been set for SecurityTrails."])

    dns_subdomains = fetch_subdomains_from_dnsdumpster(domain)
    signal_emitter.progress_updated.emit(100)
    signal_emitter.update_api_output.emit("DNS Dumpster", dns_subdomains)


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()

        self.setWindowIcon(QIcon('lookup.png'))

        self.setWindowTitle("SubDomain Finder")
        self.setGeometry(100, 100, 1000, 600)

        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)

        self.layout = QVBoxLayout()
        self.centralWidget().setLayout(self.layout)

        self.init_ui()
        self.api_keys = load_api_keys()  # Initialize API keys when GUI starts

    def init_ui(self):
        # Domain Input
        self.domain_label = QLabel("Domain:")
        self.domain_input = QLineEdit()
        self.domain_input.setPlaceholderText("Enter domain (without www. or https://)")

        # Wordlist Selection
        self.wordlist_label = QLabel("Wordlist:")
        self.wordlist_path = QLabel("No wordlist selected...")
        self.browse_button = QPushButton("Browse...")
        self.browse_button.clicked.connect(self.browse_wordlist)

        # Output TextArea
        self.output_label = QLabel("Output:")
        self.output_text = QTextEdit()
        self.output_text.setReadOnly(True)
        self.output_text.setMinimumHeight(200)

        # Progress Bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setMinimum(0)
        self.progress_bar.setMaximum(100)

        # Buttons for SubDomain Enumeration
        self.enum_wordlist_button = QPushButton("Enumerate with Wordlist")
        self.enum_wordlist_button.clicked.connect(self.enumerate_with_wordlist)

        self.enum_api_button = QPushButton("Enumerate with API")
        self.enum_api_button.clicked.connect(self.enumerate_with_api)

        # Save Output Button
        self.save_output_button = QPushButton("Save Output")
        self.save_output_button.clicked.connect(self.save_output)

        # API Key Setting
        self.api_label = QLabel("API Key:")
        self.api_input = QLineEdit()
        self.api_input.setPlaceholderText("Enter API key")

        self.set_api_button = QPushButton("Set API Key")
        self.set_api_button.clicked.connect(self.set_api_key)

        self.service_label = QLabel("Service:")
        self.service_combo = QComboBox()
        self.service_combo.addItem("No Service Selected")
        self.service_combo.addItems(REQUIRED_APIS)
        self.service_combo.currentIndexChanged.connect(self.service_selected)

        # Buttons for API Actions
        self.clear_api_button = QPushButton("Clear API Key")
        self.clear_api_button.clicked.connect(self.clear_api_key)

        self.get_api_button = QPushButton("Get API Key")
        self.get_api_button.clicked.connect(self.get_api_key)

        # Help Tab
        self.help_tab = QTabWidget()

        help_tab1 = QWidget()
        help_tab1_layout = QVBoxLayout()
        help_tab1_text = QLabel("""Instructions:\n1. Enter the domain name without www. or https://
2. Select a wordlist file for enumeration.
3. Use 'Enumerate with Wordlist' button to find subdomains using the selected wordlist.
4. Use 'Enumerate with API' button for API-based enumeration.
5. Manage API keys by selecting a service, entering an API key, and using the respective buttons to set, clear, or get API keys for VirusTotal and SecurityTrails.""")

        help_tab1_layout.addWidget(help_tab1_text)
        help_tab1.setLayout(help_tab1_layout)

        self.help_tab.addTab(help_tab1, "How to Use")

        # Adding Widgets to Main Layout
        self.layout.addWidget(self.domain_label)
        self.layout.addWidget(self.domain_input)
        self.layout.addWidget(self.wordlist_label)
        self.layout.addWidget(self.wordlist_path)
        self.layout.addWidget(self.browse_button)
        self.layout.addWidget(self.output_label)
        self.layout.addWidget(self.output_text)
        self.layout.addWidget(self.progress_bar)
        self.layout.addWidget(self.enum_wordlist_button)
        self.layout.addWidget(self.enum_api_button)
        self.layout.addWidget(self.save_output_button)
        self.layout.addWidget(self.api_label)
        self.layout.addWidget(self.api_input)
        self.layout.addWidget(self.set_api_button)
        self.layout.addWidget(self.service_label)
        self.layout.addWidget(self.service_combo)
        self.layout.addWidget(self.clear_api_button)
        self.layout.addWidget(self.get_api_button)
        self.layout.addWidget(self.help_tab)

    def set_api_key(self):
        service_name = self.service_combo.currentText().lower()
        
        if not service_name or service_name == "no service selected":
            QMessageBox.warning(self, "Service Error", "No service is selected.")
            return
        
        current_api_key = self.api_keys.get(service_name)

        if current_api_key:
            replace = QMessageBox.question(self, "API Key Replacement", 
                                        f"An API key for {service_name} is already set. Do you want to replace it?",
                                        QMessageBox.Yes | QMessageBox.No)
            if replace == QMessageBox.No:
                self.api_input.clear()
                QMessageBox.information(self, "API Key", f"Keeping the existing API key for {service_name}.")
                return
        
        api_key = self.api_input.text().strip()

        if not validate_api_key(api_key):
            self.api_input.clear()
            QMessageBox.warning(self, "API Key Error", f"Invalid API key format for {service_name}. API key must match the required format.")
            return
        
        self.api_keys[service_name] = api_key
        save_api_keys(self.api_keys)
        QMessageBox.information(self, "API Key Set", f"API key for {service_name} has been set.")

    def clear_api_key(self):
        service_name = self.service_combo.currentText().lower()

        if not service_name or service_name == "no service selected":
            QMessageBox.warning(self, "Service Error", "No service is selected.")
            return

        if service_name in self.api_keys:
            del self.api_keys[service_name]
            save_api_keys(self.api_keys)
            QMessageBox.information(self, "API Key Cleared", f"API key for {service_name} has been cleared.")
        else:
            QMessageBox.warning(self, "API Key Error", f"No API key set for {service_name}.")

    def get_api_key(self):
        service_name = self.service_combo.currentText().lower()

        if not service_name or service_name == "no service selected":
            QMessageBox.warning(self, "Service Error", "No service is selected.")
            return

        api_key = self.api_keys.get(service_name)

        if api_key:
            QMessageBox.information(self, "API Key", f"The API key for {service_name} is: {api_key}")
        else:
            QMessageBox.warning(self, "API Key Error", f"No API key set for {service_name}.")


    def service_selected(self, index):
        service_name = self.service_combo.itemText(index).lower()
        api_key = self.api_keys.get(service_name)

    def browse_wordlist(self):
        wordlist_file, _ = QFileDialog.getOpenFileName(self, "Select Wordlist File", "", "Text Files (*.txt)")

        if wordlist_file:
            self.wordlist_path.setText(wordlist_file)

    # Modify enumerate_with_wordlist to handle threading and progress
    def enumerate_with_wordlist(self):
        domain = self.domain_input.text().strip()
        wordlist = self.wordlist_path.text().strip()

        if not domain:
            QMessageBox.warning(self, "Domain Error", "Please enter a domain name.")
            return

        if not os.path.exists(wordlist):
            QMessageBox.warning(self, "Wordlist Error", "Selected wordlist file does not exist.")
            return

        # Disable all other components while loading
        self.set_enabled_components(False)

        signal_emitter = SignalEmitter()
        signal_emitter.progress_updated.connect(self.progress_bar.setValue)
        signal_emitter.update_output.connect(self.update_output)  # Connect update signal

        wordlist_thread = Thread(target=partial(self.run_wordlist_enum, domain, wordlist, signal_emitter))
        wordlist_thread.start()

    def run_wordlist_enum(self, domain, wordlist, signal_emitter):
        output = subdomain_enum(domain, wordlist, signal_emitter)
        # Emit signal to update output in GUI thread
        signal_emitter.update_output.emit(output)
        # Enable all components after loading completes
        self.set_enabled_components(True)

    def update_output(self, output):
        self.output_text.clear()
        self.output_text.append(f"Using Wordlist: {self.wordlist_path.text()}\n")
        for line in output:
            self.output_text.append(line)
        self.output_text.append("")  # Blank line for separation

    def enumerate_with_api(self):
        domain = self.domain_input.text().strip()

        if not domain:
            QMessageBox.warning(self, "Domain Error", "Please enter a domain name.")
            return

        # Disable all other components while loading
        self.set_enabled_components(False)

        signal_emitter = SignalEmitter()
        signal_emitter.progress_updated.connect(self.progress_bar.setValue)
        signal_emitter.update_api_output.connect(self.update_api_output)  # Connect update signal

        api_thread = Thread(target=partial(self.run_api_enum, domain, self.api_keys, signal_emitter))
        api_thread.start()

    def run_api_enum(self, domain, api_keys, signal_emitter):
        enumerate_with_api(domain, api_keys, signal_emitter)
        # Enable all components after loading completes
        self.set_enabled_components(True)

    def update_api_output(self, source, subdomains):
        self.output_text.append(f"From {source}:")
        if subdomains:
            for subdomain in subdomains:
                self.output_text.append(f"  - {subdomain}")
        else:
            self.output_text.append(f"  No subdomains found from {source}.")
        self.output_text.append("")  # Blank line for separation

    def set_enabled_components(self, enabled):
        # Enable or disable all UI components except the progress bar
        for widget in self.centralWidget().findChildren(QWidget):
            if widget != self.progress_bar:
                widget.setEnabled(enabled)

    def save_output(self):
        if self.output_text.toPlainText().strip() == "":
            QMessageBox.warning(self, "Save Output Error", "There are no results to be saved.")
            return

        save_file, _ = QFileDialog.getSaveFileName(self, "Save Output File", "", "Text Files (*.txt)")

        if save_file:
            with open(save_file, 'w') as file:
                file.write(self.output_text.toPlainText())
            QMessageBox.information(self, "Save Output", "Output saved successfully.")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())
