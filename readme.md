# SubDomain Finder

SubDomain Finder is a GUI-based tool to discover subdomains using either a wordlist or APIs like VirusTotal and SecurityTrails. This tool is built using Python and PySide6 for the user interface.

## Features
- **Subdomain Enumeration with Wordlist**: Use a custom wordlist to brute-force subdomains.
- **API-based Subdomain Enumeration**: Fetch subdomains via APIs like VirusTotal and SecurityTrails.
- **DNS Dumpster Integration**: Additional subdomain results using DNS Dumpster.
- **API Key Management**: Easily manage API keys directly in the GUI.
- **Progress Bar**: Visual feedback for ongoing operations.
- **Save Output**: Save results to a text file.

## Prerequisites
- Python 3.6+
- PySide6
- Requests
- dnspython

## Installation

1. Clone the repository:
    ```bash
    git clone https://github.com/yourusername/subdomain-finder.git
    cd subdomain-finder
    ```

2. Install the required Python libraries:
    ```bash
    pip install -r requirements.txt
    ```

3. You can manage the API keys for **VirusTotal** and **SecurityTrails** by either manually editing the `api.json` file or using the tool's GUI.

## Usage

1. Run the application:
    ```bash
    python ui_SubDomain_Finder.py
    ```

2. Enter the domain you want to enumerate (without `www.` or `https://`).
   
3. Select the method of enumeration:
    - **Wordlist**: Choose a text file containing possible subdomain names.
    - **API**: Make sure your API keys for VirusTotal and SecurityTrails are set.

4. Hit **Enumerate** and monitor the progress bar.

5. View results in the output section and save the output if needed.

### Wordlist Enumeration

- Select a wordlist file by clicking the **Browse...** button.
- Click **Enumerate with Wordlist** to begin the enumeration.

### API-based Enumeration

- Ensure your API keys are set in the **API Key** section.
- Click **Enumerate with API** to fetch subdomains from VirusTotal, SecurityTrails, and DNS Dumpster.

### Managing API Keys

1. Select a service (VirusTotal or SecurityTrails) from the dropdown.
2. Enter the API key and click **Set API Key**.
3. Use **Get API Key** to retrieve the current key or **Clear API Key** to remove it.

## License
This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Acknowledgments
- **VirusTotal API** for subdomain data.
- **SecurityTrails API** for subdomain enumeration.
- **DNS Dumpster** for DNS-based subdomain discovery.

