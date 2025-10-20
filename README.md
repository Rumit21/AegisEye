#AegisEye — Threat Analytics Dashboard  

AegisEye is a cybersecurity analytics dashboard designed to visualize and analyze simulated network and authentication logs — mimicking a modern Security Operations Center (SOC) interface.  
It leverages data analysis, visualization, and lightweight automation to help detect potential intrusions, anomalies, and threat patterns in real time.  

---

Project Overview  
This project simulates a centralized SOC dashboard that aggregates data from authentication, web, and firewall logs to identify:  
- Brute force login attempts  
- SQL injection probes  
- Suspicious access patterns  
- Port scans and high-frequency connection spikes  

The app uses Dash + Plotly for visualization and Python data analysis to generate synthetic logs, process alerts, and create detailed PDF reports — giving analysts a quick, intuitive snapshot of network health.

---

 Tech Stack  
| Layer | Technology |
|:------|:------------|
| Frontend | Plotly Dash |
| Backend | Flask (via Dash) |
| Data Processing | Pandas, NumPy |
| Reporting | ReportLab (PDF generation) |
| Visualization | Plotly Express |
| Log Simulation | Python Randomized Data Generator |

---

Key Features  
-Interactive KPI cards — Real-time metrics for alert counts, severities, and unique IPs  
- GeoIP mapping — Shows alert distribution by country  
- Drill-down details — Click any alert row to reveal related Auth/Web/Firewall activity  
- CSV & PDF exports— One-click data export for compliance or sharing  
- Synthetic data generator — Simulates continuous network activity for testing  

---

 Folder Structure 
 AegisEye/
│
├── app.py # Main Dash application
├── src/
│ ├── ingest.py # Data ingestion and alert generation logic
│ ├── ip_geo.py # GeoIP mapping for source IPs
│ ├── generate_sample_logs.py # Synthetic log generator
│ └── init.py
├── data/ # Contains generated CSV logs
├── requirements.txt
├── .gitignore
└── README.md

#How to Run Locally  

```bash
# 1. Clone the repository
git clone https://github.com/Rumit21/AegisEye.git
cd AegisEye

# 2. Set up virtual environment
python -m venv venv
source venv/Scripts/activate      # On Windows
# or
source venv/bin/activate          # On Linux/Mac

# 3. Install dependencies
pip install -r requirements.txt

# 4. Generate sample logs
python src/generate_sample_logs.py

# 5. Run the dashboard
python app.py
Then open your browser at http://127.0.0.1:8050
