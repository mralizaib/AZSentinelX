# ByteIT Security Alert Management System Architecture

## System Overview
The ByteIT Security Alert Management System (AZ Sentinel X) is a professional security monitoring and response platform that bridges the gap between raw security events and actionable intelligence.

## Data Flow & Integration
1. **Security Infrastructure**:
   - **Wazuh SIEM**: Primary source for security events and agent monitoring.
   - **SonicWall**: Network security logs and firewall alerts.
   - **Windows Event Logs**: OS-level security monitoring (Logon success/failure, service changes).
   - **FIM (File Integrity Monitoring)**: Monitoring critical system files and registry keys.

2. **Integration API Layer**:
   - **OpenSearch API**: Real-time querying of stored security events.
   - **Wazuh API**: Management of security agents and system status.
   - **Gmail SMTP**: Automated notification system for critical alerts.
   - **AI Search Engine**: LLM-driven analysis of security patterns ("Who did what and where").

3. **Intelligent Categorization Engine**:
   - **Critical (Level 15+)**: Immediate threats requiring instant response.
   - **High (Level 12-14)**: Serious security incidents.
   - **Medium (Level 7-11)**: Suspicious activities.
   - **Low (Level 1-6)**: Minor security events.
   - **FIM (Rule 553, 554)**: Specific file integrity changes.
   - **Misc Events**: Segregated informational logs (SonicWall warnings, Success logons, registry additions) to keep the security dashboard clean.

4. **Action & Visualization**:
   - **Flask Dashboard**: Interactive real-time monitoring.
   - **Automated Email Reports**: Scheduled or immediate notifications.
   - **Professional Exports**: Support for PDF, XLSX, and CSV (including 12-day historical searches).
   - **AI Insights**: Contextual analysis of security logs in professional Markdown format.

---
*Created for Project Presentation - January 2026*
