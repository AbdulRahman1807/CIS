import argparse
import http.server
import json
import os
import sys

# Keep track of target report file path globally
REPORT_FILE_PATH = "report.json"
TEMPLATES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "templates")

class AuditReportHandler(http.server.BaseHTTPRequestHandler):
    
    def log_message(self, format, *args):
        # Prevent spamming stderr/logs for every request unless required
        sys.stderr.write("%s - - [%s] %s\n" %
                         (self.address_string(),
                          self.log_date_time_string(),
                          format%args))

    def do_GET(self):
        if self.path == "/" or self.path == "/index.html":
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            
            # Read report data from disk
            report_data = None
            if os.path.exists(REPORT_FILE_PATH):
                try:
                    with open(REPORT_FILE_PATH, "r", encoding="utf-8") as f:
                        report_data = json.load(f)
                except Exception as e:
                    print(f"Error reading {REPORT_FILE_PATH}: {e}", file=sys.stderr)
            
            # Read template HTML
            html_template = "<html><body><h1>Report template missing</h1></body></html>"
            template_path = os.path.join(TEMPLATES_DIR, "report.html")
            if os.path.exists(template_path):
                try:
                    with open(template_path, "r", encoding="utf-8") as f:
                        html_template = f.read()
                except Exception as e:
                    print(f"Error reading HTML template: {e}", file=sys.stderr)
            else:
                # Fallback to absolute path search if templates folder is located differently
                # (e.g. workspace relative)
                fallback_path = os.path.join(os.getcwd(), "audit_agent", "templates", "report.html")
                if os.path.exists(fallback_path):
                    try:
                        with open(fallback_path, "r", encoding="utf-8") as f:
                            html_template = f.read()
                    except Exception as e:
                        pass
            
            # Prepare JSON script string to inject
            if report_data is not None:
                json_str = json.dumps(report_data)
            else:
                json_str = "null"
                
            # Replace placeholder with report JSON
            # Placeholder in HTML should be: /* REPORT_JSON_DATA */
            output_html = html_template.replace("/* REPORT_JSON_DATA */", f"window.AUDIT_REPORT = {json_str};")
            
            self.wfile.write(output_html.encode("utf-8"))
        elif self.path == "/api/report":
            # Optional api endpoint for convenience
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.end_headers()
            
            report_data = {}
            if os.path.exists(REPORT_FILE_PATH):
                try:
                    with open(REPORT_FILE_PATH, "r", encoding="utf-8") as f:
                        report_data = json.load(f)
                except Exception as e:
                    report_data = {"error": f"Failed to read report.json: {str(e)}"}
            else:
                report_data = {"error": "report.json file not found on disk"}
                
            self.wfile.write(json.dumps(report_data).encode("utf-8"))
        else:
            self.send_response(404)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"Not Found")

def run_server():
    global REPORT_FILE_PATH
    
    parser = argparse.ArgumentParser(description="Serve the CIS Audit Agent Web UI")
    parser.add_argument("--report", default="report.json", help="Path to report.json file")
    parser.add_argument("--port", type=int, default=8000, help="Port to listen on")
    
    args = parser.parse_args()
    REPORT_FILE_PATH = os.path.abspath(args.report)
    
    server_address = ("", args.port)
    httpd = http.server.HTTPServer(server_address, AuditReportHandler)
    print(f"CIS Audit Agent Web UI listening on http://localhost:{args.port}")
    print(f"Serving report from: {REPORT_FILE_PATH}")
    
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down server.")
        sys.exit(0)

if __name__ == "__main__":
    run_server()
