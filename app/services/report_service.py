import io
import datetime
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
from app.database import get_monitored_urls_col

class ReportService:
    """Service generating downloadable threat intelligence audit PDF reports."""

    @staticmethod
    def generate_threat_report():
        """Compile executive PDF report of all monitored websites and threat standings."""
        buffer = io.BytesIO()
        pdf = canvas.Canvas(buffer, pagesize=A4)
        width, height = A4

        y = height - 40

        # Title
        pdf.setFont("Helvetica-Bold", 18)
        pdf.drawString(40, y, "TamperTrace – Threat Intelligence Report")
        y -= 30

        pdf.setFont("Helvetica", 10)
        pdf.drawString(40, y, f"Generated on: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        y -= 30

        # Table Header
        pdf.setFont("Helvetica-Bold", 11)
        pdf.drawString(40, y, "URL")
        pdf.drawString(340, y, "Threat Status")
        y -= 15

        pdf.line(40, y, 550, y)
        y -= 20

        pdf.setFont("Helvetica", 10)
        records = list(get_monitored_urls_col().find())

        for rec in records:
            url = rec.get("url", "N/A")
            change_detected = rec.get("change_detected", False)
            vt_malicious = rec.get("vt_malicious", 0)

            if change_detected:
                status = "DEFACED"
            elif vt_malicious > 0:
                status = "MALICIOUS"
            else:
                status = "CLEAN"

            if y < 60:
                pdf.showPage()
                y = height - 40
                pdf.setFont("Helvetica", 10)

            pdf.drawString(40, y, str(url)[:55])
            pdf.drawString(340, y, status)
            y -= 18

        # Summary Section
        y -= 20
        pdf.setFont("Helvetica-Bold", 11)
        pdf.drawString(40, y, "Summary Overview")
        y -= 15
        pdf.setFont("Helvetica", 10)

        total = len(records)
        defaced = len([r for r in records if r.get("change_detected")])
        malicious = len([r for r in records if r.get("vt_malicious", 0) > 0])
        clean = total - defaced - malicious

        pdf.drawString(40, y, f"Total Monitored Websites: {total}")
        y -= 15
        pdf.drawString(40, y, f"Confirmed Defaced: {defaced}")
        y -= 15
        pdf.drawString(40, y, f"Malicious Assets: {malicious}")
        y -= 15
        pdf.drawString(40, y, f"Verified Clean: {clean}")

        pdf.save()
        buffer.seek(0)
        return buffer
