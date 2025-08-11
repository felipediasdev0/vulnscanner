from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
import asyncio
from scanner import run_scan

app = Flask(__name__)
CORS(app)  # <=== ADICIONADO

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    data = request.get_json(force=True)
    targets = data.get('targets')
    concurrency = data.get('concurrency', 5)

    if not targets or not isinstance(targets, list):
        return jsonify({"error": "'targets' deve ser uma lista de URLs"}), 400

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        report = loop.run_until_complete(run_scan(targets, concurrency=concurrency))
    finally:
        loop.close()

    findings = [{
        "target": f.target,
        "category": f.category,
        "name": f.name,
        "severity": f.severity,
        "detail": f.detail,
        "evidence": f.evidence
    } for f in report.findings]

    return jsonify({
        "started_at": report.started_at,
        "finished_at": report.finished_at,
        "findings": findings
    })

if __name__ == '__main__':
    app.run(debug=True, port=8000)
