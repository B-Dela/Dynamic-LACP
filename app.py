import os
import uuid
from flask import Flask, render_template, request, jsonify, send_file
from werkzeug.utils import secure_filename
import pdfplumber

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['OUTPUT_FOLDER'] = 'outputs'
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50 MB max file size
ALLOWED_EXTENSIONS = {'pdf'}

# Create directories if they don't exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(app.config['OUTPUT_FOLDER'], exist_ok=True)

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def count_pdf_pages(filepath):
    try:
        with pdfplumber.open(filepath) as pdf:
            return len(pdf.pages)
    except Exception as e:
        print(f"Error opening PDF: {e}")
        return 0

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze():
    if 'file' not in request.files:
        return jsonify({'error': 'No file part in the request'}), 400

    file = request.files['file']

    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400

    if not allowed_file(file.filename):
        return jsonify({'error': 'Invalid file type. Only PDF files are allowed.'}), 400

    if file:
        filename = secure_filename(file.filename)
        # Prevent concurrent overwrites by appending UUID
        unique_id = uuid.uuid4().hex[:8]
        safe_filename = f"{unique_id}_{filename}"
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], safe_filename)
        file.save(filepath)

        # Check page count
        page_count = count_pdf_pages(filepath)
        if page_count > 450:
            os.remove(filepath)
            return jsonify({'error': f'PDF has too many pages ({page_count}). Maximum allowed is 450.'}), 400

        try:
            from analyzer import parse_pdf
            from aggregator import aggregate_data
            from excel_generator import create_excel_report

            # Parse the PDF
            parsed_data = parse_pdf(filepath)

            if not parsed_data:
                return jsonify({'error': 'Could not extract valid student results from the PDF. Please check the file format.'}), 400

            # Aggregate the data
            aggregated_data = aggregate_data(parsed_data)

            # Generate the Excel report
            output_filename = f"analysis_{filename.rsplit('.', 1)[0]}_{unique_id}.xlsx"
            output_filepath = os.path.join(app.config['OUTPUT_FOLDER'], output_filename)
            create_excel_report(aggregated_data, output_filepath)

            return jsonify({
                'message': 'Analysis complete',
                'download_url': f'/download/{output_filename}'
            })

        except Exception as e:
            import traceback
            traceback.print_exc()
            return jsonify({'error': f'Error during analysis: {str(e)}'}), 500

@app.route('/download/<filename>')
def download(filename):
    safe_filename = secure_filename(filename)
    filepath = os.path.join(app.config['OUTPUT_FOLDER'], safe_filename)

    if os.path.exists(filepath):
        return send_file(filepath, as_attachment=True)
    else:
        return jsonify({'error': 'File not found'}), 404

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
