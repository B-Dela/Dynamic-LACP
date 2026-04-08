import pdfplumber
import re

def parse_pdf(filepath):
    """
    Parses the WASSCE PDF to extract student results.
    Returns a list of dictionaries with structure:
    [{
        'gender': 'MALE' | 'FEMALE',
        'results': { 'SUBJECT NAME': 'GRADE', ... }
    }, ...]
    """
    students_data = []

    with pdfplumber.open(filepath) as pdf:
        for page in pdf.pages:
            tables = page.extract_tables()
            for table in tables:
                # The provided image shows columns: INDEX NUMBER, NAME, GENDER, DOB, RESULTS
                # Sometimes headers are on the first row, sometimes not. Let's find indices dynamically or assume fixed positions.
                # Assuming index based on the screenshot:
                # 0: INDEX NUMBER, 1: NAME, 2: GENDER, 3: DOB, 4: RESULTS

                header = table[0] if table else []
                # Simple check if it's the header row
                start_idx = 1 if len(header) > 0 and 'INDEX NUMBER' in str(header[0]).upper() else 0

                for row in table[start_idx:]:
                    if len(row) < 5:
                        continue

                    gender_str = str(row[2]).strip().upper()
                    results_str = str(row[4]).strip()

                    if not gender_str or not results_str or gender_str not in ['MALE', 'FEMALE']:
                        continue

                    # Parse results string: "SOCIAL STUDIES - C4 , ENGLISH LANG - B3 , ..."
                    # Handle varying spaces and newlines
                    # First, replace newlines with spaces to make it a single line
                    results_str = results_str.replace('\n', ' ')

                    # Split by comma
                    subject_grade_pairs = [pair.strip() for pair in results_str.split(',')]

                    student_results = {}
                    for pair in subject_grade_pairs:
                        if not pair:
                            continue

                        # Split by hyphen (-) to get subject and grade
                        parts = pair.split('-')
                        if len(parts) >= 2:
                            # Rejoin in case subject name has hyphens (e.g. LIT-IN-ENGLISH)
                            subject = '-'.join(parts[:-1]).strip().upper()
                            grade = parts[-1].strip().upper()

                            # Clean up grade - expecting A1, B2, B3, C4, C5, C6, D7, E8, F9
                            # Sometimes there might be extra spaces or characters, extract just the 2 chars
                            match = re.search(r'([A-F][1-9])', grade)
                            if match:
                                clean_grade = match.group(1)
                                student_results[subject] = clean_grade

                    if student_results:
                        students_data.append({
                            'gender': gender_str,
                            'results': student_results
                        })

    return students_data
