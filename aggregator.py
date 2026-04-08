def aggregate_data(parsed_students):
    """
    Takes parsed student data and aggregates it by Subject, Gender, and Grade.
    Returns a dictionary of structure:
    {
        'SUBJECT_NAME': {
            'A1': {'B': 0, 'G': 0, 'T': 0},
            'B2': {'B': 0, 'G': 0, 'T': 0},
            ...
        }
    }
    """

    # Initialize empty aggregation dictionary
    agg_data = {}

    # Standardize grades
    grades = ['A1', 'B2', 'B3', 'C4', 'C5', 'C6', 'D7', 'E8', 'F9']

    for student in parsed_students:
        gender = student['gender'].upper()
        if gender == 'MALE':
            gender_key = 'B'
        elif gender == 'FEMALE':
            gender_key = 'G'
        else:
            continue

        results = student.get('results', {})

        for subject, grade in results.items():
            # Standardize subject names (e.g. "ENGLISH LANG" -> "English Language")
            std_subject = standardize_subject(subject)

            if std_subject not in agg_data:
                # Initialize subject with all zeros for all grades
                agg_data[std_subject] = {
                    g: {'B': 0, 'G': 0, 'T': 0} for g in grades
                }
                agg_data[std_subject]['REGISTERED'] = {'B': 0, 'G': 0, 'T': 0}
                agg_data[std_subject]['PRESENTED'] = {'B': 0, 'G': 0, 'T': 0}
                agg_data[std_subject]['ABSENT'] = {'B': 0, 'G': 0, 'T': 0}
                agg_data[std_subject]['CANCELLED PAPERS'] = {'B': 0, 'G': 0, 'T': 0}

            # Add to presented count (everyone parsed counts as presented)
            agg_data[std_subject]['PRESENTED'][gender_key] += 1
            agg_data[std_subject]['PRESENTED']['T'] += 1

            # Registered is typically presented + absent. Let's assume registered = presented for this simplified view.
            agg_data[std_subject]['REGISTERED'][gender_key] += 1
            agg_data[std_subject]['REGISTERED']['T'] += 1

            if grade in grades:
                agg_data[std_subject][grade][gender_key] += 1
                agg_data[std_subject][grade]['T'] += 1

    return agg_data


def standardize_subject(raw_subject):
    """
    Maps raw PDF subject names to the standard template names.
    """
    raw_subject = str(raw_subject).strip().upper()

    # Define mappings based on common abbreviations and typos from the PDF
    mapping = {
        'ENGLISH LANG': 'English Language',
        'MATHEMATICS(CORE)': 'Mathematics',
        'MATHEMATICS (CORE)': 'Mathematics',
        'CORE MATHS': 'Mathematics',
        'CORE MATHEMATICS': 'Mathematics',
        'INTEGRATED SCIENCE': 'Integrated Science',
        'SOCIAL STUDIES': 'Social Studies',

        'BIOLOGY': 'Biology',
        'CHEMISTRY': 'Chemistry',
        'PHYSICS': 'Physics',
        'MATHEMATICS(ELECTIVE)': 'Mathematics (Elective)',
        'MATHEMATICS (ELECTIVE)': 'Mathematics (Elective)',
        'ELECTIVE MATHS': 'Mathematics (Elective)',
        'GOVERNMENT': 'Government',
        'GEOGRAPHY': 'Geography',
        'ECONOMICS': 'Economics',
        'HISTORY': 'History',
        'LIT-IN-ENGLISH': 'Literature In English',
        'LITERATURE IN ENGLISH': 'Literature In English',
        'GHANAIAN LANGUAGE': 'Ghanaian Language',
        'FRENCH': 'French',
        'CHRISTIAN REL STUDIES': 'Christian Religious Studies',
        'CHRISTIAN RELIGIOUS STUDIES': 'Christian Religious Studies',
        'ISLAMIC RELIGIOUS STUDIES': 'Islamic Religious Studies',
        'ISLAMIC REL STUDIES': 'Islamic Religious Studies',
        'GEN KNOW IN ART': 'General Knowledge In Art',
        'GENERAL KNOWLEDGE IN ART': 'General Knowledge In Art',
        'MUSIC': 'Music',
        'ICT (ELECTIVE)': 'ICT (Elective)',
        'GENERAL AGRICULTURE': 'General Agriculture',
        'GEN AGRIC': 'General Agriculture',
        'ANIMAL HUSBANDRY': 'Animal Husbandry',
        'CROP HUSBANDRY': 'Crop Husbandry',
        'FISHERIES': 'Fisheries',
        'FORESTRY': 'Forestry',
        'ACCOUNTING': 'Accounting',
        'FINANCIAL ACCOUNTING': 'Accounting',
        'BUSINESS MANAGEMENT': 'Business Management',
        'BUSINESS MATHS/PRINCIPLES OF COST ACCOUNTING': 'Business Maths/Principles of Cost Accounting',
        'AUTO MECHANICS': 'Auto Mechanics',
        'BUILDING CONSTRUCTION': 'Building Construction',
        'ELECTRONICS': 'Electronics',
        'METAL WORK': 'Metal Work',
        'TECHNICAL DRAWING': 'Technical Drawing',
        'WOOD WORK': 'Wood Work',
        'MGT IN LIVING': 'Management In Living',
        'MANAGEMENT IN LIVING': 'Management In Living',
        'FOOD AND NUTRITION': 'Food And Nutrition',
        'CLOTHING & TEXTILES': 'Clothing And Textiles',
        'CLOTHING AND TEXTILES': 'Clothing And Textiles',
        'TEXTILES': 'Textiles',
        'GRAPHIC DESIGN': 'Graphic Design',
        'PICTURE MAKING': 'Picture Making',
        'BASKETRY': 'Basketry',
        'CERAMICS': 'Ceramics',
        'JEWELLERY': 'Jewellery',
        'LEATHER WORK': 'Leather Work',
        'SCULPTURE': 'Sculpture',
        'APPLIED ELECTRICITY': 'Applied Electricity'
    }

    # Check direct mapping
    if raw_subject in mapping:
        return mapping[raw_subject]

    # Check partial mapping (e.g., if 'MGT' is in the string, map to 'Management In Living')
    for key, value in mapping.items():
        if key in raw_subject:
            return value

    # Default to title-casing the raw subject if not found
    return raw_subject.title()
