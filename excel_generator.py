from openpyxl import Workbook
from openpyxl.styles import Alignment, Font, PatternFill, Border, Side
from openpyxl.utils import get_column_letter

def create_excel_report(aggregated_data, output_path):
    wb = Workbook()
    ws = wb.active
    ws.title = "WASSCE Analysis"

    # --- Styling Setup ---
    font_bold = Font(bold=True)
    font_normal = Font(bold=False)
    align_center = Alignment(horizontal='center', vertical='center', wrap_text=True)
    align_left = Alignment(horizontal='left', vertical='center', wrap_text=True)
    align_right = Alignment(horizontal='right', vertical='center')

    thin_border = Border(
        left=Side(style='thin'),
        right=Side(style='thin'),
        top=Side(style='thin'),
        bottom=Side(style='thin')
    )

    grey_fill = PatternFill(start_color="D9D9D9", end_color="D9D9D9", fill_type="solid")
    dark_grey_fill = PatternFill(start_color="808080", end_color="808080", fill_type="solid")
    green_fill = PatternFill(start_color="00B050", end_color="00B050", fill_type="solid")
    light_green_fill = PatternFill(start_color="C6EFCE", end_color="C6EFCE", fill_type="solid")

    # --- Titles ---
    ws.merge_cells('A1:CH1')
    ws['A1'] = "GHANA EDUCATION SERVICE"
    ws['A1'].font = font_bold
    ws['A1'].alignment = align_center

    ws.merge_cells('A2:CH2')
    ws['A2'] = "CENTRAL REGION"
    ws['A2'].font = font_bold
    ws['A2'].alignment = align_center

    ws.merge_cells('A3:CH3')
    ws['A3'] = "WASSCE 2023 SCHOOL RESULTS ANALYSIS"
    ws['A3'].font = font_bold
    ws['A3'].alignment = align_center

    # --- School Info Row ---
    ws.merge_cells('A5:E5')
    ws['A5'] = "SCHOOL:"
    ws['A5'].alignment = align_right
    ws['A5'].font = font_bold

    ws.merge_cells('F5:AA5') # Placeholder for school name
    ws['F5'].border = thin_border

    ws.merge_cells('AB5:AG5')
    ws['AB5'] = "Number of papers written"
    ws['AB5'].font = font_bold
    ws['AB5'].alignment = align_center
    ws['AB5'].border = thin_border

    ws.merge_cells('AH5:AJ5') # Value
    ws['AH5'].fill = green_fill
    ws['AH5'].border = thin_border

    ws.merge_cells('AK5:AM5')
    ws['AK5'] = "Type of school"
    ws['AK5'].font = font_bold
    ws['AK5'].alignment = align_center
    ws['AK5'].border = thin_border

    ws.merge_cells('AN5:AP5') # PUBLIC / PRIVATE
    ws['AN5'] = "PUBLIC"
    ws['AN5'].alignment = align_center
    ws['AN5'].border = thin_border

    # --- Headers ---
    headers = [
        "S/N", "SUBJECTS",
        "REGISTERED", "PRESENTED", "ABSENT", "CANCELLED\nPAPERS",
        "A1", "B2", "B3", "C4", "C5", "C6", "D7", "E8", "F9",
        "A1-C6 Total Pass", "A1-C6 % Total Pass",
        "D7-E8 Total Pass", "D7-E8 % Total Pass",
        "F9 Total Fail", "F9 % Total Fail"
    ]

    # 1. Main Header Row (Row 7)
    ws.merge_cells('A7:A8')
    ws['A7'] = "S/N"
    ws['A7'].alignment = align_center
    ws['A7'].border = thin_border
    ws['A7'].font = font_bold

    ws.merge_cells('B7:B8')
    ws['B7'] = "SUBJECTS"
    ws['B7'].alignment = align_center
    ws['B7'].border = thin_border
    ws['B7'].font = font_bold

    # Categories
    ws.merge_cells('C7:K7')
    ws['C7'] = "CANDIDATES"
    ws['C7'].alignment = align_center
    ws['C7'].border = thin_border
    ws['C7'].font = font_bold

    ws.merge_cells('L7:N7')
    ws['L7'] = "CANCELLED\nPAPERS"
    ws['L7'].alignment = align_center
    ws['L7'].border = thin_border
    ws['L7'].font = font_bold

    ws.merge_cells('O7:CH7')
    ws['O7'] = "GRADES OBTAINED (NO. OF CANDIDATES)"
    ws['O7'].alignment = align_center
    ws['O7'].border = thin_border
    ws['O7'].font = font_bold

    # 2. Sub-Header Row 1 (Row 8) - Groupings
    cols_mapping = {
        'C': 'REGISTERED', 'F': 'PRESENTED', 'I': 'ABSENT', 'L': '', # Cancelled is already merged
        'O': 'A1', 'R': 'B2', 'U': 'B3', 'X': 'C4', 'AA': 'C5', 'AD': 'C6',
        'AG': 'D7', 'AJ': 'E8', 'AM': 'F9',
        'AP': 'A1-C6', 'AX': 'D7-E8', 'BF': 'F9'
    }

    for start_col, label in cols_mapping.items():
        if label:
            end_col_idx = ws[f'{start_col}8'].column + 2
            end_col = get_column_letter(end_col_idx)

            # Custom merge for A1-C6 and beyond based on image structure
            if label == 'A1-C6':
                end_col = 'AW'
            elif label == 'D7-E8':
                end_col = 'BE'
            elif label == 'F9' and start_col == 'BF':
                end_col = 'CH'
            else:
                end_col = get_column_letter(ws[f'{start_col}8'].column + 2)

            if start_col != 'L': # L is merged above
                ws.merge_cells(f'{start_col}8:{end_col}8')
                ws[f'{start_col}8'] = label
                ws[f'{start_col}8'].alignment = align_center
                ws[f'{start_col}8'].border = thin_border
                ws[f'{start_col}8'].font = font_normal

    # 3. Sub-Header Row 2 (Row 9) - B, G, T
    current_col = 3 # Start from C

    # Add B, G, T for basic metrics and grades
    for _ in range(13): # Registered -> F9
        for label in ['B', 'G', 'T']:
            col_letter = get_column_letter(current_col)
            ws[f'{col_letter}9'] = label
            ws[f'{col_letter}9'].alignment = align_center
            ws[f'{col_letter}9'].border = thin_border
            ws[f'{col_letter}9'].font = font_bold
            if label == 'T':
                ws[f'{col_letter}9'].fill = grey_fill
            current_col += 1

    # Add B, G, T, Total Pass, % Total Pass for A1-C6
    for label in ['B', 'G', 'T', 'Total Pass', '% Total\nPass']:
        if label in ['B', 'G', 'T']:
            col_letter = get_column_letter(current_col)
            ws[f'{col_letter}9'] = label
            current_col += 1
        else:
            # Need to span slightly more columns or just one for these based on exact replica
            # Simplify: assign to next column
            col_letter = get_column_letter(current_col)
            ws[f'{col_letter}9'] = label
            # Merge 2 columns for wider text if needed, let's just make it single for now
            if label == 'Total Pass':
                ws.merge_cells(f'{col_letter}9:{get_column_letter(current_col+1)}9')
                current_col += 2
            else:
                ws.merge_cells(f'{col_letter}9:{get_column_letter(current_col+1)}9')
                current_col += 2

        start_col = get_column_letter(current_col - (2 if label in ['Total Pass', '% Total\nPass'] else 1))
        ws[f'{start_col}9'].alignment = align_center
        ws[f'{start_col}9'].border = thin_border
        ws[f'{start_col}9'].font = font_bold
        if label == 'T' or label == 'Total Pass' or label == '% Total\nPass':
             ws[f'{start_col}9'].fill = grey_fill if label == 'T' else light_green_fill

    # D7-E8
    for label in ['B', 'G', 'T', 'Total Pass', '% Total\nPass']:
        if label in ['B', 'G', 'T']:
            col_letter = get_column_letter(current_col)
            ws[f'{col_letter}9'] = label
            current_col += 1
        else:
            col_letter = get_column_letter(current_col)
            ws[f'{col_letter}9'] = label
            if label == 'Total Pass':
                ws.merge_cells(f'{col_letter}9:{get_column_letter(current_col+1)}9')
                current_col += 2
            else:
                ws.merge_cells(f'{col_letter}9:{get_column_letter(current_col+1)}9')
                current_col += 2

        start_col = get_column_letter(current_col - (2 if label in ['Total Pass', '% Total\nPass'] else 1))
        ws[f'{start_col}9'].alignment = align_center
        ws[f'{start_col}9'].border = thin_border
        ws[f'{start_col}9'].font = font_bold
        if label == 'T' or label == 'Total Pass' or label == '% Total\nPass':
             ws[f'{start_col}9'].fill = grey_fill if label == 'T' else light_green_fill

    # F9
    for label in ['B', 'G', 'T', 'Total Fail', '% Total\nFail']:
        if label in ['B', 'G', 'T']:
            col_letter = get_column_letter(current_col)
            ws[f'{col_letter}9'] = label
            current_col += 1
        else:
            col_letter = get_column_letter(current_col)
            ws[f'{col_letter}9'] = label
            if label == 'Total Fail':
                ws.merge_cells(f'{col_letter}9:{get_column_letter(current_col+1)}9')
                current_col += 2
            else:
                ws.merge_cells(f'{col_letter}9:{get_column_letter(current_col+1)}9')
                current_col += 2

        start_col = get_column_letter(current_col - (2 if label in ['Total Fail', '% Total\nFail'] else 1))
        ws[f'{start_col}9'].alignment = align_center
        ws[f'{start_col}9'].border = thin_border
        ws[f'{start_col}9'].font = font_bold
        if label == 'T' or label == 'Total Fail' or label == '% Total\nFail':
             ws[f'{start_col}9'].fill = grey_fill if label == 'T' else light_green_fill


    # --- Formatting all borders for header rows ---
    for row in ws['A7:CH9']:
        for cell in row:
            if cell.border == Border():
                 cell.border = thin_border

    # Fill specific columns with grey
    for col in ['E', 'H', 'K', 'N', 'Q', 'T', 'W', 'Z', 'AC', 'AF', 'AI', 'AL', 'AO', 'AR']:
        ws[f'{col}9'].fill = grey_fill

    ws['H9'].fill = dark_grey_fill # Presented T is darker in screenshot

    # --- Data Population ---
    row_num = 10

    # Core Subjects First
    ws.merge_cells(f'A{row_num}:CH{row_num}')
    ws[f'A{row_num}'] = "Core"
    ws[f'A{row_num}'].font = font_bold
    ws[f'A{row_num}'].alignment = Alignment(horizontal='center', vertical='center')
    ws[f'A{row_num}'].fill = grey_fill
    for cell in ws[row_num]: cell.border = thin_border
    row_num += 1

    core_subjects = ['English Language', 'Mathematics', 'Integrated Science', 'Social Studies']
    electives = [
        'Biology', 'Chemistry', 'Physics', 'Mathematics (Elective)', 'Government',
        'Geography', 'Economics', 'History', 'Literature In English', 'Ghanaian Language',
        'French', 'Christian Religious Studies', 'Islamic Religious Studies',
        'General Knowledge In Art', 'Music', 'ICT (Elective)', 'General Agriculture',
        'Animal Husbandry', 'Crop Husbandry', 'Fisheries', 'Forestry', 'Accounting',
        'Business Management', 'Business Maths/Principles of Cost Accounting',
        'Auto Mechanics', 'Building Construction', 'Electronics', 'Metal Work',
        'Technical Drawing', 'Wood Work', 'Management In Living', 'Food And Nutrition',
        'Clothing And Textiles', 'Textiles', 'Graphic Design', 'Picture Making',
        'Basketry', 'Ceramics', 'Jewellery', 'Leather Work', 'Sculpture', 'Applied Electricity'
    ]

    def write_row(s_num, subject_name, r_num, is_core=False):
        ws[f'A{r_num}'] = s_num
        ws[f'A{r_num}'].alignment = align_center
        ws[f'A{r_num}'].border = thin_border

        ws[f'B{r_num}'] = subject_name
        ws[f'B{r_num}'].alignment = align_left
        ws[f'B{r_num}'].border = thin_border

        # Get data
        s_data = aggregated_data.get(subject_name, None)

        col_idx = 3 # Start at C

        # Helper to write B, G, T and apply formulas
        def write_bgt(metrics, col_start):
             b_val = metrics['B'] if s_data else 0
             g_val = metrics['G'] if s_data else 0
             t_val = b_val + g_val

             b_col = get_column_letter(col_start)
             g_col = get_column_letter(col_start+1)
             t_col = get_column_letter(col_start+2)

             ws[f'{b_col}{r_num}'] = b_val
             ws[f'{g_col}{r_num}'] = g_val
             ws[f'{t_col}{r_num}'] = f"={b_col}{r_num}+{g_col}{r_num}"

             for col in [b_col, g_col, t_col]:
                 ws[f'{col}{r_num}'].alignment = align_center
                 ws[f'{col}{r_num}'].border = thin_border
                 if col == t_col:
                     ws[f'{col}{r_num}'].fill = grey_fill
                     if label == 'PRESENTED' and is_core:
                         ws[f'{col}{r_num}'].fill = dark_grey_fill
             return col_start + 3

        # Registered, Presented, Absent, Cancelled
        for label in ['REGISTERED', 'PRESENTED', 'ABSENT', 'CANCELLED PAPERS']:
            metrics = s_data.get(label, {'B':0, 'G':0, 'T':0}) if s_data else {'B':0, 'G':0, 'T':0}
            col_idx = write_bgt(metrics, col_idx)

        # Grades A1 - F9
        grades = ['A1', 'B2', 'B3', 'C4', 'C5', 'C6', 'D7', 'E8', 'F9']
        for grade in grades:
             metrics = s_data.get(grade, {'B':0, 'G':0, 'T':0}) if s_data else {'B':0, 'G':0, 'T':0}
             col_idx = write_bgt(metrics, col_idx)

        # Calculated columns
        # A1-C6 Total Pass
        # B = sum(B for A1-C6), G = sum(G for A1-C6), T = sum(T for A1-C6)

        # Let's map grade columns
        # A1(O,P,Q), B2(R,S,T), B3(U,V,W), C4(X,Y,Z), C5(AA,AB,AC), C6(AD,AE,AF)
        a1_c6_b_cols = ['O', 'R', 'U', 'X', 'AA', 'AD']
        a1_c6_g_cols = ['P', 'S', 'V', 'Y', 'AB', 'AE']
        a1_c6_t_cols = ['Q', 'T', 'W', 'Z', 'AC', 'AF']

        b_sum_form = "+".join([f"{c}{r_num}" for c in a1_c6_b_cols])
        g_sum_form = "+".join([f"{c}{r_num}" for c in a1_c6_g_cols])
        t_sum_form = "+".join([f"{c}{r_num}" for c in a1_c6_t_cols])

        # B
        col = get_column_letter(col_idx); ws[f'{col}{r_num}'] = f"={b_sum_form}"; ws[f'{col}{r_num}'].alignment = align_center; ws[f'{col}{r_num}'].border = thin_border; col_idx+=1
        # G
        col = get_column_letter(col_idx); ws[f'{col}{r_num}'] = f"={g_sum_form}"; ws[f'{col}{r_num}'].alignment = align_center; ws[f'{col}{r_num}'].border = thin_border; col_idx+=1
        # T
        col = get_column_letter(col_idx); ws[f'{col}{r_num}'] = f"={t_sum_form}"; ws[f'{col}{r_num}'].alignment = align_center; ws[f'{col}{r_num}'].border = thin_border; ws[f'{col}{r_num}'].fill = grey_fill; col_idx+=1

        # Total Pass (Merge 2)
        col = get_column_letter(col_idx); next_col = get_column_letter(col_idx+1)
        ws.merge_cells(f'{col}{r_num}:{next_col}{r_num}')
        ws[f'{col}{r_num}'] = f"={get_column_letter(col_idx-1)}{r_num}" # Equals T
        ws[f'{col}{r_num}'].alignment = align_center; ws[f'{col}{r_num}'].border = thin_border; ws[f'{col}{r_num}'].fill = grey_fill;
        ws[f'{next_col}{r_num}'].border = thin_border; col_idx+=2

        # % Total Pass (Merge 2)
        col = get_column_letter(col_idx); next_col = get_column_letter(col_idx+1)
        ws.merge_cells(f'{col}{r_num}:{next_col}{r_num}')
        # (Total Pass / Presented T) * 100
        presented_t_col = 'H'
        ws[f'{col}{r_num}'] = f"=IF({presented_t_col}{r_num}>0, ({get_column_letter(col_idx-2)}{r_num}/{presented_t_col}{r_num})*100, 0)"
        ws[f'{col}{r_num}'].alignment = align_center; ws[f'{col}{r_num}'].border = thin_border; ws[f'{col}{r_num}'].number_format = '0.00'
        ws[f'{next_col}{r_num}'].border = thin_border; col_idx+=2

        # D7-E8
        d7_e8_b_cols = ['AG', 'AJ']
        d7_e8_g_cols = ['AH', 'AK']
        d7_e8_t_cols = ['AI', 'AL']

        b_sum_form = "+".join([f"{c}{r_num}" for c in d7_e8_b_cols])
        g_sum_form = "+".join([f"{c}{r_num}" for c in d7_e8_g_cols])
        t_sum_form = "+".join([f"{c}{r_num}" for c in d7_e8_t_cols])

        # B
        col = get_column_letter(col_idx); ws[f'{col}{r_num}'] = f"={b_sum_form}"; ws[f'{col}{r_num}'].alignment = align_center; ws[f'{col}{r_num}'].border = thin_border; col_idx+=1
        # G
        col = get_column_letter(col_idx); ws[f'{col}{r_num}'] = f"={g_sum_form}"; ws[f'{col}{r_num}'].alignment = align_center; ws[f'{col}{r_num}'].border = thin_border; col_idx+=1
        # T
        col = get_column_letter(col_idx); ws[f'{col}{r_num}'] = f"={t_sum_form}"; ws[f'{col}{r_num}'].alignment = align_center; ws[f'{col}{r_num}'].border = thin_border; ws[f'{col}{r_num}'].fill = grey_fill; col_idx+=1

        # Total Pass (Merge 2)
        col = get_column_letter(col_idx); next_col = get_column_letter(col_idx+1)
        ws.merge_cells(f'{col}{r_num}:{next_col}{r_num}')
        ws[f'{col}{r_num}'] = f"={get_column_letter(col_idx-1)}{r_num}"
        ws[f'{col}{r_num}'].alignment = align_center; ws[f'{col}{r_num}'].border = thin_border; ws[f'{col}{r_num}'].fill = grey_fill;
        ws[f'{next_col}{r_num}'].border = thin_border; col_idx+=2

        # % Total Pass (Merge 2)
        col = get_column_letter(col_idx); next_col = get_column_letter(col_idx+1)
        ws.merge_cells(f'{col}{r_num}:{next_col}{r_num}')
        ws[f'{col}{r_num}'] = f"=IF({presented_t_col}{r_num}>0, ({get_column_letter(col_idx-2)}{r_num}/{presented_t_col}{r_num})*100, 0)"
        ws[f'{col}{r_num}'].alignment = align_center; ws[f'{col}{r_num}'].border = thin_border; ws[f'{col}{r_num}'].number_format = '0.00'
        ws[f'{next_col}{r_num}'].border = thin_border; col_idx+=2

        # F9
        f9_b_col = 'AM'
        f9_g_col = 'AN'
        f9_t_col = 'AO'

        # B
        col = get_column_letter(col_idx); ws[f'{col}{r_num}'] = f"={f9_b_col}{r_num}"; ws[f'{col}{r_num}'].alignment = align_center; ws[f'{col}{r_num}'].border = thin_border; col_idx+=1
        # G
        col = get_column_letter(col_idx); ws[f'{col}{r_num}'] = f"={f9_g_col}{r_num}"; ws[f'{col}{r_num}'].alignment = align_center; ws[f'{col}{r_num}'].border = thin_border; col_idx+=1
        # T
        col = get_column_letter(col_idx); ws[f'{col}{r_num}'] = f"={f9_t_col}{r_num}"; ws[f'{col}{r_num}'].alignment = align_center; ws[f'{col}{r_num}'].border = thin_border; ws[f'{col}{r_num}'].fill = grey_fill; col_idx+=1

        # Total Fail (Merge 2)
        col = get_column_letter(col_idx); next_col = get_column_letter(col_idx+1)
        ws.merge_cells(f'{col}{r_num}:{next_col}{r_num}')
        ws[f'{col}{r_num}'] = f"={get_column_letter(col_idx-1)}{r_num}"
        ws[f'{col}{r_num}'].alignment = align_center; ws[f'{col}{r_num}'].border = thin_border; ws[f'{col}{r_num}'].fill = grey_fill;
        ws[f'{next_col}{r_num}'].border = thin_border; col_idx+=2

        # % Total Fail (Merge 2)
        col = get_column_letter(col_idx); next_col = get_column_letter(col_idx+1)
        ws.merge_cells(f'{col}{r_num}:{next_col}{r_num}')
        ws[f'{col}{r_num}'] = f"=IF({presented_t_col}{r_num}>0, ({get_column_letter(col_idx-2)}{r_num}/{presented_t_col}{r_num})*100, 0)"
        ws[f'{col}{r_num}'].alignment = align_center; ws[f'{col}{r_num}'].border = thin_border; ws[f'{col}{r_num}'].number_format = '0.00'
        ws[f'{next_col}{r_num}'].border = thin_border; col_idx+=2

        # Apply dark fill to Presented T column if it's a core subject
        if is_core:
            ws[f'H{r_num}'].fill = dark_grey_fill


    # Write Core subjects
    idx = 1
    for subj in core_subjects:
        write_row(idx, subj, row_num, is_core=True)
        row_num += 1
        idx += 1

    # Write Elective header
    ws.merge_cells(f'A{row_num}:CH{row_num}')
    ws[f'A{row_num}'] = "Elective"
    ws[f'A{row_num}'].font = font_bold
    ws[f'A{row_num}'].alignment = Alignment(horizontal='center', vertical='center')
    ws[f'A{row_num}'].fill = grey_fill
    for cell in ws[row_num]: cell.border = thin_border
    row_num += 1

    # Write Elective subjects
    idx = 1
    for subj in electives:
        write_row(idx, subj, row_num, is_core=False)
        row_num += 1
        idx += 1

    # Adjust column widths
    ws.column_dimensions['A'].width = 4
    ws.column_dimensions['B'].width = 30
    for col_idx in range(3, 87): # C to CH
        col_letter = get_column_letter(col_idx)
        ws.column_dimensions[col_letter].width = 4.5

    wb.save(output_path)
