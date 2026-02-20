"""
00_process_persona_mapping.py

Description:
    This interactive script processes persona-to-AD Security Group mappings from an Excel 
    file and enriches the data with corresponding DocUnit assignments. It creates a 
    relational table suitable for further analysis and user review processes.
    
    The script prompts users to specify file paths with suggested defaults, allowing for
    flexible file selection while maintaining ease of use.

Purpose:
    The script serves as the primary data processor for IQMS persona management, transforming
    complex Excel-based persona mappings into a structured CSV format that can be used for:
    - User access reviews
    - Security group audits
    - Persona-to-DocUnit relationship analysis
    - Data enrichment pipelines

Process Flow:
    1. Prompt user for file paths (with suggested defaults):
       - Input Excel file containing persona mappings
       - DocUnit reference CSV file
       - Output CSV file location
    2. Validate that input files exist
    3. Read Excel file with persona mappings (supports multiple sheets)
    4. Transform Excel columns into relational records (persona -> AD Security Group pairs)
    5. Extract identifiers from both DocUnit names and AD Security Group names
    6. Match AD Security Groups to DocUnits using intelligent identifier matching strategies:
       - Primary: Extract identifier from the end of the security group name
       - Fallback 1: Use the last 4 characters as identifier
       - Fallback 2: Search for pattern (2 letters + 2 digits) within the name
    7. Export the enriched data to CSV format with columns: persona, AD Security Group, DocUnit
    
    Note: All values are trimmed (whitespace removed) before comparison, lookup, and insertion
          to ensure data quality and accurate matching.

Input (User Prompted):
    - Excel file: User provides full path (default: mapping_persona_sg/ID now-Personas mapping.xlsx)
    - DocUnit reference: User provides full path (default: reports/docunit_persona_members_20260131_163801.csv)

Output (User Prompted):
    - CSV file: User provides full path (default: exports/persona_ad_sg_mapping.csv)
    - Columns: persona, AD Security Group, DocUnit
    - Error tracking for unmatched DocUnits

Identifier Matching Logic:
    - DocUnit identifiers: Extracted from format "Name (ID)" -> e.g., "BCC AG Basel (CH01)" -> "CH01"
    - Security Group identifiers: Multiple strategies applied in sequence:
        1. Last segment after underscore (e.g., "..._ch01" -> "CH01")
        2. Last 4 characters if matching identifier pattern
        3. Regex pattern search for 2-letter + 2-digit code anywhere in the name

Usage:
    python tools/00_process_persona_mapping.py
    
    The script will interactively prompt for:
    1. Excel file path (with default suggestion)
    2. DocUnit CSV file path (with default suggestion)
    3. Output CSV file path (with default suggestion)
    
    Press Enter to accept the suggested default, or provide a custom full path.
"""

import pandas as pd
import re
from pathlib import Path
import os


# ============================================================================
# HELPER FUNCTIONS - USER INPUT
# ============================================================================

def get_user_input(prompt, default_value):
    """
    Prompts the user for input with a suggested default value.
    
    Args:
        prompt: The prompt message to display
        default_value: The default value to suggest (and use if user presses Enter)
    
    Returns:
        str: The user's input or the default value if no input provided
    """
    print(f"\n{prompt}")
    print(f"Suggested: {default_value}")
    user_input = input("Enter full path (or press Enter to use suggested): ").strip()
    
    if user_input:
        return user_input
    else:
        return str(default_value)


# ============================================================================
# HELPER FUNCTIONS - DATA PROCESSING
# ============================================================================

def process_excel_sheet(df, sheet_name):
    """
    Processes an Excel sheet and creates relational entries.
    
    Each column in the sheet represents a persona, and the values in that column
    represent the AD Security Groups assigned to that persona. This function
    transforms the columnar structure into a relational format.
    
    Args:
        df: DataFrame of the sheet
        sheet_name: Name of the sheet (for debug output)
    
    Returns:
        List of dictionaries containing persona and AD Security Group pairs
    """
    records = []
    
    print(f"\nProcessing sheet: {sheet_name}")
    print(f"Columns found: {len(df.columns)}")
    
    # Iterate through all columns
    for column in df.columns:
        # Column name represents the persona
        persona = str(column).strip()
        
        # Iterate through all rows in this column
        for value in df[column]:
            # Skip empty values and NaN
            if pd.notna(value) and str(value).strip():
                ad_group = str(value).strip()
                
                # Create a relational record: persona <-> AD Security Group
                records.append({
                    'persona': persona,
                    'AD Security Group': ad_group
                })
    
    print(f"  → {len(records)} entries created")
    return records


def extract_identifier_from_docunit(docunit_name):
    """
    Extracts the identifier from a DocUnit name.
    
    DocUnit names follow the format: "Description (IDENTIFIER)"
    Example: "BCC AG Basel (CH01)" -> "CH01"
    
    Args:
        docunit_name: The full DocUnit name string
        
    Returns:
        str: The extracted identifier (e.g., "CH01") or None if no match
        
    Note:
        Input value is trimmed before processing to ensure clean matching.
    """
    # Trim whitespace before processing
    if docunit_name:
        docunit_name = str(docunit_name).strip()
    
    match = re.search(r'\(([A-Z0-9]+)\)$', docunit_name)
    if match:
        return match.group(1).strip()
    return None


def extract_identifier_from_sg(sg_name):
    """
    Extracts the identifier from the end of an AD Security Group name.
    
    Security Groups typically follow naming conventions where the DocUnit identifier
    appears as the last segment after underscores.
    
    Example: "ef.u.iqms_qms_internal_task_owner_bcc_ag_basel_ch01" -> "CH01"
    
    Args:
        sg_name: The full AD Security Group name
        
    Returns:
        str: The extracted identifier in uppercase (e.g., "CH01") or None if no match
        
    Note:
        Input value and segments are trimmed before processing to ensure clean matching.
    """
    # Trim whitespace before processing
    if sg_name:
        sg_name = str(sg_name).strip()
    
    # Get the last segment after the final underscore
    parts = sg_name.split('_')
    if parts:
        last_part = parts[-1].strip()
        # Check if it matches typical identifier pattern (2-4 letters + 2 digits)
        if re.match(r'^[a-z]{2,4}\d{2}$', last_part, re.IGNORECASE):
            return last_part.upper()
    return None


def find_identifier_pattern(sg_name):
    """
    Searches for identifier pattern: 2 uppercase letters followed by 2 digits.
    
    This is a fallback strategy when the identifier cannot be extracted using
    standard naming conventions. It searches anywhere in the string for the pattern.
    
    Example: "IQMS QMS OOS QA CO Germany DE20 2" -> "DE20"
    
    Args:
        sg_name: The AD Security Group name or any string to search
        
    Returns:
        str: The last matching identifier found in uppercase, or None if no match
        
    Note:
        Input value and matched results are trimmed before processing to ensure clean matching.
    """
    # Trim whitespace before processing
    if sg_name:
        sg_name = str(sg_name).strip()
    
    # Find all matches of 2 letters + 2 digits pattern
    matches = re.findall(r'\b([A-Z]{2}\d{2})\b', sg_name, re.IGNORECASE)
    if matches:
        # Return the last match (often the most relevant)
        return matches[-1].strip().upper()
    return None


def add_docunit_column(df_mapping, docunit_file):
    """
    Adds the DocUnit column to the mapping DataFrame.
    
    This function matches each AD Security Group to its corresponding DocUnit by
    extracting and comparing identifiers. Uses multiple fallback strategies to
    maximize successful matches.
    
    Args:
        df_mapping: DataFrame containing persona and AD Security Group columns
        docunit_file: Path to the DocUnit CSV reference file
        
    Returns:
        tuple: (DataFrame with added DocUnit column, number of errors/unmatched entries)
        
    Note:
        All values (DocUnit names, Security Group names, identifiers) are trimmed before
        comparison and lookup to ensure accurate matching and clean data quality.
    """
    print(f"\n{'='*80}")
    print("STEP 2: Add DocUnit Column")
    print(f"{'='*80}")
    
    print(f"\nLoading DocUnit file: {docunit_file}")
    df_docunit = pd.read_csv(docunit_file)
    print(f"  → {len(df_docunit)} entries loaded")
    
    # Create distinct list of DocUnits (trim values)
    docunits = df_docunit['docunit'].unique()
    print(f"  → {len(docunits)} unique DocUnits found")
    
    # Create mapping from Identifier to DocUnit Name (with trimmed values)
    identifier_to_docunit = {}
    for docunit in docunits:
        # Trim docunit value before processing
        docunit_trimmed = str(docunit).strip() if docunit else docunit
        identifier = extract_identifier_from_docunit(docunit_trimmed)
        if identifier:
            # Store trimmed identifier and docunit
            identifier_to_docunit[identifier.strip()] = docunit_trimmed
    
    print(f"\n  → {len(identifier_to_docunit)} DocUnit identifiers mapped")
    print(f"\nExamples:")
    for i, (identifier, docunit) in enumerate(list(identifier_to_docunit.items())[:5]):
        print(f"    {identifier} → {docunit}")
    
    # Add DocUnit column using intelligent matching strategies
    print(f"\nAdding DocUnit column...")
    docunit_values = []
    errors = 0
    fallback_last4_matches = 0
    fallback_pattern_matches = 0
    
    for idx, row in df_mapping.iterrows():
        # Trim the security group name before processing
        sg_name = str(row['AD Security Group']).strip() if row['AD Security Group'] else ''
        identifier = extract_identifier_from_sg(sg_name)
        
        # Trim identifier before lookup
        if identifier:
            identifier = identifier.strip()
        
        if identifier and identifier in identifier_to_docunit:
            # Strategy 1: Direct match from extracted identifier
            docunit_values.append(identifier_to_docunit[identifier])
        else:
            # Strategy 2: Fallback using last 4 characters
            if len(sg_name) >= 4:
                last_four = sg_name[-4:].strip().upper()
                if last_four in identifier_to_docunit:
                    docunit_values.append(identifier_to_docunit[last_four])
                    fallback_last4_matches += 1
                else:
                    # Strategy 3: Fallback using pattern search (2 letters + 2 digits)
                    pattern_identifier = find_identifier_pattern(sg_name)
                    # Trim pattern identifier before lookup
                    if pattern_identifier:
                        pattern_identifier = pattern_identifier.strip()
                    if pattern_identifier and pattern_identifier in identifier_to_docunit:
                        docunit_values.append(identifier_to_docunit[pattern_identifier])
                        fallback_pattern_matches += 1
                    else:
                        # No match found with any strategy
                        docunit_values.append("ERROR: Docunit not found")
                        errors += 1
                        if errors <= 5:  # Show first 5 errors for debugging
                            print(f"  No match for: {sg_name}")
                            print(f"    ID: {identifier}, Last4: {last_four}, Pattern: {pattern_identifier}")
            else:
                # Security group name too short to extract identifier
                docunit_values.append("ERROR: Docunit not found")
                errors += 1
                if errors <= 5:
                    print(f"  No match for: {sg_name} (too short)")
    
    df_mapping['DocUnit'] = docunit_values
    
    print(f"\nDocUnit mapping completed:")
    print(f"  Successfully mapped: {len(df_mapping) - errors}")
    print(f"    - Direct matches: {len(df_mapping) - errors - fallback_last4_matches - fallback_pattern_matches}")
    print(f"    - Fallback (last 4 characters): {fallback_last4_matches}")
    print(f"    - Fallback (pattern 2 letters + 2 digits): {fallback_pattern_matches}")
    print(f"  Errors (not found): {errors}")
    
    return df_mapping, errors


def main():
    """
    Main execution function for the interactive persona mapping process.
    
    This function guides the user through an interactive workflow:
    1. Prompts for input Excel file path (with default suggestion)
    2. Prompts for DocUnit reference CSV file path (with default suggestion) 
    3. Prompts for output CSV file path (with default suggestion)
    4. Validates that input files exist
    5. Processes the Excel data and creates relational mappings
    6. Enriches data with DocUnit information
    7. Saves the result to the specified output file
    
    The user can press Enter to accept default paths or provide custom full paths.
    """
    
    # Define default paths (relative to project root) to suggest to the user
    project_root = Path(__file__).parent.parent  # One level up from tools/
    default_excel_file = project_root / "mapping_persona_sg" / "ID now-Personas mapping.xlsx"
    default_docunit_file = project_root / "reports" / "docunit_persona_members_20260131_163801.csv"
    default_output_file = project_root / "exports" / "persona_ad_sg_mapping.csv"
    
    # Display welcome message
    print(f"{'='*80}")
    print("PERSONA MAPPING PROCESSOR")
    print(f"{'='*80}")
    print("\nThis script will process persona-to-AD Security Group mappings.")
    print("You will be prompted to provide file paths for:")
    print("  1. Input Excel file (persona mappings)")
    print("  2. DocUnit reference CSV file")
    print("  3. Output CSV file location")
    
    # Get user input for file paths
    excel_file = Path(get_user_input(
        "\n[1/3] Excel file with persona mappings:",
        default_excel_file
    ))
    
    docunit_file = Path(get_user_input(
        "\n[2/3] DocUnit reference CSV file:",
        default_docunit_file
    ))
    
    output_file = Path(get_user_input(
        "\n[3/3] Output CSV file path:",
        default_output_file
    ))
    
    # Validate that user-specified input files exist
    if not excel_file.exists():
        print(f"\n❌ ERROR: Excel file not found: {excel_file}")
        return
    
    if not docunit_file.exists():
        print(f"\n❌ ERROR: DocUnit file not found: {docunit_file}")
        return
    
    # Create output directory if it doesn't exist (based on user-specified output path)
    output_dir = output_file.parent
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Display confirmed file selections to user before processing
    print(f"\n{'='*80}")
    print("FILE SELECTIONS CONFIRMED")
    print(f"{'='*80}")
    print(f"Excel file:   {excel_file}")
    print(f"DocUnit file: {docunit_file}")
    print(f"Output file:  {output_file}")
    
    print(f"\n{'='*80}")
    print("STEP 1: Process Excel file and create relational table")
    print(f"{'='*80}")
    
    print(f"\nReading user-specified Excel file: {excel_file}")
    
    # Read Excel file (path provided by user)
    try:
        # Read first sheet (index 0) - contains persona mappings
        df_sheet1 = pd.read_excel(excel_file, sheet_name=0)
        print(f"\n✓ Sheet 1 loaded: {df_sheet1.shape[0]} rows, {df_sheet1.shape[1]} columns")
        
        # Read second sheet (index 1) - contains additional persona mappings
        df_sheet2 = pd.read_excel(excel_file, sheet_name=1)
        print(f"✓ Sheet 2 loaded: {df_sheet2.shape[0]} rows, {df_sheet2.shape[1]} columns")
        
    except Exception as e:
        print(f"Error reading Excel file: {e}")
        return
    
    # Process both sheets and combine results
    all_records = []
    
    # Process Sheet 1 - transform columns to relational records
    records_sheet1 = process_excel_sheet(df_sheet1, "Sheet 1")
    all_records.extend(records_sheet1)
    
    # Process Sheet 2 - transform columns to relational records
    records_sheet2 = process_excel_sheet(df_sheet2, "Sheet 2")
    all_records.extend(records_sheet2)
    
    # Convert combined records to DataFrame for further processing
    result_df = pd.DataFrame(all_records)
    
    print(f"\nTotal: {len(all_records)} entries created")
    
    # Add DocUnit column using user-specified reference file
    result_df, errors = add_docunit_column(result_df, docunit_file)
    
    # Save enriched data as CSV to user-specified location
    print(f"\n{'='*80}")
    print("STEP 3: Save CSV file")
    print(f"{'='*80}")
    
    try:
        # Write to user-specified output file path
        result_df.to_csv(output_file, index=False, encoding='utf-8-sig', sep=',')
        print(f"\n✓ CSV successfully saved: {output_file}")
        print(f"  Columns: {list(result_df.columns)}")
        print(f"  Entries: {len(result_df)}")
        
        # Display first 5 entries as preview
        print(f"\nPreview (first 5 entries):")
        print(result_df.head().to_string(index=False))
        
        # Display error statistics if any DocUnits could not be matched
        if errors > 0:
            print(f"\n⚠ Entries with errors ({errors} total, showing first 10):")
            error_df = result_df[result_df['DocUnit'] == "ERROR: Docunit not found"]
            print(error_df.head(10).to_string(index=False))
        
        print(f"\n{'='*80}")
        print("✓ PROCESSING COMPLETED SUCCESSFULLY")
        print(f"{'='*80}")
        
    except Exception as e:
        print(f"Error saving CSV: {e}")


if __name__ == "__main__":
    main()
