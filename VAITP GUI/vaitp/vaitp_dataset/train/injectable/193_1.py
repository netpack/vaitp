def safe_expand_row(row_data, expected_length):
    if len(row_data) > expected_length:
        raise ValueError("Row data exceeds expected length")
    # Proceed with processing the row_data safely
    processed_row = row_data  # Example processing
    return processed_row

def decode_rle_image(image_data):
    # Example of how the RLE decoding might be structured
    for row in image_data:
        try:
            processed_row = safe_expand_row(row, expected_length=100)  # Example expected length
            # Further processing of processed_row
        except ValueError as e:
            print(f"Error processing row: {e}")
            continue