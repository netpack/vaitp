# import os
# import random
# import json

# # Directories
# patched_dir = "/Users/fredericbogaerts/vaitp/VAITP GUI/vaitp/vaitp_dataset/train/noninjectable"
# vulnerable_dir = "/Users/fredericbogaerts/vaitp/VAITP GUI/vaitp/vaitp_dataset/train/injectable"

# # Output file
# output_path = "prompt_response_dataset.json"

# def load_files_from_directory(directory):
#     """Load all Python files from a given directory."""
#     file_data = {}
#     for filename in os.listdir(directory):
#         if filename.endswith(".py"):
#             filepath = os.path.join(directory, filename)
#             with open(filepath, "r") as f:
#                 file_data[filename] = f.read()
#     return file_data

# def pair_examples(vulnerable_files, patched_files):
#     """Pair vulnerable and patched files to create prompt-response pairs."""
#     all_pairs = []
    
#     vulnerable_keys = set(vulnerable_files.keys())
#     patched_keys = set(patched_files.keys())
#     common_keys = vulnerable_keys.intersection(patched_keys)
    
#     # Pair files with matching names
#     for key in common_keys:
#         vulnerable_code = vulnerable_files[key]
#         patched_code = patched_files[key]

#         # Inject vulnerability prompt
#         inject_prompt = f"Inject a vulnerability in the following code:\n{patched_code}"
#         inject_response = f"Here is a possible version of that code with a vulnerability:\n{vulnerable_code}"
#         all_pairs.append({"prompt": inject_prompt, "response": inject_response})

#         # Fix vulnerability prompt
#         fix_prompt = f"Fix the vulnerability in the following code:\n{vulnerable_code}"
#         fix_response = f"Here is the patched version of that code:\n{patched_code}"
#         all_pairs.append({"prompt": fix_prompt, "response": fix_response})
    
#     # Handle unmatched files (mix vulnerable and patched examples to generate more data)
#     unmatched_vulnerable = vulnerable_keys - common_keys
#     unmatched_patched = patched_keys - common_keys
#     unmatched_vulnerable_codes = [vulnerable_files[key] for key in unmatched_vulnerable]
#     unmatched_patched_codes = [patched_files[key] for key in unmatched_patched]
    
#     # Mix unmatched examples to generate extra data
#     for vulnerable_code in unmatched_vulnerable_codes:
#         for patched_code in random.sample(unmatched_patched_codes, min(len(unmatched_patched_codes), 5)):
#             inject_prompt = f"Inject a vulnerability in the following code:\n{patched_code}"
#             inject_response = f"Here is a possible version of that code with a vulnerability:\n{vulnerable_code}"
#             all_pairs.append({"prompt": inject_prompt, "response": inject_response})

#             fix_prompt = f"Fix the vulnerability in the following code:\n{vulnerable_code}"
#             fix_response = f"Here is the patched version of that code:\n{patched_code}"
#             all_pairs.append({"prompt": fix_prompt, "response": fix_response})

#     return all_pairs

# # Load vulnerable and patched files
# vulnerable_files = load_files_from_directory(vulnerable_dir)
# patched_files = load_files_from_directory(patched_dir)

# # Generate prompt-response pairs
# pairs = pair_examples(vulnerable_files, patched_files)

# # Save to JSON
# with open(output_path, "w") as f:
#     json.dump(pairs, f, indent=4)

# print(f"Prompt-response dataset saved to {output_path}")



import os
import json

def create_training_dataset(injectable_dir, noninjectable_dir, output_filepath="training_dataset.json"):
    """
    Creates a JSON dataset for fine-tuning, pairing patched (injectable)
    and vulnerable (noninjectable) Python code files.

    Args:
        injectable_dir (str): Path to the directory containing patched Python files.
        noninjectable_dir (str): Path to the directory containing vulnerable Python files.
        output_filepath (str): Path to save the resulting JSON dataset file.
    """
    dataset = []
    injectable_files = os.listdir(injectable_dir)
    noninjectable_files = os.listdir(noninjectable_dir)

    # Create sets for faster lookups
    noninjectable_files_set = set(noninjectable_files)

    for filename in injectable_files:
        if filename.endswith(".py"):
            injectable_filepath = os.path.join(injectable_dir, filename)
            noninjectable_filepath_candidate = os.path.join(noninjectable_dir, filename)

            if filename in noninjectable_files_set:
                try:
                    with open(injectable_filepath, 'r') as f_injectable:
                        patched_code = f_injectable.read()
                    with open(noninjectable_filepath_candidate, 'r') as f_noninjectable:
                        vulnerable_code = f_noninjectable.read()

                    prompt_text = f"Inject a vulnerability in the following scripts:\n\n```python\n{patched_code}\n```"
                    response_text = f"Here is the vulnerable version:\n\n```python\n{vulnerable_code}\n```"

                    dataset.append({"prompt": prompt_text, "response": response_text})

                except Exception as e:
                    print(f"Error processing files {filename}: {e}")

    with open(output_filepath, 'w') as outfile:
        json.dump(dataset, outfile, indent=4)

    print(f"Successfully created training dataset with {len(dataset)} examples at {output_filepath}")

if __name__ == "__main__":
    injectable_directory = "/Users/fredericbogaerts/vaitp/VAITP GUI/vaitp/vaitp_dataset/train/injectable/"
    noninjectable_directory = "/Users/fredericbogaerts/vaitp/VAITP GUI/vaitp/vaitp_dataset/train/noninjectable/"
    output_file = "training_dataset.json"

    create_training_dataset(injectable_directory, noninjectable_directory, output_file)