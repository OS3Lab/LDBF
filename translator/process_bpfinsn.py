import os
import subprocess
import sys

def process_instruction_files(directory_path):
	"""
	Iterates over all .txt files in a given directory, generates new filenames,
	and executes the disassembler.py script.
	It will skip any files that already end with '-trans.txt'.

	:param directory_path: The path to the directory to process.
	"""
	# 1. Check if the target directory exists.
	if not os.path.isdir(directory_path):
		print(f"Error: Directory '{directory_path}' not found.")
		sys.exit(1)

	print(f"Processing directory: {directory_path}\n")

	# 2. Iterate over all files in the directory.
	for filename in os.listdir(directory_path):
		if filename.endswith(".txt"):
			
			# --- NEW: Skip files that are already output files ---
			# Check if the filename already follows the output pattern (e.g., "123-trans.txt").
			if filename.endswith("-trans.txt"):
				print(f"Skipping previously generated file: {filename}")
				continue  # Stop processing this file and move to the next one.
			# --- END NEW ---

			# Construct the full path for the input file.
			input_file_path = os.path.join(directory_path, filename)
			
			# 3. Generate the output filename by appending "-trans".
			base_name, extension = os.path.splitext(filename)
			output_filename = f"{base_name}-trans{extension}"
			output_file_path = os.path.join(directory_path, output_filename)
			
			# Prepare the command to be executed.
			command = ["python", "disassembler.py", input_file_path, output_file_path]
			
			print(f"Executing: {' '.join(command)}")
			
			try:
				# 4. Execute the command.
				result = subprocess.run(command, check=True, capture_output=True, text=True, encoding='utf-8')
				print(f"Successfully processed: {filename}")
				# To see the output of disassembler.py, you can uncomment the following lines.
				# if result.stdout:
				#     print(f"Output:\n{result.stdout}")
			except FileNotFoundError:
				print("Error: 'python' or 'disassembler.py' not found. Please ensure they are available in your environment.")
				sys.exit(1)
			except subprocess.CalledProcessError as e:
				print(f"Error: Command failed while processing '{filename}'.")
				print(f"Return Code: {e.returncode}")
				print(f"Stderr:\n{e.stderr}")
				# Depending on your needs, you might want to continue or stop the script.
				# continue  # To continue with the next file.
				# sys.exit(1) # To stop the script immediately.

	print("\nFinished processing all .txt files.")

if __name__ == "__main__":
	# Use sys.argv to get the target directory from command-line arguments.
	if len(sys.argv) < 2:
		print("Usage: python process_files.py <path_to_directory>")
		sys.exit(1)
		
	target_directory = sys.argv[1]
	process_instruction_files(target_directory)