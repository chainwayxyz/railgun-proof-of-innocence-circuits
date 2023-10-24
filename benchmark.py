import subprocess

def get_non_linear_constraints(circuit_file, output_folder):
    command = ["circom", circuit_file, "--r1cs", "-o", output_folder]
    result = subprocess.run(command, capture_output=True, text=True)

    if result.returncode != 0:
        return None

    for line in result.stdout.split("\n"):
        if "non-linear constraints:" in line:
            return int(line.split(":")[1].strip())
    return None

def comment_code(file_path, start_line, end_line):
    with open(file_path, 'r') as file:
        lines = file.readlines()

    # Comment out all lines from start_line+1 to end_line
    for i in range(start_line, end_line):
        if not lines[i].startswith("//"):
            lines[i] = "// " + lines[i]

    with open(file_path, 'w') as file:
        file.writelines(lines)

def calculate_constraints_for_range(file_path, executable_file_path, benchmark_output_file_path, line_range, output_folder):
    original_content = None
    with open(file_path, 'r') as file:
        original_content = file.readlines()

    with open(benchmark_output_file_path, 'w') as file:
        file.writelines(original_content)

    previous_constraints = None
    for end in range(line_range[0], line_range[1] + 1):
        # Restore the original content before each iteration
        with open(file_path, 'w') as file:
            file.writelines(original_content)

        # Comment the code
        comment_code(file_path, end, line_range[1])

        # Calculate constraints
        constraints = get_non_linear_constraints(executable_file_path, output_folder)
        if constraints is not None:
            increase = 0
            if previous_constraints:
                increase = constraints - previous_constraints
            
            print(f"Non-linear constraints for ({line_range[0]}, {end}) -> {constraints} (+{increase})")

            # Add constraints as a comment at the end of the line
            with open(benchmark_output_file_path, 'r') as file:
                lines = file.readlines()
            lines[end - 1] = lines[end - 1].rstrip() + f" // Constraints: {constraints} (+{increase})\n"
            with open(benchmark_output_file_path, 'w') as file:
                file.writelines(lines)

            previous_constraints = constraints

if __name__ == "__main__":
    file_path = "circuits/library/poi-transaction.circom"
    executable_file_path = "circuits/poi-transaction-13x13.circom"
    benchmark_output_file_path = "circuits/benchmark/poi-transaction-13x13.circom"
    line_range = (11, 128)
    output_folder = "artifacts/circuits"
    calculate_constraints_for_range(file_path, executable_file_path, benchmark_output_file_path, line_range, output_folder)
