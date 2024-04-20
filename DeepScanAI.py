import os
from openai import OpenAI

# Set the API key as an environment variable
os.environ['OPENAI_API_KEY'] = 'lm-studio'

# Function to read source code files and analyze for vulnerabilities
def analyze_source_code(source_code_path, output_file_path, ai_model):
    # Point to the local server
    client = OpenAI(base_url="http://localhost:1234/v1")

    # Initialize history for AI interaction
    history = [
        {"role": "system", "content": "You are an intelligent assistant. You always provide well-reasoned answers that are both correct and helpful."},
        {"role": "user", "content": "Hello, introduce yourself to someone opening this program for the first time. Be concise."},
    ]

    # Get list of files and folders in the provided path
    files_and_folders = os.listdir(source_code_path)

    # Check each item in the directory
    for item in files_and_folders:
        item_path = os.path.join(source_code_path, item)
        
        # If item is a folder, recursively analyze its contents
        if os.path.isdir(item_path):
            analyze_source_code(item_path, output_file_path, ai_model)
        # If item is a file, read its content and analyze for vulnerabilities
        elif os.path.isfile(item_path):
            with open(item_path, 'rb') as file:
                try:
                    source_code = file.read().decode('utf-8')
                except UnicodeDecodeError:
                    try:
                        # Try decoding with 'latin-1' encoding
                        source_code = file.read().decode('latin-1')
                    except UnicodeDecodeError:
                        print(f"Skipping file: {item_path} due to decoding error")
                        continue
            
            # Create prompt message
            prompt_message = {
                "role": "user",
                "content": source_code + "\n\nList any security vulnerability in below source code. Ensure to include vulnerable code, line numbers and other details in a human readable secure source code reporting format. Dont report those issues where you are not certain, dont report version related issues, focus only on code, I/O and any function calls and dont give any generic recommendations if code is clean"
            }

            # Add prompt message to history
            history.append(prompt_message)

            # Request analysis from AI model
            completion = client.chat.completions.create(
                model=ai_model,
                messages=history,
                temperature=0.7,
                stream=True,
                max_tokens=1500,  # Limit the number of tokens to prevent API errors
            )
            
            # Extract AI response
            ai_response = ""
            initial_messages = 0  # Number of initial messages to skip
            for chunk in completion:
                if initial_messages < len(history):
                    initial_messages += 1
                    continue
                if chunk.choices[0].delta.content:
                    ai_response += chunk.choices[0].delta.content

            # Write AI response to output file
            with open(output_file_path, 'a') as output_file:
                output_file.write(f"\n\n{item_path}\n")
                output_file.write(ai_response)

            # Clear source code variable and remove prompt message from history
            del source_code
            history.pop()
            
            print(f"Analysis completed for: {item_path}")

# Main function
def main():
    # Ask user for source code path
    source_code_path = input("Enter the path to the source code directory: ")

    # Ask user for output file path
    output_file_path = input("Enter the path to save the vulnerability analysis report (including file name): ")

    # Ask user for AI model
    ai_model = input("Enter the AI model name: ")

    # Analyze source code for vulnerabilities
    analyze_source_code(source_code_path, output_file_path, ai_model)

    print("Vulnerability analysis completed!")

if __name__ == "__main__":
    main()
