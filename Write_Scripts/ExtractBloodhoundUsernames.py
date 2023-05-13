import argparse
import json


def extract_usernames(input_file, output_file):
    # Load JSON data from file
    with open(input_file, 'r') as f:
        data = json.load(f)

    # Extract "spotlight" field from JSON data
    spotlight = data['spotlight']

    # Loop through each key-value pair in the dictionary
    usernames = ""
    for key, value in spotlight.items():
        # Extract the name from the email address string and print it
        name = value[0].split('@')[0]
        usernames = usernames + name + "\n"
        if name != name.split('.')[0]:
            usernames = usernames + name.split('.')[0] + "\n"

    # Remove last newline character
    usernames = usernames.rstrip()

    # Write the usernames to a file
    with open(output_file, 'w') as f:
        f.write(usernames)

if __name__ == "__main__":
    # Set up argument parser
    parser = argparse.ArgumentParser(description='Extract usernames from a JSON file')
    parser.add_argument('input_file', type=str, help='path to input JSON file')
    parser.add_argument('output_file', type=str, help='path to output file')

    # Parse command line arguments
    args = parser.parse_args()

    # Call extract_usernames function with command line arguments
    extract_usernames(args.input_file, args.output_file)
