Encrypts/decrypts user input using Rivest cipher 6 algorithm, a symmetric key block cipher.
This implementation uses 20 rounds and includes the key scheduler.

Execute with the following parameters:
	<input-file-name> <output-file-name>

File format:
	Line 1: Specify encrypt/decrypt with the string "Encryption" or "Decryption"
	Line 2: Specify plaintext as follows: "plaintext: 01 23 45 56 67 78 9a bc de f0...", 
			or specift ciphertext as follows: "ciphertext: 01 23 45 67 89 ab..."
	Line 3: Specify key for key scheduler as follows: "userkey: se cr et ke y1 23 45..."

(An example input file "example_input.txt" is included in folder)

Notes:
	Machine architecture requirement: Only known to work correctly on 32-bit machines (tested on Linux)
	Plaintext/Ciphertext can have any size as input is padded, but the key must be 32 bytes (32 characters)
	Must compile and then execute
	Input file must exist in current directory

