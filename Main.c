/*
// Main.c - contains all relevent code for the GMUCipher project (see documentation)
//
// Copyright (c) - 2021
*/
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <stdarg.h>
#include <ctype.h>
#include <sys/stat.h>
#include <errno.h>

#ifndef _countof
#define _countof(a) sizeof(a)/sizeof(a[0])
#endif

#ifndef SIZE_MAX
#define SIZE_MAX 0xffffffff
#endif

/*
// Struct that encapsulates a cipher key file.
*/
typedef struct CipherKeyFile
{
	size_t wordCount;
	char** wordArray;
	size_t size;
	char*  buffer;
} CipherKeyFile;

/*
// Frees a dynamically-allocated cipher key file from memory.
*/
void FreeCipherKeyFile(CipherKeyFile* cipherKeyFile)
{
	if (cipherKeyFile != NULL)
	{
		free(cipherKeyFile->wordArray);
		free(cipherKeyFile->buffer);
		free(cipherKeyFile);
	}
}

/*
// Enum for menu options.
*/
typedef enum MenuOption
{
	invalid,
	readCipher,
	encipher,
	decipher,
	quitProgram
} MenuOption;

/*
// Prints the menu options.
*/
void printMenuOptions()
{
	printf("***** Menu Options ******\n");
	printf("1) Enter a text file to use as a cipher key\n");
	printf("2) Enter a message to encipher\n");
	printf("3) Enter a text file to decipher\n");
	printf("4) Quit the program\n");
	printf("\n");
}

/*
 * Prints a line as page break.
 */
void pageBreak(void)
{
	printf("*********************************************************************************\n");
	printf("\n");
}

/*
// Prompts for a string value and returns its length (or EOF on error).
*/
int promptFor(char* buffer, int bufferSize, const char* prompt, ...)
{
	int newLength      = EOF;
	int originalLength = 0;
	int character      = 0;

	if (buffer != NULL && bufferSize > 0)
	{
		*buffer = '\0';

		if (prompt != NULL)
		{
			va_list alist;
			va_start(alist, prompt);

			vprintf(prompt, alist);

			va_end(alist);
		}

		if (fgets(buffer, bufferSize, stdin))
		{
			/*
			// Trim the trailing newlines from the input string:
			*/
			originalLength = strlen(buffer);

			newLength = originalLength;

			while (newLength > 0 && buffer[newLength - 1] == '\n')
			{
				buffer[--newLength] = '\0';
			}

			/*
			// Clear the input buffer if we didn't see a newline:
			*/
			if (originalLength == newLength)
			{
				while (!feof(stdin))
				{
					character = fgetc(stdin);

					if (character <= EOF || character == '\n')
					{
						break;
					}
				}
			}
		}
	}

	return newLength;
}

/*
// Prompts for an integer between a given range (inclusively).
*/
int promptForInt(int minValue, int maxValue, const char* prompt)
{
	char  buffer[100] = {0};
	char* remainder   = buffer;
	int   integer     = 0;

	while (true)
	{
		promptFor(buffer, _countof(buffer), prompt);

		integer = strtol(buffer, &remainder, 10);

		if (remainder == buffer || *remainder != '\0' || integer < minValue || integer > maxValue)
		{
			printf("\n");
			printf("An integer between %d and %d was expected.\n", minValue, maxValue);
			printf("\n");
		}
		else
		{
			break;
		}
	}

	return integer;
}

/*
// Prompts for a menu option.
*/
MenuOption promptForMenuOption()
{
	MenuOption option = invalid;

	printMenuOptions();

	option = promptForInt(1, 4, "Enter a menu option (#): ");
	printf("\n");

	return option;
}

/*
// Parses or counts the words in a given cipher key file.
*/
bool ParseWords(CipherKeyFile* cipherKeyFile)
{
	bool   success   = true;
	int    status    = 0;
	char*  cipherItr = NULL;
	char*  cipherEnd = NULL;
	int    wordState = 0;
	size_t wordIndex = 0;

	/*
	// Validate parameters:
	*/
	if (status == 0)
	{
		if (cipherKeyFile == NULL || cipherKeyFile->buffer == NULL)
		{
			status = EINVAL;
		}
		else if (cipherKeyFile->wordArray == NULL)
		{
			cipherKeyFile->wordCount = 0;
		}
	}

	/*
	// Count or parse words in the content buffer:
	*/
	if (status == 0)
	{
		wordState  = 0;
		wordIndex  = 0;
		cipherItr = cipherKeyFile->buffer;
		cipherEnd = cipherKeyFile->buffer + cipherKeyFile->size;

		while (cipherItr < cipherEnd)
		{
			if (wordState == 0) /* Skip white space. */
			{
				if (isspace(*((unsigned char*)cipherItr)))
				{
					++cipherItr;
				}
				else
				{
					wordState = 1;
				}
				continue;
			}

			if (wordState == 1) /* Start of word. */
			{
				if (cipherKeyFile->wordArray != NULL)
				{
					if (wordIndex >= cipherKeyFile->wordCount)
					{
						status = ERANGE;
						break;
					}
					else
					{
						cipherKeyFile->wordArray[wordIndex] = cipherItr;

						++wordIndex;
					}
				}
				else
				{
					++cipherKeyFile->wordCount;
				}

				wordState = 2;

				continue;
			}

			if (wordState == 2) /* Skip over word. */
			{
				if (isspace(*((unsigned char*)cipherItr)))
				{
					wordState = 0;

					if (cipherKeyFile->wordArray != NULL)
					{
						*cipherItr++ = '\0';
					}
				}
				else
				{
					++cipherItr;
				}
				continue;
			}
		}

		if (cipherKeyFile->wordArray != NULL)
		{
			*cipherItr = '\0';
		}
	}

	/*
	// Return true on success, false otherwise:
	*/
	if (status != 0)
	{
		errno   = status;
		success = false;
	}

	return success;
}

/*
// Prompts for a text file and stores the contents as the cipher key.
*/
CipherKeyFile* readCipherKey()
{
	CipherKeyFile* cipherKeyFile = NULL;
	int            status        = 0;
	char           fileName[200] = {0};
	FILE*          fpInput       = 0;
	struct stat    statBuffer    = {0};
	int            charIndex     = 0;

	cipherKeyFile = NULL;

	/*
	// Allocate and initialize cipher key file:
	*/
	if (status == 0)
	{
		cipherKeyFile = (CipherKeyFile*)calloc(1, sizeof(CipherKeyFile));

		if (cipherKeyFile == NULL)
		{
			status = ENOMEM;
		}
	}

	/*
	// Open a prompted file and get file size:
	*/
	promptFor(fileName, _countof(fileName), "Enter the name of the cipher key text file: ");
	printf("\n");

	if (status == 0)
	{
		fpInput = fopen(fileName, "rb");

		if (fpInput == NULL)
		{
			status = errno;
		}
		else if (fstat(_fileno(fpInput), &statBuffer) != 0)
		{
			status = errno;
		}
		else if (statBuffer.st_size > SIZE_MAX - sizeof(char))
		{
			status = EFBIG;
		}
		else
		{
			cipherKeyFile->size = (size_t)statBuffer.st_size;
		}
	}

	/*
	// Allocate cipher key file buffer and read file:
	*/
	if (status == 0)
	{
		cipherKeyFile->buffer = malloc(cipherKeyFile->size + sizeof(char));

		if (cipherKeyFile == NULL)
		{
			status = ENOMEM;
		}
		else if (fread(cipherKeyFile->buffer, sizeof(char), cipherKeyFile->size, fpInput) != cipherKeyFile->size)
		{
			status = errno;
		}
		else
		{
			cipherKeyFile->buffer[cipherKeyFile->size / sizeof(char)] = '\0';

			while (cipherKeyFile->buffer[charIndex] != '\0')
			{
				tolower(cipherKeyFile->buffer[charIndex]);
				++charIndex;
			}
		}
	}

	/*
	// Count and parse words in the content buffer:
	*/
	if (status == 0)
	{
		if (!ParseWords(cipherKeyFile))
		{
			status = errno;
		}
		else
		{
			cipherKeyFile->wordArray = (char**)calloc(cipherKeyFile->wordCount, sizeof(char*));

			if (cipherKeyFile->wordArray == NULL)
			{
				status = ENOMEM;
			}
			else if (!ParseWords(cipherKeyFile))
			{
				status = errno;
			}
		}
	}

	/*
	// Clean-up before return:
	*/
	if (fpInput != NULL)
	{
		fclose(fpInput);
	}

	/*
	// Return cipher key file or NULL on error:
	*/
	if (status != 0)
	{
		FreeCipherKeyFile(cipherKeyFile);
		cipherKeyFile = NULL;
		errno         = status;
	}

	return cipherKeyFile;
}

/*
// Enciphers a given message.
*/
bool encipherMessage(CipherKeyFile* cipherKeyFile, char* message, int messageLength, char* result, size_t resultSize)
{
	bool  success    = true;
	char* resultItr  = result;
	int   status     = 0;
	char* messageItr = message;
	char* messageEnd = message + messageLength;
	
	char   character = 0;
	size_t wordIndex = 0;
	size_t charIndex = 0;
	size_t occurance = 0;
	bool   found     = false;
	bool   foundOne  = false;

	/*
	// Validate parameters:
	*/
	if (status == 0)
	{
		if (cipherKeyFile == NULL || cipherKeyFile->buffer == NULL
			|| cipherKeyFile->wordArray == NULL || message == NULL)
		{
			status = EINVAL;
		}
	}

	/*
	// Encipher the message:
	*/
	if (status == 0)
	{
		while (messageItr < messageEnd)
		{
			*resultItr = '\0';

			if (isspace(*messageItr))
			{
				if (resultItr > result && *(resultItr - 1) == ',')
					--resultItr;
				*resultItr++ = *messageItr;
			}
			else
			{
				character = tolower(*messageItr);
				wordIndex = 0;
				charIndex = 0;
				occurance = (rand() % 10) + 1;
				found     = false;
				foundOne  = false;

				do
				{
					for (wordIndex = 0; wordIndex < cipherKeyFile->wordCount; ++wordIndex)
					{
						char*  word       = cipherKeyFile->wordArray[wordIndex];
						size_t wordLength = strlen(word);

						for (charIndex = 0; charIndex < wordLength; ++charIndex)
						{
							if (word[charIndex] == character)
							{
								foundOne = true;

								if (occurance == 1)
								{
									found = true;
									break;
								}

								--occurance;
							}
						}

						if (found)
							break;
					}

					if (found)
						break;
				}
				while (foundOne);

				if (!found)
				{
					resultItr += sprintf(resultItr, "#,");
				}
				else
				{
					resultItr += sprintf(resultItr, "%u,%u,", wordIndex, charIndex);
				}
			}
			++messageItr;
		}

		if (resultItr > result)
		{
			*(--resultItr) = '\0';
		}
	}

	/*
	// Return true on success, otherwise false:
	*/
	if (status != 0)
	{
		errno   = status;
		success = false;
	}

	return success;
}

/*
// Reads a prompted message and enciphers the content, storing the enciphered result in a prompted file.
*/
bool encipherFile(CipherKeyFile* cipherKeyFile)
{
	bool  success       = true;
	int   status        = 0;
	char  message[2000] = {0};
	char  result[4000]  = {0};
	char  fileName[200] = {0};
	FILE* fpOutput      = NULL;

	/*
	// Prompt for and encipher a message:
	*/
	if (status == 0)
	{
		promptFor(message, _countof(message), "Enter a message to encipher:\n");
		printf("\n");

		if (!encipherMessage(cipherKeyFile, message, strlen(message), result, sizeof(result)))
		{
			status  = errno;
		}
	}

	/*
	// Prompt for and open file to write to:
	*/
	if (status == 0)
	{
		promptFor(fileName, _countof(fileName), "Enter the name of the text file to store the results in: ");
		printf("\n");

		fpOutput = fopen(fileName, "wt");

		if (fpOutput == NULL)
		{
			status = errno;
		}
	}

	/*
	// Write enciphered message to file:
	*/
	if (status == 0)
	{
		fputs(result, fpOutput);
        fclose(fpOutput);
	}

	/*
	// Return true on success, otherwise false:
	*/
	if (status != 0)
	{
		errno  = status;
		success = false;
	}

	return success;
}

/*
// Reads a prompted file and deciphers the contents, storing the deciphered result in the file.
*/
bool decipherFile(CipherKeyFile* cipherKeyFile)
{
	bool        success       = true;
	int         status        = 0;
	char        fileName[200] = {0};
	FILE*       fpInput       = NULL;
	struct stat statBuffer    = {0};
	char*       buffer        = NULL;
	size_t      bufferSize    = 0;
	char*       bufferItr     = NULL;
	char*       bufferEnd     = NULL;
	size_t      wordIndex     = 0;
	size_t      charIndex     = 0;
	int         cIndex        = 0;

	/*
	// Prompt for the name of the file to decipher:
	*/
	if (status == 0)
	{
		promptFor(fileName, _countof(fileName), "Enter the name of the text file to decipher: ");
		printf("\n");

		fpInput = fopen(fileName, "rb"); 

		if (fpInput == NULL)
		{
			status = errno;
		}
		else if (fstat(_fileno(fpInput), &statBuffer) != 0)
		{
			status = errno;
		}
		else if (statBuffer.st_size > SIZE_MAX - sizeof(char))
		{
			status = EFBIG;
		}
		else
		{
			bufferSize = (size_t)statBuffer.st_size;
		}
	}

	/*
	// Read and store the file content:
	*/
	if (status == 0)
	{
		buffer = (char*)calloc(bufferSize / sizeof(char) + 1, bufferSize + sizeof(char));

		if (buffer == NULL)
		{
			status = errno;
		}
		else if (fread(buffer, sizeof(char), bufferSize, fpInput))
		{
			status = errno;
		}
		else
		{
			buffer[bufferSize / sizeof(char)] = '\0';
		}
	}

	/*
	// Decipher and print the stored file content to the console:
	*/
	if (status == 0)
	{
		bufferItr = buffer;
		bufferEnd = NULL;

		while (*bufferItr != '\0')
		{
			if (isspace(*bufferItr))
			{
				printf("%c", *bufferItr);
				++bufferItr;
			}
			else if (*bufferItr == '#')
			{
				printf("#");
				++bufferItr;

				if (*bufferItr == ',')
				{
					++bufferItr;
				}
			}
			else if (isdigit(*bufferItr))
			{
				wordIndex = strtol(bufferItr, &bufferEnd, 10);
				charIndex = strtol(bufferEnd+1, &bufferEnd, 10);

				printf("%c", cipherKeyFile->wordArray[wordIndex][charIndex]);

				bufferItr = bufferEnd;

				if (*bufferItr == ',')
				{
					++bufferItr;
				}
			}

			if (*bufferItr == '\0')
			{
				printf("\n");
			}
		}

		printf("\n");
	}

	/*
	// Return true on success, otherwise false:
	*/
	if (status != 0)
	{
		errno   = status;
		success = false;
	}

	free(buffer);

	return success;
}

/*
// Program entry point. Main program loop.
*/
int main()
{
	int            status        = 0;
	MenuOption     option        = invalid;
	CipherKeyFile* cipherKeyFile = NULL;

	while (true)
	{
		/*
		// Prompt for a menu option:
		*/
		do
		{
			option = promptForMenuOption();
		}
		while (option == invalid);

		pageBreak();

		/*
		// Handle menu option:
		*/
		if (option == quitProgram)
		{
			printf("Cipher task completed successfully. Self destructing in 3...2...1...\n");
			break;
		}

		switch (option)
		{
			/*
			// Read a cipher key: 
			*/
			case readCipher:
			{
				if (status == 0)
				{
					cipherKeyFile = readCipherKey();

					if (cipherKeyFile == NULL)
					{
						status = errno;
						fprintf(stderr, "Could not read file (%d): %s.\n", status, strerror(status));
						break;
					}
				}

				break;
			}

			/*
			// Encipher message from console:
			*/
			case encipher:
			{
				if (status == 0)
				{
					if (cipherKeyFile == NULL)
					{
						cipherKeyFile = readCipherKey();

						if (cipherKeyFile == NULL)
						{
							status = errno;
							fprintf(stderr, "Could not read file (%d): %s.\n", status, strerror(status));
							break;
						}
					}
				}

				if (status == 0)
				{
					if (!encipherFile(cipherKeyFile))
					{
						status = errno;
						fprintf(stderr, "Could not encipher message (%d): %s.\n", status, strerror(status));
						break;
					}
				}

				break;
			}

			/*
			// Decipher message from file:
			*/
			case decipher:
			{
				if (status == 0)
				{
					if (cipherKeyFile == NULL)
					{
						cipherKeyFile = readCipherKey();

						if (cipherKeyFile == NULL)
						{
							status = errno;
							fprintf(stderr, "Could not read file (%d): %s.\n", status, strerror(status));
							break;
						}
					}
				}

				if (status == 0)
				{
					if (!decipherFile(cipherKeyFile))
					{
						status = errno;
						fprintf(stderr, "Could not decipher file (%d): %s.\n", status, strerror(status));
						break;
					}
				}

				break;
			}

			default:
			{
				#ifdef _DEBUG
				printf("You shouldn't be here...\n.");
				#endif
			}
		}

		pageBreak();

		if (status != 0)
			break;
	}

	FreeCipherKeyFile(cipherKeyFile);

	return status;
}