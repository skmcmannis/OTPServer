//Generates key files for use with OTP encryption
// Input example: keygen keylength
// Input example with output redirection: keygen keylength > keyfilename
//Author: Shawn McMannis
//Last mod date: 6/6/2019


#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


//main
int main(int argc, const char* argv[])
{
	int keylength;
	char* key = NULL;

	//File variable for output
	FILE* outputFile;

	//Seed the random generator
	srand(time(0));

	//Check for proper arguments
	if(argc < 2)
	{
		fprintf(stderr, "USAGE: %s keylength\n", argv[0]);
		exit(0);
	}

	//Store keylength
	keylength = atoi(argv[1]);

	//Allocate array space for key
	key = calloc(keylength + 1, sizeof(char));
	assert(key != NULL);

	//Generate key
	char* c;
	int i, n;
	for(i = 0;i < keylength;i++)
	{
		//Generate random number between 0 and 26, inclusive
		n = rand() % 27;

		//Convert generated integer to character
		switch(n)
		{
			case 0:
				c = "A";
				break;
			case 1:
				c = "B";
				break;
			case 2:
				c = "C";
				break;
			case 3:
				c = "D";
				break;
			case 4:
				c = "E";
				break;
			case 5:
				c = "F";
				break;
			case 6:
				c = "G";
				break;
			case 7:
				c = "H";
				break;
			case 8:
				c = "I";
				break;
			case 9:
				c = "J";
				break;
			case 10:
				c = "K";
				break;
			case 11:
				c = "L";
				break;
			case 12:
				c = "M";
				break;
			case 13:
				c = "N";
				break;
			case 14:
				c = "O";
				break;
			case 15:
				c = "P";
				break;
			case 16:
				c = "Q";
				break;
			case 17:
				c = "R";
				break;
			case 18:
				c = "S";
				break;
			case 19:
				c = "T";
				break;
			case 20:
				c = "U";
				break;
			case 21:
				c = "V";
				break;
			case 22:
				c = "W";
				break;
			case 23:
				c = "X";
				break;
			case 24:
				c = "Y";
				break;
			case 25:
				c = "Z";
				break;
			case 26:
				c = " ";
				break;
		}

		//Concatenate the generated character to the key
		strcat(key, c);
	}

	//Add newline to the key
	strcat(key, "\n");

	//If no output redirect, print key to stdout
	if(argc == 2)
	{
		printf("%s", key);
	}
	//else print to provided filename
	else if(argv[2] == ">" && argc == 4)
	{
		outputFile = fopen(argv[3], "w");
		//Check for error
		if(outputFile == NULL)
		{
			fprintf(stderr,"Cannot open file %s\n", argv[3]);
			exit(0);
		}
		//If no errors, write to file
		else
		{
			fprintf(outputFile, key);
		}

		//Close the file
		fclose(outputFile);
	}

	//Free memory
	free(key);
	
	return 0;
}
