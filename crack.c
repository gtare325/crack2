#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "md5.h"

const int PASS_LEN = 20;        // Maximum any password will be
const int HASH_LEN = 33;        // Length of MD5 hash strings


// Given a target plaintext word, use it to try to find
// a matching hash in the hashFile.
// Get this function working first!
char * tryWord(char * plaintext, char * hashFilename)
{
    // Hash the plaintext
    char *hash = md5(plaintext, strlen(plaintext));
    if (!hash) return NULL;

    // Open the hash file
    FILE *fp = fopen(hashFilename, "r");
    if (!fp) {
        fprintf(stderr, "Error opening hash file\n");
        free(hash);
        return NULL;
    }

    // Loop through the hash file, one line at a time.
    char line[HASH_LEN];
    while (fgets(line, HASH_LEN, fp)) {
        
        int i = 0;
        while (line[i] != '\0') {
            if (line[i] == '\n') {
                line[i] = '\0';
                break;
            }
            i++;
        }

        // Attempt to match the hash from the file to the hash of the plaintext.
        if (strcmp(hash, line) == 0) {
            fclose(fp);
            return hash;
        }
    }

    // Close files?
    fclose(fp);

    // Free memory?
    free(hash);

    // Null if hash wasnt found
    return NULL;
}


int main(int argc, char *argv[])
{
    if (argc < 3) 
    {
        fprintf(stderr, "Usage: %s hash_file dict_file\n", argv[0]);
        exit(1);
    }

    // These two lines exist for testing. When you have
    // tryWord working, it should display the hash for "hello",
    // which is 5d41402abc4b2a76b9719d911017c592.
    // Then you can remove these two lines and complete the rest
    // of the main function below.
    char *found = tryWord("hello", "hashes00.txt");
    printf("%s %s\n", found, "hello");


    // Open the dictionary file for reading.
    FILE *dictFile = fopen(argv[2], "r");
    if (!dictFile) {
        fprintf(stderr, "Error opening dictionary file\n");
        exit(1);
    }

    int cracked = 0;
    char word[PASS_LEN];

    // For each dictionary word, pass it to tryWord, which
    // will attempt to match it against the hashes in the hash_file.
    while (fgets(word, PASS_LEN, dictFile)) {
        // Remove newline manually
        int i = 0;
        while (word[i] != '\0') {
            if (word[i] == '\n') {
                word[i] = '\0';
                break;
            }
            i++;
        }

        // If we got a match, display the hash and the word. For example:
        //   5d41402abc4b2a76b9719d911017c592 hello
        char *found = tryWord(word, argv[1]);
        if (found) {
            printf("%s %s\n", found, word);
            free(found);
            cracked++;
        }
    }
    
    // Close the dictionary file.
    fclose(dictFile);

    // Display the number of hashes that were cracked.
    printf("%d hashes cracked!\n", cracked);
}
