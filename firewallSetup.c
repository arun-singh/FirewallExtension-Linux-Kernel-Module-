
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <regex.h>
#include "linked_list.h"
#include <fcntl.h>
#include <unistd.h>

#define BUFFERLENGTH 256
#define PROC_ENTRY_FILENAME "/proc/firewallExtension"

void writeToProc(List * ruleList, char * flag){
	int procFd = open (PROC_ENTRY_FILENAME, O_WRONLY);
	if(procFd==-1){
		fprintf (stderr, "Opening proc file failed!\n");
		if(ruleList!=NULL)
			free_list(ruleList);
		close(procFd);
    	exit (1);
	}

	write(procFd, flag, 2); //write flag
	if(strcmp(flag, "W")==0){ //new rules
		ListItem * curr = ruleList->p_head;
		while(curr!=NULL){
			write(procFd, curr->p_data, strlen(curr->p_data)+1);
			curr=curr->p_next;
		}
		write(procFd, "EOF", 4); //end of file
		free_list(ruleList);
	}

	close(procFd);
}

void parseRules(char * filename){
	FILE * firewallRules = fopen(filename, "r");
	char rule[BUFFERLENGTH];
	struct stat st;
	List * ruleList = create_list();
	int count = 0;
	//Process each rule
	while(fgets(rule, sizeof(rule), firewallRules)){
		count++;
  		//check each rule is well formed
		regex_t regex;
		int res;

		regcomp(&regex, "[0-9]+ (\\/\\w+)+\\n", REG_EXTENDED);
		res = regexec(&regex, rule, 0, NULL, 0);
		if(res!=0){
			printf("%s\n", "ERROR: Ill-formed file");
			regfree(&regex);
			fclose(firewallRules);
			free_list(ruleList);
			exit(0);
		}
		regfree(&regex);

		//split each rule to get filename
		char * token;
  		char * save;
		int len = strlen(rule);

		char tmp[len+1];
		strncpy(tmp, rule, len);

		if(tmp[len-1]=='\n')
			tmp[len-1]='\0';

		token = strtok_r(tmp, " ", &save);
		token = strtok_r(NULL, " ", &save);
		char * filename = token;

		//check path exists
		if(stat(filename, &st)!=0){
			printf("%s\n", "ERROR: Cannot execute file");
			fclose(firewallRules);
			free_list(ruleList);
			exit(0);
		}
		//rule passed all checks
		append_list(ruleList, rule);
	}

	fclose(firewallRules);
	writeToProc(ruleList, "W");
}


int main (int argc, char **argv) {

	if(argv[1]==NULL){
		printf("%s %s\n", argv[0], "Usage: L | W <filename>");
		exit(0);
	}

	char * flag = argv[1];
	if(strcmp(flag, "L")==0){
		writeToProc(NULL, "L");
	}else if(strcmp(flag, "W")==0){
		if(argv[2]==NULL){
			printf("%s\n", "ERROR: Filename required");
			exit(0);
		}
		parseRules(argv[2]);
	}else{
		printf("%s %s\n", argv[0], "Usage: L | W <filename>");
		exit(0);
	}

	return 0;
}





