#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "common.h"

#define MAX_CMD_SIZE 1024


int main(int argc, char *argv[]){
	char cmd[MAX_CMD_SIZE];
	char *cmd_token;
	char **cmd_arg = NULL;

	int nb_arg;
	int i;
	int fd;
	int return_value;

	size_t length;
	/*fd = open("/dev/kshell", O_RDWR);
	if (fd == -1){
		printf("Erreur d'ouverture du fichier /dev/kshell\n");
		exit(1);
	}*/

	for(;;){
		nb_arg = 0;
		
		printf("Veuillez entrer votre commande\n");
		/*Buffer overflow protection*/
		fgets(cmd, MAX_CMD_SIZE, stdin);
		cmd_token = strtok(cmd, " ");

		/* Split la commande selon les espaces pour recuperer les arguments de la commande*/
		while(cmd_token != NULL){
			cmd_arg = realloc(cmd_arg, sizeof (char*) * ++nb_arg);
			
			if(cmd_arg == NULL){
				printf("Memory allocation failed\n");
				exit(-1);
			}

			cmd_arg[nb_arg - 1] = cmd_token;
			cmd_token = strtok(NULL, " ");
		}

		cmd_arg = realloc (cmd_arg, sizeof (char*) * (nb_arg +1));
		cmd_arg[nb_arg] = 0;
 
		/*fgets recupère aussi \n de la fin, ce qu'on retire ici*/
		length = strlen(cmd_arg[nb_arg-1]) - 1;
		if (cmd_arg[nb_arg-1][length] == '\n')
			cmd_arg[nb_arg-1][length] = '\0';

		/*Mettre tous les caractères de la commande en minuscule*/
		for(i = 0; cmd_arg[0][i]; i++){
			cmd_arg[0][i] = tolower(cmd_arg[0][i]);
		}

		if(strcmp(cmd_arg[0], "list") == 0){
			printf("list\n"); 
			if(nb_arg != 1)
				goto ERRNBARG;

			/*return_value = ioctl(fd, KSHELL_IOC_LIST,
			if(return_value == -1)
				return errno;*/
		}
		else if(strcmp(cmd_arg[0], "fg") == 0){
			printf("fg\n");
			if(nb_arg != 2)
				goto ERRNBARG;
		}
		else if(strcmp(cmd_arg[0], "kill") == 0){
			printf("kill\n");
			if(nb_arg != 3)
				goto ERRNBARG;
		}
		else if(strcmp(cmd_arg[0], "wait") == 0){
			printf("wait\n");
			if(nb_arg < 2)
				goto ERRNBARG;
		}
		else if(strcmp(cmd_arg[0], "meminfo") == 0){
			printf("meminfo\n");
			if(nb_arg != 1)
				goto ERRNBARG;
		}
		else if(strcmp(cmd_arg[0], "modinfo") == 0){
			printf("modinfo\n");
			if(nb_arg != 2)
				goto ERRNBARG;
		}
		else{
			printf("La commande demandée n'existe pas\n");
		}
		
		if(cmd_arg != NULL){
			free(cmd_arg);
			/* Important de refaire pointer vers NULL, sinon il n'est pas possible de
			 * realloc un pointeur non initialise soit par NULL soit par malloc
			 */
			cmd_arg = NULL;
		}
		continue;

ERRNBARG: printf("Le nombre d'arguments passés avec la commande %s n'est pas correct\n", cmd_arg[0]);

	}

	close(fd);
}
