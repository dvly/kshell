#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
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
	int background; /*Background = 1 si la commande est lance avec & sinon background = 0*/

	struct common data;

	size_t length;
	fd = open("/dev/kshell", O_RDWR);
	if (fd == -1){
		printf("Erreur d'ouverture du fichier /dev/kshell\n");
		exit(1);
	}

	for(;;){
		nb_arg = 0;
		background = 0;
		return_value = 0;
		
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

		/*Foreground ou background*/
		if(strcmp(cmd_arg[nb_arg-1], "&") == 0)
			background = 1;

		/*Mettre tous les caractères de la commande en minuscule*/
		for(i = 0; cmd_arg[0][i]; i++){
			cmd_arg[0][i] = tolower(cmd_arg[0][i]);
		}

		/*Clean la variable common*/
		memset(&data, '\0', sizeof(struct common));

		if(strcmp(cmd_arg[0], "list") == 0){
			printf("list\n"); 
			if(nb_arg != 1){
				if(background){
					printf("Impossible de lancer list en arriere plan\n");
					goto CONT;
				}
				else
					goto ERRNBARG;
			}

			return_value = ioctl(fd, SYNC_IOC_LIST, &data);
		}
		else if(strcmp(cmd_arg[0], "fg") == 0){
			printf("fg\n");
			if(nb_arg != 2){
				if(background){	
					printf("Impossible de lancer fg en arrière plan\n");
					goto CONT;
				}
				else
					goto ERRNBARG;
			}
			data.cmd_id = atoi(cmd_arg[1]);
			return_value = ioctl(fd, SYNC_IOC_FG, (void*)&data);
		}
		else if(strcmp(cmd_arg[0], "kill") == 0){
			printf("kill\n");
			if(nb_arg == 3){ 
				data.cmd_id = atoi(cmd_arg[2]); 
				data.sig = atoi(cmd_arg[1]+1);

				return_value = ioctl(fd, SYNC_IOC_KILL, (void*)&data);
			}
			else if(nb_arg == 4 && background){ 
				data.cmd_id = atoi(cmd_arg[2]); 
				data.sig = atoi(cmd_arg[1]+1);

				return_value = ioctl(fd, ASYNC_IOC_KILL, (void*)&data);
			}
			else
				goto ERRNBARG;
		}
		else if(strcmp(cmd_arg[0], "wait") == 0){
			printf("wait\n");
			if(nb_arg < 2)
				goto ERRNBARG;
			if(nb_arg > 2 && background){ 
			/*TODO : Initialiser data*/
				return_value = ioctl(fd, ASYNC_IOC_WAIT, (void*)&data);
			}
			else if(nb_arg >= 2){ 
				return_value = ioctl(fd, SYNC_IOC_WAIT, (void*)&data);
			}
			else
				goto ERRNBARG;
		}
		else if(strcmp(cmd_arg[0], "meminfo") == 0){
			printf("meminfo\n");
			if(nb_arg == 2 && background)	
				return_value = ioctl(fd, ASYNC_IOC_MEMINFO, (void*)&data);
			else if(nb_arg == 1)
				return_value = ioctl(fd, SYNC_IOC_MEMINFO, (void*)&data);
			else
				goto ERRNBARG;
		}
		else if(strcmp(cmd_arg[0], "modinfo") == 0){
			printf("modinfo\n");

			if(nb_arg >= 2){
				data.len = strlen(cmd_arg[1]);
				strcpy(data.name, cmd_arg[1]);
				printf("Le strlen de %s : %d\n", data.name, data.len);
			}

			if(nb_arg == 3 && background)	
				return_value = ioctl(fd, ASYNC_IOC_MODINFO, (void*)&data);
			else if(nb_arg == 2)
				return_value = ioctl(fd, SYNC_IOC_MODINFO, (void*)&data);
			else
				goto ERRNBARG;
		}
		else{
			printf("La commande demandée n'existe pas\n");
		}

		if(return_value < 0){
			printf("ERROR %d\n", return_value);
			goto CONT;
		}	

		if(!background){
			printf("%s", data.buffer);
			while(data.pipe_id != 0){
				memset(data.buffer, '\0', USER_BUFFER_SIZE-1);
				data.cmd_id = data.pipe_id;
				return_value = ioctl(fd, SYNC_IOC_FG, &data);
				if(return_value < 0){
					printf("ERROR %d\n", return_value);
					goto CONT;
				}
				printf("%s", data.buffer);
			}
		}

		goto CONT;
	
ERRNBARG: printf("Le nombre d'arguments passés avec la commande %s n'est pas correct\n", cmd_arg[0]);

CONT:	if(cmd_arg != NULL){
			free(cmd_arg);
			/* Important de refaire pointer vers NULL, sinon il n'est pas possible de
			 * realloc un pointeur non initialise soit par NULL soit par malloc
			 */
			cmd_arg = NULL;
		}
		printf("continue\n");
		continue;
	}

	printf("after for loop\n");
	close(fd);
}
