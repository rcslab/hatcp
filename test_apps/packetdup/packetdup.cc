#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/event.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

#include "vars.h"

#define APP_PORT	6123
#define CTL_PORT	6124
#define BUFSZ 65535

#define MSO 3
#define RSO 1
#define CLI 0

#define	SOMIG_CB_TCPCB		0
#define	SOMIG_CB_INPCB		1
#define	SOMIG_CB_CC		2

const char* CTL_PRI_ADDR = "172.16.1.150";
const char* CTL_REP_ADDR = "172.16.0.151";
const char* APP_ADDR = "172.16.0.150";

void send_msg(int fd, char *str);

struct cmd_table_entry {
	const char* cmd;
	void (*func)(int fd, char *para);
};

void func_cmd_info(int fd, char *para);
#define CMD_INFO {"info", &func_cmd_info}
const struct cmd_table_entry cmd_info = CMD_INFO;

void func_cmd_migrate(int fd, char *para);
#define CMD_MIGRATE {"migrate", &func_cmd_migrate}
const struct cmd_table_entry cmd_migrate = CMD_MIGRATE;

void func_cmd_gen(int fd, char *para);
#define CMD_GEN {"gen", &func_cmd_gen}
const struct cmd_table_entry cmd_gen = CMD_GEN;

void func_cmd_tcpcb(int fd, char *para);
#define CMD_TCPCB {"tcpcb", &func_cmd_tcpcb}
const struct cmd_table_entry cmd_tcpcb = CMD_TCPCB;

void func_cmd_inpcb(int fd, char *para);
#define CMD_INPCB {"inpcb", &func_cmd_inpcb}
const struct cmd_table_entry cmd_inpcb = CMD_INPCB;

void func_cmd_ccv(int fd, char *para);
#define CMD_CCV {"ccv", &func_cmd_ccv}
const struct cmd_table_entry cmd_ccv = CMD_CCV;


const struct cmd_table_entry cmd_table[6] = {
	cmd_info,
	cmd_migrate,
	cmd_gen,
	cmd_tcpcb,
	cmd_inpcb,
	cmd_ccv
};

int verbose = 0;


void 
func_cmd_info(int fd, char *para)
{
	int opt = 1;
	socklen_t optlen;
#ifdef SOMIGRATION
	sleep(1);
	getsockopt(fd, SOL_SOCKET, SO_MIG_DEBUG, &opt, &optlen);
#else
	printf("Current kernel build does not support this command.\n");
#endif
}

void
func_cmd_migrate(int fd, char *para)
{
	int optlen, error;
#ifdef SOMIGRATION
	struct somig_migopt opt;

	opt.node = atoi(para);
	opt.flag = 0x2; // + 0x10000000;
	optlen = sizeof(opt);
	printf("Migrating to peer %u with flag %u\n", opt.node, opt.flag);
	error = setsockopt(fd, SOL_SOCKET, SO_MIG_MIGRATE, &opt, optlen);
	if (error) {
		printf("Failed to migrate to peer. err %d\n", error);
	}

	// what now?
#endif
}

void
func_cmd_gen(int fd, char *para)
{
	char *buf;
	int size = atoi(para);

	buf = (char *)calloc(size + 1, 1);
	for (int i=0;i<size;i++) 
		buf[i] = i%255 + 1;
	buf[size] = '\0';
	send_msg(fd, buf);
	free(buf);
}

void
func_cmd_tcpcb(int fd, char *para)
{
	int error;
	char buffer[65536];
	uint32_t *val;
	socklen_t len;

#ifdef SOMIGRATION
	int opt;

	opt = MSO;
	if (getsockopt(fd, SOL_SOCKET, SO_MIG_ROLE, &opt, &len)) {
		perror("setsockopt - role");
		exit(0);
	}
	if (opt != MSO && opt != RSO) {
		printf("Wrong somig role.\n");
		return;
	}
#else
	printf("Wrong mso role.\n");
	return;
#endif

	printf("\n\n");
	
	val = (uint32_t *)buffer;
	*val = SOMIG_CB_TCPCB;
	len = 65536;
	error = getsockopt(fd, SOL_SOCKET, SO_MIG_DUMP_CB, val, &len);
	if (error) {
		printf("Failed to query cb info. err %d\n", errno);
	}

	for (int i=0;i<sizeof(struct tcpcb);i+=sizeof(char *)) {
		val = (uint32_t *)(buffer+i);
		printf("%lu: %u\n", i/sizeof(char *), *val);
	}

	printf("\n");
}

void
func_cmd_inpcb(int fd, char *para)
{
	int error;
	char buffer[65536];
	socklen_t len;

#ifdef SOMIGRATION
	int opt;

	opt = MSO;
	if (getsockopt(fd, SOL_SOCKET, SO_MIG_ROLE, &opt, &len)) {
		perror("setsockopt - role");
		exit(0);
	}
	if (opt != MSO && opt != RSO) {
		printf("Wrong somig role.\n");
		return;
	}

#else
	printf("Wrong mso role.\n");
	return;
#endif

	printf("\n\n");
	
	len = 65536;
	error = getsockopt(fd, SOL_SOCKET, SOMIG_CB_INPCB, buffer, &len);
	if (error) {
		printf("Failed to query cb info. err %d\n", error);
	}

	printf("\n");
}

void
func_cmd_ccv(int fd, char *para)
{
	int error;
	char buffer[65536];
	socklen_t len;

#ifdef SOMIGRATION
	int opt;

	opt = MSO;
	if (getsockopt(fd, SOL_SOCKET, SO_MIG_ROLE, &opt, &len)) {
		perror("setsockopt - role");
		exit(0);
	}
	if (opt != MSO && opt != RSO) {
		printf("Wrong somig role.\n");
		return;
	}

#else
	printf("Wrong mso role.\n");
	return;
#endif

	printf("\n");
	len = 65536;
	if (getsockopt(fd, IPPROTO_TCP, TCP_CONGESTION, buffer, &len) != 0) {
		perror("getsockopt - cc");
		return;
	}
	printf("%s\n", buffer); 
	
	len = 65536;
	memset(buffer, 0, len);
	error = getsockopt(fd, SOL_SOCKET, SOMIG_CB_CC, buffer, &len);
	if (error) {
		printf("Failed to query cb info. err %d\n", error);
	}

	printf("\n");
}

void
print_time(int mode)
{	
	time_t timer;
	char tmbuf[26];
	struct tm *tm_info;

	timer = time(NULL);
	tm_info = localtime(&timer);
	strftime(tmbuf, 26, "[%Y-%m-%d %H:%M:%S]", tm_info);
	if (mode == 0) {
		printf("\033[0;32m");
		printf("%s[Recv] ", tmbuf);
	} else if (mode == 1) {	
		printf("\033[0;31m");
		printf("%s[Send] ", tmbuf);
	} else {
		printf("\033[0;33m");
		printf("%s[Info] ", tmbuf);
	}
	printf("\033[0m");
}

void
msg(int type, const char* format, ...) 
{
	va_list arglist;

	print_time(type);
	va_start(arglist, format);
	vprintf(format, arglist);
	va_end(arglist);
}

void 
LOG(const char* format, ...)
{
	if (!verbose)
		return;
	va_list arglist;
	va_start(arglist, format);
	msg(999, format, arglist);
	va_end(arglist);
}

void
cmd(int fd, char *str)
{
	int i, cmd_size;
	char cmd_str[32];
	char para_str[255];

	printf("\033[A\r");
	for (int j=0;j<strlen(str);j++)
		printf(" ");
	printf("\r");
	print_time(999);
	printf("%s", str);
	
	bzero(cmd_str, 32);
	bzero(para_str, 255);
	for (i=1;i<strlen(str);i++) {
		if (str[i] == ' ' || str[i] == '\0' || str[i] == '\n')
			break;
		cmd_str[i-1] = str[i];
	}

	if (str[i] == ' ' && i < strlen(str)-1)
		strcpy(para_str, str+i+1);
	bzero(str, strlen(str));

	cmd_size = sizeof(cmd_table) / sizeof(struct cmd_table_entry);
	for (i=0;i<cmd_size;i++) {
		if (strcmp(cmd_table[i].cmd, cmd_str) == 0) {
			(void)(*cmd_table[i].func)(fd, para_str);
			return;
		}
	}

	msg(999, "Invalid command.\n");
}

void 
send_msg(int fd, char *str)
{
	send(fd, str, strlen(str), 0);
	printf("\033[A\r");
	for (int j=0;j<strlen(str);j++)
		printf(" ");
	printf("\r");
	print_time(1);
	printf("%s", str);
	bzero(str, strlen(str));
}

int
create_socket()
{
	int fd, opt;

	fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0) {
		printf("Failed to create socket\n");
		exit(EXIT_FAILURE); 
	}

	opt = 1;
	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) { 
		perror("setsockopt"); 
		exit(EXIT_FAILURE); 
	}
	if (setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt))) { 
		perror("setsockopt"); 
		exit(EXIT_FAILURE); 
	}
	return (fd);
}

#ifdef SOMIGRATION
int 
#ifdef SMCP
init_mso(int fd, char *mso_addr, uint16_t ctl_port, const char *local, int port)
#else
init_mso(int fd, char *mso_addr, uint16_t ctl_port)
#endif
{
	int opt;
	struct sockaddr_in address;

	opt = MSO;
	if (setsockopt(fd, SOL_SOCKET, SO_MIG_ROLE, &opt, sizeof(opt))) {
		perror("setsockopt - role");
		exit(0);
	}

#ifdef SMCP
	address.sin_family = AF_INET;
	address.sin_addr.s_addr = inet_addr(local); 
	address.sin_port = htons(port);

	if (setsockopt(fd, SOL_SOCKET, SO_MIG_PREBIND, 
		(struct sockaddr*)&address, sizeof(address))) {
		perror("setsockopt - somigpostbind");
		return (-1);
	}
#endif

	address.sin_family = AF_INET;
	address.sin_addr.s_addr = inet_addr(mso_addr);
	address.sin_port = htons(ctl_port);
	if (setsockopt(fd, SOL_SOCKET, SO_MIG_BIND, 
	    (struct sockaddr *)&address, sizeof(address))) {
		perror("setsockopt - somigbind");
		exit(0);
	}

	opt = 1;
	if (setsockopt(fd, SOL_SOCKET, SO_MIG_LISTEN, &opt, sizeof(opt))) {
		perror("setsockopt - somiglisten");
		exit(0);
	}

	LOG("SOMIG Listening to %s:%d...\n", mso_addr, ctl_port);

	return (fd);
}

int 
#ifdef SMCP
init_rso(int fd, char *mso_addr, char *rso_addr, int ctl_port, const char *local, int port)
#else
init_rso(int fd, char *mso_addr, char *rso_addr, int ctl_port)
#endif
{
	int opt;
	struct sockaddr_in address;

	opt = RSO;
	if (setsockopt(fd, SOL_SOCKET, SO_MIG_ROLE, &opt, sizeof(opt))) {
		perror("setsockopt - role");
		exit(0);
	}

#ifdef SMCP
	address.sin_family = AF_INET;
	address.sin_addr.s_addr = inet_addr(local); 
	address.sin_port = htons(port);

	if (setsockopt(fd, SOL_SOCKET, SO_MIG_PREBIND, 
		(struct sockaddr*)&address, sizeof(address))) {
		perror("setsockopt - somigpostbind");
		return (-1);
	}
#endif

	address.sin_family = AF_INET;
	address.sin_addr.s_addr = inet_addr(rso_addr); 
#ifndef SMCP
	address.sin_port = htons(ctl_port);
#endif
	if (setsockopt(fd, SOL_SOCKET, SO_MIG_BIND, 
	    (struct sockaddr*)&address, sizeof(address))) {
		perror("setsockopt - somigbind");
		exit(0);
	}

	opt = 1;
	if (setsockopt(fd, SOL_SOCKET, SO_MIG_LISTEN, 
	    (struct sockaddr*)&opt, sizeof(opt))) {
		perror("setsockopt - somiglisten");
		exit(0);
	}

	/* Connect to PRIMARY */
	address.sin_addr.s_addr = inet_addr(mso_addr);
#ifndef SMCP
	address.sin_port = htons(ctl_port); 
#endif
	if (setsockopt(fd, SOL_SOCKET, SO_MIG_CONNECT, (struct sockaddr*)&address, 
	    sizeof(address))) {
		perror("CTLSO connect");
		exit(EXIT_FAILURE);
	}
	
	return (fd);
}

#endif

int
init_app_server(int fd, char *app_addr, uint16_t port)
{
	struct sockaddr_in address;

	address.sin_family = AF_INET;
	address.sin_addr.s_addr = inet_addr(app_addr);
	address.sin_port = htons(port);

	if (bind(fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
		perror("server bind");
		exit(0);
	}

	LOG("Listening to %s:%u...\n", app_addr, port);
	listen(fd, 5);
	return fd;
}

int 
init_app_client(int fd, char *app_addr, int port)
{
	struct sockaddr_in address;

	address.sin_family = AF_INET;
	address.sin_addr.s_addr = inet_addr(app_addr);
	address.sin_port = htons(port);

	if (connect(fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
		perror("client connect");
		exit(0);
	}
	return (fd);
}

int 
accept_socket(int fd)
{
	int tmpfd;
	socklen_t len;
	struct sockaddr_in address;

	tmpfd = accept(fd, (struct sockaddr *)&address, &len);
	if (tmpfd < 0) {
		perror("server accept");
		exit(0);
	}
	//close(fd);
	return (tmpfd);
}


void 
usage()
{
	printf("usage: [-m mode][-S Server Addr][-P Server Port]\n");
	printf("       [-A Primary Ctl Addr][-a Primary Port]\n");
	printf("       [-R Replica Ctl Addr][-r Replica Port][-h]\n");
	printf("modes: \n   mso: Main server with somig\n   rso: Replica server\n   cli: Client\n");
}


int
main(int argc, char* argv[])
{
	int fd, ch, error, kq, ret, fd_stdin;
	uint16_t app_port = APP_PORT, ctl_port = CTL_PORT;
	int mode = CLI;
	int server = 0;
	bool done = false;
	socklen_t len;
	char *app_addr = (char*)APP_ADDR;
	char *mso_addr = (char*)CTL_PRI_ADDR;
	char *rso_addr = (char*)CTL_REP_ADDR;
	char *buffer, *inbuf;
	struct kevent event;
	struct kevent tevent;

	while ((ch = getopt(argc, argv, "m:S:P:A:a:R:r:shv")) != -1) {
		switch (ch) {
		case 'm':
#ifdef SOMIGRATION
			if (strcmp("mso", optarg) == 0) {
				mode = MSO;
			} else if (strcmp("rso", optarg) == 0) {
				mode = RSO;
			} else
#endif
			if (strcmp("cli", optarg) == 0) {
				mode = CLI;
			} else {
				printf("Invalid operation mode. See usage[-h].\n");
				exit(0);
			}
			break;
		case 'S':
			app_addr = optarg;
			break;
		case 'P':
			app_port = (uint16_t)atoi(optarg);
			break;
		case 'A':
			mso_addr = optarg;
			break;
		case 'a':
		case 'r':
			ctl_port = (uint16_t)atoi(optarg);
			break;
		case 'R':
			rso_addr = optarg;
			break;
		case 'v':
			verbose = 1;
			break;
		case 's':
			server = 1;
			break;
		case 'h':
		default:
			usage();
			exit(0);
		}
	}
	
	fd = create_socket();

#ifdef SOMIGRATION
	if (mode == MSO) {
		fd = init_app_server(fd, app_addr, app_port);
#ifdef SMCP
		init_mso(fd, mso_addr, ctl_port, app_addr, app_port);
#else
		init_mso(fd, mso_addr, ctl_port);
#endif
		fd = accept_socket(fd);
	} else if (mode == RSO) {
#ifdef SMCP
		fd = init_rso(fd, mso_addr, rso_addr, ctl_port, app_addr, app_port);
#else
		fd = init_rso(fd, mso_addr, rso_addr, ctl_port);
#endif
		init_app_server(fd, rso_addr, app_port);
		fd = accept_socket(fd);
	} else 
#endif
	if (mode == CLI) {
		if (server) {
			init_app_server(fd, app_addr, app_port);
			fd = accept_socket(fd);
		} else {
			init_app_client(fd, app_addr, app_port);
		}
	} else {
		if (mode == MSO || mode == RSO)
			printf("Please run on proper kernel.\n");
		else
			printf("Invalid working mode.\n");
		exit(0);
	}

	fd_stdin = STDIN_FILENO;
	kq = kqueue();
	if (kq == -1) {
		perror("kqueue");
		exit(0);
	}
	buffer = (char*)calloc(1, BUFSZ);
	inbuf = (char*)calloc(1, BUFSZ);

	EV_SET(&event, fd, EVFILT_READ, EV_ADD | EV_ENABLE | EV_CLEAR, 0, 0, NULL);
	ret = kevent(kq, &event, 1, NULL, 0, NULL);
	if (ret == -1) {
		perror("kevent register (socket)");
		exit(0);
	}

	EV_SET(&event, fd_stdin, EVFILT_READ, EV_ADD | EV_ENABLE | EV_CLEAR, 0, 0, NULL);
	ret = kevent(kq, &event, 1, NULL, 0, NULL);
	if (ret == -1) {
		perror("kevent register (stdin)");
		exit(0);
	}

	while (1) {
		ret = kevent(kq, NULL, 0, &tevent, 1, NULL);
		if (ret == -1) {
			perror("kqueue query");
			exit(0);
		} else if (ret > 0) {
			if (tevent.ident == fd) {
				print_time(0);	
				read(fd, buffer, BUFSZ);
				printf("%s", buffer);
				bzero(buffer, BUFSZ);
			} else if (tevent.ident == fd_stdin) {
				done = false;
				while (!done) {
					ch = read(fd_stdin, buffer, BUFSZ);
					if (ch <= 0) break;
					if (ch + strlen(inbuf) > sizeof(inbuf)) {
						char *tmp = (char*)calloc(1, 2 * BUFSZ);
						strcpy(tmp, inbuf);
						free(inbuf);
						inbuf = tmp;
					}
					for (int i=0;i<strlen(buffer);i++) {
						inbuf[strlen(inbuf)] = buffer[i];
						if (buffer[i] == 10) {
							if (buffer[0] == '/') 
								cmd(fd, buffer);
							else 
								send_msg(fd, buffer);
							done = true;
							break;
						}
					}
					bzero(buffer, BUFSZ);
				}
			}
		}
	}
	free(buffer);
	free(inbuf);
	close(fd);
	return 0;
}

 

