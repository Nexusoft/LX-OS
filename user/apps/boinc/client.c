#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h> 
#include <stdlib.h>
#include <strings.h>
#include <string.h>
#include <sys/stat.h>
#include <zlib.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <openssl/sha.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>

#include <nexus/kshmem.h>
#include <nexus/syscalls.h>
#include <nexus/nexuscalls.h>
#include <nexus/linuxcalls.h>
#include <nexus/Thread.interface.h>
#include <nexus/guard.h>
#include <nexus/rdtsc.h>

#define xtod(c) ((c>='0' && c<='9') ? c-'0' : ((c>='a' && c<='f') ? c-'a'+10 : 0))
#define size(ptr) (xtod(*ptr) * (16*16*16) + xtod(*(ptr+1)) * (16*16) + xtod(*(ptr+2)) * 16 + xtod(*(ptr+3)))

char hexB (unsigned char c){
	char h;
	h = c/16;
	if (h<=9) h+='0';
	else h=h-10+'A';
	return h;
}

char hexS (unsigned char c){
	char h;
	h = c%16;
	if (h<=9) h+='0';
	else h=h-10+'A';
	return h;
}

uint64_t tv1;
uint64_t tv2;
char *num1 = NULL;
char *num2 = NULL;

char * cmd = NULL;

void error(char *msg)
{
    	perror(msg);
    	exit(0);
}

void connect_to_server (char port[4], char host[18], int * sockfd){

	int portno;
    	struct sockaddr_in serv_addr;
	struct sockaddr_in addr;
    	struct hostent *server;
	unsigned int address[4];

	sscanf(host, "%d.%d.%d.%d",&address[0], &address[1], &address[2], &address[3]);
	unsigned char *address_dest = (unsigned char *)&serv_addr.sin_addr.s_addr;
  	int i;
  	for(i=0; i < 4; i++) 
		address_dest[i] = address[i];
	serv_addr.sin_family = AF_INET;
	portno = atoi(port);
	serv_addr.sin_port = htons(80);

	addr.sin_family = AF_INET;
  	addr.sin_addr.s_addr = htonl(INADDR_ANY);
  	addr.sin_port = htons(0);
    	
    	*sockfd = socket(AF_INET, SOCK_STREAM, 0); 
    	if (*sockfd < 0) 
        	error("ERROR opening socket");    	
    	
	bind(*sockfd, (struct sockaddr *)&addr, sizeof(addr));
    	if (connect(*sockfd,(struct sockaddr *)&serv_addr,sizeof(serv_addr)) < 0) 
        	error("ERROR connecting");
}

//It sends a request for work to the Scheduler Server
//and it receives a reply with the location of arguments
//and input.txt
 
int sceduler_request_reply (int sockfd){
	
	int n;	
	char * request_buf;
	char * reply_buf;
	FILE * request_fp = NULL;
	FILE * reply_fp = NULL;
	struct stat file_info;
	gzFile comp;
	char * ptr;

	request_fp = fopen("bin/request_scheduler.txt", "r");
    	if (request_fp==NULL){
		printf("Could not open the file\n");
		return 1;
    	}
	if(stat("bin/request_scheduler.txt", &file_info)) {
    		printf("Couldnt open '%s'\n", "bin/request_scheduler.txt");
    		return 1;
  	}

    	request_buf = (char*) calloc(file_info.st_size+1, sizeof(char));
	reply_buf = (char*) calloc(8000, sizeof(char));

    	fread(request_buf, sizeof(char), file_info.st_size,request_fp); 
	printf("->ready to send request\n");
   	n = write(sockfd,request_buf,strlen(request_buf));
    	if (n < 0) 
         	error("ERROR writing to socket");
	printf("->Request sent\n");
	printf("->ready to read reply\n");
    	n = read(sockfd,reply_buf,8000);
	printf("->Reply read\n");
	if(strstr( reply_buf, "Continue" ) != NULL){
		printf("->read Continue\n");
		memset(reply_buf, 0, 8000);
    		reply_fp = fopen("bin/reply_scheduler.gz", "w");
		n=read(sockfd,reply_buf,8000);
		printf("->all the reply has been read\n");
		if(n > 0){
			ptr = strstr( reply_buf, "Content-Type" );
			fwrite(ptr+26, 1, n,reply_fp);
			fclose(reply_fp);
			memset(reply_buf, 0, 8000);
			comp = gzopen("bin/reply_scheduler.gz", "r");
			n=gzread(comp, reply_buf, 8000);
			gzclose(comp);
			reply_fp = fopen("bin/reply_scheduler.txt", "w");
    			fwrite(reply_buf, 1, n,reply_fp);
		}
		printf("->reply uncompressed\n");
		fclose(reply_fp);
	}
	fclose(request_fp);
	free(request_buf);
	free(reply_buf);
	return 0;
}

//It extracts the urls of the locations of arguments and 
//input.txt from the reply of the Scheduler Server

void extract_cmd_input(char cmd[100],char input[100]){

	FILE * reply_fp = NULL;	
	struct stat file_info;
	char * reply_buf = NULL;
	char * ptr1 = NULL;
	char * ptr2 = NULL;
	int i=0;

	reply_fp = fopen("bin/reply_scheduler.txt", "r");
	stat("bin/reply_scheduler.txt", &file_info);
	reply_buf = (char*) calloc(file_info.st_size+1, sizeof(char));
	fread(reply_buf, sizeof(char), file_info.st_size,reply_fp); 	
	ptr1 = strstr( reply_buf, "/download" );  
    	ptr2 = strstr( ptr1, "</url>" );
	while (ptr1 != ptr2){
		cmd[i] = *ptr1;
		i++;
		ptr1++;
	}
	cmd[i]='\0';
	printf("%s\n",cmd);
	ptr1 = strstr( ptr2, "/download" );
	ptr2 = strstr( ptr1, "</url>" );
	i=0;
	while (ptr1 != ptr2){
		input[i] = *ptr1;
		i++;
		ptr1++;
	}
	input[i]='\0';
	printf("%s\n",input);
	fclose(reply_fp);
	free(reply_buf);
}

//It creates and sends the request GET for arguments and
//intput.txt to Data Server

void make_and_send_request(char url[100], char choice){

	FILE * request_fp = NULL;
	FILE * reply_fp = NULL;
	FILE * reply_fp2 = NULL;
	char * request_buf = NULL;
	char * reply_buf = NULL;
	int i, n, size;
	int sockfd;
	char * ptr1 = NULL;
	gzFile comp;
	char md[20];
	char *cert[2];
	char filepath[128];
	int fd;
	FSID file;
	struct nxguard_object file_obj;
	char *goal;
	char *axiom;

	connect_to_server("80","217.67.244.150",&sockfd);
	request_fp = fopen("bin/request_get.txt", "r");
	request_buf = (char*) calloc(260, sizeof(char));
	request_buf[0] = 'G'; request_buf[1] = 'E';
	request_buf[2] = 'T'; request_buf[3] = ' ';
	for(i=0; url[i]!= '\0'; i++)
		request_buf[i+4] = url[i];
	fread(request_buf+i+4, sizeof(char), 256-strlen(url) ,request_fp);
	printf("%s\n",request_buf);

	n = write(sockfd,request_buf,strlen(request_buf));
    	if (n < 0) 
         	error("ERROR writing to socket");

	if(choice=='c'){//get arguments
		reply_buf = (char*) calloc(800, sizeof(char));
		n = read(sockfd,reply_buf,800);
    		if (n < 0) 
         		error("ERROR reading from socket");
		ptr1 = strstr( reply_buf, "/html" );
		reply_fp = fopen("bin/reply_cmd.gz", "w");
    		fwrite(ptr1+9, 1, 68,reply_fp);
		fclose(reply_fp);
		comp = gzopen("bin/reply_cmd.gz", "r");
		memset(reply_buf, 0, 800);
		n=gzread(comp, reply_buf, 68);
		gzclose(comp);
		reply_fp = fopen("bin/reply_cmd.txt", "w");
		reply_buf[n]='\0';
    		fwrite(reply_buf, 1, n+1,reply_fp);
		cmd = reply_buf; //we save arguments in the cmd buffer
		fclose(reply_fp);
		printf("%s\n",reply_buf);
	}else{
		reply_buf = (char*) calloc(8000, sizeof(char));
		reply_fp = fopen("bin/reply_input_reassembled.gz", "w");
		while ((n=read(sockfd,reply_buf,8000))>0)
			fwrite(reply_buf, 1, n,reply_fp);
		fclose(reply_fp);
		free(reply_buf);
		reply_buf = (char*) calloc(63000, sizeof(char));
		reply_fp2 = fopen("bin/reply_input_reassembled.gz", "r");
		reply_fp = fopen("bin/reply_input_dechanked.gz", "w");

		n = fread(reply_buf,1,363,reply_fp2);
		if (n < 0) 
         		error("ERROR reading from file");
    		ptr1 = reply_buf + 357;
		size = size(ptr1);
		memset(reply_buf, 0, n);
		i=0;
		while((n=fread(reply_buf,1,size,reply_fp2))>0){
			do{
				fwrite(reply_buf, 1, n,reply_fp);
				size -= n;
				memset(reply_buf, 0, n);
				n=fread(reply_buf,1,size,reply_fp2);
			}while(size>0);
			memset(reply_buf, 0, n);
			n=fread(reply_buf,1,8,reply_fp2);
			ptr1 = reply_buf + 2;
			size = size(ptr1);
			memset(reply_buf, 0, size);
		}
		if (n < 0) 
         		error("ERROR reading from file");
		fclose(reply_fp);
		fclose(reply_fp2);
		free(reply_buf);
		reply_buf = (char*) calloc(7500000, sizeof(char));
		if (reply_buf == NULL)
			printf("error\n");
		comp = gzopen("bin/reply_input_dechanked.gz", "r");
		n = gzread(comp, reply_buf, 7500000);
		gzclose(comp);

		fd = open("bin/input.txt",O_WRONLY | O_CREAT | O_EXCL, "w");
		if (errno == EEXIST)
			error("Someone else opened input.txt!\n");
    		write(fd, reply_buf, n);
		close(fd);
		
		tv1 = rdtsc64();
		file = nxcall_fsid_byname("bin/input.txt");
		if (!FSID_isFile(file))
			printf("error: file lookup\n");
		file_obj.fsid = file;
		goal = malloc(45);
		sprintf(goal, "name.guard says subject = %d", getpid());
		nxguard_goal_set_str(SYS_FS_Write_CMD, &file_obj, goal);
		axiom = malloc(56);
		sprintf(axiom, "assume <<%s>>", goal);
		nxguard_proof_set(SYS_FS_Write_CMD, &file_obj, axiom);
		free(goal); free(axiom);

		memset ( md, 0, 20 );
		SHA1(reply_buf, n, md);
		cert[0] = (char*) calloc(55, sizeof(char));
		sprintf(cert[0],"input = ");
		for(i=0; i<20; i++){
			cert[0][i*2+8]=hexB(md[i]);
			cert[0][i*2+9]=hexS(md[i]);
		}
		cert[0][i*2+8] = '\0';
		cert[1] = 0;
		Thread_Sha1_SaysCert(cert, filepath);
		rename(filepath, "tmp/i_s_input.pem");
		free(reply_buf);
	}
	fclose(request_fp);
	free(request_buf);
	//close(sockfd);
}

void upload_results (void){

	FILE * cmd_fp = NULL;
	int sockfd,n,i;
	FILE * request_fp = NULL;
	char * request_buf = NULL;
	char * reply_buf = NULL;
	char * result[2];
	char filepath[128];
	struct stat st;
	int size=0;
	char *pt;
	char md[20];
	char *cert[2];

	stat("bin/factors.txt", &st);
	if(st.st_size == 0){
		printf("output = no factors\n");
		result[0] = (char*) calloc(20, sizeof(char));
		sprintf(result[0],"no factors");
	}else{
		printf("Primes were found!\n");
		//put the factors in result buffer
	}
	result[1]=0;
	Thread_Sha1_SaysCert(result, filepath);
	rename(filepath, "tmp/i_s_output.pem");

	stat("/tmp/sysinfo.pem", &st);  
	size += st.st_size;
	stat("/tmp/i_s_output.pem", &st);
	size += st.st_size;
	stat("/tmp/i_s_cmd.pem", &st);
	size += st.st_size;
	stat("/tmp/i_sf_sha1.pem", &st);
	size += st.st_size;
	stat("/tmp/i_s_exec.pem", &st);
	size += st.st_size;
	stat("/tmp/i_s_input.pem", &st);
	size += st.st_size;

	request_buf = (char*) calloc(size + 870 - 17 + 6*30 + 1600, sizeof(char));
	request_fp = fopen("bin/request_upload.txt", "r");
	stat("bin/request_upload.txt", &st);
	fread(request_buf, sizeof(char), st.st_size ,request_fp);
	pt = request_buf + st.st_size;
	fclose(request_fp);
	
	sprintf(pt,"<output>");
	pt += 8;
	request_fp = fopen("/tmp/i_s_output.pem", "r");
	stat("/tmp/i_s_output.pem", &st); 
	fread(pt, sizeof(char), st.st_size ,request_fp);
	pt += st.st_size;
	fclose(request_fp);
	sprintf(pt,"</output>\n");

	pt += 10;	
	sprintf(pt,"<sha1>");
	pt += 6;
	request_fp = fopen("/tmp/i_sf_sha1.pem", "r");
	stat("/tmp/i_sf_sha1.pem", &st); 
	fread(pt, sizeof(char), st.st_size ,request_fp);
	pt += st.st_size;
	fclose(request_fp);
	sprintf(pt,"</sha1>\n");

	pt += 8;	
	sprintf(pt,"<sysinfo>");
	pt += 9;
	request_fp = fopen("/tmp/sysinfo.pem", "r");
	stat("/tmp/sysinfo.pem", &st); 
	fread(pt, sizeof(char), st.st_size ,request_fp);
	pt += st.st_size;
	fclose(request_fp);
	sprintf(pt,"</sysinfo>\n");

	pt += 11;	
	sprintf(pt,"<input>");
	pt += 7;
	request_fp = fopen("/tmp/i_s_input.pem", "r");
	stat("/tmp/i_s_input.pem", &st); 
	fread(pt, sizeof(char), st.st_size ,request_fp);
	pt += st.st_size;
	fclose(request_fp);
	sprintf(pt,"</input>\n");

	pt += 9;	
	sprintf(pt,"<exec>");
	pt += 6;
	request_fp = fopen("/tmp/i_s_exec.pem", "r");
	stat("/tmp/i_s_exec.pem", &st); 
	fread(pt, sizeof(char), st.st_size ,request_fp);
	pt += st.st_size;
	fclose(request_fp);
	sprintf(pt,"</exec>\n");

	pt += 8;	
	sprintf(pt,"<cmd>");
	pt += 5;
	request_fp = fopen("/tmp/i_s_cmd.pem", "r");
	stat("/tmp/i_s_cmd.pem", &st); 
	fread(pt, sizeof(char), st.st_size ,request_fp);
	pt += st.st_size;
	fclose(request_fp);
	sprintf(pt,"</cmd>\n");

	memset ( md, 0, 20 );
	SHA1(request_buf, strlen(request_buf), md); 
	cert[0] = (char*) calloc(55, sizeof(char)); 
	sprintf(cert[0],"msg_hash = "); 
	for(i=0; i<20; i++){
		cert[0][i*2+11]=hexB(md[i]);
		cert[0][i*2+12]=hexS(md[i]);
	}
	cert[0][i*2+11]='\0'; 
	cert[1] = 0; 
	Thread_Sha1_SaysCert(cert, filepath);
	rename(filepath, "tmp/i_s_msg.pem"); 
	
	pt += 7;	
	sprintf(pt,"<msg>");
	pt += 5;
	request_fp = fopen("/tmp/i_s_msg.pem", "r");
	stat("/tmp/i_s_msg.pem", &st); 
	fread(pt, sizeof(char), st.st_size ,request_fp);
	pt += st.st_size;
	fclose(request_fp);
	sprintf(pt,"</msg>\n");
	
	tv2 = rdtsc64();
	printf("time = %f\n", ((tv2 - tv1)*1.0)/NXCLOCK_RATE);

	//the uploading works, but it is not good to fill
	//a server with "garbage".
	
/*	connect_to_server("80","192.0.32.10",&sockfd);

	n = write(sockfd,request_buf,strlen(request_buf));
	if (n < 0) 
       		error("ERROR writing to socket");	

	reply_buf = (char*) calloc(200, sizeof(char));
	n = read(sockfd,reply_buf,200);
	if (n < 0) 
       		error("ERROR reading from socket");*/

	free(reply_buf);
	free(request_buf);
}

void start_worker (void){

	char arg[7][15];
	char *argv[8];
	char *ptr = NULL;
	int i,j,status;
	struct stat file_info;
	char *newargv[] = { "bin/sr2sieve", NULL, NULL, NULL, "-ibin/input.txt", NULL, NULL, NULL};
	char *newenviron[] = { NULL };
	pid_t pid;
	char filepath[128];
	char sha[20];
	char *cert[2];
	char md[20];
	char * pt;
	int fd;
	FSID file;
	struct nxguard_object file_obj;
	char *goal;

	ptr = cmd;
	i = j = 0;
	while((*ptr) != '\0'){
		if((*ptr) == ' '){
			arg[i][j] = '\0';
			ptr++;
			i++;
			j = 0;
		}			
		arg[i][j] = *ptr;
		j++;
		ptr++;
	}
	arg[i][j] = '\0';
	printf("Arguments are ready!\n Begin the execution of sr2sieve!\n");
	newargv[1] = arg[1]; newargv[2] = arg[2]; newargv[3] = arg[3]; newargv[5] = arg[5]; newargv[6] = arg[6];
	
	if(num1 != NULL){// for measurments only
		newargv[1] = num1;
		newargv[3] = num2;
	}

	memset ( md, 0, 20 );
	SHA1(cmd, strlen(cmd), md);
	cert[0] = (char*) calloc(50, sizeof(char));
	sprintf(cert[0],"cmd = ");
	for(i=0; i<20; i++){
		cert[0][i*2+6]=hexB(md[i]);
		cert[0][i*2+7]=hexS(md[i]);
	}
	cert[0][i*2+6]='\0';
	cert[1] = 0;
	Thread_Sha1_SaysCert(cert, filepath);
	rename(filepath, "tmp/i_s_cmd.pem");

	pid = nxcall_exec_ex("bin/sr2sieve", newargv, NULL, 0);

	fd = open("bin/factors.txt",O_WRONLY | O_CREAT | O_EXCL, "w");
	if (errno == EEXIST)
		error("Someone else opened factors.txt!\n");
	close(fd);
	file = nxcall_fsid_byname("bin/factors.txt");
	if (!FSID_isFile(file))
		printf("error: file lookup\n");
	file_obj.fsid = file;
	goal = malloc(200);
	sprintf(goal, "name.guard says subject = %d", pid);
	nxguard_goal_set_str(SYS_FS_Write_CMD, &file_obj, goal);
	free(goal);
	fd = open("bin/factors.txt",O_WRONLY | O_TRUNC, "w");
	close(fd);

	Thread_Sha1_GetCert(0, filepath);
	rename(filepath, "tmp/i_sf_sha1.pem");
	free(cert[0]);

	memset ( sha, 0, 20 );
	Thread_Sha1_Get(pid, sha);
	cert[0] = (char*) calloc(50, sizeof(char));
	sprintf(cert[0],"exec = ");
	for(i=0; i<20; i++){
		cert[0][i*2+7]=hexB(sha[i]);
		cert[0][i*2+8]=hexS(sha[i]);
	}
	cert[0][i*2+7]='\0';
	cert[1] = 0;
	Thread_Sha1_SaysCert(cert, filepath);
	rename(filepath, "tmp/i_s_exec.pem");

	nxlibc_syscall_waitpid(pid, &status, 0);
	if(WIFEXITED(status))
		upload_results();
	else
		error("sr2sieve did not terminate normally!\n");
}

void generate_needed_files(void);

int main(int argc, char *argv[]){

    	int sockfd;
	char cmd[100];
	char input[100];

	if(argc>1){ //arguments only for measurments
		num1=argv[1];
		num2=argv[2];
	}
	printf("Connect to server.\n");
	connect_to_server("80","217.67.244.150",&sockfd);
	generate_needed_files();
	printf("Needed files are generated.\n");
	printf("Send request to server and receive its reply.\n");
	sceduler_request_reply(sockfd);
//	close(sockfd); It does not work right now!!!
	printf("Extract cmd and input urls from the scheduler reply.\n");
	extract_cmd_input(cmd,input);
	printf("Get cmd.\n");
	make_and_send_request(cmd,'c');
	printf("Get input.\n");
	make_and_send_request(input,'i');
	printf("Start worker.\n");
//	start_worker();
	
    	return 0;
}

//It creates the (xml)files we need for the requests
//The fields with ??????? should be filled by the
// user's information

void generate_needed_files(void){

	FILE * fp_get = NULL;
	char get_request[] = {
		" HTTP/1.1\n"
		"User-Agent: BOINC client (i686-pc-linux-gnu 6.10.58)\n"
		"Host: www.primegrid.com\n"
		"Accept: */*\n"
		"Accept-Encoding: deflate, gzip\n"
		"Content-Type: application/x-www-form-urlencoded\n"
		"\n"};

	fp_get = fopen("bin/request_get.txt", "w");
	fwrite(get_request, 1, 180,fp_get);
	fclose(fp_get);

	FILE * fp_upload = NULL;
	char upload_request[] = {
	"POST /cgi/file_upload_handler HTTP/1.1\n"
	"User-Agent: BOINC client (i686-pc-linux-gnu 6.10.58)\n"
	"Host: www.primegrid.com\n"
	"Accept: */*\n"
	"Accept-Encoding: deflate, gzip\n"
	"Content-Type: application/x-www-form-urlencoded\n"
	"Content-Length: 633\n\n"
"<data_server_request>\n"
"    <core_client_major_version>6</core_client_major_version>\n"
"    <core_client_minor_version>10</core_client_minor_version>\n"
"    <core_client_release>58</core_client_release>\n"
"<file_upload>\n"
"<file_info>\n"
"    <name>321_sr2sieve_2259847_0_0</name>\n"
"    <nbytes>0.000000</nbytes>\n"
"    <max_nbytes>331072.000000</max_nbytes>\n"
"    <generated_locally/>\n"
"    <status>0</status>\n"
"    <upload_when_present/>\n"
"    <url>http://www.primegrid.com/cgi/file_upload_handler</url>\n"
"<xml_signature>\n"
"</xml_signature>\n"
"</file_info>\n"
"<nbytes>10</nbytes>\n"
"<offset>0</offset>\n"
};

	fp_upload = fopen("bin/request_upload.txt", "w");
	fwrite(upload_request, 1, strlen(upload_request),fp_upload);
	fclose(fp_upload);

	FILE * fp_scheduler = NULL;
	char scheduler_request[] = {
		"POST /cgi/cgi HTTP/1.1\r\n"
		"User-Agent: BOINC client (i686-pc-linux-gnu 6.10.58)\r\n"
		"Host: www.primegrid.com\r\n"
		"Accept: */*\r\n"
		"Accept-Encoding: deflate, gzip\r\n"
		"Content-Type: application/x-www-form-urlencoded\r\n"
		"Content-Length: 7645\r\n"
		"Expect: 100-continue\r\n\r\n"
"<scheduler_request>\n"
"    <authenticator>???????</authenticator>\n"
"    <hostid>???????</hostid>\n"
"    <rpc_seqno>8</rpc_seqno>\n"
"    <core_client_major_version>6</core_client_major_version>\n"
"    <core_client_minor_version>10</core_client_minor_version>\n"
"    <core_client_release>58</core_client_release>\n"
"    <resource_share_fraction>1.000000</resource_share_fraction>\n"
"    <rrs_fraction>1.000000</rrs_fraction>\n"
"    <prrs_fraction>1.000000</prrs_fraction>\n"
"    <duration_correction_factor>1.000099</duration_correction_factor>\n"
"    <sandbox>0</sandbox>\n"
"    <work_req_seconds>43201.728000</work_req_seconds>\n"
"    <cpu_req_secs>43201.728000</cpu_req_secs>\n"
"    <cpu_req_instances>2.000000</cpu_req_instances>\n"
"    <estimated_delay>0.000000</estimated_delay>\n"
"    <client_cap_plan_class>1</client_cap_plan_class>\n"
"    <platform_name>anonymous</platform_name>\n"
"    <app_versions>\n"
"<app_version>\n"
"    <app_name>321_sr2sieve</app_name>\n"
"    <version_num>102</version_num>\n"
"    <platform>i686-pc-linux-gnu</platform>\n"
"    <avg_ncpus>1.000000</avg_ncpus>\n"
"    <max_ncpus>1.000000</max_ncpus>\n"
"    <flops>1003780849.476557</flops>\n"
"</app_version>\n"
"    </app_versions>\n"
"    <code_sign_key>\n"
"1024\n"
"cffaddb9663fd86a8dbecbe7dad55d883f372f63cc0d042dcb9c8a05ef1cf2ab\n"
"af63b7fb672e3f88f0cfca46c899cc9e783963f8200d776d37ba6a69b8cb4bad\n"
"d0e3e667c8d0925c662e5299073b5a0e0b6893b0b86fbcdf0b3267cae368e421\n"
"f0fc583fb7c63659c1f7ff402c3fd76becd2af6b4ff253e312949f3350fb6333\n"
"0000000000000000000000000000000000000000000000000000000000000000\n"
"0000000000000000000000000000000000000000000000000000000000000000\n"
"0000000000000000000000000000000000000000000000000000000000000000\n"
"0000000000000000000000000000000000000000000000000000000000010001\n"
".\n"
"</code_sign_key>\n"
"<working_global_preferences>\n"
"<global_preferences>\n"
"   <source_project>http://www.primegrid.com/</source_project>\n"
"   <mod_time>1287881720.000000</mod_time>\n"
"   <run_on_batteries>1</run_on_batteries>\n"
"   <run_if_user_active>1</run_if_user_active>\n"
"   <run_gpu_if_user_active>0</run_gpu_if_user_active>\n"
"   <suspend_if_no_recent_input>0.000000</suspend_if_no_recent_input>\n"
"   <suspend_cpu_usage>25.000000</suspend_cpu_usage>\n"
"   <start_hour>0.000000</start_hour>\n"
"   <end_hour>0.000000</end_hour>\n"
"   <net_start_hour>0.000000</net_start_hour>\n"
"   <net_end_hour>0.000000</net_end_hour>\n"
"   <leave_apps_in_memory>0</leave_apps_in_memory>\n"
"   <confirm_before_connecting>0</confirm_before_connecting>\n"
"   <hangup_if_dialed>0</hangup_if_dialed>\n"
"   <dont_verify_images>0</dont_verify_images>\n"
"   <work_buf_min_days>0.000010</work_buf_min_days>\n"
"   <work_buf_additional_days>0.250000</work_buf_additional_days>\n"
"   <max_ncpus_pct>100.000000</max_ncpus_pct>\n"
"   <cpu_scheduling_period_minutes>60.000000</cpu_scheduling_period_minutes>\n"
"   <disk_interval>60.000000</disk_interval>\n"
"   <disk_max_used_gb>10.000000</disk_max_used_gb>\n"
"   <disk_max_used_pct>50.000000</disk_max_used_pct>\n"
"   <disk_min_free_gb>0.001000</disk_min_free_gb>\n"
"   <vm_max_used_pct>75.000000</vm_max_used_pct>\n"
"   <ram_max_used_busy_pct>50.000000</ram_max_used_busy_pct>\n"
"   <ram_max_used_idle_pct>90.000000</ram_max_used_idle_pct>\n"
"   <idle_time_to_run>3.000000</idle_time_to_run>\n"
"   <max_bytes_sec_up>0.000000</max_bytes_sec_up>\n"
"   <max_bytes_sec_down>0.000000</max_bytes_sec_down>\n"
"   <cpu_usage_limit>50.000000</cpu_usage_limit>\n"
"   <daily_xfer_limit_mb>0.000000</daily_xfer_limit_mb>\n"
"   <daily_xfer_period_days>0</daily_xfer_period_days>\n"
"</global_preferences>\n"
"</working_global_preferences>\n"
"<global_preferences>\n"
"    <source_project>http://www.primegrid.com/</source_project>\n"
"    <source_scheduler>http://www.primegrid.com/cgi/cgi</source_scheduler>\n"
"<mod_time>1287881720</mod_time>\n"
"<run_on_batteries>0</run_on_batteries>\n"
"<run_if_user_active>1</run_if_user_active>\n"
"<run_gpu_if_user_active>0</run_gpu_if_user_active>\n"
"<idle_time_to_run>3</idle_time_to_run>\n"
"<suspend_if_no_recent_input>0</suspend_if_no_recent_input>\n"
"<suspend_cpu_usage>25</suspend_cpu_usage>\n"
"<leave_apps_in_memory>0</leave_apps_in_memory>\n"
"<cpu_scheduling_period_minutes>60</cpu_scheduling_period_minutes>\n"
"<max_cpus>0</max_cpus>\n"
"<max_ncpus_pct>100</max_ncpus_pct>\n"
"<cpu_usage_limit>100</cpu_usage_limit>\n"
"<disk_max_used_gb>100</disk_max_used_gb>\n"
"<disk_min_free_gb>0.001</disk_min_free_gb>\n"
"<disk_max_used_pct>50</disk_max_used_pct>\n"
"<disk_interval>60</disk_interval>\n"
"<vm_max_used_pct>75</vm_max_used_pct>\n"
"<ram_max_used_busy_pct>50</ram_max_used_busy_pct>\n"
"<ram_max_used_idle_pct>90</ram_max_used_idle_pct>\n"
"<work_buf_min_days>0</work_buf_min_days>\n"
"<work_buf_additional_days>0.25</work_buf_additional_days>\n"
"<confirm_before_connecting>0</confirm_before_connecting>\n"
"<hangup_if_dialed>0</hangup_if_dialed>\n"
"<max_bytes_sec_down>0</max_bytes_sec_down>\n"
"<max_bytes_sec_up>0</max_bytes_sec_up>\n"
"<daily_xfer_limit_mb>0</daily_xfer_limit_mb>\n"
"<daily_xfer_period_days>0</daily_xfer_period_days>\n"
"<dont_verify_images>0</dont_verify_images>\n"
"</global_preferences>\n"
"<global_prefs_source_email_hash>???????</global_prefs_source_email_hash>\n"
"<cross_project_id>???????</cross_project_id>\n"
"<time_stats>\n"
"    <on_frac>0.159537</on_frac>\n"
"    <connected_frac>-1.000000</connected_frac>\n"
"    <active_frac>0.967032</active_frac>\n"
"</time_stats>\n"
"<net_stats>\n"
"    <bwup>25851.799599</bwup>\n"
"    <avg_up>172536.328601</avg_up>\n"
"    <avg_time_up>1289349756.856145</avg_time_up>\n"
"    <bwdown>997213.135509</bwdown>\n"
"    <avg_down>11218639.295538</avg_down>\n"
"    <avg_time_down>1289349751.435245</avg_time_down>\n"
"</net_stats>\n"
"<host_info>\n"
"    <timezone>???????</timezone>\n"
"    <domain_name>???????</domain_name>\n"
"    <ip_addr>???????</ip_addr>\n"
"    <host_cpid>???????</host_cpid>\n"
"    <p_ncpus>???????</p_ncpus>\n"
"    <p_vendor>???????</p_vendor>\n"
"    <p_model>???????</p_model>\n"
"    <p_features>???????</p_features>\n"
"    <p_fpops>???????</p_fpops>\n"
"    <p_iops>???????</p_iops>\n"
"    <p_membw>???????</p_membw>\n"
"    <p_calculated>???????</p_calculated>\n"
"    <m_nbytes>???????</m_nbytes>\n"
"    <m_cache>???????</m_cache>\n"
"    <m_swap>???????</m_swap>\n"
"    <d_total>???????</d_total>\n"
"    <d_free>???????</d_free>\n"
"    <os_name>???????</os_name>\n"
"    <os_version>???????</os_version>\n"
"</host_info>\n"
"    <disk_usage>\n"
"        <d_boinc_used_total>11530119.000000</d_boinc_used_total>\n"
"        <d_boinc_used_project>93928.000000</d_boinc_used_project>\n"
"    </disk_usage>\n"
"    <coprocs>\n"
"<coproc_cuda>\n"
"   <count>1</count>\n"
"   <name>GeForce 8400M GS</name>\n"
"   <req_secs>0.000000</req_secs>\n"
"   <req_instances>0.000000</req_instances>\n"
"   <estimated_delay>0.000000</estimated_delay>\n"
"   <drvVersion>0</drvVersion>\n"
"   <cudaVersion>3000</cudaVersion>\n"
"   <totalGlobalMem>133496832</totalGlobalMem>\n"
"   <sharedMemPerBlock>16384</sharedMemPerBlock>\n"
"   <regsPerBlock>8192</regsPerBlock>\n"
"   <warpSize>32</warpSize>\n"
"   <memPitch>2147483647</memPitch>\n"
"   <maxThreadsPerBlock>512</maxThreadsPerBlock>\n"
"   <maxThreadsDim>512 512 64</maxThreadsDim>\n"
"   <maxGridSize>65535 65535 1</maxGridSize>\n"
"   <totalConstMem>65536</totalConstMem>\n"
"   <major>1</major>\n"
"   <minor>1</minor>\n"
"   <clockRate>800000</clockRate>\n"
"   <textureAlignment>256</textureAlignment>\n"
"   <deviceOverlap>1</deviceOverlap>\n"
"   <multiProcessorCount>2</multiProcessorCount>\n"
"</coproc_cuda>\n"
"    </coprocs>\n"
"<other_results>\n"
"</other_results>\n"
"<in_progress_results>\n"
"</in_progress_results>\n"
"</scheduler_request>\n"
};

	fp_scheduler = fopen("bin/request_scheduler.txt", "w");
	fwrite(scheduler_request, 1, 7889,fp_scheduler);
	fclose(fp_scheduler);
}
