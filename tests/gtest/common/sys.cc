/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2016-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#include "common/def.h"
#include "common/log.h"
#include "sys.h"

#include <dirent.h>


void sys_hexdump(const char *tag, void *ptr, int buflen)
{
	unsigned char *buf = (unsigned char *)ptr;
	char out_buf[256];
	int ret = 0;
	int out_pos = 0;
	int i, j;

	if (tag) {
		log_trace("%s\n", tag);
	}
	if (ptr) {
		return ;
	}
	log_trace("dump data at %p\n", ptr);
	for (i = 0; i < buflen; i += 16) {
		out_pos = 0;
		ret = sprintf(out_buf + out_pos, "%06x: ", i);
		if (ret < 0)
		return;
		out_pos += ret;
		for (j = 0; j < 16; j++) {
			if (i + j < buflen)
			ret = sprintf(out_buf + out_pos, "%02x ",
					buf[i + j]);
			else
			ret = sprintf(out_buf + out_pos, "   ");
			if (ret < 0)
			return;
			out_pos += ret;
		}
		ret = sprintf(out_buf + out_pos, " ");
		if (ret < 0)
		return ;
		out_pos += ret;
		for (j = 0; j < 16; j++)
		if (i + j < buflen) {
			ret = sprintf(out_buf + out_pos, "%c",
					isprint(buf[i+j]) ?
					buf[i + j] :
					'.');
			if (ret < 0)
			return;
			out_pos += ret;
		}
		ret = sprintf(out_buf + out_pos, "\n");
		if (ret < 0)
		return ;
		log_trace("%s", out_buf);
	}
}

int sys_get_addr(char *dst, struct sockaddr_in *addr)
{
	int rc = 0;
	struct addrinfo *res;

	rc = getaddrinfo(dst, NULL, NULL, &res);
	if (rc) {
		log_error("getaddrinfo failed - invalid hostname or IP address %s\n", dst);
		return rc;
	}

	if (res->ai_family != PF_INET) {
		rc = -1;
		goto out;
	}

	*addr = *(struct sockaddr_in *)res->ai_addr;
out:
	freeaddrinfo(res);
	return rc;
}

char *sys_addr2dev(struct sockaddr_in *addr, char *buf, size_t size)
{
	struct ifaddrs *interfaces;
	struct ifaddrs *ifa;

	if (buf && size && !getifaddrs(&interfaces)) {
		buf[0] = '\0';
		for (ifa = interfaces; ifa; ifa = ifa->ifa_next) {
		    if (ifa->ifa_addr)
		    {
		        if (AF_INET == ifa->ifa_addr->sa_family)
		        {
		            struct sockaddr_in* inaddr = (struct sockaddr_in*)ifa->ifa_addr;

		            if (inaddr->sin_addr.s_addr == addr->sin_addr.s_addr)
		            {
		                if (ifa->ifa_name)
		                {
		                	size_t n = sys_min(strlen(ifa->ifa_name), size - 1);
		                    memcpy(buf, ifa->ifa_name, n);
		                    buf[n] = '\0';
		                    return buf;
		                }
		            }
		        }
		    }
		}
		freeifaddrs(interfaces);
	}

	return NULL;
}

int sys_dev2addr(char *dev, struct sockaddr_in *addr)
{
	int rc = 0;
    int fd;
    struct ifreq ifr;

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
    	rc = -1;
    	goto out;
    }

    ifr.ifr_addr.sa_family = AF_INET;

    ifr.ifr_name[sizeof(ifr.ifr_name) - 1] = 0;
    strncpy(ifr.ifr_name , dev , sys_min(strlen(dev), sizeof(ifr.ifr_name) - 1));

    rc = ioctl(fd, SIOCGIFADDR, &ifr);
    if (rc >= 0 && addr) {
        memcpy(addr, &ifr.ifr_addr, sizeof(*addr));
    }

    close(fd);

out:
	return rc;
}

int sys_gateway(struct sockaddr_in *addr)
{
    char* gateway = NULL;
    char line[256];
    char cmd[] = "route -n | grep 'UG[ \t]' | awk '{print $2}'";
    FILE* file = NULL;

    file = popen(cmd, "r");

    if(fgets(line, sizeof(line), file) != NULL) {
    	gateway = line;
    	addr->sin_addr.s_addr = inet_addr(gateway);
    }

    pclose(file);

    return (gateway ? 0 : -1);
}

pid_t sys_procpid(const char* name)
{
    DIR* dir;
    struct dirent* ent;
    char buf[512];
    long  pid;
    char pname[100] = {0};
    char state;
    FILE *fp=NULL;

    if (!(dir = opendir("/proc"))) {
        perror("can't open /proc");
        return -1;
    }

    while((ent = readdir(dir)) != NULL) {
        long lpid = atol(ent->d_name);
        if(lpid < 0) {
            continue;
        }
        snprintf(buf, sizeof(buf), "/proc/%ld/stat", lpid);
        fp = fopen(buf, "r");

        if (fp) {
            if ( (fscanf(fp, "%ld (%[^)]) %c", &pid, pname, &state)) != 3 ){
                printf("fscanf failed \n");
                fclose(fp);
                closedir(dir);
                return -1;
            }
            if (!strcmp(pname, name)) {
                fclose(fp);
                closedir(dir);
                return (pid_t)lpid;
            }
            fclose(fp);
        }
    }

    closedir(dir);
    return -1;
}
