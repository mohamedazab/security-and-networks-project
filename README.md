# security-and-networks-project

## Tool: rootkit for linux supports kernel version 4.0.0-..
### Disclaimer: use virtual machine inorder not to damage your PC
### The kernel may crash the OS


## functionalities:
    - [X] Hidden from modules
      - Can not be found using lsmod and system commands
    - [X] Hide a particular process from the process list
    - [X] provide user with root access
    - [X] keylogger
## How to run?

- start:
    > sudo make
    gcc client -o client.c

    > sudo insmod rootkit.ko
    
- log kernal output (in another terminal) -> shows key logger output

    > sudo su -

    > cd /var/log

    > tail - f kern.log
    
- to view list of lkms attached 
    > lsmod
    
- remove LKM
    
    > sudo  rmmod rootkit.ko
    
- interact with client.c
    - gain root priviges
    > ./client --root-shell
    
    - create dummy process
    > perl -MPOSIX -e '$0="sadhadxk"; pause' &
    
    - hide proccess with certain id
    > ./client --hide-pid=PID
    
