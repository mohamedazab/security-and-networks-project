# security-and-networks-project

## Tool: rootkit for linux

## functionalities:
    - [X] Hidden from modules
      - Can not be found using lsmod and system commands
    - [] Hide a particular process from the process list
    - [] provide user with root acces
## How to run?

- start:
    > sudo make
    gcc client -o client.c

    > sudo insmod rootkit.ko
- log kernal output (in another terminal)

    > sudo su -

    > cd /var/log

    > tail - f kern.log
- remove LKM
    
    > sudo  rmmod hello.ko