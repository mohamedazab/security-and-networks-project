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

    > sudo insmod hello.ko
- log kernal output (in another terminal)

    > cd /var/log

    > tail - f kern.log
- remove LKM
    
    > sudo  rmmod hello.ko