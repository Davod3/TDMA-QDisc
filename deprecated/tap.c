#include <stdio.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <fcntl.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

int tun_alloc(char *dev)
{
    struct ifreq ifr;
    int fd, err;

    if( (fd = open("/dev/net/tun", O_RDWR)) < 0 )
       return fd;

    memset(&ifr, 0, sizeof(ifr));

    /* Flags: IFF_TUN   - TUN device (no Ethernet headers)
     *        IFF_TAP   - TAP device
     *
     *        IFF_NO_PI - Do not provide packet information
     */
    ifr.ifr_flags = IFF_TAP;
    if( *dev )
       strncpy(ifr.ifr_name, dev, IFNAMSIZ);

    if( (err = ioctl(fd, TUNSETIFF, (void *) &ifr)) < 0 ){
       close(fd);
       return err;
    }
    strcpy(dev, ifr.ifr_name);
    return fd;
}


int main(int argc, char *argv[]) {

    if( argc < 2 ) {
        printf("Error: invalid number of arguments\n");
        return -1;
    }

    char tapname[] = "tap0";

    printf("Creating device %s\n", tapname);
    int tap_fd = tun_alloc(tapname);



    size_t count = 0;
    while(1) {
        const size_t buffer_size = 4000;
        char packet_buffer[buffer_size];
        int n_read = read(tap_fd, packet_buffer, buffer_size);
        if (n_read < 0) {
            fprintf(stderr, "Error: Failed to read packet");
            continue;
        }
        printf("%d\n", count++);
        printf("Received %dB: \n", n_read);
        for (int i=0; i<n_read; i++) {
            printf("%02X ", packet_buffer[i]);
            if((i+1)%8==0) printf("\n");
        }
        printf("\n");

    }

    return 0;
}
