#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>

static int __init ratdma_init(void) {

    printk(KERN_DEBUG "SYNC: Module initialized.\n");

    return 0;

}

static void __exit ratdma_exit(void) {

    printk(KERN_DEBUG "SYNC: Module disabled.\n");

}

module_init(ratdma_init);
module_exit(ratdma_exit);
MODULE_LICENSE("GPL");