#Path to source code
VM_PATH="/home/codelab/Projects/Virtualization/Arch"

# Startup command
sudo qemu-system-x86_64 -m 6G -cpu host -smp 4 -machine type=q35,accel=kvm -rtc base=localtime -hda ${VM_PATH}/arch.img -cdrom ${VM_PATH}/archlinux-2024.06.01-x86_64.iso -net tap -net nic -vga virtio -virtfs local,path=../,mount_tag=host0,security_model=passthrough,id=host0