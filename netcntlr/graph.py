import matplotlib.pyplot as plt
from matplotlib.animation import FuncAnimation
import pyroute2

def get_netlink_msg():
    return

def update(frame,data):
    # plot the frame
    ax.clear()
    ax.plot(data)
    
def main():
    fig, ax = plt.subplots()
    ani = FuncAnimation(fig,update,interval=1000)
    plt.show()
    
    # main event loop
    while True:
        data = get_netlink_msg()
        # start plotting
        if data == 'start':
            pass
        # update plot
        elif data == 'update':
            pass
        # end program
        elif data == 'quit':
            break
        
if __name__ == '__main__':
    main()