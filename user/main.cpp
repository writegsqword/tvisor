
#include <fcntl.h>
#include <sys/mman.h>
#include <stdio.h>
#include <iostream>
#include <fstream>
#include <iterator>
#include <cstdint>
#include <unistd.h>

char* mmap_res = NULL;


void print_procselfmaps() {

    std::ifstream selfmaps("/proc/self/maps");
    
    std::string line;
    while(std::getline(selfmaps, line)) {
        std::cout << line << std::endl;
    }
    selfmaps.close();
}



int write_command(int fd, std::string cmd) {
    write(fd, cmd.c_str(), cmd.size());
    return 0;
}
int main(int argc, char** argv) {


    //probably registered here? idk
    int dev_fd = open("/dev/tvisor", O_RDWR);
    std::cout << "fd: " << dev_fd << std::endl;

    
    
    write_command(dev_fd, "create");
    write_command(dev_fd, "enable");
    std::cout << "launching" << std::endl;
    write_command(dev_fd, "launch");
    

    while(true)
    {};
    
    // void* res = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE, MAP_PRIVATE, dev_fd, 0);
    // mmap_res = (char*)res;
    // std::cout << "mem map @ " << std::hex << res << std::endl;
    // print_procselfmaps();
    
    // char* wr_ptr = mmap_res + 0x800;
    // std::cout << "attempting read @ " << (uint64_t)wr_ptr << "..." << std::endl;
    // //read
    // char a = *wr_ptr;
    // std::cout << "read out " << std::hex << (int)a << std::endl;
    // std::cout << "attempting write..." << std::endl;
    // //write
    // *wr_ptr = 0x1;

    // std::cout << "attempting read @ " << (uint64_t)wr_ptr << "..." << std::endl;
    // //read
    // a = *wr_ptr;
    // std::cout << "read out " << std::hex << (int)a << std::endl;
    // std::cout << "exiting..." << std::endl;
    // print_procselfmaps();

    return 0;



}
