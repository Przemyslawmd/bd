
#include "server.h"
#include <chrono>
#include <iostream>
#include <unistd.h>


void Server::runServer()
{
    while (true) {
        std::cout << "Server started" << std::endl;
        usleep(3000000);
    }
};