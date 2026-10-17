
#include <iostream>
#include <string>
#include <thread>

#include "server.h"


int main(int argc, char** argv)
{
     Server server;
     std::jthread serverThread([&server]() {
          server.runServer();
     });

     std::string inputLine;

     while (true) {
          std::cout << std::format("\033[1;32m@bdshell\033[0m:$ ") << std::flush;

          if (!std::getline(std::cin, inputLine)) {
               break;
          }
          std::cout << inputLine << "\n";
     }
}
