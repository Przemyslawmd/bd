
#include <iostream>
#include <string>


int main(int argc, char **argv)
{
     std::string inputLine;

     while (true) {
          std::cout << std::format("\033[1;32m@bdshell\033[0m:$ ") << std::flush;

          if (!std::getline(std::cin, inputLine)) {
               break;
          }
          std::cout << inputLine << "\n";
     }
}