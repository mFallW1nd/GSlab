/*
This program is for a ptrace inject game.

The player wins the game under the following conditions:
1. The player can modify the global string in victim's memory, to "HACKED".
2. The player can modify the return value of add() function, and you should make
the add function's result must be 0xffffffff what ever the input is.
3. The player can modify the string in victim's stack, to "HACKED".

Good luck!
*/

#include <cstdlib>
#include <iostream>

int add(int a, int b);

char str_1[] = "I'm in victim's global string";

int main() {
  std::cout << "[+] I'm in victim's main" << std::endl << std::endl;

  // output the global string
  std::cout << "The global string is: " << str_1 << std::endl << std::endl;

  // do some simple calulation and print the result
  int num_1, num_2;
  std::cout << "Please input two numbers: " << std::endl;
  std::cin >> num_1 >> num_2;
  std::cout << "Result: " << add(num_1, num_2) << std::endl << std::endl;

  // output the string player input
  char str[64];
  std::cout << "Please input a string: " << std::endl;
  std::cin >> str;
  std::cout << "The input string is: " << str << std::endl << std::endl;

  return EXIT_SUCCESS;
}

int add(int a, int b) { return a + b; }
