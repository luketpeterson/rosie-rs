#include <librosie.h>

int main() {
  str smoke_str = rosie_new_string((byte_ptr)"smoke", 5);
  return (int) smoke_str.len;
}

