cmake_minimum_required(VERSION 3.16)
project(she_memory_update VERSION 1.0.0 LANGUAGES C)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(MSVC)
  add_compile_options(/W4)
else()
  add_compile_options(-Wall -Wextra -Wpedantic -Wshadow -Wconversion)
endif()

# Library: crypto, protocol and emulator. Link this into your own tools or firmware.
add_library(she STATIC src/she_crypto.c src/she_protocol.c src/she_emulator.c)
target_include_directories(she PUBLIC include)

add_executable(she-update src/main.c)
target_link_libraries(she-update PRIVATE she)

include(CTest)
if(BUILD_TESTING)
  add_executable(test_she tests/test_she.c)
  target_link_libraries(test_she PRIVATE she)

  foreach(group crypto protocol emulator)
    add_test(NAME ${group} COMMAND test_she ${group})
  endforeach()

  add_test(NAME cli_spec_example COMMAND she-update)
  set_tests_properties(cli_spec_example PROPERTIES
    PASS_REGULAR_EXPRESSION "M5 820d8d95dc11b4668878160cb2a4e23e.*verified")
  add_test(NAME cli_ram_key COMMAND she-update --key-id RAM_KEY --auth-id SECRET_KEY --counter 0)
  add_test(NAME cli_rejects_secret_key COMMAND she-update --key-id SECRET_KEY)
  set_tests_properties(cli_rejects_secret_key PROPERTIES WILL_FAIL TRUE)
  add_test(NAME cli_bad_argument COMMAND she-update --uid 0102)
  set_tests_properties(cli_bad_argument PROPERTIES WILL_FAIL TRUE)
endif()
