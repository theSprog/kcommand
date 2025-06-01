#include "include/command.hpp"
#include <iostream>
#include <chrono>

using namespace kcommand;

void test_basic_command() {
    std::cout << "=== Test Basic Command ===" << std::endl;

    // 基本命令执行
    auto cmd = Command::build("echo 'Hello {}'", "World").capture_stdout();
    std::cout << cmd.commandline() << std::endl;
    auto result = cmd.run();

    std::cout << "Exit code: " << result.exit_code() << std::endl;
    std::cout << "Output: \n" << result.stdout_text() << std::endl;
}

void test_command_with_capture() {
    std::cout << "\n=== Test Command with Capture ===" << std::endl;

    auto result = Command::build("ls -la").capture_stdout().capture_stderr().run();

    std::cout << "Exit code: " << result.exit_code() << std::endl;
    std::cout << "STDOUT length: " << result.stdout_bytes().size() << " bytes" << std::endl;
    std::cout << "chars: \n" << result.stdout_text() << std::endl;
}

void test_shell_mode() {
    std::cout << "\n=== Test Shell Mode ===" << std::endl;

    auto cmd = Command::shell("echo {} | grep {}", "hello world test", "world").capture_stdout();
    std::cout << cmd.commandline() << std::endl;
    auto result = cmd.run();

    std::cout << "Exit code: " << result.exit_code() << std::endl;
    std::cout << "Output: \n" << result.stdout_text() << std::endl;

    try {
        auto ok = Command::build("ls -l {}", "/tmp");             // 通过
        auto bad = Command::build("ls -l {} | grep txt", "/tmp"); // 抛异常
    } catch (kcommand::CommandExecException& e) {
        std::cout << e.what() << std::endl;
    }
}

void test_working_directory() {
    std::cout << "\n=== Test Working Directory ===" << std::endl;

    auto result = Command::build("ls").dir("~/Desktop").capture_stdout().run();
    auto result2 = Command::build("pwd").dir("~/Desktop").capture_stdout().run();

    std::cout << "Exit code: " << result.exit_code() << std::endl;
    std::cout << "Output: \n" << result.stdout_text() << std::endl;

    std::cout << "Exit code: " << result2.exit_code() << std::endl;
    std::cout << "Output: \n" << result2.stdout_text() << std::endl;
}

void test_environment_variables() {
    std::cout << "\n=== Test Environment Variables ===" << std::endl;

    auto result = Command::build("printenv").env("MY_TEST_VAR", "Hello from env!").capture_stdout().run();

    std::cout << "Exit code: " << result.exit_code() << std::endl;
    std::cout << "Env Output: \n" << result.stdout_text() << std::endl;
}

void test_stdin_input() {
    std::cout << "\n=== Test STDIN Input ===" << std::endl;

    auto result = Command::build("cat").stdin_text("Hello from stdin!\nLine 2\n").capture_stdout().run();

    std::cout << "Exit code: " << result.exit_code() << std::endl;
    std::cout << "Output: \n" << result.stdout_text() << std::endl;
}

void test_line_callbacks() {
    std::cout << "\n=== Test Line Callbacks ===" << std::endl;

    auto result =
        Command::build("echo 'Line 1\nLine 2\nLine 3'")
            .on_stdout_line([](const std::string& line) { std::cout << "Got line: [" << line << "]" << std::endl; })
            .run();

    std::cout << "Exit code: " << result.exit_code() << std::endl;
}

void test_timeout() {
    std::cout << "\n=== Test Timeout ===" << std::endl;

    auto start = std::chrono::steady_clock::now();
    auto result = Command::build("sleep 5").timeout(std::chrono::seconds(2)).run();
    auto end = std::chrono::steady_clock::now();

    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);

    std::cout << "Exit code: " << result.exit_code() << std::endl;
    std::cout << "Timed out: " << (result.timed_out() ? "Yes" : "No") << std::endl;
    std::cout << "Duration: " << duration.count() << "ms" << std::endl;
}

void test_async_execution() {
    std::cout << "\n=== Test Async Execution ===" << std::endl;

    auto handle = Command::shell("sleep 2 && echo 'Done!'").capture_stdout().run_async();

    std::cout << "Command started, waiting..." << std::endl;
    std::cout << "Running: " << (handle->running() ? "Yes" : "No") << std::endl;

    auto result = handle->get();

    std::cout << "Exit code: " << result.exit_code() << std::endl;
    std::cout << "Output: \n" << result.stdout_text() << std::endl;
}

void test_command_chaining() {
    std::cout << "\n=== Test Command Chaining ===" << std::endl;

    // 演示链式调用的强大之处
    auto result = Command::shell("find /etc -name '*.conf' | head -5")
                      .dir("/")
                      .env("LANG", "C")
                      .capture_stdout()
                      .capture_stderr()
                      .timeout(std::chrono::seconds(10))
                      .run();

    std::cout << "Command: " << Command::build("find /etc -name '*.conf' | head -5").commandline() << std::endl;
    std::cout << "Exit code: " << result.exit_code() << std::endl;
    if (! result.stdout_text().empty()) {
        std::cout << "Found files:\n" << result.stdout_text() << std::endl;
    }
    if (! result.stderr_text().empty()) {
        std::cout << "Errors: \n" << result.stderr_text() << std::endl;
    }
}

void test_long_cmd() {
    auto result = Command::shell("while true; do echo \"y\"; sleep 1; done")
                      .on_stdout_line([](const std::string& line) { std::cout << line << std::endl; })
                      .run_async();

    while (true) {
        std::cout << "--------" << std::endl;
        sleep(1);
    }
}

int main() {
    try {
        // test_basic_command();
        // test_command_with_capture();
        test_shell_mode();
        // test_shell_mode();
        // test_working_directory();
        // test_environment_variables();
        // test_stdin_input();
        // test_line_callbacks();
        // test_timeout();  // 可能比较慢，可以注释掉
        // test_async_execution();
        // test_command_chaining();
        // test_long_cmd();

        std::cout << "\n=== All tests completed! ===" << std::endl;

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
