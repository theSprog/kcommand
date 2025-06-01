#include <iostream>

#include <vector>
#include <string>
#include <iomanip>
#include "../include/command.hpp"

using namespace kcommand;

struct TestCase {
    std::string command;
    bool expected_safe;
    std::string description;
};

void run_test(const TestCase& test, int& passed, int& total) {
    total++;
    bool result = CommandAnalyzer::is_simple_command(test.command);

    bool test_passed = (result == test.expected_safe);
    if (test_passed) {
        passed++;
        std::cout << "✓ ";
    } else {
        std::cout << "✗ ";
    }

    std::cout << std::left << std::setw(40) << ("\"" + test.command + "\"")
              << " Expected: " << (test.expected_safe ? "SAFE" : "UNSAFE") << " Got: " << (result ? "SAFE" : "UNSAFE")
              << " - " << test.description << std::endl;
    if (! test_passed) {
        exit(1);
    }
}

int main(const int argc, const char** argv) {
    std::vector<TestCase> test_cases = {
        // === 安全的简单命令 ===
        {                              "ls",  true,                     "基本命令"},
        {                          "ls -la",  true,                 "带参数的命令"},
        {                      "echo hello",  true,                   "带文本参数"},
        {                    "cat file.txt",  true,                     "文件操作"},
        {                      "mkdir test",  true,                     "目录操作"},
        {                             "pwd",  true,                     "路径命令"},
        {                            "date",  true,                 "系统信息命令"},
        {                          "whoami",  true,                     "用户信息"},
        {                          "ps aux",  true,                     "进程查看"},
        {                           "df -h",  true,                     "磁盘使用"},

        // === 引号测试 ===
        {              "echo 'hello world'",  true,                 "单引号字符串"},
        {            "echo \"hello world\"",  true,                 "双引号字符串"},
        {              "echo 'pipe | test'",  true,             "单引号中的管道符"},
        {       "echo \"semicolon ; test\"",  true,               "双引号中的分号"},
        {          "echo 'quote \" inside'",  true,             "单引号中的双引号"},
        {         "echo \"quote ' inside\"",  true,             "双引号中的单引号"},
        {       "echo 'mixed; | & symbols'",  true,       "单引号中的多个特殊符号"},

        // === 转义字符测试 ===
        {                        "echo \\;",  true,                     "转义分号"},
        {                        "echo \\|",  true,                     "转义管道"},
        {                        "echo \\&",  true,                   "转义与符号"},
        {                        "echo \\>",  true,                   "转义重定向"},
        {                        "echo \\<",  true,               "转义输入重定向"},

        // === 管道操作符测试 ===
        {                   "ls | grep txt", false,                     "基本管道"},
        {                 "cat file | head", false,                     "文件管道"},
        {            "ps aux | grep python", false,                     "进程过滤"},
        {               "echo test | wc -l", false,                     "计数管道"},
        {               "ls || echo failed", false,                   "逻辑或操作"},
        {        "mkdir test || echo exist", false,                     "条件执行"},

        // === 后台执行和逻辑操作 ===
        {                      "sleep 10 &", false,                     "后台执行"},
        {              "ls && echo success", false,                       "逻辑与"},
        {        "test -f file && cat file", false,                     "条件执行"},
        {"command1 && command2 && command3", false,                   "多重逻辑与"},

        // === 命令分隔符 ===
        {                         "ls; pwd", false,                   "命令分隔符"},
        {          "echo hello; echo world", false,                   "多命令执行"},
        {                     "cd /tmp; ls", false,               "目录切换后执行"},

        // === 重定向操作 ===
        {                 "ls > output.txt", false,                   "输出重定向"},
        {                 "cat < input.txt", false,                   "输入重定向"},
        {            "echo test >> log.txt", false,                   "追加重定向"},
        {            "command 2> error.log", false,                   "错误重定向"},
        {          "command > out.txt 2>&1", false,                   "合并重定向"},
        {      "command < in.txt > out.txt", false,               "输入输出重定向"},
        {                      "cat << EOF", false,                     "Here文档"},

        // === 命令替换测试 ===
        {                     "echo $(pwd)", false,                 "命令替换 $()"},
        {           "echo $(ls | grep txt)", false,                 "复杂命令替换"},
        {      "ls $(find . -name '*.txt')", false,                 "嵌套命令替换"},
        {                     "echo `date`", false,               "反引号命令替换"},
        {                      "echo `pwd`", false,               "反引号路径替换"},

        // === 参数扩展测试 ===
        {                    "echo ${HOME}", false,                     "参数扩展"},
        {                    "echo ${PATH}", false,                 "环境变量扩展"},
        {           "echo ${USER:-default}", false,                   "默认值扩展"},

        // === 危险关键字测试 ===
        {                         "eval ls", false,                     "eval命令"},
        {                       "exec bash", false,                     "exec命令"},
        {                    "bash -c 'ls'", false,                     "bash执行"},
        {                    "sh script.sh", false,                    "shell脚本"},
        {                         "sudo ls", false,                     "sudo命令"},
        {                       "su - user", false,                     "切换用户"},
        {          "find . -exec rm {} \\;", false,                    "find exec"},
        {                        "xargs rm", false,                    "xargs命令"},

        // === 网络命令测试 ===
        {         "curl http://example.com", false,                     "HTTP请求"},
        {                   "wget file.zip", false,                     "文件下载"},
        {                      "nc -l 8080", false,                     "网络连接"},
        {                   "ssh user@host", false,                      "SSH连接"},
        {             "scp file user@host:", false,                     "安全复制"},

        // === 危险文件操作 ===
        {                        "rm -rf /", false,                     "危险删除"},
        {                  "chmod 777 file", false,                     "权限修改"},
        {                 "chown root file", false,                   "所有者修改"},
        {           "mv /etc/passwd backup", false,                 "移动系统文件"},

        // === 进程控制 ===
        {                    "kill -9 1234", false,                 "强制终止进程"},
        {                   "killall nginx", false,                 "终止所有进程"},
        {                 "nohup command &", false,                   "不挂断执行"},

        // === 复杂组合测试 ===
        {  "ls && echo done || echo failed", false,                 "复杂逻辑组合"},
        {                 "(cd /tmp && ls)", false,                  "子shell执行"},
        {   "{ echo start; ls; echo end; }", false,                       "命令组"},
        { "command1 | command2 && command3", false,                   "管道加逻辑"},

        // === 历史扩展测试 ===
        {                              "!!", false,                 "重复上个命令"},
        {                             "!ls", false,                 "历史命令扩展"},
        {                          "echo !",  true,     "单独的感叹号（在空格前）"},

        // === 大括号扩展测试 ===
        {                    "echo {a,b,c}", false,                   "大括号扩展"},
        {               "cp file.{txt,bak}", false,                     "文件扩展"},
        {                 "mkdir dir{1..5}", false,                     "序列扩展"},

        // === 进程替换测试 ===
        {      "diff <(ls dir1) <(ls dir2)", false,                     "进程替换"},
        {          "command >(tee log.txt)", false,                 "输出进程替换"},

        // === 语法错误测试 ===
        {            "echo 'unclosed quote", false,                 "未闭合单引号"},
        {           "echo \"unclosed quote", false,                 "未闭合双引号"},
        {                 "echo $(unclosed", false,               "未闭合命令替换"},
        {                 "echo ${unclosed", false,               "未闭合参数扩展"},

        // === 边界情况测试 ===
        {                                "",  true,                       "空命令"},
        {                             "   ",  true,                       "仅空格"},
        {                          "  ls  ",  true,                     "前后空格"},
        {                   "echo #comment",  true,    "带注释（某些shell中安全）"},

        // === 转义组合测试 ===
        {                   "echo \\$(pwd)",  true,               "转义的命令替换"},
        {                 "echo \\`date\\`",  true,                 "转义的反引号"},
        {          "echo 'normal \\n text'",  true,             "单引号中的反斜杠"},

        // === 复杂引号嵌套 ===
        {    "echo \"outer 'inner' quote\"",  true,             "双引号中的单引号"},
        {    "echo 'outer \"inner\" quote'",  true,             "单引号中的双引号"},

        // === 特殊文件名测试 ===
        {                "ls file;name.txt", false,               "文件名中的分号"},
        {              "ls 'file;name.txt'",  true,         "引号保护的特殊文件名"},
        {         "ls \"file with spaces\"",  true,                   "空格文件名"},

        // === 环境变量（不在替换中） ===
        {               "$HOME/bin/command", true,                     "变量扩展"},
        {                      "echo $USER", true,                 "环境变量输出"},
        {                         "\\$HOME",  true,               "转义的美元符号"},
    };

    int passed = 0;
    int total = 0;

    std::cout << "运行 " << test_cases.size() << " 个测试用例...\n\n";

    for (const auto& test : test_cases) {
        run_test(test, passed, total);
    }

    std::cout << "\n=== 测试结果汇总 ===\n";
    std::cout << "总测试数: " << total << std::endl;
    std::cout << "通过数: " << passed << std::endl;
    std::cout << "失败数: " << (total - passed) << std::endl;
    std::cout << "通过率: " << std::fixed << std::setprecision(1) << (100.0 * passed / total) << "%" << std::endl;
}
