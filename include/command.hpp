#pragma once

#include <cstdint>
#include <ctime>
#include <future>
#include <stdexcept>
#include <string>
#include <vector>
#include <map>
#include <functional>
#include <chrono>
#include <memory>
#include <thread>
#include <iostream>
#include <sstream>
#include <unordered_set>

// Unix系统调用
#include <unistd.h>
#include <sys/wait.h>
#include <signal.h>
#include <fcntl.h>
#include <poll.h>
#include <errno.h>
#include <cstring>

namespace kcommand {

using LineCallback = std::function<void(const std::string&)>;

// =============================================================================
// 工具函数
// =============================================================================
namespace detail {
// 安全地分割命令行为参数数组
inline std::vector<std::string> split_command(const std::string& cmd) {
    std::vector<std::string> args;
    std::string current;
    bool in_quotes = false;
    bool escaped = false;

    for (char c : cmd) {
        if (escaped) {
            current += c;
            escaped = false;
        } else if (c == '\\') {
            escaped = true;
        } else if (c == '"' || c == '\'') {
            in_quotes = ! in_quotes;
        } else if (! in_quotes && std::isspace(c)) {
            if (! current.empty()) {
                args.push_back(current);
                current.clear();
            }
        } else {
            current += c;
        }
    }

    if (! current.empty()) {
        args.push_back(current);
    }

    return args;
}

class Pipe {
    int fds[2]; // fds[0]: read end, fds[1]: write end

  public:
    // 构造函数：创建管道
    Pipe() {
        if (::pipe(fds) == -1) {
            throw std::runtime_error("Failed to create pipe: " + std::string(strerror(errno)));
        }
    }

    // 析构函数：安全关闭文件描述符
    ~Pipe() {
        close_both();
    }

    // 禁用拷贝，避免双关闭
    Pipe(const Pipe&) = delete;
    Pipe& operator=(const Pipe&) = delete;

    // 允许移动，转移所有权
    Pipe(Pipe&& other) noexcept {
        fds[0] = other.fds[0];
        fds[1] = other.fds[1];
        other.fds[0] = -1;
        other.fds[1] = -1;
    }

    Pipe& operator=(Pipe&& other) noexcept {
        if (this != &other) {
            // 先关闭自身
            if (fds[0] != -1) ::close(fds[0]);
            if (fds[1] != -1) ::close(fds[1]);
            // 移动赋值
            fds[0] = other.fds[0];
            fds[1] = other.fds[1];
            other.fds[0] = -1;
            other.fds[1] = -1;
        }
        return *this;
    }

    // 读端/写端获取器
    int read_fd() const {
        return fds[0];
    }

    int write_fd() const {
        return fds[1];
    }

    void dup2_read(int fd) const {
        ::dup2(read_fd(), fd);
    }

    void dup2_write(int fd) const {
        ::dup2(write_fd(), fd);
    }

    void close_write() {
        if (fds[1] != -1) {
            ::close(fds[1]);
            fds[1] = -1;
        }
    }

    void close_read() {
        if (fds[0] != -1) {
            ::close(fds[0]);
            fds[0] = -1;
        }
    }

    void close_both() {
        close_read();
        close_write();
    }
};

// 设置非阻塞
inline void set_nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1) {
        throw std::runtime_error("Failed to get fd flags");
    }
    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1) {
        throw std::runtime_error("Failed to set non-blocking");
    }
}

// 读取全部数据
inline std::vector<uint8_t> read_all(int fd) {
    std::vector<uint8_t> data;
    char buffer[4096];

    struct pollfd pfd{fd, POLLIN};

    for (;;) {
        int ret = poll(&pfd, 1, -1); // 无限等待，或用 1000 并处理 0
        if (ret == -1) {
            if (errno == EINTR) continue;
            break; // 真错误
        }
        if (ret == 0) continue; // 超时 -> 继续轮询

        if (pfd.revents & POLLIN) {
            ssize_t n = ::read(fd, buffer, sizeof(buffer));
            if (n > 0) {
                data.insert(data.end(), buffer, buffer + n);
            } else if (n == 0) {
                break; // EOF
            } else if (errno == EINTR) {
                continue;
            } else if (errno == EAGAIN || errno == EWOULDBLOCK) {
                continue; // 重新 poll
            } else {
                break; // 其他 read 错误
            }
        }

        if (pfd.revents & (POLLHUP | POLLERR)) {
            // 还有没读完的数据？把它们统统吸完
            ssize_t n;
            while ((n = ::read(fd, buffer, sizeof(buffer))) > 0) data.insert(data.end(), buffer, buffer + n);
            // 然后再真正退出

            break;
        }
    }
    return data;
}

// 逐行读取并调用回调
inline void read_lines(int fd, const LineCallback& callback, size_t buf_sz = 4096) {
    std::string line_buf; // 一行的内容
    std::vector<char> chunk(buf_sz);

    while (true) {
        ssize_t n = ::read(fd, chunk.data(), chunk.size());
        if (n > 0) {
            for (ssize_t i = 0; i < n; ++i) {
                char ch = chunk[i];
                if (ch == '\n') {       // 已经收到一行了
                    callback(line_buf); // line_buf 可能为空
                    line_buf.clear();
                } else if (ch != '\r') { // 警惕 \r\n
                    line_buf += ch;
                }
            }
        } else if (n == 0) {
            // EOF – 把最后一行推送出去
            if (! line_buf.empty()) {
                callback(line_buf);
            }
            break;
        } else if (errno == EINTR) {
            continue; // 被信号打断，重读
        } else if (errno == EAGAIN || errno == EWOULDBLOCK) {
            // 若上层把 fd 设成非阻塞，可选择 sleep/poll；此处简单继续
            continue;
        } else {
            // 其他 read 错误：可记录日志或抛异常
            break;
        }
    }
}

inline std::vector<uint8_t> handle_fd(int fd, bool capture_enabled, const LineCallback& line_cb) {
    // 情况 A：用户提供了回调
    if (line_cb) {
        std::vector<uint8_t> collected;
        // 若同时要求 capture，边回调边缓存
        if (capture_enabled) {
            // read_lines 改成可写 lambda
            read_lines(fd, [&](const std::string& line) {
                line_cb(line);
                collected.insert(collected.end(), line.begin(), line.end());
                collected.push_back('\n');
            });
            return collected;
        } else {
            read_lines(fd, line_cb);
            return {}; // 不需要返回数据
        }
    }

    // 情况 B：无回调，但要求 capture
    if (capture_enabled) {
        return read_all(fd);
    }

    // 情况 C：啥也不做
    return {};
}


} // namespace detail

namespace fmt {
template <typename T>
inline std::string to_string(T&& v) {
    std::ostringstream oss;
    oss << std::forward<T>(v);
    return oss.str();
}

inline std::string to_string(bool v) {
    return v ? "true" : "false";
}

template <typename... Args>
std::string format(const std::string& fmt, Args&&... args) {
    constexpr std::size_t N = sizeof...(Args);
    std::array<std::string, N> a{{to_string(std::forward<Args>(args))...}};

    std::size_t total = fmt.size();
    for (auto& s : a) {
        total += s.size();
    }

    std::string out;
    out.reserve(total);

    std::size_t idx = 0;
    for (std::size_t i = 0; i < fmt.size(); ++i) {
        if (i + 1 < fmt.size() && fmt[i] == '{' && fmt[i + 1] == '}' && idx < N) {
            out.append(a[idx++]);
            ++i; // skip the '}'
        } else {
            out.push_back(fmt[i]);
        }
    }
    return out;
}

template <typename... Args>
inline void print(const std::string& fmt, Args&&... args) {
    std::cout << format(fmt, std::forward<Args>(args)...);
}

template <typename... Args>
inline void println(const std::string& fmt, Args&&... args) {
    std::cout << format(fmt, std::forward<Args>(args)...) << '\n';
}
} // namespace fmt

// =============================================================================
// 结果结构体
// =============================================================================
class CommandResult {
  private:
    int exit_code_ = -1;
    bool timed_out_ = false;
    std::vector<uint8_t> stdout_;
    std::vector<uint8_t> stderr_;

  public:
    CommandResult() = default;

    CommandResult(int exit_code, bool timed_out, std::vector<uint8_t> stdout_data, std::vector<uint8_t> stderr_data)
        : exit_code_(exit_code), timed_out_(timed_out), stdout_(std::move(stdout_data)),
          stderr_(std::move(stderr_data)) {}

    std::string stdout_text() const {
        return std::string(stdout_.begin(), stdout_.end());
    }

    std::vector<uint8_t> stdout_bytes() const {
        return stdout_;
    }

    std::string stderr_text() const {
        return std::string(stderr_.begin(), stderr_.end());
    }

    std::vector<uint8_t> stderr_bytes() const {
        return stderr_;
    }

    int exit_code() const {
        return exit_code_;
    }

    bool timed_out() const {
        return timed_out_;
    }

    // 内部设置方法
    void set_exit_code(int code) {
        exit_code_ = code;
    }

    void set_timed_out(bool timeout) {
        timed_out_ = timeout;
    }

    void set_stdout(std::vector<uint8_t> data) {
        stdout_ = std::move(data);
    }

    void set_stderr(std::vector<uint8_t> data) {
        stderr_ = std::move(data);
    }
};

// =============================================================================
// 异步句柄接口
// =============================================================================
struct FutureHandle {
    virtual ~FutureHandle() = default;

    // 阻塞等待子进程结束，返回结果
    virtual CommandResult get() = 0;

    // 发送 SIGTERM
    virtual void terminate() = 0;

    // 发送 SIGKILL
    virtual void kill() = 0;

    // 检查是否仍在运行
    virtual bool running() const = 0;
};

// =============================================================================
// 核心抽象接口
// =============================================================================
struct Executable {
    virtual ~Executable() = default;

    // 阻塞执行，返回执行结果
    virtual CommandResult run() = 0;

    // 异步执行，返回句柄
    virtual std::unique_ptr<FutureHandle> run_async() = 0;
};

// =============================================================================
// FutureHandle 实现
// =============================================================================
class CommandFutureHandle : public FutureHandle {
    pid_t pid_;
    std::future<CommandResult> fut_;

  public:
    CommandFutureHandle(pid_t p, std::future<CommandResult>&& f) : pid_(p), fut_(std::move(f)) {}

    CommandResult get() override {
        return fut_.get();
    }

    void terminate() override {
        if (running()) ::kill(pid_, SIGTERM);
    }

    void kill() override {
        if (running()) ::kill(pid_, SIGKILL);
    }

    bool running() const override {
        auto status = fut_.wait_for(std::chrono::milliseconds(0));
        return status != std::future_status::ready;
    }
};

class CommandAnalyzer {
  private:
    static const std::unordered_set<std::string>& dangerous_keywords() {
        // 危险的shell关键字
        static const std::unordered_set<std::string> keywords = {
            "eval",   "exec",   "source", ".",       "bash",  "sh",    "zsh",    "csh",    "tcsh",   "sudo",
            "su",     "chroot", "nohup",  "timeout", "xargs", "find",  "grep",   "sed",    "awk",    "perl",
            "python", "ruby",   "node",   "curl",    "wget",  "nc",    "netcat", "telnet", "ssh",    "scp",
            "rsync",  "rm",     "rmdir",  "mv",      "cp",    "chmod", "chown",  "kill",   "killall"};
        return keywords;
    }

    struct ParseState {
        bool in_single_quotes = false;
        bool in_double_quotes = false;
        bool escaped = false;
        bool in_substitution = false; // $(...) 或 `...`
        int substitution_depth = 0;
        bool in_parameter_expansion = false; // ${...}
        int brace_depth = 0;
    };

    // 检查是否在引号内
    static bool is_quoted(const ParseState& state) {
        return state.in_single_quotes || state.in_double_quotes;
    }

    // 跳过空白字符
    static size_t skip_whitespace(const std::string& cmd, size_t pos) {
        while (pos < cmd.size() && std::isspace(cmd[pos])) {
            pos++;
        }
        return pos;
    }

    // 提取单词（用于关键字检测）
    static std::string extract_word(const std::string& cmd, size_t& pos) {
        size_t start = pos;
        while (pos < cmd.size() && (std::isalnum(cmd[pos]) || cmd[pos] == '_' || cmd[pos] == '-')) {
            pos++;
        }
        return cmd.substr(start, pos - start);
    }

    // 检查危险的内置命令和关键字
    static bool is_dangerous_keyword(const std::string& word) {
        return dangerous_keywords().find(word) != dangerous_keywords().end();
    }

  public:
    static bool is_simple_command(const std::string& cmd) {
        if (cmd.empty()) return true;

        ParseState state;
        size_t i = 0;

        // 跳过开头的空白
        i = skip_whitespace(cmd, i);
        if (i >= cmd.size()) return true;

        // 检查第一个单词是否为危险关键字
        size_t word_start = i;
        std::string first_word = extract_word(cmd, i);
        if (is_dangerous_keyword(first_word)) {
            return false;
        }
        i = word_start; // 重置位置继续正常解析

        while (i < cmd.size()) {
            char c = cmd[i];

            // 处理转义字符
            if (state.escaped) {
                state.escaped = false;
                i++;
                continue;
            }

            if (c == '\\') {
                state.escaped = true;
                i++;
                continue;
            }

            // 处理引号
            if (c == '\'' && ! state.in_double_quotes && ! state.in_substitution) {
                state.in_single_quotes = ! state.in_single_quotes;
                i++;
                continue;
            }

            if (c == '"' && ! state.in_single_quotes) {
                state.in_double_quotes = ! state.in_double_quotes;
                i++;
                continue;
            }

            // 在单引号内，除了单引号本身，其他都忽略
            if (state.in_single_quotes) {
                i++;
                continue;
            }

            // 处理命令替换和参数扩展
            if (c == '$') {
                if (i + 1 < cmd.size()) {
                    if (cmd[i + 1] == '(') {
                        if (! is_quoted(state)) return false; // 命令替换
                        state.in_substitution = true;
                        state.substitution_depth++;
                        i += 2;
                        continue;
                    } else if (cmd[i + 1] == '{') {
                        state.in_parameter_expansion = true;
                        state.brace_depth++;
                        i += 2;
                        continue;
                    }
                }
            }

            if (c == '`' && ! is_quoted(state)) {
                return false; // 反引号命令替换
            }

            // 处理括号和大括号的嵌套
            if (state.in_substitution && c == '(') {
                state.substitution_depth++;
            } else if (state.in_substitution && c == ')') {
                state.substitution_depth--;
                if (state.substitution_depth == 0) {
                    state.in_substitution = false;
                }
            }

            if (state.in_parameter_expansion && c == '{') {
                state.brace_depth++;
            } else if (state.in_parameter_expansion && c == '}') {
                state.brace_depth--;
                if (state.brace_depth == 0) {
                    state.in_parameter_expansion = false;
                }
            }

            // 在替换或扩展内部，跳过危险字符检测
            if (state.in_substitution || state.in_parameter_expansion || is_quoted(state)) {
                i++;
                continue;
            }

            // 检测危险的操作符

            // 管道操作符
            if (c == '|') {
                if (i + 1 < cmd.size() && cmd[i + 1] == '|') {
                    return false; // ||
                }
                return false; // |
            }

            // 后台执行和逻辑与
            if (c == '&') {
                if (i + 1 < cmd.size() && cmd[i + 1] == '&') {
                    return false; // &&
                }
                return false; // &
            }

            // 命令分隔符
            if (c == ';') {
                return false;
            }

            // 重定向操作符
            if (c == '>' || c == '<') {
                // 检查是否为复合重定向操作符
                if (i + 1 < cmd.size()) {
                    char next = cmd[i + 1];
                    if ((c == '>' && (next == '>' || next == '&')) || (c == '<' && (next == '<' || next == '&'))) {
                        return false;
                    }
                }
                return false;
            }

            // 历史扩展
            if (c == '!') {
                // 在某些shell中，!可能触发历史扩展
                if (i + 1 < cmd.size() && ! std::isspace(cmd[i + 1])) {
                    return false;
                }
            }

            // 进程替换 (bash特有)
            if (c == '(' || c == ')') {
                // 独立的括号可能表示子shell
                // 找到前一个非空白字符
                size_t j = (i == 0 ? 0 : i - 1);
                while (j > 0 && std::isspace(cmd[j])) --j;

                bool at_start_or_spaces = (j == 0 && std::isspace(cmd[0])) || (i == 0);
                bool prev_is_ctrl = (cmd[j] == ';' || cmd[j] == '&' || cmd[j] == '|' || cmd[j] == '(');

                if (at_start_or_spaces || prev_is_ctrl) {
                    return false; // 可能是子 shell 或进程替换
                }
            }

            // 大括号扩展
            if (c == '{' || c == '}') {
                return false;
            }

            // 波浪号扩展
            if (c == '~' && (i == 0 || std::isspace(cmd[i - 1]))) {
                // 这通常是安全的，但在严格模式下可能要禁止
                // return false;
            }

            i++;
        }

        // 检查是否有未闭合的引号或替换
        if (state.in_single_quotes || state.in_double_quotes || state.in_substitution || state.in_parameter_expansion) {
            return false; // 语法错误，不是简单命令
        }

        return true;
    }
};

// =============================================================================
// Command 类实现
// =============================================================================
// 用抛出异常替代 _exit(127)
class CommandExecException : public std::runtime_error {
  public:
    explicit CommandExecException(const std::string& what_arg) : std::runtime_error(what_arg) {}

    explicit CommandExecException(const char* what_arg) : std::runtime_error(what_arg) {}
};

class Command : public Executable {
  private:
    std::string command_line_;
    std::string working_dir_;
    std::map<std::string, std::string> env_vars_;
    std::vector<uint8_t> stdin_data_;
    std::function<void(std::ostream&)> stdin_writer_;
    std::chrono::milliseconds timeout_ms_{0};
    std::vector<int> inherit_fds_;

    bool capture_stdout_ = false;
    bool capture_stderr_ = false;
    LineCallback stdout_line_callback_;
    LineCallback stderr_line_callback_;
    bool shell_mode_ = false;
    std::string shell_intepreter = "/bin/sh";

    explicit Command(const std::string& cmd, bool shell_mode = false) : command_line_(cmd), shell_mode_(shell_mode) {}

  public:
    // 构造：接收完整命令行模板，以及可变参数替换
    template <typename... Args>
    static Command build(const std::string& template_str, Args&&... args) {
        std::string cmd = fmt::format(template_str, std::forward<Args>(args)...);
        if (! CommandAnalyzer::is_simple_command(cmd)) {
            throw CommandExecException(fmt::format(
                "Command::build(): detected shell operators in `{}`.\nUse Command::shell() if you really need a compound command.",
                cmd));
        }
        return Command(cmd, false);
    }

    // 直接使用 shell mode
    template <typename... Args>
    static Command shell(const std::string& template_str, Args&&... args) {
        std::string formatted_cmd = fmt::format(template_str, std::forward<Args>(args)...);
        return Command(formatted_cmd, true);
    }

    Command& set_interpreter(std::string interpreter_path) {
        shell_intepreter = interpreter_path;
        return *this;
    }

    // 设置工作目录
    Command& dir(const std::string& dir_path) {
        // 支持 ~/abc/def
        if (! dir_path.empty() && dir_path[0] == '~') { // 解析 HOME
            const char* home = ::getenv("HOME");
            if (home && dir_path.size() == 1) { // "~"
                working_dir_ = home;
            } else if (home) { // "~/sub/path"
                working_dir_ = std::string(home) + dir_path.substr(1);
            } else {
                throw std::runtime_error("HOME not set");
            }
        } else {
            working_dir_ = dir_path; // 普通绝对 / 相对路径
        }
        return *this;
    }

    // 设置环境变量（单个）
    Command& env(const std::string& key, const std::string& value) {
        env_vars_[key] = value;
        return *this;
    }

    // 设置环境变量（多个）
    Command& env(const std::map<std::string, std::string>& envs) {
        for (const auto& pair : envs) {
            env_vars_[pair.first] = pair.second;
        }
        return *this;
    }

    // 设置 stdin 输入（二进制流）
    Command& stdin_bin(const std::vector<uint8_t>& data) {
        stdin_data_ = data;
        return *this;
    }

    // 设置 stdin 输入（字符串）
    Command& stdin_text(const std::string& text_data) {
        stdin_data_.assign(text_data.begin(), text_data.end());
        return *this;
    }

    // 以回调方式写入 stdin
    Command& on_stdin(const std::function<void(std::ostream&)>& writer) {
        stdin_writer_ = writer;
        return *this;
    }

    // 捕获 stdout 到内存
    Command& capture_stdout() {
        capture_stdout_ = true;
        return *this;
    }

    // 捕获 stderr 到内存
    Command& capture_stderr() {
        capture_stderr_ = true;
        return *this;
    }

    // 流式回调逐行读取 stdout
    Command& on_stdout_line(const LineCallback& cb) {
        stdout_line_callback_ = cb;
        return *this;
    }

    // 流式回调逐行读取 stderr
    Command& on_stderr_line(const LineCallback& cb) {
        stderr_line_callback_ = cb;
        return *this;
    }

    // 新生成的子进程可以继承父进程 fd
    Command& inherit_fd(int fd) {
        inherit_fds_.push_back(fd);
        return *this;
    }

    Command& inherit_fds(std::vector<int> fds) {
        inherit_fds_.insert(inherit_fds_.end(), fds.begin(), fds.end());
        return *this;
    }

    // 设置超时时间
    Command& timeout(std::chrono::milliseconds duration) {
        timeout_ms_ = duration;
        return *this;
    }

    // 获取构建后的完整命令行
    std::string commandline() const {
        return command_line_;
    }

    std::string get_interpreter() const {
        return shell_intepreter;
    }

    // 同步执行
    CommandResult run() override {
        auto handle = run_async();
        return handle->get();
    }

    // 异步执行
    std::unique_ptr<FutureHandle> run_async() override {
        auto in = detail::Pipe();
        auto out = detail::Pipe();
        auto err = detail::Pipe();

        pid_t pid = ::fork();
        if (pid < 0) throw std::runtime_error("fork failed");

        if (pid == 0) {
            setup_child_process(std::move(in), std::move(out), std::move(err));
        }
        return setup_parent_process(pid, std::move(in), std::move(out), std::move(err));
    }


  private:
    void setup_child_process(detail::Pipe in, detail::Pipe out, detail::Pipe err) {
        in.dup2_read(STDIN_FILENO);
        out.dup2_write(STDOUT_FILENO);
        err.dup2_write(STDERR_FILENO);

        in.close_both();  // 读端已 dup2，写端必须提前关
        out.close_both(); // 写端已 dup2，读端必须提前关
        err.close_both();

        execute_command();

        // 析构函数自动关闭
        // in.close_both();
        // out.close_both();
        // err.close_both();
    }

    void execute_command() {
        if (! working_dir_.empty()) {
            if (::chdir(working_dir_.c_str()) == -1) {
                throw CommandExecException("chdir failed");
            }
        }

        for (const auto& kv : env_vars_) {
            if (::setenv(kv.first.c_str(), kv.second.c_str(), 1) == -1)
                throw CommandExecException("setenv failed for: " + kv.first);
        }

        if (shell_mode_) {
            // Shell 模式
            execl(shell_intepreter.c_str(), shell_intepreter.c_str(), "-c", command_line_.c_str(), nullptr);
            throw CommandExecException("Shell mode exec fail");
        } else {
            // 非 Shell 模式，需要分割命令
            auto args = detail::split_command(command_line_);
            if (args.empty()) {
                throw CommandExecException("Non-Shell args empty");
            }

            std::vector<char*> argv;
            for (const auto& arg : args) {
                argv.push_back(const_cast<char*>(arg.c_str()));
            }
            argv.push_back(nullptr);

            execvp(argv[0], argv.data());
            throw CommandExecException("Non-Shell mode exec fail");
        }
    }

  private:
    struct CapturedData {
        detail::Pipe pin;
        detail::Pipe pout;
        detail::Pipe perr;
        std::vector<uint8_t> stdin_data;
        std::shared_ptr<std::promise<CommandResult>> promise_ptr;
        pid_t pid;
        std::chrono::milliseconds timeout_ms;
        bool capture_stdout;
        bool capture_stderr;
        LineCallback stdout_cb;
        LineCallback stderr_cb;
    };

    std::unique_ptr<FutureHandle> setup_parent_process(pid_t pid, detail::Pipe in, detail::Pipe out, detail::Pipe err) {
        in.close_read();
        out.close_write();
        err.close_write();

        auto promise_ptr = std::make_shared<std::promise<CommandResult>>();
        std::future<CommandResult> fut = promise_ptr->get_future();

        // just code for c++11, because we cannot use `advance lambda capture`
        auto captured_data = std::make_shared<CapturedData>(CapturedData{
            .pin = std::move(in),
            .pout = std::move(out),
            .perr = std::move(err),
            .stdin_data = std::move(stdin_data_),
            .timeout_ms = this->timeout_ms_,
            .capture_stdout = this->capture_stdout_,
            .capture_stderr = this->capture_stderr_,
            .stdout_cb = this->stdout_line_callback_,
            .stderr_cb = this->stderr_line_callback_,
        });

        std::thread([captured_data, promise_ptr, pid]() mutable {
            CommandResult cmd_result;

            /* 1 写入 stdin */
            write_stdin(captured_data->stdin_data, captured_data->pin);

            /* 2 读取 stdout / stderr*/
            read_stdout(cmd_result, captured_data->capture_stdout, captured_data->pout, captured_data->stdout_cb);
            read_stderr(cmd_result, captured_data->capture_stderr, captured_data->perr, captured_data->stderr_cb);

            /* 3 等子进程退出 */
            wait_exit(cmd_result, pid, captured_data->timeout_ms);

            /* 4 交结果给 promise */
            submit_result(cmd_result, promise_ptr.get());
        }).detach();

        return std::unique_ptr<FutureHandle>(new CommandFutureHandle(pid, std::move(fut)));
    }

    static void write_stdin(std::vector<uint8_t>& stdin_data, detail::Pipe& pin) {
        if (! stdin_data.empty()) ::write(pin.write_fd(), stdin_data.data(), stdin_data.size());
        pin.close_write(); // 写完后立刻给子进程 EOF
    }

    static void
    read_stdout(CommandResult& cmd_result, bool capture_stdout, detail::Pipe& pout, const LineCallback& stdout_cb) {
        auto stdout_data = detail::handle_fd(pout.read_fd(), capture_stdout, stdout_cb);
        if (! stdout_data.empty()) cmd_result.set_stdout(std::move(stdout_data));

        pout.close_read(); // 读完后关闭读端
    }

    static void
    read_stderr(CommandResult& cmd_result, bool capture_stderr, detail::Pipe& perr, const LineCallback& stderr_cb) {
        auto stderr_data = detail::handle_fd(perr.read_fd(), capture_stderr, stderr_cb);
        if (! stderr_data.empty()) cmd_result.set_stderr(std::move(stderr_data));
        perr.close_read();
    }

    static void wait_exit(CommandResult& cmd_result, pid_t pid, std::chrono::milliseconds timeout) {
        int status = 0;
        auto deadline = std::chrono::steady_clock::now() + timeout;

        while (true) {
            pid_t ret = ::waitpid(pid, &status, WNOHANG); // 非阻塞检查
            if (ret == pid) {
                // 子进程退出了
                if (WIFEXITED(status))
                    cmd_result.set_exit_code(WEXITSTATUS(status));
                else if (WIFSIGNALED(status))
                    cmd_result.set_exit_code(-WTERMSIG(status));
                break;
            } else if (ret == 0) {
                // 子进程还活着
                if (timeout.count() > 0 && std::chrono::steady_clock::now() > deadline) {
                    // 超时，杀掉
                    ::kill(pid, SIGKILL);
                    cmd_result.set_exit_code(-SIGKILL);
                    cmd_result.set_timed_out(true);
                    break;
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(50)); // 避免忙等
            } else if (ret == -1 && errno != EINTR) {
                // 真错误
                break;
            }
        }
    }

    static void submit_result(CommandResult& res, std::promise<CommandResult>* promise_ptr) {
        promise_ptr->set_value(std::move(res));
    }
};

} // namespace kcommand
