// Emon DSL —— 测试入口（最小框架）
#include <cstdio>
#include <string>
#include <functional>
#include <vector>
#include <stdexcept>

struct TestCase {
    const char* name;
    std::function<void()> fn;
};
static std::vector<TestCase>& tests() { static std::vector<TestCase> v; return v; }

#define EMON_TEST(name) \
    static void name(); \
    static bool _reg_##name = [](){ tests().push_back({#name, name}); return true; }(); \
    static void name()

int main() {
    int failed = 0;
    for (auto& t : tests()) {
        try {
            t.fn();
            printf("PASS  %s\n", t.name);
        } catch (const std::exception& e) {
            ++failed;
            printf("FAIL  %s: %s\n", t.name, e.what());
        }
    }
    printf("=== %zu tests, %d failed ===\n", tests().size(), failed);
    return failed ? 1 : 0;
}
