#include <common/log.h>
#include <chrono>
#include <iomanip>
#include <iostream>
using namespace std;
using namespace chrono;

Logger::Logger(const string& logFileName) : logFileOpened_(false), logFileName_(logFileName) {}

Logger::~Logger()
{
    if (logFile_.is_open()) logFile_.close();
}

bool Logger::openLogFile()
{
    WriteGuard guard = rwLock.write();

    if (!logFileOpened_)
    {
        logFile_.open(logFileName_, ios::app);
        if (!logFile_.is_open())
        {
            cerr << "无法打开日志文件!" << endl;
            return false;
        }
        logFile_ << '\n';
        logFileOpened_ = true;
    }
    return true;
}

void Logger::log(const string& message)
{
    if (!logFileOpened_ && !openLogFile()) return;

    WriteGuard guard = rwLock.write();
    if (logFile_.is_open()) logFile_ << getCurrentTime() << " - " << message << endl;
}

string Logger::getCurrentTime()
{
    auto now = system_clock::now();

    auto now_time_t = system_clock::to_time_t(now);
    auto millis     = duration_cast<milliseconds>(now.time_since_epoch()) % 1000;

    ostringstream oss;
    oss << put_time(localtime(&now_time_t), "%Y-%m-%d %H:%M:%S") << '.' << setw(3) << setfill('0') << millis.count();

    return oss.str();
}

Logger glb_logger("Router.log");