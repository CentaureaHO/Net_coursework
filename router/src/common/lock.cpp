#include <common/lock.h>

/**
 * @brief 读锁守护构造函数
 *
 * @param lock 读写锁对象
 */
ReadGuard::ReadGuard(ReWrLock& lock) : lock{lock} {}

/**
 * @brief 写锁守护构造函数
 *
 * @param lock 读写锁对象
 */
WriteGuard::WriteGuard(ReWrLock& lock) : lock{lock} {}

/**
 * @brief 读写锁构造函数
 *
 * 初始化读写锁的读者和写者计数。
 */
ReWrLock::ReWrLock() : reader_count{}, writer_count{} {}

/**
 * @brief 获取读锁
 *
 * 如果存在写者，则等待。增加读者计数并返回读锁守护对象。
 * @return 读锁守护对象
 */
ReadGuard ReWrLock::read()
{
    std::unique_lock<std::mutex> lock_guard(mtx);

    while (writer_count > 0) { cond_var.wait(lock_guard); }

    ++reader_count;
    ReadGuard guard(*this);
    return guard;
}

/**
 * @brief 获取写锁
 *
 * 如果存在读者或写者，则等待。增加写者计数并返回写锁守护对象。
 * @return 写锁守护对象
 */
WriteGuard ReWrLock::write()
{
    std::unique_lock<std::mutex> lock_guard(mtx);

    while (reader_count > 0 || writer_count > 0) { cond_var.wait(lock_guard); }

    ++writer_count;
    WriteGuard guard(*this);
    return guard;
}

/**
 * @brief 读锁守护析构函数
 *
 * 在对象销毁时减少读者计数，如果没有读者，则通知等待的写者。
 */
ReadGuard::~ReadGuard()
{
    std::unique_lock<std::mutex> lock_guard(lock.mtx);
    --lock.reader_count;
    if (lock.reader_count < 1) { lock.cond_var.notify_one(); }
}

/**
 * @brief 写锁守护析构函数
 *
 * 在对象销毁时减少写者计数，通知所有等待的线程。
 */
WriteGuard::~WriteGuard()
{
    std::unique_lock<std::mutex> lock_guard(lock.mtx);
    --lock.writer_count;
    lock.cond_var.notify_all();
}