#ifndef __COMMON_LOCK_H__
#define __COMMON_LOCK_H__

#include <condition_variable>
#include <mutex>

class ReWrLock;

/**
 * @brief 读锁守护类
 *
 * 用于管理读锁的生命周期。
 */
class ReadGuard
{
    friend ReWrLock;

  public:
    /**
     * @brief 析构函数
     *
     * 在对象销毁时释放读锁。
     */
    ~ReadGuard();

  private:
    /**
     * @brief 构造函数
     *
     * @param lock 读写锁对象
     */
    ReadGuard(ReWrLock& lock);

    ReWrLock& lock;  ///< 引用关联的读写锁对象
};

/**
 * @brief 写锁守护类
 *
 * 用于管理写锁的生命周期。
 */
class WriteGuard
{
    friend ReWrLock;

  public:
    /**
     * @brief 析构函数
     *
     * 在对象销毁时释放写锁。
     */
    ~WriteGuard();

  private:
    /**
     * @brief 构造函数
     *
     * @param lock 读写锁对象
     */
    WriteGuard(ReWrLock& lock);

    ReWrLock& lock;  ///< 引用关联的读写锁对象
};

/**
 * @brief 读写锁类
 *
 * 提供读写锁的功能，允许多个读者或者单个写者访问资源。
 */
class ReWrLock
{
    friend WriteGuard;
    friend ReadGuard;

  private:
    std::mutex              mtx;           ///< 互斥锁，用于保护共享资源
    std::condition_variable cond_var;      ///< 条件变量，用于同步
    int                     reader_count;  ///< 当前持有读锁的数量
    int                     writer_count;  ///< 当前持有写锁的数量

  public:
    /**
     * @brief 构造函数
     *
     * 初始化读写锁。
     */
    ReWrLock();

    /**
     * @brief 获取读锁
     *
     * 如果存在写者，则等待。
     * @return 读锁守护对象
     */
    ReadGuard read();

    /**
     * @brief 获取写锁
     *
     * 如果存在读者或写者，则等待。
     * @return 写锁守护对象
     */
    WriteGuard write();
};

#endif