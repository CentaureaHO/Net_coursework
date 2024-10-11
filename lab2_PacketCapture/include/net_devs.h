#ifndef __NET_DEVS_H__
#define __NET_DEVS_H__

#include <string>
#include <vector>

#include <pcap_defs.h>

/**
 * @brief 网络设备类，用于管理网络设备和捕获数据包
 *
 */
class NetDevice
{
  public:
    class DeviceInfo;

  private:
    pcap_t*     _device_handle;  ///< 存储打开的设备句柄
    std::string _device_name;    ///< 选中的设备名称

    /**
     * @brief 静态成员变量，用于存储所有可用的网络设备
     *
     */
    static std::vector<NetDevice::DeviceInfo> _devices;

    /**
     * @brief 静态成员变量，标记设备是否已经初始化
     *
     */
    static bool _devices_initialized;

  public:
    /**
     * @brief 设备信息结构体，包含设备名称和描述
     *
     */
    struct DeviceInfo
    {
        std::string name;         ///< 设备名称
        std::string description;  ///< 设备描述
    };

    /**
     * @brief 构造函数，初始化网络设备对象
     *
     */
    NetDevice();

    /**
     * @brief 析构函数，确保设备在析构时关闭
     *
     */
    ~NetDevice();

    /**
     * @brief 返回所有可用的网络设备列表
     *
     * @return const std::vector<DeviceInfo>& 网络设备列表
     */
    static const std::vector<DeviceInfo>& getDevices();

    /**
     * @brief 选择指定的网络设备
     *
     * @param deviceName 设备名称
     */
    void selectDevice(const std::string& deviceName);

    /**
     * @brief 获取当前选中的设备名称
     *
     * @return std::string 设备名称
     */
    std::string getCurDeviceName() const;

    /**
     * @brief 打开设备以进行数据包捕获
     *
     */
    void openDevice();

    /**
     * @brief 获取当前打开的设备句柄
     *
     * @return pcap_t* 返回设备句柄
     */
    pcap_t* getDeviceHandle() const;

    /**
     * @brief 捕获指定数量的数据包，并返回它们
     *
     * @param packet_count 捕获的数据包数量
     * @return std::vector<std::pair<struct pcap_pkthdr, std::vector<u_char>>> 捕获到的数据包
     */
    std::vector<std::pair<struct pcap_pkthdr, std::vector<u_char>>> capturePackets(int packet_count);

    /**
     * @brief 停止数据包捕获
     *
     */
    void stopCapture();

    /**
     * @brief 关闭网络设备
     *
     */
    void closeDevice();

  private:
    /**
     * @brief 更新设备列表，查找并存储所有可用的设备
     *
     */
    static void updateDevices();

    /**
     * @brief 静态回调函数，用于处理捕获到的数据包
     *
     * @param userData 用户数据指针，传递给回调函数
     * @param packetHeader 数据包头部信息
     * @param packet 捕获到的数据包
     */
    static void packetCollector(u_char* userData, const struct pcap_pkthdr* packetHeader, const u_char* packet);
};

#endif  // __NET_DEVS_H__