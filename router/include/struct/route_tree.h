#ifndef __STRUCT_ROUTE_TREE_H__
#define __STRUCT_ROUTE_TREE_H__

#include <pcap.h>
#include <iterator>
#include <string>
#include <stack>
#include <stdint.h>

class RouteTree
{
  public:
    struct Route
    {
        std::string ip;
        uint8_t     mask;
        std::string next_jump;
    };

    class Node
    {
      private:
        Node*        left;   // 表示0
        Node*        right;  // 表示1
        std::string* next_jump;

      public:
        Node();
        ~Node();

      private:
        uint8_t      __add_route(const uint32_t& ip, const std::string& n_j, uint8_t& left_level, uint8_t& high);
        uint8_t      __remove_route(const uint32_t& ip, uint8_t& left_level, uint8_t& high);
        std::string* __lookup(const uint32_t& ip, uint8_t& left_level, uint8_t& high);
        void         clear_routes();

        friend class RouteTree;
    };

    class Iterator : public std::iterator<std::forward_iterator_tag, Route>
    {
      private:
        struct StackFrame
        {
            Node*    node;
            uint8_t  mask;
            uint32_t path_bits;
        };

        std::stack<StackFrame> stack;
        Route                  current_route;
        bool                   has_current;

        void advance();

      public:
        Iterator();
        Iterator(Node* root);

        Route     operator*() const;
        Iterator& operator++();

        bool operator==(const Iterator& other) const;
        bool operator!=(const Iterator& other) const;
    };

    Iterator begin() const;
    Iterator end() const;

  private:
    static uint32_t dname_cnt;
    std::string     name;
    Node*           root;

  public:
    RouteTree(pcap_if_t* dev = nullptr);
    RouteTree(const std::string& name, pcap_if_t* dev = nullptr);
    ~RouteTree();

    void update_device(pcap_if_t* dev);

    void set_default_route(const std::string& next_jump);

    /*
     * 0: 添加成功
     * 1: 修改成功
     * 2: 不允许外部修改直连路由
     */
    uint8_t add_route(const std::string& ip, uint8_t mask, const std::string& next_jump);

    /*
     * 0: 删除成功
     * 1: 删除失败
     * 2: 不允许删除直连路由
     */
    uint8_t remove_route(const std::string& ip, uint8_t mask);

    /*
     * 空串：未找到，且无默认路由
     * 非空：下一跳地址
     */
    std::string lookup(const std::string& ip, uint8_t mask);

    void print() const;

  private:
    uint8_t __add_route(const std::string& ip, uint8_t mask, const std::string& next_jump);
    void    __init(pcap_if_t* dev);
};

#endif  // __ROUTE_TREE__