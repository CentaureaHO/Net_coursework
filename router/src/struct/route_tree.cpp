#include <struct/route_tree.h>
#include <common/log.h>
#include <net/net_devs.h>
#include <iostream>
#include <iomanip>
#include <sstream>
using namespace std;

RouteTree::Node::Node() : left(nullptr), right(nullptr), next_jump(nullptr) {}
RouteTree::Node::~Node()
{
    if (left) delete left;
    if (right) delete right;
    if (next_jump) delete next_jump;
}

uint8_t RouteTree::Node::__add_route(const uint32_t& ip, const string& n_j, uint8_t& left_level, uint8_t& high)
{
    if (left_level == 0)
    {
        if (next_jump)
        {
            if (*next_jump == "Direct") return 2;

            *next_jump = n_j;
            return 1;
        }
        else
            next_jump = new string(n_j);
        return 0;
    }

    bool bit = ip & (1 << high);
    if (bit)
    {
        if (!right) right = new Node();
        return right->__add_route(ip, n_j, --left_level, --high);
    }
    else
    {
        if (!left) left = new Node();
        return left->__add_route(ip, n_j, --left_level, --high);
    }
}

uint8_t RouteTree::Node::__remove_route(const uint32_t& ip, uint8_t& left_level, uint8_t& high)
{
    if (left_level == 0)
    {
        if (!next_jump) return 1;

        if (*next_jump == "Direct") return 2;
        delete next_jump;
        next_jump = nullptr;
        return 0;
    }

    bool bit = ip & (1 << high);
    if (bit)
    {
        if (!right) return 1;
        return right->__remove_route(ip, --left_level, --high);
    }
    else
    {
        if (!left) return 1;
        return left->__remove_route(ip, --left_level, --high);
    }

    return 1;
}

string* RouteTree::Node::__lookup(const uint32_t& ip, uint8_t& left_level, uint8_t& high, string*& best_match)
{
    if (next_jump) best_match = next_jump;
    if (left_level == 0) return best_match;
    bool bit = ip & (1 << high);
    if (bit)
    {
        if (right) return right->__lookup(ip, --left_level, --high, best_match);
    }
    else
    {
        if (left) return left->__lookup(ip, --left_level, --high, best_match);
    }
    return best_match;
}

RouteTree::Iterator::Iterator() : has_current(false) {}

RouteTree::Iterator::Iterator(Node* root_node)
{
    if (root_node)
    {
        StackFrame frame;
        frame.node      = root_node;
        frame.mask      = 0;
        frame.path_bits = 0;
        stack.push(frame);
        has_current = false;
        advance();
    }
    else { has_current = false; }
}

void RouteTree::Iterator::advance()
{
    has_current = false;
    while (!stack.empty())
    {
        StackFrame current = stack.top();
        stack.pop();

        Node*    node      = current.node;
        uint8_t  mask      = current.mask;
        uint32_t path_bits = current.path_bits;

        if (node->next_jump)
        {
            uint32_t ip_int = (path_bits << (32 - mask));
            string   ip_str = to_string((ip_int >> 24) & 0xFF) + "." + to_string((ip_int >> 16) & 0xFF) + "." +
                            to_string((ip_int >> 8) & 0xFF) + "." + to_string(ip_int & 0xFF);
            current_route.ip        = ip_str;
            current_route.mask      = mask;
            current_route.next_jump = *(node->next_jump);
            has_current             = true;
        }

        if (node->right)
        {
            StackFrame right_frame;
            right_frame.node      = node->right;
            right_frame.mask      = mask + 1;
            right_frame.path_bits = (path_bits << 1) | 1;
            stack.push(right_frame);
        }

        if (node->left)
        {
            StackFrame left_frame;
            left_frame.node      = node->left;
            left_frame.mask      = mask + 1;
            left_frame.path_bits = (path_bits << 1);
            stack.push(left_frame);
        }

        if (has_current) { return; }
    }
}

RouteTree::Route RouteTree::Iterator::operator*() const { return current_route; }

RouteTree::Iterator& RouteTree::Iterator::operator++()
{
    if (has_current) { advance(); }
    return *this;
}

bool RouteTree::Iterator::operator==(const Iterator& other) const
{
    if (has_current != other.has_current) return false;
    if (!has_current && !other.has_current) return true;
    if (!has_current || !other.has_current) return false;
    if (stack.empty() && other.stack.empty()) return true;
    if (!stack.empty() && !other.stack.empty())
    {
        return stack.top().node == other.stack.top().node && stack.top().mask == other.stack.top().mask &&
               stack.top().path_bits == other.stack.top().path_bits;
    }
    return false;
}

bool RouteTree::Iterator::operator!=(const Iterator& other) const { return !(*this == other); }

RouteTree::Iterator RouteTree::begin() const { return Iterator(root); }

RouteTree::Iterator RouteTree::end() const { return Iterator(); }

RouteTree::RouteTree(pcap_if_t* dev) : name("RT_" + to_string(dname_cnt++)), root(new Node()) { __init(dev); }
RouteTree::RouteTree(const string& name, pcap_if_t* dev) : name(name), root(new Node()) { __init(dev); }
RouteTree::~RouteTree() { delete root; }

void RouteTree::__init(pcap_if_t* dev)
{
    if (!dev) return;

    vector<pair<string, uint8_t>> ips;
    getLocalIPs(dev, ips);

    for (auto& [ip, mask] : ips)
    {
        // cout << "Add Direct Route: " << ip << "/" << static_cast<int>(mask) << endl;
        LOG(glb_logger, "Add Direct Route: ", ip.c_str(), "/", static_cast<int>(mask));
        __add_route(ip, mask, "Direct");
    }
}

void RouteTree::update_device(pcap_if_t* dev)
{
    if (!dev) return;

    // cout << "Update Route Table: " << name << ", clear all routes." << endl;
    LOG(glb_logger, "Update Route Table: ", name.c_str(), ", clear all routes.");
    delete root;
    root = nullptr;
    root = new Node();

    vector<pair<string, uint8_t>> ips;
    getLocalIPs(dev, ips);

    for (auto& [ip, mask] : ips)
    {
        // cout << "Add Direct Route: " << ip << "/" << static_cast<int>(mask) << endl;
        LOG(glb_logger, "Add Direct Route: ", ip.c_str(), "/", static_cast<int>(mask));
        __add_route(ip, mask, "Direct");
    }
}

void RouteTree::set_default_route(const string& next_jump)
{
    if (next_jump == "Direct") return;

    if (root->next_jump)
        *root->next_jump = next_jump;
    else
        root->next_jump = new string(next_jump);
}

uint8_t RouteTree::add_route(const string& ip, uint8_t mask, const string& next_jump)
{
    if (next_jump == "Direct") return 2;
    return __add_route(ip, mask, next_jump);
}

uint8_t RouteTree::__add_route(const string& ip, uint8_t mask, const string& next_jump)
{
    // 期望：IP地址格式为'xxx.xxx.xxx.xxx'，mask为0~32
    uint8_t hi = 0, mi = 0, lo = 0, la = 0;
    if (sscanf(ip.c_str(), "%hhu.%hhu.%hhu.%hhu", &hi, &mi, &lo, &la) != 4) return 1;

    uint32_t ip_int     = (hi << 24) | (mi << 16) | (lo << 8) | la;
    uint8_t  left_level = mask;
    uint8_t  high       = 31;

    return root->__add_route(ip_int, next_jump, left_level, high);
}

uint8_t RouteTree::remove_route(const string& ip, uint8_t mask)
{
    if (mask == 0) return 2;

    uint8_t hi = 0, mi = 0, lo = 0, la = 0;
    if (sscanf(ip.c_str(), "%hhu.%hhu.%hhu.%hhu", &hi, &mi, &lo, &la) != 4) return 1;

    uint32_t ip_int     = (hi << 24) | (mi << 16) | (lo << 8) | la;
    uint8_t  left_level = mask;
    uint8_t  high       = 31;

    return root->__remove_route(ip_int, left_level, high);
}

string RouteTree::lookup(const string& ip, uint8_t mask)
{
    uint8_t hi = 0, mi = 0, lo = 0, la = 0;
    if (sscanf(ip.c_str(), "%hhu.%hhu.%hhu.%hhu", &hi, &mi, &lo, &la) != 4) return "";
    uint32_t ip_int     = (hi << 24) | (mi << 16) | (lo << 8) | la;
    uint8_t  left_level = mask;
    uint8_t  high       = 31;
    string*  best_match = nullptr;
    root->__lookup(ip_int, left_level, high, best_match);
    if (best_match) return *best_match;
    if (root->next_jump) return *root->next_jump;
    return "";
}

void RouteTree::print() const
{
    cout << "Route Table: " << name << endl;
    for (const auto& route : *this)
    {
        uint8_t hi = 0, mi = 0, lo = 0, la = 0;
        if (sscanf(route.ip.c_str(), "%hhu.%hhu.%hhu.%hhu", &hi, &mi, &lo, &la) != 4) continue;

        cout << "IP: " << setw(3) << setfill('0') << static_cast<int>(hi) << "." << setw(3) << setfill('0')
             << static_cast<int>(mi) << "." << setw(3) << setfill('0') << static_cast<int>(lo) << "." << setw(3)
             << setfill('0') << static_cast<int>(la) << "/" << setw(2) << setfill(' ') << static_cast<int>(route.mask)
             << " -> " << route.next_jump << endl;
    }
}

uint32_t RouteTree::dname_cnt = 0;