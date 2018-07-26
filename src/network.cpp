#include <algorithm>
#include <utility>

#include "network.h"

namespace network {

    wpa_network::wpa_network(const wpa_network_id &network_id, const wpa_ssid &ssid,
                             const wpa_bssid &bssid)
        : m_id(network_id), m_ssid(ssid), m_bssid(bssid) {}

    wpa_network::wpa_network(const wpa_network &other)
        : m_id(other.m_id), m_ssid(other.m_ssid), m_bssid(other.m_bssid) {}

    wpa_network::wpa_network(wpa_network &&other)
        : m_id(std::move(other.m_id)),
          m_ssid(std::move(other.m_ssid)),
          m_bssid(std::move(other.m_bssid)) {}

    wpa_bssid::wpa_bssid(const std::array<uint8_t, BSSID_LEN> &bssid) : m_bssid(bssid) {}

    const wpa_network_id &wpa_network::id() const { return m_id; }

    const wpa_ssid &wpa_network::ssid() const { return m_ssid; }

    const wpa_bssid &wpa_network::bssid() const { return m_bssid; }

    std::array<uint8_t, wpa_bssid::BSSID_LEN> wpa_bssid::bssid() const { return m_bssid; }

    std::ostream &operator<<(std::ostream &os, const wpa_bssid &bssid) {
        auto bssid_cpy = bssid.bssid();

        if (bssid_cpy.cbegin() == bssid_cpy.cend()) {
            return os;
        }

        os << *bssid_cpy.cbegin();

        for (auto it = bssid_cpy.cbegin() + 1; it != bssid_cpy.cend(); ++it) {
            os << ":" << *it;
        }

        return os;
    }

    wpa_ssid::wpa_ssid(const std::string &ssid) : m_ssid(ssid) {}

    const std::string &wpa_ssid::ssid() const { return m_ssid; }

    std::ostream &operator<<(std::ostream &ostream, const wpa_ssid &ssid) {
        ostream << ssid.ssid();
        return ostream;
    }

    wpa_network_id::wpa_network_id(int32_t id) : m_id(id) {}

    int32_t wpa_network_id::id() const { return m_id; }

    bool operator==(const wpa_network_id &lhs, const wpa_network_id &rhs) {
        return lhs.m_id == rhs.m_id;
    }

    bool operator!=(const wpa_network_id &lhs, const wpa_network_id &rhs) { return !(lhs == rhs); }

    std::ostream &operator<<(std::ostream &ostream, const wpa_network_id &id) {
        ostream << id.id();
        return ostream;
    }

    wpa_interface_path::wpa_interface_path(fs::path ctrl_dir, fs::path interface)
        : m_ctrl_dir(std::move(ctrl_dir)), m_interface(std::move(interface)) {}

    fs::path wpa_interface_path::path() const { return m_interface; }

    wpa_interface wpa_interface_path::open_interface() const { return wpa_interface(*this); }

    wpa_interface::wpa_interface(wpa_interface &&device) noexcept
        : m_interface_path(std::move(device.m_interface_path)), m_ctrl(std::move(device.m_ctrl)) {}

    wpa_interface::wpa_interface(wpa_interface_path interface_path)
        : m_interface_path(std::move(interface_path)),
          m_ctrl(wpa_ctrl_open(m_interface_path.path().c_str()), wpa_ctrl_close) {}

    wpa_interface::operator bool() const { return m_ctrl != nullptr; }

    wpa_interface &wpa_interface::operator=(wpa_interface &&other) noexcept {
        swap(other);

        return *this;
    }

    void wpa_interface::swap(wpa_interface &other) noexcept {
        using fs::swap;
        using std::swap;

        swap(m_interface_path, other.m_interface_path);
        swap(m_ctrl, other.m_ctrl);
    }

    std::string wpa_interface::status() {
        return wpa_command::execute_command<wpa_commands::STATUS>(*this);
    }

    std::string wpa_interface::verbose_status() {
        return wpa_command::execute_command<wpa_commands::STATUS_VERBOSE>(*this);
    }

    void wpa_interface::logon() { return wpa_command::execute_command<wpa_commands::LOGON>(*this); }

    void wpa_interface::logoff() {
        return wpa_command::execute_command<wpa_commands::LOGOFF>(*this);
    }

    void wpa_interface::reassociate() {
        return wpa_command::execute_command<wpa_commands::REASSOCIATE>(*this);
    }

    void wpa_interface::reconnect() {
        return wpa_command::execute_command<wpa_commands::RECONNECT>(*this);
    }

    void wpa_interface::preauth(const wpa_bssid &bssid) {
        return wpa_command::execute_command<wpa_commands::PREAUTH>(*this, bssid);
    }

    void wpa_interface::attach() {
        return wpa_command::execute_command<wpa_commands::ATTACH>(*this);
    }
    void wpa_interface::detach() {
        return wpa_command::execute_command<wpa_commands::DETACH>(*this);
    }
    void wpa_interface::reconfigure() {
        return wpa_command::execute_command<wpa_commands::RECONFIGURE>(*this);
    }
    void wpa_interface::terminate() {
        return wpa_command::execute_command<wpa_commands::TERMINATE>(*this);
    }

    void set_bssid(const wpa_network_id &id, const wpa_bssid &bssid);

    std::vector<wpa_network> wpa_interface::list_networks() {
        return wpa_command::execute_command<wpa_commands::LIST_NETWORKS>(*this);
    }

    void wpa_interface::disconnect() {
        return wpa_command::execute_command<wpa_commands::DISCONNECT>(*this);
    }

    void wpa_interface::scan_async() {}
    void wpa_interface::scan_sync() {}

    void wpa_interface::select_network(const wpa_network_id &id) {
        return wpa_command::execute_command<wpa_commands::SELECT_NETWORK>(*this, id);
    }

    void wpa_interface::enable_network(const wpa_network_id &id) {
        return wpa_command::execute_command<wpa_commands::ENABLE_NETWORK>(*this, id);
    }

    void wpa_interface::disable_network(const wpa_network_id &id) {
        return wpa_command::execute_command<wpa_commands::DISABLE_NETWORK>(*this, id);
    }

    wpa_network_id wpa_interface::add_network() {
        return wpa_command::execute_command<wpa_commands::ADD_NETWORK>(*this);
    }

    void wpa_interface::remove_network(const wpa_network_id &id) {
        return wpa_command::execute_command<wpa_commands::REMOVE_NETWORK>(*this, id);
    }

    void wpa_interface::set_network(const wpa_network_id &id, const std::string &key,
                                    const std::string &value) {
        return wpa_command::execute_command<wpa_commands::SET_NETWORK>(*this, id, key, value);
    }

    void wpa_interface::get_network(const wpa_network_id &id, const std::string &key) {
        return wpa_command::execute_command<wpa_commands::GET_NETWORK>(*this, id, key);
    }

    void swap(wpa_interface &lhs, wpa_interface &rhs) { lhs.swap(rhs); }

    std::vector<wpa_interface_path> wpa_manager::get_interfaces(const fs::path &ctrl_dir) {
        std::vector<wpa_interface_path> devices;

        for (auto &current_device : fs::directory_iterator(ctrl_dir)) {
            devices.emplace_back(ctrl_dir, current_device.path());
        }

        return devices;
    }

}  // namespace network
