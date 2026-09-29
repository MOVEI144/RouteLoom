#include "routeloom/usb_bridge.hpp"

static_assert(sizeof(routeloom::usb::UsbBridge) <= 26480,
              "disabled gateway and observation features retain state");

int main() { return 0; }
