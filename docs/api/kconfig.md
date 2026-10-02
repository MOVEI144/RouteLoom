# Component Kconfig reference

生成元を編集し、`python3 tools/gen_user_reference.py` で更新する。

条件付き default は上から評価する。実効値は `sdkconfig` と capability で確認する。
app 固有の Kconfig は対象外。秘密の値は reference に展開しない。

## routeloom

生成元：[components/routeloom/Kconfig](../../components/routeloom/Kconfig)

### CONFIG_ROUTELOOM_TRACE

```text
bool "Periodic Owner trace logs"
        default n
        help
            Logs the periodic diagnostics that otherwise cost console time
            on every node: the stack high-water mark and Owner counters
            once a minute, the member/authority counters every 5 s and the
            bridge USB counters every 2 s. Off in field images.
```

### CONFIG_ROUTELOOM_HIL_TRACE_LINK_EPOCHS

```text
bool "HIL trace of link context IDs and RLD1 handshake steps"
        default n
        help
            Bench-only diagnostic logs for reset recovery. Context IDs and
            handshake step numbers are logged, never keys or payloads.
```

### CONFIG_ROUTELOOM_HIL_HEAP_TELEMETRY

```text
bool "HIL free heap and largest block once per minute"
        default n
        help
            Bench-only heap samples beside the existing stack high-water log.
            Logs free, largest and minimum free 8-bit heap in bytes so a
            long hardware run can detect leaks and fragmentation. Also logs
            aggregate neighbor-discovery counts for route diagnosis.
```

### CONFIG_ROUTELOOM_HIL_EDHOC_TIMING

```text
bool "HIL timings for EDHOC P-256 operations and full exchange"
        default n
        help
            Logs operation durations and the full handshake duration on an
            ESP bench. No key, transcript or payload bytes are logged.
```

### CONFIG_ROUTELOOM_HIL_LR250_TELEMETRY

```text
bool "HIL log of the ESP-NOW LR250 driver rate call"
        default n
        help
            Logs the status returned by esp_now_set_peer_rate_config for
            each peer registration. This proves driver acceptance; air-rate
            confirmation still requires an independent sniffer.
```

### CONFIG_ROUTELOOM_HIL_DROP_RX_MAC

```text
string "HIL drop frames received from one peer MAC (empty disables)"
        default ""
        help
            Bench-only one-hop topology control. Set a 17-character colon
            separated MAC address to discard that sender's ESP-NOW frames
            before discovery and Wire processing. Use paired images to
            prevent a direct BIND and force a relay path. Empty by default.
```

### CONFIG_ROUTELOOM_HIL_RX_MIN_RSSI

```text
int "HIL minimum RX RSSI in dBm (0 disables)"
        range -127 0
        default 0
        help
            Bench-only weak-link simulation. Discard frames below this
            RSSI before discovery and Wire processing. Frames without RX
            metadata bypass this threshold. Zero removes the filter.
```

### CONFIG_ROUTELOOM_HIL_RX_DROP_PERMILLE

```text
int "HIL random RX drops per thousand (0 disables)"
        range 0 1000
        default 0
        help
            Bench-only loss injection using esp_random, after the RSSI
            threshold. Intentional drops and the pre-filter RSSI histogram
            are logged separately from RX queue overflows once a minute.
            Zero removes this filter; with both filters zero, their code
            and diagnostic state are absent from the image.
```

### CONFIG_ROUTELOOM_WIFI_NETIF_INIT

```text
bool "Start esp_netif (lwIP TCP/IP task) before the Wi-Fi driver"
        default n
        help
            ESP-NOW needs the Wi-Fi driver and the default event loop only.
            esp_netif_init() additionally starts the lwIP TCP/IP task and
            its mailboxes, which cost boot heap on ESP32-C3 gateways that
            never use IP networking. Enable only for firmware that also
            runs esp_netif/lwIP.
```

### CONFIG_ROUTELOOM_BOOT_HEAP_FLOOR_BYTES

```text
int "Boot heap floor after ESP-NOW start (bytes, 0 disables)"
        range 0 262144
        default 8192
        help
            After Wi-Fi, PHY and ESP-NOW are up the runtime logs the free
            internal heap and its largest block. Below this floor it logs
            the BOOT_HEAP_BELOW_FLOOR error (the node keeps running); the
            HIL harness treats that line as a failed start. The static-RAM
            guard in CI (tools/firmware_ram_report.py) models the same
            figure from measured per-target offsets; this is the on-device
            check of the real number (docs/design/sdk-v1/ram-budget.md).
```

### choice ROUTELOOM_RESOURCE_PROFILE

```text
prompt "Resource profile"
        default ROUTELOOM_RESOURCE_PROFILE_RELAY
        help
            Compile-time capacities of the Owner, MeshNode and USB bridge
            (include/routeloom/profile.hpp). The end-session count is the
            number of peers holding a live end-to-end key at once, not the
            mesh size: a full table evicts the oldest idle context and
            RLRES1 restores it on the next send.
```

### CONFIG_ROUTELOOM_RESOURCE_PROFILE_ENDPOINT

```text
bool "endpoint (8 end sessions, 16 routes, no join relay or USB)"
```

### CONFIG_ROUTELOOM_RESOURCE_PROFILE_RELAY

```text
bool "relay (8 end sessions, no join relay gateway or USB)"
```

### CONFIG_ROUTELOOM_RESOURCE_PROFILE_GATEWAY_SMALL

```text
bool "gateway_small (64 end sessions; ESP32-C3 gateway)"
```

### CONFIG_ROUTELOOM_RESOURCE_PROFILE_GATEWAY

```text
bool "gateway (128 end sessions)"
```

### CONFIG_ROUTELOOM_RESOURCE_PROFILE_FULL

```text
bool "full (every table at its maximum; host tests)"
```

### CONFIG_ROUTELOOM_RESOURCE_PROFILE_ID

```text
int
        default 1 if ROUTELOOM_RESOURCE_PROFILE_ENDPOINT
        default 3 if ROUTELOOM_RESOURCE_PROFILE_GATEWAY_SMALL
        default 4 if ROUTELOOM_RESOURCE_PROFILE_GATEWAY
        default 5 if ROUTELOOM_RESOURCE_PROFILE_FULL
        default 2
```

### choice ROUTELOOM_ROLE

```text
prompt "Device role"
        default ROUTELOOM_ROLE_RELAY
        help
            The role this image runs. A role above the resource profile
            (a gateway on a relay or endpoint profile, a relay on an
            endpoint profile) is refused before RF starts with
            RESOURCE_PROFILE_ROLE_MISMATCH.
```

### CONFIG_ROUTELOOM_ROLE_ENDPOINT

```text
bool "endpoint"
```

### CONFIG_ROUTELOOM_ROLE_RELAY

```text
bool "relay"
```

### CONFIG_ROUTELOOM_ROLE_GATEWAY

```text
bool "gateway (USB-attached)"
```

### CONFIG_ROUTELOOM_ROLE_ID

```text
int
        default 1 if ROUTELOOM_ROLE_ENDPOINT
        default 3 if ROUTELOOM_ROLE_GATEWAY
        default 2
```

### choice ROUTELOOM_DEDUP_PROFILE

```text
prompt "Dedup capacity"
        default ROUTELOOM_DEDUP_PROFILE_DEFAULT
        help
            Compile-time capacity of the node's duplicate-suppression pool
            (docs/reference/resource-profiles.json dedup_entries). Each record
            is 136 bytes of static RAM inside MeshNode (the budget allows 152).
            Terminal pins may use at most 7/8 of the pool; a relay's transit
            records are held only for the frame's own deadline plus a short
            slack. The resource profile sets the default (32 for endpoint and
            gateway_small, 96 otherwise); the other entries pin a size per
            image. Static RAM per role: docs/design/sdk-v1/ram-budget.md.
```

### CONFIG_ROUTELOOM_DEDUP_PROFILE_DEFAULT

```text
bool "resource profile default"
```

### CONFIG_ROUTELOOM_DEDUP_PROFILE_LEAF

```text
bool "leaf-small (32 records)"
```

### CONFIG_ROUTELOOM_DEDUP_PROFILE_RELAY

```text
bool "relay-c3 (96 records)"
```

### CONFIG_ROUTELOOM_DEDUP_PROFILE_GATEWAY

```text
bool "gateway-s3 (256 records)"
```

### CONFIG_ROUTELOOM_DEDUP_CAPACITY

```text
int
        default 32 if ROUTELOOM_DEDUP_PROFILE_LEAF
        default 96 if ROUTELOOM_DEDUP_PROFILE_RELAY
        default 256 if ROUTELOOM_DEDUP_PROFILE_GATEWAY
        default 0
```

### CONFIG_ROUTELOOM_USB_NODE_STATUS

```text
bool "node_status_v1 (HostOps 0x40-0x42)"
            default n if ROUTELOOM_RESOURCE_PROFILE_GATEWAY_SMALL
            default y
            help
                Per-node link/route tracking for the 0x40 pages and 0x42
                events. Off: attach_node_status() answers Unsupported and
                capability bit 6 is never advertised.
```

### CONFIG_ROUTELOOM_USB_GATEWAY_ENDPOINT

```text
bool "gateway_endpoint_v1 and config_endpoint_v1 (HostOps 0x10-0x25)"
            default n if ROUTELOOM_RESOURCE_PROFILE_GATEWAY_SMALL
            default y
            help
                Host registration, ingress and remote-gateway send slots of
                the explicit gateway endpoint, and the routed config lane.
                Off: attach_gateway()/attach_config() answer Unsupported and
                capability bits 3-4 are never advertised.
```

### CONFIG_ROUTELOOM_USB_GROUP

```text
bool "group_delivery_v1 (HostOps 0x50-0x52)"
            default y
```

### CONFIG_ROUTELOOM_USB_OBSERVATION

```text
bool "observation_v1 (HostOps 0x70-0x72)"
            default y
```

### choice ROUTELOOM_SECURITY_MODE

```text
prompt "Security owner profile"
        default ROUTELOOM_SECURITY_MODE_DEV_RAM
        help
            Exclusive session-security profile (G-SEC P4 §8.4). The
            reference, bridge and example entries share one
            EspNowSecurityOwner. DevRam is the development default
            (RAM-only provider, no NVS counter/replay writes); MemberEdhoc
            is the production candidate.
```

### CONFIG_ROUTELOOM_SECURITY_MODE_DEV_RAM

```text
bool "dev-ram (pairwise RAM sessions, no identity claim)"
```

### CONFIG_ROUTELOOM_SECURITY_MODE_MEMBER_EDHOC

```text
bool "member-edhoc (EDHOC membership via the security owner)"
```

### CONFIG_ROUTELOOM_APP_OBJECT_TRANSFER

```text
bool "Authenticated unicast application objects (4 KiB)"
        default n
        help
            Explicit object sends use Bulk priority and two outstanding chunks.
            Ordinary sends keep their existing payload limit. Applications
            provide the receive buffer and retain the immutable transmit loan.
```

### CONFIG_ROUTELOOM_APP_OBJECT_RX_SLOTS

```text
int "Application object receive slots"
        depends on ROUTELOOM_APP_OBJECT_TRANSFER
        range 1 1 if IDF_TARGET_ESP32C3
        range 1 2
        default 1 if IDF_TARGET_ESP32C3
        default 2
```

## routeloom_device

生成元：[components/routeloom_device/Kconfig](../../components/routeloom_device/Kconfig)

### CONFIG_ROUTELOOM_BOARD_C6_EXTERNAL_ANTENNA

```text
bool "C6 board: select external antenna"
        default n
        depends on IDF_TARGET_ESP32C6
        help
            Selects the external antenna path with GPIO14 high. By default
            GPIO14 is low for the internal antenna. Device startup enables
            the board RF switch with GPIO3 low before initializing Wi-Fi.
```

### CONFIG_ROUTELOOM_OWNER_TASK_STACK_SIZE

```text
int "Owner task stack (bytes)"
        range 8192 65536
        default 16384
        help
            Stack of the task that boots the node and runs the Owner loop
            (security owner, crypto, USB bridge, mesh pump). P4 §12.2 budgets
            16 KiB until the on-device high-water is measured. app_main only
            starts this task, so the ESP-IDF main task keeps its default stack.
```

### CONFIG_ROUTELOOM_OWNER_TASK_PRIORITY

```text
int "Owner task priority"
        range 1 24
        default 1
        help
            FreeRTOS priority of the Owner task. 1 equals the ESP-IDF main
            task the Owner loop ran on before.
```

### CONFIG_ROUTELOOM_NETWORK_ID

```text
hex "Network ID (low 32 bits on the wire)"
        default 0x524c0001
        help
            Pre-provisioning identity. Field images take it from the
            verified BoardConfig; the DevRam quick start
            (ROUTELOOM_DEV_KCONFIG_IDENTITY) uses this value.
```

### CONFIG_ROUTELOOM_NODE_ID

```text
hex "Node ID"
        default 0x1
```

### CONFIG_ROUTELOOM_CHANNEL

```text
int "2.4 GHz Wi-Fi channel"
        range 1 13
        default 6
```

### CONFIG_ROUTELOOM_DEV_KCONFIG_IDENTITY

```text
bool "DevRam quick start: Kconfig identity and development key"
        default n
        depends on ROUTELOOM_SECURITY_MODE_DEV_RAM
        help
            Takes the node, network and channel from this menu and the PSK
            from ROUTELOOM_DEVELOPMENT_KEY_HEX instead of the provisioned
            BoardConfig (rlcfg/rlkeys). For a first two-board test without
            provisioning; field images leave it off.
            Gateway USB requires the provisioned BoardConfig secret; this
            quick start cannot boot a gateway with an attached USB bridge.
```

### CONFIG_ROUTELOOM_TX_POWER_QDBM

```text
int "Approved test profile TX power, quarter-dBm"
        range 8 80
        default 40
        help
            This value is only a development profile. It is not a regulatory
            or product approval.
```

### CONFIG_ROUTELOOM_ROUTE_GATEWAY_SCOPED

```text
bool "Gateway-scoped routing profile (100-node sites)"
        default n
        depends on ROUTELOOM_SECURITY_MODE_DEV_RAM
        help
            Switches the node from the flat routing profile to the
            gateway-scoped profile (docs/design/sdk-v1/routing-scale.md,
            issue #41): routes to the listed gateways are proactive and
            refreshed along the gateway tree; other destinations are learned
            up the tree or on demand (ROUTE_REQUEST). Every node of a site
            must enable it with the same gateway set. Disabled keeps the flat
            profile and the SDK route timers (5000 ms / 15000 ms) unchanged.
            A gateway-role image lists its own Node ID as the first gateway.
            Under DEV_RAM the set is the dev profile's scoped routing policy.
```

### CONFIG_ROUTELOOM_GROUP_TREE_FLAT

```text
bool "Flat group tree: site gateways are group roots, not scoped routes"
        default n
        depends on ROUTELOOM_SECURITY_MODE_MEMBER_EDHOC
        help
            dev-flow §6.3 separates the group tree root set from the routing
            policy. Enabled, the verified SitePackage gateway list lands in
            node.group_roots and routing stays flat; disabled (default), the
            list keeps engaging the gateway-scoped profile it always has.
```

### CONFIG_ROUTELOOM_ROUTE_GATEWAY_1

```text
hex "Primary route gateway Node ID"
        default 0x1
        depends on ROUTELOOM_ROUTE_GATEWAY_SCOPED && !ROUTELOOM_ROLE_GATEWAY
        help
            The site gateway, normally the gateway image's ROUTELOOM_NODE_ID.
            Preferred uplink when a second gateway is configured. Must be
            non-zero; the build fails otherwise.
```

### CONFIG_ROUTELOOM_ROUTE_GATEWAY_2

```text
hex "Secondary route gateway Node ID; 0 = none"
        default 0x0
        depends on ROUTELOOM_ROUTE_GATEWAY_SCOPED
        help
            Optional second gateway of the site (at most two). Must differ
            from the first gateway.
```

### CONFIG_ROUTELOOM_ROUTE_PERIOD_MS

```text
int "Scoped route advertisement period (tick), ms"
        range 1000 60000
        default 5000
        depends on ROUTELOOM_ROUTE_GATEWAY_SCOPED
        help
            Scheduling tick of the scoped profile. Each gateway-tree link is
            refreshed once per 6 ticks (route_refresh_ticks, SDK default).
```

### CONFIG_ROUTELOOM_ROUTE_LIFETIME_MS

```text
int "Scoped route lifetime (lease), ms"
        range 14000 3600000
        default 90000
        depends on ROUTELOOM_ROUTE_GATEWAY_SCOPED
        help
            Lease of every learned route. The lease rule (routing-scale.md
            section 5) requires lifetime >= (2 x 6 + 2) x period, i.e. at
            least 70000 ms at the 5000 ms tick; the build fails on a
            violating pair. Product value: 90000 ms.
```

### CONFIG_ROUTELOOM_ROUTE_BROADCAST

```text
bool "Broadcast self+gateway route advertisements (GroupLink, opt-in)"
        default n
        depends on ROUTELOOM_ROUTE_GATEWAY_SCOPED
        help
            P5-2: downward refreshes to two or more grant-holding neighbors
            share one GroupLink route advertisement instead of one unicast
            each (routing-scale.md section 8). Every other target keeps
            unicast, so a mixed site keeps working. Enable on the whole site
            at once.
```

### CONFIG_ROUTELOOM_CAPABILITY

```text
hex "Capability bitmap (USB HelloAck on a gateway, discovery otherwise)"
        default 0x7 if ROUTELOOM_ROLE_GATEWAY
        default 0x3
        depends on ROUTELOOM_ROLE_GATEWAY
        help
            Gateway images: the HelloAck capability bitmap. A bit is only
            advertised when the matching endpoint is attached. Bit 2 (0x4)
            host_ops_v1 (SUBMIT/QUERY_DISPATCH/RETIRE_THROUGH/SKIP/
            TIME_SAMPLE, bound to the NVS-monotonic boot lease); bits 0-1
            are the legacy default with no per-bit meaning. EXPERIMENTAL
            opt-ins: bit 3 (0x8) gateway_endpoint_v1 (0x10-0x13), bit 4
            (0x10) config_endpoint_v1 (0x20-0x23), bit 5 (0x20)
            m1_diagnostics_v1 (0x30/0x31), bit 6 (0x40) node_status_v1
            (0x40-0x42), bit 7 (0x80) group_delivery_v1 (0x50-0x52; masked
            unless the node can source a group send), bit 11 (0x800)
            observation_v1 (0x70-0x72) and bit 13 (0x2000) channel_plan_v1
            (0x68/0x69, MemberEdhoc with ROUTELOOM_MIGRATION). Bits 6, 7,
            11 and 13 ride the HostOps carrier, so they need bit 2.
```

### CONFIG_ROUTELOOM_DEVELOPMENT_KEY_HEX

```text
string "DEVELOPMENT ONLY 32-byte network master key in hex"
        default "524f5554454c4f4f4d2d444556454c4f504d454e542d4b45592d4f4e4c592121"
        depends on ROUTELOOM_SECURITY_MODE_DEV_RAM
        help
            Shared development key of the DevRam quick start. Never use
            this default in a deployment.
```

### CONFIG_ROUTELOOM_CONFIG

```text
bool "Enable the remote-config target endpoint (RCC1 permit journal)"
        default n
        depends on !ROUTELOOM_ROLE_GATEWAY
        help
            Installs a ConfigTarget on the routed end-protected lane with a
            durable NVS-backed ConfigJournal (SDK namespace) and its RLF1
            floor. MemberEdhoc verifies RLCP1_COSE_ESP256 permits signed by
            the adopted site's authority key (kid = site_id) and binds once
            the membership is adopted. DevRam verifies the dev-HMAC permit
            key derived from its PSK (SecurityProfile::Development, never a
            production identity claim). The journal takes about 42 KB of
            static RAM: on ESP32-C3 it fits the endpoint resource profile
            only, and the build stops with an error for any other profile
            (the relay and gateway profiles would fall below the static RAM
            floor that radio start needs).
```

### CONFIG_ROUTELOOM_CONFIG_AUTHORITY

```text
hex "Config authority Node ID permitted to issue permits"
        default 0x1
        depends on ROUTELOOM_CONFIG && !ROUTELOOM_SECURITY_MODE_MEMBER_EDHOC
```

### CONFIG_ROUTELOOM_CONFIG_AUTHORITY_GENERATION

```text
int "Permitted authority generation for config permits"
        range 1 2147483647
        default 1
        depends on ROUTELOOM_CONFIG && !ROUTELOOM_SECURITY_MODE_MEMBER_EDHOC
```

### CONFIG_ROUTELOOM_OBSERVATION_REMOTE

```text
bool "Answer remote Diagnostic (48) observation queries over the mesh"
        default n
        depends on !ROUTELOOM_ROLE_GATEWAY
        help
            The node serves its read-only observation sections to
            end-protected RemoteObservationQuery frames (subtype 7). This only
            compiles the responder in; adopted coordinator modes (Member,
            Dev) answer and every other mode refuses, re-evaluated each pass.
```

### CONFIG_ROUTELOOM_MIGRATION

```text
int "Channel migration mode (0=Disabled, 1=Observe, 2=Manual)"
        range 0 2
        default 0
        help
            EXPERIMENTAL, MemberEdhoc only: a plan is signed by the adopted
            site's authority key (SAK), which DevRam does not have. DevRam
            keeps a fixed channel (SitePackage/Kconfig); a DevRam image with a
            non-zero mode stops the build instead of dropping the setting.
            Wires the migration participant and control-object
            transport onto the authenticated Wire lane. Observe runs the
            coordinator's evidence collection only; Manual additionally
            permits operator-driven plan issuance/surveys. Every member
            verifies plans with the adopted site's key and keeps its
            committed channel across reboots; the USB gateway is the site's plan authority in Manual mode and
            admits host plans over channel_plan_v1 (ROUTELOOM_CAPABILITY
            bit 13). Observe mode does not advertise that capability.
```

### CONFIG_ROUTELOOM_MIGRATION_RTT_P99_MS

```text
int "Measured management RTT P99 bound (ms) — deployment input"
        range 1 60000
        default 250
        depends on ROUTELOOM_MIGRATION != 0
```

### CONFIG_ROUTELOOM_MIGRATION_DELIVERY_BOUND_MS

```text
int "Measured control delivery bound (ms) — deployment input"
        range 1 60000
        default 2000
        depends on ROUTELOOM_MIGRATION != 0
```

### CONFIG_ROUTELOOM_MIGRATION_TRANSFER_BOUND_MS

```text
int "Measured prepare-phase transfer bound (ms) — deployment input"
        range 1 30000
        default 2000
        depends on ROUTELOOM_MIGRATION != 0
```

### CONFIG_ROUTELOOM_MIGRATION_SWITCH_BOUND_MS

```text
int "Measured local channel-switch bound (ms) — deployment input"
        range 1 5000
        default 50
        depends on ROUTELOOM_MIGRATION != 0
```

### CONFIG_ROUTELOOM_DEEP_SLEEP

```text
bool "Drive a deep-sleep prepare/enter cycle"
        default n
        depends on !ROUTELOOM_ROLE_GATEWAY
        help
            Experimental path: the Owner prepares sleep after
            ROUTELOOM_SLEEP_AFTER_MS of uptime and enters deep sleep with a
            timer wake. Real wake timing and current draw remain HIL work.
```

### CONFIG_ROUTELOOM_SLEEP_AFTER_MS

```text
int "Uptime before sleep_prepare is requested"
        range 1000 3600000
        default 10000
        depends on ROUTELOOM_DEEP_SLEEP
        help
            The defaults (10 s awake / 30 s asleep) are a bench demo duty
            cycle, not a battery operating point (issue #58). Battery
            deployments need a long sleep interval with a short warm resume,
            sized against docs/spec/power.md.
```

### CONFIG_ROUTELOOM_SLEEP_RADIO_BUDGET_MS

```text
int "Maximum radio-on time per deep-sleep wake"
        range 1000 3600000
        default 40000
        depends on ROUTELOOM_DEEP_SLEEP
        help
            Bounds discovery, membership recovery and sleep drain together.
            Exhaustion stops the radio and uses the existing bounded fault
            backoff, including when an isolated node never adopts membership.
```

### CONFIG_ROUTELOOM_SLEEP_DURATION_MS

```text
int "Timer wake duration for the deep-sleep cycle"
        range 100 86400000
        default 30000
        depends on ROUTELOOM_DEEP_SLEEP
        help
            Bench demo value (see ROUTELOOM_SLEEP_AFTER_MS). Every wake is a
            full reboot that consumes one boot session and its epochs.
```

### CONFIG_ROUTELOOM_MAINTENANCE_CONSOLE

```text
bool "Factory maintenance console on USB Serial/JTAG (office provisioning)"
        default n
        help
            Factory provisioning build (docs/design/sdk-v1/07-host-api-tooling.md
            §6): instead of booting the mesh (and on a gateway the USB bridge
            protocol), the node serves the maintenance console on USB
            Serial/JTAG pre-RF — keygen answers the office challenge with a
            proof of possession, identity seals the office bundle into
            rlsec/rlident as the committed RLI1 twin pair. Never enable in a
            field build: a console-enabled device re-provisions whoever holds
            its USB until RLI1 seals it with console_locked. The sdkv1 stores
            are wired in every build; this flag only gates the console.
            The console commits only a BoardConfig this chip could boot:
            the same chip, role, security mode and station MAC.
```
