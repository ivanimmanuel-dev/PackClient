import "pe"

rule PackClient_Launcher_Marker_Constellation_2026 {
    meta:
        description = "Detects the distinctive protocol and worker marker constellation in the recovered PackClientLauncher build"
        author = "Ivan Immanuel Shaji"
        date = "2026-09-05"
        status = "experimental"
        scope = "defensive static scanning"
        reference = "https://ivanimmanuel-dev.github.io/PackClient/references/detection-guide.html"

    strings:
        $plh1 = "PLH1" ascii
        $plc1 = "PLC1" ascii
        $pla1 = "PLA1" ascii
        $plk1 = "PLK1" ascii
        $ipc = "1RCP" ascii
        $worker = "/scr_cap_worker" ascii
        $psk_env = "PACK_LAUNCH_PSK" ascii
        $psk_fallback = "pack-launch-dev-psk" ascii
        $plugin_store = "PackMonitorClient.PluginStore.v1" ascii wide
        $core_primary = "PackClientCore.primary.dll" ascii wide

    condition:
        uint16(0) == 0x5a4d and pe.is_pe and
        $worker and $ipc and
        3 of ($plh1, $plc1, $pla1, $plk1) and
        1 of ($psk_*) and
        1 of ($plugin_store, $core_primary)
}
