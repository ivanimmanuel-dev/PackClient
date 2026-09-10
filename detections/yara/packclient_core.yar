import "pe"

rule PackClient_Core_Marker_Constellation_2026 {
    meta:
        description = "Detects the recovered PackClient Core using Core exports and plugin interface strings"
        author = "Ivan Immanuel Shaji"
        date = "2026-09-10"
        status = "experimental"
        scope = "defensive static scanning"
        reference = "https://github.com/ivanimmanuel-dev/PackClient/blob/main/docs/detection-guide.md"
        sample_sha256 = "4de6ef8647fb4b599966a233740cb0514d1e71b8019a1a1792ed7e1e514edf1c"

    strings:
        $core_name = "PackClientCore.dll" ascii
        $core_run = "PackClientDll_Run" ascii
        $core_alloc = "PackClient_AllocStoredPluginImageW" ascii

        $plugin_store = "PackMonitorClient.PluginStore.v1" ascii
        $plugin_feature = "PackPlugin_GetFeatureId" ascii
        $plugin_registry = "PackPlugin.Registry.dll" wide
        $plugin_browser = "PackPlugin_BrowserMgr_TryHandleExtRemote" ascii

    condition:
        uint16(0) == 0x5a4d and pe.is_pe and
        all of ($core_*) and
        3 of ($plugin_*)
}
