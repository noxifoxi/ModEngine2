#include "modengine/crash_handler.h"
#include "modengine/logging.h"
#include "modengine/mod_engine.h"
#include "modengine/version.h"

#include <optional>
#include <windows.h>
#include <iostream>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <modengine/settings_loader.h>

using namespace modengine;
using namespace spdlog;

namespace fs = std::filesystem;

static HMODULE modengine_instance;
static fs::path modengine_path;
static fs::path game_path;

typedef int(WINAPI* fnEntry)(void);

std::shared_ptr<ModEngine> modengine::mod_engine_global;
Hook<fnEntry> hooked_entrypoint;
HookSet entry_hook_set;

int WINAPI modengine_entrypoint(void)
{
    wchar_t dll_filename[MAX_PATH + 1];

    // Grab the path to the modengine2.dll file, so we can locate the global
    // configuration from here if it exists.
    if (!GetModuleFileNameW(modengine_instance, dll_filename, MAX_PATH)) {
        return false;
    }

    modengine_path = fs::path(dll_filename).parent_path();
    if (modengine_path.filename() == "bin") {
        modengine_path = modengine_path.parent_path();
    }

    wchar_t game_filename[MAX_PATH + 1];

    // Also get the path to the game executable, to support legacy use-cases of putting
    // mods in the game folder.
    if (!GetModuleFileNameW(nullptr, game_filename, MAX_PATH)) {
        return false;
    }

    game_path = fs::path(game_filename).parent_path();

    start_crash_handler(modengine_path, game_path);

    auto is_debugger_enabled = std::getenv("MODENGINE_DEBUG_GAME") != nullptr;
    if (is_debugger_enabled) {
        while (!IsDebuggerPresent()) {
            Sleep(100);
        }

        DebugBreak();
    }

    /* We need to restore any changes to entrypoint code.
     * Steam checks the signature of this */
    entry_hook_set.unhook_all();

#if ELDEN_LOADER_MODE
    const auto settings_path_env = std::getenv("MODENGINE_CONFIG");
    if (settings_path_env == nullptr) {
       _putenv_s("MODENGINE_CONFIG", (game_path / "modengine.toml").string().c_str());
    }
#endif

    SettingsLoader settings_loader(modengine_path, game_path);
    Settings settings;

    auto logs_path = modengine_path / "logs";
    if (!fs::exists(logs_path)) {
        (void) fs::create_directory(logs_path);
    }

    auto logger = logging::setup_logger(logs_path, is_debugger_enabled);
    spdlog::set_default_logger(logger);

    auto settings_status = settings_loader.load(settings);
    auto config = settings.get_config_reader().read_config_object<ModEngineConfig>({ "modengine" });

    if (config.debug && !is_debugger_enabled) {
        // Create debug console
        AllocConsole();
        FILE* stream;
        freopen_s(&stream, "CONOUT$", "w", stdout);
        freopen_s(&stream, "CONIN$", "r", stdin);

        logger->set_level(spdlog::level::trace);
        logger->sinks().push_back(std::make_shared<spdlog::sinks::stdout_color_sink_mt>());
    }

    const auto game_info = GameInfo::from_current_module();
    if (!game_info) {
        error("Unable to detect a supported game");
        return false;
    }

    info("ModEngine version {} initializing for {}", modengine::g_version, game_info->description(), game_info->version);
    info("Local settings loaded: {}, Global settings loaded: {}",
        settings_status.found_local_config,
        settings_status.found_global_config);
    info("Main thread ID: {}", GetCurrentThreadId());

    mod_engine_global.reset(new ModEngine { *game_info, settings, config });

    try {
        mod_engine_global->attach();
    } catch (std::exception& e) {
        error("Failed to attach modengine: {}", e.what());
    }

#if !ELDEN_LOADER_MODE
    return hooked_entrypoint.original();
#else
    return 0;
#endif
}

static bool attach(HMODULE module)
{
    modengine_instance = module;
    wchar_t dll_filename[MAX_PATH];

    // Grab the path to the modengine2.dll file, so we can locate the global
    // configuration from here if it exists.
    if (!GetModuleFileNameW(module, dll_filename, MAX_PATH)) {
        return false;
    }

    modengine_path = fs::path(dll_filename).parent_path();
    if (modengine_path.filename() == "bin") {
        modengine_path = modengine_path.parent_path();
    }

    wchar_t game_filename[MAX_PATH];

    // Also get the path to the game executable, to support legacy use-cases of putting
    // mods in the game folder.
    if (!GetModuleFileNameW(nullptr, game_filename, MAX_PATH)) {
        return false;
    }

    game_path = fs::path(game_filename).parent_path();

#if !ELDEN_LOADER_MODE
    hooked_entrypoint.original = reinterpret_cast<fnEntry>(DetourGetEntryPoint(nullptr));
    hooked_entrypoint.replacement = modengine_entrypoint;
    entry_hook_set.install(reinterpret_cast<Hook<modengine::GenericFunctionPointer>*>(&hooked_entrypoint));
    entry_hook_set.hook_all();
#else
    // Chain with Elden Mod Loader
    modengine_entrypoint();
#endif

    return true;
}

static bool detach()
{
    if (mod_engine_global != nullptr) {
        mod_engine_global->detach();
    }

    return true;
}

BOOL APIENTRY DllMain(HMODULE module, DWORD dwReason, LPVOID)
{
    if (DetourIsHelperProcess()) {
        return TRUE;
    }

    switch (dwReason) {
    case DLL_PROCESS_ATTACH:
        DetourRestoreAfterWith();
        return attach(module);
    case DLL_PROCESS_DETACH:
        return detach();
    }
    return TRUE;
}
