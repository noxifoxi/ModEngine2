set(CMAKE_CXX_STANDARD 20)
enable_language(ASM_MASM)
enable_testing()

configure_file("modengine/version.cpp" "${CMAKE_CURRENT_BINARY_DIR}/version.cpp" @ONLY)

source_group(
        TREE "${PROJECT_SOURCE_DIR}/include"
        PREFIX "Header Files"
        FILES ${HEADER_LIST})

set(IMGUI_SRC
        "../third-party/imgui/imgui.cpp"
        "../third-party/imgui/imgui_draw.cpp"
        "../third-party/imgui/imgui_widgets.cpp"
        "../third-party/imgui/imgui_tables.cpp"
        "../third-party/imgui/backends/imgui_impl_dx11.cpp"
        "../third-party/imgui/backends/imgui_impl_win32.cpp"
)

set(KIERO_SRC "../third-party/kiero/kiero.cpp")

set_source_files_properties(
        ${KIERO_SRC}
        ${IMGUI_SRC}
        PROPERTIES
        COMPILE_FLAGS "-w"
)

add_library(modengine2 SHARED
        main.cpp
        ${CMAKE_CURRENT_BINARY_DIR}/version.cpp
        modengine/crash_handler.cpp
        modengine/extension.cpp
        modengine/extension_set.cpp
        modengine/mod_engine.cpp
        modengine/game_info.cpp
        modengine/hook_set.cpp
        modengine/overlay.cpp
        modengine/patch.cpp
        modengine/script_host.cpp
        modengine/settings.cpp
        modengine/lifecycle/render.cpp
        modengine/scripting/api_patch.cpp
        modengine/ext/base/base_extension.cpp
        modengine/ext/debug_menu/ds3/debug_menu_ds3.cpp
        modengine/ext/debug_menu/ds3/_DS3BootMenu.asm
        modengine/ext/debug_menu/ds3/_DS3Debug.asm
        modengine/ext/debug_menu/ds3/_DS3DebugDash.asm
        modengine/ext/debug_menu/ds3/_DS3GameProperties.asm
        modengine/ext/mod_loader/archive_file_overrides.cpp
        modengine/ext/mod_loader/mod_loader_extension.cpp
        modengine/ext/mod_loader/wwise_file_overrides.cpp
        modengine/ext/profiling/profiling_extension.cpp
        modengine/ext/profiling/profiler_trampoline.asm
        modengine/ext/profiling/main_loop.cpp
        modengine/ext/profiling/thread_hooks.cpp
        modengine/ext/scylla/scyllahide_extension.cpp
        modengine/util/hex_string.cpp
        modengine/util/platform.cpp
        ${IMGUI_SRC}
        ${KIERO_SRC} modengine/logging.cpp modengine/logging.h modengine/settings_loader.cpp modengine/settings_loader.h modengine/logger.cpp)

target_compile_features(modengine2 PUBLIC cxx_std_20)
target_compile_options(modengine2 PUBLIC /utf-8)
target_compile_definitions(modengine2 PUBLIC FMT_HEADER_ONLY SPDLOG_WCHAR_TO_UTF8_SUPPORT)
target_compile_definitions(modengine2 INTERFACE FMT_HEADER_ONLY MODENGINE_EXTERNAL)

target_include_directories(modengine2 PUBLIC
        "$<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>"
        "$<INSTALL_INTERFACE:$<INSTALL_PREFIX>/include>")

target_link_libraries(modengine2 PUBLIC
        "$<BUILD_INTERFACE:${LUA_LIBRARIES}>"
        "$<INSTALL_INTERFACE:$<INSTALL_PREFIX>/lib/lua.lib>")

target_compile_definitions(modengine2 PRIVATE KIERO_USE_DETOURS=1 KIERO_INCLUDE_D3D11=1)

target_include_directories(modengine2 PRIVATE
        ${DETOURS_INCLUDE_DIR}
        ${CMAKE_CURRENT_SOURCE_DIR}
        "../third-party/kiero"
        "../third-party/imgui"
        "../third-party/imgui/backends"
        "../third-party/MINT"
        "../third-party/ImTerm/include"
        "../third-party/sol2_ImGui_Bindings"
        "../third-party/mem/include")

target_link_libraries(modengine2 PRIVATE
        ${DETOURS_LIBRARY}
        spdlog::spdlog_header_only
        sol2
        crashpad::crashpad)

target_precompile_headers(modengine2 PUBLIC
        "$<$<COMPILE_LANGUAGE:CXX>:<MINT.h$<ANGLE-R>>"
        "$<$<COMPILE_LANGUAGE:CXX>:<sol/sol.hpp$<ANGLE-R>>"
        "$<$<COMPILE_LANGUAGE:CXX>:<fmt/format.h$<ANGLE-R>>"
        "$<$<COMPILE_LANGUAGE:CXX>:<spdlog/spdlog.h$<ANGLE-R>>"
        "$<$<COMPILE_LANGUAGE:CXX>:<toml++/toml.h$<ANGLE-R>>")

target_precompile_headers(modengine2 PRIVATE
        "$<$<COMPILE_LANGUAGE:CXX>:<imgui.h$<ANGLE-R>>")
