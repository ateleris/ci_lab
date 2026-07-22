project(CFS_CI_LAB C)

set(APP_SRC_FILES
    fsw/src/ci_lab_app.c
    fsw/src/ci_lab_cmds.c
)

if (CFE_EDS_ENABLED)
  list(APPEND APP_SRC_FILES
    fsw/src/ci_lab_eds_dispatch.c
    fsw/src/ci_lab_eds_decode.c
  )
else()
  list(APPEND APP_SRC_FILES
    fsw/src/ci_lab_dispatch.c
    fsw/src/ci_lab_crypto_decode.c
  )
endif()


# Create the app module
add_cfe_app(ci_lab ${APP_SRC_FILES})

target_include_directories(ci_lab PUBLIC fsw/inc)
# Mission defs hold the shared E2EQSS SDLS-GVCID config (e2eqss_sdls_cfg.h)
target_include_directories(ci_lab PRIVATE ${MISSION_DEFS})
add_cfe_app_dependency(ci_lab apqs_lib)
