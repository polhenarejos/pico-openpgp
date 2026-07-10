idf_component_register(
    SRCS ${SOURCES}
    INCLUDE_DIRS .
    REQUIRES mbedtls efuse pico-keys-sdk
)
if(OPENPGP_TEST_INIT_LEGACY_PIN)
    target_compile_definitions(${COMPONENT_LIB} PRIVATE OPENPGP_TEST_INIT_LEGACY_PIN=1)
endif()
if(ENABLE_ADMINLESS_MODE)
    target_compile_definitions(${COMPONENT_LIB} PRIVATE ENABLE_ADMINLESS_MODE=1)
endif()
idf_component_set_property(${COMPONENT_NAME} WHOLE_ARCHIVE ON)
