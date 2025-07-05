#ifndef RUNAR_IOS_FFI_H
#define RUNAR_IOS_FFI_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Error codes
typedef enum {
    RUNAR_ERROR_SUCCESS = 0,
    RUNAR_ERROR_INVALID_PARAMETERS = 1,
    RUNAR_ERROR_NODE_NOT_INITIALIZED = 2,
    RUNAR_ERROR_NODE_ALREADY_STARTED = 3,
    RUNAR_ERROR_NODE_NOT_STARTED = 4,
    RUNAR_ERROR_SERVICE_NOT_FOUND = 5,
    RUNAR_ERROR_SERVICE_REGISTRATION_FAILED = 6,
    RUNAR_ERROR_KEYCHAIN_ERROR = 7,
    RUNAR_ERROR_SERIALIZATION_ERROR = 8,
    RUNAR_ERROR_NETWORK_ERROR = 9
} runar_error_code_t;

// Error structure
typedef struct {
    int32_t code;
    const char* message;
    const char* details;
} runar_error_t;

// Node configuration
typedef struct {
    const char* node_id;
    const char* default_network_id;
} runar_node_config_t;

// Node information
typedef struct {
    const char* node_id;
    const char* network_id;
    int is_running;
    int32_t peer_count;
    int32_t service_count;
} runar_node_info_t;

// Data result
typedef struct {
    const uint8_t* data;
    uintptr_t data_len;
    const runar_error_t* error;
} runar_data_result_t;

// Opaque node type
typedef struct runar_node runar_node_t;

// Callback types
typedef void (*runar_start_callback_t)(const char*, const runar_error_t*);
typedef void (*runar_stop_callback_t)(const char*, const runar_error_t*);
typedef void (*runar_request_callback_t)(const runar_data_result_t*);
typedef void (*runar_publish_callback_t)(const char*, const runar_error_t*);
typedef void (*runar_event_callback_t)(const char*, const uint8_t*, uintptr_t);
typedef void (*runar_service_callback_t)(int, const runar_error_t*);

// Function declarations
runar_error_t runar_runtime_initialize(void);
runar_error_t runar_runtime_handle_background(void);
runar_error_t runar_runtime_handle_foreground(void);

runar_node_t* runar_node_create(const runar_node_config_t* config);
void runar_node_start(runar_node_t* node, runar_start_callback_t callback);
void runar_node_stop(runar_node_t* node, runar_stop_callback_t callback);
void runar_node_request(runar_node_t* node, const char* path, const uint8_t* data, uintptr_t data_len, runar_request_callback_t callback);
void runar_node_publish(runar_node_t* node, const char* topic, const uint8_t* data, uintptr_t data_len, runar_publish_callback_t callback);
const char* runar_node_subscribe(runar_node_t* node, const char* topic, runar_event_callback_t callback);
runar_node_info_t runar_node_get_info(runar_node_t* node);

void runar_service_register(const char* path, const char* name, const char* version, const char* description, 
                           uint8_t* (*action_handler)(const char*, const uint8_t*, uintptr_t),
                           void (*event_handler)(const char*, const uint8_t*, uintptr_t),
                           runar_service_callback_t callback);
void runar_service_unregister(const char* path, runar_service_callback_t callback);

runar_error_t runar_lifecycle_setup_observers(runar_node_t* node);
runar_error_t runar_lifecycle_handle_background(runar_node_t* node);
runar_error_t runar_lifecycle_handle_foreground(runar_node_t* node);
runar_error_t runar_lifecycle_handle_memory_warning(runar_node_t* node);

#ifdef __cplusplus
}
#endif

#endif // RUNAR_IOS_FFI_H 