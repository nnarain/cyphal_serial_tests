///                            ____                   ______            __          __
///                           / __ `____  ___  ____  / ____/_  ______  / /_  ____  / /
///                          / / / / __ `/ _ `/ __ `/ /   / / / / __ `/ __ `/ __ `/ /
///                         / /_/ / /_/ /  __/ / / / /___/ /_/ / /_/ / / / / /_/ / /
///                         `____/ .___/`___/_/ /_/`____/`__, / .___/_/ /_/`__,_/_/
///                             /_/                     /____/_/
///
/// TODO the docs are missing.
///
/// --------------------------------------------------------------------------------------------------------------------
///
/// This software is distributed under the terms of the MIT License.
/// Copyright (c) 2022 OpenCyphal.
/// Author: Pavel Kirienko <pavel@opencyphal.org>

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/// Semantic version of this library (not the Cyphal specification).
/// API will be backward compatible within the same major version.
#define SERARD_VERSION_MAJOR 0
#define SERARD_VERSION_MINOR 1

/// The version number of the Cyphal specification implemented by this library.
#define SERARD_CYPHAL_SPECIFICATION_VERSION_MAJOR 1
#define SERARD_CYPHAL_SPECIFICATION_VERSION_MINOR 0

/// These error codes may be returned from the library API calls whose return type is a signed integer in the negated
/// form (e.g., error code 2 returned as -2). A non-negative return value represents success.
/// API calls whose return type is not a signed integer cannot fail by contract.
/// No other error states may occur in the library.
/// By contract, a well-characterized application with properly sized memory pools will never encounter errors.
/// The error code 1 is not used because -1 is often used as a generic error code in 3rd-party code.
#define SERARD_ERROR_ARGUMENT 2
#define SERARD_ERROR_MEMORY 3
#define SERARD_ERROR_ANONYMOUS 4

/// Parameter ranges are inclusive; the lower bound is zero for all. See Cyphal/serial Specification for background.
#define SERARD_SUBJECT_ID_MAX 8191U
#define SERARD_SERVICE_ID_MAX 511U
#define SERARD_NODE_ID_MAX 0xFFFEU
#define SERARD_PRIORITY_MAX 7U
#define SERARD_TRANSFER_KIND_MAX 2U
// TODO: probably incorrect max?
#define SERARD_TRANSFER_ID_BIT_LENGTH 5U
#define SERARD_TRANSFER_ID_MAX ((1U << SERARD_TRANSFER_ID_BIT_LENGTH) - 1U)

/// This value represents an undefined node-ID: broadcast destination or anonymous source.
#define SERARD_NODE_ID_UNSET 0xFFFFU

/// This is the recommended transfer-ID timeout value given in the Cyphal Specification. The application may choose
/// different values per subscription (i.e., per data specifier) depending on its timing requirements.
#define SERARD_DEFAULT_TRANSFER_ID_TIMEOUT_USEC 2000000UL

/// A Cyphal/serial transfer has this byte at the beginning and at the end. Adjacent delimiters may be coalesced.
#define SERARD_TRANSFER_DELIMITER 0

// Forward declarations.
typedef uint64_t SerardMicrosecond;
typedef uint16_t SerardPortID;
typedef uint16_t SerardNodeID;
typedef uint64_t SerardTransferID;

/// Transfer priority level mnemonics per the recommendations given in the Cyphal Specification.
enum SerardPriority
{
    SerardPriorityExceptional = 0,
    SerardPriorityImmediate   = 1,
    SerardPriorityFast        = 2,
    SerardPriorityHigh        = 3,
    SerardPriorityNominal     = 4,  ///< Nominal priority level should be the default.
    SerardPriorityLow         = 5,
    SerardPrioritySlow        = 6,
    SerardPriorityOptional    = 7,
};

/// Transfer kinds as defined by the Cyphal Specification.
enum SerardTransferKind
{
    SerardTransferKindMessage  = 0,  ///< Multicast, from publisher to all subscribers.
    SerardTransferKindResponse = 1,  ///< Point-to-point, from server to client.
    SerardTransferKindRequest  = 2,  ///< Point-to-point, from client to server.
};
#define SERARD_NUM_TRANSFER_KINDS 3

/// The AVL tree node structure is exposed here to avoid pointer casting/arithmetics inside the library.
/// The user code is not expected to interact with this type except if advanced introspection is required.
struct SerardTreeNode
{
    struct SerardTreeNode* up;     ///< Do not access this field.
    struct SerardTreeNode* lr[2];  ///< Left and right children of this node may be accessed for tree traversal.
    int8_t                 bf;     ///< Do not access this field.
};

/// A Cyphal transfer metadata (everything except the payload).
struct SerardTransferMetadata
{
    enum SerardPriority priority;

    enum SerardTransferKind transfer_kind;

    /// Subject-ID for message publications; service-ID for service requests/responses.
    SerardPortID port_id;

    /// For outgoing message transfers the value shall be SERARD_NODE_ID_UNSET (otherwise the state is invalid).
    /// For outgoing service transfers this is the destination address (invalid if unset).
    /// For incoming non-anonymous transfers this is the node-ID of the origin.
    /// For incoming anonymous transfers the value is reported as SERARD_NODE_ID_UNSET.
    SerardNodeID remote_node_id;

    /// When responding to a service request, the response transfer SHALL have the same transfer-ID value as the
    /// request because the client will match the response with the request based on that.
    ///
    /// When publishing a message transfer, the value SHALL be one greater than the previous transfer under the same
    /// subject-ID; the initial value should be zero.
    ///
    /// When publishing a service request transfer, the value SHALL be one greater than the previous transfer under
    /// the same service-ID addressed to the same server node-ID; the initial value should be zero.
    ///
    /// A simple and robust way of managing transfer-ID counters is to keep a separate static variable per subject-ID
    /// and per (service-ID, server-node-ID) pair.
    SerardTransferID transfer_id;
};

/// Transfer subscription state. The application can register its interest in a particular kind of transfers exchanged
/// over the link by creating such subscription objects.
/// Transfers for which there is no active subscription will be silently dropped by the library.
/// SUBSCRIPTION INSTANCES SHALL NOT BE MOVED WHILE IN USE.
struct SerardRxSubscription
{
    struct SerardTreeNode base;  ///< Read-only

    SerardMicrosecond transfer_id_timeout_usec;
    size_t            extent;   ///< Read-only
    SerardPortID      port_id;  ///< Read-only

    /// This field can be arbitrarily mutated by the user. It is never accessed by the library.
    /// Its purpose is to simplify integration with OOP interfaces.
    void* user_reference;

    struct SerardInternalRxSession* sessions;  ///< Read-only
};

/// Reassembled incoming transfer returned by serardRxAccept().
struct SerardRxTransfer
{
    struct SerardTransferMetadata metadata;

    /// The timestamp of the first received data fragment of this transfer.
    /// The time system may be arbitrary as long as the clock is monotonic (steady).
    SerardMicrosecond timestamp_usec;

    /// payload_size is the , while payload_extent is the size of the memory buffer allocated by
    /// libserard to store the payload.
    /// payload_size is guaranteed to be less than or equal to payload_extent.
    /// If the payload is empty (payload_size = 0), the payload pointer may be NULL.
    /// The application is required to deallocate the payload buffer after the transfer is processed.
    /// Always de-allocate payload_extent bytes, NOT payload_size
    size_t payload_size;
    size_t payload_extent;
    void*  payload;
};

/// A pointer to the memory allocation function. The semantics are similar to malloc():
///     - The returned pointer shall point to an uninitialized block of memory that is at least "size" bytes large.
///     - If there is not enough memory, the returned pointer shall be NULL.
///     - The memory shall be aligned at least at max_align_t.
///     - The execution time should be constant (O(1)).
///     - The worst-case memory consumption (worst fragmentation) should be understood by the developer.
///
/// If the standard dynamic memory manager of the target platform does not satisfy the above requirements,
/// consider using O1Heap: https://github.com/pavel-kirienko/o1heap. Alternatively, some applications may prefer to
/// use a set of fixed-size block pool allocators (see the high-level overview for details).
///
/// The API documentation is written on the assumption that the memory management functions have constant
/// complexity and are non-blocking.
///
/// The value of the user reference is taken from the corresponding field of the memory resource structure.
typedef void* (*SerardMemoryAllocate)(void* const user_reference, const size_t size);

/// The counterpart of the above -- this function is invoked to return previously allocated memory to the allocator.
/// The size argument contains the amount of memory that was originally requested via the allocation function;
/// its value is undefined if the pointer is NULL.
/// The semantics are similar to free():
///     - The pointer was previously returned by the allocation function.
///     - The pointer may be NULL, in which case the function shall have no effect.
///     - The execution time should be constant (O(1)).
///
/// The value of the user reference is taken from the corresponding field of the memory resource structure.
typedef void (*SerardMemoryDeallocate)(void* const user_reference, const size_t size, void* const pointer);

/// A memory resource encapsulates the dynamic memory allocation and deallocation facilities.
/// Note that the library allocates a large amount of small fixed-size objects for bookkeeping purposes;
/// allocators for them can be implemented using fixed-size block pools to eliminate extrinsic memory fragmentation.
/// Instances are mostly intended to be passed by value.
struct SerardMemoryResource
{
    void*                  user_reference;  ///< Passed as the first argument.
    SerardMemoryDeallocate deallocate;      ///< Shall be a valid pointer.
    SerardMemoryAllocate   allocate;        ///< Shall be a valid pointer.
};

/// This function is invoked per fragment of the constructed serialized transfer.
/// The data_size is guaranteed to be in [1, 255] and the data pointer is guaranteed to be valid.
/// The function may or may not be blocking -- the library doesn't care but it affects its API semantics.
/// The return value shall be true on success; false aborts the transfer immediately.
/// The lifetime of the pointed data ends after return from this function.
typedef bool (*SerardTxEmit)(void* user_reference, uint8_t data_size, const uint8_t* data);

/// This is the core structure that keeps all of the states and allocated resources of the library instance.
struct Serard
{
    /// User pointer that can link this instance with other objects.
    /// This field can be changed arbitrarily, the library does not access it after initialization.
    /// The default value is NULL.
    void* user_reference;

    /// The node-ID of the local node. Per the Cyphal Specification, the node-ID should not be assigned more than once.
    /// The default value is SERARD_NODE_ID_UNSET.
    SerardNodeID node_id;

    /// The library uses separate memory resources for two kinds of objects:
    ///
    ///     - Payload buffers allocated for the received transfers.
    ///       The size of each allocation is (metadata overhead) + max(extent, (payload size));
    ///       transfers that contain larger payload will be implicitly truncated (see the Implicit Truncation Rule).
    ///
    ///     - RX session states. Each session state is a small object of size sizeof(SerardInternalRxSession)
    ///       used for internal bookkeeping per remote node transmitting data on a given port.
    ///
    /// The user may leverage this separation to implement different memory allocation strategies for these two kinds
    /// of objects. For example, the user may choose to allocate the payload buffers from O1Heap and the session
    /// states from a fixed-size block pool.
    struct SerardMemoryResource memory_payload;
    struct SerardMemoryResource memory_rx_session;

    /// Read-only
    struct SerardRxSubscription* rx_subscriptions[SERARD_NUM_TRANSFER_KINDS];
};

/// Each redundant interface from which transfers are to be received needs to have a separate instance of this type.
/// It keeps the state related to COBS decoding and CRC verification.
/// There is no de-segmentation because in Cyphal/serial, the maximum frame size is unlimited.
///
/// Ex https://github.com/Zubax/kocherga/blob/69e2131d3a26807428f67dc2f823afd988da1bc7/kocherga/kocherga_serial.hpp#L161
struct SerardReassembler
{
    uint8_t code;
    uint8_t copy;
    uint8_t state;
    uint8_t counter;
    // TODO: can we (re)move this?
    uint8_t header[24];
    // struct SerardRxHeaderModel header;
    struct SerardRxSubscription* sub;
    size_t                       max_payload_size;
};

/// Construct a new library instance.
/// The default values will be assigned as specified in the structure field documentation.
/// If any of the pointers are NULL, the behavior is undefined.
/// The instance does not hold any resources itself except for the allocated memory.
/// The time complexity is constant. This function does not invoke the dynamic memory manager.
struct Serard serardInit(const struct SerardMemoryResource memory_payload,
                         const struct SerardMemoryResource memory_rx_session);

/// TODO the docs are missing.
/// Negative -- invalid argument; zero -- emitter failure; positive -- success.
int8_t serardTxPush(struct Serard* const                       ins,
                    const struct SerardTransferMetadata* const metadata,
                    const size_t                               payload_size,
                    const void* const                          payload,
                    void* const                                user_reference,
                    const SerardTxEmit                         emitter);

/// TODO the docs are missing.
struct SerardReassembler serardReassemblerInit(void);

/// TODO the docs are missing.
/// If inout_payload_size is greater than zero, the payload pointer shall be advanced by the negative payload size delta
/// and the function shall be invoked again. This condition is guaranteed to never occur if the input payload size
/// does not exceed 32 bytes.
int8_t serardRxAccept(struct Serard* const                ins,
                      struct SerardReassembler* const     reassembler,
                      const SerardMicrosecond             timestamp_usec,
                      size_t* const                       inout_payload_size,
                      const uint8_t* const                payload,
                      struct SerardRxTransfer* const      out_transfer,
                      struct SerardRxSubscription** const out_subscription);

/// This function creates a new subscription, allowing the application to register its interest in a particular
/// category of transfers. The library will reject all transfers for which there is no active subscription.
/// The reference out_subscription shall retain validity until the subscription is terminated (the referred object
/// cannot be moved or destroyed).
///
/// If such subscription already exists, it will be removed first as if serardRxUnsubscribe() was
/// invoked by the application, and then re-created anew with the new parameters.
///
/// The extent defines the size of the transfer payload memory buffer; or, in other words, the maximum possible size
/// of received objects, considering also possible future versions with new fields. It is safe to pick larger values.
/// Note well that the extent is not the same thing as the maximum size of the object, it is usually larger!
/// Transfers that carry payloads that exceed the specified extent will be accepted anyway but the excess payload
/// will be truncated away, as mandated by the Specification. The transfer CRC is always validated regardless of
/// whether its payload is truncated.
///
/// The default transfer-ID timeout value is defined as SERARD_DEFAULT_TRANSFER_ID_TIMEOUT_USEC; use it if not sure.
///
/// The return value is 1 if a new subscription has been created as requested.
/// The return value is 0 if such subscription existed at the time the function was invoked. In this case,
/// the existing subscription is terminated and then a new one is created in its place. Pending transfers may be lost.
/// The return value is a negated invalid argument error if any of the input arguments are invalid.
///
/// For the time complexity see serardRxUnsubscribe().
/// This function does not allocate new memory. The function may deallocate memory if such subscription already
/// existed; the deallocation behavior is specified in the documentation for serardRxUnsubscribe().
int8_t serardRxSubscribe(struct Serard* const               ins,
                         const enum SerardTransferKind      transfer_kind,
                         const SerardPortID                 port_id,
                         const size_t                       extent,
                         const SerardMicrosecond            transfer_id_timeout_usec,
                         struct SerardRxSubscription* const out_subscription);

/// This function reverses the effect of serardRxSubscribe().
/// If the subscription is found, all its memory is de-allocated (session states and payload buffers); to determine
/// the amount of memory freed, please refer to the memory allocation requirement model of serardRxAccept().
///
/// The return value is 1 if such subscription existed (and, therefore, it was removed).
/// The return value is 0 if such subscription does not exist. In this case, the function has no effect.
/// The return value is a negated invalid argument error if any of the input arguments are invalid.
///
/// The time complexity is O(log x + y), where x is the number of current subscriptions under the specified transfer
/// kind, and y is the number of existing RX sessions for the selected subscription.
/// This function does not allocate new memory.
int8_t serardRxUnsubscribe(struct Serard* const          ins,
                           const enum SerardTransferKind transfer_kind,
                           const SerardPortID            port_id);

#ifdef __cplusplus
}
#endif
