// This is an AUTO-GENERATED Cyphal DSDL data type implementation. Curious? See https://opencyphal.org.
// You shouldn't attempt to edit this file.
//
// Checking this file under version control is not recommended unless it is used as part of a high-SIL
// safety-critical codebase. The typical usage scenario is to generate it as part of the build process.
//
// To avoid conflicts with definitions given in the source DSDL file, all entities created by the code generator
// are named with an underscore at the end, like foo_bar_().
//
// Generator:     nunavut-2.3.1 (serialization was enabled)
// Source file:   /cyphal_types/public_regulated_data_types/uavcan/metatransport/can/ArbitrationID.0.1.dsdl
// Generated at:  2024-10-06 20:48:11.405209 UTC
// Is deprecated: no
// Fixed port-ID: None
// Full name:     uavcan.metatransport.can.ArbitrationID
// Version:       0.1
//
// Platform
//     python_implementation:  CPython
//     python_version:  3.12.3
//     python_release_level:  final
//     python_build:  ('main', 'Sep 11 2024 14:17:37')
//     python_compiler:  GCC 13.2.0
//     python_revision:
//     python_xoptions:  {}
//     runtime_platform:  Linux-5.15.153.1-microsoft-standard-WSL2-x86_64-with-glibc2.39
//
// Language Options
//     target_endianness:  any
//     omit_float_serialization_support:  False
//     enable_serialization_asserts:  False
//     enable_override_variable_array_capacity:  False
//     cast_format:  (({type}) {value})

#ifndef UAVCAN_METATRANSPORT_CAN_ARBITRATION_ID_0_1_INCLUDED_
#define UAVCAN_METATRANSPORT_CAN_ARBITRATION_ID_0_1_INCLUDED_

#include <nunavut/support/serialization.h>
#include <stdint.h>
#include <stdlib.h>
#include <uavcan/metatransport/can/BaseArbitrationID_0_1.h>
#include <uavcan/metatransport/can/ExtendedArbitrationID_0_1.h>

static_assert( NUNAVUT_SUPPORT_LANGUAGE_OPTION_TARGET_ENDIANNESS == 1693710260,
              "/cyphal_types/public_regulated_data_types/uavcan/metatransport/can/ArbitrationID.0.1.dsdl is trying to use a serialization library that was compiled with "
              "different language options. This is dangerous and therefore not allowed." );
static_assert( NUNAVUT_SUPPORT_LANGUAGE_OPTION_OMIT_FLOAT_SERIALIZATION_SUPPORT == 0,
              "/cyphal_types/public_regulated_data_types/uavcan/metatransport/can/ArbitrationID.0.1.dsdl is trying to use a serialization library that was compiled with "
              "different language options. This is dangerous and therefore not allowed." );
static_assert( NUNAVUT_SUPPORT_LANGUAGE_OPTION_ENABLE_SERIALIZATION_ASSERTS == 0,
              "/cyphal_types/public_regulated_data_types/uavcan/metatransport/can/ArbitrationID.0.1.dsdl is trying to use a serialization library that was compiled with "
              "different language options. This is dangerous and therefore not allowed." );
static_assert( NUNAVUT_SUPPORT_LANGUAGE_OPTION_ENABLE_OVERRIDE_VARIABLE_ARRAY_CAPACITY == 0,
              "/cyphal_types/public_regulated_data_types/uavcan/metatransport/can/ArbitrationID.0.1.dsdl is trying to use a serialization library that was compiled with "
              "different language options. This is dangerous and therefore not allowed." );
static_assert( NUNAVUT_SUPPORT_LANGUAGE_OPTION_CAST_FORMAT == 2368206204,
              "/cyphal_types/public_regulated_data_types/uavcan/metatransport/can/ArbitrationID.0.1.dsdl is trying to use a serialization library that was compiled with "
              "different language options. This is dangerous and therefore not allowed." );

#ifdef __cplusplus
extern "C" {
#endif

/// This type does not have a fixed port-ID. See https://forum.opencyphal.org/t/choosing-message-and-service-ids/889
#define uavcan_metatransport_can_ArbitrationID_0_1_HAS_FIXED_PORT_ID_ false

// +-------------------------------------------------------------------------------------------------------------------+
// | uavcan.metatransport.can.ArbitrationID.0.1
// +-------------------------------------------------------------------------------------------------------------------+
#define uavcan_metatransport_can_ArbitrationID_0_1_FULL_NAME_             "uavcan.metatransport.can.ArbitrationID"
#define uavcan_metatransport_can_ArbitrationID_0_1_FULL_NAME_AND_VERSION_ "uavcan.metatransport.can.ArbitrationID.0.1"

/// Extent is the minimum amount of memory required to hold any serialized representation of any compatible
/// version of the data type; or, on other words, it is the the maximum possible size of received objects of this type.
/// The size is specified in bytes (rather than bits) because by definition, extent is an integer number of bytes long.
/// When allocating a deserialization (RX) buffer for this data type, it should be at least extent bytes large.
/// When allocating a serialization (TX) buffer, it is safe to use the size of the largest serialized representation
/// instead of the extent because it provides a tighter bound of the object size; it is safe because the concrete type
/// is always known during serialization (unlike deserialization). If not sure, use extent everywhere.
#define uavcan_metatransport_can_ArbitrationID_0_1_EXTENT_BYTES_                    5UL
#define uavcan_metatransport_can_ArbitrationID_0_1_SERIALIZATION_BUFFER_SIZE_BYTES_ 5UL
static_assert(uavcan_metatransport_can_ArbitrationID_0_1_EXTENT_BYTES_ >= uavcan_metatransport_can_ArbitrationID_0_1_SERIALIZATION_BUFFER_SIZE_BYTES_,
              "Internal constraint violation");

typedef struct
{
    union  /// The union is placed first to ensure that the active element address equals the struct address.
    {
        /// uavcan.metatransport.can.BaseArbitrationID.0.1 base
        uavcan_metatransport_can_BaseArbitrationID_0_1 base;

        /// uavcan.metatransport.can.ExtendedArbitrationID.0.1 extended
        uavcan_metatransport_can_ExtendedArbitrationID_0_1 extended;
    };
    uint8_t _tag_;
} uavcan_metatransport_can_ArbitrationID_0_1;

/// The number of fields in the union. Valid tag values range from zero to this value minus one, inclusive.
#define uavcan_metatransport_can_ArbitrationID_0_1_UNION_OPTION_COUNT_ 2U

/// Serialize an instance into the provided buffer.
/// The lifetime of the resulting serialized representation is independent of the original instance.
/// This method may be slow for large objects (e.g., images, point clouds, radar samples), so in a later revision
/// we may define a zero-copy alternative that keeps references to the original object where possible.
///
/// @param obj      The object to serialize.
///
/// @param buffer   The destination buffer. There are no alignment requirements.
///                 @see uavcan_metatransport_can_ArbitrationID_0_1_SERIALIZATION_BUFFER_SIZE_BYTES_
///
/// @param inout_buffer_size_bytes  When calling, this is a pointer to the size of the buffer in bytes.
///                                 Upon return this value will be updated with the size of the constructed serialized
///                                 representation (in bytes); this value is then to be passed over to the transport
///                                 layer. In case of error this value is undefined.
///
/// @returns Negative on error, zero on success.
static inline int8_t uavcan_metatransport_can_ArbitrationID_0_1_serialize_(
    const uavcan_metatransport_can_ArbitrationID_0_1* const obj, uint8_t* const buffer,  size_t* const inout_buffer_size_bytes)
{
    if ((obj == NULL) || (buffer == NULL) || (inout_buffer_size_bytes == NULL))
    {
        return -NUNAVUT_ERROR_INVALID_ARGUMENT;
    }
    const size_t capacity_bytes = *inout_buffer_size_bytes;
    if ((8U * (size_t) capacity_bytes) < 40UL)
    {
        return -NUNAVUT_ERROR_SERIALIZATION_BUFFER_TOO_SMALL;
    }
    // Notice that fields that are not an integer number of bytes long may overrun the space allocated for them
    // in the serialization buffer up to the next byte boundary. This is by design and is guaranteed to be safe.
    size_t offset_bits = 0U;
    {   // Union tag field: truncated uint8
        buffer[offset_bits / 8U] = (uint8_t)(obj->_tag_);  // C std, 6.3.1.3 Signed and unsigned integers
        offset_bits += 8U;
    }
    if (0U == obj->_tag_)  // uavcan.metatransport.can.BaseArbitrationID.0.1 base
    {
        size_t _size_bytes0_ = 4UL;  // Nested object (max) size, in bytes.
        int8_t _err0_ = uavcan_metatransport_can_BaseArbitrationID_0_1_serialize_(
            &obj->base, &buffer[offset_bits / 8U], &_size_bytes0_);
        if (_err0_ < 0)
        {
            return _err0_;
        }
        // It is assumed that we know the exact type of the serialized entity, hence we expect the size to match.
        offset_bits += _size_bytes0_ * 8U;  // Advance by the size of the nested object.
    }
    else if (1U == obj->_tag_)  // uavcan.metatransport.can.ExtendedArbitrationID.0.1 extended
    {
        size_t _size_bytes1_ = 4UL;  // Nested object (max) size, in bytes.
        int8_t _err1_ = uavcan_metatransport_can_ExtendedArbitrationID_0_1_serialize_(
            &obj->extended, &buffer[offset_bits / 8U], &_size_bytes1_);
        if (_err1_ < 0)
        {
            return _err1_;
        }
        // It is assumed that we know the exact type of the serialized entity, hence we expect the size to match.
        offset_bits += _size_bytes1_ * 8U;  // Advance by the size of the nested object.
    }
    else
    {
        return -NUNAVUT_ERROR_REPRESENTATION_BAD_UNION_TAG;
    }
    if (offset_bits % 8U != 0U)  // Pad to 8 bits. TODO: Eliminate redundant padding checks.
    {
        const uint8_t _pad0_ = (uint8_t)(8U - offset_bits % 8U);
        const int8_t _err2_ = nunavutSetUxx(&buffer[0], capacity_bytes, offset_bits, 0U, _pad0_);  // Optimize?
        if (_err2_ < 0)
        {
            return _err2_;
        }
        offset_bits += _pad0_;
    }
    // It is assumed that we know the exact type of the serialized entity, hence we expect the size to match.
    *inout_buffer_size_bytes = (size_t) (offset_bits / 8U);
    return NUNAVUT_SUCCESS;
}

/// Deserialize an instance from the provided buffer.
/// The lifetime of the resulting object is independent of the original buffer.
/// This method may be slow for large objects (e.g., images, point clouds, radar samples), so in a later revision
/// we may define a zero-copy alternative that keeps references to the original buffer where possible.
///
/// @param obj      The object to update from the provided serialized representation.
///
/// @param buffer   The source buffer containing the serialized representation. There are no alignment requirements.
///                 If the buffer is shorter or longer than expected, it will be implicitly zero-extended or truncated,
///                 respectively; see Specification for "implicit zero extension" and "implicit truncation" rules.
///
/// @param inout_buffer_size_bytes  When calling, this is a pointer to the size of the supplied serialized
///                                 representation, in bytes. Upon return this value will be updated with the
///                                 size of the consumed fragment of the serialized representation (in bytes),
///                                 which may be smaller due to the implicit truncation rule, but it is guaranteed
///                                 to never exceed the original buffer size even if the implicit zero extension rule
///                                 was activated. In case of error this value is undefined.
///
/// @returns Negative on error, zero on success.
static inline int8_t uavcan_metatransport_can_ArbitrationID_0_1_deserialize_(
    uavcan_metatransport_can_ArbitrationID_0_1* const out_obj, const uint8_t* buffer, size_t* const inout_buffer_size_bytes)
{
    if ((out_obj == NULL) || (inout_buffer_size_bytes == NULL) || ((buffer == NULL) && (0 != *inout_buffer_size_bytes)))
    {
        return -NUNAVUT_ERROR_INVALID_ARGUMENT;
    }
    if (buffer == NULL)
    {
        buffer = (const uint8_t*)"";
    }
    const size_t capacity_bytes = *inout_buffer_size_bytes;
    const size_t capacity_bits = capacity_bytes * (size_t) 8U;
    size_t offset_bits = 0U;
    // Union tag field: truncated uint8
    if ((offset_bits + 8U) <= capacity_bits)
    {
        out_obj->_tag_ = buffer[offset_bits / 8U] & 255U;
    }
    else
    {
        out_obj->_tag_ = 0U;
    }
    offset_bits += 8U;
    if (0U == out_obj->_tag_)  // uavcan.metatransport.can.BaseArbitrationID.0.1 base
    {
        {
            size_t _size_bytes2_ = (size_t)(capacity_bytes - nunavutChooseMin((offset_bits / 8U), capacity_bytes));
            const int8_t _err3_ = uavcan_metatransport_can_BaseArbitrationID_0_1_deserialize_(
                &out_obj->base, &buffer[offset_bits / 8U], &_size_bytes2_);
            if (_err3_ < 0)
            {
                return _err3_;
            }
            offset_bits += _size_bytes2_ * 8U;  // Advance by the size of the nested serialized representation.
        }
    }
    else if (1U == out_obj->_tag_)  // uavcan.metatransport.can.ExtendedArbitrationID.0.1 extended
    {
        {
            size_t _size_bytes3_ = (size_t)(capacity_bytes - nunavutChooseMin((offset_bits / 8U), capacity_bytes));
            const int8_t _err4_ = uavcan_metatransport_can_ExtendedArbitrationID_0_1_deserialize_(
                &out_obj->extended, &buffer[offset_bits / 8U], &_size_bytes3_);
            if (_err4_ < 0)
            {
                return _err4_;
            }
            offset_bits += _size_bytes3_ * 8U;  // Advance by the size of the nested serialized representation.
        }
    }
    else
    {
        return -NUNAVUT_ERROR_REPRESENTATION_BAD_UNION_TAG;
    }
    offset_bits = (offset_bits + 7U) & ~(size_t) 7U;  // Align on 8 bits.
    *inout_buffer_size_bytes = (size_t) (nunavutChooseMin(offset_bits, capacity_bits) / 8U);
    return NUNAVUT_SUCCESS;
}

/// Initialize an instance to default values. Does nothing if @param out_obj is NULL.
/// This function intentionally leaves inactive elements uninitialized; for example, members of a variable-length
/// array beyond its length are left uninitialized; aliased union memory that is not used by the first union field
/// is left uninitialized, etc. If full zero-initialization is desired, just use memset(&obj, 0, sizeof(obj)).
static inline void uavcan_metatransport_can_ArbitrationID_0_1_initialize_(uavcan_metatransport_can_ArbitrationID_0_1* const out_obj)
{
    if (out_obj != NULL)
    {
        size_t size_bytes = 0;
        const uint8_t buf = 0;
        const int8_t err = uavcan_metatransport_can_ArbitrationID_0_1_deserialize_(out_obj, &buf, &size_bytes);

        (void) err;
    }
}
/// Mark option "base" active without initializing it. Does nothing if @param obj is NULL.
static inline void uavcan_metatransport_can_ArbitrationID_0_1_select_base_(uavcan_metatransport_can_ArbitrationID_0_1* const obj)
{
    if (obj != NULL)
    {
        obj->_tag_ = 0;
    }
}

/// Check if option "base" is active. Returns false if @param obj is NULL.
static inline bool uavcan_metatransport_can_ArbitrationID_0_1_is_base_(const uavcan_metatransport_can_ArbitrationID_0_1* const obj)
{
    return ((obj != NULL) && (obj->_tag_ == 0));
}

/// Mark option "extended" active without initializing it. Does nothing if @param obj is NULL.
static inline void uavcan_metatransport_can_ArbitrationID_0_1_select_extended_(uavcan_metatransport_can_ArbitrationID_0_1* const obj)
{
    if (obj != NULL)
    {
        obj->_tag_ = 1;
    }
}

/// Check if option "extended" is active. Returns false if @param obj is NULL.
static inline bool uavcan_metatransport_can_ArbitrationID_0_1_is_extended_(const uavcan_metatransport_can_ArbitrationID_0_1* const obj)
{
    return ((obj != NULL) && (obj->_tag_ == 1));
}

#ifdef __cplusplus
}
#endif
#endif // UAVCAN_METATRANSPORT_CAN_ARBITRATION_ID_0_1_INCLUDED_

