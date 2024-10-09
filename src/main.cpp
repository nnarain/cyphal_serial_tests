#include <Arduino.h>

#include <serard.h>
#include <o1heap.h>

#include <uavcan/node/Heartbeat_1_0.h>
#include <uavcan/primitive/scalar/Bit_1_0.h>

#define HEARTBEAT_PERIOD 1000

// https://github.com/107-systems/107-Arduino-Cyphal/blob/95886ffa9a45a71497a0434b7b62ae72840dc243/src/Node.hpp
template<size_t SIZE>
class alignas(O1HEAP_ALIGNMENT) Heap final : public std::array<uint8_t, SIZE> {};
static constexpr size_t HEAP_SIZE = 16384UL;

static Heap<HEAP_SIZE> ARENA;

static O1HeapInstance* heap{nullptr};

static void* serardAlloc(void*, size_t size)
{
  return o1heapAllocate(heap, size);
}

static void serardFree(void*, size_t, void* ptr)
{
  o1heapFree(heap, ptr);
}

static const SerardMemoryResource allocator = {
  .user_reference = nullptr,
  .deallocate = &serardFree,
  .allocate = &serardAlloc,
};

static const SerardNodeID NODE_ID = 5;
static Serard serard;
static SerardReassembler reassembler;

static constexpr SerardPortID BIT_PORT_ID = 1620U;
static SerardRxSubscription cmd_sub;

static uint32_t last_heartbeat = 0;

static bool serialEmitter(void* const, uint8_t size, const uint8_t* data)
{
  Serial.write(reinterpret_cast<const char*>(data), size);
  return true;
}

static void cmdCallback(const uavcan_primitive_scalar_Bit_1_0& msg)
{
  if (msg.value)
  {
    digitalWrite(LED_BUILTIN, HIGH);
  }
  else
  {
    digitalWrite(LED_BUILTIN, LOW);
  }
}

static void onReceive(const SerardRxTransfer* const transfer)
{
  const SerardTransferMetadata* const metadata = &transfer->metadata;

  uavcan_primitive_scalar_Bit_1_0 bit;
  size_t size = transfer->payload_size;
  uavcan_primitive_scalar_Bit_1_0_deserialize_(&bit, reinterpret_cast<const uint8_t*>(transfer->payload), &size);
  serardFree(nullptr, transfer->payload_extent, transfer->payload);

  cmdCallback(bit);
}

void setup() {
  // heap_base = new uint8_t[HEAP_SIZE];
  // Allocator setup for serard
  heap = o1heapInit(ARENA.data(), HEAP_SIZE);

  // Initialize serard
  serard = serardInit(allocator, allocator);
  reassembler = serardReassemblerInit();

  // Setup subscribers
  serardRxSubscribe(&serard, SerardTransferKindMessage, BIT_PORT_ID, uavcan_primitive_scalar_Bit_1_0_EXTENT_BYTES_, 10000, &cmd_sub);

  // Hardware setup
  Serial.begin(115200);

  pinMode(LED_BUILTIN, OUTPUT);
}

void loop() {
  const auto now = millis();
  if (now - last_heartbeat > HEARTBEAT_PERIOD)
  {
    const uavcan_node_Health_1_0 health = {
        .value = uavcan_node_Health_1_0_NOMINAL,
    };
    const uavcan_node_Mode_1_0 mode = {
        .value = uavcan_node_Mode_1_0_OPERATIONAL,
    };
    const uavcan_node_Heartbeat_1_0 heartbeat = {
        .uptime = now,
        .health = health,
        .mode = mode,
        .vendor_specific_status_code = 0,
    };

    uint8_t buf[uavcan_node_Heartbeat_1_0_SERIALIZATION_BUFFER_SIZE_BYTES_];
    size_t buf_size = uavcan_node_Heartbeat_1_0_SERIALIZATION_BUFFER_SIZE_BYTES_;

    uavcan_node_Heartbeat_1_0_serialize_(&heartbeat, buf, &buf_size);
    const SerardTransferMetadata metadata = {
      .priority = SerardPriorityNominal,
      .transfer_kind = SerardTransferKindMessage,
      .port_id = uavcan_node_Heartbeat_1_0_FIXED_PORT_ID_,
      .remote_node_id = NODE_ID,
    };
    serardTxPush(&serard, &metadata, buf_size, buf, nullptr, &serialEmitter);
  }

  // Handle incoming data
  uint8_t buf[256];
  SerardRxTransfer transfer;
  SerardRxSubscription* sub{nullptr};

  size_t payload_size = Serial.readBytes(reinterpret_cast<char*>(buf), 256);


  if (serardRxAccept(&serard, &reassembler, micros(), &payload_size, buf, &transfer, &sub)) {
    onReceive(&transfer);
  }
}
