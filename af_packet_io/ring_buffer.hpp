#pragma once

#include <cstddef>
#include <cstdint>
#include <linux/if_packet.h>

namespace af_packet_io {

class RingView {
  public:
    RingView() = default;
    RingView(void* area, size_t length, size_t block_size, size_t block_count, size_t frame_size);

    bool valid() const noexcept { return area_ != nullptr; }

    tpacket_block_desc* block_at(size_t index) const;
    size_t block_count() const noexcept { return block_count_; }
    size_t frame_count() const noexcept { return frame_count_; }
    size_t frame_size() const noexcept { return frame_size_; }
    size_t block_size() const noexcept { return block_size_; }

  private:
    void* area_ = nullptr;
    size_t length_ = 0;
    size_t frame_size_ = 0;
    size_t frame_count_ = 0;
    size_t block_count_ = 0;
    size_t block_size_ = 0;
};

} // namespace af_packet_io
