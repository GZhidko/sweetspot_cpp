#include "ring_buffer.hpp"

#include <sys/mman.h>

namespace af_packet_io {

RingView::RingView(void* area, size_t length, size_t frame_size)
    : area_(area), length_(length), frame_size_(frame_size) {
    if (!area_ || length_ == 0 || frame_size_ == 0) {
        area_ = nullptr;
        length_ = 0;
        frame_size_ = 0;
        return;
    }
    frame_count_ = length_ / frame_size_;
    block_count_ = frame_count_; // caller supplies block granularity from req
}

tpacket_block_desc* RingView::block_at(size_t index) const {
    if (!area_ || index >= block_count_) {
        return nullptr;
    }
    return reinterpret_cast<tpacket_block_desc*>(static_cast<char*>(area_) + index * frame_size_);
}

} // namespace af_packet_io

