#ifndef SAMPLE_PTR_H
#define SAMPLE_PTR_H

#include <cstdint>
#include <cstring>
#include <iostream>
#include <condition_variable>
#include <mutex>
#include <thread>

namespace ara {
    namespace core {

        template <typename T>
        class SamplePtr {
        public:
            SamplePtr() : ptr_(nullptr) {}

            explicit SamplePtr(T* ptr) : ptr_(ptr) {}

            ~SamplePtr() {
                delete[] ptr_;
            }

            // Copy constructor
            SamplePtr(const SamplePtr& other) : ptr_(new T[1]) {
                // Copy the data
                if (other.ptr_ != nullptr) {
                    std::memcpy(ptr_, other.ptr_, sizeof(T));
                }
            }

            // Disable copy assignment
            SamplePtr& operator=(const SamplePtr&) = delete;

            // Enable move semantics
            SamplePtr(SamplePtr&& other) noexcept : ptr_(other.ptr_) {
                other.ptr_ = nullptr;
            }

            SamplePtr& operator=(SamplePtr&& other) noexcept {
                if (this != &other) {
                    delete[] ptr_;
                    ptr_ = other.ptr_;
                    other.ptr_ = nullptr;
                }
                return *this;
            }

            T* get() const {
                return ptr_;
            }

            T* release() {
                T* releasedPtr = ptr_;
                ptr_ = nullptr;
                return releasedPtr;
            }

            // Additional methods for thread synchronization
            void setData(T* newData) {
                std::unique_lock<std::mutex> lock(mutex_);
                ptr_ = newData;
                conditionVariable_.notify_all();
            }
            void notify(){
                conditionVariable_.notify_all();
            }
            void waitForData() {
                std::unique_lock<std::mutex> lock(mutex_);
                conditionVariable_.wait(lock, [this] { return ptr_ != nullptr; });
            }

        private:
            T* ptr_;
            std::mutex mutex_;
            std::condition_variable conditionVariable_;
        };

    } // namespace core
} // namespace ara

#endif