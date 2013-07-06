
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// Copyright 2005-2010 Google, Inc.
// Author: sorenj@google.com (Jeffrey Sorensen)

#include <fst/mapped-file.h>

#include <errno.h>
#include <fcntl.h>

namespace fst {

// Alignment required for mapping structures (in bytes.)  Regions of memory
// that are not aligned upon a 128 bit boundary will be read from the file
// instead.  This is consistent with the alignment boundary set in the
// const and compact fst code.
const int MappedFile::kArchAlignment = 16;

MappedFile::MappedFile(const MemoryRegion &region) : region_(region) { }

MappedFile::~MappedFile() {
  if (region_.size != 0) {
    if (region_.mmap != NULL) {
      VLOG(1) << "munmap'ed " << region_.size << " bytes at " << region_.mmap;
      if (munmap(region_.mmap, region_.size) != 0) {
        LOG(ERROR) << "failed to unmap region: "<< strerror(errno);
      }
    } else {
      operator delete(region_.data);
    }
  }
}

MappedFile* MappedFile::Allocate(size_t size) {
  MemoryRegion region;
  region.data = size == 0 ? NULL : operator new(size);
  region.mmap = NULL;
  region.size = size;
  return new MappedFile(region);
}

MappedFile* MappedFile::Borrow(void *data) {
  MemoryRegion region;
  region.data = data;
  region.mmap = data;
  region.size = 0;
  return new MappedFile(region);
}

MappedFile* MappedFile::Map(istream* s, const FstReadOptions &opts,
                            size_t size) {
  size_t pos = s->tellg();
  if (opts.mode == FstReadOptions::MAP && pos >= 0 &&
      pos % kArchAlignment == 0) {
    int fd = open(opts.source.c_str(), O_RDONLY);
    if (fd != -1) {
      int pagesize = getpagesize();
      off_t offset = pos % pagesize;
      off_t upsize = size + offset;
      void *map = mmap(0, upsize, PROT_READ, MAP_SHARED, fd, pos - offset);
      char *data = reinterpret_cast<char*>(map);
      if (close(fd) == 0 && map != MAP_FAILED) {
        MemoryRegion region;
        region.mmap = map;
        region.size = upsize;
        region.data = reinterpret_cast<void*>(data + offset);
        MappedFile *mmf = new MappedFile(region);
        s->seekg(pos + size, ios::beg);
        if (s) {
          VLOG(1) << "mmap'ed region of " << size << " at offset " << pos
                  << " from " << opts.source.c_str() << " to addr " << map;
          return mmf;
        }
        delete mmf;
      } else {
        LOG(INFO) << "Mapping of file failed: " << strerror(errno);
      }
    }
  }
  // If all else fails resort to reading from file into allocated buffer.
  if (opts.mode != FstReadOptions::READ) {
    LOG(WARNING) << "File mapping at offset " << pos << " of file "
                 << opts.source << " could not be honored, reading instead.";
  }
  MappedFile* mf = Allocate(size);
  if (!s->read(reinterpret_cast<char*>(mf->mutable_data()), size)) {
    delete mf;
    return NULL;
  }
  return mf;
}

}  // namespace fst
