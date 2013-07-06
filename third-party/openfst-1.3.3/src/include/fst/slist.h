// slist.h
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// Author: riley@google.com (Michael Riley)
//
// \file
// Includes slist definition or defines in terms of STL list as a fallback.

#ifndef FST_LIB_SLIST_H__
#define FST_LIB_SLIST_H__

#include <fst/config.h>

#ifdef HAVE___GNU_CXX__SLIST_INT_

#include <ext/slist>

namespace fst {

using __gnu_cxx::slist;

}

#else

#include <list>

namespace fst {

using std::list;

template <typename T> class slist : public list<T> {
 public:
  typedef typename list<T>::iterator iterator;
  typedef typename list<T>::const_iterator const_iterator;

  using list<T>::erase;

  iterator erase_after(iterator pos) {
    iterator npos = pos;
    erase(++npos);
    return pos;
  }
};

}  // namespace fst

#endif  // HAVE___GNU_CXX__SLIST_INT_

#endif  // FST_LIB_SLIST_H__
