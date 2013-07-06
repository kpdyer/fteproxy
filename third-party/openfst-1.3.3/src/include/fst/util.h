// util.h

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
// Author: riley@google.com (Michael Riley)
//
// \file
// FST utility inline definitions.

#ifndef FST_LIB_UTIL_H__
#define FST_LIB_UTIL_H__

#include <tr1/unordered_map>
using std::tr1::unordered_map;
using std::tr1::unordered_multimap;
#include <tr1/unordered_set>
using std::tr1::unordered_set;
using std::tr1::unordered_multiset;
#include <list>
#include <map>
#include <set>
#include <sstream>
#include <string>
#include <vector>
using std::vector;


#include <fst/compat.h>
#include <fst/types.h>

#include <iostream>
#include <fstream>
#include <sstream>

//
// UTILITY FOR ERROR HANDLING
//

DECLARE_bool(fst_error_fatal);

#define FSTERROR() (FLAGS_fst_error_fatal ? LOG(FATAL) : LOG(ERROR))

namespace fst {

//
// UTILITIES FOR TYPE I/O
//

// Read some types from an input stream.

// Generic case.
template <typename T>
inline istream &ReadType(istream &strm, T *t) {
  return t->Read(strm);
}

// Fixed size, contiguous memory read.
#define READ_POD_TYPE(T)                                    \
inline istream &ReadType(istream &strm, T *t) {             \
  return strm.read(reinterpret_cast<char *>(t), sizeof(T)); \
}

READ_POD_TYPE(bool);
READ_POD_TYPE(char);
READ_POD_TYPE(signed char);
READ_POD_TYPE(unsigned char);
READ_POD_TYPE(short);
READ_POD_TYPE(unsigned short);
READ_POD_TYPE(int);
READ_POD_TYPE(unsigned int);
READ_POD_TYPE(long);
READ_POD_TYPE(unsigned long);
READ_POD_TYPE(long long);
READ_POD_TYPE(unsigned long long);
READ_POD_TYPE(float);
READ_POD_TYPE(double);

// String case.
inline istream &ReadType(istream &strm, string *s) {
  s->clear();
  int32 ns = 0;
  strm.read(reinterpret_cast<char *>(&ns), sizeof(ns));
  for (int i = 0; i < ns; ++i) {
    char c;
    strm.read(&c, 1);
    *s += c;
  }
  return strm;
}

// Pair case.
template <typename S, typename T>
inline istream &ReadType(istream &strm, pair<S, T> *p) {
  ReadType(strm, &p->first);
  ReadType(strm, &p->second);
  return strm;
}

template <typename S, typename T>
inline istream &ReadType(istream &strm, pair<const S, T> *p) {
  ReadType(strm, const_cast<S *>(&p->first));
  ReadType(strm, &p->second);
  return strm;
}

// General case - no-op.
template <typename C>
void StlReserve(C *c, int64 n) {}

// Specialization for vectors.
template <typename S, typename T>
void StlReserve(vector<S, T> *c, int64 n) {
  c->reserve(n);
}

// STL sequence container.
#define READ_STL_SEQ_TYPE(C)                             \
template <typename S, typename T>                        \
inline istream &ReadType(istream &strm, C<S, T> *c) {    \
  c->clear();                                            \
  int64 n = 0;                                           \
  strm.read(reinterpret_cast<char *>(&n), sizeof(n));    \
  StlReserve(c, n);                                      \
  for (ssize_t i = 0; i < n; ++i) {                      \
    typename C<S, T>::value_type value;                  \
    ReadType(strm, &value);                              \
    c->insert(c->end(), value);                          \
  }                                                      \
  return strm;                                           \
}

READ_STL_SEQ_TYPE(vector);
READ_STL_SEQ_TYPE(list);

// STL associative container.
#define READ_STL_ASSOC_TYPE(C)                           \
template <typename S, typename T, typename U>            \
inline istream &ReadType(istream &strm, C<S, T, U> *c) { \
  c->clear();                                            \
  int64 n = 0;                                           \
  strm.read(reinterpret_cast<char *>(&n), sizeof(n));    \
  for (ssize_t i = 0; i < n; ++i) {                      \
    typename C<S, T, U>::value_type value;               \
    ReadType(strm, &value);                              \
    c->insert(value);                                    \
  }                                                      \
  return strm;                                           \
}

READ_STL_ASSOC_TYPE(set);
READ_STL_ASSOC_TYPE(unordered_set);
READ_STL_ASSOC_TYPE(map);
READ_STL_ASSOC_TYPE(unordered_map);

// Write some types to an output stream.

// Generic case.
template <typename T>
inline ostream &WriteType(ostream &strm, const T t) {
  t.Write(strm);
  return strm;
}

// Fixed size, contiguous memory write.
#define WRITE_POD_TYPE(T)                                           \
inline ostream &WriteType(ostream &strm, const T t) {               \
  return strm.write(reinterpret_cast<const char *>(&t), sizeof(T)); \
}

WRITE_POD_TYPE(bool);
WRITE_POD_TYPE(char);
WRITE_POD_TYPE(signed char);
WRITE_POD_TYPE(unsigned char);
WRITE_POD_TYPE(short);
WRITE_POD_TYPE(unsigned short);
WRITE_POD_TYPE(int);
WRITE_POD_TYPE(unsigned int);
WRITE_POD_TYPE(long);
WRITE_POD_TYPE(unsigned long);
WRITE_POD_TYPE(long long);
WRITE_POD_TYPE(unsigned long long);
WRITE_POD_TYPE(float);
WRITE_POD_TYPE(double);

// String case.
inline ostream &WriteType(ostream &strm, const string &s) {
  int32 ns = s.size();
  strm.write(reinterpret_cast<const char *>(&ns), sizeof(ns));
  return strm.write(s.data(), ns);
}

// Pair case.
template <typename S, typename T>
inline ostream &WriteType(ostream &strm, const pair<S, T> &p) {
  WriteType(strm, p.first);
  WriteType(strm, p.second);
  return strm;
}

// STL sequence container.
#define WRITE_STL_SEQ_TYPE(C)                                                \
template <typename S, typename T>                                            \
inline ostream &WriteType(ostream &strm, const C<S, T> &c) {                 \
  int64 n = c.size();                                                        \
  strm.write(reinterpret_cast<char *>(&n), sizeof(n));                       \
  for (typename C<S, T>::const_iterator it = c.begin();                      \
       it != c.end(); ++it)                                                  \
     WriteType(strm, *it);                                                   \
  return strm;                                                               \
}

WRITE_STL_SEQ_TYPE(vector);
WRITE_STL_SEQ_TYPE(list);

// STL associative container.
#define WRITE_STL_ASSOC_TYPE(C)                                              \
template <typename S, typename T, typename U>                                \
inline ostream &WriteType(ostream &strm, const C<S, T, U> &c) {              \
  int64 n = c.size();                                                        \
  strm.write(reinterpret_cast<char *>(&n), sizeof(n));                       \
  for (typename C<S, T, U>::const_iterator it = c.begin();                   \
       it != c.end(); ++it)                                                  \
     WriteType(strm, *it);                                                   \
  return strm;                                                               \
}

WRITE_STL_ASSOC_TYPE(set);
WRITE_STL_ASSOC_TYPE(unordered_set);
WRITE_STL_ASSOC_TYPE(map);
WRITE_STL_ASSOC_TYPE(unordered_map);

// Utilities for converting between int64 or Weight and string.

int64 StrToInt64(const string &s, const string &src, size_t nline,
                 bool allow_negative, bool *error = 0);

template <typename Weight>
Weight StrToWeight(const string &s, const string &src, size_t nline) {
  Weight w;
  istringstream strm(s);
  strm >> w;
  if (!strm) {
    FSTERROR() << "StrToWeight: Bad weight = \"" << s
               << "\", source = " << src << ", line = " << nline;
    return Weight::NoWeight();
  }
  return w;
}

void Int64ToStr(int64 n, string *s);

template <typename Weight>
void WeightToStr(Weight w, string *s) {
  ostringstream strm;
  strm.precision(9);
  strm << w;
  s->append(strm.str().data(), strm.str().size());
}

// Utilities for reading/writing label pairs

// Returns true on success
template <typename Label>
bool ReadLabelPairs(const string& filename,
                    vector<pair<Label, Label> >* pairs,
                    bool allow_negative = false) {
  ifstream strm(filename.c_str());

  if (!strm) {
    LOG(ERROR) << "ReadLabelPairs: Can't open file: " << filename;
    return false;
  }

  const int kLineLen = 8096;
  char line[kLineLen];
  size_t nline = 0;

  pairs->clear();
  while (strm.getline(line, kLineLen)) {
    ++nline;
    vector<char *> col;
    SplitToVector(line, "\n\t ", &col, true);
    if (col.size() == 0 || col[0][0] == '\0')  // empty line
      continue;
    if (col.size() != 2) {
      LOG(ERROR) << "ReadLabelPairs: Bad number of columns, "
                 << "file = " << filename << ", line = " << nline;
      return false;
    }

    bool err;
    Label frmlabel = StrToInt64(col[0], filename, nline, allow_negative, &err);
    if (err) return false;
    Label tolabel = StrToInt64(col[1], filename, nline, allow_negative, &err);
    if (err) return false;
    pairs->push_back(make_pair(frmlabel, tolabel));
  }
  return true;
}

// Returns true on success
template <typename Label>
bool WriteLabelPairs(const string& filename,
                     const vector<pair<Label, Label> >& pairs) {
  ostream *strm = &cout;
  if (!filename.empty()) {
    strm = new ofstream(filename.c_str());
    if (!*strm) {
      LOG(ERROR) << "WriteLabelPairs: Can't open file: " << filename;
      return false;
    }
  }

  for (ssize_t n = 0; n < pairs.size(); ++n)
    *strm << pairs[n].first << "\t" << pairs[n].second << "\n";

  if (!*strm) {
    LOG(ERROR) << "WriteLabelPairs: Write failed: "
               << (filename.empty() ? "standard output" : filename);
    return false;
  }
  if (strm != &cout)
    delete strm;
  return true;
}

// Utilities for converting a type name to a legal C symbol.

void ConvertToLegalCSymbol(string *s);


//
// UTILITIES FOR STREAM I/O
//

bool AlignInput(istream &strm);
bool AlignOutput(ostream &strm);

//
// UTILITIES FOR PROTOCOL BUFFER I/O
//


// An associative container for which testing membership is
// faster than an STL set if members are restricted to an interval
// that excludes most non-members. A 'Key' must have ==, !=, and < defined.
// Element 'NoKey' should be a key that marks an uninitialized key and
// is otherwise unused. 'Find()' returns an STL const_iterator to the match
// found, otherwise it equals 'End()'.
template <class Key, Key NoKey>
class CompactSet {
public:
  typedef typename set<Key>::const_iterator const_iterator;

  CompactSet()
    : min_key_(NoKey),
      max_key_(NoKey) { }

  CompactSet(const CompactSet<Key, NoKey> &compact_set)
    : set_(compact_set.set_),
      min_key_(compact_set.min_key_),
      max_key_(compact_set.max_key_) { }

  void Insert(Key key) {
    set_.insert(key);
    if (min_key_ == NoKey || key < min_key_)
      min_key_ = key;
    if (max_key_ == NoKey || max_key_ < key)
        max_key_ = key;
  }

  void Erase(Key key) {
    set_.erase(key);
    if (set_.empty()) {
        min_key_ = max_key_ = NoKey;
    } else if (key == min_key_) {
      ++min_key_;
    } else if (key == max_key_) {
      --max_key_;
    }
  }

  void Clear() {
    set_.clear();
    min_key_ = max_key_ = NoKey;
  }

  const_iterator Find(Key key) const {
    if (min_key_ == NoKey ||
        key < min_key_ || max_key_ < key)
      return set_.end();
    else
      return set_.find(key);
  }

  bool Member(Key key) const {
    if (min_key_ == NoKey || key < min_key_ || max_key_ < key) {
      return false;   // out of range
    } else if (min_key_ != NoKey && max_key_ + 1 == min_key_ + set_.size()) {
      return true;    // dense range
    } else {
      return set_.find(key) != set_.end();
    }
  }

  const_iterator Begin() const { return set_.begin(); }

  const_iterator End() const { return set_.end(); }

  // All stored keys are greater than or equal to this value.
  Key LowerBound() const { return min_key_; }

  // All stored keys are less than or equal to this value.
  Key UpperBound() const { return max_key_; }

private:
  set<Key> set_;
  Key min_key_;
  Key max_key_;

  void operator=(const CompactSet<Key, NoKey> &);  //disallow
};

}  // namespace fst

#endif  // FST_LIB_UTIL_H__
