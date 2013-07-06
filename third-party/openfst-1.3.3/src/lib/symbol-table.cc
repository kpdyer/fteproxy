
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
// All Rights Reserved.
//
// Author : Johan Schalkwyk
//
// \file
// Classes to provide symbol-to-integer and integer-to-symbol mappings.

#include <fst/symbol-table.h>

#include <fst/util.h>

DEFINE_bool(fst_compat_symbols, true,
            "Require symbol tables to match when appropriate");
DEFINE_string(fst_field_separator, "\t ",
              "Set of characters used as a separator between printed fields");

namespace fst {

// Maximum line length in textual symbols file.
const int kLineLen = 8096;

// Identifies stream data as a symbol table (and its endianity)
static const int32 kSymbolTableMagicNumber = 2125658996;

SymbolTableTextOptions::SymbolTableTextOptions()
    : allow_negative(false), fst_field_separator(FLAGS_fst_field_separator) { }

SymbolTableImpl* SymbolTableImpl::ReadText(istream &strm,
                                           const string &filename,
                                           const SymbolTableTextOptions &opts) {
  SymbolTableImpl* impl = new SymbolTableImpl(filename);

  int64 nline = 0;
  char line[kLineLen];
  while (strm.getline(line, kLineLen)) {
    ++nline;
    vector<char *> col;
    string separator = opts.fst_field_separator + "\n";
    SplitToVector(line, separator.c_str(), &col, true);
    if (col.size() == 0)  // empty line
      continue;
    if (col.size() != 2) {
      LOG(ERROR) << "SymbolTable::ReadText: Bad number of columns ("
                 << col.size() << "), "
                 << "file = " << filename << ", line = " << nline
                 << ":<" << line << ">";
      delete impl;
      return 0;
    }
    const char *symbol = col[0];
    const char *value = col[1];
    char *p;
    int64 key = strtoll(value, &p, 10);
    if (p < value + strlen(value) ||
        (!opts.allow_negative && key < 0) || key == -1) {
      LOG(ERROR) << "SymbolTable::ReadText: Bad non-negative integer \""
                 << value << "\", "
                 << "file = " << filename << ", line = " << nline;
      delete impl;
      return 0;
    }
    impl->AddSymbol(symbol, key);
  }

  return impl;
}

void SymbolTableImpl::MaybeRecomputeCheckSum() const {
  {
    ReaderMutexLock check_sum_lock(&check_sum_mutex_);
    if (check_sum_finalized_)
      return;
  }

  // We'll aquire an exclusive lock to recompute the checksums.
  MutexLock check_sum_lock(&check_sum_mutex_);
  if (check_sum_finalized_)  // Another thread (coming in around the same time
    return;                  // might have done it already).  So we recheck.

  // Calculate the original label-agnostic check sum.
  CheckSummer check_sum;
  for (int64 i = 0; i < symbols_.size(); ++i)
    check_sum.Update(symbols_[i], strlen(symbols_[i]) + 1);
  check_sum_string_ = check_sum.Digest();

  // Calculate the safer, label-dependent check sum.
  CheckSummer labeled_check_sum;
  for (int64 key = 0; key < dense_key_limit_; ++key) {
    ostringstream line;
    line << symbols_[key] << '\t' << key;
    labeled_check_sum.Update(line.str().data(), line.str().size());
  }
  for (map<int64, const char*>::const_iterator it =
       key_map_.begin();
       it != key_map_.end();
       ++it) {
    if (it->first >= dense_key_limit_) {
      ostringstream line;
      line << it->second << '\t' << it->first;
      labeled_check_sum.Update(line.str().data(), line.str().size());
    }
  }
  labeled_check_sum_string_ = labeled_check_sum.Digest();

  check_sum_finalized_ = true;
}

int64 SymbolTableImpl::AddSymbol(const string& symbol, int64 key) {
  map<const char *, int64, StrCmp>::const_iterator it =
      symbol_map_.find(symbol.c_str());
  if (it == symbol_map_.end()) {  // only add if not in table
    check_sum_finalized_ = false;

    char *csymbol = new char[symbol.size() + 1];
    strcpy(csymbol, symbol.c_str());
    symbols_.push_back(csymbol);
    key_map_[key] = csymbol;
    symbol_map_[csymbol] = key;

    if (key >= available_key_) {
      available_key_ = key + 1;
    }
  } else {
    // Log if symbol already in table with different key
    if (it->second != key) {
      VLOG(1) << "SymbolTable::AddSymbol: symbol = " << symbol
              << " already in symbol_map_ with key = "
              << it->second
              << " but supplied new key = " << key
              << " (ignoring new key)";
    }
  }
  return key;
}

static bool IsInRange(const vector<pair<int64, int64> >& ranges,
                      int64 key) {
  if (ranges.size() == 0) return true;
  for (size_t i = 0; i < ranges.size(); ++i) {
    if (key >= ranges[i].first && key <= ranges[i].second)
      return true;
  }
  return false;
}

SymbolTableImpl* SymbolTableImpl::Read(istream &strm,
                                       const SymbolTableReadOptions& opts) {
  int32 magic_number = 0;
  ReadType(strm, &magic_number);
  if (!strm) {
    LOG(ERROR) << "SymbolTable::Read: read failed";
    return 0;
  }
  string name;
  ReadType(strm, &name);
  SymbolTableImpl* impl = new SymbolTableImpl(name);
  ReadType(strm, &impl->available_key_);
  int64 size;
  ReadType(strm, &size);
  if (!strm) {
    LOG(ERROR) << "SymbolTable::Read: read failed";
    delete impl;
    return 0;
  }

  string symbol;
  int64 key;
  impl->check_sum_finalized_ = false;
  for (size_t i = 0; i < size; ++i) {
    ReadType(strm, &symbol);
    ReadType(strm, &key);
    if (!strm) {
      LOG(ERROR) << "SymbolTable::Read: read failed";
      delete impl;
      return 0;
    }

    char *csymbol = new char[symbol.size() + 1];
    strcpy(csymbol, symbol.c_str());
    impl->symbols_.push_back(csymbol);
    if (key == impl->dense_key_limit_ &&
        key == impl->symbols_.size() - 1)
      impl->dense_key_limit_ = impl->symbols_.size();
    else
      impl->key_map_[key] = csymbol;

    if (IsInRange(opts.string_hash_ranges, key)) {
      impl->symbol_map_[csymbol] = key;
    }
  }
  return impl;
}

bool SymbolTableImpl::Write(ostream &strm) const {
  WriteType(strm, kSymbolTableMagicNumber);
  WriteType(strm, name_);
  WriteType(strm, available_key_);
  int64 size = symbols_.size();
  WriteType(strm, size);
  // first write out dense keys
  int64 i = 0;
  for (; i < dense_key_limit_; ++i) {
    WriteType(strm, string(symbols_[i]));
    WriteType(strm, i);
  }
  // next write out the remaining non densely packed keys
  for (map<const char *, int64, StrCmp>::const_iterator it =
           symbol_map_.begin(); it != symbol_map_.end(); ++it) {
    if ((it->second >= 0) && (it->second < dense_key_limit_))
      continue;
    WriteType(strm, string(it->first));
    WriteType(strm, it->second);
    ++i;
  }
  if (i != size) {
    LOG(ERROR) << "SymbolTable::Write:  write failed";
    return false;
  }
  strm.flush();
  if (!strm) {
    LOG(ERROR) << "SymbolTable::Write: write failed";
    return false;
  }
  return true;
}

const int64 SymbolTable::kNoSymbol;


void SymbolTable::AddTable(const SymbolTable& table) {
  for (SymbolTableIterator iter(table); !iter.Done(); iter.Next())
    impl_->AddSymbol(iter.Symbol());
}

bool SymbolTable::WriteText(ostream &strm,
                            const SymbolTableTextOptions &opts) const {
  if (opts.fst_field_separator.empty()) {
    LOG(ERROR) << "Missing required field separator";
    return false;
  }
  bool once_only = false;
  for (SymbolTableIterator iter(*this); !iter.Done(); iter.Next()) {
    ostringstream line;
    if (iter.Value() < 0 && !opts.allow_negative && !once_only) {
      LOG(WARNING) << "Negative symbol table entry when not allowed";
      once_only = true;
    }
    line << iter.Symbol() << opts.fst_field_separator[0] << iter.Value()
         << '\n';
    strm.write(line.str().data(), line.str().length());
  }
  return true;
}
}  // namespace fst
