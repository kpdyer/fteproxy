
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

#ifndef FST_LIB_SYMBOL_TABLE_H__
#define FST_LIB_SYMBOL_TABLE_H__

#include <cstring>
#include <string>
#include <utility>
using std::pair; using std::make_pair;
#include <vector>
using std::vector;


#include <fst/compat.h>
#include <iostream>
#include <fstream>
#include <sstream>


#include <map>

DECLARE_bool(fst_compat_symbols);

namespace fst {

// WARNING: Reading via symbol table read options should
//          not be used. This is a temporary work around for
//          reading symbol ranges of previously stored symbol sets.
struct SymbolTableReadOptions {
  SymbolTableReadOptions() { }

  SymbolTableReadOptions(vector<pair<int64, int64> > string_hash_ranges_,
                         const string& source_)
      : string_hash_ranges(string_hash_ranges_),
        source(source_) { }

  vector<pair<int64, int64> > string_hash_ranges;
  string source;
};

struct SymbolTableTextOptions {
  SymbolTableTextOptions();

  bool allow_negative;
  string fst_field_separator;
};

class SymbolTableImpl {
 public:
  SymbolTableImpl(const string &name)
      : name_(name),
        available_key_(0),
        dense_key_limit_(0),
        check_sum_finalized_(false) {}

  explicit SymbolTableImpl(const SymbolTableImpl& impl)
      : name_(impl.name_),
        available_key_(0),
        dense_key_limit_(0),
        check_sum_finalized_(false) {
    for (size_t i = 0; i < impl.symbols_.size(); ++i) {
      AddSymbol(impl.symbols_[i], impl.Find(impl.symbols_[i]));
    }
  }

  ~SymbolTableImpl() {
    for (size_t i = 0; i < symbols_.size(); ++i)
      delete[] symbols_[i];
  }

  // TODO(johans): Add flag to specify whether the symbol
  //               should be indexed as string or int or both.
  int64 AddSymbol(const string& symbol, int64 key);

  int64 AddSymbol(const string& symbol) {
    int64 key = Find(symbol);
    return (key == -1) ? AddSymbol(symbol, available_key_++) : key;
  }

  static SymbolTableImpl* ReadText(
      istream &strm, const string &name,
      const SymbolTableTextOptions &opts = SymbolTableTextOptions());

  static SymbolTableImpl* Read(istream &strm,
                               const SymbolTableReadOptions& opts);

  bool Write(ostream &strm) const;

  //
  // Return the string associated with the key. If the key is out of
  // range (<0, >max), return an empty string.
  string Find(int64 key) const {
    if (key >=0 && key < dense_key_limit_)
      return string(symbols_[key]);

    map<int64, const char*>::const_iterator it =
        key_map_.find(key);
    if (it == key_map_.end()) {
      return "";
    }
    return string(it->second);
  }

  //
  // Return the key associated with the symbol. If the symbol
  // does not exists, return SymbolTable::kNoSymbol.
  int64 Find(const string& symbol) const {
    return Find(symbol.c_str());
  }

  //
  // Return the key associated with the symbol. If the symbol
  // does not exists, return SymbolTable::kNoSymbol.
  int64 Find(const char* symbol) const {
    map<const char *, int64, StrCmp>::const_iterator it =
        symbol_map_.find(symbol);
    if (it == symbol_map_.end()) {
      return -1;
    }
    return it->second;
  }

  int64 GetNthKey(ssize_t pos) const {
    if ((pos < 0) || (pos >= symbols_.size())) return -1;
    else return Find(symbols_[pos]);
  }

  const string& Name() const { return name_; }

  int IncrRefCount() const {
    return ref_count_.Incr();
  }
  int DecrRefCount() const {
    return ref_count_.Decr();
  }
  int RefCount() const {
    return ref_count_.count();
  }

  string CheckSum() const {
    MaybeRecomputeCheckSum();
    return check_sum_string_;
  }

  string LabeledCheckSum() const {
    MaybeRecomputeCheckSum();
    return labeled_check_sum_string_;
  }

  int64 AvailableKey() const {
    return available_key_;
  }

  size_t NumSymbols() const {
    return symbols_.size();
  }

 private:
  // Recomputes the checksums (both of them) if we've had changes since the last
  // computation (i.e., if check_sum_finalized_ is false).
  // Takes ~2.5 microseconds (dbg) or ~230 nanoseconds (opt) on a 2.67GHz Xeon
  // if the checksum is up-to-date (requiring no recomputation).
  void MaybeRecomputeCheckSum() const;

  struct StrCmp {
    bool operator()(const char *s1, const char *s2) const {
      return strcmp(s1, s2) < 0;
    }
  };

  string name_;
  int64 available_key_;
  int64 dense_key_limit_;
  vector<const char *> symbols_;
  map<int64, const char*> key_map_;
  map<const char *, int64, StrCmp> symbol_map_;

  mutable RefCounter ref_count_;
  mutable bool check_sum_finalized_;
  mutable string check_sum_string_;
  mutable string labeled_check_sum_string_;
  mutable Mutex check_sum_mutex_;
};

//
// \class SymbolTable
// \brief Symbol (string) to int and reverse mapping
//
// The SymbolTable implements the mappings of labels to strings and reverse.
// SymbolTables are used to describe the alphabet of the input and output
// labels for arcs in a Finite State Transducer.
//
// SymbolTables are reference counted and can therefore be shared across
// multiple machines. For example a language model grammar G, with a
// SymbolTable for the words in the language model can share this symbol
// table with the lexical representation L o G.
//
class SymbolTable {
 public:
  static const int64 kNoSymbol = -1;

  // Construct symbol table with an unspecified name.
  SymbolTable() : impl_(new SymbolTableImpl("<unspecified>")) {}

  // Construct symbol table with a unique name.
  SymbolTable(const string& name) : impl_(new SymbolTableImpl(name)) {}

  // Create a reference counted copy.
  SymbolTable(const SymbolTable& table) : impl_(table.impl_) {
    impl_->IncrRefCount();
  }

  // Derefence implentation object. When reference count hits 0, delete
  // implementation.
  virtual ~SymbolTable() {
    if (!impl_->DecrRefCount()) delete impl_;
  }

  // Copys the implemenation from one symbol table to another.
  void operator=(const SymbolTable &st) {
    if (impl_ != st.impl_) {
      st.impl_->IncrRefCount();
      if (!impl_->DecrRefCount()) delete impl_;
      impl_ = st.impl_;
    }
  }

  // Read an ascii representation of the symbol table from an istream. Pass a
  // name to give the resulting SymbolTable.
  static SymbolTable* ReadText(
      istream &strm, const string& name,
      const SymbolTableTextOptions &opts = SymbolTableTextOptions()) {
    SymbolTableImpl* impl = SymbolTableImpl::ReadText(strm, name, opts);
    if (!impl)
      return 0;
    else
      return new SymbolTable(impl);
  }

  // read an ascii representation of the symbol table
  static SymbolTable* ReadText(const string& filename,
      const SymbolTableTextOptions &opts = SymbolTableTextOptions()) {
    ifstream strm(filename.c_str(), ifstream::in);
    if (!strm) {
      LOG(ERROR) << "SymbolTable::ReadText: Can't open file " << filename;
      return 0;
    }
    return ReadText(strm, filename, opts);
  }


  // WARNING: Reading via symbol table read options should
  //          not be used. This is a temporary work around.
  static SymbolTable* Read(istream &strm,
                           const SymbolTableReadOptions& opts) {
    SymbolTableImpl* impl = SymbolTableImpl::Read(strm, opts);
    if (!impl)
      return 0;
    else
      return new SymbolTable(impl);
  }

  // read a binary dump of the symbol table from a stream
  static SymbolTable* Read(istream &strm, const string& source) {
    SymbolTableReadOptions opts;
    opts.source = source;
    return Read(strm, opts);
  }

  // read a binary dump of the symbol table
  static SymbolTable* Read(const string& filename) {
    ifstream strm(filename.c_str(), ifstream::in | ifstream::binary);
    if (!strm) {
      LOG(ERROR) << "SymbolTable::Read: Can't open file " << filename;
      return 0;
    }
    return Read(strm, filename);
  }

  //--------------------------------------------------------
  // Derivable Interface (final)
  //--------------------------------------------------------
  // create a reference counted copy
  virtual SymbolTable* Copy() const {
    return new SymbolTable(*this);
  }

  // Add a symbol with given key to table. A symbol table also
  // keeps track of the last available key (highest key value in
  // the symbol table).
  virtual int64 AddSymbol(const string& symbol, int64 key) {
    MutateCheck();
    return impl_->AddSymbol(symbol, key);
  }

  // Add a symbol to the table. The associated value key is automatically
  // assigned by the symbol table.
  virtual int64 AddSymbol(const string& symbol) {
    MutateCheck();
    return impl_->AddSymbol(symbol);
  }

  // Add another symbol table to this table. All key values will be offset
  // by the current available key (highest key value in the symbol table).
  // Note string symbols with the same key value with still have the same
  // key value after the symbol table has been merged, but a different
  // value. Adding symbol tables do not result in changes in the base table.
  virtual void AddTable(const SymbolTable& table);

  // return the name of the symbol table
  virtual const string& Name() const {
    return impl_->Name();
  }

  // Return the label-agnostic MD5 check-sum for this table.  All new symbols
  // added to the table will result in an updated checksum.
  // DEPRECATED.
  virtual string CheckSum() const {
    return impl_->CheckSum();
  }

  // Same as CheckSum(), but this returns an label-dependent version.
  virtual string LabeledCheckSum() const {
    return impl_->LabeledCheckSum();
  }

  virtual bool Write(ostream &strm) const {
    return impl_->Write(strm);
  }

  bool Write(const string& filename) const {
    ofstream strm(filename.c_str(), ofstream::out | ofstream::binary);
    if (!strm) {
      LOG(ERROR) << "SymbolTable::Write: Can't open file " << filename;
      return false;
    }
    return Write(strm);
  }

  // Dump an ascii text representation of the symbol table via a stream
  virtual bool WriteText(
      ostream &strm,
      const SymbolTableTextOptions &opts = SymbolTableTextOptions()) const;

  // Dump an ascii text representation of the symbol table
  bool WriteText(const string& filename) const {
    ofstream strm(filename.c_str());
    if (!strm) {
      LOG(ERROR) << "SymbolTable::WriteText: Can't open file " << filename;
      return false;
    }
    return WriteText(strm);
  }

  // Return the string associated with the key. If the key is out of
  // range (<0, >max), log error and return an empty string.
  virtual string Find(int64 key) const {
    return impl_->Find(key);
  }

  // Return the key associated with the symbol. If the symbol
  // does not exists, log error and  return SymbolTable::kNoSymbol
  virtual int64 Find(const string& symbol) const {
    return impl_->Find(symbol);
  }

  // Return the key associated with the symbol. If the symbol
  // does not exists, log error and  return SymbolTable::kNoSymbol
  virtual int64 Find(const char* symbol) const {
    return impl_->Find(symbol);
  }

  // Return the current available key (i.e highest key number+1) in
  // the symbol table
  virtual int64 AvailableKey(void) const {
    return impl_->AvailableKey();
  }

  // Return the current number of symbols in table (not necessarily
  // equal to AvailableKey())
  virtual size_t NumSymbols(void) const {
    return impl_->NumSymbols();
  }

  virtual int64 GetNthKey(ssize_t pos) const {
    return impl_->GetNthKey(pos);
  }

 private:
  explicit SymbolTable(SymbolTableImpl* impl) : impl_(impl) {}

  void MutateCheck() {
    // Copy on write
    if (impl_->RefCount() > 1) {
      impl_->DecrRefCount();
      impl_ = new SymbolTableImpl(*impl_);
    }
  }

  const SymbolTableImpl* Impl() const {
    return impl_;
  }

 private:
  SymbolTableImpl* impl_;
};


//
// \class SymbolTableIterator
// \brief Iterator class for symbols in a symbol table
class SymbolTableIterator {
 public:
  SymbolTableIterator(const SymbolTable& table)
      : table_(table),
        pos_(0),
        nsymbols_(table.NumSymbols()),
        key_(table.GetNthKey(0)) { }

  ~SymbolTableIterator() { }

  // is iterator done
  bool Done(void) {
    return (pos_ == nsymbols_);
  }

  // return the Value() of the current symbol (int64 key)
  int64 Value(void) {
    return key_;
  }

  // return the string of the current symbol
  string Symbol(void) {
    return table_.Find(key_);
  }

  // advance iterator forward
  void Next(void) {
    ++pos_;
    if (pos_ < nsymbols_) key_ = table_.GetNthKey(pos_);
  }

  // reset iterator
  void Reset(void) {
    pos_ = 0;
    key_ = table_.GetNthKey(0);
  }

 private:
  const SymbolTable& table_;
  ssize_t pos_;
  size_t nsymbols_;
  int64 key_;
};


// Tests compatibilty between two sets of symbol tables
inline bool CompatSymbols(const SymbolTable *syms1, const SymbolTable *syms2,
                          bool warning = true) {
  if (!FLAGS_fst_compat_symbols) {
    return true;
  } else if (!syms1 && !syms2) {
    return true;
  } else if (syms1 && !syms2) {
    if (warning)
      LOG(WARNING) <<
          "CompatSymbols: first symbol table present but second missing";
    return false;
  } else if (!syms1 && syms2) {
    if (warning)
      LOG(WARNING) <<
          "CompatSymbols: second symbol table present but first missing";
    return false;
  } else if (syms1->LabeledCheckSum() != syms2->LabeledCheckSum()) {
    if (warning)
      LOG(WARNING) << "CompatSymbols: Symbol table check sums do not match";
    return false;
  } else {
    return true;
  }
}


// Relabels a symbol table as specified by the input vector of pairs
// (old label, new label). The new symbol table only retains symbols
// for which a relabeling is *explicitely* specified.
// TODO(allauzen): consider adding options to allow for some form
// of implicit identity relabeling.
template <class Label>
SymbolTable *RelabelSymbolTable(const SymbolTable *table,
                                const vector<pair<Label, Label> > &pairs) {
  SymbolTable *new_table = new SymbolTable(
      table->Name().empty() ? string() :
      (string("relabeled_") + table->Name()));

  for (size_t i = 0; i < pairs.size(); ++i)
    new_table->AddSymbol(table->Find(pairs[i].first), pairs[i].second);

  return new_table;
}

// Symbol Table Serialization
inline void SymbolTableToString(const SymbolTable *table, string *result) {
  ostringstream ostrm;
  table->Write(ostrm);
  *result = ostrm.str();
}

inline SymbolTable *StringToSymbolTable(const string &s) {
  istringstream istrm(s);
  return SymbolTable::Read(istrm, SymbolTableReadOptions());
}



}  // namespace fst

#endif  // FST_LIB_SYMBOL_TABLE_H__
