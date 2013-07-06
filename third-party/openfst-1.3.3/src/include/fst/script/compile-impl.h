// compile.h

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
// Class to to compile a binary Fst from textual input.

#ifndef FST_SCRIPT_COMPILE_IMPL_H_
#define FST_SCRIPT_COMPILE_IMPL_H_

#include <tr1/unordered_map>
using std::tr1::unordered_map;
using std::tr1::unordered_multimap;
#include <sstream>
#include <string>
#include <vector>
using std::vector;

#include <iostream>
#include <fstream>
#include <sstream>
#include <fst/fst.h>
#include <fst/util.h>
#include <fst/vector-fst.h>

DECLARE_string(fst_field_separator);

namespace fst {

// Compile a binary Fst from textual input, helper class for fstcompile.cc
// WARNING: Stand-alone use of this class not recommended, most code should
// read/write using the binary format which is much more efficient.
template <class A> class FstCompiler {
 public:
  typedef A Arc;
  typedef typename A::StateId StateId;
  typedef typename A::Label Label;
  typedef typename A::Weight Weight;

  // WARNING: use of 'allow_negative_labels = true' not recommended; may
  // cause conflicts
  FstCompiler(istream &istrm, const string &source,
            const SymbolTable *isyms, const SymbolTable *osyms,
            const SymbolTable *ssyms, bool accep, bool ikeep,
              bool okeep, bool nkeep, bool allow_negative_labels = false)
      : nline_(0), source_(source),
        isyms_(isyms), osyms_(osyms), ssyms_(ssyms),
        nstates_(0), keep_state_numbering_(nkeep),
        allow_negative_labels_(allow_negative_labels) {
    char line[kLineLen];
    while (istrm.getline(line, kLineLen)) {
      ++nline_;
      vector<char *> col;
      string separator = FLAGS_fst_field_separator + "\n";
      SplitToVector(line, separator.c_str(), &col, true);
      if (col.size() == 0 || col[0][0] == '\0')  // empty line
        continue;
      if (col.size() > 5 ||
          (col.size() > 4 && accep) ||
          (col.size() == 3 && !accep)) {
        FSTERROR() << "FstCompiler: Bad number of columns, source = "
                   << source_
                   << ", line = " << nline_;
        fst_.SetProperties(kError, kError);
        return;
      }
      StateId s = StrToStateId(col[0]);
      while (s >= fst_.NumStates())
        fst_.AddState();
      if (nline_ == 1)
        fst_.SetStart(s);

      Arc arc;
      StateId d = s;
      switch (col.size()) {
      case 1:
        fst_.SetFinal(s, Weight::One());
        break;
      case 2:
        fst_.SetFinal(s, StrToWeight(col[1], true));
        break;
      case 3:
        arc.nextstate = d = StrToStateId(col[1]);
        arc.ilabel = StrToILabel(col[2]);
        arc.olabel = arc.ilabel;
        arc.weight = Weight::One();
        fst_.AddArc(s, arc);
        break;
      case 4:
        arc.nextstate = d = StrToStateId(col[1]);
        arc.ilabel = StrToILabel(col[2]);
        if (accep) {
          arc.olabel = arc.ilabel;
          arc.weight = StrToWeight(col[3], false);
        } else {
          arc.olabel = StrToOLabel(col[3]);
          arc.weight = Weight::One();
        }
        fst_.AddArc(s, arc);
        break;
      case 5:
        arc.nextstate = d = StrToStateId(col[1]);
        arc.ilabel = StrToILabel(col[2]);
        arc.olabel = StrToOLabel(col[3]);
        arc.weight = StrToWeight(col[4], false);
        fst_.AddArc(s, arc);
      }
      while (d >= fst_.NumStates())
        fst_.AddState();
    }
    if (ikeep)
      fst_.SetInputSymbols(isyms);
    if (okeep)
      fst_.SetOutputSymbols(osyms);
  }

  const VectorFst<A> &Fst() const {
    return fst_;
  }

 private:
  // Maximum line length in text file.
  static const int kLineLen = 8096;

  int64 StrToId(const char *s, const SymbolTable *syms,
                const char *name, bool allow_negative = false) const {
    int64 n = 0;

    if (syms) {
      n = syms->Find(s);
      if (n == -1 || (!allow_negative && n < 0)) {
        FSTERROR() << "FstCompiler: Symbol \"" << s
                   << "\" is not mapped to any integer " << name
                   << ", symbol table = " << syms->Name()
                   << ", source = " << source_ << ", line = " << nline_;
        fst_.SetProperties(kError, kError);
      }
    } else {
      char *p;
      n = strtoll(s, &p, 10);
      if (p < s + strlen(s) || (!allow_negative && n < 0)) {
        FSTERROR() << "FstCompiler: Bad " << name << " integer = \"" << s
                   << "\", source = " << source_ << ", line = " << nline_;
        fst_.SetProperties(kError, kError);
      }
    }
    return n;
  }

  StateId StrToStateId(const char *s) {
    StateId n = StrToId(s, ssyms_, "state ID");

    if (keep_state_numbering_)
      return n;

    // remap state IDs to make dense set
    typename unordered_map<StateId, StateId>::const_iterator it = states_.find(n);
    if (it == states_.end()) {
      states_[n] = nstates_;
      return nstates_++;
    } else {
      return it->second;
    }
  }

  StateId StrToILabel(const char *s) const {
    return StrToId(s, isyms_, "arc ilabel", allow_negative_labels_);
  }

  StateId StrToOLabel(const char *s) const {
    return StrToId(s, osyms_, "arc olabel", allow_negative_labels_);
  }

  Weight StrToWeight(const char *s, bool allow_zero) const {
    Weight w;
    istringstream strm(s);
    strm >> w;
    if (!strm || (!allow_zero && w == Weight::Zero())) {
      FSTERROR() << "FstCompiler: Bad weight = \"" << s
                 << "\", source = " << source_ << ", line = " << nline_;
      fst_.SetProperties(kError, kError);
      w = Weight::NoWeight();
    }
    return w;
  }

  mutable VectorFst<A> fst_;
  size_t nline_;
  string source_;                      // text FST source name
  const SymbolTable *isyms_;           // ilabel symbol table
  const SymbolTable *osyms_;           // olabel symbol table
  const SymbolTable *ssyms_;           // slabel symbol table
  unordered_map<StateId, StateId> states_;  // state ID map
  StateId nstates_;                    // number of seen states
  bool keep_state_numbering_;
  bool allow_negative_labels_;         // not recommended; may cause conflicts

  DISALLOW_COPY_AND_ASSIGN(FstCompiler);
};

}  // namespace fst

#endif  // FST_SCRIPT_COMPILE_IMPL_H_
