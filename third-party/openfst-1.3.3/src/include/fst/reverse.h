// reverse.h

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
// Functions and classes to sort arcs in an FST.

#ifndef FST_LIB_REVERSE_H__
#define FST_LIB_REVERSE_H__

#include <algorithm>
#include <vector>
using std::vector;

#include <fst/cache.h>


namespace fst {

// Reverses an FST. The reversed result is written to an output
// MutableFst.  If A transduces string x to y with weight a, then the
// reverse of A transduces the reverse of x to the reverse of y with
// weight a.Reverse().
//
// Typically, a = a.Reverse() and Arc = RevArc (e.g. for
// TropicalWeight or LogWeight).  In general, e.g. when the weights
// only form a left or right semiring, the output arc type must match
// the input arc type except having the reversed Weight type.
template<class Arc, class RevArc>
void Reverse(const Fst<Arc> &ifst, MutableFst<RevArc> *ofst) {
  typedef typename Arc::StateId StateId;
  typedef typename Arc::Weight Weight;
  typedef typename RevArc::Weight RevWeight;

  ofst->DeleteStates();
  ofst->SetInputSymbols(ifst.InputSymbols());
  ofst->SetOutputSymbols(ifst.OutputSymbols());
  if (ifst.Properties(kExpanded, false))
    ofst->ReserveStates(CountStates(ifst) + 1);
  StateId istart = ifst.Start();
  StateId ostart = ofst->AddState();
  ofst->SetStart(ostart);

  for (StateIterator< Fst<Arc> > siter(ifst);
       !siter.Done();
       siter.Next()) {
    StateId is = siter.Value();
    StateId os = is + 1;
    while (ofst->NumStates() <= os)
      ofst->AddState();
    if (is == istart)
      ofst->SetFinal(os, RevWeight::One());

    Weight final = ifst.Final(is);
    if (final != Weight::Zero()) {
      RevArc oarc(0, 0, final.Reverse(), os);
      ofst->AddArc(0, oarc);
    }

    for (ArcIterator< Fst<Arc> > aiter(ifst, is);
         !aiter.Done();
         aiter.Next()) {
      const Arc &iarc = aiter.Value();
      RevArc oarc(iarc.ilabel, iarc.olabel, iarc.weight.Reverse(), os);
      StateId nos = iarc.nextstate + 1;
      while (ofst->NumStates() <= nos)
        ofst->AddState();
      ofst->AddArc(nos, oarc);
    }
  }
  uint64 iprops = ifst.Properties(kCopyProperties, false);
  uint64 oprops = ofst->Properties(kFstProperties, false);
  ofst->SetProperties(ReverseProperties(iprops) | oprops, kFstProperties);
}

}  // namespace fst

#endif  // FST_LIB_REVERSE_H__
