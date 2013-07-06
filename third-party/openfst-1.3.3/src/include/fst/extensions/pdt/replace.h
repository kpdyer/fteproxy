// replace.h

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
// Recursively replace Fst arcs with other Fst(s) returning a PDT.

#ifndef FST_EXTENSIONS_PDT_REPLACE_H__
#define FST_EXTENSIONS_PDT_REPLACE_H__

#include <tr1/unordered_map>
using std::tr1::unordered_map;
using std::tr1::unordered_multimap;

#include <fst/replace.h>

namespace fst {

// Hash to paren IDs
template <typename S>
struct ReplaceParenHash {
  size_t operator()(const pair<size_t, S> &p) const {
    return p.first + p.second * kPrime;
  }
 private:
  static const size_t kPrime = 7853;
};

template <typename S> const size_t ReplaceParenHash<S>::kPrime;

// Builds a pushdown transducer (PDT) from an RTN specification
// identical to that in fst/lib/replace.h. The result is a PDT
// encoded as the FST 'ofst' where some transitions are labeled with
// open or close parentheses. To be interpreted as a PDT, the parens
// must balance on a path (see PdtExpand()). The open/close
// parenthesis label pairs are returned in 'parens'.
template <class Arc>
void Replace(const vector<pair<typename Arc::Label,
             const Fst<Arc>* > >& ifst_array,
             MutableFst<Arc> *ofst,
             vector<pair<typename Arc::Label,
             typename Arc::Label> > *parens,
             typename Arc::Label root) {
  typedef typename Arc::Label Label;
  typedef typename Arc::StateId StateId;
  typedef typename Arc::Weight Weight;

  ofst->DeleteStates();
  parens->clear();

  unordered_map<Label, size_t> label2id;
  for (size_t i = 0; i < ifst_array.size(); ++i)
    label2id[ifst_array[i].first] = i;

  Label max_label = kNoLabel;
  size_t max_non_term_count = 0;

  // Queue of non-terminals to replace
  deque<size_t> non_term_queue;
  // Map of non-terminals to replace to count
  unordered_map<Label, size_t> non_term_map;
  non_term_queue.push_back(root);
  non_term_map[root] = 1;;

  // PDT state corr. to ith replace FST start state.
  vector<StateId> fst_start(ifst_array.size(), kNoLabel);
  // PDT state, weight pairs corr. to ith replace FST final state & weights.
  vector< vector<pair<StateId, Weight> > > fst_final(ifst_array.size());

  // Builds single Fst combining all referenced input Fsts. Leaves in the
  // non-termnals for now.  Tabulate the PDT states that correspond to
  // the start and final states of the input Fsts.
  for (StateId soff = 0; !non_term_queue.empty(); soff = ofst->NumStates()) {
    Label label = non_term_queue.front();
    non_term_queue.pop_front();
    size_t fst_id = label2id[label];

    const Fst<Arc> *ifst = ifst_array[fst_id].second;
    for (StateIterator< Fst<Arc> > siter(*ifst);
         !siter.Done(); siter.Next()) {
      StateId is = siter.Value();
      StateId os = ofst->AddState();
      if (is == ifst->Start()) {
        fst_start[fst_id] = os;
        if (label == root)
          ofst->SetStart(os);
      }
      if (ifst->Final(is) != Weight::Zero()) {
        if (label == root)
          ofst->SetFinal(os, ifst->Final(is));
        fst_final[fst_id].push_back(make_pair(os, ifst->Final(is)));
      }
      for (ArcIterator< Fst<Arc> > aiter(*ifst, is);
           !aiter.Done(); aiter.Next()) {
        Arc arc = aiter.Value();
        if (max_label == kNoLabel || arc.olabel > max_label)
          max_label = arc.olabel;
        typename unordered_map<Label, size_t>::const_iterator it =
            label2id.find(arc.olabel);
        if (it != label2id.end()) {
          size_t nfst_id = it->second;
          if (ifst_array[nfst_id].second->Start() == -1)
            continue;
          size_t count = non_term_map[arc.olabel]++;
          if (count == 0)
            non_term_queue.push_back(arc.olabel);
          if (count > max_non_term_count)
            max_non_term_count = count;
        }
        arc.nextstate += soff;
        ofst->AddArc(os, arc);
      }
    }
  }

  // Changes each non-terminal transition to an open parenthesis
  // transition redirected to the PDT state that corresponds to the
  // start state of the input FST for the non-terminal. Adds close parenthesis
  // transitions from the PDT states corr. to the final states of the
  // input FST for the non-terminal to the former destination state of the
  // non-terminal transition.

  typedef MutableArcIterator< MutableFst<Arc> > MIter;
  typedef unordered_map<pair<size_t, StateId >, size_t,
                   ReplaceParenHash<StateId> > ParenMap;

  // Parenthesis pair ID per fst, state pair.
  ParenMap paren_map;
  // # of parenthesis pairs per fst.
  vector<size_t> nparens(ifst_array.size(), 0);
  // Initial open parenthesis label
  Label first_open_paren = max_label + 1;
  Label first_close_paren = max_label + max_non_term_count + 1;

  for (StateIterator< Fst<Arc> > siter(*ofst);
       !siter.Done(); siter.Next()) {
    StateId os = siter.Value();
    MIter *aiter = new MIter(ofst, os);
    for (size_t n = 0; !aiter->Done(); aiter->Next(), ++n) {
      Arc arc = aiter->Value();
      typename unordered_map<Label, size_t>::const_iterator lit =
          label2id.find(arc.olabel);
      if (lit != label2id.end()) {
        size_t nfst_id = lit->second;

        // Get parentheses. Ensures distinct parenthesis pair per
        // non-terminal and destination state but otherwise reuses them.
        Label open_paren = kNoLabel, close_paren = kNoLabel;
        pair<size_t, StateId> paren_key(nfst_id, arc.nextstate);
        typename ParenMap::const_iterator pit = paren_map.find(paren_key);
        if (pit != paren_map.end()) {
          size_t paren_id = pit->second;
          open_paren = (*parens)[paren_id].first;
          close_paren = (*parens)[paren_id].second;
        } else {
          size_t paren_id = nparens[nfst_id]++;
          open_paren = first_open_paren + paren_id;
          close_paren = first_close_paren + paren_id;
          paren_map[paren_key] = paren_id;
          if (paren_id >= parens->size())
            parens->push_back(make_pair(open_paren, close_paren));
        }

        // Sets open parenthesis.
        Arc sarc(open_paren, open_paren, arc.weight, fst_start[nfst_id]);
        aiter->SetValue(sarc);

        // Adds close parentheses.
        for (size_t i = 0; i < fst_final[nfst_id].size(); ++i) {
          pair<StateId, Weight> &p = fst_final[nfst_id][i];
          Arc farc(close_paren, close_paren, p.second, arc.nextstate);

          ofst->AddArc(p.first, farc);
          if (os == p.first) {  // Invalidated iterator
            delete aiter;
            aiter = new MIter(ofst, os);
            aiter->Seek(n);
          }
        }
      }
    }
    delete aiter;
  }
}

}  // namespace fst

#endif  // FST_EXTENSIONS_PDT_REPLACE_H__
