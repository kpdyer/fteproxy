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
// Author: johans@google.com (Johan Schalkwyk)
//
// \file
// Functions and classes for the recursive replacement of Fsts.
//

#ifndef FST_LIB_REPLACE_H__
#define FST_LIB_REPLACE_H__

#include <tr1/unordered_map>
using std::tr1::unordered_map;
using std::tr1::unordered_multimap;
#include <set>
#include <string>
#include <utility>
using std::pair; using std::make_pair;
#include <vector>
using std::vector;

#include <fst/cache.h>
#include <fst/expanded-fst.h>
#include <fst/fst.h>
#include <fst/matcher.h>
#include <fst/replace-util.h>
#include <fst/state-table.h>
#include <fst/test-properties.h>

namespace fst {

//
// REPLACE STATE TUPLES AND TABLES
//
// The replace state table has the form
//
// template <class A, class P>
// class ReplaceStateTable {
//  public:
//   typedef A Arc;
//   typedef P PrefixId;
//   typedef typename A::StateId StateId;
//   typedef ReplaceStateTuple<StateId, PrefixId> StateTuple;
//   typedef typename A::Label Label;
//
//   // Required constuctor
//   ReplaceStateTable(const vector<pair<Label, const Fst<A>*> > &fst_tuples,
//                     Label root);
//
//   // Required copy constructor that does not copy state
//   ReplaceStateTable(const ReplaceStateTable<A,P> &table);
//
//   // Lookup state ID by tuple. If it doesn't exist, then add it.
//   StateId FindState(const StateTuple &tuple);
//
//   // Lookup state tuple by ID.
//   const StateTuple &Tuple(StateId id) const;
// };


// \struct ReplaceStateTuple
// \brief Tuple of information that uniquely defines a state in replace
template <class S, class P>
struct ReplaceStateTuple {
  typedef S StateId;
  typedef P PrefixId;

  ReplaceStateTuple()
      : prefix_id(-1), fst_id(kNoStateId), fst_state(kNoStateId) {}

  ReplaceStateTuple(PrefixId p, StateId f, StateId s)
      : prefix_id(p), fst_id(f), fst_state(s) {}

  PrefixId prefix_id;  // index in prefix table
  StateId fst_id;      // current fst being walked
  StateId fst_state;   // current state in fst being walked, not to be
                       // confused with the state_id of the combined fst
};


// Equality of replace state tuples.
template <class S, class P>
inline bool operator==(const ReplaceStateTuple<S, P>& x,
                       const ReplaceStateTuple<S, P>& y) {
  return x.prefix_id == y.prefix_id &&
      x.fst_id == y.fst_id &&
      x.fst_state == y.fst_state;
}


// \class ReplaceRootSelector
// Functor returning true for tuples corresponding to states in the root FST
template <class S, class P>
class ReplaceRootSelector {
 public:
  bool operator()(const ReplaceStateTuple<S, P> &tuple) const {
    return tuple.prefix_id == 0;
  }
};


// \class ReplaceFingerprint
// Fingerprint for general replace state tuples.
template <class S, class P>
class ReplaceFingerprint {
 public:
  ReplaceFingerprint(const vector<uint64> *size_array)
      : cumulative_size_array_(size_array) {}

  uint64 operator()(const ReplaceStateTuple<S, P> &tuple) const {
    return tuple.prefix_id * (cumulative_size_array_->back()) +
        cumulative_size_array_->at(tuple.fst_id - 1) +
        tuple.fst_state;
  }

 private:
  const vector<uint64> *cumulative_size_array_;
};


// \class ReplaceFstStateFingerprint
// Useful when the fst_state uniquely define the tuple.
template <class S, class P>
class ReplaceFstStateFingerprint {
 public:
  uint64 operator()(const ReplaceStateTuple<S, P>& tuple) const {
    return tuple.fst_state;
  }
};


// \class ReplaceHash
// A generic hash function for replace state tuples.
template <typename S, typename P>
class ReplaceHash {
 public:
  size_t operator()(const ReplaceStateTuple<S, P>& t) const {
    return t.prefix_id + t.fst_id * kPrime0 + t.fst_state * kPrime1;
  }
 private:
  static const size_t kPrime0;
  static const size_t kPrime1;
};

template <typename S, typename P>
const size_t ReplaceHash<S, P>::kPrime0 = 7853;

template <typename S, typename P>
const size_t ReplaceHash<S, P>::kPrime1 = 7867;

template <class A, class T> class ReplaceFstMatcher;


// \class VectorHashReplaceStateTable
// A two-level state table for replace.
// Warning: calls CountStates to compute the number of states of each
// component Fst.
template <class A, class P = ssize_t>
class VectorHashReplaceStateTable {
 public:
  typedef A Arc;
  typedef typename A::StateId StateId;
  typedef typename A::Label Label;
  typedef P PrefixId;
  typedef ReplaceStateTuple<StateId, P> StateTuple;
  typedef VectorHashStateTable<ReplaceStateTuple<StateId, P>,
                               ReplaceRootSelector<StateId, P>,
                               ReplaceFstStateFingerprint<StateId, P>,
                               ReplaceFingerprint<StateId, P> > StateTable;

  VectorHashReplaceStateTable(
      const vector<pair<Label, const Fst<A>*> > &fst_tuples,
      Label root) : root_size_(0) {
    cumulative_size_array_.push_back(0);
    for (size_t i = 0; i < fst_tuples.size(); ++i) {
      if (fst_tuples[i].first == root) {
        root_size_ = CountStates(*(fst_tuples[i].second));
        cumulative_size_array_.push_back(cumulative_size_array_.back());
      } else {
        cumulative_size_array_.push_back(cumulative_size_array_.back() +
                                         CountStates(*(fst_tuples[i].second)));
      }
    }
    state_table_ = new StateTable(
        new ReplaceRootSelector<StateId, P>,
        new ReplaceFstStateFingerprint<StateId, P>,
        new ReplaceFingerprint<StateId, P>(&cumulative_size_array_),
        root_size_,
        root_size_ + cumulative_size_array_.back());
  }

  VectorHashReplaceStateTable(const VectorHashReplaceStateTable<A, P> &table)
      : root_size_(table.root_size_),
        cumulative_size_array_(table.cumulative_size_array_) {
    state_table_ = new StateTable(
        new ReplaceRootSelector<StateId, P>,
        new ReplaceFstStateFingerprint<StateId, P>,
        new ReplaceFingerprint<StateId, P>(&cumulative_size_array_),
        root_size_,
        root_size_ + cumulative_size_array_.back());
  }

  ~VectorHashReplaceStateTable() {
    delete state_table_;
  }

  StateId FindState(const StateTuple &tuple) {
    return state_table_->FindState(tuple);
  }

  const StateTuple &Tuple(StateId id) const {
    return state_table_->Tuple(id);
  }

 private:
  StateId root_size_;
  vector<uint64> cumulative_size_array_;
  StateTable *state_table_;
};


// \class DefaultReplaceStateTable
// Default replace state table
template <class A, class P = ssize_t>
class DefaultReplaceStateTable : public CompactHashStateTable<
  ReplaceStateTuple<typename A::StateId, P>,
  ReplaceHash<typename A::StateId, P> > {
 public:
  typedef A Arc;
  typedef typename A::StateId StateId;
  typedef typename A::Label Label;
  typedef P PrefixId;
  typedef ReplaceStateTuple<StateId, P> StateTuple;
  typedef CompactHashStateTable<StateTuple,
                                ReplaceHash<StateId, PrefixId> > StateTable;

  using StateTable::FindState;
  using StateTable::Tuple;

  DefaultReplaceStateTable(
      const vector<pair<Label, const Fst<A>*> > &fst_tuples,
      Label root) {}

  DefaultReplaceStateTable(const DefaultReplaceStateTable<A, P> &table)
      : StateTable() {}
};

//
// REPLACE FST CLASS
//

// By default ReplaceFst will copy the input label of the 'replace arc'.
// For acceptors we do not want this behaviour. Instead we need to
// create an epsilon arc when recursing into the appropriate Fst.
// The 'epsilon_on_replace' option can be used to toggle this behaviour.
template <class A, class T = DefaultReplaceStateTable<A> >
struct ReplaceFstOptions : CacheOptions {
  int64 root;    // root rule for expansion
  bool  epsilon_on_replace;
  bool  take_ownership;  // take ownership of input Fst(s)
  T*    state_table;

  ReplaceFstOptions(const CacheOptions &opts, int64 r)
      : CacheOptions(opts),
        root(r),
        epsilon_on_replace(false),
        take_ownership(false),
        state_table(0) {}
  explicit ReplaceFstOptions(int64 r)
      : root(r),
        epsilon_on_replace(false),
        take_ownership(false),
        state_table(0) {}
  ReplaceFstOptions(int64 r, bool epsilon_replace_arc)
      : root(r),
        epsilon_on_replace(epsilon_replace_arc),
        take_ownership(false),
        state_table(0) {}
  ReplaceFstOptions()
      : root(kNoLabel),
        epsilon_on_replace(false),
        take_ownership(false),
        state_table(0) {}
};


// \class ReplaceFstImpl
// \brief Implementation class for replace class Fst
//
// The replace implementation class supports a dynamic
// expansion of a recursive transition network represented as Fst
// with dynamic replacable arcs.
//
template <class A, class T>
class ReplaceFstImpl : public CacheImpl<A> {
  friend class ReplaceFstMatcher<A, T>;

 public:
  using FstImpl<A>::SetType;
  using FstImpl<A>::SetProperties;
  using FstImpl<A>::WriteHeader;
  using FstImpl<A>::SetInputSymbols;
  using FstImpl<A>::SetOutputSymbols;
  using FstImpl<A>::InputSymbols;
  using FstImpl<A>::OutputSymbols;

  using CacheImpl<A>::PushArc;
  using CacheImpl<A>::HasArcs;
  using CacheImpl<A>::HasFinal;
  using CacheImpl<A>::HasStart;
  using CacheImpl<A>::SetArcs;
  using CacheImpl<A>::SetFinal;
  using CacheImpl<A>::SetStart;

  typedef typename A::Label   Label;
  typedef typename A::Weight  Weight;
  typedef typename A::StateId StateId;
  typedef CacheState<A> State;
  typedef A Arc;
  typedef unordered_map<Label, Label> NonTerminalHash;

  typedef T StateTable;
  typedef typename T::PrefixId PrefixId;
  typedef ReplaceStateTuple<StateId, PrefixId> StateTuple;

  // constructor for replace class implementation.
  // \param fst_tuples array of label/fst tuples, one for each non-terminal
  ReplaceFstImpl(const vector< pair<Label, const Fst<A>* > >& fst_tuples,
                 const ReplaceFstOptions<A, T> &opts)
      : CacheImpl<A>(opts),
        epsilon_on_replace_(opts.epsilon_on_replace),
        state_table_(opts.state_table ? opts.state_table :
                     new StateTable(fst_tuples, opts.root)) {

    SetType("replace");

    if (fst_tuples.size() > 0) {
      SetInputSymbols(fst_tuples[0].second->InputSymbols());
      SetOutputSymbols(fst_tuples[0].second->OutputSymbols());
    }

    bool all_negative = true;  // all nonterminals are negative?
    bool dense_range = true;   // all nonterminals are positive
                               // and form a dense range containing 1?
    for (size_t i = 0; i < fst_tuples.size(); ++i) {
      Label nonterminal = fst_tuples[i].first;
      if (nonterminal >= 0)
        all_negative = false;
      if (nonterminal > fst_tuples.size() || nonterminal <= 0)
        dense_range = false;
    }

    vector<uint64> inprops;
    bool all_ilabel_sorted = true;
    bool all_olabel_sorted = true;
    bool all_non_empty = true;
    fst_array_.push_back(0);
    for (size_t i = 0; i < fst_tuples.size(); ++i) {
      Label label = fst_tuples[i].first;
      const Fst<A> *fst = fst_tuples[i].second;
      nonterminal_hash_[label] = fst_array_.size();
      nonterminal_set_.insert(label);
      fst_array_.push_back(opts.take_ownership ? fst : fst->Copy());
      if (fst->Start() == kNoStateId)
        all_non_empty = false;
      if(!fst->Properties(kILabelSorted, false))
        all_ilabel_sorted = false;
      if(!fst->Properties(kOLabelSorted, false))
        all_olabel_sorted = false;
      inprops.push_back(fst->Properties(kCopyProperties, false));
      if (i) {
        if (!CompatSymbols(InputSymbols(), fst->InputSymbols())) {
          FSTERROR() << "ReplaceFstImpl: input symbols of Fst " << i
                     << " does not match input symbols of base Fst (0'th fst)";
          SetProperties(kError, kError);
        }
        if (!CompatSymbols(OutputSymbols(), fst->OutputSymbols())) {
          FSTERROR() << "ReplaceFstImpl: output symbols of Fst " << i
                     << " does not match output symbols of base Fst "
                     << "(0'th fst)";
          SetProperties(kError, kError);
        }
      }
    }
    Label nonterminal = nonterminal_hash_[opts.root];
    if ((nonterminal == 0) && (fst_array_.size() > 1)) {
      FSTERROR() << "ReplaceFstImpl: no Fst corresponding to root label '"
                 << opts.root << "' in the input tuple vector";
      SetProperties(kError, kError);
    }
    root_ = (nonterminal > 0) ? nonterminal : 1;

    SetProperties(ReplaceProperties(inprops, root_ - 1, epsilon_on_replace_,
                                    all_non_empty));
    // We assume that all terminals are positive.  The resulting
    // ReplaceFst is known to be kILabelSorted when all sub-FSTs are
    // kILabelSorted and one of the 3 following conditions is satisfied:
    //  1. 'epsilon_on_replace' is false, or
    //  2. all non-terminals are negative, or
    //  3. all non-terninals are positive and form a dense range containing 1.
    if (all_ilabel_sorted &&
        (!epsilon_on_replace_ || all_negative || dense_range))
      SetProperties(kILabelSorted, kILabelSorted);
    // Similarly, the resulting ReplaceFst is known to be
    // kOLabelSorted when all sub-FSTs are kOLabelSorted and one of
    // the 2 following conditions is satisfied:
    //  1. all non-terminals are negative, or
    //  2. all non-terninals are positive and form a dense range containing 1.
    if (all_olabel_sorted && (all_negative || dense_range))
      SetProperties(kOLabelSorted, kOLabelSorted);

    // Enable optional caching as long as sorted and all non empty.
    if (Properties(kILabelSorted | kOLabelSorted) && all_non_empty)
      always_cache_ = false;
    else
      always_cache_ = true;
    VLOG(2) << "ReplaceFstImpl::ReplaceFstImpl: always_cache = "
            << (always_cache_ ? "true" : "false");
  }

  ReplaceFstImpl(const ReplaceFstImpl& impl)
      : CacheImpl<A>(impl),
        epsilon_on_replace_(impl.epsilon_on_replace_),
        always_cache_(impl.always_cache_),
        state_table_(new StateTable(*(impl.state_table_))),
        nonterminal_set_(impl.nonterminal_set_),
        nonterminal_hash_(impl.nonterminal_hash_),
        root_(impl.root_) {
    SetType("replace");
    SetProperties(impl.Properties(), kCopyProperties);
    SetInputSymbols(impl.InputSymbols());
    SetOutputSymbols(impl.OutputSymbols());
    fst_array_.reserve(impl.fst_array_.size());
    fst_array_.push_back(0);
    for (size_t i = 1; i < impl.fst_array_.size(); ++i) {
      fst_array_.push_back(impl.fst_array_[i]->Copy(true));
    }
  }

  ~ReplaceFstImpl() {
    VLOG(2) << "~ReplaceFstImpl: gc = "
            << (CacheImpl<A>::GetCacheGc() ? "true" : "false")
            << ", gc_size = " << CacheImpl<A>::GetCacheSize()
            << ", gc_limit = " << CacheImpl<A>::GetCacheLimit();

    delete state_table_;
    for (size_t i = 1; i < fst_array_.size(); ++i) {
      delete fst_array_[i];
    }
  }

  // Computes the dependency graph of the replace class and returns
  // true if the dependencies are cyclic. Cyclic dependencies will result
  // in an un-expandable replace fst.
  bool CyclicDependencies() const {
    ReplaceUtil<A> replace_util(fst_array_, nonterminal_hash_, root_);
    return replace_util.CyclicDependencies();
  }

  // Return or compute start state of replace fst
  StateId Start() {
    if (!HasStart()) {
      if (fst_array_.size() == 1) {      // no fsts defined for replace
        SetStart(kNoStateId);
        return kNoStateId;
      } else {
        const Fst<A>* fst = fst_array_[root_];
        StateId fst_start = fst->Start();
        if (fst_start == kNoStateId)  // root Fst is empty
          return kNoStateId;

        PrefixId prefix = GetPrefixId(StackPrefix());
        StateId start = state_table_->FindState(
            StateTuple(prefix, root_, fst_start));
        SetStart(start);
        return start;
      }
    } else {
      return CacheImpl<A>::Start();
    }
  }

  // return final weight of state (kInfWeight means state is not final)
  Weight Final(StateId s) {
    if (!HasFinal(s)) {
      const StateTuple& tuple  = state_table_->Tuple(s);
      const StackPrefix& stack = stackprefix_array_[tuple.prefix_id];
      const Fst<A>* fst = fst_array_[tuple.fst_id];
      StateId fst_state = tuple.fst_state;

      if (fst->Final(fst_state) != Weight::Zero() && stack.Depth() == 0)
        SetFinal(s, fst->Final(fst_state));
      else
        SetFinal(s, Weight::Zero());
    }
    return CacheImpl<A>::Final(s);
  }

  size_t NumArcs(StateId s) {
    if (HasArcs(s)) {  // If state cached, use the cached value.
      return CacheImpl<A>::NumArcs(s);
    } else if (always_cache_) {  // If always caching, expand and cache state.
      Expand(s);
      return CacheImpl<A>::NumArcs(s);
    } else {  // Otherwise compute the number of arcs without expanding.
      StateTuple tuple  = state_table_->Tuple(s);
      if (tuple.fst_state == kNoStateId)
        return 0;

      const Fst<A>* fst = fst_array_[tuple.fst_id];
      size_t num_arcs = fst->NumArcs(tuple.fst_state);
      if (ComputeFinalArc(tuple, 0))
        num_arcs++;

      return num_arcs;
    }
  }

  // Returns whether a given label is a non terminal
  bool IsNonTerminal(Label l) const {
    // TODO(allauzen): be smarter and take advantage of
    // all_dense or all_negative.
    // Use also in ComputeArc, this would require changes to replace
    // so that recursing into an empty fst lead to a non co-accessible
    // state instead of deleting the arc as done currently.
    // Current use correct, since i/olabel sorted iff all_non_empty.
    typename NonTerminalHash::const_iterator it =
        nonterminal_hash_.find(l);
    return it != nonterminal_hash_.end();
  }

  size_t NumInputEpsilons(StateId s) {
    if (HasArcs(s)) {
      // If state cached, use the cached value.
      return CacheImpl<A>::NumInputEpsilons(s);
    } else if (always_cache_ || !Properties(kILabelSorted)) {
      // If always caching or if the number of input epsilons is too expensive
      // to compute without caching (i.e. not ilabel sorted),
      // then expand and cache state.
      Expand(s);
      return CacheImpl<A>::NumInputEpsilons(s);
    } else {
      // Otherwise, compute the number of input epsilons without caching.
      StateTuple tuple  = state_table_->Tuple(s);
      if (tuple.fst_state == kNoStateId)
        return 0;
      const Fst<A>* fst = fst_array_[tuple.fst_id];
      size_t num  = 0;
      if (!epsilon_on_replace_) {
        // If epsilon_on_replace is false, all input epsilon arcs
        // are also input epsilons arcs in the underlying machine.
        fst->NumInputEpsilons(tuple.fst_state);
      } else {
        // Otherwise, one need to consider that all non-terminal arcs
        // in the underlying machine also become input epsilon arc.
        ArcIterator<Fst<A> > aiter(*fst, tuple.fst_state);
        for (; !aiter.Done() &&
                 ((aiter.Value().ilabel == 0) ||
                  IsNonTerminal(aiter.Value().olabel));
             aiter.Next())
          ++num;
      }
      if (ComputeFinalArc(tuple, 0))
        num++;
      return num;
    }
  }

  size_t NumOutputEpsilons(StateId s) {
    if (HasArcs(s)) {
      // If state cached, use the cached value.
      return CacheImpl<A>::NumOutputEpsilons(s);
    } else if(always_cache_ || !Properties(kOLabelSorted)) {
      // If always caching or if the number of output epsilons is too expensive
      // to compute without caching (i.e. not olabel sorted),
      // then expand and cache state.
      Expand(s);
      return CacheImpl<A>::NumOutputEpsilons(s);
    } else {
      // Otherwise, compute the number of output epsilons without caching.
      StateTuple tuple  = state_table_->Tuple(s);
      if (tuple.fst_state == kNoStateId)
        return 0;
      const Fst<A>* fst = fst_array_[tuple.fst_id];
      size_t num  = 0;
      ArcIterator<Fst<A> > aiter(*fst, tuple.fst_state);
      for (; !aiter.Done() &&
               ((aiter.Value().olabel == 0) ||
                IsNonTerminal(aiter.Value().olabel));
           aiter.Next())
        ++num;
      if (ComputeFinalArc(tuple, 0))
        num++;
      return num;
    }
  }

  uint64 Properties() const { return Properties(kFstProperties); }

  // Set error if found; return FST impl properties.
  uint64 Properties(uint64 mask) const {
    if (mask & kError) {
      for (size_t i = 1; i < fst_array_.size(); ++i) {
        if (fst_array_[i]->Properties(kError, false))
          SetProperties(kError, kError);
      }
    }
    return FstImpl<Arc>::Properties(mask);
  }

  // return the base arc iterator, if arcs have not been computed yet,
  // extend/recurse for new arcs.
  void InitArcIterator(StateId s, ArcIteratorData<A> *data) {
    if (!HasArcs(s))
      Expand(s);
    CacheImpl<A>::InitArcIterator(s, data);
    // TODO(allauzen): Set behaviour of generic iterator
    // Warning: ArcIterator<ReplaceFst<A> >::InitCache()
    // relies on current behaviour.
  }


  // Extend current state (walk arcs one level deep)
  void Expand(StateId s) {
    StateTuple tuple = state_table_->Tuple(s);

    // If local fst is empty
    if (tuple.fst_state == kNoStateId) {
      SetArcs(s);
      return;
    }

    ArcIterator< Fst<A> > aiter(
        *(fst_array_[tuple.fst_id]), tuple.fst_state);
    Arc arc;

    // Create a final arc when needed
    if (ComputeFinalArc(tuple, &arc))
      PushArc(s, arc);

    // Expand all arcs leaving the state
    for (;!aiter.Done(); aiter.Next()) {
      if (ComputeArc(tuple, aiter.Value(), &arc))
        PushArc(s, arc);
    }

    SetArcs(s);
  }

  void Expand(StateId s, const StateTuple &tuple,
              const ArcIteratorData<A> &data) {
     // If local fst is empty
    if (tuple.fst_state == kNoStateId) {
      SetArcs(s);
      return;
    }

    ArcIterator< Fst<A> > aiter(data);
    Arc arc;

    // Create a final arc when needed
    if (ComputeFinalArc(tuple, &arc))
      AddArc(s, arc);

    // Expand all arcs leaving the state
    for (; !aiter.Done(); aiter.Next()) {
      if (ComputeArc(tuple, aiter.Value(), &arc))
        AddArc(s, arc);
    }

    SetArcs(s);
  }

  // If arcp == 0, only returns if a final arc is required, does not
  // actually compute it.
  bool ComputeFinalArc(const StateTuple &tuple, A* arcp,
                       uint32 flags = kArcValueFlags) {
    const Fst<A>* fst = fst_array_[tuple.fst_id];
    StateId fst_state = tuple.fst_state;
    if (fst_state == kNoStateId)
      return false;

   // if state is final, pop up stack
    const StackPrefix& stack = stackprefix_array_[tuple.prefix_id];
    if (fst->Final(fst_state) != Weight::Zero() && stack.Depth()) {
      if (arcp) {
        arcp->ilabel = 0;
        arcp->olabel = 0;
        if (flags & kArcNextStateValue) {
          PrefixId prefix_id = PopPrefix(stack);
          const PrefixTuple& top = stack.Top();
          arcp->nextstate = state_table_->FindState(
              StateTuple(prefix_id, top.fst_id, top.nextstate));
        }
        if (flags & kArcWeightValue)
          arcp->weight = fst->Final(fst_state);
      }
      return true;
    } else {
      return false;
    }
  }

  // Compute the arc in the replace fst corresponding to a given
  // in the underlying machine. Returns false if the underlying arc
  // corresponds to no arc in the replace.
  bool ComputeArc(const StateTuple &tuple, const A &arc, A* arcp,
                  uint32 flags = kArcValueFlags) {
    if (!epsilon_on_replace_ &&
        (flags == (flags & (kArcILabelValue | kArcWeightValue)))) {
      *arcp = arc;
      return true;
    }

    if (arc.olabel == 0) {  // expand local fst
      StateId nextstate = flags & kArcNextStateValue
          ? state_table_->FindState(
              StateTuple(tuple.prefix_id, tuple.fst_id, arc.nextstate))
          : kNoStateId;
      *arcp = A(arc.ilabel, arc.olabel, arc.weight, nextstate);
    } else {
      // check for non terminal
      typename NonTerminalHash::const_iterator it =
          nonterminal_hash_.find(arc.olabel);
      if (it != nonterminal_hash_.end()) {  // recurse into non terminal
        Label nonterminal = it->second;
        const Fst<A>* nt_fst = fst_array_[nonterminal];
        PrefixId nt_prefix = PushPrefix(stackprefix_array_[tuple.prefix_id],
                                        tuple.fst_id, arc.nextstate);

        // if start state is valid replace, else arc is implicitly
        // deleted
        StateId nt_start = nt_fst->Start();
        if (nt_start != kNoStateId) {
          StateId nt_nextstate =  flags & kArcNextStateValue
              ? state_table_->FindState(
                  StateTuple(nt_prefix, nonterminal, nt_start))
              : kNoStateId;
          Label ilabel = (epsilon_on_replace_) ? 0 : arc.ilabel;
          *arcp = A(ilabel, 0, arc.weight, nt_nextstate);
        } else {
          return false;
        }
      } else {
        StateId nextstate = flags & kArcNextStateValue
            ? state_table_->FindState(
                StateTuple(tuple.prefix_id, tuple.fst_id, arc.nextstate))
            : kNoStateId;
        *arcp = A(arc.ilabel, arc.olabel, arc.weight, nextstate);
      }
    }
    return true;
  }

  // Returns the arc iterator flags supported by this Fst.
  uint32 ArcIteratorFlags() const {
    uint32 flags = kArcValueFlags;
    if (!always_cache_)
      flags |= kArcNoCache;
    return flags;
  }

  T* GetStateTable() const {
    return state_table_;
  }

  const Fst<A>* GetFst(Label fst_id) const {
    return fst_array_[fst_id];
  }

  bool EpsilonOnReplace() const { return epsilon_on_replace_; }

  // private helper classes
 private:
  static const size_t kPrime0;

  // \class PrefixTuple
  // \brief Tuple of fst_id and destination state (entry in stack prefix)
  struct PrefixTuple {
    PrefixTuple(Label f, StateId s) : fst_id(f), nextstate(s) {}

    Label   fst_id;
    StateId nextstate;
  };

  // \class StackPrefix
  // \brief Container for stack prefix.
  class StackPrefix {
   public:
    StackPrefix() {}

    // copy constructor
    StackPrefix(const StackPrefix& x) :
        prefix_(x.prefix_) {
    }

    void Push(StateId fst_id, StateId nextstate) {
      prefix_.push_back(PrefixTuple(fst_id, nextstate));
    }

    void Pop() {
      prefix_.pop_back();
    }

    const PrefixTuple& Top() const {
      return prefix_[prefix_.size()-1];
    }

    size_t Depth() const {
      return prefix_.size();
    }

   public:
    vector<PrefixTuple> prefix_;
  };


  // \class StackPrefixEqual
  // \brief Compare two stack prefix classes for equality
  class StackPrefixEqual {
   public:
    bool operator()(const StackPrefix& x, const StackPrefix& y) const {
      if (x.prefix_.size() != y.prefix_.size()) return false;
      for (size_t i = 0; i < x.prefix_.size(); ++i) {
        if (x.prefix_[i].fst_id    != y.prefix_[i].fst_id ||
           x.prefix_[i].nextstate != y.prefix_[i].nextstate) return false;
      }
      return true;
    }
  };

  //
  // \class StackPrefixKey
  // \brief Hash function for stack prefix to prefix id
  class StackPrefixKey {
   public:
    size_t operator()(const StackPrefix& x) const {
      size_t sum = 0;
      for (size_t i = 0; i < x.prefix_.size(); ++i) {
        sum += x.prefix_[i].fst_id + x.prefix_[i].nextstate*kPrime0;
      }
      return sum;
    }
  };

  typedef unordered_map<StackPrefix, PrefixId, StackPrefixKey, StackPrefixEqual>
  StackPrefixHash;

  // private methods
 private:
  // hash stack prefix (return unique index into stackprefix array)
  PrefixId GetPrefixId(const StackPrefix& prefix) {
    typename StackPrefixHash::iterator it = prefix_hash_.find(prefix);
    if (it == prefix_hash_.end()) {
      PrefixId prefix_id = stackprefix_array_.size();
      stackprefix_array_.push_back(prefix);
      prefix_hash_[prefix] = prefix_id;
      return prefix_id;
    } else {
      return it->second;
    }
  }

  // prefix id after a stack pop
  PrefixId PopPrefix(StackPrefix prefix) {
    prefix.Pop();
    return GetPrefixId(prefix);
  }

  // prefix id after a stack push
  PrefixId PushPrefix(StackPrefix prefix, Label fst_id, StateId nextstate) {
    prefix.Push(fst_id, nextstate);
    return GetPrefixId(prefix);
  }


  // private data
 private:
  // runtime options
  bool epsilon_on_replace_;
  bool always_cache_;  // Optionally caching arc iterator disabled when true

  // state table
  StateTable *state_table_;

  // cross index of unique stack prefix
  // could potentially have one copy of prefix array
  StackPrefixHash prefix_hash_;
  vector<StackPrefix> stackprefix_array_;

  set<Label> nonterminal_set_;
  NonTerminalHash nonterminal_hash_;
  vector<const Fst<A>*> fst_array_;
  Label root_;

  void operator=(const ReplaceFstImpl<A, T> &);  // disallow
};


template <class A, class T>
const size_t ReplaceFstImpl<A, T>::kPrime0 = 7853;

//
// \class ReplaceFst
// \brief Recursivively replaces arcs in the root Fst with other Fsts.
// This version is a delayed Fst.
//
// ReplaceFst supports dynamic replacement of arcs in one Fst with
// another Fst. This replacement is recursive.  ReplaceFst can be used
// to support a variety of delayed constructions such as recursive
// transition networks, union, or closure.  It is constructed with an
// array of Fst(s). One Fst represents the root (or topology)
// machine. The root Fst refers to other Fsts by recursively replacing
// arcs labeled as non-terminals with the matching non-terminal
// Fst. Currently the ReplaceFst uses the output symbols of the arcs
// to determine whether the arc is a non-terminal arc or not. A
// non-terminal can be any label that is not a non-zero terminal label
// in the output alphabet.
//
// Note that the constructor uses a vector of pair<>. These correspond
// to the tuple of non-terminal Label and corresponding Fst. For example
// to implement the closure operation we need 2 Fsts. The first root
// Fst is a single Arc on the start State that self loops, it references
// the particular machine for which we are performing the closure operation.
//
// The ReplaceFst class supports an optionally caching arc iterator:
//    ArcIterator< ReplaceFst<A> >
// The ReplaceFst need to be built such that it is known to be ilabel
// or olabel sorted (see usage below).
//
// Observe that Matcher<Fst<A> > will use the optionally caching arc
// iterator when available (Fst is ilabel sorted and matching on the
// input, or Fst is olabel sorted and matching on the output).
// In order to obtain the most efficient behaviour, it is recommended
// to set 'epsilon_on_replace' to false (this means constructing acceptors
// as transducers with epsilons on the input side of nonterminal arcs)
// and matching on the input side.
//
// This class attaches interface to implementation and handles
// reference counting, delegating most methods to ImplToFst.
template <class A, class T = DefaultReplaceStateTable<A> >
class ReplaceFst : public ImplToFst< ReplaceFstImpl<A, T> > {
 public:
  friend class ArcIterator< ReplaceFst<A, T> >;
  friend class StateIterator< ReplaceFst<A, T> >;
  friend class ReplaceFstMatcher<A, T>;

  typedef A Arc;
  typedef typename A::Label   Label;
  typedef typename A::Weight  Weight;
  typedef typename A::StateId StateId;
  typedef CacheState<A> State;
  typedef ReplaceFstImpl<A, T> Impl;

  using ImplToFst<Impl>::Properties;

  ReplaceFst(const vector<pair<Label, const Fst<A>* > >& fst_array,
             Label root)
      : ImplToFst<Impl>(new Impl(fst_array, ReplaceFstOptions<A, T>(root))) {}

  ReplaceFst(const vector<pair<Label, const Fst<A>* > >& fst_array,
             const ReplaceFstOptions<A, T> &opts)
      : ImplToFst<Impl>(new Impl(fst_array, opts)) {}

  // See Fst<>::Copy() for doc.
  ReplaceFst(const ReplaceFst<A, T>& fst, bool safe = false)
      : ImplToFst<Impl>(fst, safe) {}

  // Get a copy of this ReplaceFst. See Fst<>::Copy() for further doc.
  virtual ReplaceFst<A, T> *Copy(bool safe = false) const {
    return new ReplaceFst<A, T>(*this, safe);
  }

  virtual inline void InitStateIterator(StateIteratorData<A> *data) const;

  virtual void InitArcIterator(StateId s, ArcIteratorData<A> *data) const {
    GetImpl()->InitArcIterator(s, data);
  }

  virtual MatcherBase<A> *InitMatcher(MatchType match_type) const {
    if ((GetImpl()->ArcIteratorFlags() & kArcNoCache) &&
        ((match_type == MATCH_INPUT && Properties(kILabelSorted, false)) ||
         (match_type == MATCH_OUTPUT && Properties(kOLabelSorted, false)))) {
      return new ReplaceFstMatcher<A, T>(*this, match_type);
    }
    else {
      VLOG(2) << "Not using replace matcher";
      return 0;
    }
  }

  bool CyclicDependencies() const {
    return GetImpl()->CyclicDependencies();
  }

 private:
  // Makes visible to friends.
  Impl *GetImpl() const { return ImplToFst<Impl>::GetImpl(); }

  void operator=(const ReplaceFst<A> &fst);  // disallow
};


// Specialization for ReplaceFst.
template<class A, class T>
class StateIterator< ReplaceFst<A, T> >
    : public CacheStateIterator< ReplaceFst<A, T> > {
 public:
  explicit StateIterator(const ReplaceFst<A, T> &fst)
      : CacheStateIterator< ReplaceFst<A, T> >(fst, fst.GetImpl()) {}

 private:
  DISALLOW_COPY_AND_ASSIGN(StateIterator);
};


// Specialization for ReplaceFst.
// Implements optional caching. It can be used as follows:
//
//   ReplaceFst<A> replace;
//   ArcIterator< ReplaceFst<A> > aiter(replace, s);
//   // Note: ArcIterator< Fst<A> > is always a caching arc iterator.
//   aiter.SetFlags(kArcNoCache, kArcNoCache);
//   // Use the arc iterator, no arc will be cached, no state will be expanded.
//   // The varied 'kArcValueFlags' can be used to decide which part
//   // of arc values needs to be computed.
//   aiter.SetFlags(kArcILabelValue, kArcValueFlags);
//   // Only want the ilabel for this arc
//   aiter.Value();  // Does not compute the destination state.
//   aiter.Next();
//   aiter.SetFlags(kArcNextStateValue, kArcNextStateValue);
//   // Want both ilabel and nextstate for that arc
//   aiter.Value();  // Does compute the destination state and inserts it
//                   // in the replace state table.
//   // No Arc has been cached at that point.
//
template <class A, class T>
class ArcIterator< ReplaceFst<A, T> > {
 public:
  typedef A Arc;
  typedef typename A::StateId StateId;

  ArcIterator(const ReplaceFst<A, T> &fst, StateId s)
      : fst_(fst), state_(s), pos_(0), offset_(0), flags_(0), arcs_(0),
        data_flags_(0), final_flags_(0) {
    cache_data_.ref_count = 0;
    local_data_.ref_count = 0;

    // If FST does not support optional caching, force caching.
    if(!(fst_.GetImpl()->ArcIteratorFlags() & kArcNoCache) &&
       !(fst_.GetImpl()->HasArcs(state_)))
       fst_.GetImpl()->Expand(state_);

    // If state is already cached, use cached arcs array.
    if (fst_.GetImpl()->HasArcs(state_)) {
      (fst_.GetImpl())->template CacheImpl<A>::InitArcIterator(state_,
                                                               &cache_data_);
      num_arcs_ = cache_data_.narcs;
      arcs_ = cache_data_.arcs;      // 'arcs_' is a ptr to the cached arcs.
      data_flags_ = kArcValueFlags;  // All the arc member values are valid.
    } else {  // Otherwise delay decision until Value() is called.
      tuple_ = fst_.GetImpl()->GetStateTable()->Tuple(state_);
      if (tuple_.fst_state == kNoStateId) {
        num_arcs_ = 0;
      } else {
        // The decision to cache or not to cache has been defered
        // until Value() or SetFlags() is called. However, the arc
        // iterator is set up now to be ready for non-caching in order
        // to keep the Value() method simple and efficient.
        const Fst<A>* fst = fst_.GetImpl()->GetFst(tuple_.fst_id);
        fst->InitArcIterator(tuple_.fst_state, &local_data_);
        // 'arcs_' is a pointer to the arcs in the underlying machine.
        arcs_ = local_data_.arcs;
        // Compute the final arc (but not its destination state)
        // if a final arc is required.
        bool has_final_arc = fst_.GetImpl()->ComputeFinalArc(
            tuple_,
            &final_arc_,
            kArcValueFlags & ~kArcNextStateValue);
        // Set the arc value flags that hold for 'final_arc_'.
        final_flags_ = kArcValueFlags & ~kArcNextStateValue;
        // Compute the number of arcs.
        num_arcs_ = local_data_.narcs;
        if (has_final_arc)
          ++num_arcs_;
        // Set the offset between the underlying arc positions and
        // the positions in the arc iterator.
        offset_ = num_arcs_ - local_data_.narcs;
        // Defers the decision to cache or not until Value() or
        // SetFlags() is called.
        data_flags_ = 0;
      }
    }
  }

  ~ArcIterator() {
    if (cache_data_.ref_count)
      --(*cache_data_.ref_count);
    if (local_data_.ref_count)
      --(*local_data_.ref_count);
  }

  void ExpandAndCache() const   {
    // TODO(allauzen): revisit this
    // fst_.GetImpl()->Expand(state_, tuple_, local_data_);
    // (fst_.GetImpl())->CacheImpl<A>*>::InitArcIterator(state_,
    //                                               &cache_data_);
    //
    fst_.InitArcIterator(state_, &cache_data_);  // Expand and cache state.
    arcs_ = cache_data_.arcs;  // 'arcs_' is a pointer to the cached arcs.
    data_flags_ = kArcValueFlags;  // All the arc member values are valid.
    offset_ = 0;  // No offset

  }

  void Init() {
    if (flags_ & kArcNoCache) {  // If caching is disabled
      // 'arcs_' is a pointer to the arcs in the underlying machine.
      arcs_ = local_data_.arcs;
      // Set the arcs value flags that hold for 'arcs_'.
      data_flags_ = kArcWeightValue;
      if (!fst_.GetImpl()->EpsilonOnReplace())
          data_flags_ |= kArcILabelValue;
      // Set the offset between the underlying arc positions and
      // the positions in the arc iterator.
      offset_ = num_arcs_ - local_data_.narcs;
    } else {  // Otherwise, expand and cache
      ExpandAndCache();
    }
  }

  bool Done() const { return pos_ >= num_arcs_; }

  const A& Value() const {
    // If 'data_flags_' was set to 0, non-caching was not requested
    if (!data_flags_) {
      // TODO(allauzen): revisit this.
      if (flags_ & kArcNoCache) {
        // Should never happen.
        FSTERROR() << "ReplaceFst: inconsistent arc iterator flags";
      }
      ExpandAndCache();  // Expand and cache.
    }

    if (pos_ - offset_ >= 0) {  // The requested arc is not the 'final' arc.
      const A& arc = arcs_[pos_ - offset_];
      if ((data_flags_ & flags_) == (flags_ & kArcValueFlags)) {
        // If the value flags for 'arc' match the recquired value flags
        // then return 'arc'.
        return arc;
      } else {
        // Otherwise, compute the corresponding arc on-the-fly.
        fst_.GetImpl()->ComputeArc(tuple_, arc, &arc_, flags_ & kArcValueFlags);
        return arc_;
      }
    } else {  // The requested arc is the 'final' arc.
      if ((final_flags_ & flags_) != (flags_ & kArcValueFlags)) {
        // If the arc value flags that hold for the final arc
        // do not match the requested value flags, then
        // 'final_arc_' needs to be updated.
        fst_.GetImpl()->ComputeFinalArc(tuple_, &final_arc_,
                                    flags_ & kArcValueFlags);
        final_flags_ = flags_ & kArcValueFlags;
      }
      return final_arc_;
    }
  }

  void Next() { ++pos_; }

  size_t Position() const { return pos_; }

  void Reset() { pos_ = 0;  }

  void Seek(size_t pos) { pos_ = pos; }

  uint32 Flags() const { return flags_; }

  void SetFlags(uint32 f, uint32 mask) {
    // Update the flags taking into account what flags are supported
    // by the Fst.
    flags_ &= ~mask;
    flags_ |= (f & fst_.GetImpl()->ArcIteratorFlags());
    // If non-caching is not requested (and caching has not already
    // been performed), then flush 'data_flags_' to request caching
    // during the next call to Value().
    if (!(flags_ & kArcNoCache) && data_flags_ != kArcValueFlags) {
      if (!fst_.GetImpl()->HasArcs(state_))
         data_flags_ = 0;
    }
    // If 'data_flags_' has been flushed but non-caching is requested
    // before calling Value(), then set up the iterator for non-caching.
    if ((f & kArcNoCache) && (!data_flags_))
      Init();
  }

 private:
  const ReplaceFst<A, T> &fst_;           // Reference to the FST
  StateId state_;                         // State in the FST
  mutable typename T::StateTuple tuple_;  // Tuple corresponding to state_

  ssize_t pos_;             // Current position
  mutable ssize_t offset_;  // Offset between position in iterator and in arcs_
  ssize_t num_arcs_;        // Number of arcs at state_
  uint32 flags_;            // Behavorial flags for the arc iterator
  mutable Arc arc_;         // Memory to temporarily store computed arcs

  mutable ArcIteratorData<Arc> cache_data_;  // Arc iterator data in cache
  mutable ArcIteratorData<Arc> local_data_;  // Arc iterator data in local fst

  mutable const A* arcs_;       // Array of arcs
  mutable uint32 data_flags_;   // Arc value flags valid for data in arcs_
  mutable Arc final_arc_;       // Final arc (when required)
  mutable uint32 final_flags_;  // Arc value flags valid for final_arc_

  DISALLOW_COPY_AND_ASSIGN(ArcIterator);
};


template <class A, class T>
class ReplaceFstMatcher : public MatcherBase<A> {
 public:
  typedef A Arc;
  typedef typename A::StateId StateId;
  typedef typename A::Label Label;
  typedef MultiEpsMatcher<Matcher<Fst<A> > > LocalMatcher;

  ReplaceFstMatcher(const ReplaceFst<A, T> &fst, fst::MatchType match_type)
      : fst_(fst),
        impl_(fst_.GetImpl()),
        s_(fst::kNoStateId),
        match_type_(match_type),
        current_loop_(false),
        final_arc_(false),
        loop_(fst::kNoLabel, 0, A::Weight::One(), fst::kNoStateId) {
    if (match_type_ == fst::MATCH_OUTPUT)
      swap(loop_.ilabel, loop_.olabel);
    InitMatchers();
  }

  ReplaceFstMatcher(const ReplaceFstMatcher<A, T> &matcher, bool safe = false)
      : fst_(matcher.fst_),
        impl_(fst_.GetImpl()),
        s_(fst::kNoStateId),
        match_type_(matcher.match_type_),
        current_loop_(false),
        loop_(fst::kNoLabel, 0, A::Weight::One(), fst::kNoStateId) {
    if (match_type_ == fst::MATCH_OUTPUT)
      swap(loop_.ilabel, loop_.olabel);
    InitMatchers();
  }

  // Create a local matcher for each component Fst of replace.
  // LocalMatcher is a multi epsilon wrapper matcher. MultiEpsilonMatcher
  // is used to match each non-terminal arc, since these non-terminal
  // turn into epsilons on recursion.
  void InitMatchers() {
    const vector<const Fst<A>*>& fst_array = impl_->fst_array_;
    matcher_.resize(fst_array.size(), 0);
    for (size_t i = 0; i < fst_array.size(); ++i) {
      if (fst_array[i]) {
        matcher_[i] =
            new LocalMatcher(*fst_array[i], match_type_, kMultiEpsList);

        typename set<Label>::iterator it = impl_->nonterminal_set_.begin();
        for (; it != impl_->nonterminal_set_.end(); ++it) {
          matcher_[i]->AddMultiEpsLabel(*it);
        }
      }
    }
  }

  virtual ReplaceFstMatcher<A, T> *Copy(bool safe = false) const {
    return new ReplaceFstMatcher<A, T>(*this, safe);
  }

  virtual ~ReplaceFstMatcher() {
    for (size_t i = 0; i < matcher_.size(); ++i)
      delete matcher_[i];
  }

  virtual MatchType Type(bool test) const {
    if (match_type_ == MATCH_NONE)
      return match_type_;

    uint64 true_prop =  match_type_ == MATCH_INPUT ?
        kILabelSorted : kOLabelSorted;
    uint64 false_prop = match_type_ == MATCH_INPUT ?
        kNotILabelSorted : kNotOLabelSorted;
    uint64 props = fst_.Properties(true_prop | false_prop, test);

    if (props & true_prop)
      return match_type_;
    else if (props & false_prop)
      return MATCH_NONE;
    else
      return MATCH_UNKNOWN;
  }

  virtual const Fst<A> &GetFst() const {
    return fst_;
  }

  virtual uint64 Properties(uint64 props) const {
    return props;
  }

 private:
  // Set the sate from which our matching happens.
  virtual void SetState_(StateId s) {
    if (s_ == s) return;

    s_ = s;
    tuple_ = impl_->GetStateTable()->Tuple(s_);
    if (tuple_.fst_state == kNoStateId) {
      done_ = true;
      return;
    }
    // Get current matcher. Used for non epsilon matching
    current_matcher_ = matcher_[tuple_.fst_id];
    current_matcher_->SetState(tuple_.fst_state);
    loop_.nextstate = s_;

    final_arc_ = false;
  }

  // Search for label, from previous set state. If label == 0, first
  // hallucinate and epsilon loop, else use the underlying matcher to
  // search for the label or epsilons.
  // - Note since the ReplaceFST recursion on non-terminal arcs causes
  //   epsilon transitions to be created we use the MultiEpsilonMatcher
  //   to search for possible matches of non terminals.
  // - If the component Fst reaches a final state we also need to add
  //   the exiting final arc.
  virtual bool Find_(Label label) {
    bool found = false;
    label_ = label;
    if (label_ == 0 || label_ == kNoLabel) {
      // Compute loop directly, saving Replace::ComputeArc
      if (label_ == 0) {
        current_loop_ = true;
        found = true;
      }
      // Search for matching multi epsilons
      final_arc_ = impl_->ComputeFinalArc(tuple_, 0);
      found = current_matcher_->Find(kNoLabel) || final_arc_ || found;
    } else {
      // Search on sub machine directly using sub machine matcher.
      found = current_matcher_->Find(label_);
    }
    return found;
  }

  virtual bool Done_() const {
    return !current_loop_ && !final_arc_ && current_matcher_->Done();
  }

  virtual const Arc& Value_() const {
    if (current_loop_) {
      return loop_;
    }
    if (final_arc_) {
      impl_->ComputeFinalArc(tuple_, &arc_);
      return arc_;
    }
    const Arc& component_arc = current_matcher_->Value();
    impl_->ComputeArc(tuple_, component_arc, &arc_);
    return arc_;
  }

  virtual void Next_() {
    if (current_loop_) {
      current_loop_ = false;
      return;
    }
    if (final_arc_) {
      final_arc_ = false;
      return;
    }
    current_matcher_->Next();
  }

  const ReplaceFst<A, T>& fst_;
  ReplaceFstImpl<A, T> *impl_;
  LocalMatcher* current_matcher_;
  vector<LocalMatcher*> matcher_;

  StateId s_;                        // Current state
  Label label_;                      // Current label

  MatchType match_type_;             // Supplied by caller
  mutable bool done_;
  mutable bool current_loop_;        // Current arc is the implicit loop
  mutable bool final_arc_;           // Current arc for exiting recursion
  mutable typename T::StateTuple tuple_;  // Tuple corresponding to state_
  mutable Arc arc_;
  Arc loop_;
};

template <class A, class T> inline
void ReplaceFst<A, T>::InitStateIterator(StateIteratorData<A> *data) const {
  data->base = new StateIterator< ReplaceFst<A, T> >(*this);
}

typedef ReplaceFst<StdArc> StdReplaceFst;


// // Recursivively replaces arcs in the root Fst with other Fsts.
// This version writes the result of replacement to an output MutableFst.
//
// Replace supports replacement of arcs in one Fst with another
// Fst. This replacement is recursive.  Replace takes an array of
// Fst(s). One Fst represents the root (or topology) machine. The root
// Fst refers to other Fsts by recursively replacing arcs labeled as
// non-terminals with the matching non-terminal Fst. Currently Replace
// uses the output symbols of the arcs to determine whether the arc is
// a non-terminal arc or not. A non-terminal can be any label that is
// not a non-zero terminal label in the output alphabet.  Note that
// input argument is a vector of pair<>. These correspond to the tuple
// of non-terminal Label and corresponding Fst.
template<class Arc>
void Replace(const vector<pair<typename Arc::Label,
             const Fst<Arc>* > >& ifst_array,
             MutableFst<Arc> *ofst, typename Arc::Label root,
             bool epsilon_on_replace) {
  ReplaceFstOptions<Arc> opts(root, epsilon_on_replace);
  opts.gc_limit = 0;  // Cache only the last state for fastest copy.
  *ofst = ReplaceFst<Arc>(ifst_array, opts);
}

template<class Arc>
void Replace(const vector<pair<typename Arc::Label,
             const Fst<Arc>* > >& ifst_array,
             MutableFst<Arc> *ofst, typename Arc::Label root) {
  Replace(ifst_array, ofst, root, false);
}

}  // namespace fst

#endif  // FST_LIB_REPLACE_H__
